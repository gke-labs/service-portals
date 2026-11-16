// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
)

type fakeLookup struct {
	mu    sync.Mutex
	nodes map[string]string
}

func (f *fakeLookup) NodeForPod(ctx context.Context, uid string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nodes[uid], nil
}

func (f *fakeLookup) set(uid, node string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nodes == nil {
		f.nodes = make(map[string]string)
	}
	f.nodes[uid] = node
}

func fakeIdentity(ctx context.Context) (string, time.Time, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", time.Time{}, errors.New("missing metadata")
	}
	nodes := md.Get("node-name")
	if len(nodes) == 0 {
		return "", time.Time{}, errors.New("missing node-name")
	}
	var expiry time.Time
	if exp := md.Get("expiry"); len(exp) > 0 {
		expiry, _ = time.Parse(time.RFC3339Nano, exp[0])
	}
	return nodes[0], expiry, nil
}

func startTestServer(t *testing.T, lookup PodLookup, pushTimeout time.Duration) (*Server, portalsv1.NodeStreamServiceClient) {
	t.Helper()
	s := NewServer(ServerConfig{
		Lookup:      lookup,
		Identity:    fakeIdentity,
		PushTimeout: pushTimeout,
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	portalsv1.RegisterNodeStreamServiceServer(grpcServer, s)

	go func() {
		_ = grpcServer.Serve(l)
	}()

	t.Cleanup(func() {
		grpcServer.Stop()
		_ = l.Close()
	})

	conn, err := grpc.Dial(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial controller: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return s, portalsv1.NewNodeStreamServiceClient(conn)
}

func openStream(t *testing.T, client portalsv1.NodeStreamServiceClient, nodeName string, expiry string) (portalsv1.NodeStreamService_StreamClient, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	ctx = metadata.AppendToOutgoingContext(ctx, "node-name", nodeName)
	if expiry != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "expiry", expiry)
	}
	stream, err := client.Stream(ctx)
	if err != nil {
		cancel()
		t.Fatalf("failed to open stream for %s: %v", nodeName, err)
	}
	return stream, cancel
}

// 1. A push for a pod on a connected node is delivered and the caller learns the node's answer.
func TestPush_DeliveredAndAnswerLearned(t *testing.T) {
	lookup := &fakeLookup{}
	lookup.set("pod-1", "node-1")
	s, client := startTestServer(t, lookup, time.Minute)

	stream, cancel := openStream(t, client, "node-1", "")
	defer cancel()

	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-1"}},
		},
	}); err != nil {
		t.Fatalf("failed to send declaration: %v", err)
	}

	push := &portalsv1.ControllerPush{
		PushId: "push-1",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-1", Identity: "test-user"},
		},
	}

	answerErrCh := make(chan error, 1)
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			answerErrCh <- err
			return
		}
		p := msg.GetPush()
		if p == nil || p.GetPushId() != "push-1" {
			answerErrCh <- errors.New("unexpected push message received")
			return
		}
		answerErrCh <- stream.Send(&portalsv1.NodeMessage{
			Payload: &portalsv1.NodeMessage_Answer{
				Answer: &portalsv1.PushAnswer{
					PushId: "push-1",
					PodUid: "pod-1",
					Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
				},
			},
		})
	}()

	ans, err := s.Push(t.Context(), push, true)
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}
	if ans.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
		t.Fatalf("expected ACCEPTED, got %v", ans.GetStatus())
	}
	if err := <-answerErrCh; err != nil {
		t.Fatalf("stream error answering push: %v", err)
	}
}

// 2. A push for a pod not yet scheduled is held and delivered when the lookup changes and the node declares the pod.
func TestPush_HeldUntilScheduledAndDeclared(t *testing.T) {
	lookup := &fakeLookup{}
	s, client := startTestServer(t, lookup, time.Minute)

	stream, cancel := openStream(t, client, "node-1", "")
	defer cancel()

	push := &portalsv1.ControllerPush{
		PushId: "push-held",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-held", Identity: "test-user"},
		},
	}

	ansCh := make(chan *portalsv1.PushAnswer, 1)
	errCh := make(chan error, 1)
	go func() {
		ans, err := s.Push(t.Context(), push, true)
		ansCh <- ans
		errCh <- err
	}()

	// Brief pause to ensure push is held pending.
	time.Sleep(50 * time.Millisecond)
	select {
	case ans := <-ansCh:
		t.Fatalf("expected push to be held, but got result prematurely: %v", ans)
	default:
	}

	// Lookup changes: pod-held is now scheduled on node-1, notify controller.
	lookup.set("pod-held", "node-1")

	// Node declares pod-held.
	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-held"}},
		},
	}); err != nil {
		t.Fatalf("failed to send declaration: %v", err)
	}

	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to recv push on stream: %v", err)
	}
	if msg.GetPush().GetPushId() != "push-held" {
		t.Fatalf("expected push-held, got %v", msg.GetPush())
	}

	// Answer the push.
	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Answer{
			Answer: &portalsv1.PushAnswer{
				PushId: "push-held",
				PodUid: "pod-held",
				Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send answer: %v", err)
	}

	if pushErr := <-errCh; pushErr != nil {
		t.Fatalf("Push failed: %v", pushErr)
	}
	ans := <-ansCh
	if ans.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED {
		t.Fatalf("expected ACCEPTED, got %v", ans.GetStatus())
	}
}

// 3. A held push is dropped at the time limit and the waiting caller is told.
func TestPush_DroppedAtTimeout(t *testing.T) {
	lookup := &fakeLookup{}
	s, _ := startTestServer(t, lookup, 50*time.Millisecond)

	push := &portalsv1.ControllerPush{
		PushId: "push-timeout",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-never", Identity: "test-user"},
		},
	}

	ans, err := s.Push(t.Context(), push, true)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got ans=%v, err=%v", ans, err)
	}

	s.mu.Lock()
	_, stillPending := s.byID["push-timeout"]
	s.mu.Unlock()
	if stillPending {
		t.Fatal("expected timed out push to be removed from byID map")
	}
}

// 4. A push is never sent to a node other than the one the lookup names, even if another node declares the pod.
func TestPush_NeverSentToNodeOtherThanLookupNames(t *testing.T) {
	lookup := &fakeLookup{}
	lookup.set("pod-secure", "node-honest")
	s, client := startTestServer(t, lookup, time.Minute)

	streamRogue, cancelRogue := openStream(t, client, "node-rogue", "")
	defer cancelRogue()

	// Rogue node attempts to claim pod-secure.
	if err := streamRogue.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-secure"}},
		},
	}); err != nil {
		t.Fatalf("failed to send rogue declaration: %v", err)
	}

	streamHonest, cancelHonest := openStream(t, client, "node-honest", "")
	defer cancelHonest()

	push := &portalsv1.ControllerPush{
		PushId: "push-secure",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-secure", Identity: "test-user"},
		},
	}

	// Caller pushes (wait=false).
	if _, err := s.Push(t.Context(), push, false); err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	// Verify rogue node never receives the push.
	rogueReceived := make(chan *portalsv1.ControllerMessage, 1)
	go func() {
		msg, _ := streamRogue.Recv()
		if msg != nil {
			rogueReceived <- msg
		}
	}()

	select {
	case msg := <-rogueReceived:
		t.Fatalf("security violation: rogue node received push: %v", msg)
	case <-time.After(100 * time.Millisecond):
	}

	// Honest node declares the pod.
	if err := streamHonest.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-secure"}},
		},
	}); err != nil {
		t.Fatalf("failed to send honest declaration: %v", err)
	}

	honestMsg, err := streamHonest.Recv()
	if err != nil {
		t.Fatalf("honest node failed to receive push: %v", err)
	}
	if honestMsg.GetPush().GetPushId() != "push-secure" {
		t.Fatalf("unexpected push on honest node: %v", honestMsg.GetPush())
	}
}

// 5. A node's refusal reaches the caller with its reason.
func TestPush_NodeRefusalWithReasonReachesCaller(t *testing.T) {
	lookup := &fakeLookup{}
	lookup.set("pod-refused", "node-1")
	s, client := startTestServer(t, lookup, time.Minute)

	stream, cancel := openStream(t, client, "node-1", "")
	defer cancel()

	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-refused"}},
		},
	}); err != nil {
		t.Fatalf("failed to send declaration: %v", err)
	}

	push := &portalsv1.ControllerPush{
		PushId: "push-refused",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-refused", Identity: "test-user"},
		},
	}

	go func() {
		msg, err := stream.Recv()
		if err != nil {
			return
		}
		_ = stream.Send(&portalsv1.NodeMessage{
			Payload: &portalsv1.NodeMessage_Answer{
				Answer: &portalsv1.PushAnswer{
					PushId:        msg.GetPush().GetPushId(),
					PodUid:        "pod-refused",
					Status:        portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED,
					RefusalReason: "policy invalid: port 9999 blocked",
				},
			},
		})
	}()

	ans, err := s.Push(t.Context(), push, true)
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}
	if ans.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED {
		t.Fatalf("expected REFUSED, got %v", ans.GetStatus())
	}
	if ans.GetRefusalReason() != "policy invalid: port 9999 blocked" {
		t.Fatalf("expected reason 'policy invalid: port 9999 blocked', got %q", ans.GetRefusalReason())
	}
}

// 6. A stream that ends loses its registration and its undelivered pushes stay pending.
func TestStreamEnd_LosesRegistrationAndUndeliveredStayPending(t *testing.T) {
	lookup := &fakeLookup{}
	lookup.set("pod-undelivered", "node-1")
	s, client := startTestServer(t, lookup, time.Minute)

	stream, cancel := openStream(t, client, "node-1", "")

	// Send declaration for another pod so the stream handler is invoked on the server.
	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"other-pod"}},
		},
	}); err != nil {
		t.Fatalf("failed to send declaration: %v", err)
	}

	// Verify node is registered.
	var nodeRegistered bool
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		_, nodeRegistered = s.nodes["node-1"]
		s.mu.Unlock()
		if nodeRegistered {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !nodeRegistered {
		t.Fatal("expected node-1 to be registered")
	}

	// Push for pod-undelivered (which node-1 has not declared).
	push := &portalsv1.ControllerPush{
		PushId: "push-undelivered",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-undelivered", Identity: "test-user"},
		},
	}
	if _, err := s.Push(t.Context(), push, false); err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	// Close stream.
	cancel()
	_ = stream.CloseSend()

	// Wait for stream cleanup.
	time.Sleep(50 * time.Millisecond)

	s.mu.Lock()
	_, nodeStillRegistered := s.nodes["node-1"]
	pending, stillPending := s.byID["push-undelivered"]
	s.mu.Unlock()

	if nodeStillRegistered {
		t.Fatal("expected node-1 to lose its registration after stream ends")
	}
	if !stillPending || pending == nil {
		t.Fatal("expected undelivered push to stay pending after stream ends")
	}
}

// 7. A replaced stream gets no further pushes.
func TestReplacedStream_GetsNoFurtherPushes(t *testing.T) {
	lookup := &fakeLookup{}
	lookup.set("pod-rep", "node-1")
	s, client := startTestServer(t, lookup, time.Minute)

	stream1, cancel1 := openStream(t, client, "node-1", "")
	defer cancel1()

	// Stream1 sends declaration to establish registration.
	if err := stream1.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-old"}},
		},
	}); err != nil {
		t.Fatalf("stream1 declaration failed: %v", err)
	}

	// Wait for stream1 to be registered.
	var stream1Registered bool
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		_, stream1Registered = s.nodes["node-1"]
		s.mu.Unlock()
		if stream1Registered {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !stream1Registered {
		t.Fatal("expected stream1 to be registered")
	}

	// Now connect stream2 to replace stream1.
	stream2, cancel2 := openStream(t, client, "node-1", "")
	defer cancel2()

	// Stream2 declares pod-rep.
	if err := stream2.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-rep"}},
		},
	}); err != nil {
		t.Fatalf("stream2 declaration failed: %v", err)
	}

	// Wait for stream2 to take over registration.
	time.Sleep(30 * time.Millisecond)

	push := &portalsv1.ControllerPush{
		PushId: "push-rep",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-rep", Identity: "test-user"},
		},
	}
	if _, err := s.Push(t.Context(), push, false); err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	stream1Msgs := make(chan *portalsv1.ControllerMessage, 1)
	go func() {
		msg, _ := stream1.Recv()
		if msg != nil {
			stream1Msgs <- msg
		}
	}()

	select {
	case msg := <-stream1Msgs:
		t.Fatalf("replaced stream1 received push: %v", msg)
	case <-time.After(100 * time.Millisecond):
	}

	stream2Msg, err := stream2.Recv()
	if err != nil {
		t.Fatalf("stream2 failed to receive push: %v", err)
	}
	if stream2Msg.GetPush().GetPushId() != "push-rep" {
		t.Fatalf("unexpected push on stream2: %v", stream2Msg.GetPush())
	}
}

// 8. Pending secrets are gone after answer and after timeout.
func TestPendingSecrets_GoneAfterAnswerAndTimeout(t *testing.T) {
	lookup := &fakeLookup{}
	lookup.set("pod-sec-answer", "node-1")
	s, client := startTestServer(t, lookup, 50*time.Millisecond)

	stream, cancel := openStream(t, client, "node-1", "")
	defer cancel()

	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-sec-answer"}},
		},
	}); err != nil {
		t.Fatalf("failed to send declaration: %v", err)
	}

	// --- Part A: Dropped after answer ---
	secretToken1 := []byte("secret-token-to-answer")
	pushAnswer := &portalsv1.ControllerPush{
		PushId: "push-sec-answer",
		Action: &portalsv1.ControllerPush_Secrets{
			Secrets: &portalsv1.PodSecrets{
				PodUid:  "pod-sec-answer",
				Secrets: map[string][]byte{"tok": secretToken1},
			},
		},
	}

	if _, err := s.Push(t.Context(), pushAnswer, false); err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	// Verify secrets are present in pending before answer.
	s.mu.Lock()
	p := s.byID["push-sec-answer"]
	s.mu.Unlock()
	if p == nil || p.push.GetSecrets() == nil {
		t.Fatal("expected push-sec-answer to hold secrets while pending")
	}

	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to recv push: %v", err)
	}

	// Node answers the push.
	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Answer{
			Answer: &portalsv1.PushAnswer{
				PushId: msg.GetPush().GetPushId(),
				PodUid: "pod-sec-answer",
				Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
			},
		},
	}); err != nil {
		t.Fatalf("failed to send answer: %v", err)
	}

	time.Sleep(30 * time.Millisecond)
	s.mu.Lock()
	_, stillPending := s.byID["push-sec-answer"]
	pushesAns := s.pending["pod-sec-answer"]
	s.mu.Unlock()
	if stillPending || len(pushesAns) > 0 {
		t.Fatal("expected push to be removed from pending after answer")
	}

	// --- Part B: Dropped after timeout ---
	secretToken2 := []byte("secret-token-to-timeout")
	pushTimeout := &portalsv1.ControllerPush{
		PushId: "push-sec-timeout",
		Action: &portalsv1.ControllerPush_Secrets{
			Secrets: &portalsv1.PodSecrets{
				PodUid:  "pod-sec-unscheduled",
				Secrets: map[string][]byte{"tok": secretToken2},
			},
		},
	}

	ans, err := s.Push(t.Context(), pushTimeout, true)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got ans=%v, err=%v", ans, err)
	}

	s.mu.Lock()
	_, stillPendingTimeout := s.byID["push-sec-timeout"]
	pushesTimeout := s.pending["pod-sec-unscheduled"]
	s.mu.Unlock()
	if stillPendingTimeout || len(pushesTimeout) > 0 {
		t.Fatal("expected timed out push to be removed from pending")
	}
}

// 9. If identity has an expiry, stream ends at that time.
func TestIdentityExpiry_EndsStream(t *testing.T) {
	lookup := &fakeLookup{}
	_, client := startTestServer(t, lookup, time.Minute)

	expiryTime := time.Now().Add(60 * time.Millisecond).Format(time.RFC3339Nano)
	stream, cancel := openStream(t, client, "node-expiring", expiryTime)
	defer cancel()

	// Initial message send works.
	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-1"}},
		},
	}); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	// After expiry passes, stream should end.
	time.Sleep(100 * time.Millisecond)
	_, err := stream.Recv()
	if err == nil {
		t.Fatal("expected stream to end after identity expiry, but Recv succeeded")
	}
}

// 10. Any node cannot answer another node's push (Point 1 from review).
func TestPush_AnswerIgnoredFromDifferentNode(t *testing.T) {
	lookup := &fakeLookup{}
	lookup.set("pod-auth", "node-1")
	s, client := startTestServer(t, lookup, 150*time.Millisecond)

	stream1, cancel1 := openStream(t, client, "node-1", "")
	defer cancel1()
	stream2, cancel2 := openStream(t, client, "node-2", "")
	defer cancel2()

	// Node-1 declares pod-auth.
	_ = stream1.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-auth"}},
		},
	})
	// Node-2 (rogue) declares pod-auth.
	_ = stream2.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-auth"}},
		},
	})

	push := &portalsv1.ControllerPush{
		PushId: "push-auth-1",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-auth", Identity: "test-user"},
		},
	}

	honestReceived := make(chan struct{}, 1)
	go func() {
		msg, err := stream1.Recv()
		if err == nil && msg.GetPush().GetPushId() == "push-auth-1" {
			honestReceived <- struct{}{}
		}
	}()

	resultCh := make(chan error, 1)
	go func() {
		_, err := s.Push(t.Context(), push, true)
		resultCh <- err
	}()

	select {
	case <-honestReceived:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("honest node did not receive push")
	}

	// Rogue node-2 sends an answer claiming acceptance for push-auth-1.
	if err := stream2.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Answer{
			Answer: &portalsv1.PushAnswer{
				PushId: "push-auth-1",
				PodUid: "pod-auth",
				Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
			},
		},
	}); err != nil {
		t.Fatalf("rogue answer send failed: %v", err)
	}

	// Caller must not see accepted; since honest node-1 never answers, caller must time out.
	select {
	case err := <-resultCh:
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("expected ErrTimeout, got: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("push did not time out")
	}
}

// 11. PodUpdate removal does not cancel pending push (Point 2 from review).
func TestPodUpdate_RemovalDoesNotCancelPendingPush(t *testing.T) {
	lookup := &fakeLookup{}
	s, client := startTestServer(t, lookup, time.Minute)

	stream1, cancel1 := openStream(t, client, "node-1", "")
	defer cancel1()

	_ = stream1.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-rem"}},
		},
	})

	push := &portalsv1.ControllerPush{
		PushId: "push-rem",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-rem", Identity: "test-user"},
		},
	}
	if _, err := s.Push(t.Context(), push, false); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	// Node-1 sends PodUpdate removing pod-rem.
	if err := stream1.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Update{
			Update: &portalsv1.PodUpdate{
				RemovedPodUids: []string{"pod-rem"},
			},
		},
	}); err != nil {
		t.Fatalf("send update failed: %v", err)
	}

	time.Sleep(30 * time.Millisecond)

	s.mu.Lock()
	pushes := s.pending["pod-rem"]
	s.mu.Unlock()
	if len(pushes) == 0 {
		t.Fatal("expected pending push to NOT be cancelled by node removal update")
	}
}

// 12. Multiple pushes for one pod arrive in order (Point 3 from review).
func TestPush_MultiplePushesArriveInOrder(t *testing.T) {
	lookup := &fakeLookup{}
	lookup.set("pod-order", "node-1")
	s, client := startTestServer(t, lookup, time.Minute)

	p1 := &portalsv1.ControllerPush{
		PushId: "order-1-policy",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-order", Identity: "user-1"},
		},
	}
	p2 := &portalsv1.ControllerPush{
		PushId: "order-2-secrets",
		Action: &portalsv1.ControllerPush_Secrets{
			Secrets: &portalsv1.PodSecrets{PodUid: "pod-order", Secrets: map[string][]byte{"k": []byte("v")}},
		},
	}
	p3 := &portalsv1.ControllerPush{
		PushId: "order-3-unbind",
		Action: &portalsv1.ControllerPush_Unbind{
			Unbind: &portalsv1.UnbindRequest{PodUid: "pod-order"},
		},
	}

	if _, err := s.Push(t.Context(), p1, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Push(t.Context(), p2, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Push(t.Context(), p3, false); err != nil {
		t.Fatal(err)
	}

	stream, cancel := openStream(t, client, "node-1", "")
	defer cancel()

	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-order"}},
		},
	}); err != nil {
		t.Fatal(err)
	}

	expectedIDs := []string{"order-1-policy", "order-2-secrets", "order-3-unbind"}
	for _, expected := range expectedIDs {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatalf("failed to recv push: %v", err)
		}
		if got := msg.GetPush().GetPushId(); got != expected {
			t.Fatalf("out of order: expected push %s, got %s", expected, got)
		}
	}
}

// 13. Dropped push is never written to stream (Point 4 from review).
func TestPush_DroppedPushNeverWrittenToStream(t *testing.T) {
	lookup := &fakeLookup{}
	s, client := startTestServer(t, lookup, time.Minute)

	stream, cancel := openStream(t, client, "node-1", "")
	defer cancel()

	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-1"}},
		},
	}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(20 * time.Millisecond)

	s.mu.Lock()
	ns := s.nodes["node-1"]
	pDropped := &pendingPush{
		push: &portalsv1.ControllerPush{
			PushId: "push-dropped",
			Action: &portalsv1.ControllerPush_Policy{Policy: &portalsv1.PodPolicy{PodUid: "pod-1", Identity: "user"}},
		},
		podUID:     "pod-1",
		sentStream: ns,
		dropped:    true,
	}
	pValid := &pendingPush{
		push: &portalsv1.ControllerPush{
			PushId: "push-valid",
			Action: &portalsv1.ControllerPush_Policy{Policy: &portalsv1.PodPolicy{PodUid: "pod-1", Identity: "user"}},
		},
		podUID:     "pod-1",
		sentStream: ns,
		dropped:    false,
	}
	ns.sendCh <- pDropped
	ns.sendCh <- pValid
	s.mu.Unlock()

	// Client should only receive push-valid; push-dropped is skipped.
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to recv msg: %v", err)
	}
	if msg.GetPush().GetPushId() != "push-valid" {
		t.Fatalf("expected push-valid, but got dropped push: %v", msg.GetPush().GetPushId())
	}

	recvCh := make(chan *portalsv1.ControllerMessage, 1)
	go func() {
		m, _ := stream.Recv()
		if m != nil {
			recvCh <- m
		}
	}()
	select {
	case m := <-recvCh:
		t.Fatalf("unexpected message: %v", m)
	case <-time.After(50 * time.Millisecond):
	}
}

// 14. Non-waiting push lives for the full time limit (Point 6 from review).
func TestPush_NonWaitingPushLivesForFullTimeout(t *testing.T) {
	lookup := &fakeLookup{}
	s, _ := startTestServer(t, lookup, 200*time.Millisecond)

	push := &portalsv1.ControllerPush{
		PushId: "push-short-ctx",
		Action: &portalsv1.ControllerPush_Policy{
			Policy: &portalsv1.PodPolicy{PodUid: "pod-short-ctx", Identity: "test-user"},
		},
	}

	shortCtx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	if _, err := s.Push(shortCtx, push, false); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	// After short context expires, push should still be pending in byID.
	time.Sleep(50 * time.Millisecond)
	s.mu.Lock()
	_, stillPending := s.byID["push-short-ctx"]
	s.mu.Unlock()
	if !stillPending {
		t.Fatal("expected non-waiting push to survive short caller context expiration")
	}

	// After full timeout (200ms), it should be dropped.
	time.Sleep(200 * time.Millisecond)
	s.mu.Lock()
	_, stillPendingAfterFull := s.byID["push-short-ctx"]
	s.mu.Unlock()
	if stillPendingAfterFull {
		t.Fatal("expected push to be dropped after full push timeout")
	}
}

// 15. Identity error is returned as is (Point 7 from review).
func TestIdentity_ErrorReturnedAsIs(t *testing.T) {
	expectedErr := status.Error(codes.PermissionDenied, "custom identity permission denied error")
	s := NewServer(ServerConfig{
		Lookup: &fakeLookup{},
		Identity: func(ctx context.Context) (string, time.Time, error) {
			return "", time.Time{}, expectedErr
		},
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	grpcServer := grpc.NewServer()
	portalsv1.RegisterNodeStreamServiceServer(grpcServer, s)
	go func() { _ = grpcServer.Serve(l) }()
	defer grpcServer.Stop()

	conn, err := grpc.Dial(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	client := portalsv1.NewNodeStreamServiceClient(conn)
	stream, err := client.Stream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, recvErr := stream.Recv()
	if recvErr == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(recvErr)
	if !ok || st.Code() != codes.PermissionDenied || st.Message() != "custom identity permission denied error" {
		t.Fatalf("expected exact error %v, got %v", expectedErr, recvErr)
	}
}

// 16. More pushes for one pod than the queue holds: all arrive, in order.
func TestPush_MorePushesThanQueueHolds_AllArriveInOrder(t *testing.T) {
	lookup := &fakeLookup{}
	lookup.set("pod-large-queue", "node-1")
	s, client := startTestServer(t, lookup, time.Minute)

	const count = 100
	for i := 0; i < count; i++ {
		push := &portalsv1.ControllerPush{
			PushId: fmt.Sprintf("queue-push-%03d", i),
			Action: &portalsv1.ControllerPush_Policy{
				Policy: &portalsv1.PodPolicy{
					PodUid:   "pod-large-queue",
					Identity: fmt.Sprintf("user-%d", i),
				},
			},
		}
		if _, err := s.Push(t.Context(), push, false); err != nil {
			t.Fatalf("push %d failed: %v", i, err)
		}
	}

	stream, cancel := openStream(t, client, "node-1", "")
	defer cancel()

	if err := stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: []string{"pod-large-queue"}},
		},
	}); err != nil {
		t.Fatalf("send declaration failed: %v", err)
	}

	for i := 0; i < count; i++ {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatalf("failed to recv push %d: %v", i, err)
		}
		expectedID := fmt.Sprintf("queue-push-%03d", i)
		if got := msg.GetPush().GetPushId(); got != expectedID {
			t.Fatalf("out of order at %d: expected %s, got %s", i, expectedID, got)
		}
	}
}

// TestTimeout_ServerToControllerDeadlineExceeded verifies that when a wait times out
// in the routing core (Server.Push), the client-facing Controller translates the ErrTimeout
// to codes.DeadlineExceeded because errors.Is(err, context.DeadlineExceeded) is true.
func TestTimeout_ServerToControllerDeadlineExceeded(t *testing.T) {
	s := NewServer(ServerConfig{
		Lookup:      &fakeLookup{},
		Identity:    fakeIdentity,
		PushTimeout: 50 * time.Millisecond,
	})

	auth, err := NewAuthenticator(AuthenticatorConfig{
		Audience:         testAudience,
		NodeAgentAccount: testNodeAgent,
		ClientAllowlist:  []string{testClientSA},
		TokenReviews: &fakeTokenReviews{
			reviewFn: func(ctx context.Context, tr *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
				return &authenticationv1.TokenReview{
					Status: authenticationv1.TokenReviewStatus{
						Authenticated: true,
						Audiences:     []string{testAudience},
						User: authenticationv1.UserInfo{
							Username: testClientSA,
						},
					},
				}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	ctrl, err := NewController(auth, s)
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}

	ctx := incomingCtx("valid-token")
	_, err = ctrl.Bind(ctx, &portalsv1.PodPolicy{
		PodUid: "pod-timeout-test",
		Policy: &portalsv1.EgressPolicy{},
		Wait:   true,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("expected codes.DeadlineExceeded, got %v: %v", status.Code(err), err)
	}
}
