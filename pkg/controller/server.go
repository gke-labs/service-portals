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
	"log"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const defaultPushTimeout = time.Minute

// ErrTimeout indicates a push timed out before being accepted by the node.
var ErrTimeout = fmt.Errorf("timed out waiting for node acceptance: %w", context.DeadlineExceeded)

// PodLookup returns the node running the specified pod UID.
type PodLookup interface {
	NodeForPod(ctx context.Context, podUID string) (string, error)
}

// IdentityFunc resolves the authenticated node and credential expiry for a stream.
type IdentityFunc func(ctx context.Context) (node string, expiry time.Time, err error)

// ServerConfig configures the Server.
type ServerConfig struct {
	Lookup      PodLookup
	Identity    IdentityFunc
	PushTimeout time.Duration
}

type pendingPush struct {
	push       *portalsv1.ControllerPush
	podUID     string
	sentStream *nodeStream
	sentNode   string
	dropped    bool
	timer      *time.Timer
	answerCh   chan *portalsv1.PushAnswer
}

type nodeStream struct {
	node   string
	sendCh chan *pendingPush
	done   chan struct{}
	pods   map[string]bool
}

// Server serves NodeStreamService and routes pushes to pods' nodes.
type Server struct {
	portalsv1.UnimplementedNodeStreamServiceServer
	lookup      PodLookup
	identity    IdentityFunc
	pushTimeout time.Duration

	mu      sync.Mutex
	nodes   map[string]*nodeStream
	pending map[string][]*pendingPush
	byID    map[string]*pendingPush
	nextID  uint64
}

// NewServer creates a new Server.
func NewServer(cfg ServerConfig) *Server {
	timeout := cfg.PushTimeout
	if timeout <= 0 {
		timeout = defaultPushTimeout
	}
	return &Server{
		lookup:      cfg.Lookup,
		identity:    cfg.Identity,
		pushTimeout: timeout,
		nodes:       make(map[string]*nodeStream),
		pending:     make(map[string][]*pendingPush),
		byID:        make(map[string]*pendingPush),
	}
}

func (s *Server) Stream(stream portalsv1.NodeStreamService_StreamServer) error {
	node, expiry, err := s.identity(stream.Context())
	if err != nil {
		return err
	}
	if node == "" {
		return status.Error(codes.Unauthenticated, "missing node identity")
	}

	ctx := stream.Context()
	if !expiry.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, expiry)
		defer cancel()
	}

	ns := &nodeStream{node: node, sendCh: make(chan *pendingPush, 64), done: make(chan struct{}), pods: make(map[string]bool)}
	s.mu.Lock()
	if old, ok := s.nodes[node]; ok {
		close(old.done)
		s.resetStreamLocked(old)
	}
	s.nodes[node] = ns
	s.mu.Unlock()
	log.Printf("controller: node %s stream connected", node)

	defer func() {
		s.mu.Lock()
		if s.nodes[node] == ns {
			delete(s.nodes, node)
			s.resetStreamLocked(ns)
		}
		s.mu.Unlock()
		log.Printf("controller: node %s stream disconnected", node)
	}()

	errCh := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			s.handleMessage(ns, msg)
		}
	}()

	for {
		select {
		case <-ns.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case p := <-ns.sendCh:
			s.mu.Lock()
			dropped, push := p.dropped || p.sentStream != ns, p.push
			s.mu.Unlock()
			if !dropped && push != nil {
				if err := stream.Send(&portalsv1.ControllerMessage{Payload: &portalsv1.ControllerMessage_Push{Push: push}}); err != nil {
					return err
				}
			}
			s.deliverPod(p.podUID)
			s.mu.Lock()
			var other string
			for uid := range s.pending {
				if uid != p.podUID && ns.pods[uid] {
					other = uid
					break
				}
			}
			s.mu.Unlock()
			if other != "" {
				s.deliverPod(other)
			}
		}
	}
}

func (s *Server) resetStreamLocked(ns *nodeStream) {
	for _, pushes := range s.pending {
		for _, p := range pushes {
			if p.sentStream == ns {
				p.sentStream = nil
			}
		}
	}
}

func (s *Server) handleMessage(ns *nodeStream, msg *portalsv1.NodeMessage) {
	var uids []string
	s.mu.Lock()
	switch p := msg.GetPayload().(type) {
	case *portalsv1.NodeMessage_Declaration:
		if s.nodes[ns.node] == ns {
			ns.pods = make(map[string]bool, len(p.Declaration.GetPodUids()))
			for _, uid := range p.Declaration.GetPodUids() {
				ns.pods[uid] = true
				if len(s.pending[uid]) > 0 {
					uids = append(uids, uid)
				}
			}
		}
	case *portalsv1.NodeMessage_Update:
		if s.nodes[ns.node] == ns {
			for _, uid := range p.Update.GetAddedPodUids() {
				ns.pods[uid] = true
				if len(s.pending[uid]) > 0 {
					uids = append(uids, uid)
				}
			}
			for _, uid := range p.Update.GetRemovedPodUids() {
				delete(ns.pods, uid)
			}
		}
	case *portalsv1.NodeMessage_Answer:
		ans := p.Answer
		cur := s.byID[ans.GetPushId()]
		if cur != nil && cur.sentStream == ns && s.nodes[ns.node] == ns && ans.GetPodUid() == cur.podUID {
			s.dropPendingLocked(cur)
			select {
			case cur.answerCh <- ans:
			default:
			}
			log.Printf("controller: pod %s node %s: outcome %s", ans.GetPodUid(), ns.node, ans.GetStatus())
		}
	}
	s.mu.Unlock()
	for _, uid := range uids {
		s.deliverPod(uid)
	}
}

// PodChanged notifies the server that a pod's lookup information changed.
func (s *Server) PodChanged(podUID string) {
	s.deliverPod(podUID)
}

func (s *Server) Push(ctx context.Context, push *portalsv1.ControllerPush, wait bool) (*portalsv1.PushAnswer, error) {
	uid := podUID(push)
	if uid == "" {
		return nil, errors.New("missing pod UID")
	}
	if push.GetPushId() == "" {
		push.PushId = fmt.Sprintf("push-%d", atomic.AddUint64(&s.nextID, 1))
	}
	p := &pendingPush{push: push, podUID: uid, answerCh: make(chan *portalsv1.PushAnswer, 1)}
	p.timer = time.AfterFunc(s.pushTimeout, func() {
		s.mu.Lock()
		if !p.dropped {
			s.dropPendingLocked(p)
			select {
			case p.answerCh <- nil:
			default:
			}
			log.Printf("controller: pod %s node %s: outcome timed out", p.podUID, p.sentNode)
		}
		s.mu.Unlock()
	})

	s.mu.Lock()
	s.pending[uid] = append(s.pending[uid], p)
	s.byID[push.GetPushId()] = p
	s.mu.Unlock()

	s.deliverPod(uid)

	if !wait {
		return &portalsv1.PushAnswer{PushId: push.GetPushId(), PodUid: uid, Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING}, nil
	}
	select {
	case ans := <-p.answerCh:
		if ans == nil {
			return nil, ErrTimeout
		}
		return ans, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Server) deliverPod(podUID string) {
	s.mu.Lock()
	if len(s.pending[podUID]) == 0 {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	node, err := s.lookup.NodeForPod(context.Background(), podUID)
	if err != nil || node == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	ns, ok := s.nodes[node]
	if !ok || !ns.pods[podUID] {
		return
	}
	for _, p := range s.pending[podUID] {
		if p.sentStream == nil && !p.dropped {
			select {
			case ns.sendCh <- p:
				p.sentStream = ns
				p.sentNode = node
			default:
				return
			}
		}
	}
}

func (s *Server) dropPendingLocked(p *pendingPush) {
	p.dropped = true
	p.timer.Stop()
	if p.push != nil {
		delete(s.byID, p.push.GetPushId())
		p.push = nil
	}
	s.pending[p.podUID] = slices.DeleteFunc(s.pending[p.podUID], func(cur *pendingPush) bool { return cur == p })
	if len(s.pending[p.podUID]) == 0 {
		delete(s.pending, p.podUID)
	}
}

func podUID(p *portalsv1.ControllerPush) string {
	switch a := p.GetAction().(type) {
	case *portalsv1.ControllerPush_Policy:
		return a.Policy.GetPodUid()
	case *portalsv1.ControllerPush_Secrets:
		return a.Secrets.GetPodUid()
	case *portalsv1.ControllerPush_Unbind:
		return a.Unbind.GetPodUid()
	}
	return ""
}
