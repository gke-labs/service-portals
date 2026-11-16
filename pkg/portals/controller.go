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

package portals

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type controllerClientConfig struct {
	addr       string
	tokenPath  string
	caCertPath string
	pm         *PodMap
	store      *portalsv1.BindingStore
}

func runControllerClient(ctx context.Context, cfg controllerClientConfig) {
	creds, err := credentials.NewClientTLSFromFile(cfg.caCertPath, "")
	if err != nil {
		log.Printf("controller: failed to load CA cert from %s: %v", cfg.caCertPath, err)
		return
	}

	conn, err := grpc.NewClient(cfg.addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Printf("controller: failed to create gRPC client: %v", err)
		return
	}
	defer func() {
		if cErr := conn.Close(); cErr != nil {
			log.Printf("warning: closing controller connection: %v", cErr)
		}
	}()

	client := portalsv1.NewNodeStreamServiceClient(conn)
	changeCh := make(chan struct{}, 1)
	unwatch := cfg.pm.Watch(changeCh)
	defer unwatch()

	backoff := 50 * time.Millisecond
	maxBackoff := 5 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		tokenBytes, err := os.ReadFile(cfg.tokenPath)
		if err != nil {
			log.Printf("controller: failed to read token file: %v", err)
			sleepBackoff(ctx, &backoff, maxBackoff)
			continue
		}
		token := strings.TrimSpace(string(tokenBytes))

		streamCtx, cancel := context.WithCancel(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token))
		stream, err := client.Stream(streamCtx)
		if err != nil {
			cancel()
			log.Printf("controller: failed to open stream: %v", err)
			sleepBackoff(ctx, &backoff, maxBackoff)
			continue
		}

	drain:
		for {
			select {
			case <-changeCh:
			default:
				break drain
			}
		}

		if err := sendDeclaration(stream, cfg.pm); err != nil {
			cancel()
			log.Printf("controller: failed to send declaration: %v", err)
			sleepBackoff(ctx, &backoff, maxBackoff)
			continue
		}

		backoff = 50 * time.Millisecond
		err = handleStream(streamCtx, stream, cfg, changeCh)
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Printf("controller: stream ended: %v", err)
			sleepBackoff(ctx, &backoff, maxBackoff)
		}
	}
}

func sendDeclaration(stream portalsv1.NodeStreamService_StreamClient, pm *PodMap) error {
	return stream.Send(&portalsv1.NodeMessage{
		Payload: &portalsv1.NodeMessage_Declaration{
			Declaration: &portalsv1.PodDeclaration{PodUids: pm.PodUIDs()},
		},
	})
}

func sleepBackoff(ctx context.Context, backoff *time.Duration, max time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(*backoff):
	}
	if *backoff *= 2; *backoff > max {
		*backoff = max
	}
}

func handleStream(ctx context.Context, stream portalsv1.NodeStreamService_StreamClient, cfg controllerClientConfig, changeCh <-chan struct{}) error {
	ansCh := make(chan *portalsv1.PushAnswer, 64)
	errCh := make(chan error, 1)

	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			push := msg.GetPush()
			if push == nil {
				continue
			}
			ans := handlePush(cfg.pm, cfg.store, push)
			select {
			case ansCh <- ans:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case <-changeCh:
			if err := sendDeclaration(stream, cfg.pm); err != nil {
				return err
			}
		case ans := <-ansCh:
			if err := stream.Send(&portalsv1.NodeMessage{
				Payload: &portalsv1.NodeMessage_Answer{Answer: ans},
			}); err != nil {
				return err
			}
		}
	}
}

func extractPodUID(push *portalsv1.RelayPush) string {
	switch act := push.GetAction().(type) {
	case *portalsv1.RelayPush_Policy:
		if act.Policy != nil {
			return act.Policy.GetPodUid()
		}
	case *portalsv1.RelayPush_Secrets:
		if act.Secrets != nil {
			return act.Secrets.GetPodUid()
		}
	case *portalsv1.RelayPush_Unbind:
		if act.Unbind != nil {
			return act.Unbind.GetPodUid()
		}
	}
	return ""
}

func handlePush(pm *PodMap, store *portalsv1.BindingStore, push *portalsv1.RelayPush) *portalsv1.PushAnswer {
	podUID := extractPodUID(push)
	if podUID == "" {
		return pushRefused(push.GetPushId(), "", "missing pod UID")
	}
	if !pm.HasPod(podUID) {
		return pushRefused(push.GetPushId(), podUID, fmt.Sprintf("pod %q not found on node", podUID))
	}

	ctx := context.Background()
	var err error
	switch act := push.GetAction().(type) {
	case *portalsv1.RelayPush_Policy:
		_, err = store.Bind(ctx, act.Policy)
	case *portalsv1.RelayPush_Secrets:
		_, err = store.InjectSecrets(ctx, act.Secrets)
	case *portalsv1.RelayPush_Unbind:
		if _, err = store.Unbind(ctx, act.Unbind); err == nil {
			log.Printf("controller push %s for pod %s: accepted unbind", push.GetPushId(), podUID)
			return &portalsv1.PushAnswer{PushId: push.GetPushId(), PodUid: podUID, Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED}
		}
	}
	if err != nil {
		return pushRefused(push.GetPushId(), podUID, status.Convert(err).Message())
	}
	accStatus, missing := store.Acceptance(podUID)
	log.Printf("controller push %s for pod %s: %s", push.GetPushId(), podUID, accStatus)
	return &portalsv1.PushAnswer{PushId: push.GetPushId(), PodUid: podUID, Status: accStatus, MissingSecrets: missing}
}

func pushRefused(pushID, podUID, reason string) *portalsv1.PushAnswer {
	log.Printf("controller push %s for pod %s: refused (%s)", pushID, podUID, reason)
	return &portalsv1.PushAnswer{PushId: pushID, PodUid: podUID, Status: portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED, RefusalReason: reason}
}
