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

package relay

import (
	"context"
	"errors"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog/v2"
)

// Core routes pushes for a pod to its node.
//
// When wait is requested, a timeout waiting for node acceptance is reported
// as an error for which errors.Is(err, context.DeadlineExceeded) is true.
type Core interface {
	Push(ctx context.Context, push *portalsv1.RelayPush, wait bool) (*portalsv1.PushAnswer, error)
}

// Controller serves PodBindService to clients, authorizing callers and routing pushes to nodes.
type Controller struct {
	portalsv1.UnimplementedPodBindServiceServer
	auth *Authenticator
	core Core
}

// NewController creates a new Controller.
func NewController(auth *Authenticator, core Core) (*Controller, error) {
	if auth == nil {
		return nil, errors.New("authenticator is required")
	}
	if core == nil {
		return nil, errors.New("routing core is required")
	}
	return &Controller{auth: auth, core: core}, nil
}

// Bind associates a pod UID with an identity and egress policy.
func (c *Controller) Bind(ctx context.Context, req *portalsv1.PodPolicy) (*portalsv1.BindResponse, error) {
	caller, err := c.auth.AuthorizeClient(ctx)
	if err != nil {
		return nil, err
	}
	method := methodOr(ctx, "Bind")
	if req == nil || req.GetPodUid() == "" {
		c.logOutcome(caller, method, "", "invalid argument: missing pod_uid")
		return nil, status.Error(codes.InvalidArgument, "pod_uid cannot be empty")
	}
	policy := req.GetPolicy()
	if policy == nil {
		c.logOutcome(caller, method, req.GetPodUid(), "invalid argument: policy cannot be nil")
		return nil, status.Error(codes.InvalidArgument, "policy cannot be nil")
	}
	if err := policy.Validate(); err != nil {
		c.logOutcome(caller, method, req.GetPodUid(), "invalid argument: "+err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	push := &portalsv1.RelayPush{Action: &portalsv1.RelayPush_Policy{Policy: req}}
	ans, err := c.push(ctx, caller, method, req.GetPodUid(), push, req.GetWait())
	if err != nil {
		return nil, err
	}

	bound := req.GetWait() && ans.GetStatus() != portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED
	return &portalsv1.BindResponse{
		PodUid:        req.GetPodUid(),
		Bound:         bound,
		Status:        ans.GetStatus(),
		RefusalReason: ans.GetRefusalReason(),
	}, nil
}

// InjectSecrets supplies named secrets for a pod UID, replacing any existing set.
func (c *Controller) InjectSecrets(ctx context.Context, req *portalsv1.PodSecrets) (*portalsv1.InjectSecretsResponse, error) {
	caller, err := c.auth.AuthorizeClient(ctx)
	if err != nil {
		return nil, err
	}
	method := methodOr(ctx, "InjectSecrets")
	if req == nil || req.GetPodUid() == "" {
		c.logOutcome(caller, method, "", "invalid argument: missing pod_uid")
		return nil, status.Error(codes.InvalidArgument, "pod_uid cannot be empty")
	}

	push := &portalsv1.RelayPush{Action: &portalsv1.RelayPush_Secrets{Secrets: req}}
	ans, err := c.push(ctx, caller, method, req.GetPodUid(), push, req.GetWait())
	if err != nil {
		return nil, err
	}

	return &portalsv1.InjectSecretsResponse{
		PodUid:        req.GetPodUid(),
		Status:        ans.GetStatus(),
		RefusalReason: ans.GetRefusalReason(),
	}, nil
}

// Unbind dissociates a pod UID, reverting it to fail-closed state.
func (c *Controller) Unbind(ctx context.Context, req *portalsv1.UnbindRequest) (*portalsv1.UnbindResponse, error) {
	caller, err := c.auth.AuthorizeClient(ctx)
	if err != nil {
		return nil, err
	}
	method := methodOr(ctx, "Unbind")
	if req == nil || req.GetPodUid() == "" {
		c.logOutcome(caller, method, "", "invalid argument: missing pod_uid")
		return nil, status.Error(codes.InvalidArgument, "pod_uid cannot be empty")
	}

	push := &portalsv1.RelayPush{Action: &portalsv1.RelayPush_Unbind{Unbind: req}}
	ans, err := c.push(ctx, caller, method, req.GetPodUid(), push, req.GetWait())
	if err != nil {
		return nil, err
	}

	return &portalsv1.UnbindResponse{
		PodUid:        req.GetPodUid(),
		Bound:         false,
		Status:        ans.GetStatus(),
		RefusalReason: ans.GetRefusalReason(),
	}, nil
}

// Get returns Unimplemented as state lives on the node, not on the controller.
func (c *Controller) Get(ctx context.Context, req *portalsv1.GetRequest) (*portalsv1.GetResponse, error) {
	caller, err := c.auth.AuthorizeClient(ctx)
	if err != nil {
		return nil, err
	}
	podUID := ""
	if req != nil {
		podUID = req.GetPodUid()
	}
	c.logOutcome(caller, methodOr(ctx, "Get"), podUID, "unimplemented")
	return nil, status.Error(codes.Unimplemented, "get is not implemented: state lives on the node")
}

func (c *Controller) push(ctx context.Context, caller, method, podUID string, push *portalsv1.RelayPush, wait bool) (*portalsv1.PushAnswer, error) {
	ans, err := c.core.Push(ctx, push, wait)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			c.logOutcome(caller, method, podUID, "timed out")
			return nil, status.Error(codes.DeadlineExceeded, "timed out waiting for node acceptance")
		}
		c.logOutcome(caller, method, podUID, "error: "+err.Error())
		return nil, status.Errorf(codes.Internal, "push failed: %v", err)
	}
	c.logOutcome(caller, method, podUID, outcomeFromAnswer(ans))
	return ans, nil
}

func (c *Controller) logOutcome(caller, method, podUID, outcome string) {
	if podUID != "" {
		klog.Infof("controller: %s for %s pod %s: %s", method, caller, podUID, outcome)
		return
	}
	klog.Infof("controller: %s for %s: %s", method, caller, outcome)
}

func outcomeFromAnswer(ans *portalsv1.PushAnswer) string {
	if ans == nil {
		return "unknown"
	}
	switch ans.GetStatus() {
	case portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED:
		return "accepted"
	case portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING:
		return "pending"
	case portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED:
		if r := ans.GetRefusalReason(); r != "" {
			return "refused: " + r
		}
		return "refused"
	default:
		return ans.GetStatus().String()
	}
}

func methodOr(ctx context.Context, fallback string) string {
	if m, ok := grpc.Method(ctx); ok && m != "" {
		return m
	}
	return fallback
}
