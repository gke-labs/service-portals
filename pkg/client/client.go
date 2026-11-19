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

// Package client provides a Go client for sandbox controllers to bind egress
// policies and inject credentials for sandbox pods via the Service Portal Controller.
//
// The client performs the complete binding sequence in a single operation (Bind):
// pushing the egress policy and any companion secrets synchronously, and returning
// success only when the node agent accepts all configurations.
//
// PodPolicy.identity is omitted from this client API because sandbox controllers
// do not require it. Workload identity is established through "Duck Identity"
// (the egress policy and secrets injected by the proxy, rather than credentials
// inside the pod), and caller identity is authenticated at the controller via
// Kubernetes projected service account tokens. The node agent and proxy resolve
// policy by pod UID and inject named secrets directly; identity is an optional
// informational field in the protobuf that is not used for credential resolution
// or enforcement.
package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// Options configures the Service Portal Controller client.
type Options struct {
	// ControllerAddr is the host:port address of the Service Portal Controller.
	ControllerAddr string
	// CAFile is the file path to the CA certificate verifying the controller's TLS certificate.
	CAFile string
	// TokenFile is the file path to the projected service account token.
	TokenFile string
}

func (o Options) validate() error {
	if o.ControllerAddr == "" {
		return errors.New("controller address is required")
	}
	if o.CAFile == "" {
		return errors.New("CA file is required")
	}
	if o.TokenFile == "" {
		return errors.New("token file is required")
	}
	return nil
}

// StatusError reports a pending or refused acceptance status from the Service Portal Controller.
type StatusError struct {
	Operation      string
	Status         portalsv1.AcceptanceStatus
	RefusalReason  string
	MissingSecrets []string
}

func (e *StatusError) Error() string {
	var parts []string
	if e.RefusalReason != "" {
		parts = append(parts, e.RefusalReason)
	}
	if len(e.MissingSecrets) > 0 {
		parts = append(parts, "missing secrets: "+strings.Join(e.MissingSecrets, ", "))
	}
	statusStr := "unknown"
	switch e.Status {
	case portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING:
		statusStr = "pending"
	case portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED:
		statusStr = "refused"
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%s %s", e.Operation, statusStr)
	}
	return fmt.Sprintf("%s %s: %s", e.Operation, statusStr, strings.Join(parts, ", "))
}

// Client communicates with the Service Portal Controller to bind egress policies and secrets.
type Client struct {
	conn      *grpc.ClientConn
	client    portalsv1.PodBindServiceClient
	tokenFile string
}

// New creates a new Client configured with opts.
func New(opts Options) (*Client, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	creds, err := credentials.NewClientTLSFromFile(opts.CAFile, "")
	if err != nil {
		return nil, fmt.Errorf("loading CA cert from %s: %w", opts.CAFile, err)
	}
	conn, err := grpc.NewClient(opts.ControllerAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("connecting to controller at %s: %w", opts.ControllerAddr, err)
	}
	return &Client{
		conn:      conn,
		client:    portalsv1.NewPodBindServiceClient(conn),
		tokenFile: opts.TokenFile,
	}, nil
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) authenticatedContext(ctx context.Context) (context.Context, error) {
	tokenBytes, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("reading token file: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token), nil
}

// Bind binds an egress policy and any companion secrets to the pod identified by podUID.
// It executes the complete binding sequence: pushing the policy, then pushing secrets
// if any are provided, and returning success only when the node agent's final answer is accepted.
// A pending answer after the policy push is expected only when secrets are about to be sent;
// a pending or refused final answer is returned as a *StatusError.
func (c *Client) Bind(ctx context.Context, podUID string, policy *portalsv1.EgressPolicy, secrets map[string][]byte) error {
	bindCtx, err := c.authenticatedContext(ctx)
	if err != nil {
		return err
	}

	bindResp, err := c.client.Bind(bindCtx, &portalsv1.PodPolicy{
		PodUid: podUID,
		Policy: policy,
		Wait:   true,
	})
	if err != nil {
		return fmt.Errorf("bind RPC failed: %w", err)
	}
	if bindResp == nil {
		return errors.New("bind response is nil")
	}

	switch bindResp.GetStatus() {
	case portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED:
		return &StatusError{
			Operation:     "bind",
			Status:        bindResp.GetStatus(),
			RefusalReason: bindResp.GetRefusalReason(),
		}
	case portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING:
		if len(secrets) == 0 {
			return &StatusError{
				Operation:      "bind",
				Status:         bindResp.GetStatus(),
				RefusalReason:  bindResp.GetRefusalReason(),
				MissingSecrets: bindResp.GetMissingSecrets(),
			}
		}
	case portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED:
		if len(secrets) == 0 {
			return nil
		}
	default:
		return fmt.Errorf("unexpected bind status: %v", bindResp.GetStatus())
	}

	// Policy push succeeded or is pending missing secrets; proceed to inject secrets.
	injectCtx, err := c.authenticatedContext(ctx)
	if err != nil {
		return err
	}

	injectResp, err := c.client.InjectSecrets(injectCtx, &portalsv1.PodSecrets{
		PodUid:  podUID,
		Secrets: secrets,
		Wait:    true,
	})
	if err != nil {
		return fmt.Errorf("inject secrets RPC failed: %w", err)
	}
	if injectResp == nil {
		return errors.New("inject secrets response is nil")
	}

	switch injectResp.GetStatus() {
	case portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED:
		return nil
	case portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED,
		portalsv1.AcceptanceStatus_ACCEPTANCE_STATUS_PENDING:
		return &StatusError{
			Operation:      "inject secrets",
			Status:         injectResp.GetStatus(),
			RefusalReason:  injectResp.GetRefusalReason(),
			MissingSecrets: injectResp.GetMissingSecrets(),
		}
	default:
		return fmt.Errorf("unexpected inject secrets status: %v", injectResp.GetStatus())
	}
}
