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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gke-labs/service-portals/pkg/portals"
	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"k8s.io/klog/v2"
)

func dialBindService(sockPath string) (*grpc.ClientConn, portalsv1.PodBindServiceClient, error) {
	conn, err := grpc.NewClient(
		"unix://"+sockPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dial bind service: %w", err)
	}
	return conn, portalsv1.NewPodBindServiceClient(conn), nil
}

func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "" {
		return nil, errors.New("file path cannot be empty")
	}
	if path == "-" {
		if stdin == nil {
			stdin = os.Stdin
		}
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

func withBindClient(ctx context.Context, sock string, fn func(context.Context, portalsv1.PodBindServiceClient) error) error {
	conn, client, err := dialBindService(sock)
	if err != nil {
		return fmt.Errorf("failed to connect to bind service: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			klog.V(4).Infof("error closing connection: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return fn(ctx, client)
}

func runBindServiceCommand(ctx context.Context, args []string, stdout io.Writer, stdin io.Reader) error {
	if len(args) == 0 {
		return errors.New("usage: portal-nri-plugin bind-service <bind|inject-secrets|get|unbind> [flags]")
	}
	switch args[0] {
	case "bind":
		return runBindServiceBind(ctx, args[1:], stdin)
	case "inject-secrets":
		return runBindServiceInjectSecrets(ctx, args[1:], stdin)
	case "get":
		return runBindServiceGet(ctx, args[1:], stdout)
	case "unbind":
		return runBindServiceUnbind(ctx, args[1:])
	default:
		return fmt.Errorf("unknown bind-service action %q; valid actions: bind, inject-secrets, get, unbind", args[0])
	}
}

func runBindServiceBind(ctx context.Context, args []string, stdin io.Reader) error {
	fs := flag.NewFlagSet("bind-service bind", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sock := fs.String("socket", portals.DefaultBindSocketPath, "Path to bind unix domain socket")
	uid := fs.String("uid", "", "Pod UID to bind")
	identity := fs.String("identity", "", "User identity")
	policyFile := fs.String("policy-file", "", "Path to protojson egress policy file (or - for stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uid == "" || *policyFile == "" {
		return errors.New("-uid and -policy-file are required")
	}
	data, err := readInput(*policyFile, stdin)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}
	policy := &portalsv1.EgressPolicy{}
	if err := protojson.Unmarshal(data, policy); err != nil {
		return fmt.Errorf("error unmarshaling egress policy: %w", err)
	}
	return withBindClient(ctx, *sock, func(ctx context.Context, client portalsv1.PodBindServiceClient) error {
		resp, err := client.Bind(ctx, &portalsv1.PodPolicy{PodUid: *uid, Identity: *identity, Policy: policy})
		if err != nil {
			return fmt.Errorf("bind failed: %s", status.Convert(err).Message())
		}
		log := klog.FromContext(ctx)
		log.Info("bound pod", "pod", resp.GetPodUid())
		return nil
	})
}

func runBindServiceInjectSecrets(ctx context.Context, args []string, stdin io.Reader) error {
	fs := flag.NewFlagSet("bind-service inject-secrets", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sock := fs.String("socket", portals.DefaultBindSocketPath, "Path to bind unix domain socket")
	uid := fs.String("uid", "", "Pod UID")
	secretsFile := fs.String("secrets-file", "", "Path to JSON secrets file (or - for stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uid == "" || *secretsFile == "" {
		return errors.New("-uid and -secrets-file are required")
	}
	data, err := readInput(*secretsFile, stdin)
	if err != nil {
		return fmt.Errorf("failed to read secrets file: %w", err)
	}
	var rawSecrets map[string]string
	if err := json.Unmarshal(data, &rawSecrets); err != nil {
		return errors.New("secrets file is not valid")
	}
	secrets := make(map[string][]byte, len(rawSecrets))
	for k, v := range rawSecrets {
		secrets[k] = []byte(v)
	}
	return withBindClient(ctx, *sock, func(ctx context.Context, client portalsv1.PodBindServiceClient) error {
		resp, err := client.InjectSecrets(ctx, &portalsv1.PodSecrets{PodUid: *uid, Secrets: secrets})
		if err != nil {
			return fmt.Errorf("inject secrets failed: %s", status.Convert(err).Message())
		}
		log := klog.FromContext(ctx)
		log.Info("injected secrets for pod", "pod", resp.GetPodUid())
		return nil
	})
}

func runBindServiceGet(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("bind-service get", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sock := fs.String("socket", portals.DefaultBindSocketPath, "Path to bind unix domain socket")
	uid := fs.String("uid", "", "Pod UID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uid == "" {
		return errors.New("-uid is required")
	}
	return withBindClient(ctx, *sock, func(ctx context.Context, client portalsv1.PodBindServiceClient) error {
		resp, err := client.Get(ctx, &portalsv1.GetRequest{PodUid: *uid})
		if err != nil {
			return fmt.Errorf("get failed: %s", status.Convert(err).Message())
		}
		m := protojson.MarshalOptions{Multiline: true, Indent: "  ", EmitDefaultValues: true}
		out, err := m.Marshal(resp)
		if err != nil {
			return fmt.Errorf("error marshaling get response: %w", err)
		}
		if _, err := fmt.Fprintln(stdout, string(out)); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	})
}

func runBindServiceUnbind(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("bind-service unbind", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sock := fs.String("socket", portals.DefaultBindSocketPath, "Path to bind unix domain socket")
	uid := fs.String("uid", "", "Pod UID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uid == "" {
		return errors.New("-uid is required")
	}
	return withBindClient(ctx, *sock, func(ctx context.Context, client portalsv1.PodBindServiceClient) error {
		resp, err := client.Unbind(ctx, &portalsv1.UnbindRequest{PodUid: *uid})
		if err != nil {
			return fmt.Errorf("unbind failed: %s", status.Convert(err).Message())
		}
		log := klog.FromContext(ctx)
		log.Info("unbound pod", "pod", resp.GetPodUid())
		return nil
	})
}
