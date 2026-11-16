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

package portalsv1

import (
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestPodSecrets_FmtRedaction(t *testing.T) {
	const secretToken = "ghp_super_secret_token_12345"
	secrets := &PodSecrets{
		PodUid: "pod-1234",
		Secrets: map[string][]byte{
			"github-token": []byte(secretToken),
		},
	}

	// Verify that the proto descriptor marks the secrets field with debug_redact = true.
	fd := secrets.ProtoReflect().Descriptor().Fields().ByName("secrets")
	if fd == nil {
		t.Fatal("secrets field not found in PodSecrets descriptor")
	}
	opts, ok := fd.Options().(*descriptorpb.FieldOptions)
	if !ok || !opts.GetDebugRedact() {
		t.Errorf("expected secrets field to have debug_redact = true, got %v", opts.GetDebugRedact())
	}

	// Verify that formatting with fmt verbs does not leak secret token bytes.
	for _, text := range []string{
		fmt.Sprint(secrets),
		fmt.Sprintf("%v", secrets),
		fmt.Sprintf("%+v", secrets),
		fmt.Sprintf("%s", secrets),
	} {
		if strings.Contains(text, secretToken) {
			t.Errorf("fmt verb output of PodSecrets (%q) leaked secret token", text)
		}
		if !strings.Contains(text, "[REDACTED]") {
			t.Errorf("fmt verb output of PodSecrets (%q) expected [REDACTED]", text)
		}
	}
}

func TestControllerPush_FmtRedaction(t *testing.T) {
	const secretToken = "ghp_controller_push_super_secret_token_99999"
	push := &ControllerPush{
		PushId: "push-001",
		Action: &ControllerPush_Secrets{
			Secrets: &PodSecrets{
				PodUid: "pod-5678",
				Secrets: map[string][]byte{
					"anthropic-key": []byte(secretToken),
				},
			},
		},
	}

	// Verify that the proto descriptor marks the secrets field in ControllerPush with debug_redact = true.
	fd := push.ProtoReflect().Descriptor().Fields().ByName("secrets")
	if fd == nil {
		t.Fatal("secrets field not found in ControllerPush descriptor")
	}
	opts, ok := fd.Options().(*descriptorpb.FieldOptions)
	if !ok || !opts.GetDebugRedact() {
		t.Errorf("expected secrets field in ControllerPush to have debug_redact = true, got %v", opts.GetDebugRedact())
	}

	// Verify that formatting ControllerPush with fmt verbs does not leak secret token bytes.
	for _, text := range []string{
		fmt.Sprint(push),
		fmt.Sprintf("%v", push),
		fmt.Sprintf("%+v", push),
		fmt.Sprintf("%s", push),
	} {
		if strings.Contains(text, secretToken) {
			t.Errorf("fmt verb output of ControllerPush (%q) leaked secret token", text)
		}
		if !strings.Contains(text, "[REDACTED]") {
			t.Errorf("fmt verb output of ControllerPush (%q) expected [REDACTED]", text)
		}
	}

	// Verify ControllerMessage wrapping ControllerPush also redacts secret token bytes.
	msg := &ControllerMessage{
		Payload: &ControllerMessage_Push{
			Push: push,
		},
	}
	for _, text := range []string{
		fmt.Sprint(msg),
		fmt.Sprintf("%v", msg),
		fmt.Sprintf("%+v", msg),
		fmt.Sprintf("%s", msg),
	} {
		if strings.Contains(text, secretToken) {
			t.Errorf("fmt verb output of ControllerMessage (%q) leaked secret token", text)
		}
		if !strings.Contains(text, "[REDACTED]") {
			t.Errorf("fmt verb output of ControllerMessage (%q) expected [REDACTED]", text)
		}
	}
}

func TestStoredBinding_FmtRedaction(t *testing.T) {
	const secretToken = "ghp_stored_binding_secret_token_88888"
	stored := &StoredBinding{
		PodUid:   "pod-stored-1",
		Identity: "user@example.com",
		Secrets: map[string][]byte{
			"gh-token": []byte(secretToken),
		},
		Bound: true,
	}

	// Verify that the proto descriptor marks the secrets field with debug_redact = true.
	fd := stored.ProtoReflect().Descriptor().Fields().ByName("secrets")
	if fd == nil {
		t.Fatal("secrets field not found in StoredBinding descriptor")
	}
	opts, ok := fd.Options().(*descriptorpb.FieldOptions)
	if !ok || !opts.GetDebugRedact() {
		t.Errorf("expected secrets field to have debug_redact = true, got %v", opts.GetDebugRedact())
	}

	// Verify formatting with fmt verbs does not leak secret token bytes.
	for _, text := range []string{
		fmt.Sprint(stored),
		fmt.Sprintf("%v", stored),
		fmt.Sprintf("%+v", stored),
		fmt.Sprintf("%s", stored),
	} {
		if strings.Contains(text, secretToken) {
			t.Errorf("fmt verb output of StoredBinding (%q) leaked secret token", text)
		}
		if !strings.Contains(text, "[REDACTED]") {
			t.Errorf("fmt verb output of StoredBinding (%q) expected [REDACTED]", text)
		}
	}
}

func TestMessages_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  proto.Message
	}{
		{
			name: "PodDeclaration",
			msg: &PodDeclaration{
				PodUids: []string{"pod-1", "pod-2", "pod-3"},
			},
		},
		{
			name: "PodUpdate",
			msg: &PodUpdate{
				AddedPodUids:   []string{"pod-4", "pod-5"},
				RemovedPodUids: []string{"pod-1"},
			},
		},
		{
			name: "PushAnswer_Accepted",
			msg: &PushAnswer{
				PushId: "push-123",
				PodUid: "pod-1",
				Status: AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
			},
		},
		{
			name: "PushAnswer_Pending",
			msg: &PushAnswer{
				PushId:         "push-124",
				PodUid:         "pod-2",
				Status:         AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
				MissingSecrets: []string{"github-token", "api-key"},
			},
		},
		{
			name: "PushAnswer_Refused",
			msg: &PushAnswer{
				PushId:        "push-125",
				PodUid:        "pod-3",
				Status:        AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED,
				RefusalReason: "egress policy syntax error: invalid hostname pattern",
			},
		},
		{
			name: "NodeMessage_Declaration",
			msg: &NodeMessage{
				Payload: &NodeMessage_Declaration{
					Declaration: &PodDeclaration{
						PodUids: []string{"pod-1", "pod-2"},
					},
				},
			},
		},
		{
			name: "NodeMessage_Update",
			msg: &NodeMessage{
				Payload: &NodeMessage_Update{
					Update: &PodUpdate{
						AddedPodUids:   []string{"pod-3"},
						RemovedPodUids: []string{"pod-1"},
					},
				},
			},
		},
		{
			name: "NodeMessage_Answer",
			msg: &NodeMessage{
				Payload: &NodeMessage_Answer{
					Answer: &PushAnswer{
						PushId: "push-456",
						PodUid: "pod-3",
						Status: AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
					},
				},
			},
		},
		{
			name: "ControllerPush_Policy",
			msg: &ControllerPush{
				PushId: "push-policy-1",
				Action: &ControllerPush_Policy{
					Policy: &PodPolicy{
						PodUid:   "pod-1",
						Identity: "user@example.com",
						Policy: &EgressPolicy{
							Rules: []*EgressRule{
								{
									Http: &HttpRule{
										Hostnames: []string{"api.example.com"},
									},
								},
							},
						},
						Wait: true,
					},
				},
			},
		},
		{
			name: "ControllerPush_Secrets",
			msg: &ControllerPush{
				PushId: "push-secrets-1",
				Action: &ControllerPush_Secrets{
					Secrets: &PodSecrets{
						PodUid: "pod-1",
						Secrets: map[string][]byte{
							"token": []byte("test-token-bytes"),
						},
						Wait: true,
					},
				},
			},
		},
		{
			name: "ControllerPush_Unbind",
			msg: &ControllerPush{
				PushId: "push-unbind-1",
				Action: &ControllerPush_Unbind{
					Unbind: &UnbindRequest{
						PodUid: "pod-1",
						Wait:   true,
					},
				},
			},
		},
		{
			name: "ControllerMessage_Push",
			msg: &ControllerMessage{
				Payload: &ControllerMessage_Push{
					Push: &ControllerPush{
						PushId: "push-controller-1",
						Action: &ControllerPush_Policy{
							Policy: &PodPolicy{
								PodUid: "pod-9",
								Wait:   true,
							},
						},
					},
				},
			},
		},
		{
			name: "PodPolicy_Wait",
			msg: &PodPolicy{
				PodUid:   "pod-client-1",
				Identity: "service-account@iam",
				Wait:     true,
			},
		},
		{
			name: "PodSecrets_Wait",
			msg: &PodSecrets{
				PodUid: "pod-client-2",
				Secrets: map[string][]byte{
					"key": []byte("value"),
				},
				Wait: true,
			},
		},
		{
			name: "UnbindRequest_Wait",
			msg: &UnbindRequest{
				PodUid: "pod-client-3",
				Wait:   true,
			},
		},
		{
			name: "BindResponse_Acceptance",
			msg: &BindResponse{
				PodUid:        "pod-1",
				Bound:         true,
				Status:        AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
				RefusalReason: "",
			},
		},
		{
			name: "InjectSecretsResponse_Acceptance",
			msg: &InjectSecretsResponse{
				PodUid:        "pod-2",
				Status:        AcceptanceStatus_ACCEPTANCE_STATUS_PENDING,
				RefusalReason: "",
			},
		},
		{
			name: "UnbindResponse_Acceptance",
			msg: &UnbindResponse{
				PodUid:        "pod-3",
				Bound:         false,
				Status:        AcceptanceStatus_ACCEPTANCE_STATUS_ACCEPTED,
				RefusalReason: "",
			},
		},
		{
			name: "GetResponse_Acceptance",
			msg: &GetResponse{
				PodUid:        "pod-4",
				Namespace:     "default",
				Name:          "sandbox-pod",
				Ips:           []string{"10.0.0.1"},
				Identity:      "test-id",
				Bound:         true,
				Status:        AcceptanceStatus_ACCEPTANCE_STATUS_REFUSED,
				RefusalReason: "node rejected binding",
			},
		},
		{
			name: "StoredBinding",
			msg: &StoredBinding{
				PodUid:   "pod-5",
				Identity: "user@test.org",
				Policy: &EgressPolicy{
					Rules: []*EgressRule{
						{
							Https: &HttpsRule{
								Hostnames: []string{"api.github.com"},
							},
						},
					},
				},
				Secrets: map[string][]byte{
					"key": []byte("val"),
				},
				Bound: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := proto.Marshal(tt.msg)
			if err != nil {
				t.Fatalf("proto.Marshal failed: %v", err)
			}

			// Create a new instance of the same concrete type for unmarshaling.
			cloned := tt.msg.ProtoReflect().New().Interface()
			if err := proto.Unmarshal(data, cloned); err != nil {
				t.Fatalf("proto.Unmarshal failed: %v", err)
			}

			if !proto.Equal(tt.msg, cloned) {
				t.Errorf("round-trip mismatch:\nwant: %+v\ngot:  %+v", tt.msg, cloned)
			}
		})
	}
}
