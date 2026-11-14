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
