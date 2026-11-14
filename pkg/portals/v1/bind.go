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
	"io"
	"sort"
	"strings"
)

// Format implements fmt.Formatter so secret token bytes are redacted when
// formatted with fmt verbs (e.g. %v, %+v, %s).
//
// Note: protobuf-go does not honour debug_redact in String() or prototext, so
// PodSecrets must never be logged or passed to a logger as a value; Format only
// covers fmt verbs.
func (x *PodSecrets) Format(f fmt.State, c rune) {
	var b strings.Builder
	if x == nil {
		b.WriteString("<nil>")
	} else {
		fmt.Fprintf(&b, "pod_uid:%q", x.GetPodUid())
		if len(x.GetSecrets()) > 0 {
			keys := make([]string, 0, len(x.GetSecrets()))
			for k := range x.GetSecrets() {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteString(" secrets:{")
			for i, k := range keys {
				if i > 0 {
					b.WriteString(" ")
				}
				fmt.Fprintf(&b, "%s:[REDACTED]", k)
			}
			b.WriteString("}")
		}
	}
	if _, err := io.WriteString(f, b.String()); err != nil {
		return
	}
}
