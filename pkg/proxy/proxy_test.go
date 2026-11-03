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

package proxy

import "testing"

func TestHostWithoutPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "host with port",
			host: "example.com:8080",
			want: "example.com",
		},
		{
			name: "host without port",
			host: "example.com",
			want: "example.com",
		},
		{
			name: "ipv4 with port",
			host: "127.0.0.1:443",
			want: "127.0.0.1",
		},
		{
			name: "ipv4 without port",
			host: "127.0.0.1",
			want: "127.0.0.1",
		},
		{
			name: "ipv6 with port",
			host: "[::1]:8443",
			want: "::1",
		},
		{
			name: "ipv6 without port",
			host: "::1",
			want: "::1",
		},
		{
			name: "empty string",
			host: "",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := HostWithoutPort(tc.host)
			if got != tc.want {
				t.Errorf("HostWithoutPort(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

func TestMatchHosts(t *testing.T) {
	tests := []struct {
		name          string
		innerHost     string
		connectTarget string
		want          bool
	}{
		{
			name:          "exact match without port",
			innerHost:     "example.com",
			connectTarget: "example.com",
			want:          true,
		},
		{
			name:          "case insensitive match",
			innerHost:     "Example.COM",
			connectTarget: "example.com",
			want:          true,
		},
		{
			name:          "inner without port matches connect target with standard 443",
			innerHost:     "example.com",
			connectTarget: "example.com:443",
			want:          true,
		},
		{
			name:          "inner without port matches connect target with standard 80",
			innerHost:     "example.com",
			connectTarget: "example.com:80",
			want:          true,
		},
		{
			name:          "both match with port",
			innerHost:     "example.com:8443",
			connectTarget: "example.com:8443",
			want:          true,
		},
		{
			name:          "port mismatch",
			innerHost:     "example.com:8443",
			connectTarget: "example.com:443",
			want:          false,
		},
		{
			name:          "inner without port does not match non-standard connect port",
			innerHost:     "example.com",
			connectTarget: "example.com:8443",
			want:          false,
		},
		{
			name:          "hostname mismatch",
			innerHost:     "attacker.com",
			connectTarget: "example.com:443",
			want:          false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchHosts(tc.innerHost, tc.connectTarget)
			if got != tc.want {
				t.Errorf("MatchHosts(%q, %q) = %v, want %v", tc.innerHost, tc.connectTarget, got, tc.want)
			}
		})
	}
}
