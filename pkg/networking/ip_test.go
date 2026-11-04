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

package networking

import (
	"testing"
)

func TestParsePeerIndex(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		expectedIdx int
		expectErr   bool
	}{
		{
			name: "standard veth link output",
			output: `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default \    link/ether 02:42:0a:f4:00:06 brd ff:ff:ff:ff:ff:ff link-netnsid 0`,
			expectedIdx: 12,
			expectErr:   false,
		},
		{
			name: "output with peer index 3",
			output: `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
4: veth0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default \    link/ether 02:42:0a:f4:00:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0`,
			expectedIdx: 3,
			expectErr:   false,
		},
		{
			name:        "empty output",
			output:      "",
			expectedIdx: 0,
			expectErr:   true,
		},
		{
			name:        "only loopback interface",
			output:      `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00`,
			expectedIdx: 0,
			expectErr:   true,
		},
		{
			name:        "interface without @if",
			output:      `1: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default \    link/ether 02:42:0a:f4:00:06 brd ff:ff:ff:ff:ff:ff`,
			expectedIdx: 0,
			expectErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idx, err := ParsePeerIndex(tc.output)
			if tc.expectErr && err == nil {
				t.Fatalf("expected error, got nil index %d", idx)
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if idx != tc.expectedIdx {
				t.Errorf("expected peer index %d, got %d", tc.expectedIdx, idx)
			}
		})
	}
}

func TestParsePodIPv4(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		expectedIP string
	}{
		{
			name: "standard ip addr output",
			output: `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth0    inet 10.244.0.6/24 brd 10.244.0.255 scope global eth0\       valid_lft forever preferred_lft forever`,
			expectedIP: "10.244.0.6",
		},
		{
			name:       "empty output",
			output:     "",
			expectedIP: "",
		},
		{
			name: "no inet address on eth0",
			output: `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth0    inet6 fe80::42:aff:fef4:6/64 scope link \       valid_lft forever preferred_lft forever`,
			expectedIP: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := ParsePodIPv4(tc.output)
			if ip != tc.expectedIP {
				t.Errorf("expected pod IP %q, got %q", tc.expectedIP, ip)
			}
		})
	}
}

func TestParseHostInterfaceFromHostLinks(t *testing.T) {
	hostLinkOutput := `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
11: veth04ae4f5@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master cbr0 state UP mode DEFAULT group default \    link/ether 8e:7b:42:01:23:45 brd ff:ff:ff:ff:ff:ff link-netns cni-12345
12: vethb9c6f2a@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master cbr0 state UP mode DEFAULT group default \    link/ether 9a:8b:7c:6d:5e:4f brd ff:ff:ff:ff:ff:ff link-netns 2408b066-51d1-44fe-9892-0b2a74cbf5e9`

	tests := []struct {
		name          string
		netnsBasename string
		expectedIface string
	}{
		{
			name:          "matching netns basename",
			netnsBasename: "2408b066-51d1-44fe-9892-0b2a74cbf5e9",
			expectedIface: "vethb9c6f2a",
		},
		{
			name:          "unmatched netns basename",
			netnsBasename: "nonexistent-netns",
			expectedIface: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iface := ParseHostInterfaceFromHostLinks(hostLinkOutput, tc.netnsBasename)
			if iface != tc.expectedIface {
				t.Errorf("expected host interface %q, got %q", tc.expectedIface, iface)
			}
		})
	}
}
