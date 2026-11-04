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
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

// ParsePeerIndex parses the peer interface index (@if<idx>) from "ip -o link show" output.
func ParsePeerIndex(output string) (int, error) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		nameField := strings.TrimSuffix(fields[1], ":")
		if nameField == "lo" || strings.HasPrefix(nameField, "lo@") {
			continue
		}
		if idx := strings.Index(nameField, "@if"); idx != -1 {
			pIdxStr := nameField[idx+3:]
			if pIdx, err := strconv.Atoi(pIdxStr); err == nil && pIdx > 0 {
				return pIdx, nil
			}
		}
	}
	return 0, fmt.Errorf("no peer interface found in ip link output")
}

// ParsePodIPv4 extracts the first non-loopback IPv4 address from "ip -o -4 addr show" output.
func ParsePodIPv4(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			nameField := strings.TrimSuffix(fields[1], ":")
			if nameField == "lo" || strings.HasPrefix(nameField, "lo@") {
				continue
			}
		}
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				cidr := fields[i+1]
				if ip, _, err := net.ParseCIDR(cidr); err == nil && !ip.IsLoopback() {
					return ip.String()
				}
			}
		}
	}
	return ""
}

// ParseHostInterfaceFromHostLinks matches a host-side interface to a pod's network namespace link.
func ParseHostInterfaceFromHostLinks(output, netnsBasename string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "link-netns "+netnsBasename) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				rawName := strings.TrimSuffix(fields[1], ":")
				if atIdx := strings.Index(rawName, "@"); atIdx != -1 {
					rawName = rawName[:atIdx]
				}
				if rawName != "" && rawName != "lo" {
					return rawName
				}
			}
		}
	}
	return ""
}

// FindHostInterface discovers the host-side peer interface and pod IPv4 address for a container netns.
func FindHostInterface(ctx context.Context, podIPs []string, netnsPath string) (string, string, error) {
	log := klog.FromContext(ctx)

	cmd := exec.Command("nsenter", "--net="+netnsPath, "ip", "-o", "link", "show")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("nsenter ip link show: %w (output: %s)", err, out)
	}

	var hostIface string
	if peerIndex, err := ParsePeerIndex(string(out)); err == nil && peerIndex > 0 {
		if iface, err := net.InterfaceByIndex(peerIndex); err == nil && iface.Name != "" {
			hostIface = iface.Name
		}
	}

	if hostIface == "" {
		base := filepath.Base(netnsPath)
		hCmd := exec.Command("ip", "-o", "link", "show")
		hOut, err := hCmd.CombinedOutput()
		if err != nil {
			log.V(1).Info("Host ip link show fallback query failed", "err", err)
		} else {
			hostIface = ParseHostInterfaceFromHostLinks(string(hOut), base)
		}
	}

	if hostIface == "" {
		return "", "", fmt.Errorf("could not identify host-side interface for netns %s", netnsPath)
	}

	var podIP string
	if len(podIPs) > 0 && podIPs[0] != "" {
		podIP = podIPs[0]
	}
	if podIP == "" {
		ipCmd := exec.Command("nsenter", "--net="+netnsPath, "ip", "-o", "-4", "addr", "show")
		ipOut, err := ipCmd.CombinedOutput()
		if err != nil {
			log.V(1).Info("Could not determine pod IPv4 via nsenter", "err", err)
		} else {
			podIP = ParsePodIPv4(string(ipOut))
		}
	}

	return hostIface, podIP, nil
}
