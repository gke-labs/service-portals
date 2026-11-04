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

// ParsePodIPv6 extracts the first non-loopback, non-link-local IPv6 address from "ip -o -6 addr show" output.
func ParsePodIPv6(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "inet6" && i+1 < len(fields) {
				if ip, _, err := net.ParseCIDR(fields[i+1]); err == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
					return ip.String()
				}
			}
		}
	}
	return ""
}

// DiscoverPodIPs extracts pod IPv4 and IPv6 addresses from podIPs or from the netns via nsenter.
func DiscoverPodIPs(ctx context.Context, podIPs []string, netnsPath string) (string, string, error) {
	log := klog.FromContext(ctx)
	var podIPv4, podIPv6 string
	for _, s := range podIPs {
		if ip := net.ParseIP(s); ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			if ip.To4() != nil && podIPv4 == "" {
				podIPv4 = s
			} else if ip.To4() == nil && podIPv6 == "" {
				podIPv6 = s
			}
		}
	}

	if (podIPv4 == "" || podIPv6 == "") && netnsPath != "" {
		if podIPv4 == "" {
			ipCmd := exec.Command("nsenter", "--net="+netnsPath, "ip", "-o", "-4", "addr", "show")
			if ipOut, err := ipCmd.CombinedOutput(); err != nil {
				log.Error(err, "Could not determine pod IPv4 via nsenter", "output", string(ipOut))
				return "", "", fmt.Errorf("nsenter ip -o -4 addr show: %w (output: %s)", err, ipOut)
			} else {
				podIPv4 = ParsePodIPv4(string(ipOut))
			}
		}
		if podIPv6 == "" {
			ipCmd := exec.Command("nsenter", "--net="+netnsPath, "ip", "-o", "-6", "addr", "show")
			if ipOut, err := ipCmd.CombinedOutput(); err != nil {
				log.Error(err, "Could not determine pod IPv6 via nsenter", "output", string(ipOut))
				return "", "", fmt.Errorf("nsenter ip -o -6 addr show: %w (output: %s)", err, ipOut)
			} else {
				podIPv6 = ParsePodIPv6(string(ipOut))
			}
		}
	}
	return podIPv4, podIPv6, nil
}

// DiscoverNodeIPv6 finds the first global, non-loopback, non-link-local IPv6 address on the node.
func DiscoverNodeIPv6() string {
	hCmd := exec.Command("ip", "-o", "-6", "addr", "show", "scope", "global")
	if out, err := hCmd.CombinedOutput(); err != nil {
		klog.V(2).Infof("Could not determine node IPv6 via ip command: %v", err)
	} else if ip := ParsePodIPv6(string(out)); ip != "" {
		return ip
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			ip := ipNet.IP
			if ip.To4() == nil && ip.To16() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip.String()
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

	podIPv4, _, err := DiscoverPodIPs(ctx, podIPs, netnsPath)
	if err != nil {
		return "", "", err
	}
	return hostIface, podIPv4, nil
}
