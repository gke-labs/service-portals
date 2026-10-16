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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runEntrypointCommand(t *testing.T, args []string, env map[string]string) (string, error) {
	t.Helper()

	entrypointPath := filepath.Join("..", "..", "images", "init-service-portals", "entrypoint.sh")
	if _, err := os.Stat(entrypointPath); err != nil {
		t.Fatalf("entrypoint.sh not found at %s: %v", entrypointPath, err)
	}

	cmd := exec.Command("sh", append([]string{entrypointPath}, args...)...)
	cmdEnv := os.Environ()
	for k, v := range env {
		cmdEnv = append(cmdEnv, k+"="+v)
	}
	cmd.Env = cmdEnv

	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runGenerateRules(t *testing.T, family string, env map[string]string) string {
	t.Helper()

	out, err := runEntrypointCommand(t, []string{"generate-rules", family}, env)
	if err != nil {
		t.Fatalf("Failed to execute entrypoint.sh generate-rules %s: %v\nOutput: %s", family, err, out)
	}
	return out
}

func TestRuleGeneration_Defaults_IPv4(t *testing.T) {
	out := runGenerateRules(t, "4", map[string]string{
		"DNS_SERVER_IPS": "10.96.0.10",
	})

	expectedSubstrings := []string{
		"*nat",
		":PORTAL_OUTPUT - [0:0]",
		"-A OUTPUT -p tcp -j PORTAL_OUTPUT",
		"-A PORTAL_OUTPUT -o lo -j RETURN",
		"-A PORTAL_OUTPUT -m owner --uid-owner 1337 -j RETURN",
		"-A PORTAL_OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 8080",
		"COMMIT",
		"*filter",
		":PORTAL_EGRESS - [0:0]",
		"-A OUTPUT -j PORTAL_EGRESS",
		"-A PORTAL_EGRESS -o lo -j ACCEPT",
		"-A PORTAL_EGRESS -d 127.0.0.1/32 -j ACCEPT",
		"-A PORTAL_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A PORTAL_EGRESS -m owner --uid-owner 1337 -j ACCEPT",
		"-A PORTAL_EGRESS -p icmp --icmp-type 0 -j ACCEPT",
		"-A PORTAL_EGRESS -p icmp --icmp-type 3 -j ACCEPT",
		"-A PORTAL_EGRESS -p icmp --icmp-type 11 -j ACCEPT",
		"-A PORTAL_EGRESS -d 169.254.0.0/16 -j REJECT --reject-with icmp-port-unreachable",
		"-A PORTAL_EGRESS -d 10.96.0.10 -p udp --dport 53 -j ACCEPT",
		"-A PORTAL_EGRESS -d 10.96.0.10 -p tcp --dport 53 -j ACCEPT",
		"-A PORTAL_EGRESS -p icmp -j REJECT --reject-with icmp-port-unreachable",
		"-A PORTAL_EGRESS -p tcp -j REJECT --reject-with icmp-port-unreachable",
		"-A PORTAL_EGRESS -p udp -j REJECT --reject-with icmp-port-unreachable",
	}

	for _, s := range expectedSubstrings {
		if !strings.Contains(out, s) {
			t.Errorf("Expected output to contain %q, but it did not.\nFull output:\n%s", s, out)
		}
	}

	// Verify that redundant flush inside restore is omitted (full-table replace is used)
	if strings.Contains(out, "-F PORTAL_EGRESS") || strings.Contains(out, "-F PORTAL_OUTPUT") {
		t.Errorf("Output should not contain redundant -F inside restore input")
	}

	// Verify that destination-unrestricted proxy ports are NOT accepted
	if strings.Contains(out, "-A PORTAL_EGRESS -p tcp --dport 8080 -j ACCEPT") {
		t.Errorf("Output should not contain destination-unrestricted port 8080 ACCEPT")
	}
}

func TestRuleGeneration_Defaults_IPv6(t *testing.T) {
	// Note: 2001:db8::53 uses the RFC 3849 documentation prefix (2001:db8::/32) as a placeholder DNS server IP.
	out := runGenerateRules(t, "6", map[string]string{
		"DNS_SERVER_IPS": "2001:db8::53",
	})

	expectedSubstrings := []string{
		"*nat",
		":PORTAL_OUTPUT - [0:0]",
		"-A OUTPUT -p tcp -j PORTAL_OUTPUT",
		"-A PORTAL_OUTPUT -o lo -j RETURN",
		"-A PORTAL_OUTPUT -m owner --uid-owner 1337 -j RETURN",
		"-A PORTAL_OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 8080",
		"COMMIT",
		"*filter",
		":PORTAL_EGRESS - [0:0]",
		"-A OUTPUT -j PORTAL_EGRESS",
		"-A PORTAL_EGRESS -o lo -j ACCEPT",
		"-A PORTAL_EGRESS -d ::1/128 -j ACCEPT",
		"-A PORTAL_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A PORTAL_EGRESS -m owner --uid-owner 1337 -j ACCEPT",
		"-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 1 -j ACCEPT",
		"-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 2 -j ACCEPT",
		"-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 3 -j ACCEPT",
		"-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 4 -j ACCEPT",
		"-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 133 -j ACCEPT",
		"-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 134 -j ACCEPT",
		"-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 135 -j ACCEPT",
		"-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 136 -j ACCEPT",
		"-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 137 -j ACCEPT",
		"-A PORTAL_EGRESS -d fd00:ec2::254/128 -j REJECT --reject-with icmp6-port-unreachable",
		"-A PORTAL_EGRESS -d fd20:ce::254/128 -j REJECT --reject-with icmp6-port-unreachable",
		"-A PORTAL_EGRESS -d fe80::/10 -j REJECT --reject-with icmp6-port-unreachable",
		"-A PORTAL_EGRESS -d 2001:db8::53 -p udp --dport 53 -j ACCEPT",
		"-A PORTAL_EGRESS -d 2001:db8::53 -p tcp --dport 53 -j ACCEPT",
		"-A PORTAL_EGRESS -p ipv6-icmp -j REJECT --reject-with icmp6-port-unreachable",
		"-A PORTAL_EGRESS -p tcp -j REJECT --reject-with icmp6-port-unreachable",
		"-A PORTAL_EGRESS -p udp -j REJECT --reject-with icmp6-port-unreachable",
	}

	for _, s := range expectedSubstrings {
		if !strings.Contains(out, s) {
			t.Errorf("Expected IPv6 output to contain %q, but it did not.\nFull output:\n%s", s, out)
		}
	}

	if strings.Contains(out, "-A PORTAL_EGRESS -p tcp --dport 8080 -j ACCEPT") {
		t.Errorf("IPv6 output should not contain destination-unrestricted port 8080 ACCEPT")
	}
}

func TestRuleGeneration_ND_And_ICMP_Ordering(t *testing.T) {
	out6 := runGenerateRules(t, "6", map[string]string{
		"DNS_SERVER_IPS": "2001:db8::53",
	})

	ndIdx := strings.Index(out6, "--icmpv6-type 135")
	linkLocalIdx := strings.Index(out6, "-d fe80::/10")
	icmpv6RejectIdx := strings.Index(out6, "-A PORTAL_EGRESS -p ipv6-icmp -j REJECT")

	if ndIdx == -1 {
		t.Fatalf("Missing Neighbor Discovery (type 135) rule in IPv6 output")
	}
	if linkLocalIdx == -1 {
		t.Fatalf("Missing link-local (fe80::/10) rule in IPv6 output")
	}
	if icmpv6RejectIdx == -1 {
		t.Fatalf("Missing ICMPv6 reject rule in IPv6 output")
	}

	if ndIdx >= linkLocalIdx {
		t.Errorf("Neighbor Discovery allow rule (idx %d) must precede link-local reject (idx %d)", ndIdx, linkLocalIdx)
	}
	if linkLocalIdx >= icmpv6RejectIdx {
		t.Errorf("Link-local reject (idx %d) must precede generic ICMPv6 reject (idx %d)", linkLocalIdx, icmpv6RejectIdx)
	}

	out4 := runGenerateRules(t, "4", map[string]string{
		"DNS_SERVER_IPS": "10.96.0.10",
	})

	icmpAllowIdx := strings.Index(out4, "--icmp-type 3")
	metadataIdx := strings.Index(out4, "-d 169.254.0.0/16")
	icmpRejectIdx := strings.Index(out4, "-A PORTAL_EGRESS -p icmp -j REJECT")

	if icmpAllowIdx == -1 || metadataIdx == -1 || icmpRejectIdx == -1 {
		t.Fatalf("Missing IPv4 ICMP allow/reject or metadata rules")
	}
	if icmpAllowIdx >= metadataIdx {
		t.Errorf("IPv4 essential ICMP allow (idx %d) must precede metadata reject (idx %d)", icmpAllowIdx, metadataIdx)
	}
	if metadataIdx >= icmpRejectIdx {
		t.Errorf("IPv4 metadata reject (idx %d) must precede generic ICMP reject (idx %d)", metadataIdx, icmpRejectIdx)
	}
}

func TestRuleGeneration_WildcardIntercept(t *testing.T) {
	out := runGenerateRules(t, "4", map[string]string{
		"INTERCEPT_PORTS": "*",
		"DNS_SERVER_IPS":  "10.96.0.10",
	})

	expected := []string{
		"-A PORTAL_OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 8443",
		"-A PORTAL_OUTPUT -p tcp ! --dport 443 -j REDIRECT --to-ports 8080",
	}
	for _, s := range expected {
		if !strings.Contains(out, s) {
			t.Errorf("Expected wildcard intercept output to contain %q, but it did not.\nFull output:\n%s", s, out)
		}
	}
}

func TestRuleGeneration_AllowMetadata(t *testing.T) {
	out4 := runGenerateRules(t, "4", map[string]string{
		"ALLOW_METADATA": "true",
		"DNS_SERVER_IPS": "10.96.0.10",
	})

	if !strings.Contains(out4, "-A PORTAL_EGRESS -d 169.254.0.0/16 -j ACCEPT") {
		t.Errorf("Expected IPv4 to contain ACCEPT for metadata, got:\n%s", out4)
	}
	if strings.Contains(out4, "-A PORTAL_EGRESS -d 169.254.0.0/16 -j REJECT") {
		t.Errorf("IPv4 should not reject metadata when ALLOW_METADATA=true")
	}

	out6 := runGenerateRules(t, "6", map[string]string{
		"ALLOW_METADATA": "true",
		"DNS_SERVER_IPS": "2001:db8::53",
	})

	expectedAllowed := []string{
		"-A PORTAL_EGRESS -d fd00:ec2::254/128 -j ACCEPT",
		"-A PORTAL_EGRESS -d fd20:ce::254/128 -j ACCEPT",
		"-A PORTAL_EGRESS -d fe80::/10 -j ACCEPT",
	}
	for _, s := range expectedAllowed {
		if !strings.Contains(out6, s) {
			t.Errorf("Expected IPv6 to contain %q for metadata allow, got:\n%s", s, out6)
		}
	}
	if strings.Contains(out6, "fd00:ec2::254/128 -j REJECT") ||
		strings.Contains(out6, "fd20:ce::254/128 -j REJECT") ||
		strings.Contains(out6, "fe80::/10 -j REJECT") {
		t.Errorf("IPv6 should not reject metadata/link-local when ALLOW_METADATA=true")
	}
}

func TestRuleGeneration_Allowlist_CIDRsAndPorts(t *testing.T) {
	env := map[string]string{
		"ALLOW_CIDRS":    "10.0.0.0/8, 192.168.0.0/16, 2001:db8::/32",
		"ALLOW_PORTS":    "8080, 9000",
		"DNS_SERVER_IPS": "10.96.0.10",
	}

	out4 := runGenerateRules(t, "4", env)
	if !strings.Contains(out4, "-A PORTAL_EGRESS -d 10.0.0.0/8 -j ACCEPT") {
		t.Errorf("IPv4 should contain 10.0.0.0/8 ACCEPT")
	}
	if !strings.Contains(out4, "-A PORTAL_EGRESS -d 192.168.0.0/16 -j ACCEPT") {
		t.Errorf("IPv4 should contain 192.168.0.0/16 ACCEPT")
	}
	if strings.Contains(out4, "2001:db8::/32") {
		t.Errorf("IPv4 should NOT contain IPv6 CIDR 2001:db8::/32")
	}
	if !strings.Contains(out4, "-A PORTAL_EGRESS -p tcp --dport 8080 -j ACCEPT") {
		t.Errorf("IPv4 should contain allow port 8080")
	}
	if !strings.Contains(out4, "-A PORTAL_EGRESS -p tcp --dport 9000 -j ACCEPT") {
		t.Errorf("IPv4 should contain allow port 9000")
	}

	out6 := runGenerateRules(t, "6", env)
	if !strings.Contains(out6, "-A PORTAL_EGRESS -d 2001:db8::/32 -j ACCEPT") {
		t.Errorf("IPv6 should contain 2001:db8::/32 ACCEPT")
	}
	if strings.Contains(out6, "10.0.0.0/8") || strings.Contains(out6, "192.168.0.0/16") {
		t.Errorf("IPv6 should NOT contain IPv4 CIDRs")
	}
	if !strings.Contains(out6, "-A PORTAL_EGRESS -p tcp --dport 8080 -j ACCEPT") {
		t.Errorf("IPv6 should contain allow port 8080")
	}
	if !strings.Contains(out6, "-A PORTAL_EGRESS -p tcp --dport 9000 -j ACCEPT") {
		t.Errorf("IPv6 should contain allow port 9000")
	}
}

func TestRuleGeneration_EgressAction_DROP(t *testing.T) {
	env := map[string]string{
		"EGRESS_ACTION":  "DROP",
		"DNS_SERVER_IPS": "10.96.0.10",
	}

	out4 := runGenerateRules(t, "4", env)
	if !strings.Contains(out4, "-A PORTAL_EGRESS -d 169.254.0.0/16 -j DROP") {
		t.Errorf("IPv4 metadata should be DROP")
	}
	if !strings.Contains(out4, "-A PORTAL_EGRESS -p icmp -j DROP") {
		t.Errorf("IPv4 ICMP should be DROP")
	}
	if !strings.Contains(out4, "-A PORTAL_EGRESS -p tcp -j DROP") {
		t.Errorf("IPv4 TCP should be DROP")
	}
	if !strings.Contains(out4, "-A PORTAL_EGRESS -p udp -j DROP") {
		t.Errorf("IPv4 UDP should be DROP")
	}
	if strings.Contains(out4, "REJECT") {
		t.Errorf("Output should not contain REJECT when EGRESS_ACTION=DROP")
	}

	out6 := runGenerateRules(t, "6", env)
	if !strings.Contains(out6, "-A PORTAL_EGRESS -d fd00:ec2::254/128 -j DROP") {
		t.Errorf("IPv6 metadata AWS should be DROP")
	}
	if !strings.Contains(out6, "-A PORTAL_EGRESS -d fd20:ce::254/128 -j DROP") {
		t.Errorf("IPv6 metadata GCE should be DROP")
	}
	if !strings.Contains(out6, "-A PORTAL_EGRESS -d fe80::/10 -j DROP") {
		t.Errorf("IPv6 link-local should be DROP")
	}
	if !strings.Contains(out6, "-A PORTAL_EGRESS -p ipv6-icmp -j DROP") {
		t.Errorf("IPv6 ICMP should be DROP")
	}
	if !strings.Contains(out6, "-A PORTAL_EGRESS -p tcp -j DROP") {
		t.Errorf("IPv6 TCP should be DROP")
	}
	if !strings.Contains(out6, "-A PORTAL_EGRESS -p udp -j DROP") {
		t.Errorf("IPv6 UDP should be DROP")
	}
	if strings.Contains(out6, "REJECT") {
		t.Errorf("IPv6 output should not contain REJECT when EGRESS_ACTION=DROP")
	}
}

func TestRuleGeneration_ResolvConfParsing(t *testing.T) {
	tmpResolv, err := os.CreateTemp("", "resolv.conf-*")
	if err != nil {
		t.Fatalf("Failed to create temp resolv.conf: %v", err)
	}
	defer os.Remove(tmpResolv.Name())

	resolvContent := `
search default.svc.cluster.local svc.cluster.local
nameserver 10.96.0.10
nameserver 2001:db8::53
options ndots:5
`
	if _, err := tmpResolv.WriteString(resolvContent); err != nil {
		t.Fatalf("Failed to write to temp resolv.conf: %v", err)
	}
	tmpResolv.Close()

	env := map[string]string{
		"RESOLV_CONF":    tmpResolv.Name(),
		"DNS_SERVER_IPS": "",
	}

	out4 := runGenerateRules(t, "4", env)
	if !strings.Contains(out4, "-A PORTAL_EGRESS -d 10.96.0.10 -p udp --dport 53 -j ACCEPT") {
		t.Errorf("IPv4 output should contain nameserver from resolv.conf, got:\n%s", out4)
	}
	if strings.Contains(out4, "2001:db8::53") {
		t.Errorf("IPv4 output should NOT contain IPv6 nameserver")
	}

	out6 := runGenerateRules(t, "6", env)
	if !strings.Contains(out6, "-A PORTAL_EGRESS -d 2001:db8::53 -p udp --dport 53 -j ACCEPT") {
		t.Errorf("IPv6 output should contain IPv6 nameserver from resolv.conf, got:\n%s", out6)
	}
	if strings.Contains(out6, "10.96.0.10") {
		t.Errorf("IPv6 output should NOT contain IPv4 nameserver")
	}
}

func TestRuleGeneration_RuleOrdering(t *testing.T) {
	env := map[string]string{
		"ALLOW_METADATA": "false",
		"ALLOW_CIDRS":    "10.0.0.0/8",
		"ALLOW_PORTS":    "9000",
		"DNS_SERVER_IPS": "10.96.0.10",
	}

	out := runGenerateRules(t, "4", env)

	natIdx := strings.Index(out, "*nat")
	filterIdx := strings.Index(out, "*filter")
	if natIdx == -1 || filterIdx == -1 || natIdx >= filterIdx {
		t.Errorf("Expected *nat table before *filter table")
	}

	icmpAllowIdx := strings.Index(out, "--icmp-type 0")
	metadataIdx := strings.Index(out, "-d 169.254.0.0/16")
	dnsIdx := strings.Index(out, "-d 10.96.0.10")
	cidrIdx := strings.Index(out, "-d 10.0.0.0/8")
	portIdx := strings.Index(out, "--dport 9000")
	icmpRejectIdx := strings.Index(out, "-A PORTAL_EGRESS -p icmp -j")
	tcpRejectIdx := strings.Index(out, "-A PORTAL_EGRESS -p tcp -j")
	udpRejectIdx := strings.Index(out, "-A PORTAL_EGRESS -p udp -j")

	if icmpAllowIdx >= metadataIdx {
		t.Errorf("Essential ICMP allow (idx %d) must precede metadata block (idx %d)", icmpAllowIdx, metadataIdx)
	}
	if metadataIdx >= dnsIdx {
		t.Errorf("Metadata block (idx %d) must precede DNS allow rules (idx %d)", metadataIdx, dnsIdx)
	}
	if metadataIdx >= cidrIdx {
		t.Errorf("Metadata block (idx %d) must precede ALLOW_CIDRS (idx %d)", metadataIdx, cidrIdx)
	}
	if dnsIdx >= cidrIdx {
		t.Errorf("DNS allow rules (idx %d) should precede ALLOW_CIDRS (idx %d)", dnsIdx, cidrIdx)
	}
	if cidrIdx >= portIdx {
		t.Errorf("ALLOW_CIDRS (idx %d) should precede ALLOW_PORTS (idx %d)", cidrIdx, portIdx)
	}
	if portIdx >= icmpRejectIdx {
		t.Errorf("ALLOW_PORTS (idx %d) must precede ICMP reject (idx %d)", portIdx, icmpRejectIdx)
	}
	if icmpRejectIdx >= tcpRejectIdx {
		t.Errorf("ICMP reject (idx %d) must precede TCP reject (idx %d)", icmpRejectIdx, tcpRejectIdx)
	}
	if tcpRejectIdx >= udpRejectIdx {
		t.Errorf("TCP reject (idx %d) should precede UDP reject (idx %d)", tcpRejectIdx, udpRejectIdx)
	}
}

func TestIPv6DecisionLogic(t *testing.T) {
	// Case A: IPv6 explicitly disabled in network namespace (disable_ipv6=1)
	tmpDisabled, err := os.CreateTemp("", "disable_ipv6-1-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpDisabled.Name())
	if _, err := tmpDisabled.WriteString("1\n"); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpDisabled.Close()

	outDisabled, errDisabled := runEntrypointCommand(t, []string{"is-ipv6-disabled"}, map[string]string{
		"IPV6_DISABLE_PATH": tmpDisabled.Name(),
	})
	if errDisabled != nil {
		t.Errorf("Expected is-ipv6-disabled to succeed for disable_ipv6=1, got err: %v, out: %s", errDisabled, outDisabled)
	}
	if !strings.Contains(outDisabled, "disabled") {
		t.Errorf("Expected 'disabled', got: %s", outDisabled)
	}

	outApplyDisabled, errApplyDisabled := runEntrypointCommand(t, []string{"apply-ipv6"}, map[string]string{
		"IPV6_DISABLE_PATH": tmpDisabled.Name(),
	})
	if errApplyDisabled != nil {
		t.Errorf("Expected apply-ipv6 to succeed when IPv6 disabled, got err: %v, out: %s", errApplyDisabled, outApplyDisabled)
	}
	if !strings.Contains(outApplyDisabled, "IPv6 is disabled in this network namespace") {
		t.Errorf("Expected info log when IPv6 disabled, got: %s", outApplyDisabled)
	}

	// Case B: IPv6 enabled in network namespace (disable_ipv6=0)
	tmpEnabled, err := os.CreateTemp("", "disable_ipv6-0-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpEnabled.Name())
	if _, err := tmpEnabled.WriteString("0\n"); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpEnabled.Close()

	outEnabled, errEnabled := runEntrypointCommand(t, []string{"is-ipv6-disabled"}, map[string]string{
		"IPV6_DISABLE_PATH": tmpEnabled.Name(),
	})
	if errEnabled == nil {
		t.Errorf("Expected is-ipv6-disabled to return non-zero when IPv6 is enabled, got nil err, out: %s", outEnabled)
	}
	if !strings.Contains(outEnabled, "enabled") {
		t.Errorf("Expected 'enabled', got: %s", outEnabled)
	}

	// Case C: IPv6 enabled but restore fails (non-existent command in PATH), fail-closed by default
	envFailClosed := map[string]string{
		"IPV6_DISABLE_PATH":     tmpEnabled.Name(),
		"PATH":                  "/nonexistent",
		"ALLOW_UNFILTERED_IPV6": "false",
	}
	outFailClosed, errFailClosed := runEntrypointCommand(t, []string{"apply-ipv6"}, envFailClosed)
	if errFailClosed == nil {
		t.Errorf("Expected apply-ipv6 to fail when restore fails and ALLOW_UNFILTERED_IPV6=false")
	}
	if !strings.Contains(outFailClosed, "Failing closed") {
		t.Errorf("Expected 'Failing closed' error log, got: %s", outFailClosed)
	}

	// Case D: IPv6 enabled and restore fails, but ALLOW_UNFILTERED_IPV6=true allows escape hatch with loud warning
	envEscapeHatch := map[string]string{
		"IPV6_DISABLE_PATH":     tmpEnabled.Name(),
		"PATH":                  "/nonexistent",
		"ALLOW_UNFILTERED_IPV6": "true",
	}
	outEscapeHatch, errEscapeHatch := runEntrypointCommand(t, []string{"apply-ipv6"}, envEscapeHatch)
	if errEscapeHatch != nil {
		t.Errorf("Expected apply-ipv6 to succeed when ALLOW_UNFILTERED_IPV6=true, got: %v\nOutput: %s", errEscapeHatch, outEscapeHatch)
	}
	if !strings.Contains(outEscapeHatch, "WARNING:") || !strings.Contains(outEscapeHatch, "UNFILTERED") {
		t.Errorf("Expected loud warning log when ALLOW_UNFILTERED_IPV6=true, got: %s", outEscapeHatch)
	}
}
