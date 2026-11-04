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
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"k8s.io/klog/v2"
)

const (
	interceptLabelKey = "service-portal.gke.io/intercept"
	interceptLabelVal = "true"
)

type pluginConfig struct {
	socketPath     string
	pluginName     string
	pluginIndex    string
	proxyHost      string
	proxyPort      string
	proxyHTTPSPort string
	dnsServers     []string
	caCertPath     string
}

type podNetworkState struct {
	hostInterface string
	podIP         string
	runtimeClass  string
}

type portalPlugin struct {
	cfg         pluginConfig
	mu          sync.Mutex
	pods        map[string]podNetworkState
	runIptables func([][]string) error
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func parseFlags() (pluginConfig, error) {
	var cfg pluginConfig
	var rawDNSServers string

	flag.StringVar(&cfg.socketPath, "socket-path", envOrDefault("NRI_SOCKET_PATH", "/var/run/nri/nri.sock"), "Path to containerd NRI socket")
	flag.StringVar(&cfg.pluginName, "plugin-name", envOrDefault("NRI_PLUGIN_NAME", "service-portal"), "NRI plugin name")
	flag.StringVar(&cfg.pluginIndex, "plugin-index", envOrDefault("NRI_PLUGIN_INDEX", envOrDefault("NRI_PLUGIN_IDX", "01")), "NRI plugin index")
	flag.StringVar(&cfg.proxyHost, "proxy-host", envOrDefault("PROXY_HOST", ""), "Proxy destination host or node IP")
	flag.StringVar(&cfg.proxyPort, "proxy-port", envOrDefault("PROXY_PORT", "8080"), "Proxy HTTP port")
	flag.StringVar(&cfg.proxyHTTPSPort, "proxy-https-port", envOrDefault("PROXY_HTTPS_PORT", "8443"), "Proxy HTTPS port")
	flag.StringVar(&rawDNSServers, "dns-servers", envOrDefault("DNS_SERVERS", ""), "Comma-separated cluster DNS server IPs")
	flag.StringVar(&cfg.caCertPath, "ca-cert-path", envOrDefault("CA_CERT_PATH", "/etc/service-portal/ca/tls.crt"), "Host path to CA certificate bundle")
	flag.Parse()

	if strings.TrimSpace(cfg.proxyHost) == "" {
		return cfg, fmt.Errorf("missing required configuration: --proxy-host or PROXY_HOST must be set to the node proxy IP")
	}
	if net.ParseIP(strings.TrimSpace(cfg.proxyHost)) == nil {
		return cfg, fmt.Errorf("invalid proxy host IP %q", cfg.proxyHost)
	}
	cfg.proxyHost = strings.TrimSpace(cfg.proxyHost)

	for _, s := range strings.Split(rawDNSServers, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if net.ParseIP(s) == nil {
			return cfg, fmt.Errorf("invalid DNS server IP %q in --dns-servers", s)
		}
		cfg.dnsServers = append(cfg.dnsServers, s)
	}
	if len(cfg.dnsServers) == 0 {
		return cfg, fmt.Errorf("missing required configuration: --dns-servers or DNS_SERVERS must specify at least one valid DNS server IP")
	}

	if strings.TrimSpace(cfg.caCertPath) == "" {
		return cfg, fmt.Errorf("missing required configuration: --ca-cert-path or CA_CERT_PATH must be set")
	}

	return cfg, nil
}

func podID(pod *api.PodSandbox) string {
	if pod == nil {
		return "<nil>"
	}
	if pod.Namespace != "" && pod.Name != "" {
		return fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
	}
	if pod.Id != "" {
		return pod.Id
	}
	return "<unnamed>"
}

func (p *portalPlugin) matchesPod(pod *api.PodSandbox) bool {
	if pod == nil || pod.Labels == nil {
		return false
	}
	return pod.Labels[interceptLabelKey] == interceptLabelVal
}

func getRuntimeClass(pod *api.PodSandbox) string {
	if pod == nil {
		return ""
	}
	if pod.RuntimeHandler != "" {
		return pod.RuntimeHandler
	}
	if pod.Annotations != nil {
		if rc, ok := pod.Annotations["io.kubernetes.cri.runtime-handler"]; ok && rc != "" {
			return rc
		}
	}
	return ""
}

func isSupportedRuntime(runtimeClass string) bool {
	switch strings.ToLower(strings.TrimSpace(runtimeClass)) {
	case "", "runc", "gvisor", "runsc", "kata", "kata-qemu", "kata-clh", "kata-fc", "kata-containers":
		return true
	default:
		return false
	}
}

func parsePeerIndex(output string) (int, error) {
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

func parsePodIPv4(output string) string {
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

func parseHostInterfaceFromHostLinks(output, netnsBasename string) string {
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

func (p *portalPlugin) findHostInterface(ctx context.Context, pod *api.PodSandbox, netnsPath string) (string, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	log := klog.FromContext(ctx)

	cmd := exec.Command("nsenter", "--net="+netnsPath, "ip", "-o", "link", "show")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("nsenter ip link show: %w (output: %s)", err, out)
	}

	var hostIface string
	if peerIndex, err := parsePeerIndex(string(out)); err == nil && peerIndex > 0 {
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
			hostIface = parseHostInterfaceFromHostLinks(string(hOut), base)
		}
	}

	if hostIface == "" {
		return "", "", fmt.Errorf("could not identify host-side interface for pod %s (netns %s)", podID(pod), netnsPath)
	}

	var podIP string
	if pod != nil && len(pod.Ips) > 0 && pod.Ips[0] != "" {
		podIP = pod.Ips[0]
	}
	if podIP == "" {
		ipCmd := exec.Command("nsenter", "--net="+netnsPath, "ip", "-o", "-4", "addr", "show")
		ipOut, err := ipCmd.CombinedOutput()
		if err != nil {
			log.V(1).Info("Could not determine pod IPv4 via nsenter", "pod", podID(pod), "err", err)
		} else {
			podIP = parsePodIPv4(string(ipOut))
		}
	}

	return hostIface, podIP, nil
}

func (p *portalPlugin) findNetnsPath(pod *api.PodSandbox) (string, error) {
	if pod == nil || pod.Linux == nil {
		return "", fmt.Errorf("pod %s has no Linux configuration (no network namespace entry)", podID(pod))
	}

	var netnsPath string
	for _, ns := range pod.Linux.Namespaces {
		if ns.Type == "network" && ns.Path != "" {
			netnsPath = ns.Path
			break
		}
	}
	if netnsPath == "" {
		return "", fmt.Errorf("pod %s has no network namespace entry (hostNetwork pods cannot be intercepted)", podID(pod))
	}

	targetStat, err := os.Stat(netnsPath)
	if err != nil {
		return "", fmt.Errorf("stat netns path %s for pod %s: %w", netnsPath, podID(pod), err)
	}

	// Ensure netnsPath is not equal to the plugin's own host network namespace
	selfStat, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return "", fmt.Errorf("stat /proc/self/ns/net: %w", err)
	}
	if os.SameFile(selfStat, targetStat) {
		return "", fmt.Errorf("pod %s resolved netns %s matches plugin host network namespace; node chains must never be touched", podID(pod), netnsPath)
	}

	return netnsPath, nil
}

func buildHostIptablesRules(hostIface, proxyHost, proxyPort, proxyHTTPSPort string, dnsServers []string) [][]string {
	prChain := "PORTAL_PR_" + hostIface
	egChain := "PORTAL_EG_" + hostIface

	var rules [][]string

	// 1. NAT table: DNAT ports 80 and 443 on host-side interface to node proxy
	rules = append(rules,
		[]string{"-t", "nat", "-N", prChain},
		[]string{"-t", "nat", "-F", prChain},
		[]string{"-t", "nat", "-D", "PREROUTING", "-i", hostIface, "-j", prChain},
		[]string{"-t", "nat", "-I", "PREROUTING", "1", "-i", hostIface, "-j", prChain},
		[]string{"-t", "nat", "-A", prChain, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", net.JoinHostPort(proxyHost, proxyPort)},
		[]string{"-t", "nat", "-A", prChain, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", net.JoinHostPort(proxyHost, proxyHTTPSPort)},
	)

	// 2. Filter table: Egress isolation and default-deny
	rules = append(rules,
		[]string{"-t", "filter", "-N", egChain},
		[]string{"-t", "filter", "-F", egChain},
		[]string{"-t", "filter", "-D", "INPUT", "-i", hostIface, "-j", egChain},
		[]string{"-t", "filter", "-I", "INPUT", "1", "-i", hostIface, "-j", egChain},
		[]string{"-t", "filter", "-D", "FORWARD", "-i", hostIface, "-j", egChain},
		[]string{"-t", "filter", "-I", "FORWARD", "1", "-i", hostIface, "-j", egChain},
		[]string{"-t", "filter", "-A", egChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		[]string{"-t", "filter", "-A", egChain, "-d", proxyHost, "-p", "tcp", "--dport", proxyPort, "-j", "ACCEPT"},
		[]string{"-t", "filter", "-A", egChain, "-d", proxyHost, "-p", "tcp", "--dport", proxyHTTPSPort, "-j", "ACCEPT"},
	)

	for _, dns := range dnsServers {
		rules = append(rules,
			[]string{"-t", "filter", "-A", egChain, "-d", dns, "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
			[]string{"-t", "filter", "-A", egChain, "-d", dns, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
			[]string{"-t", "filter", "-A", egChain, "-m", "conntrack", "--ctorigdst", dns, "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
			[]string{"-t", "filter", "-A", egChain, "-m", "conntrack", "--ctorigdst", dns, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
		)
	}

	rules = append(rules,
		[]string{"-t", "filter", "-A", egChain, "-p", "tcp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
		[]string{"-t", "filter", "-A", egChain, "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
		[]string{"-t", "filter", "-A", egChain, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
	)

	return rules
}

func buildHostCleanupRules(hostIface string) [][]string {
	prChain := "PORTAL_PR_" + hostIface
	egChain := "PORTAL_EG_" + hostIface

	return [][]string{
		{"-t", "nat", "-D", "PREROUTING", "-i", hostIface, "-j", prChain},
		{"-t", "nat", "-F", prChain},
		{"-t", "nat", "-X", prChain},
		{"-t", "filter", "-D", "INPUT", "-i", hostIface, "-j", egChain},
		{"-t", "filter", "-D", "FORWARD", "-i", hostIface, "-j", egChain},
		{"-t", "filter", "-F", egChain},
		{"-t", "filter", "-X", egChain},
	}
}

func runIptables(ruleCmds [][]string) error {
	for _, args := range ruleCmds {
		cmd := exec.Command("iptables", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			msg := string(out)
			if len(args) >= 3 {
				// -N fails if chain already exists: "Chain already exists"
				if args[2] == "-N" && strings.Contains(strings.ToLower(msg), "already exists") {
					continue
				}
				// -D or -X fails if rule or chain does not exist:
				if (args[2] == "-D" || args[2] == "-X") && (strings.Contains(strings.ToLower(msg), "does not exist") ||
					strings.Contains(msg, "No chain/target/match by that name") ||
					strings.Contains(strings.ToLower(msg), "bad rule") ||
					strings.Contains(strings.ToLower(msg), "too many links")) {
					continue
				}
			}
			return fmt.Errorf("iptables %v failed: %w (output: %s)", args, err, out)
		}
	}
	return nil
}

func (p *portalPlugin) executeIptables(ruleCmds [][]string) error {
	if p.runIptables != nil {
		return p.runIptables(ruleCmds)
	}
	return runIptables(ruleCmds)
}

func (p *portalPlugin) installHostIptablesRules(hostIface string) error {
	rules := buildHostIptablesRules(hostIface, p.cfg.proxyHost, p.cfg.proxyPort, p.cfg.proxyHTTPSPort, p.cfg.dnsServers)
	return p.executeIptables(rules)
}

func (p *portalPlugin) removeHostIptablesRules(hostIface string) error {
	rules := buildHostCleanupRules(hostIface)
	return p.executeIptables(rules)
}

func (p *portalPlugin) configurePod(ctx context.Context, pod *api.PodSandbox) error {
	if ctx == nil {
		ctx = context.Background()
	}
	log := klog.FromContext(ctx)
	log.Info("Configuring pod sandbox", "pod", podID(pod), "id", pod.Id)

	runtimeClass := getRuntimeClass(pod)
	if !isSupportedRuntime(runtimeClass) {
		return fmt.Errorf("unsupported runtime class %q for opted-in pod %s: refusing to start unprotected pod", runtimeClass, podID(pod))
	}

	netnsPath, err := p.findNetnsPath(pod)
	if err != nil {
		return fmt.Errorf("unable to determine netns path for pod %s: %w", podID(pod), err)
	}

	hostIface, podIP, err := p.findHostInterface(ctx, pod, netnsPath)
	if err != nil {
		return fmt.Errorf("unable to find host interface for pod %s: %w", podID(pod), err)
	}

	if err := p.installHostIptablesRules(hostIface); err != nil {
		return fmt.Errorf("install host iptables rules on %s for pod %s: %w", hostIface, podID(pod), err)
	}

	p.mu.Lock()
	p.pods[pod.Id] = podNetworkState{
		hostInterface: hostIface,
		podIP:         podIP,
		runtimeClass:  runtimeClass,
	}
	p.mu.Unlock()

	log.Info("Successfully installed host-side iptables rules for pod", "pod", podID(pod), "hostIface", hostIface, "podIP", podIP, "runtimeClass", runtimeClass)
	return nil
}

func (p *portalPlugin) cleanupPod(ctx context.Context, pod *api.PodSandbox) error {
	if ctx == nil {
		ctx = context.Background()
	}
	log := klog.FromContext(ctx)
	if pod == nil {
		return nil
	}

	p.mu.Lock()
	state, found := p.pods[pod.Id]
	if found {
		delete(p.pods, pod.Id)
	}
	p.mu.Unlock()

	var hostIface string
	if found {
		hostIface = state.hostInterface
	} else {
		netnsPath, err := p.findNetnsPath(pod)
		if err != nil {
			log.V(1).Info("Could not resolve netns path during cleanup", "pod", podID(pod), "err", err)
		} else {
			iface, _, err := p.findHostInterface(ctx, pod, netnsPath)
			if err != nil {
				log.V(1).Info("Could not find host interface during cleanup", "pod", podID(pod), "err", err)
			} else {
				hostIface = iface
			}
		}
	}

	if hostIface != "" {
		log.Info("Cleaning up host-side iptables rules for pod", "pod", podID(pod), "hostIface", hostIface)
		if err := p.removeHostIptablesRules(hostIface); err != nil {
			return fmt.Errorf("clean up host iptables rules on %s for pod %s: %w", hostIface, podID(pod), err)
		}
	}
	return nil
}

func (p *portalPlugin) StopPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	if !p.matchesPod(pod) {
		return nil
	}
	return p.cleanupPod(ctx, pod)
}

func (p *portalPlugin) RemovePodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	if !p.matchesPod(pod) {
		return nil
	}
	return p.cleanupPod(ctx, pod)
}

func (p *portalPlugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	log := klog.FromContext(ctx)
	log.Info("Synchronize called", "pods", len(pods), "containers", len(containers))

	var syncErrors []error
	for _, pod := range pods {
		if !p.matchesPod(pod) {
			continue
		}
		log.Info("Synchronizing existing intercepted pod sandbox", "pod", podID(pod), "id", pod.Id)
		if err := p.configurePod(ctx, pod); err != nil {
			log.Error(err, "Error synchronizing rules for pod", "pod", podID(pod))
			syncErrors = append(syncErrors, fmt.Errorf("pod %s: %w", podID(pod), err))
		}
	}

	if len(syncErrors) > 0 {
		// Note on failure consequence: containerd treats a non-nil error returned from
		// Synchronize as plugin registration failure and terminates the connection.
		// One misconfigured or failing existing pod will take the entire plugin offline,
		// leaving new pods to start unprotected (fail-open) until the DaemonSet pod restarts.
		// This behavior is accepted for the spike because a proper cluster-level admission
		// and fail-closed gate is deferred to #181/#182.
		return nil, errors.Join(syncErrors...)
	}
	return nil, nil
}

func (p *portalPlugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	if !p.matchesPod(pod) {
		return nil
	}
	return p.configurePod(ctx, pod)
}

func (p *portalPlugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	if !p.matchesPod(pod) {
		return nil, nil, nil
	}

	runtimeClass := getRuntimeClass(pod)
	if !isSupportedRuntime(runtimeClass) {
		return nil, nil, fmt.Errorf("unsupported runtime class %q for opted-in pod %s: refusing to start unprotected pod", runtimeClass, podID(pod))
	}

	if ctx == nil {
		ctx = context.Background()
	}
	log := klog.FromContext(ctx)
	log.Info("Intercepting container creation", "pod", podID(pod), "container", ctr.Name)

	// Fail closed if the CA certificate bundle is missing on the host
	if _, err := os.Stat(p.cfg.caCertPath); err != nil {
		return nil, nil, fmt.Errorf("CA certificate bundle not found at %s: %w", p.cfg.caCertPath, err)
	}

	// Injected mounts in NRI adjustments are resolved on the host by containerd.
	// This works because the DaemonSet mounts the CA directory at the identical
	// hostPath and containerPath (/etc/service-portal/ca).
	adjustment := &api.ContainerAdjustment{}
	adjustment.AddEnv("SSL_CERT_FILE", "/etc/service-portal/ca/tls.crt")
	adjustment.AddMount(&api.Mount{
		Destination: "/etc/service-portal/ca/tls.crt",
		Source:      p.cfg.caCertPath,
		Type:        "bind",
		Options:     []string{"rbind", "ro"},
	})
	log.Info("Injected CA cert mount and SSL_CERT_FILE into container", "container", ctr.Name, "caCertPath", p.cfg.caCertPath)

	return adjustment, nil, nil
}

func main() {
	klog.InitFlags(nil)
	cfg, err := parseFlags()
	if err != nil {
		klog.Fatalf("Invalid configuration: %v", err)
	}

	p := &portalPlugin{
		cfg:  cfg,
		pods: make(map[string]podNetworkState),
	}

	s, err := stub.New(p,
		stub.WithPluginName(cfg.pluginName),
		stub.WithPluginIdx(cfg.pluginIndex),
		stub.WithSocketPath(cfg.socketPath),
	)
	if err != nil {
		klog.Fatalf("Failed to create NRI stub: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	klog.Infof("Starting portal-nri-plugin (name=%s, index=%s, socket=%s, proxyHost=%s)...", cfg.pluginName, cfg.pluginIndex, cfg.socketPath, cfg.proxyHost)
	if err := s.Run(ctx); err != nil {
		klog.Fatalf("NRI stub run failed: %v", err)
	}
}
