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
	"strings"
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

type portalPlugin struct {
	cfg pluginConfig
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

// applyIptablesRules executes a sequence of iptables command argument slices
// inside the target network namespace via nsenter.
func applyIptablesRules(netnsPath string, ruleCmds [][]string) error {
	for _, args := range ruleCmds {
		cmdArgs := append([]string{"--net=" + netnsPath, "iptables"}, args...)
		cmd := exec.Command("nsenter", cmdArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			msg := string(out)
			if len(args) >= 3 {
				// -N fails if chain already exists: "Chain already exists"
				if args[2] == "-N" && strings.Contains(strings.ToLower(msg), "already exists") {
					continue
				}
				// -D fails if rule or chain does not exist:
				// "does not exist", "No chain/target/match by that name", "Bad rule"
				if args[2] == "-D" && (strings.Contains(strings.ToLower(msg), "does not exist") ||
					strings.Contains(msg, "No chain/target/match by that name") ||
					strings.Contains(strings.ToLower(msg), "bad rule")) {
					continue
				}
			}
			return fmt.Errorf("iptables %v failed: %w (output: %s)", args, err, out)
		}
	}
	return nil
}

// installIptablesRules configures transparent redirection (NAT DNAT) and
// default-deny egress filtering (Filter) inside the pod's network namespace.
//
// Security boundary & netns isolation:
// Even though these iptables rules reside in the pod's network namespace, standard
// unprivileged Kubernetes containers run without CAP_NET_ADMIN in their namespace
// (which holds under Pod Security Standards 'baseline' and 'restricted' profiles).
// Without CAP_NET_ADMIN, any attempt by a workload process (even running as root UID 0)
// to inspect, modify, flush, or delete iptables rules or alter routing tables is
// rejected by the Linux kernel with EPERM ("Operation not permitted").
// Precondition & Assumption: This guarantee strictly depends on opted-in pods not
// being granted CAP_NET_ADMIN or privileged execution in their pod spec; a container
// with CAP_NET_ADMIN in the pod netns can rewrite or delete these rules. Host-side
// enforcement (tracked in #181) is required to remove this trust assumption.
func (p *portalPlugin) installIptablesRules(netnsPath string) error {
	var rules [][]string

	// 1. NAT table: DNAT ports 80 and 443 to node proxy
	rules = append(rules,
		[]string{"-t", "nat", "-N", "PORTAL_OUTPUT"},
		[]string{"-t", "nat", "-F", "PORTAL_OUTPUT"},
		[]string{"-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", "PORTAL_OUTPUT"},
		[]string{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "PORTAL_OUTPUT"},
		[]string{"-t", "nat", "-A", "PORTAL_OUTPUT", "-o", "lo", "-j", "RETURN"},
		[]string{"-t", "nat", "-A", "PORTAL_OUTPUT", "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", net.JoinHostPort(p.cfg.proxyHost, p.cfg.proxyPort)},
		[]string{"-t", "nat", "-A", "PORTAL_OUTPUT", "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", net.JoinHostPort(p.cfg.proxyHost, p.cfg.proxyHTTPSPort)},
	)

	// 2. Filter table: Egress isolation and default-deny
	rules = append(rules,
		[]string{"-t", "filter", "-N", "PORTAL_EGRESS"},
		[]string{"-t", "filter", "-F", "PORTAL_EGRESS"},
		[]string{"-t", "filter", "-D", "OUTPUT", "-j", "PORTAL_EGRESS"},
		[]string{"-t", "filter", "-A", "OUTPUT", "-j", "PORTAL_EGRESS"},
		[]string{"-t", "filter", "-A", "PORTAL_EGRESS", "-o", "lo", "-j", "ACCEPT"},
		[]string{"-t", "filter", "-A", "PORTAL_EGRESS", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		[]string{"-t", "filter", "-A", "PORTAL_EGRESS", "-d", p.cfg.proxyHost, "-p", "tcp", "--dport", p.cfg.proxyPort, "-j", "ACCEPT"},
		[]string{"-t", "filter", "-A", "PORTAL_EGRESS", "-d", p.cfg.proxyHost, "-p", "tcp", "--dport", p.cfg.proxyHTTPSPort, "-j", "ACCEPT"},
	)

	for _, dns := range p.cfg.dnsServers {
		rules = append(rules,
			[]string{"-t", "filter", "-A", "PORTAL_EGRESS", "-d", dns, "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
			[]string{"-t", "filter", "-A", "PORTAL_EGRESS", "-d", dns, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
		)
	}

	rules = append(rules,
		[]string{"-t", "filter", "-A", "PORTAL_EGRESS", "-p", "tcp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
		[]string{"-t", "filter", "-A", "PORTAL_EGRESS", "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
		[]string{"-t", "filter", "-A", "PORTAL_EGRESS", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
	)

	return applyIptablesRules(netnsPath, rules)
}

func (p *portalPlugin) configurePod(ctx context.Context, pod *api.PodSandbox) error {
	log := klog.FromContext(ctx)
	log.Info("Configuring pod sandbox", "pod", podID(pod), "id", pod.Id)

	netnsPath, err := p.findNetnsPath(pod)
	if err != nil {
		return fmt.Errorf("unable to determine netns path for pod %s: %w", podID(pod), err)
	}

	if err := p.installIptablesRules(netnsPath); err != nil {
		return fmt.Errorf("install iptables rules for pod %s: %w", podID(pod), err)
	}

	log.Info("Successfully installed iptables rules in pod", "pod", podID(pod), "netns", netnsPath)
	return nil
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

	p := &portalPlugin{cfg: cfg}

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
