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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/gke-labs/service-portals/pkg/networking"
	"github.com/gke-labs/service-portals/pkg/portals"
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
	adminURL       string
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
	activePods  map[string]portals.PodInfo
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
	flag.StringVar(&cfg.adminURL, "admin-url", envOrDefault("ADMIN_URL", "unix://"+portals.DefaultAdminSocketPath), "URL or unix domain socket of the node proxy admin server")
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
	return pod.Annotations["io.kubernetes.cri.runtime-handler"]
}

func isSupportedRuntime(runtimeClass string) bool {
	switch strings.ToLower(strings.TrimSpace(runtimeClass)) {
	case "", "runc", "gvisor", "runsc", "kata", "kata-qemu", "kata-clh", "kata-fc", "kata-containers":
		return true
	default:
		return false
	}
}

func (p *portalPlugin) validateRuntime(pod *api.PodSandbox) error {
	runtimeClass := getRuntimeClass(pod)
	if !isSupportedRuntime(runtimeClass) {
		return fmt.Errorf("unsupported runtime class %q for opted-in pod %s: refusing to start unprotected pod", runtimeClass, podID(pod))
	}
	return nil
}

func (p *portalPlugin) findHostInterface(ctx context.Context, pod *api.PodSandbox, netnsPath string) (string, string, error) {
	var ips []string
	if pod != nil {
		ips = pod.Ips
	}
	return networking.FindHostInterface(ctx, ips, netnsPath)
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

	rules = append(rules,
		[]string{"-t", "nat", "-N", prChain},
		[]string{"-t", "nat", "-F", prChain},
		[]string{"-t", "nat", "-D", "PREROUTING", "-i", hostIface, "-j", prChain},
		[]string{"-t", "nat", "-I", "PREROUTING", "1", "-i", hostIface, "-j", prChain},
		[]string{"-t", "nat", "-A", prChain, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", net.JoinHostPort(proxyHost, proxyPort)},
		[]string{"-t", "nat", "-A", prChain, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", net.JoinHostPort(proxyHost, proxyHTTPSPort)},
	)

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
				if args[2] == "-N" && strings.Contains(strings.ToLower(msg), "already exists") {
					continue
				}
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

func newAdminHTTPClient(adminURL string) (*http.Client, string, error) {
	if strings.HasPrefix(adminURL, "unix://") || (strings.HasPrefix(adminURL, "/") && !strings.HasPrefix(adminURL, "http")) {
		socketPath := strings.TrimPrefix(adminURL, "unix://")
		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
				},
			},
			Timeout: 2 * time.Second,
		}, "http://unix", nil
	}
	return &http.Client{Timeout: 2 * time.Second}, strings.TrimRight(adminURL, "/"), nil
}

func (p *portalPlugin) notifyPodUpdate(ctx context.Context, method, path string, payload any) error {
	if p.cfg.adminURL == "" {
		return nil
	}
	var data []byte
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal pod payload: %w", err)
		}
		data = b
	}
	client, baseURL, err := newAdminHTTPClient(p.cfg.adminURL)
	if err != nil {
		return fmt.Errorf("invalid admin URL %q: %w", p.cfg.adminURL, err)
	}
	url := baseURL + path
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
		body, rErr := io.ReadAll(resp.Body)
		if rErr != nil {
			body = nil
		}
		if err := resp.Body.Close(); err != nil {
			klog.V(4).Infof("error closing response body: %v", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("admin server returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return nil
	}
	return fmt.Errorf("failed to notify proxy at %s: %w", url, lastErr)
}

func (p *portalPlugin) syncActivePodsWithProxy(ctx context.Context) {
	p.mu.Lock()
	if len(p.activePods) == 0 {
		p.mu.Unlock()
		return
	}
	pods := make([]portals.PodInfo, 0, len(p.activePods))
	for _, pod := range p.activePods {
		pods = append(pods, pod)
	}
	p.mu.Unlock()

	client, baseURL, err := newAdminHTTPClient(p.cfg.adminURL)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/pods", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	var existing []*portals.PodInfo
	if err := json.NewDecoder(resp.Body).Decode(&existing); err != nil {
		if cErr := resp.Body.Close(); cErr != nil {
			klog.V(4).Infof("error closing response body: %v", cErr)
		}
		return
	}
	if err := resp.Body.Close(); err != nil {
		klog.V(4).Infof("error closing response body: %v", err)
	}

	if len(existing) < len(pods) {
		if err := p.notifyPodUpdate(ctx, http.MethodPut, "/api/v1/pods", pods); err != nil {
			klog.V(2).Infof("reconciliation sync to proxy failed: %v", err)
		}
	}
}

func (p *portalPlugin) startProxySyncLoop(ctx context.Context) {
	if p.cfg.adminURL == "" {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.syncActivePodsWithProxy(ctx)
			}
		}
	}()
}

func (p *portalPlugin) configurePod(ctx context.Context, pod *api.PodSandbox) error {
	log := klog.FromContext(ctx)
	log.Info("Configuring pod sandbox", "pod", podID(pod), "id", pod.Id)

	runtimeClass := getRuntimeClass(pod)
	if err := p.validateRuntime(pod); err != nil {
		return err
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
	log := klog.FromContext(ctx)
	if pod == nil {
		return nil
	}

	p.mu.Lock()
	state, found := p.pods[pod.Id]
	if found {
		delete(p.pods, pod.Id)
	}
	delete(p.activePods, pod.Uid)
	p.mu.Unlock()

	var hostIface string
	if found {
		hostIface = state.hostInterface
	} else {
		netnsPath, err := p.findNetnsPath(pod)
		if err != nil {
			log.Error(err, "Could not resolve netns path during cleanup", "pod", podID(pod))
		} else {
			iface, _, err := p.findHostInterface(ctx, pod, netnsPath)
			if err != nil {
				log.Error(err, "Could not find host interface during cleanup", "pod", podID(pod))
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

	if pod.Uid != "" {
		if err := p.notifyPodUpdate(ctx, http.MethodDelete, "/api/v1/pods/"+pod.Uid, nil); err != nil {
			log.Error(err, "Failed to unregister pod with proxy", "pod", podID(pod))
			return fmt.Errorf("unregister pod %s with proxy: %w", podID(pod), err)
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
	var syncedPods []portals.PodInfo

	p.mu.Lock()
	p.activePods = make(map[string]portals.PodInfo)
	p.mu.Unlock()

	for _, pod := range pods {
		if !p.matchesPod(pod) {
			continue
		}
		log.Info("Synchronizing existing intercepted pod sandbox", "pod", podID(pod), "id", pod.Id)
		if err := p.configurePod(ctx, pod); err != nil {
			log.Error(err, "Error synchronizing rules for pod", "pod", podID(pod))
			syncErrors = append(syncErrors, fmt.Errorf("pod %s: %w", podID(pod), err))
		} else {
			p.mu.Lock()
			state := p.pods[pod.Id]
			p.mu.Unlock()

			var ips []string
			if len(pod.Ips) > 0 {
				ips = pod.Ips
			} else if state.podIP != "" {
				ips = []string{state.podIP}
			}
			info := portals.PodInfo{
				UID:         pod.Uid,
				Namespace:   pod.Namespace,
				Name:        pod.Name,
				IPs:         ips,
				Annotations: pod.Annotations,
				Labels:      pod.Labels,
			}
			syncedPods = append(syncedPods, info)

			p.mu.Lock()
			p.activePods[pod.Uid] = info
			p.mu.Unlock()
		}
	}

	if len(syncedPods) > 0 {
		if err := p.notifyPodUpdate(ctx, http.MethodPut, "/api/v1/pods", syncedPods); err != nil {
			log.Error(err, "Failed to synchronize pods with proxy")
			return nil, fmt.Errorf("synchronize pods with proxy: %w", err)
		}
	}

	if len(syncErrors) > 0 {
		return nil, errors.Join(syncErrors...)
	}
	return nil, nil
}

func (p *portalPlugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	log := klog.FromContext(ctx)
	if !p.matchesPod(pod) {
		return nil
	}
	if err := p.validateRuntime(pod); err != nil {
		return err
	}
	if err := p.configurePod(ctx, pod); err != nil {
		return err
	}

	p.mu.Lock()
	state := p.pods[pod.Id]
	p.mu.Unlock()

	var ips []string
	if len(pod.Ips) > 0 {
		ips = pod.Ips
	} else if state.podIP != "" {
		ips = []string{state.podIP}
	}

	info := portals.PodInfo{
		UID:         pod.Uid,
		Namespace:   pod.Namespace,
		Name:        pod.Name,
		IPs:         ips,
		Annotations: pod.Annotations,
		Labels:      pod.Labels,
	}

	if err := p.notifyPodUpdate(ctx, http.MethodPost, "/api/v1/pods", info); err != nil {
		log.Error(err, "Failed to register pod with proxy", "pod", podID(pod))
		if cErr := p.cleanupPod(ctx, pod); cErr != nil {
			log.Error(cErr, "Failed to cleanup pod after registration failure", "pod", podID(pod))
		}
		return fmt.Errorf("register pod %s with proxy: %w", podID(pod), err)
	}

	p.mu.Lock()
	p.activePods[pod.Uid] = info
	p.mu.Unlock()

	return nil
}

func (p *portalPlugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	if !p.matchesPod(pod) {
		return nil, nil, nil
	}

	if err := p.validateRuntime(pod); err != nil {
		return nil, nil, err
	}

	log := klog.FromContext(ctx)
	log.Info("Intercepting container creation", "pod", podID(pod), "container", ctr.Name)

	if _, err := os.Stat(p.cfg.caCertPath); err != nil {
		return nil, nil, fmt.Errorf("CA certificate bundle not found at %s: %w", p.cfg.caCertPath, err)
	}

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

func runBindCommand(args []string) {
	fs := flag.NewFlagSet("bind", flag.ExitOnError)
	socket := fs.String("socket", portals.DefaultAdminSocketPath, "Path to admin unix domain socket or HTTP URL")
	uid := fs.String("uid", "", "Pod UID to bind")
	identity := fs.String("identity", "", "User identity")
	policy := fs.String("policy", "", "Allowed policy rules")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *uid == "" {
		fmt.Fprintf(os.Stderr, "error: --uid is required\n")
		os.Exit(1)
	}

	client, baseURL, err := newAdminHTTPClient(*socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating client: %v\n", err)
		os.Exit(1)
	}

	payload, err := json.Marshal(portals.BindRequest{
		PodUID:   *uid,
		Identity: *identity,
		Policy:   *policy,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling bind payload: %v\n", err)
		os.Exit(1)
	}
	resp, err := client.Post(baseURL+"/bind", "application/json", bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintf(os.Stderr, "bind request failed: %v\n", err)
		os.Exit(1)
	}
	body, rErr := io.ReadAll(resp.Body)
	if rErr != nil {
		body = nil
	}
	if err := resp.Body.Close(); err != nil {
		klog.V(4).Infof("error closing response body: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "bind failed (status %d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(body))
}

func runUnbindCommand(args []string) {
	fs := flag.NewFlagSet("unbind", flag.ExitOnError)
	socket := fs.String("socket", portals.DefaultAdminSocketPath, "Path to admin unix domain socket or HTTP URL")
	uid := fs.String("uid", "", "Pod UID to unbind")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *uid == "" {
		fmt.Fprintf(os.Stderr, "error: --uid is required\n")
		os.Exit(1)
	}

	client, baseURL, err := newAdminHTTPClient(*socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating client: %v\n", err)
		os.Exit(1)
	}

	payload, err := json.Marshal(portals.UnbindRequest{
		PodUID: *uid,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling unbind payload: %v\n", err)
		os.Exit(1)
	}
	resp, err := client.Post(baseURL+"/unbind", "application/json", bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintf(os.Stderr, "unbind request failed: %v\n", err)
		os.Exit(1)
	}
	body, rErr := io.ReadAll(resp.Body)
	if rErr != nil {
		body = nil
	}
	if err := resp.Body.Close(); err != nil {
		klog.V(4).Infof("error closing response body: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "unbind failed (status %d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(body))
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "bind":
			runBindCommand(os.Args[2:])
			return
		case "unbind":
			runUnbindCommand(os.Args[2:])
			return
		}
	}

	klog.InitFlags(nil)
	cfg, err := parseFlags()
	if err != nil {
		klog.Fatalf("Invalid configuration: %v", err)
	}

	p := &portalPlugin{
		cfg:        cfg,
		pods:       make(map[string]podNetworkState),
		activePods: make(map[string]portals.PodInfo),
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

	p.startProxySyncLoop(ctx)

	klog.Infof("Starting portal-nri-plugin (name=%s, index=%s, socket=%s, proxyHost=%s, adminURL=%s)...", cfg.pluginName, cfg.pluginIndex, cfg.socketPath, cfg.proxyHost, cfg.adminURL)
	if err := s.Run(ctx); err != nil {
		klog.Fatalf("NRI stub run failed: %v", err)
	}
}
