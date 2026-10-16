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
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

type pluginConfig struct {
	socketPath     string
	pluginName     string
	pluginIdx      string
	interceptLabel string
	proxyHost      string
	proxyPort      string
	proxyHTTPSPort string
	caCertPath     string
	interceptHosts string
	interceptIP    string
	dnsServers     string
	nodeTaint      string
	nodeName       string
	labelKey       string
	labelVal       string
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

func parseFlags() pluginConfig {
	var cfg pluginConfig
	flag.StringVar(&cfg.socketPath, "socket-path", envOrDefault("NRI_SOCKET_PATH", "/var/run/nri/nri.sock"), "Path to containerd NRI socket")
	flag.StringVar(&cfg.pluginName, "plugin-name", envOrDefault("NRI_PLUGIN_NAME", "service-portal"), "NRI plugin name")
	flag.StringVar(&cfg.pluginIdx, "plugin-idx", envOrDefault("NRI_PLUGIN_IDX", "01"), "NRI plugin index")
	flag.StringVar(&cfg.interceptLabel, "intercept-label", envOrDefault("INTERCEPT_LABEL", "service-portal.gke.io/intercept=true"), "Pod label key=value to intercept")
	flag.StringVar(&cfg.proxyHost, "proxy-host", envOrDefault("PROXY_HOST", ""), "Proxy destination host (auto-detected via gateway if empty)")
	flag.StringVar(&cfg.proxyPort, "proxy-port", envOrDefault("PROXY_PORT", "8080"), "Proxy HTTP port")
	flag.StringVar(&cfg.proxyHTTPSPort, "proxy-https-port", envOrDefault("PROXY_HTTPS_PORT", "8443"), "Proxy HTTPS port")
	flag.StringVar(&cfg.caCertPath, "ca-cert-path", envOrDefault("CA_CERT_PATH", "/etc/service-portal/ca/tls.crt"), "Host path to CA certificate bundle")
	flag.StringVar(&cfg.interceptHosts, "intercept-hosts", envOrDefault("INTERCEPT_HOSTS", "gemini.backend,github.backend,other.backend"), "Comma-separated hostnames to resolve to intercept IP")
	flag.StringVar(&cfg.interceptIP, "intercept-ip", envOrDefault("INTERCEPT_IP", ""), "IP address intercepted hostnames resolve to")
	flag.StringVar(&cfg.dnsServers, "dns-servers", envOrDefault("DNS_SERVERS", ""), "Comma-separated cluster DNS server IPs")
	flag.StringVar(&cfg.nodeTaint, "node-taint", envOrDefault("NODE_TAINT", ""), "Node taint (key or key:effect) to remove when plugin is synchronized")
	flag.StringVar(&cfg.nodeName, "node-name", envOrDefault("NODE_NAME", ""), "Node name for node taint gating")
	flag.Parse()

	parts := strings.SplitN(cfg.interceptLabel, "=", 2)
	cfg.labelKey = parts[0]
	if len(parts) > 1 {
		cfg.labelVal = parts[1]
	} else {
		cfg.labelVal = "true"
	}

	return cfg
}

func (p *portalPlugin) matchesPod(pod *api.PodSandbox) bool {
	if pod == nil {
		return false
	}
	if val, ok := pod.Labels[p.cfg.labelKey]; ok && val == p.cfg.labelVal {
		return true
	}
	if val, ok := pod.Annotations[p.cfg.labelKey]; ok && val == p.cfg.labelVal {
		return true
	}
	return false
}

func (p *portalPlugin) getInterceptIP(pod *api.PodSandbox) string {
	if pod != nil && pod.Annotations != nil {
		if ip := pod.Annotations["service-portal.gke.io/intercept-ip"]; ip != "" {
			return strings.TrimSpace(ip)
		}
	}
	if pod != nil && pod.Labels != nil {
		if ip := pod.Labels["service-portal.gke.io/intercept-ip"]; ip != "" {
			return strings.TrimSpace(ip)
		}
	}
	return strings.TrimSpace(p.cfg.interceptIP)
}

func (p *portalPlugin) getInterceptHosts(pod *api.PodSandbox) string {
	if pod != nil && pod.Annotations != nil {
		if hosts := pod.Annotations["service-portal.gke.io/intercept-hosts"]; hosts != "" {
			return strings.TrimSpace(hosts)
		}
	}
	return strings.TrimSpace(p.cfg.interceptHosts)
}

func (p *portalPlugin) configurePod(pod *api.PodSandbox, isSync bool) error {
	log.Printf("[NRI] Configuring pod sandbox: %s/%s (ID: %s, isSync: %v)", pod.Namespace, pod.Name, pod.Id, isSync)

	// 1. Find network namespace path
	netnsPath, err := p.findNetnsPath(pod)
	if err != nil {
		return fmt.Errorf("unable to determine netns path for pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	log.Printf("[NRI] Pod %s/%s netns path: %s", pod.Namespace, pod.Name, netnsPath)

	// 2. Determine proxy destination host (strict: fail closed on error, no silent fallbacks)
	proxyHost := p.cfg.proxyHost
	if proxyHost == "" {
		gw, err := p.detectGateway(netnsPath)
		if err != nil {
			return fmt.Errorf("failed to detect gateway for pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		proxyHost = gw
	}
	log.Printf("[NRI] Pod %s/%s using proxy host: %s", pod.Namespace, pod.Name, proxyHost)

	// 3. Discover DNS nameservers (strict: fail closed on error, no silent fallbacks)
	dnsServers, err := p.discoverDNSServers(pod, netnsPath)
	if err != nil {
		return fmt.Errorf("failed to discover DNS servers for pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	log.Printf("[NRI] Pod %s/%s DNS servers: %v", pod.Namespace, pod.Name, dnsServers)

	// 4. Validate intercept IP (strict: fail closed if unconfigured, no silent fallbacks)
	interceptIP := p.getInterceptIP(pod)
	if interceptIP == "" || net.ParseIP(interceptIP) == nil {
		return fmt.Errorf("invalid or missing intercept IP (%q) for pod %s/%s; must be configured via --intercept-ip, INTERCEPT_IP env, or pod annotation service-portal.gke.io/intercept-ip", interceptIP, pod.Namespace, pod.Name)
	}

	// 5. Install iptables rules inside pod netns
	if err := p.installIptablesRules(netnsPath, proxyHost, dnsServers); err != nil {
		return fmt.Errorf("failed to install iptables rules in pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	log.Printf("[NRI] Successfully installed iptables rules in pod %s/%s", pod.Namespace, pod.Name)

	// 6. Update /etc/hosts for the pod
	// In RunPodSandbox, kubelet has not yet created /var/lib/kubelet/pods/<uid>/etc-hosts (it is created
	// when kubelet starts containers). Therefore, hosts file absence is non-fatal during RunPodSandbox
	// (entries are appended when CreateContainer receives the /etc/hosts mount).
	// In Synchronize, sandboxes are already running, so etc-hosts is required.
	interceptHosts := p.getInterceptHosts(pod)
	if err := p.updatePodHosts(pod, interceptHosts, interceptIP); err != nil {
		if isSync {
			return fmt.Errorf("failed to update pod /etc/hosts for %s/%s during synchronize: %w", pod.Namespace, pod.Name, err)
		}
		log.Printf("[NRI] Notice: pod /etc/hosts not present yet during RunPodSandbox for %s/%s: %v (will be appended in CreateContainer)", pod.Namespace, pod.Name, err)
	}

	return nil
}

func (p *portalPlugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	log.Printf("[NRI] Synchronize called: %d pods, %d containers", len(pods), len(containers))

	// Re-apply rules to all already-running opted-in sandboxes.
	// Log per-pod errors and continue so a single stale sandbox does not fail plugin registration.
	for _, pod := range pods {
		if !p.matchesPod(pod) {
			continue
		}
		log.Printf("[NRI] Synchronizing existing intercepted pod sandbox: %s/%s (ID: %s)", pod.Namespace, pod.Name, pod.Id)
		if err := p.configurePod(pod, true); err != nil {
			log.Printf("[NRI] Error synchronizing rules for pod %s/%s: %v", pod.Namespace, pod.Name, err)
			continue
		}
	}

	// If node taint gating is configured, remove the taint from this node
	if err := p.removeNodeTaint(ctx); err != nil {
		log.Printf("[NRI] Warning: failed to remove node taint: %v", err)
	}

	return nil, nil
}

func (p *portalPlugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	if !p.matchesPod(pod) {
		return nil
	}

	return p.configurePod(pod, false)
}

func (p *portalPlugin) StopPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	if p.matchesPod(pod) {
		log.Printf("[NRI] StopPodSandbox for intercepted pod: %s/%s", pod.Namespace, pod.Name)
	}
	return nil
}

func (p *portalPlugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	if !p.matchesPod(pod) {
		return nil, nil, nil
	}

	log.Printf("[NRI] Intercepting container creation: pod=%s/%s container=%s", pod.Namespace, pod.Name, ctr.Name)

	interceptIP := p.getInterceptIP(pod)
	interceptHosts := p.getInterceptHosts(pod)
	if interceptIP != "" && net.ParseIP(interceptIP) != nil {
		// Ensure intercepted hosts are present in the pod's etc-hosts file mounted into the container
		for _, m := range ctr.Mounts {
			if m.Destination == "/etc/hosts" && m.Source != "" {
				if err := p.appendHostsEntry(m.Source, interceptHosts, interceptIP); err != nil {
					log.Printf("[NRI] Warning: failed to append hosts to %s: %v", m.Source, err)
				}
			}
		}
	}

	adjustment := &api.ContainerAdjustment{}

	// Inject SSL_CERT_FILE environment variable
	adjustment.AddEnv("SSL_CERT_FILE", "/etc/service-portal/ca/tls.crt")

	// Inject bind mount for CA certificate bundle if it exists
	if p.cfg.caCertPath != "" {
		if _, err := os.Stat(p.cfg.caCertPath); err != nil {
			log.Printf("[NRI] CA certificate not found at %s: %v", p.cfg.caCertPath, err)
		} else {
			adjustment.AddMount(&api.Mount{
				Destination: "/etc/service-portal/ca/tls.crt",
				Source:      p.cfg.caCertPath,
				Type:        "bind",
				Options:     []string{"rbind", "ro"},
			})
			log.Printf("[NRI] Injected CA cert mount into container %s from %s", ctr.Name, p.cfg.caCertPath)
		}
	}

	return adjustment, nil, nil
}

func (p *portalPlugin) findNetnsPath(pod *api.PodSandbox) (string, error) {
	checkPath := func(path string) (string, error) {
		if path == "" {
			return "", nil
		}
		if _, err := os.Stat(path); err != nil {
			if !os.IsNotExist(err) {
				return "", fmt.Errorf("stat %s: %w", path, err)
			}
			return "", nil
		}
		return path, nil
	}

	if pod.Linux != nil {
		for _, ns := range pod.Linux.Namespaces {
			if ns.Type == "network" && ns.Path != "" {
				resolved, err := checkPath(ns.Path)
				if err != nil {
					return "", err
				}
				if resolved != "" {
					return resolved, nil
				}
				if strings.HasPrefix(ns.Path, "/var/run/netns/") {
					canonical := strings.Replace(ns.Path, "/var/run/netns/", "/run/netns/", 1)
					canonicalResolved, err := checkPath(canonical)
					if err != nil {
						return "", err
					}
					if canonicalResolved != "" {
						return canonicalResolved, nil
					}
				}
			}
		}
	}
	if pod.Pid > 0 {
		procPath := fmt.Sprintf("/proc/%d/ns/net", pod.Pid)
		resolved, err := checkPath(procPath)
		if err != nil {
			return "", err
		}
		if resolved != "" {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("unable to determine netns path for pod %s/%s", pod.Namespace, pod.Name)
}

func (p *portalPlugin) detectGateway(netnsPath string) (string, error) {
	cmd := exec.Command("nsenter", "--net="+netnsPath, "ip", "route", "show", "default")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ip route failed: %w (output: %s)", err, out)
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			gw := fields[i+1]
			if net.ParseIP(gw) != nil {
				return gw, nil
			}
		}
	}
	return "", fmt.Errorf("no default gateway found in route output: %s", out)
}

func (p *portalPlugin) discoverDNSServers(pod *api.PodSandbox, netnsPath string) ([]string, error) {
	var servers []string
	if p.cfg.dnsServers != "" {
		for _, s := range strings.Split(p.cfg.dnsServers, ",") {
			s = strings.TrimSpace(s)
			if net.ParseIP(s) != nil {
				servers = append(servers, s)
			}
		}
		if len(servers) > 0 {
			return servers, nil
		}
	}

	// Read containerd sandbox resolv.conf. Do NOT fall back to nsenter or host resolv.conf
	// (hostNetwork DaemonSet reading host resolv.conf yields Docker/metadata resolver which silently blocks cluster DNS).
	sandboxResolv := fmt.Sprintf("/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/%s/resolv.conf", pod.Id)
	data, err := os.ReadFile(sandboxResolv)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[NRI] Warning: failed to read sandbox resolv.conf at %s: %v", sandboxResolv, err)
		}
	} else {
		servers = parseResolvConf(string(data))
		if len(servers) > 0 {
			return servers, nil
		}
	}

	return nil, fmt.Errorf("failed to discover cluster DNS servers for pod %s/%s (requires DNS_SERVERS or containerd sandbox resolv.conf)", pod.Namespace, pod.Name)
}

func parseResolvConf(content string) []string {
	var servers []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip := parts[1]
				if net.ParseIP(ip) != nil {
					servers = append(servers, ip)
				}
			}
		}
	}
	return servers
}

func (p *portalPlugin) installIptablesRules(netnsPath, proxyHost string, dnsServers []string) error {
	runCmd := func(args ...string) error {
		cmdArgs := append([]string{"--net=" + netnsPath, "iptables"}, args...)
		cmd := exec.Command("nsenter", cmdArgs...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %v failed: %w (output: %s)", args, err, out)
		}
		return nil
	}

	// 1. NAT table: REDIRECT / DNAT
	if err := runCmd("-t", "nat", "-N", "PORTAL_OUTPUT"); err != nil {
		if flushErr := runCmd("-t", "nat", "-F", "PORTAL_OUTPUT"); flushErr != nil {
			return fmt.Errorf("failed to initialize PORTAL_OUTPUT nat chain: %w", flushErr)
		}
	}
	if err := runCmd("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", "PORTAL_OUTPUT"); err != nil {
		log.Printf("[NRI] Debug: nat OUTPUT jump rule not present or delete returned: %v", err)
	}
	if err := runCmd("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "PORTAL_OUTPUT"); err != nil {
		return err
	}
	if err := runCmd("-t", "nat", "-A", "PORTAL_OUTPUT", "-o", "lo", "-j", "RETURN"); err != nil {
		return err
	}
	if err := runCmd("-t", "nat", "-A", "PORTAL_OUTPUT", "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", proxyHost+":"+p.cfg.proxyPort); err != nil {
		return err
	}
	if err := runCmd("-t", "nat", "-A", "PORTAL_OUTPUT", "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", proxyHost+":"+p.cfg.proxyHTTPSPort); err != nil {
		return err
	}

	// 2. Filter table: Egress isolation and default-deny
	if err := runCmd("-N", "PORTAL_EGRESS"); err != nil {
		if flushErr := runCmd("-F", "PORTAL_EGRESS"); flushErr != nil {
			return fmt.Errorf("failed to initialize PORTAL_EGRESS filter chain: %w", flushErr)
		}
	}
	if err := runCmd("-D", "OUTPUT", "-j", "PORTAL_EGRESS"); err != nil {
		log.Printf("[NRI] Debug: filter OUTPUT jump rule not present or delete returned: %v", err)
	}
	if err := runCmd("-A", "OUTPUT", "-j", "PORTAL_EGRESS"); err != nil {
		return err
	}
	if err := runCmd("-A", "PORTAL_EGRESS", "-o", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := runCmd("-A", "PORTAL_EGRESS", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := runCmd("-A", "PORTAL_EGRESS", "-d", proxyHost, "-p", "tcp", "--dport", p.cfg.proxyPort, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := runCmd("-A", "PORTAL_EGRESS", "-d", proxyHost, "-p", "tcp", "--dport", p.cfg.proxyHTTPSPort, "-j", "ACCEPT"); err != nil {
		return err
	}
	for _, dns := range dnsServers {
		if err := runCmd("-A", "PORTAL_EGRESS", "-d", dns, "-p", "udp", "--dport", "53", "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := runCmd("-A", "PORTAL_EGRESS", "-d", dns, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	if err := runCmd("-A", "PORTAL_EGRESS", "-p", "tcp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"); err != nil {
		return err
	}
	if err := runCmd("-A", "PORTAL_EGRESS", "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"); err != nil {
		return err
	}
	if err := runCmd("-A", "PORTAL_EGRESS", "-p", "icmp", "-j", "REJECT"); err != nil {
		return err
	}

	return nil
}

func (p *portalPlugin) appendHostsEntry(targetPath, hostsStr, interceptIP string) (retErr error) {
	hosts := strings.Split(hostsStr, ",")
	var cleanedHosts []string
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h != "" {
			cleanedHosts = append(cleanedHosts, h)
		}
	}
	if len(cleanedHosts) == 0 {
		return nil
	}

	entry := fmt.Sprintf("%s %s\n", interceptIP, strings.Join(cleanedHosts, " "))

	content, err := os.ReadFile(targetPath)
	if err != nil {
		return fmt.Errorf("failed to read hosts file %s: %w", targetPath, err)
	}
	if strings.Contains(string(content), cleanedHosts[0]) {
		return nil
	}

	f, err := os.OpenFile(targetPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open hosts file %s: %w", targetPath, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("failed to close hosts file %s: %w", targetPath, closeErr)
		}
	}()

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("failed to write hosts entry to %s: %w", targetPath, err)
	}
	log.Printf("[NRI] Appended intercept hosts to %s: %s", targetPath, strings.TrimSpace(entry))
	return nil
}

func (p *portalPlugin) updatePodHosts(pod *api.PodSandbox, hostsStr, interceptIP string) error {
	podUID := pod.Uid
	if podUID == "" && pod.Labels != nil {
		podUID = pod.Labels["io.kubernetes.pod.uid"]
	}
	if podUID == "" {
		return fmt.Errorf("pod %s/%s has empty UID", pod.Namespace, pod.Name)
	}

	var candidatePaths []string
	candidatePaths = append(candidatePaths, filepath.Join("/var/lib/kubelet/pods", podUID, "etc-hosts"))
	matches, err := filepath.Glob(fmt.Sprintf("/var/lib/kubelet/pods/*%s*/etc-hosts", podUID))
	if err != nil {
		log.Printf("[NRI] Warning: glob failed for pod UID %s etc-hosts: %v", podUID, err)
	} else {
		candidatePaths = append(candidatePaths, matches...)
	}

	updated := false
	for _, targetPath := range candidatePaths {
		if _, err := os.Stat(targetPath); err != nil {
			if !os.IsNotExist(err) {
				log.Printf("[NRI] Warning: stat %s failed: %v", targetPath, err)
			}
			continue
		}
		if err := p.appendHostsEntry(targetPath, hostsStr, interceptIP); err != nil {
			log.Printf("[NRI] Warning: failed appending hosts to %s: %v", targetPath, err)
		} else {
			updated = true
		}
	}

	if !updated {
		return fmt.Errorf("unable to locate etc-hosts for pod UID %s", podUID)
	}
	return nil
}

func (p *portalPlugin) removeNodeTaint(ctx context.Context) error {
	if p.cfg.nodeTaint == "" || p.cfg.nodeName == "" {
		return nil
	}

	apiHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	apiPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if apiHost == "" || apiPort == "" {
		log.Printf("[NRI] Not running in Kubernetes or KUBERNETES_SERVICE_HOST not set; skipping node taint removal")
		return nil
	}

	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return fmt.Errorf("failed to read serviceaccount token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))

	caCertPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read serviceaccount ca.crt: %w", err)
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to append serviceaccount ca cert to cert pool")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 10 * time.Second,
	}

	nodeURL := fmt.Sprintf("https://%s:%s/api/v1/nodes/%s", apiHost, apiPort, p.cfg.nodeName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nodeURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create node GET request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get node %s: %w", p.cfg.nodeName, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("[NRI] Warning: failed to close node GET response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("getting node %s failed with status %d (read error: %v)", p.cfg.nodeName, resp.StatusCode, readErr)
		}
		return fmt.Errorf("getting node %s failed with status %d: %s", p.cfg.nodeName, resp.StatusCode, body)
	}

	var nodeObj struct {
		Spec struct {
			Taints []struct {
				Key    string `json:"key"`
				Value  string `json:"value,omitempty"`
				Effect string `json:"effect,omitempty"`
			} `json:"taints"`
		} `json:"spec"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&nodeObj); err != nil {
		return fmt.Errorf("failed to decode node response: %w", err)
	}

	targetKey := p.cfg.nodeTaint
	targetEffect := ""
	if parts := strings.SplitN(p.cfg.nodeTaint, ":", 2); len(parts) == 2 {
		targetKey = parts[0]
		targetEffect = parts[1]
	}

	remainingTaints := make([]any, 0)
	taintFound := false
	for _, t := range nodeObj.Spec.Taints {
		if t.Key == targetKey && (targetEffect == "" || t.Effect == targetEffect) {
			taintFound = true
			continue
		}
		remainingTaints = append(remainingTaints, t)
	}

	if !taintFound {
		log.Printf("[NRI] Node taint %q not found on node %s", p.cfg.nodeTaint, p.cfg.nodeName)
		return nil
	}

	patchData := map[string]any{
		"spec": map[string]any{
			"taints": remainingTaints,
		},
	}
	patchBytes, err := json.Marshal(patchData)
	if err != nil {
		return fmt.Errorf("failed to marshal node patch: %w", err)
	}

	patchReq, err := http.NewRequestWithContext(ctx, http.MethodPatch, nodeURL, bytes.NewReader(patchBytes))
	if err != nil {
		return fmt.Errorf("failed to create node patch request: %w", err)
	}
	patchReq.Header.Set("Authorization", "Bearer "+token)
	patchReq.Header.Set("Content-Type", "application/strategic-merge-patch+json")

	patchResp, err := client.Do(patchReq)
	if err != nil {
		return fmt.Errorf("failed to patch node %s: %w", p.cfg.nodeName, err)
	}
	defer func() {
		if closeErr := patchResp.Body.Close(); closeErr != nil {
			log.Printf("[NRI] Warning: failed to close node patch response body: %v", closeErr)
		}
	}()

	if patchResp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(patchResp.Body)
		if readErr != nil {
			return fmt.Errorf("patching node %s failed with status %d (read error: %v)", p.cfg.nodeName, patchResp.StatusCode, readErr)
		}
		return fmt.Errorf("patching node %s failed with status %d: %s", p.cfg.nodeName, patchResp.StatusCode, body)
	}

	log.Printf("[NRI] Successfully removed taint %q from node %s", p.cfg.nodeTaint, p.cfg.nodeName)
	return nil
}

func main() {
	cfg := parseFlags()
	p := &portalPlugin{cfg: cfg}

	s, err := stub.New(p,
		stub.WithPluginName(cfg.pluginName),
		stub.WithPluginIdx(cfg.pluginIdx),
		stub.WithSocketPath(cfg.socketPath),
	)
	if err != nil {
		log.Fatalf("Failed to create NRI stub: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	log.Printf("Starting portal-nri-plugin (name=%s, idx=%s, socket=%s)...", cfg.pluginName, cfg.pluginIdx, cfg.socketPath)
	if err := s.Run(ctx); err != nil {
		log.Fatalf("NRI stub run failed: %v", err)
	}
}
