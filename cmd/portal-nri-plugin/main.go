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
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

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
	flag.StringVar(&cfg.proxyHost, "proxy-host", envOrDefault("PROXY_HOST", ""), "Proxy destination host (auto-detected if empty)")
	flag.StringVar(&cfg.proxyPort, "proxy-port", envOrDefault("PROXY_PORT", "8080"), "Proxy HTTP port")
	flag.StringVar(&cfg.proxyHTTPSPort, "proxy-https-port", envOrDefault("PROXY_HTTPS_PORT", "8443"), "Proxy HTTPS port")
	flag.StringVar(&cfg.caCertPath, "ca-cert-path", envOrDefault("CA_CERT_PATH", "/etc/service-portal/ca/tls.crt"), "Host path to CA certificate bundle")
	flag.StringVar(&cfg.interceptHosts, "intercept-hosts", envOrDefault("INTERCEPT_HOSTS", "gemini.backend,github.backend,other.backend"), "Comma-separated hostnames to resolve to intercept IP")
	flag.StringVar(&cfg.interceptIP, "intercept-ip", envOrDefault("INTERCEPT_IP", "8.8.8.8"), "IP address intercepted hostnames resolve to")
	flag.StringVar(&cfg.dnsServers, "dns-servers", envOrDefault("DNS_SERVERS", ""), "Comma-separated cluster DNS server IPs")
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
	// Also accept shorthand portal=true
	if val, ok := pod.Labels["portal"]; ok && val == "true" {
		return true
	}
	return false
}

func (p *portalPlugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	log.Printf("[NRI] Synchronize called: %d pods, %d containers", len(pods), len(containers))
	return nil, nil
}

func (p *portalPlugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	if !p.matchesPod(pod) {
		return nil
	}

	log.Printf("[NRI] Intercepting pod sandbox: %s/%s (ID: %s)", pod.Namespace, pod.Name, pod.Id)

	// 1. Find network namespace path
	netnsPath := p.findNetnsPath(pod)
	if netnsPath == "" {
		return fmt.Errorf("unable to determine netns path for pod %s/%s", pod.Namespace, pod.Name)
	}
	log.Printf("[NRI] Pod %s/%s netns path: %s", pod.Namespace, pod.Name, netnsPath)

	// 2. Determine proxy destination host
	proxyHost := p.cfg.proxyHost
	if proxyHost == "" {
		gw, err := p.detectGateway(netnsPath)
		if err != nil {
			log.Printf("[NRI] Warning: failed to detect gateway for pod %s/%s: %v, defaulting to 10.244.0.1", pod.Namespace, pod.Name, err)
			proxyHost = "10.244.0.1"
		} else {
			proxyHost = gw
		}
	}
	log.Printf("[NRI] Pod %s/%s using proxy host: %s", pod.Namespace, pod.Name, proxyHost)

	// 3. Discover DNS nameservers
	dnsServers := p.discoverDNSServers(pod, netnsPath)
	log.Printf("[NRI] Pod %s/%s DNS servers: %v", pod.Namespace, pod.Name, dnsServers)

	// 4. Install iptables rules inside pod netns
	if err := p.installIptablesRules(netnsPath, proxyHost, dnsServers); err != nil {
		return fmt.Errorf("failed to install iptables rules in pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	log.Printf("[NRI] Successfully installed iptables rules in pod %s/%s", pod.Namespace, pod.Name)

	// 5. Update /etc/hosts for the pod
	if err := p.updatePodHosts(pod); err != nil {
		log.Printf("[NRI] Warning: failed to update pod /etc/hosts for %s/%s: %v", pod.Namespace, pod.Name, err)
	}

	return nil
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

	// Ensure intercepted hosts are present in the pod's etc-hosts file mounted into the container
	for _, m := range ctr.Mounts {
		if m.Destination == "/etc/hosts" && m.Source != "" {
			if err := p.appendHostsEntry(m.Source); err != nil {
				log.Printf("[NRI] Warning: failed to append hosts to %s: %v", m.Source, err)
			}
		}
	}

	adjustment := &api.ContainerAdjustment{}

	// Inject SSL_CERT_FILE environment variable
	adjustment.AddEnv("SSL_CERT_FILE", "/etc/service-portal/ca/tls.crt")

	// Inject bind mount for CA certificate bundle if it exists
	if p.cfg.caCertPath != "" {
		if _, err := os.Stat(p.cfg.caCertPath); err == nil {
			adjustment.AddMount(&api.Mount{
				Destination: "/etc/service-portal/ca/tls.crt",
				Source:      p.cfg.caCertPath,
				Type:        "bind",
				Options:     []string{"rbind", "ro"},
			})
			log.Printf("[NRI] Injected CA cert mount into container %s from %s", ctr.Name, p.cfg.caCertPath)
		} else {
			log.Printf("[NRI] CA certificate not found at %s: %v", p.cfg.caCertPath, err)
		}
	}

	return adjustment, nil, nil
}

func (p *portalPlugin) findNetnsPath(pod *api.PodSandbox) string {
	checkPath := func(path string) string {
		if path == "" {
			return ""
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
		if strings.HasPrefix(path, "/var/run/netns/") {
			canonical := strings.Replace(path, "/var/run/netns/", "/run/netns/", 1)
			if _, err := os.Stat(canonical); err == nil {
				return canonical
			}
		}
		return ""
	}

	if pod.Linux != nil {
		for _, ns := range pod.Linux.Namespaces {
			if ns.Type == "network" && ns.Path != "" {
				if resolved := checkPath(ns.Path); resolved != "" {
					return resolved
				}
			}
		}
	}
	if pod.Pid > 0 {
		procPath := fmt.Sprintf("/proc/%d/ns/net", pod.Pid)
		if resolved := checkPath(procPath); resolved != "" {
			return resolved
		}
	}
	return ""
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

func (p *portalPlugin) discoverDNSServers(pod *api.PodSandbox, netnsPath string) []string {
	var servers []string
	if p.cfg.dnsServers != "" {
		for _, s := range strings.Split(p.cfg.dnsServers, ",") {
			s = strings.TrimSpace(s)
			if net.ParseIP(s) != nil {
				servers = append(servers, s)
			}
		}
		if len(servers) > 0 {
			return servers
		}
	}

	// Try reading containerd sandbox resolv.conf
	sandboxResolv := fmt.Sprintf("/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/%s/resolv.conf", pod.Id)
	if data, err := os.ReadFile(sandboxResolv); err == nil {
		servers = parseResolvConf(string(data))
		if len(servers) > 0 {
			return servers
		}
	}

	// Try reading via nsenter
	cmd := exec.Command("nsenter", "--net="+netnsPath, "cat", "/etc/resolv.conf")
	if out, err := cmd.CombinedOutput(); err == nil {
		servers = parseResolvConf(string(out))
		if len(servers) > 0 {
			return servers
		}
	}

	// Try host resolv.conf
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		servers = parseResolvConf(string(data))
		if len(servers) > 0 {
			return servers
		}
	}

	// Fallback to standard Kubernetes Service cluster DNS
	return []string{"10.96.0.10"}
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
	_ = runCmd("-t", "nat", "-N", "PORTAL_OUTPUT")
	_ = runCmd("-t", "nat", "-F", "PORTAL_OUTPUT")
	_ = runCmd("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", "PORTAL_OUTPUT")
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
	_ = runCmd("-N", "PORTAL_EGRESS")
	_ = runCmd("-F", "PORTAL_EGRESS")
	_ = runCmd("-D", "OUTPUT", "-j", "PORTAL_EGRESS")
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
	_ = runCmd("-A", "PORTAL_EGRESS", "-p", "icmp", "-j", "REJECT")

	return nil
}

func (p *portalPlugin) appendHostsEntry(targetPath string) error {
	hosts := strings.Split(p.cfg.interceptHosts, ",")
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

	entry := fmt.Sprintf("%s %s\n", p.cfg.interceptIP, strings.Join(cleanedHosts, " "))

	content, err := os.ReadFile(targetPath)
	if err != nil {
		return err
	}
	if strings.Contains(string(content), cleanedHosts[0]) {
		return nil
	}

	f, err := os.OpenFile(targetPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		return err
	}
	log.Printf("[NRI] Appended intercept hosts to %s: %s", targetPath, strings.TrimSpace(entry))
	return nil
}

func (p *portalPlugin) updatePodHosts(pod *api.PodSandbox) error {
	podUID := pod.Uid
	if podUID == "" && pod.Labels != nil {
		podUID = pod.Labels["io.kubernetes.pod.uid"]
	}

	var candidatePaths []string
	if podUID != "" {
		candidatePaths = append(candidatePaths, filepath.Join("/var/lib/kubelet/pods", podUID, "etc-hosts"))
	}
	if matches, err := filepath.Glob(fmt.Sprintf("/var/lib/kubelet/pods/*%s*/etc-hosts", podUID)); err == nil {
		candidatePaths = append(candidatePaths, matches...)
	}

	updated := false
	for _, targetPath := range candidatePaths {
		if _, err := os.Stat(targetPath); err == nil {
			if err := p.appendHostsEntry(targetPath); err == nil {
				updated = true
			}
		}
	}

	if !updated {
		return fmt.Errorf("unable to locate etc-hosts for pod UID %s", podUID)
	}
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
