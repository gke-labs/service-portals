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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"sigs.k8s.io/yaml"
)

// PluginConf represents the configuration parsed from the CNI network config list.
type PluginConf struct {
	types.NetConf
	ProxyPort      int    `json:"proxyPort"`
	ProxyHTTPSPort int    `json:"proxyHttpsPort"`
	InterceptPorts string `json:"interceptPorts"`
	GatewayIP      string `json:"gatewayIP"`
	ClusterDNS     string `json:"clusterDNS"`
	Kubeconfig     string `json:"kubeconfig"`
	OptInLabel     string `json:"optInLabel"`
	OptInValue     string `json:"optInValue"`
}

// KubeConfig represents minimal kubeconfig structure needed to query the API server.
type KubeConfig struct {
	Clusters []struct {
		Cluster struct {
			Server                   string `json:"server" yaml:"server"`
			CertificateAuthority     string `json:"certificate-authority" yaml:"certificate-authority"`
			CertificateAuthorityData string `json:"certificate-authority-data" yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `json:"insecure-skip-tls-verify" yaml:"insecure-skip-tls-verify"`
		} `json:"cluster" yaml:"cluster"`
		Name string `json:"name" yaml:"name"`
	} `json:"clusters" yaml:"clusters"`
	Users []struct {
		Name string `json:"name" yaml:"name"`
		User struct {
			Token string `json:"token" yaml:"token"`
		} `json:"user" yaml:"user"`
	} `json:"users" yaml:"users"`
}

// PodMetadata represents the minimal pod JSON from the Kubernetes API.
type PodMetadata struct {
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, "service-portal-cni")
}

func parseConf(stdin []byte) (*PluginConf, error) {
	conf := &PluginConf{
		ProxyPort:      8080,
		ProxyHTTPSPort: 8443,
		InterceptPorts: "80,443",
		OptInLabel:     "portals.gke.io/intercept",
		OptInValue:     "true",
		Kubeconfig:     "/etc/cni/net.d/service-portal.kubeconfig",
	}

	if err := json.Unmarshal(stdin, conf); err != nil {
		return nil, fmt.Errorf("failed to parse netconf: %w", err)
	}

	// Parse previous result if present in chaining mode
	if err := version.ParsePrevResult(&conf.NetConf); err != nil {
		return nil, fmt.Errorf("failed to parse prevResult: %w", err)
	}

	return conf, nil
}

func parseCNIArgs(argsStr string) (podNamespace, podName string) {
	for _, pair := range strings.Split(argsStr, ";") {
		k, v, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		switch k {
		case "K8S_POD_NAMESPACE":
			podNamespace = v
		case "K8S_POD_NAME":
			podName = v
		}
	}
	return
}

func cmdCheck(args *skel.CmdArgs) error {
	return nil
}

func cmdDel(args *skel.CmdArgs) error {
	// In CNI DEL, the network namespace is about to be deleted by the container runtime.
	// Netfilter rules inside the pod netns are automatically reclaimed with the netns.
	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}

	podNamespace, podName := parseCNIArgs(args.Args)
	if podNamespace == "" || podName == "" {
		// Non-Kubernetes container, pass through unchanged
		return outputResult(conf)
	}

	// Check if the pod is selected
	selected, err := isPodSelected(conf, podNamespace, podName)
	if err != nil {
		log.Printf("service-portal-cni: failed to look up pod %s/%s: %v", podNamespace, podName, err)
		// Fail-closed: if we cannot determine pod policy due to API error, fail pod sandbox creation
		return fmt.Errorf("service-portal-cni: failed to query pod %s/%s: %w", podNamespace, podName, err)
	}

	if !selected {
		// Pod not selected, pass through unchanged
		return outputResult(conf)
	}

	log.Printf("service-portal-cni: pod %s/%s is selected for egress interception", podNamespace, podName)

	if args.Netns == "" {
		return fmt.Errorf("service-portal-cni: missing Netns in CNI args for selected pod %s/%s", podNamespace, podName)
	}

	// Determine gateway IP (host proxy IP) from pod netns routes or configuration
	gatewayIP := conf.GatewayIP
	if gatewayIP == "" {
		gw, err := discoverGatewayIP(args.Netns)
		if err != nil {
			return fmt.Errorf("failed to discover gateway IP in netns %s: %w", args.Netns, err)
		}
		gatewayIP = gw
	}

	// Determine cluster DNS IP(s)
	clusterDNS := conf.ClusterDNS
	if clusterDNS == "" {
		dnsIP, err := discoverClusterDNS(conf)
		if err != nil {
			log.Printf("service-portal-cni: could not discover cluster DNS via API, defaulting to 10.96.0.10: %v", err)
			clusterDNS = "10.96.0.10"
		} else {
			clusterDNS = dnsIP
		}
	}

	// Install iptables redirect and egress filtering rules inside pod netns
	if err := configureNetnsRules(args.Netns, gatewayIP, clusterDNS, conf.ProxyPort, conf.ProxyHTTPSPort, conf.InterceptPorts); err != nil {
		return fmt.Errorf("failed to configure iptables rules in netns %s: %w", args.Netns, err)
	}

	log.Printf("service-portal-cni: successfully installed redirect/deny rules for %s/%s (gateway=%s, dns=%s)",
		podNamespace, podName, gatewayIP, clusterDNS)

	return outputResult(conf)
}

func outputResult(conf *PluginConf) error {
	if conf.PrevResult != nil {
		return types.PrintResult(conf.PrevResult, conf.CNIVersion)
	}
	res := &types100.Result{
		CNIVersion: conf.CNIVersion,
	}
	return types.PrintResult(res, conf.CNIVersion)
}

func isPodSelected(conf *PluginConf, namespace, name string) (bool, error) {
	client, baseURL, token, err := getKubeClient(conf.Kubeconfig)
	if err != nil {
		return false, fmt.Errorf("failed to create kube client: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s", strings.TrimRight(baseURL, "/"), namespace, name)

	// Retry briefly in case of API server propagation delay
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			return false, err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil {
				log.Printf("service-portal-cni: error closing response body: %v", closeErr)
			}
		}()

		if resp.StatusCode == http.StatusNotFound {
			lastErr = fmt.Errorf("pod %s/%s not found (HTTP 404)", namespace, name)
			time.Sleep(250 * time.Millisecond)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return false, fmt.Errorf("status code %d from API server (and failed reading body: %w)", resp.StatusCode, readErr)
			}
			return false, fmt.Errorf("unexpected status code %d from API server: %s", resp.StatusCode, string(body))
		}

		var pod PodMetadata
		if err := json.NewDecoder(resp.Body).Decode(&pod); err != nil {
			return false, fmt.Errorf("failed to decode pod response: %w", err)
		}

		// Check opt-in label
		if val, ok := pod.Metadata.Labels[conf.OptInLabel]; ok && val == conf.OptInValue {
			return true, nil
		}
		// Also check opt-in annotation
		if val, ok := pod.Metadata.Annotations[conf.OptInLabel]; ok && val == conf.OptInValue {
			return true, nil
		}
		// Also match if PortalPolicy annotation is present
		if val, ok := pod.Metadata.Annotations["portals.gke.io/policy"]; ok && val != "" {
			return true, nil
		}

		return false, nil
	}

	return false, lastErr
}

func getKubeClient(kubeconfigPath string) (*http.Client, string, string, error) {
	// 1. Try reading kubeconfig file
	if kubeconfigPath != "" {
		data, err := os.ReadFile(kubeconfigPath)
		if err != nil {
			log.Printf("service-portal-cni: failed to read kubeconfig %s: %v", kubeconfigPath, err)
		} else {
			var kc KubeConfig
			if err := yaml.Unmarshal(data, &kc); err == nil && len(kc.Clusters) > 0 {
				server := kc.Clusters[0].Cluster.Server
				token := ""
				if len(kc.Users) > 0 {
					token = kc.Users[0].User.Token
				}

				tlsConfig := &tls.Config{
					InsecureSkipVerify: kc.Clusters[0].Cluster.InsecureSkipTLSVerify,
				}

				log.Printf("service-portal-cni: read kubeconfig server=%s caDataLen=%d caFile=%s",
					server, len(kc.Clusters[0].Cluster.CertificateAuthorityData), kc.Clusters[0].Cluster.CertificateAuthority)
				if kc.Clusters[0].Cluster.CertificateAuthorityData != "" {
					caBytes, err := base64.StdEncoding.DecodeString(kc.Clusters[0].Cluster.CertificateAuthorityData)
					if err != nil {
						caBytes = []byte(kc.Clusters[0].Cluster.CertificateAuthorityData)
					}
					cp := x509.NewCertPool()
					ok := cp.AppendCertsFromPEM(caBytes)
					log.Printf("service-portal-cni: AppendCertsFromPEM from caData ok=%v", ok)
					tlsConfig.RootCAs = cp
				} else if kc.Clusters[0].Cluster.CertificateAuthority != "" {
					caBytes, err := os.ReadFile(kc.Clusters[0].Cluster.CertificateAuthority)
					if err == nil {
						cp := x509.NewCertPool()
						cp.AppendCertsFromPEM(caBytes)
						tlsConfig.RootCAs = cp
					} else {
						// If path in container does not exist on host, try host PKI path
						if hostCA, err := os.ReadFile("/etc/kubernetes/pki/ca.crt"); err == nil {
							cp := x509.NewCertPool()
							cp.AppendCertsFromPEM(hostCA)
							tlsConfig.RootCAs = cp
						} else {
							log.Printf("service-portal-cni: failed to read host CA: %v", err)
						}
					}
				}

				tr := &http.Transport{
					TLSClientConfig: tlsConfig,
					DialContext: (&net.Dialer{
						Timeout: 5 * time.Second,
					}).DialContext,
				}
				return &http.Client{Transport: tr, Timeout: 5 * time.Second}, server, token, nil
			}
		}
	}

	// 2. Try in-cluster environment
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host != "" && port != "" {
		server := fmt.Sprintf("https://%s:%s", host, port)
		tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		token := ""
		if err != nil {
			log.Printf("service-portal-cni: could not read serviceaccount token: %v", err)
		} else {
			token = strings.TrimSpace(string(tokenBytes))
		}

		tlsConfig := &tls.Config{}
		caBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
		if err != nil {
			log.Printf("service-portal-cni: could not read serviceaccount ca.crt: %v", err)
		} else {
			cp := x509.NewCertPool()
			cp.AppendCertsFromPEM(caBytes)
			tlsConfig.RootCAs = cp
		}

		tr := &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		return &http.Client{Transport: tr, Timeout: 5 * time.Second}, server, token, nil
	}

	// 3. Fallback: localhost kind apiserver
	server := "https://127.0.0.1:6443"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}, server, "", nil
}

func discoverGatewayIP(netnsPath string) (string, error) {
	// Execute `ip route show default` inside the pod netns via nsenter
	out, err := exec.Command("nsenter", "--net="+netnsPath, "ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ip route failed: %v (output: %s)", err, string(out))
	}

	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("could not find default gateway in route output: %s", string(out))
}

func discoverClusterDNS(conf *PluginConf) (string, error) {
	client, baseURL, token, err := getKubeClient(conf.Kubeconfig)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/kube-system/services/kube-dns", strings.TrimRight(baseURL, "/"))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("service-portal-cni: error closing response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	var svc struct {
		Spec struct {
			ClusterIP string `json:"clusterIP"`
		} `json:"spec"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&svc); err != nil {
		return "", err
	}

	if svc.Spec.ClusterIP != "" {
		return svc.Spec.ClusterIP, nil
	}

	return "", fmt.Errorf("empty clusterIP on kube-dns service")
}

func configureNetnsRules(netnsPath, gatewayIP, clusterDNS string, proxyPort, proxyHTTPSPort int, interceptPorts string) error {
	run := func(args ...string) error {
		cmdArgs := append([]string{"--net=" + netnsPath, "iptables"}, args...)
		cmd := exec.Command("nsenter", cmdArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables %v failed: %w (output: %s)", args, err, string(out))
		}
		return nil
	}

	// 1. NAT Table: Redirection
	if err := run("-t", "nat", "-N", "PORTAL_OUTPUT"); err != nil {
		log.Printf("service-portal-cni: ignoring NAT table PORTAL_OUTPUT creation error: %v", err)
	}
	if err := run("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "PORTAL_OUTPUT"); err != nil {
		return err
	}
	if err := run("-t", "nat", "-A", "PORTAL_OUTPUT", "-o", "lo", "-j", "RETURN"); err != nil {
		return err
	}
	// Exclude proxy UID 1337 in case proxy process or sidecar runs locally
	if err := run("-t", "nat", "-A", "PORTAL_OUTPUT", "-m", "owner", "--uid-owner", "1337", "-j", "RETURN"); err != nil {
		log.Printf("service-portal-cni: ignoring NAT table UID 1337 rule error: %v", err)
	}

	// Redirect ports to gateway IP (where node DaemonSet proxy is listening)
	dstHTTP := fmt.Sprintf("%s:%d", gatewayIP, proxyPort)
	dstHTTPS := fmt.Sprintf("%s:%d", gatewayIP, proxyHTTPSPort)

	for _, p := range strings.Split(interceptPorts, ",") {
		port := strings.TrimSpace(p)
		if port == "" {
			continue
		}
		if port == "443" {
			if err := run("-t", "nat", "-A", "PORTAL_OUTPUT", "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", dstHTTPS); err != nil {
				return err
			}
		} else {
			if err := run("-t", "nat", "-A", "PORTAL_OUTPUT", "-p", "tcp", "--dport", port, "-j", "DNAT", "--to-destination", dstHTTP); err != nil {
				return err
			}
		}
	}

	// 2. Filter Table: Default-Deny & Egress Enforcement
	// Loopback
	if err := run("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	// Conntrack established/related
	if err := run("-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	// Proxy UID exemption (defense in depth)
	if err := run("-A", "OUTPUT", "-m", "owner", "--uid-owner", "1337", "-j", "ACCEPT"); err != nil {
		log.Printf("service-portal-cni: ignoring filter table UID 1337 rule error: %v", err)
	}

	// Allow Cluster DNS only
	if clusterDNS != "" {
		for _, dnsIP := range strings.Split(clusterDNS, ",") {
			ip := strings.TrimSpace(dnsIP)
			if ip == "" {
				continue
			}
			if err := run("-A", "OUTPUT", "-p", "udp", "-d", ip, "--dport", "53", "-j", "ACCEPT"); err != nil {
				return err
			}
			if err := run("-A", "OUTPUT", "-p", "tcp", "-d", ip, "--dport", "53", "-j", "ACCEPT"); err != nil {
				return err
			}
		}
	}

	// Allow traffic to node proxy (Gateway IP on PROXY_PORT and PROXY_HTTPS_PORT)
	if err := run("-A", "OUTPUT", "-p", "tcp", "-d", gatewayIP, "--dport", strconv.Itoa(proxyPort), "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := run("-A", "OUTPUT", "-p", "tcp", "-d", gatewayIP, "--dport", strconv.Itoa(proxyHTTPSPort), "-j", "ACCEPT"); err != nil {
		return err
	}

	// Reject all other outbound TCP and UDP
	if err := run("-A", "OUTPUT", "-p", "tcp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"); err != nil {
		return err
	}
	if err := run("-A", "OUTPUT", "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"); err != nil {
		return err
	}

	return nil
}
