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

package portals

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sidecardns "github.com/gke-labs/service-portals/pkg/dns"
	"github.com/gke-labs/service-portals/pkg/proxy"
	"golang.org/x/net/dns/dnsmessage"
)

// TestRule_NoLoop proves that a rule whose host is the real upstream hostname
// (e.g. api.github.com) does not loop through the sidecar DNS server, but instead
// resolves via the explicit upstream resolver to reach the real destination.
func TestRule_NoLoop(t *testing.T) {
	// 1. Mock upstream backend server representing the real api.github.com service
	var receivedAuthHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("X-Backend", "real-api-github-com")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "real backend response")
	}))
	defer backend.Close()

	backendHost, backendPort, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split backend addr: %v", err)
	}
	backendIP := net.ParseIP(backendHost)

	// 2. Mock upstream cluster DNS server:
	// When queried for api.github.com, it resolves to backendIP (the real upstream destination).
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP for mock upstream DNS: %v", err)
	}
	defer upstreamConn.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, clientAddr, err := upstreamConn.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Message
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}

			resp := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       req.Header.ID,
					Response: true,
					RCode:    dnsmessage.RCodeSuccess,
				},
				Questions: req.Questions,
			}
			if len(req.Questions) > 0 && strings.EqualFold(strings.TrimSuffix(req.Questions[0].Name.String(), "."), "api.github.com") {
				var a [4]byte
				copy(a[:], backendIP.To4())
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  req.Questions[0].Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   60,
					},
					Body: &dnsmessage.AResource{A: a},
				})
			} else {
				resp.Header.RCode = dnsmessage.RCodeNameError
			}

			packed, err := resp.Pack()
			if err == nil {
				_, _ = upstreamConn.WriteTo(packed, clientAddr)
			}
		}
	}()

	upstreamDNSAddr := upstreamConn.LocalAddr().String()

	// 3. Sidecar local DNS server:
	// Simulates the sidecar DNS server at 127.0.0.1:53 answering for api.github.com with proxy IP 127.0.0.2.
	// If the proxy dialer accidentally resolved through system/local DNS, it would hit 127.0.0.2 (looping).
	sidecarProxyIP := net.ParseIP("127.0.0.2")
	sidecarDNS, err := sidecardns.NewServer(sidecardns.Config{
		BindAddr:  "127.0.0.1:0",
		ProxyIPv4: sidecarProxyIP,
		Matcher: sidecardns.RuleMatcherFunc(func(host string) bool {
			return host == "api.github.com"
		}),
	})
	if err != nil {
		t.Fatalf("failed to create sidecar DNS: %v", err)
	}
	dnsCtx, cancelDNS := context.WithCancel(t.Context())
	defer cancelDNS()
	if err := sidecarDNS.Start(dnsCtx); err != nil {
		t.Fatalf("failed to start sidecar DNS: %v", err)
	}
	defer func() { _ = sidecarDNS.Shutdown(t.Context()) }()

	// 4. Create rules directory with a rule for api.github.com
	rulesDir := t.TempDir()
	ruleContent := fmt.Sprintf(`
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata:
  name: github
spec:
  host: api.github.com
  rewriteUrl: http://api.github.com:%s
  authToken: swapped-github-secret-token
`, backendPort)

	rulePath := filepath.Join(rulesDir, "github.yaml")
	if err := os.WriteFile(rulePath, []byte(ruleContent), 0644); err != nil {
		t.Fatalf("failed to write rule file: %v", err)
	}

	// 5. Build upstream resolver connected to the mock cluster DNS server
	upstreamResolver := proxy.NewUpstreamResolver([]string{upstreamDNSAddr})

	// 6. Instantiate RuleRouter with the upstream resolver
	rr := NewRuleRouterWithResolver(rulesDir, nil, "", "", 0, nil, upstreamResolver)
	if err := rr.loadRules(); err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	// 7. Make a request to the proxy with Host: api.github.com
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/user", nil)
	req.Host = "api.github.com"

	rr.ServeHTTP(rec, req)

	// 8. Verify the proxy resolved api.github.com via upstream resolver to the mock backend
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	if !strings.Contains(rec.Body.String(), "real backend response") {
		t.Errorf("expected response from real backend, got: %s", rec.Body.String())
	}

	if receivedAuthHeader != "Bearer swapped-github-secret-token" {
		t.Errorf("expected swapped auth token 'Bearer swapped-github-secret-token', got: %s", receivedAuthHeader)
	}
}
