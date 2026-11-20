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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/service-portals/pkg/dns"
	portalsv1 "github.com/gke-labs/service-portals/pkg/portals/v1"
	"github.com/gke-labs/service-portals/pkg/proxy"
	"golang.org/x/net/dns/dnsmessage"
)

func newTestEnv(t *testing.T) (*PodMap, *portalsv1.BindingStore) {
	t.Helper()
	pm := NewPodMap()
	store, err := portalsv1.NewBindingStore("")
	if err != nil {
		t.Fatalf("failed to create BindingStore: %v", err)
	}
	return pm, store
}

// dialRoutingTransport creates an http.Transport that routes requests destined for targetAddr
// to the upstream listener address over TCP.
func dialRoutingTransport(upstreamAddr string, tlsConfig *tls.Config) http.RoundTripper {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig: tlsConfig,
	}
	return tr
}

func TestEgressHandler_MatchingRequestReplacesPlaceholder(t *testing.T) {
	var upstreamCalled atomic.Int32
	var receivedAuth string
	var receivedHost string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled.Add(1)
		receivedAuth = r.Header.Get("Authorization")
		receivedHost = r.Host
		w.Header().Set("X-Upstream-Resp", "ok")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from upstream"))
	}))
	defer upstream.Close()

	pm, store := newTestEnv(t)
	podIP := "10.244.1.5"
	podUID := "pod-test-uid"

	pm.AddOrUpdatePod(&PodInfo{
		UID:       podUID,
		Namespace: "default",
		Name:      "test-pod",
		IPs:       []string{podIP},
	})

	_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"api.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{80},
						},
						Effects: &portalsv1.HttpRuleEffects{
							ReplaceHeaders: []*portalsv1.CredentialHeader{
								{
									Header:        "Authorization",
									Prefix:        "Bearer ",
									CredentialUri: "secret://github-token",
								},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	_, err = store.InjectSecrets(t.Context(), &portalsv1.PodSecrets{
		PodUid: podUID,
		Secrets: map[string][]byte{
			"github-token": []byte("ghp_realSecretToken123"),
		},
	})
	if err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}

	transport := dialRoutingTransport(upstream.Listener.Addr().String(), nil)
	handler := NewEgressHandler(pm, store, transport, nil)

	req := httptest.NewRequest("GET", "http://api.example.com/v1/user", nil)
	req.RemoteAddr = podIP + ":45678"
	req.Header.Set("Authorization", "placeholder-token")
	req.Header.Set("Connection", "close")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if upstreamCalled.Load() != 1 {
		t.Fatalf("expected upstream to be called once, got %d", upstreamCalled.Load())
	}
	if receivedAuth != "Bearer ghp_realSecretToken123" {
		t.Errorf("expected Authorization 'Bearer ghp_realSecretToken123', got %q", receivedAuth)
	}
	if receivedHost != "api.example.com" {
		t.Errorf("expected Host 'api.example.com', got %q", receivedHost)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from upstream" {
		t.Errorf("expected body 'hello from upstream', got %q", string(body))
	}
	if resp.Header.Get("X-Upstream-Resp") != "ok" {
		t.Errorf("expected X-Upstream-Resp 'ok', got %q", resp.Header.Get("X-Upstream-Resp"))
	}
}

func TestEgressHandler_RequestWithoutPlaceholderForwardedWithoutOne(t *testing.T) {
	var upstreamCalled atomic.Int32
	var receivedAuth string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled.Add(1)
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	pm, store := newTestEnv(t)
	podIP := "10.244.1.5"
	podUID := "pod-test-uid"

	pm.AddOrUpdatePod(&PodInfo{
		UID: podUID,
		IPs: []string{podIP},
	})

	_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"api.example.com"},
						Ports:     &portalsv1.Ports{Numbers: []int32{80}},
						Effects: &portalsv1.HttpRuleEffects{
							ReplaceHeaders: []*portalsv1.CredentialHeader{
								{
									Header:        "Authorization",
									Prefix:        "Bearer ",
									CredentialUri: "secret://my-token",
								},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	_, err = store.InjectSecrets(t.Context(), &portalsv1.PodSecrets{
		PodUid: podUID,
		Secrets: map[string][]byte{
			"my-token": []byte("super-secret"),
		},
	})
	if err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}

	transport := dialRoutingTransport(upstream.Listener.Addr().String(), nil)
	handler := NewEgressHandler(pm, store, transport, nil)

	req := httptest.NewRequest("GET", "http://api.example.com/public", nil)
	req.RemoteAddr = podIP + ":54321"
	// Request carries no Authorization header

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if upstreamCalled.Load() != 1 {
		t.Fatalf("expected upstream to be called once, got %d", upstreamCalled.Load())
	}
	if receivedAuth != "" {
		t.Errorf("expected no Authorization header forwarded, got %q", receivedAuth)
	}
}

func TestEgressHandler_RefusalsReachNothingUpstream(t *testing.T) {
	var upstreamCalled atomic.Int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	transport := dialRoutingTransport(upstream.Listener.Addr().String(), nil)

	t.Run("unknown source address", func(t *testing.T) {
		upstreamCalled.Store(0)
		pm, store := newTestEnv(t)
		handler := NewEgressHandler(pm, store, transport, nil)

		req := httptest.NewRequest("GET", "http://api.example.com/test", nil)
		req.RemoteAddr = "192.168.1.99:50000" // Not in PodMap

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
		}
		if upstreamCalled.Load() != 0 {
			t.Errorf("expected 0 calls reaching upstream, got %d", upstreamCalled.Load())
		}
	})

	t.Run("unbound pod", func(t *testing.T) {
		upstreamCalled.Store(0)
		pm, store := newTestEnv(t)
		podIP := "10.0.0.10"
		podUID := "pod-unbound"
		pm.AddOrUpdatePod(&PodInfo{UID: podUID, IPs: []string{podIP}})
		// Pod registered in PodMap but never bound in store

		handler := NewEgressHandler(pm, store, transport, nil)

		ctx, cancel := context.WithCancel(t.Context())
		req := httptest.NewRequest("GET", "http://api.example.com/test", nil).WithContext(ctx)
		req.RemoteAddr = podIP + ":50000"

		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			handler.ServeHTTP(w, req)
			close(done)
		}()

		// Handler must hold the request without returning an immediate 403 response
		select {
		case <-done:
			t.Fatal("expected ServeHTTP to hold request for unbound pod, but it returned immediately")
		case <-time.After(50 * time.Millisecond):
		}

		// When client times out / cancels connection, handler exits cleanly
		cancel()
		<-done

		if w.Body.Len() != 0 {
			t.Errorf("expected 0 response bytes, got %d (body: %s)", w.Body.Len(), w.Body.String())
		}
		if upstreamCalled.Load() != 0 {
			t.Errorf("expected 0 calls reaching upstream, got %d", upstreamCalled.Load())
		}
	})

	t.Run("non-matching host", func(t *testing.T) {
		upstreamCalled.Store(0)
		pm, store := newTestEnv(t)
		podIP := "10.0.0.11"
		podUID := "pod-bound"
		pm.AddOrUpdatePod(&PodInfo{UID: podUID, IPs: []string{podIP}})

		_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
			PodUid: podUID,
			Policy: &portalsv1.EgressPolicy{
				Rules: []*portalsv1.EgressRule{
					{
						Http: &portalsv1.HttpRule{
							Hostnames: []string{"allowed.example.com"},
							Ports:     &portalsv1.Ports{Numbers: []int32{80}},
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("Bind failed: %v", err)
		}

		handler := NewEgressHandler(pm, store, transport, nil)

		req := httptest.NewRequest("GET", "http://denied.example.com/test", nil)
		req.RemoteAddr = podIP + ":50000"

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
		}
		if upstreamCalled.Load() != 0 {
			t.Errorf("expected 0 calls reaching upstream, got %d", upstreamCalled.Load())
		}
	})

	t.Run("non-matching port", func(t *testing.T) {
		upstreamCalled.Store(0)
		pm, store := newTestEnv(t)
		podIP := "10.0.0.12"
		podUID := "pod-bound-port"
		pm.AddOrUpdatePod(&PodInfo{UID: podUID, IPs: []string{podIP}})

		_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
			PodUid: podUID,
			Policy: &portalsv1.EgressPolicy{
				Rules: []*portalsv1.EgressRule{
					{
						Http: &portalsv1.HttpRule{
							Hostnames: []string{"api.example.com"},
							Ports:     &portalsv1.Ports{Numbers: []int32{80}},
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("Bind failed: %v", err)
		}

		handler := NewEgressHandler(pm, store, transport, nil)

		req := httptest.NewRequest("GET", "http://api.example.com:8080/test", nil)
		req.RemoteAddr = podIP + ":50000"

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
		}
		if upstreamCalled.Load() != 0 {
			t.Errorf("expected 0 calls reaching upstream, got %d", upstreamCalled.Load())
		}
	})

	t.Run("wrong protocol", func(t *testing.T) {
		upstreamCalled.Store(0)
		pm, store := newTestEnv(t)
		podIP := "10.0.0.13"
		podUID := "pod-https-only"
		pm.AddOrUpdatePod(&PodInfo{UID: podUID, IPs: []string{podIP}})

		// Rule allows HTTPS only
		_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
			PodUid: podUID,
			Policy: &portalsv1.EgressPolicy{
				Rules: []*portalsv1.EgressRule{
					{
						Https: &portalsv1.HttpsRule{
							Hostnames: []string{"api.example.com"},
							Ports:     &portalsv1.Ports{Numbers: []int32{443}},
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("Bind failed: %v", err)
		}

		handler := NewEgressHandler(pm, store, transport, nil)

		// Request is cleartext HTTP
		req := httptest.NewRequest("GET", "http://api.example.com/test", nil)
		req.RemoteAddr = podIP + ":50000"

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
		}
		if upstreamCalled.Load() != 0 {
			t.Errorf("expected 0 calls reaching upstream, got %d", upstreamCalled.Load())
		}
	})

	t.Run("missing secret", func(t *testing.T) {
		upstreamCalled.Store(0)
		pm, store := newTestEnv(t)
		podIP := "10.0.0.14"
		podUID := "pod-missing-secret"
		pm.AddOrUpdatePod(&PodInfo{UID: podUID, IPs: []string{podIP}})

		_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
			PodUid: podUID,
			Policy: &portalsv1.EgressPolicy{
				Rules: []*portalsv1.EgressRule{
					{
						Http: &portalsv1.HttpRule{
							Hostnames: []string{"api.example.com"},
							Ports:     &portalsv1.Ports{Numbers: []int32{80}},
							Effects: &portalsv1.HttpRuleEffects{
								ReplaceHeaders: []*portalsv1.CredentialHeader{
									{
										Header:        "Authorization",
										CredentialUri: "secret://unregistered-secret",
									},
								},
							},
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("Bind failed: %v", err)
		}
		// No secret injected!

		handler := NewEgressHandler(pm, store, transport, nil)

		req := httptest.NewRequest("GET", "http://api.example.com/test", nil)
		req.RemoteAddr = podIP + ":50000"
		req.Header.Set("Authorization", "placeholder")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
		}
		if upstreamCalled.Load() != 0 {
			t.Errorf("expected 0 calls reaching upstream, got %d", upstreamCalled.Load())
		}
	})

	t.Run("reject CONNECT", func(t *testing.T) {
		upstreamCalled.Store(0)
		pm, store := newTestEnv(t)
		handler := NewEgressHandler(pm, store, transport, nil)

		req := httptest.NewRequest(http.MethodConnect, "http://api.example.com:443", nil)
		req.RemoteAddr = "10.0.0.1:12345"

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 Method Not Allowed, got %d", resp.StatusCode)
		}
		if upstreamCalled.Load() != 0 {
			t.Errorf("expected 0 calls reaching upstream, got %d", upstreamCalled.Load())
		}
	})
}

func TestEgressHandler_SecretsIsolatedBetweenPods(t *testing.T) {
	var receivedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	pm, store := newTestEnv(t)
	transport := dialRoutingTransport(upstream.Listener.Addr().String(), nil)
	handler := NewEgressHandler(pm, store, transport, nil)

	podAIP := "10.1.0.1"
	podAUID := "pod-a"
	podBIP := "10.1.0.2"
	podBUID := "pod-b"

	pm.AddOrUpdatePod(&PodInfo{UID: podAUID, IPs: []string{podAIP}})
	pm.AddOrUpdatePod(&PodInfo{UID: podBUID, IPs: []string{podBIP}})

	policy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Http: &portalsv1.HttpRule{
					Hostnames: []string{"api.example.com"},
					Ports:     &portalsv1.Ports{Numbers: []int32{80}},
					Effects: &portalsv1.HttpRuleEffects{
						ReplaceHeaders: []*portalsv1.CredentialHeader{
							{
								Header:        "Authorization",
								Prefix:        "Bearer ",
								CredentialUri: "secret://api-key",
							},
						},
					},
				},
			},
		},
	}

	if _, err := store.Bind(t.Context(), &portalsv1.PodPolicy{PodUid: podAUID, Policy: policy}); err != nil {
		t.Fatalf("Bind pod A failed: %v", err)
	}
	if _, err := store.Bind(t.Context(), &portalsv1.PodPolicy{PodUid: podBUID, Policy: policy}); err != nil {
		t.Fatalf("Bind pod B failed: %v", err)
	}

	if _, err := store.InjectSecrets(t.Context(), &portalsv1.PodSecrets{
		PodUid:  podAUID,
		Secrets: map[string][]byte{"api-key": []byte("secret-token-A")},
	}); err != nil {
		t.Fatalf("InjectSecrets pod A failed: %v", err)
	}
	if _, err := store.InjectSecrets(t.Context(), &portalsv1.PodSecrets{
		PodUid:  podBUID,
		Secrets: map[string][]byte{"api-key": []byte("secret-token-B")},
	}); err != nil {
		t.Fatalf("InjectSecrets pod B failed: %v", err)
	}

	// Pod A request
	reqA := httptest.NewRequest("GET", "http://api.example.com/data", nil)
	reqA.RemoteAddr = podAIP + ":12345"
	reqA.Header.Set("Authorization", "placeholder")

	wA := httptest.NewRecorder()
	handler.ServeHTTP(wA, reqA)
	if wA.Result().StatusCode != http.StatusOK {
		t.Fatalf("pod A request failed with status %d", wA.Result().StatusCode)
	}
	if receivedAuth != "Bearer secret-token-A" {
		t.Errorf("expected pod A to get 'Bearer secret-token-A', got %q", receivedAuth)
	}

	// Pod B request
	reqB := httptest.NewRequest("GET", "http://api.example.com/data", nil)
	reqB.RemoteAddr = podBIP + ":54321"
	reqB.Header.Set("Authorization", "placeholder")

	wB := httptest.NewRecorder()
	handler.ServeHTTP(wB, reqB)
	if wB.Result().StatusCode != http.StatusOK {
		t.Fatalf("pod B request failed with status %d", wB.Result().StatusCode)
	}
	if receivedAuth != "Bearer secret-token-B" {
		t.Errorf("expected pod B to get 'Bearer secret-token-B', got %q", receivedAuth)
	}

	// If pod A's secret is removed via empty inject, pod A must not receive pod B's secret
	if _, err := store.InjectSecrets(t.Context(), &portalsv1.PodSecrets{
		PodUid:  podAUID,
		Secrets: map[string][]byte{},
	}); err != nil {
		t.Fatalf("InjectSecrets pod A empty failed: %v", err)
	}

	wA2 := httptest.NewRecorder()
	reqA2 := httptest.NewRequest("GET", "http://api.example.com/data", nil)
	reqA2.RemoteAddr = podAIP + ":12345"
	reqA2.Header.Set("Authorization", "placeholder")

	handler.ServeHTTP(wA2, reqA2)
	if wA2.Result().StatusCode != http.StatusForbidden {
		t.Errorf("expected pod A with cleared secrets to be 403 Forbidden, got %d", wA2.Result().StatusCode)
	}
}

func TestEgressHandler_HTTPSMatchingRequest(t *testing.T) {
	var receivedAuth string
	var upstreamCalled atomic.Int32

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled.Add(1)
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("tls ok"))
	}))
	defer upstream.Close()

	pm, store := newTestEnv(t)
	podIP := "10.244.2.10"
	podUID := "pod-https-uid"

	pm.AddOrUpdatePod(&PodInfo{UID: podUID, IPs: []string{podIP}})

	_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Https: &portalsv1.HttpsRule{
						Hostnames: []string{"api.secure.com"},
						Ports:     &portalsv1.Ports{Numbers: []int32{443}},
						Effects: &portalsv1.HttpRuleEffects{
							ReplaceHeaders: []*portalsv1.CredentialHeader{
								{
									Header:        "Authorization",
									Prefix:        "Bearer ",
									CredentialUri: "secret://tls-token",
								},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	_, err = store.InjectSecrets(t.Context(), &portalsv1.PodSecrets{
		PodUid: podUID,
		Secrets: map[string][]byte{
			"tls-token": []byte("secureTokenSecret"),
		},
	})
	if err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}

	tlsConfig := upstream.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.InsecureSkipVerify = true
	transport := dialRoutingTransport(upstream.Listener.Addr().String(), tlsConfig)

	handler := NewEgressHandler(pm, store, transport, nil)

	req := httptest.NewRequest("GET", "https://api.secure.com/secure/endpoint", nil)
	req.RemoteAddr = podIP + ":41234"
	req.Header.Set("Authorization", "placeholder")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if upstreamCalled.Load() != 1 {
		t.Fatalf("expected upstream to be called once, got %d", upstreamCalled.Load())
	}
	if receivedAuth != "Bearer secureTokenSecret" {
		t.Errorf("expected 'Bearer secureTokenSecret', got %q", receivedAuth)
	}
}

func TestEgressHandler_DefaultTransportDirectAddress(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("direct ok"))
	}))
	defer upstream.Close()

	_, portStr, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort failed: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	pm, store := newTestEnv(t)
	podIP := "10.244.3.1"
	podUID := "pod-direct"

	pm.AddOrUpdatePod(&PodInfo{UID: podUID, IPs: []string{podIP}})

	_, err = store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"localhost"},
						Ports:     &portalsv1.Ports{Numbers: []int32{int32(port)}},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// NewEgressHandler with nil transport defaults to http.DefaultTransport
	handler := NewEgressHandler(pm, store, nil, nil)

	req := httptest.NewRequest("GET", "http://localhost:"+portStr+"/direct", nil)
	req.RemoteAddr = podIP + ":34567"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "direct ok" {
		t.Errorf("expected body 'direct ok', got %q", string(body))
	}
}

func TestEgressHandler_ClearTextRequestWithHTTPSAbsoluteFormTargetMatchedAsHTTP(t *testing.T) {
	var upstreamCalled atomic.Int32
	var receivedHost string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled.Add(1)
		receivedHost = r.Host
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("cleartext ok"))
	}))
	defer upstream.Close()

	pm, store := newTestEnv(t)
	podIP := "10.244.4.1"
	podUID := "pod-cleartext"
	pm.AddOrUpdatePod(&PodInfo{UID: podUID, IPs: []string{podIP}})

	// Policy has an HTTP rule for api.example.com on port 80.
	_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"api.example.com"},
						Ports:     &portalsv1.Ports{Numbers: []int32{80}},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	transport := dialRoutingTransport(upstream.Listener.Addr().String(), nil)
	handler := NewEgressHandler(pm, store, transport, nil)

	// Send a clear-text request (r.TLS == nil) where the client specifies an absolute-form https:// URI.
	// httptest.NewRequest sets req.TLS when the URL starts with https://, so clear req.TLS to represent
	// a request received on the clear-text HTTP listener.
	// Because the connection is cleartext, the protocol must be evaluated strictly as http, matching
	// the HTTP rule rather than allowing the client to select the https protocol.
	req := httptest.NewRequest("GET", "https://api.example.com/endpoint", nil)
	req.TLS = nil
	req.RemoteAddr = podIP + ":45000"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if upstreamCalled.Load() != 1 {
		t.Fatalf("expected upstream to be called once, got %d", upstreamCalled.Load())
	}
	if receivedHost != "api.example.com" {
		t.Errorf("expected Host 'api.example.com', got %q", receivedHost)
	}

	// Verify that if the policy only allows HTTPS, the cleartext request with https:// URI is denied.
	_, err = store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Https: &portalsv1.HttpsRule{
						Hostnames: []string{"api.example.com"},
						Ports:     &portalsv1.Ports{Numbers: []int32{443}},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind HTTPS-only policy failed: %v", err)
	}

	upstreamCalled.Store(0)
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "https://api.example.com/endpoint", nil)
	req2.TLS = nil
	req2.RemoteAddr = podIP + ":45000"

	handler.ServeHTTP(w2, req2)
	resp2 := w2.Result()
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 Forbidden when cleartext request hits HTTPS-only policy, got %d", resp2.StatusCode)
	}
	if upstreamCalled.Load() != 0 {
		t.Errorf("expected 0 calls reaching upstream for forbidden cleartext request, got %d", upstreamCalled.Load())
	}
}

func TestRequestTarget(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		tls         bool
		wantHost    string
		wantPort    int32
		wantErrText string
	}{
		{
			name:        "empty host",
			host:        "",
			wantErrText: "missing host",
		},
		{
			name:     "cleartext default port 80",
			host:     "api.example.com",
			tls:      false,
			wantHost: "api.example.com",
			wantPort: 80,
		},
		{
			name:     "tls default port 443",
			host:     "api.example.com",
			tls:      true,
			wantHost: "api.example.com",
			wantPort: 443,
		},
		{
			name:     "explicit port overrides default",
			host:     "api.example.com:8080",
			tls:      false,
			wantHost: "api.example.com",
			wantPort: 8080,
		},
		{
			name:     "trailing dot is stripped and normalized to lower",
			host:     "API.EXAMPLE.COM.",
			tls:      false,
			wantHost: "api.example.com",
			wantPort: 80,
		},
		{
			name:        "invalid port string",
			host:        "api.example.com:notaport",
			wantErrText: "invalid port",
		},
		{
			name:        "port zero",
			host:        "api.example.com:0",
			wantErrText: "invalid port",
		},
		{
			name:     "ipv6 literal without port",
			host:     "[::1]",
			tls:      false,
			wantHost: "::1",
			wantPort: 80,
		},
		{
			name:     "ipv6 literal with port",
			host:     "[::1]:8443",
			tls:      false,
			wantHost: "::1",
			wantPort: 8443,
		},
		{
			name:        "invalid host multiple colons without brackets",
			host:        "foo:bar:baz",
			wantErrText: "invalid host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://placeholder/", nil)
			req.Host = tt.host
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			} else {
				req.TLS = nil
			}

			gotHost, gotPort, err := requestTarget(req)
			if tt.wantErrText != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrText)
				}
				if !strings.Contains(err.Error(), tt.wantErrText) {
					t.Errorf("expected error containing %q, got %v", tt.wantErrText, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotHost != tt.wantHost {
				t.Errorf("host = %q, want %q", gotHost, tt.wantHost)
			}
			if gotPort != tt.wantPort {
				t.Errorf("port = %d, want %d", gotPort, tt.wantPort)
			}
		})
	}
}

type mockConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *mockConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *mockConn) Read(b []byte) (n int, err error) {
	if c.Conn != nil {
		return c.Conn.Read(b)
	}
	return 0, io.EOF
}

func TestEgressHandler_GetCertificate(t *testing.T) {
	caCertPath, caKeyPath := createTestCA(t)
	signer, err := proxy.NewCertSigner(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("failed to create CertSigner: %v", err)
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("failed to read ca.crt: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	pm, store := newTestEnv(t)
	podIP := "10.244.1.5"
	podUID := "pod-bound-tls"

	pm.AddOrUpdatePod(&PodInfo{
		UID:       podUID,
		Namespace: "default",
		Name:      "tls-pod",
		IPs:       []string{podIP},
	})

	_, err = store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Https: &portalsv1.HttpsRule{
						Hostnames: []string{"api.example.com", "*.sub.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{443},
						},
					},
				},
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"cleartext.example.com"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	// Register an unbound pod in PodMap (not bound in store)
	unboundIP := "10.244.1.20"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       "pod-unbound",
		Namespace: "default",
		Name:      "unbound-pod",
		IPs:       []string{unboundIP},
	})

	handler := NewEgressHandler(pm, store, nil, signer)

	clientHello := func(sni, remoteAddr string) *tls.ClientHelloInfo {
		var conn net.Conn
		if remoteAddr != "" {
			conn = &mockConn{remoteAddr: parseRemoteAddr(remoteAddr)}
		}
		return &tls.ClientHelloInfo{
			ServerName: sni,
			Conn:       conn,
		}
	}

	t.Run("bound pod gets certificate that chains to test CA and is valid for name", func(t *testing.T) {
		cert, err := handler.GetCertificate(clientHello("api.example.com", podIP+":12345"))
		if err != nil {
			t.Fatalf("expected certificate, got error: %v", err)
		}
		if cert == nil || len(cert.Certificate) == 0 {
			t.Fatal("expected non-empty certificate")
		}

		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse leaf certificate: %v", err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:   caPool,
			DNSName: "api.example.com",
		}); err != nil {
			t.Errorf("certificate failed verification against CA: %v", err)
		}
	})

	t.Run("unknown source address gets no certificate", func(t *testing.T) {
		_, err := handler.GetCertificate(clientHello("api.example.com", "10.99.99.99:12345"))
		if err == nil {
			t.Fatal("expected error for unknown source address, got nil")
		}
		if !strings.Contains(err.Error(), "unknown caller") {
			t.Errorf("expected error to mention unknown caller, got: %v", err)
		}
	})

	t.Run("unbound pod gets no certificate", func(t *testing.T) {
		_, err := handler.GetCertificate(clientHello("api.example.com", unboundIP+":12345"))
		if err == nil {
			t.Fatal("expected error for unbound pod, got nil")
		}
		if !strings.Contains(err.Error(), "unbound pod") {
			t.Errorf("expected error to mention unbound pod, got: %v", err)
		}
	})

	t.Run("unbound pod holds TLS connection without immediate error", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		info := &tls.ClientHelloInfo{
			ServerName: "api.example.com",
			Conn:       &mockConn{Conn: serverConn, remoteAddr: parseRemoteAddr(unboundIP + ":12345")},
		}

		done := make(chan struct{})
		go func() {
			_, _ = handler.GetCertificate(info)
			close(done)
		}()

		select {
		case <-done:
			t.Fatal("expected GetCertificate to hold connection for unbound pod, but returned immediately")
		case <-time.After(50 * time.Millisecond):
		}

		// Client closes connection; GetCertificate unblocks cleanly
		_ = clientConn.Close()
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("expected GetCertificate to return after client closed connection")
		}
	})

	t.Run("empty server name gets no certificate", func(t *testing.T) {
		_, err := handler.GetCertificate(clientHello("", podIP+":12345"))
		if err == nil {
			t.Fatal("expected error for empty server name, got nil")
		}
		if !strings.Contains(err.Error(), "missing server name") {
			t.Errorf("expected error to mention missing server name, got: %v", err)
		}
	})

	t.Run("repeated handshakes for same name do not sign again", func(t *testing.T) {
		cert1, err := handler.GetCertificate(clientHello("api.example.com", podIP+":12345"))
		if err != nil {
			t.Fatalf("first GetCertificate failed: %v", err)
		}

		// Subsequent handshake for the same host (including case and trailing dot variations)
		cert2, err := handler.GetCertificate(clientHello("API.EXAMPLE.COM.", podIP+":54321"))
		if err != nil {
			t.Fatalf("second GetCertificate failed: %v", err)
		}

		if cert1 != cert2 {
			t.Error("expected cert1 and cert2 to be the exact same cached certificate pointer")
		}
	})

	t.Run("bound on certificates for names outside the policy holds", func(t *testing.T) {
		// Host that only has an HTTP rule, no HTTPS rule
		_, err := handler.GetCertificate(clientHello("cleartext.example.com", podIP+":12345"))
		if err == nil {
			t.Error("expected error for cleartext-only host on TLS handshake, got nil")
		}

		// Arbitrary host not in policy
		_, err = handler.GetCertificate(clientHello("unmatched.example.com", podIP+":12345"))
		if err == nil {
			t.Error("expected error for unmatched host, got nil")
		}

		// Another arbitrary foreign host
		_, err = handler.GetCertificate(clientHello("evil.attacker.com", podIP+":12345"))
		if err == nil {
			t.Error("expected error for attacker host, got nil")
		}
	})

	t.Run("nil signer returns error", func(t *testing.T) {
		noSignerHandler := NewEgressHandler(pm, store, nil, nil)
		_, err := noSignerHandler.GetCertificate(clientHello("api.example.com", podIP+":12345"))
		if err == nil {
			t.Fatal("expected error when signer is nil, got nil")
		}
	})
}

func TestEgressHandler_TLSHandshakeEndToEnd(t *testing.T) {
	caCertPath, caKeyPath := createTestCA(t)
	signer, err := proxy.NewCertSigner(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("failed to create CertSigner: %v", err)
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("failed to read ca.crt: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	pm, store := newTestEnv(t)

	// In this test, client dials the TLS server from 127.0.0.1.
	// Bind 127.0.0.1 as the pod IP so caller resolution succeeds.
	podIP := "127.0.0.1"
	podUID := "pod-local-tls"

	pm.AddOrUpdatePod(&PodInfo{
		UID:       podUID,
		Namespace: "test",
		Name:      "test-sandbox",
		IPs:       []string{podIP},
	})

	_, err = store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Https: &portalsv1.HttpsRule{
						Hostnames: []string{"allowed.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{443},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	handler := NewEgressHandler(pm, store, nil, signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	tlsListener := tls.NewListener(listener, &tls.Config{
		GetCertificate: handler.GetCertificate,
	})
	defer tlsListener.Close()

	go func() {
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	t.Run("allowed host completes TLS handshake and verifies against CA", func(t *testing.T) {
		conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
			RootCAs:    caPool,
			ServerName: "allowed.example.com",
		})
		if err != nil {
			t.Fatalf("TLS handshake failed: %v", err)
		}
		defer conn.Close()

		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			t.Fatal("expected peer certificates")
		}
		if state.PeerCertificates[0].Subject.CommonName != "allowed.example.com" {
			t.Errorf("expected CommonName allowed.example.com, got %q", state.PeerCertificates[0].Subject.CommonName)
		}
	})

	t.Run("disallowed host handshake fails", func(t *testing.T) {
		conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
			RootCAs:    caPool,
			ServerName: "disallowed.example.com",
		})
		if err == nil {
			conn.Close()
			t.Fatal("expected TLS handshake to fail for disallowed host, but it succeeded")
		}
	})
}

func TestEgressHandler_MatchHost(t *testing.T) {
	pm, store := newTestEnv(t)

	podAIP := "10.244.1.10"
	podAUID := "pod-a"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       podAUID,
		Namespace: "default",
		Name:      "pod-a",
		IPs:       []string{podAIP},
	})

	_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podAUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"http-exact.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{8080},
						},
					},
				},
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"*.http-wild.example.com"},
						Ports: &portalsv1.Ports{
							All: &portalsv1.AllPorts{},
						},
					},
				},
				{
					Https: &portalsv1.HttpsRule{
						Hostnames: []string{"https-exact.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{443},
						},
					},
				},
				{
					Https: &portalsv1.HttpsRule{
						Hostnames: []string{"*.https-wild.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{8443},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind pod A failed: %v", err)
	}

	podBIP := "10.244.1.20"
	podBUID := "pod-b"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       podBUID,
		Namespace: "default",
		Name:      "pod-b",
		IPs:       []string{podBIP},
	})

	_, err = store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podBUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"pod-b-only.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{80},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind pod B failed: %v", err)
	}

	podCIP := "10.244.1.30"
	podCUID := "pod-c"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       podCUID,
		Namespace: "default",
		Name:      "pod-c",
		IPs:       []string{podCIP},
	})

	handler := NewEgressHandler(pm, store, nil, nil)

	addrA := &net.UDPAddr{IP: net.ParseIP(podAIP), Port: 12345}
	addrB := &net.UDPAddr{IP: net.ParseIP(podBIP), Port: 23456}
	addrC := &net.UDPAddr{IP: net.ParseIP(podCIP), Port: 34567}
	addrUnknown := &net.UDPAddr{IP: net.ParseIP("10.244.1.99"), Port: 45678}

	tests := []struct {
		name     string
		addr     net.Addr
		host     string
		expected bool
	}{
		// Pod A queries
		{"pod A http exact", addrA, "http-exact.example.com", true},
		{"pod A http exact with dot", addrA, "http-exact.example.com.", true},
		{"pod A http exact uppercase", addrA, "HTTP-EXACT.EXAMPLE.COM", true},
		{"pod A http exact with port", addrA, "http-exact.example.com:8080", true},
		{"pod A http wildcard", addrA, "foo.http-wild.example.com", true},
		{"pod A https exact", addrA, "https-exact.example.com", true},
		{"pod A https exact with port", addrA, "https-exact.example.com:443", true},
		{"pod A https wildcard", addrA, "bar.https-wild.example.com", true},
		{"pod A outside policy", addrA, "outside.example.com", false},
		{"pod A pod B rule not matched", addrA, "pod-b-only.example.com", false},

		// Pod B queries (isolation)
		{"pod B pod B rule matched", addrB, "pod-b-only.example.com", true},
		{"pod B pod A http exact not matched", addrB, "http-exact.example.com", false},
		{"pod B pod A http wildcard not matched", addrB, "foo.http-wild.example.com", false},
		{"pod B pod A https exact not matched", addrB, "https-exact.example.com", false},
		{"pod B pod A https wildcard not matched", addrB, "bar.https-wild.example.com", false},

		// Unbound pod C
		{"unbound pod gets nothing", addrC, "http-exact.example.com", false},
		{"unbound pod gets nothing for pod B rule", addrC, "pod-b-only.example.com", false},

		// Unknown source address
		{"unknown caller gets nothing", addrUnknown, "http-exact.example.com", false},

		// Nil client address
		{"nil client address gets nothing", nil, "http-exact.example.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := handler.MatchHost(tc.host, tc.addr)
			if got != tc.expected {
				t.Errorf("MatchHost(%q, %v) = %v; expected %v", tc.host, tc.addr, got, tc.expected)
			}
		})
	}
}

func TestEgressHandler_ShouldDrop(t *testing.T) {
	pm, store := newTestEnv(t)

	boundIP := "10.244.1.10"
	boundUID := "pod-bound"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       boundUID,
		Namespace: "default",
		Name:      "pod-bound",
		IPs:       []string{boundIP},
	})
	_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: boundUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"example.com"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	unboundIP := "10.244.1.20"
	unboundUID := "pod-unbound"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       unboundUID,
		Namespace: "default",
		Name:      "pod-unbound",
		IPs:       []string{unboundIP},
	})

	handler := NewEgressHandler(pm, store, nil, nil)

	addrBound := &net.UDPAddr{IP: net.ParseIP(boundIP), Port: 12345}
	addrUnbound := &net.UDPAddr{IP: net.ParseIP(unboundIP), Port: 23456}
	addrUnknown := &net.UDPAddr{IP: net.ParseIP("10.244.1.99"), Port: 34567}

	tests := []struct {
		name     string
		addr     net.Addr
		host     string
		expected bool
	}{
		{"unbound pod is dropped", addrUnbound, "example.com", true},
		{"unbound pod any host is dropped", addrUnbound, "any.other.host", true},
		{"bound pod is not dropped", addrBound, "example.com", false},
		{"bound pod unlisted host is not dropped (handled by MatchHost)", addrBound, "other.com", false},
		{"unknown caller is dropped", addrUnknown, "example.com", true},
		{"nil client address is dropped", nil, "example.com", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := handler.ShouldDrop(tc.host, tc.addr)
			if got != tc.expected {
				t.Errorf("ShouldDrop(%q, %v) = %v; expected %v", tc.host, tc.addr, got, tc.expected)
			}
		})
	}
}

func sendDNSQueryFromPacketConn(t *testing.T, conn net.PacketConn, serverAddr, qname string, qtype dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	serverUDP, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("failed to resolve server UDP addr %s: %v", serverAddr, err)
	}

	req := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               4321,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(qname),
				Type:  qtype,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	packed, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack query: %v", err)
	}
	if _, err := conn.WriteTo(packed, serverUDP); err != nil {
		t.Fatalf("failed to send query: %v", err)
	}

	buf := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("failed to read DNS response: %v", err)
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}
	return resp
}

func sendDNSQueryFromPacketConnExpectTimeout(t *testing.T, conn net.PacketConn, serverAddr, qname string, qtype dnsmessage.Type, timeout time.Duration) {
	t.Helper()
	serverUDP, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("failed to resolve server UDP addr %s: %v", serverAddr, err)
	}

	req := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               4321,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(qname),
				Type:  qtype,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	packed, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack query: %v", err)
	}
	if _, err := conn.WriteTo(packed, serverUDP); err != nil {
		t.Fatalf("failed to send query: %v", err)
	}

	buf := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}
	n, _, err := conn.ReadFrom(buf)
	if err == nil {
		t.Fatalf("expected query to be dropped (timeout), but got response (%d bytes)", n)
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

func TestEgressHandler_DNSServer_BoundedAnswers(t *testing.T) {
	pm, store := newTestEnv(t)

	podAIP := "127.0.0.10"
	podAUID := "pod-dns-a"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       podAUID,
		Namespace: "default",
		Name:      "pod-dns-a",
		IPs:       []string{podAIP},
	})

	_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podAUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"http-exact.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{80},
						},
					},
				},
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"*.http-wild.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{8080},
						},
					},
				},
				{
					Https: &portalsv1.HttpsRule{
						Hostnames: []string{"https-exact.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{443},
						},
					},
				},
				{
					Https: &portalsv1.HttpsRule{
						Hostnames: []string{"*.https-wild.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{8443},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind pod A failed: %v", err)
	}

	podBIP := "127.0.0.20"
	podBUID := "pod-dns-b"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       podBUID,
		Namespace: "default",
		Name:      "pod-dns-b",
		IPs:       []string{podBIP},
	})

	_, err = store.Bind(t.Context(), &portalsv1.PodPolicy{
		PodUid: podBUID,
		Policy: &portalsv1.EgressPolicy{
			Rules: []*portalsv1.EgressRule{
				{
					Http: &portalsv1.HttpRule{
						Hostnames: []string{"pod-b-only.example.com"},
						Ports: &portalsv1.Ports{
							Numbers: []int32{80},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Bind pod B failed: %v", err)
	}

	podCIP := "127.0.0.30"
	podCUID := "pod-dns-c"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       podCUID,
		Namespace: "default",
		Name:      "pod-dns-c",
		IPs:       []string{podCIP},
	})

	handler := NewEgressHandler(pm, store, nil, nil)

	proxyIPv4 := net.ParseIP("127.0.0.2")
	proxyIPv6 := net.ParseIP("::1")
	srv, err := dns.NewServer(dns.Config{
		BindAddr:      "127.0.0.1:0",
		ProxyIPv4:     proxyIPv4,
		ProxyIPv6:     proxyIPv6,
		Matcher:       handler,
		DropEvaluator: handler,
		DefaultAction: "Deny",
	})
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start DNS server: %v", err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()

	dnsAddr := srv.UDPAddr().String()

	connA, err := net.ListenPacket("udp", net.JoinHostPort(podAIP, "0"))
	if err != nil {
		t.Fatalf("failed to listen UDP for pod A (%s): %v", podAIP, err)
	}
	defer connA.Close()

	connB, err := net.ListenPacket("udp", net.JoinHostPort(podBIP, "0"))
	if err != nil {
		t.Fatalf("failed to listen UDP for pod B (%s): %v", podBIP, err)
	}
	defer connB.Close()

	connC, err := net.ListenPacket("udp", net.JoinHostPort(podCIP, "0"))
	if err != nil {
		t.Fatalf("failed to listen UDP for pod C (%s): %v", podCIP, err)
	}
	defer connC.Close()

	unknownIP := "127.0.0.40"
	connUnknown, err := net.ListenPacket("udp", net.JoinHostPort(unknownIP, "0"))
	if err != nil {
		t.Fatalf("failed to listen UDP for unknown caller (%s): %v", unknownIP, err)
	}
	defer connUnknown.Close()

	expectedA := [4]byte{127, 0, 0, 2}
	expectedAAAA := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	assertAnswerA := func(t *testing.T, resp dnsmessage.Message) {
		t.Helper()
		if resp.RCode != dnsmessage.RCodeSuccess {
			t.Fatalf("expected RCodeSuccess, got %v", resp.RCode)
		}
		if len(resp.Answers) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
		}
		aRecord, ok := resp.Answers[0].Body.(*dnsmessage.AResource)
		if !ok {
			t.Fatalf("expected *dnsmessage.AResource, got %T", resp.Answers[0].Body)
		}
		if aRecord.A != expectedA {
			t.Errorf("expected IP %v, got %v", expectedA, aRecord.A)
		}
	}

	assertAnswerAAAA := func(t *testing.T, resp dnsmessage.Message) {
		t.Helper()
		if resp.RCode != dnsmessage.RCodeSuccess {
			t.Fatalf("expected RCodeSuccess, got %v", resp.RCode)
		}
		if len(resp.Answers) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
		}
		aaaaRecord, ok := resp.Answers[0].Body.(*dnsmessage.AAAAResource)
		if !ok {
			t.Fatalf("expected *dnsmessage.AAAAResource, got %T", resp.Answers[0].Body)
		}
		if aaaaRecord.AAAA != expectedAAAA {
			t.Errorf("expected IPv6 %v, got %v", expectedAAAA, aaaaRecord.AAAA)
		}
	}

	assertNXDOMAIN := func(t *testing.T, resp dnsmessage.Message) {
		t.Helper()
		if resp.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("expected NXDOMAIN (RCodeNameError), got %v", resp.RCode)
		}
		if len(resp.Answers) != 0 {
			t.Fatalf("expected 0 answers on NXDOMAIN, got %d", len(resp.Answers))
		}
	}

	// 1. Pod A queries: exact http rule answered with proxy address
	t.Run("pod A http exact A", func(t *testing.T) {
		resp := sendDNSQueryFromPacketConn(t, connA, dnsAddr, "http-exact.example.com.", dnsmessage.TypeA)
		assertAnswerA(t, resp)
	})
	t.Run("pod A http exact AAAA", func(t *testing.T) {
		resp := sendDNSQueryFromPacketConn(t, connA, dnsAddr, "http-exact.example.com.", dnsmessage.TypeAAAA)
		assertAnswerAAAA(t, resp)
	})

	// 2. Pod A queries: wildcard http rule answered with proxy address
	t.Run("pod A http wildcard", func(t *testing.T) {
		resp := sendDNSQueryFromPacketConn(t, connA, dnsAddr, "sub.http-wild.example.com.", dnsmessage.TypeA)
		assertAnswerA(t, resp)
	})

	// 3. Pod A queries: exact https rule answered with proxy address
	t.Run("pod A https exact", func(t *testing.T) {
		resp := sendDNSQueryFromPacketConn(t, connA, dnsAddr, "https-exact.example.com.", dnsmessage.TypeA)
		assertAnswerA(t, resp)
	})

	// 4. Pod A queries: wildcard https rule answered with proxy address
	t.Run("pod A https wildcard", func(t *testing.T) {
		resp := sendDNSQueryFromPacketConn(t, connA, dnsAddr, "sub.https-wild.example.com.", dnsmessage.TypeA)
		assertAnswerA(t, resp)
	})

	// 5. Pod A queries: name outside its policy gets NXDOMAIN
	t.Run("pod A unlisted host gets NXDOMAIN", func(t *testing.T) {
		resp := sendDNSQueryFromPacketConn(t, connA, dnsAddr, "outside.example.com.", dnsmessage.TypeA)
		assertNXDOMAIN(t, resp)
	})

	// 6. Pod A queries: name in pod B's policy gets NXDOMAIN
	t.Run("pod A cannot resolve pod B host", func(t *testing.T) {
		resp := sendDNSQueryFromPacketConn(t, connA, dnsAddr, "pod-b-only.example.com.", dnsmessage.TypeA)
		assertNXDOMAIN(t, resp)
	})

	// 7. Pod B queries: pod A's host gets NXDOMAIN (isolation)
	t.Run("pod B cannot resolve pod A host", func(t *testing.T) {
		resp := sendDNSQueryFromPacketConn(t, connB, dnsAddr, "http-exact.example.com.", dnsmessage.TypeA)
		assertNXDOMAIN(t, resp)
	})

	// 8. Pod B queries: own host answered with proxy address
	t.Run("pod B resolves own host", func(t *testing.T) {
		resp := sendDNSQueryFromPacketConn(t, connB, dnsAddr, "pod-b-only.example.com.", dnsmessage.TypeA)
		assertAnswerA(t, resp)
	})

	// 9. Unbound pod C queries: gets no answer (dropped)
	t.Run("unbound pod gets no answer then succeeds after bind", func(t *testing.T) {
		sendDNSQueryFromPacketConnExpectTimeout(t, connC, dnsAddr, "http-exact.example.com.", dnsmessage.TypeA, 100*time.Millisecond)

		// Once policy is bound, retry succeeds
		_, err := store.Bind(t.Context(), &portalsv1.PodPolicy{
			PodUid: podCUID,
			Policy: &portalsv1.EgressPolicy{
				Rules: []*portalsv1.EgressRule{
					{
						Http: &portalsv1.HttpRule{
							Hostnames: []string{"http-exact.example.com"},
							Ports:     &portalsv1.Ports{Numbers: []int32{80}},
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("Bind failed for pod C: %v", err)
		}

		resp := sendDNSQueryFromPacketConn(t, connC, dnsAddr, "http-exact.example.com.", dnsmessage.TypeA)
		assertAnswerA(t, resp)
	})

	// 10. Unknown source address: query is dropped (UDP times out without response)
	t.Run("unknown caller is dropped on UDP", func(t *testing.T) {
		sendDNSQueryFromPacketConnExpectTimeout(t, connUnknown, dnsAddr, "http-exact.example.com.", dnsmessage.TypeA, 100*time.Millisecond)
	})
}

func TestEgressHandler_ShortNameResolution_PodNamespaceIsolation(t *testing.T) {
	var nsACalls atomic.Int32
	var nsBCalls atomic.Int32
	var agentNSCalls atomic.Int32

	upstreamNSA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nsACalls.Add(1)
		if r.Host != "backend" {
			t.Errorf("upstreamNSA expected Host 'backend', got %q", r.Host)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response from ns-a"))
	}))
	defer upstreamNSA.Close()

	upstreamNSB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nsBCalls.Add(1)
		if r.Host != "backend" {
			t.Errorf("upstreamNSB expected Host 'backend', got %q", r.Host)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response from ns-b"))
	}))
	defer upstreamNSB.Close()

	upstreamAgentNS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentNSCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response from service-portal-system"))
	}))
	defer upstreamAgentNS.Close()

	// Transport routes based on dialed req.URL.Host to simulate cluster DNS resolution
	routingTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			switch addr {
			case "backend.ns-a.svc.cluster.local:80":
				return (&net.Dialer{}).DialContext(ctx, network, upstreamNSA.Listener.Addr().String())
			case "backend.ns-b.svc.cluster.local:80":
				return (&net.Dialer{}).DialContext(ctx, network, upstreamNSB.Listener.Addr().String())
			case "backend.service-portal-system.svc.cluster.local:80":
				return (&net.Dialer{}).DialContext(ctx, network, upstreamAgentNS.Listener.Addr().String())
			default:
				return nil, fmt.Errorf("unexpected dial destination %s", addr)
			}
		},
	}

	pm, store := newTestEnv(t)

	podAIP := "10.244.1.10"
	podAUID := "pod-caller-a"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       podAUID,
		Namespace: "ns-a",
		Name:      "client-a",
		IPs:       []string{podAIP},
	})

	podBIP := "10.244.1.20"
	podBUID := "pod-caller-b"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       podBUID,
		Namespace: "ns-b",
		Name:      "client-b",
		IPs:       []string{podBIP},
	})

	// Both pods have a policy allowing short name "backend"
	policy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Http: &portalsv1.HttpRule{
					Hostnames: []string{"backend"},
					Ports:     &portalsv1.Ports{Numbers: []int32{80}},
				},
			},
		},
	}

	if _, err := store.Bind(t.Context(), &portalsv1.PodPolicy{PodUid: podAUID, Policy: policy}); err != nil {
		t.Fatalf("bind pod A failed: %v", err)
	}
	if _, err := store.Bind(t.Context(), &portalsv1.PodPolicy{PodUid: podBUID, Policy: policy}); err != nil {
		t.Fatalf("bind pod B failed: %v", err)
	}

	handler := NewEgressHandler(pm, store, routingTransport, nil)
	handler.clusterDomain = "cluster.local"
	handler.podSearchRest = "svc.cluster.local"

	// 1. Pod A in ns-a requests http://backend/
	reqA := httptest.NewRequest("GET", "http://backend/data", nil)
	reqA.RemoteAddr = podAIP + ":12345"
	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, reqA)

	respA := recA.Result()
	defer respA.Body.Close()
	bodyA, _ := io.ReadAll(respA.Body)

	if respA.StatusCode != http.StatusOK {
		t.Fatalf("Pod A request failed with status %d: %s", respA.StatusCode, string(bodyA))
	}
	if string(bodyA) != "response from ns-a" {
		t.Errorf("Pod A expected response from ns-a, got %q", string(bodyA))
	}
	if nsACalls.Load() != 1 {
		t.Errorf("expected 1 call to ns-a upstream, got %d", nsACalls.Load())
	}

	// 2. Pod B in ns-b requests http://backend/
	reqB := httptest.NewRequest("GET", "http://backend/data", nil)
	reqB.RemoteAddr = podBIP + ":23456"
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, reqB)

	respB := recB.Result()
	defer respB.Body.Close()
	bodyB, _ := io.ReadAll(respB.Body)

	if respB.StatusCode != http.StatusOK {
		t.Fatalf("Pod B request failed with status %d: %s", respB.StatusCode, string(bodyB))
	}
	if string(bodyB) != "response from ns-b" {
		t.Errorf("Pod B expected response from ns-b, got %q", string(bodyB))
	}
	if nsBCalls.Load() != 1 {
		t.Errorf("expected 1 call to ns-b upstream, got %d", nsBCalls.Load())
	}

	// 3. Crucial assertion: Upstream in agent's namespace (service-portal-system) must NEVER be dialed
	if agentNSCalls.Load() != 0 {
		t.Errorf("expected 0 calls to node agent namespace upstream, got %d", agentNSCalls.Load())
	}
}

func TestEgressHandler_ShortNameResolution_FailClosed(t *testing.T) {
	pm, store := newTestEnv(t)

	policy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Http: &portalsv1.HttpRule{
					Hostnames: []string{"backend"},
					Ports:     &portalsv1.Ports{Numbers: []int32{80}},
				},
			},
		},
	}

	// Pod without namespace metadata cannot have short in-cluster name resolved
	t.Run("missing namespace fails closed", func(t *testing.T) {
		podNoNSIP := "10.244.1.30"
		podNoNSUID := "pod-no-ns"
		pm.AddOrUpdatePod(&PodInfo{
			UID:       podNoNSUID,
			Namespace: "", // missing namespace
			Name:      "pod-missing-ns",
			IPs:       []string{podNoNSIP},
		})

		if _, err := store.Bind(t.Context(), &portalsv1.PodPolicy{PodUid: podNoNSUID, Policy: policy}); err != nil {
			t.Fatalf("bind failed: %v", err)
		}

		handler := NewEgressHandler(pm, store, nil, nil)
		handler.clusterDomain = "cluster.local"
		handler.podSearchRest = "svc.cluster.local"

		req := httptest.NewRequest("GET", "http://backend/test", nil)
		req.RemoteAddr = podNoNSIP + ":34567"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		resp := rec.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for pod with missing namespace, got %d", resp.StatusCode)
		}
	})

	// Pod with valid namespace but handler missing resolv.conf cluster search domain fails closed
	t.Run("missing cluster search domain fails closed", func(t *testing.T) {
		podValidIP := "10.244.1.31"
		podValidUID := "pod-valid-ns"
		pm.AddOrUpdatePod(&PodInfo{
			UID:       podValidUID,
			Namespace: "ns-a",
			Name:      "pod-valid-ns",
			IPs:       []string{podValidIP},
		})
		if _, err := store.Bind(t.Context(), &portalsv1.PodPolicy{PodUid: podValidUID, Policy: policy}); err != nil {
			t.Fatalf("bind failed: %v", err)
		}

		hNoCluster := NewEgressHandler(pm, store, nil, nil)
		hNoCluster.clusterDomain = ""
		hNoCluster.podSearchRest = "" // no cluster search domain in resolv.conf

		req := httptest.NewRequest("GET", "http://backend/test", nil)
		req.RemoteAddr = podValidIP + ":34568"
		rec := httptest.NewRecorder()
		hNoCluster.ServeHTTP(rec, req)

		resp := rec.Result()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for missing cluster search domain, got %d", resp.StatusCode)
		}
	})
}

func TestEgressHandler_ShortNameResolution_TLSUpstreamVerification(t *testing.T) {
	// Generate a test CA
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating CA key: %v", err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Upstream CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed creating CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed parsing CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Server cert is issued strictly for "backend.ns-a.svc.cluster.local", NOT for bare "backend".
	serverPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating server key: %v", err)
	}
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "backend.ns-a.svc.cluster.local"},
		DNSNames:     []string{"backend.ns-a.svc.cluster.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed creating server cert: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Assert that the upstream sees the original Host header as sent by the pod
		if r.Host != "backend" {
			t.Errorf("upstream expected Host 'backend', got %q", r.Host)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("tls response from ns-a"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverDER},
				PrivateKey:  serverPriv,
			},
		},
	}
	server.StartTLS()
	defer server.Close()

	// Transport verifies TLS against the completed URL host using the CA pool
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
		TLSClientConfig: &tls.Config{
			RootCAs: caPool,
		},
	}

	pm, store := newTestEnv(t)

	podAIP := "10.244.1.10"
	podAUID := "pod-tls-a"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       podAUID,
		Namespace: "ns-a",
		Name:      "client-a",
		IPs:       []string{podAIP},
	})

	podBIP := "10.244.1.20"
	podBUID := "pod-tls-b"
	pm.AddOrUpdatePod(&PodInfo{
		UID:       podBUID,
		Namespace: "ns-b",
		Name:      "client-b",
		IPs:       []string{podBIP},
	})

	policy := &portalsv1.EgressPolicy{
		Rules: []*portalsv1.EgressRule{
			{
				Https: &portalsv1.HttpsRule{
					Hostnames: []string{"backend"},
					Ports:     &portalsv1.Ports{Numbers: []int32{443}},
				},
			},
		},
	}

	if _, err := store.Bind(t.Context(), &portalsv1.PodPolicy{PodUid: podAUID, Policy: policy}); err != nil {
		t.Fatalf("bind pod A failed: %v", err)
	}
	if _, err := store.Bind(t.Context(), &portalsv1.PodPolicy{PodUid: podBUID, Policy: policy}); err != nil {
		t.Fatalf("bind pod B failed: %v", err)
	}

	handler := NewEgressHandler(pm, store, transport, nil)
	handler.clusterDomain = "cluster.local"
	handler.podSearchRest = "svc.cluster.local"

	// 1. Pod A (in ns-a) requests https://backend/
	// Upstream TLS cert verification validates against backend.ns-a.svc.cluster.local (succeeds)
	reqA := httptest.NewRequest("GET", "https://backend/path", nil)
	reqA.RemoteAddr = podAIP + ":12345"
	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, reqA)

	respA := recA.Result()
	defer respA.Body.Close()
	bodyA, _ := io.ReadAll(respA.Body)

	if respA.StatusCode != http.StatusOK {
		t.Fatalf("Pod A request failed with status %d: %s", respA.StatusCode, string(bodyA))
	}
	if string(bodyA) != "tls response from ns-a" {
		t.Errorf("expected 'tls response from ns-a', got %q", string(bodyA))
	}

	// 2. Pod B (in ns-b) requests https://backend/
	// Upstream TLS cert verification validates against backend.ns-b.svc.cluster.local.
	// Since server cert is only valid for backend.ns-a.svc.cluster.local, verification fails.
	reqB := httptest.NewRequest("GET", "https://backend/path", nil)
	reqB.RemoteAddr = podBIP + ":23456"
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, reqB)

	respB := recB.Result()
	defer respB.Body.Close()

	if respB.StatusCode != http.StatusBadGateway {
		t.Fatalf("Pod B request expected 502 Bad Gateway due to TLS SAN mismatch, got %d", respB.StatusCode)
	}
}

func TestParseResolvConf(t *testing.T) {
	tmp, err := os.CreateTemp("", "resolv-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	content := `nameserver 10.96.0.10
search service-portal-system.svc.custom.internal svc.custom.internal custom.internal extra.search.domain
options ndots:5
`
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmp.Close()

	searches, domain, podRest := parseResolvConf(tmp.Name())
	if len(searches) != 4 {
		t.Errorf("expected 4 search domains, got %d (%v)", len(searches), searches)
	}
	if domain != "custom.internal" {
		t.Errorf("expected cluster domain 'custom.internal', got %q", domain)
	}
	if podRest != "svc.custom.internal" {
		t.Errorf("expected pod search rest 'svc.custom.internal', got %q", podRest)
	}

	// File with search line but no cluster domain entry (no <namespace>.svc.<domain>)
	tmpNoCluster, err := os.CreateTemp("", "resolv-test-nocluster-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpNoCluster.Name())
	if _, err := tmpNoCluster.WriteString("search mycorp.local external.domain\n"); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpNoCluster.Close()

	searchesNoCluster, domainNoCluster, podRestNoCluster := parseResolvConf(tmpNoCluster.Name())
	if len(searchesNoCluster) != 2 {
		t.Errorf("expected 2 search domains, got %d", len(searchesNoCluster))
	}
	if domainNoCluster != "" {
		t.Errorf("expected empty cluster domain, got %q", domainNoCluster)
	}
	if podRestNoCluster != "" {
		t.Errorf("expected empty pod search rest, got %q", podRestNoCluster)
	}

	// Nonexistent file returns empty values with no fallback
	searchesNone, domainNone, podRestNone := parseResolvConf("/nonexistent/file/path")
	if searchesNone != nil || domainNone != "" || podRestNone != "" {
		t.Errorf("expected nil/empty for nonexistent file, got %v, %q, %q", searchesNone, domainNone, podRestNone)
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want string
	}{
		{
			name: "IPv4",
			addr: &net.TCPAddr{IP: net.ParseIP("10.244.1.5"), Port: 12345},
			want: "10.244.1.5",
		},
		{
			name: "IPv6",
			addr: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 12345},
			want: "2001:db8::1",
		},
		{
			name: "IPv4-mapped",
			addr: &net.TCPAddr{IP: net.ParseIP("::ffff:10.244.1.5"), Port: 12345},
			want: "10.244.1.5",
		},
		{
			name: "nil",
			addr: nil,
			want: "",
		},
		{
			name: "unparseable RemoteAddr",
			addr: parseRemoteAddr("invalid:remote:addr"),
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientIP(tc.addr); got != tc.want {
				t.Errorf("clientIP(%v) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}
