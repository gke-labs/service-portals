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

package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRejectConnect(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "test-backend")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend ok"))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("Failed to parse backend URL: %v", err)
	}

	p, err := NewHTTPProxy(backendURL, "test-token", "Authorization", "", "")
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	t.Run("CONNECT returns 405", func(t *testing.T) {
		conn, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
		if err != nil {
			t.Fatalf("Failed to dial proxy: %v", err)
		}
		defer conn.Close()

		req := "CONNECT backend:443 HTTP/1.1\r\nHost: backend:443\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("Failed to write CONNECT: %v", err)
		}

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, resp.StatusCode)
		}
	})

	t.Run("Ordinary request on same proxy succeeds", func(t *testing.T) {
		client := proxyServer.Client()
		resp, err := client.Get(proxyServer.URL + "/ordinary")
		if err != nil {
			t.Fatalf("Failed to make GET request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Backend") != "test-backend" {
			t.Errorf("Expected X-Backend header 'test-backend', got %q", resp.Header.Get("X-Backend"))
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read body: %v", err)
		}
		if string(body) != "backend ok" {
			t.Errorf("Expected body 'backend ok', got %q", string(body))
		}
	})
}

func TestAbsoluteFormRequestRewrittenToTarget(t *testing.T) {
	var receivedHost string
	var receivedAuth string
	var receivedPath string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		receivedAuth = r.Header.Get("Authorization")
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("Failed to parse backend URL: %v", err)
	}

	p, err := NewHTTPProxy(backendURL, "test-secret-token", "Authorization", "", "")
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Send an absolute-form HTTP request for a foreign host (as sent by explicit proxy clients):
	// GET http://evil.example/foreign-path HTTP/1.1
	// Host: evil.example
	conn, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial proxy: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	req := "GET http://evil.example/foreign-path HTTP/1.1\r\nHost: evil.example\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	if string(body) != "backend response" {
		t.Errorf("Expected body 'backend response', got %q", string(body))
	}

	if receivedHost != backendURL.Host {
		t.Errorf("Backend expected Host %q, got %q", backendURL.Host, receivedHost)
	}
	if receivedAuth != "Bearer test-secret-token" {
		t.Errorf("Backend expected Authorization 'Bearer test-secret-token', got %q", receivedAuth)
	}
	if receivedPath != "/foreign-path" {
		t.Errorf("Backend expected Path '/foreign-path', got %q", receivedPath)
	}
}

func TestHostWithoutPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "host with port",
			host: "example.com:8080",
			want: "example.com",
		},
		{
			name: "host without port",
			host: "example.com",
			want: "example.com",
		},
		{
			name: "ipv4 with port",
			host: "127.0.0.1:443",
			want: "127.0.0.1",
		},
		{
			name: "ipv4 without port",
			host: "127.0.0.1",
			want: "127.0.0.1",
		},
		{
			name: "ipv6 with port",
			host: "[::1]:8443",
			want: "::1",
		},
		{
			name: "ipv6 without port",
			host: "::1",
			want: "::1",
		},
		{
			name: "empty string",
			host: "",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := HostWithoutPort(tc.host)
			if got != tc.want {
				t.Errorf("HostWithoutPort(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}
