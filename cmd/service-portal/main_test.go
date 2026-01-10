package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestProxyInjectsAuthToken(t *testing.T) {
	expectedToken := "secret-token"

	// 1. Start a mock HTTPS backend
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+expectedToken {
			t.Errorf("Expected Authorization header 'Bearer %s', got '%s'", expectedToken, auth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("Failed to parse backend URL: %v", err)
	}

	// 2. Create the proxy
	proxy := newProxy(backendURL, expectedToken)

	// Configure the proxy to trust the test server's certificate
	proxy.Transport = backend.Client().Transport

	// 3. Create a request to the proxy
	req := httptest.NewRequest("GET", "http://localhost:8080/some/path", nil)
	w := httptest.NewRecorder()

	// 4. Serve the request
	proxy.ServeHTTP(w, req)

	// 5. Verify the response
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.Status)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "OK" {
		t.Errorf("Expected body 'OK', got '%s'", string(body))
	}
}
