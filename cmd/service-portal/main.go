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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	target := os.Getenv("TARGET_URL")
	if target == "" {
		target = "https://generativelanguage.googleapis.com"
	}

	upstreamAuthToken := os.Getenv("UPSTREAM_AUTH_TOKEN")
	if upstreamAuthToken == "" {
		log.Println("Warning: UPSTREAM_AUTH_TOKEN is not set. No Authorization header will be injected.")
	}

	upstreamAuthHeader := os.Getenv("UPSTREAM_AUTH_HEADER")
	if upstreamAuthHeader == "" {
		upstreamAuthHeader = "Authorization"
	}
	upstreamAuthHeader = http.CanonicalHeaderKey(upstreamAuthHeader)

	targetURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid TARGET_URL: %w", err)
	}

	proxy := newProxy(targetURL, upstreamAuthToken, upstreamAuthHeader)

	caCertPath := os.Getenv("CA_CERT_PATH")
	caKeyPath := os.Getenv("CA_KEY_PATH")

	var handler http.Handler = proxy
	if caCertPath != "" && caKeyPath != "" {
		log.Printf("Loading CA from %s and %s", caCertPath, caKeyPath)
		mitm, err := newMITMHandler(proxy, caCertPath, caKeyPath)
		if err != nil {
			return fmt.Errorf("failed to create MITM handler: %w", err)
		}
		handler = mitm
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: handler,
	}

	errChan := make(chan error, 1)
	go func() {
		log.Printf("Starting proxy on :%s forwarding to %s", port, target)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("server failed: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Println("Shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown failed: %w", err)
		}
	}

	return nil
}

type mitmContextKey struct{}

func newProxy(targetURL *url.URL, upstreamAuthToken string, upstreamAuthHeader string) *httputil.ReverseProxy {
	targetProxy := httputil.NewSingleHostReverseProxy(targetURL)
	targetDirector := targetProxy.Director

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			host := req.Host
			if host == "" {
				host = req.URL.Host
			}

			isMITM, _ := req.Context().Value(mitmContextKey{}).(bool)

			// We force the target host if:
			// 1. The requested host matches the target host
			// 2. This is a direct request to the proxy (not MITM and not an absolute URL)
			forceTarget := false
			if host == targetURL.Host {
				forceTarget = true
			} else if !isMITM && req.URL.Host == "" {
				forceTarget = true
			}

			if forceTarget {
				targetDirector(req)
				req.Host = targetURL.Host
				if upstreamAuthToken != "" {
					if upstreamAuthHeader == "Authorization" {
						req.Header.Set(upstreamAuthHeader, "Bearer "+upstreamAuthToken)
					} else {
						req.Header.Set(upstreamAuthHeader, upstreamAuthToken)
					}
				}
			} else {
				if req.URL.Scheme == "" {
					req.URL.Scheme = "https"
				}
				if req.URL.Host == "" {
					req.URL.Host = req.Host
				}
			}
			// Remove headers that might interfere or reveal the proxy's identity if desired
			req.Header.Del("X-Forwarded-For")
		},
	}

	// Simple logging
	proxy.ModifyResponse = func(resp *http.Response) error {
		log.Printf("Proxied %s %s -> %s", resp.Request.Method, resp.Request.URL, resp.Status)
		return nil
	}

	return proxy
}

type mitmHandler struct {
	proxy  *httputil.ReverseProxy
	caCert *x509.Certificate
	caKey  crypto.PrivateKey
	certs  map[string]*tls.Certificate
	mu     sync.RWMutex
}

func newMITMHandler(proxy *httputil.ReverseProxy, certPath, keyPath string) (*mitmHandler, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, err
	}

	return &mitmHandler{
		proxy:  proxy,
		caCert: caCert,
		caKey:  tlsCert.PrivateKey,
		certs:  make(map[string]*tls.Certificate),
	}, nil
}

func (h *mitmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	h.proxy.ServeHTTP(w, r)
}

func (h *mitmHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		clientConn.Close()
		return
	}

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	cert, err := h.getCert(host)
	if err != nil {
		log.Printf("Failed to get cert for %s: %v", host, err)
		clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed for %s: %v", host, err)
		tlsConn.Close()
		return
	}

	// Create a simple server to handle the decrypted requests
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), mitmContextKey{}, true)
			h.proxy.ServeHTTP(w, r.WithContext(ctx))
		}),
	}

	// We use a custom listener that just returns our tlsConn once
	l := &oneShotListener{conn: tlsConn}
	if err := server.Serve(l); err != nil && err != http.ErrServerClosed && err != io.EOF {
		log.Printf("Serve failed: %v", err)
	}
}

func (h *mitmHandler) getCert(host string) (*tls.Certificate, error) {
	h.mu.RLock()
	cert, ok := h.certs[host]
	h.mu.RUnlock()
	if ok {
		return cert, nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Double check
	if cert, ok := h.certs[host]; ok {
		return cert, nil
	}

	// Generate new cert
	cert, err := h.signCert(host)
	if err != nil {
		return nil, err
	}
	h.certs[host] = cert
	return cert, nil
}

func (h *mitmHandler) signCert(host string) (*tls.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, h.caCert, &priv.PublicKey, h.caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

type oneShotListener struct {
	conn net.Conn
	once sync.Once
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		c = l.conn
	})
	if c == nil {
		return nil, io.EOF
	}
	return c, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
