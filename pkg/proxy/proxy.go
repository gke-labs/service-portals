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
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type HTTPProxy struct {
	TargetURL  *url.URL
	AuthToken  string
	AuthHeader string

	caCert *x509.Certificate
	caKey  crypto.PrivateKey

	certs map[string]*tls.Certificate
	mu    sync.RWMutex

	Transport http.RoundTripper
}

// ParseResolvConf parses nameservers from a resolv.conf format file, excluding loopback addresses.
func ParseResolvConf(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var servers []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			ip := net.ParseIP(fields[1])
			if ip != nil && !ip.IsLoopback() {
				servers = append(servers, fields[1])
			}
		}
	}
	return servers, nil
}

// ResolveUpstreamDNSServers discovers configured upstream DNS servers.
// It checks UPSTREAM_DNS_SERVERS, DNS_SERVER_IPS, /etc/service-portal/upstream-resolv.conf,
// and /etc/resolv.conf, filtering out loopback addresses to prevent proxy routing loops.
func ResolveUpstreamDNSServers() []string {
	if env := os.Getenv("UPSTREAM_DNS_SERVERS"); env != "" {
		return filterLoopbackServers(splitAndTrim(env))
	}
	if env := os.Getenv("DNS_SERVER_IPS"); env != "" {
		return filterLoopbackServers(splitAndTrim(env))
	}
	if servers, err := ParseResolvConf("/etc/service-portal/ca/upstream-resolv.conf"); err == nil && len(servers) > 0 {
		return servers
	}
	if servers, err := ParseResolvConf("/etc/service-portal/upstream-resolv.conf"); err == nil && len(servers) > 0 {
		return servers
	}
	if servers, err := ParseResolvConf("/etc/resolv.conf"); err == nil && len(servers) > 0 {
		return servers
	}
	return nil
}

func filterLoopbackServers(servers []string) []string {
	var filtered []string
	for _, s := range servers {
		host, _, err := net.SplitHostPort(s)
		if err != nil {
			host = s
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.IsLoopback() {
			continue
		}
		filtered = append(filtered, s)
	}
	return filtered
}

// NewUpstreamResolver creates a net.Resolver whose Dial function connects directly
// to the specified upstream DNS server(s).
func NewUpstreamResolver(servers []string) *net.Resolver {
	if len(servers) == 0 {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			var lastErr error
			for _, s := range servers {
				target := s
				if !strings.Contains(target, ":") {
					target = net.JoinHostPort(target, "53")
				}
				conn, err := d.DialContext(ctx, network, target)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

// NewTransport creates an http.Transport configured with the given DNS resolver.
func NewTransport(resolver *net.Resolver) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func NewHTTPProxy(targetURL *url.URL, authToken, authHeader string, caCertPath, caKeyPath string) (*HTTPProxy, error) {
	return NewHTTPProxyWithResolver(targetURL, authToken, authHeader, caCertPath, caKeyPath, nil)
}

func NewHTTPProxyWithResolver(targetURL *url.URL, authToken, authHeader string, caCertPath, caKeyPath string, resolver *net.Resolver) (*HTTPProxy, error) {
	if resolver == nil {
		servers := ResolveUpstreamDNSServers()
		resolver = NewUpstreamResolver(servers)
	}

	var transport http.RoundTripper = NewTransport(resolver)
	if os.Getenv("OTEL_INSTRUMENTATION_ENABLED") == "true" {
		transport = otelhttp.NewTransport(transport)
	}

	p := &HTTPProxy{
		TargetURL:  targetURL,
		AuthToken:  authToken,
		AuthHeader: authHeader,
		certs:      make(map[string]*tls.Certificate),
		Transport:  transport,
	}

	if caCertPath != "" && caKeyPath != "" {
		certPEM, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		keyPEM, err := os.ReadFile(caKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA key: %w", err)
		}

		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA key pair: %w", err)
		}

		p.caCert, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}
		p.caKey = tlsCert.PrivateKey
	}

	return p, nil
}

// HostWithoutPort returns host with any trailing :port stripped.
// If host does not contain a port or cannot be split, host is returned unchanged.
func HostWithoutPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

func (p *HTTPProxy) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := info.ServerName
	if host == "" {
		host = "localhost"
	}
	host = HostWithoutPort(host)
	return p.getCert(host)
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect && p.caCert != nil {
		p.handleConnect(w, r)
		return
	}

	p.proxyRequest(w, r, false)
}

func (p *HTTPProxy) proxyRequest(w http.ResponseWriter, r *http.Request, isMITM bool) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	forceTarget := false
	if host == p.TargetURL.Host {
		forceTarget = true
	} else if !isMITM && r.URL.Host == "" {
		forceTarget = true
	}

	outReq := r.Clone(r.Context())
	if forceTarget {
		outReq.URL.Scheme = p.TargetURL.Scheme
		outReq.URL.Host = p.TargetURL.Host
		outReq.Host = p.TargetURL.Host

		if p.AuthToken != "" {
			if p.AuthHeader == "Authorization" {
				outReq.Header.Set(p.AuthHeader, "Bearer "+p.AuthToken)
			} else {
				outReq.Header.Set(p.AuthHeader, p.AuthToken)
			}
		}
	} else {
		if outReq.URL.Scheme == "" {
			outReq.URL.Scheme = "https"
		}
		if outReq.URL.Host == "" {
			outReq.URL.Host = r.Host
		}
	}

	// Remove hop-by-hop headers in request
	removeHopByHopHeaders(outReq.Header)
	outReq.Header.Del("X-Forwarded-For")

	resp, err := p.Transport.RoundTrip(outReq)
	if err != nil {
		log.Printf("Proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	// Remove hop-by-hop headers in response
	removeHopByHopHeaders(resp.Header)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// Announce trailers
	if len(resp.Trailer) > 0 {
		var trailerKeys []string
		for k := range resp.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		w.Header().Set("Trailer", strings.Join(trailerKeys, ","))
	}

	w.WriteHeader(resp.StatusCode)

	// Copy body and flush continuously
	flusher, isFlusher := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, wErr := w.Write(buf[:n]); wErr != nil {
				log.Printf("Error writing response body: %v", wErr)
				return
			}
			if isFlusher {
				flusher.Flush()
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading response body: %v", err)
			}
			break
		}
	}

	// Copy trailers after body
	for k, vv := range resp.Trailer {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	log.Printf("Proxied %s %s -> %s", r.Method, r.URL, resp.Status)
}

func removeHopByHopHeaders(h http.Header) {
	// RFC 7230, section 6.1: Connection-specific header fields
	if c := h.Get("Connection"); c != "" {
		for _, f := range splitAndTrim(c) {
			h.Del(f)
		}
	}
	for _, f := range hopByHopHeaders {
		h.Del(f)
	}
}

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	var res []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

func (p *HTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
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
		if closeErr := clientConn.Close(); closeErr != nil {
			log.Printf("Error closing client connection: %v", closeErr)
		}
		return
	}

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	cert, err := p.getCert(host)
	if err != nil {
		log.Printf("Failed to get cert for %s: %v", host, err)
		if closeErr := clientConn.Close(); closeErr != nil {
			log.Printf("Error closing client connection: %v", closeErr)
		}
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed for %s: %v", host, err)
		if closeErr := tlsConn.Close(); closeErr != nil {
			log.Printf("Error closing TLS connection: %v", closeErr)
		}
		return
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.proxyRequest(w, r, true)
		}),
	}

	l := &connectionHandler{conn: tlsConn}
	if err := server.Serve(l); err != nil && err != http.ErrServerClosed && err != io.EOF {
		log.Printf("Serve failed: %v", err)
	}
}

func (p *HTTPProxy) getCert(host string) (*tls.Certificate, error) {
	p.mu.RLock()
	cert, ok := p.certs[host]
	p.mu.RUnlock()
	if ok {
		return cert, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if cert, ok := p.certs[host]; ok {
		return cert, nil
	}

	cert, err := p.signCert(host)
	if err != nil {
		return nil, err
	}
	p.certs[host] = cert
	return cert, nil
}

func (p *HTTPProxy) signCert(host string) (*tls.Certificate, error) {
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

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, p.caCert, &priv.PublicKey, p.caKey)
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

type connectionHandler struct {
	conn net.Conn
	once sync.Once
}

func (l *connectionHandler) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		c = l.conn
	})
	if c == nil {
		return nil, io.EOF
	}
	return c, nil
}

func (l *connectionHandler) Close() error {
	return nil
}

func (l *connectionHandler) Addr() net.Addr {
	return l.conn.LocalAddr()
}
