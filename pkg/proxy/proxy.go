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
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type HTTPProxy struct {
	TargetURL            *url.URL
	ListenHost           string // Hostname this proxy rule listens for (spec.host)
	AuthToken            string
	AuthHeader           string
	RequiredProxyToken   string
	ProxyAuthSecret      string
	ProxyAuthTokenMaxAge time.Duration

	caCert *x509.Certificate
	caKey  crypto.PrivateKey

	certs map[string]*tls.Certificate
	mu    sync.RWMutex

	Transport http.RoundTripper
}

func NewHTTPProxy(targetURL *url.URL, authToken, authHeader string, caCertPath, caKeyPath string) (*HTTPProxy, error) {
	p := &HTTPProxy{
		TargetURL:  targetURL,
		AuthToken:  authToken,
		AuthHeader: authHeader,
		certs:      make(map[string]*tls.Certificate),
		Transport:  http.DefaultTransport,
	}

	if os.Getenv("OTEL_INSTRUMENTATION_ENABLED") == "true" {
		p.Transport = otelhttp.NewTransport(p.Transport)
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
	if p.RequiredProxyToken != "" || p.ProxyAuthSecret != "" {
		pod, ok := p.AuthenticateProxyRequest(r.Header.Get("Proxy-Authorization"))
		if !ok {
			log.Printf("Proxy auth failed: missing or invalid Proxy-Authorization")
			w.Header().Set("Proxy-Authenticate", `Basic realm="Service Portal Proxy"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
		if pod != nil {
			if pod.Namespace == "" {
				log.Printf("Proxy auth: authenticated request: %s", pod.Name)
			} else {
				log.Printf("Proxy auth: authenticated request from pod %s/%s (uid: %s)", pod.Namespace, pod.Name, pod.UID)
			}
		}
	}

	if r.Method == http.MethodConnect && p.caCert != nil {
		p.handleConnect(w, r)
		return
	}

	p.proxyRequest(w, r, false, "")
}

// MatchHosts returns true if innerHost matches connectTarget.
// If both specify a port, the ports must match.
// If innerHost does not specify a port, it matches connectTarget if either connectTarget has no port
// or connectTarget specifies the standard HTTPS/HTTP port (443/80).
func MatchHosts(innerHost, connectTarget string) bool {
	innerH, innerP, err1 := net.SplitHostPort(innerHost)
	if err1 != nil {
		innerH = innerHost
		innerP = ""
	}

	connH, connP, err2 := net.SplitHostPort(connectTarget)
	if err2 != nil {
		connH = connectTarget
		connP = ""
	}

	if !strings.EqualFold(innerH, connH) {
		return false
	}

	if innerP != "" && connP != "" {
		return innerP == connP
	}

	if connP != "" && connP != "443" && connP != "80" && innerP == "" {
		return false
	}

	return true
}

func (p *HTTPProxy) proxyRequest(w http.ResponseWriter, r *http.Request, isMITM bool, connectTarget string) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	if isMITM {
		if connectTarget == "" || !MatchHosts(host, connectTarget) {
			log.Printf("MITM Host escape blocked: inner host %q does not match CONNECT target %q", host, connectTarget)
			http.Error(w, fmt.Sprintf("Access Denied: inner host %q does not match CONNECT target", host), http.StatusForbidden)
			return
		}
	}

	forceTarget := false
	if host == p.TargetURL.Host || (p.ListenHost != "" && strings.EqualFold(HostWithoutPort(host), HostWithoutPort(p.ListenHost))) {
		forceTarget = true
	} else if !isMITM && r.URL.Host == "" {
		forceTarget = true
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
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

	connectTarget := r.Host
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			p.proxyRequest(w, req, true, connectTarget)
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

// ValidateProxyAuth checks if the Proxy-Authorization header matches the expected token.
// Supports both 'Bearer <token>' and 'Basic <base64>' headers.
func ValidateProxyAuth(header, requiredToken string) bool {
	if requiredToken == "" {
		return true
	}
	if header == "" {
		return false
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return false
	}
	authType := strings.ToLower(parts[0])
	credential := strings.TrimSpace(parts[1])

	if authType == "bearer" {
		return credential == requiredToken
	}

	if authType == "basic" {
		decoded, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return false
		}
		credStr := string(decoded)
		userPass := strings.SplitN(credStr, ":", 2)
		if userPass[0] == requiredToken {
			return true
		}
		if len(userPass) == 2 && userPass[1] == requiredToken {
			return true
		}
	}
	return false
}

// PodIdentity represents the identity of a client pod authenticated via proxy token.
type PodIdentity struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

// MintPodToken creates a cryptographically signed per-pod token using HMAC-SHA256.
// An optional now time.Time parameter may be supplied to control the timestamp for testing.
func MintPodToken(secret string, id PodIdentity, now ...time.Time) string {
	t := time.Now()
	if len(now) > 0 && !now[0].IsZero() {
		t = now[0]
	}
	payload := fmt.Sprintf("%s:%s:%s:%d", id.Namespace, id.Name, id.UID, t.Unix())
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encodedPayload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s.%s", encodedPayload, sig)
}

// DefaultTokenMaxAge is the default validity duration for per-pod tokens (24 hours).
const DefaultTokenMaxAge = 24 * time.Hour

// VerifyPodToken verifies a per-pod token using HMAC-SHA256 and ensures it has not expired.
// If maxAge <= 0, DefaultTokenMaxAge (24 hours) is enforced.
func VerifyPodToken(token, secret string, maxAge time.Duration) (*PodIdentity, bool) {
	if token == "" || secret == "" {
		return nil, false
	}
	if maxAge <= 0 {
		maxAge = DefaultTokenMaxAge
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, false
	}
	encodedPayload, sig := parts[0], parts[1]
	expectedMAC := hmac.New(sha256.New, []byte(secret))
	expectedMAC.Write([]byte(encodedPayload))
	expectedSig := hex.EncodeToString(expectedMAC.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return nil, false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, false
	}
	fields := strings.Split(string(payloadBytes), ":")
	if len(fields) < 4 {
		return nil, false
	}

	issuedAtUnix, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return nil, false
	}
	issuedAt := time.Unix(issuedAtUnix, 0)
	if time.Since(issuedAt) > maxAge {
		log.Printf("Proxy auth: token expired (issued %v, max age %v)", issuedAt, maxAge)
		return nil, false
	}
	if issuedAt.Sub(time.Now()) > 5*time.Minute {
		log.Printf("Proxy auth: token timestamp in future (issued %v)", issuedAt)
		return nil, false
	}

	return &PodIdentity{
		Namespace: fields[0],
		Name:      fields[1],
		UID:       fields[2],
	}, true
}

// ExtractProxyTokens parses candidate tokens from a Proxy-Authorization header.
// The mutating admission webhook (injector) emits credentials formatted as
// Basic base64("pod:<token>") via the proxy URL userinfo (http://pod:<token>@proxy:port).
// Standard clients may also send credentials as "Bearer <token>".
// For compatibility with static tokens, username-only Basic auth is also accepted.
func ExtractProxyTokens(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return nil
	}
	authType := strings.ToLower(parts[0])
	credential := strings.TrimSpace(parts[1])

	switch authType {
	case "bearer":
		return []string{credential}
	case "basic":
		decoded, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return nil
		}
		credStr := string(decoded)
		userPass := strings.SplitN(credStr, ":", 2)
		if len(userPass) == 2 {
			if userPass[0] == "pod" {
				return []string{userPass[1]}
			}
			if userPass[1] == "" || userPass[1] == "x" || userPass[1] == "ignored" {
				return []string{userPass[0]}
			}
			return []string{userPass[1], userPass[0]}
		}
		return []string{userPass[0]}
	}
	return nil
}

// ExtractProxyToken parses the credential token from a Proxy-Authorization header.
func ExtractProxyToken(header string) string {
	tokens := ExtractProxyTokens(header)
	if len(tokens) > 0 {
		return tokens[0]
	}
	return ""
}

// AuthenticateProxyRequest verifies credentials in Proxy-Authorization header against configured secret or static token.
func (p *HTTPProxy) AuthenticateProxyRequest(header string) (*PodIdentity, bool) {
	if p.RequiredProxyToken == "" && p.ProxyAuthSecret == "" {
		return nil, true
	}
	tokens := ExtractProxyTokens(header)
	if len(tokens) == 0 {
		return nil, false
	}

	for _, token := range tokens {
		if p.ProxyAuthSecret != "" {
			if pod, ok := VerifyPodToken(token, p.ProxyAuthSecret, p.ProxyAuthTokenMaxAge); ok {
				return pod, true
			}
		}

		if p.RequiredProxyToken != "" && token == p.RequiredProxyToken {
			pod := &PodIdentity{
				Namespace: "",
				Name:      "unattributed (static token)",
				UID:       "",
			}
			return pod, true
		}
	}

	return nil, false
}
