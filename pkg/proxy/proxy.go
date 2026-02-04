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
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// BaseProxy provides basic forward proxy functionality including CONNECT support.
type BaseProxy struct {
	// Transport is used to perform the actual HTTP requests.
	// If nil, http.DefaultTransport is used.
	Transport http.RoundTripper

	// OnRequest is called for every non-CONNECT request.
	// It can modify the request or return a response.
	// If it returns a response, that response is sent back to the client.
	OnRequest func(req *http.Request) (*http.Response, error)
}

func (p *BaseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	p.handleHTTP(w, r)
}

func (p *BaseProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	log.Printf("CONNECT %s", r.Host)
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(destConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, destConn)
		done <- struct{}{}
	}()

	<-done
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func (p *BaseProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// In a forward proxy, the URL is usually absolute.
	if r.URL.Host == "" && r.Host != "" {
		r.URL.Host = r.Host
	}
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}

	var resp *http.Response
	var err error

	if p.OnRequest != nil {
		resp, err = p.OnRequest(r)
	}

	if err != nil {
		log.Printf("Error in OnRequest: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if resp == nil {
		transport := p.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}

		// Prepare request for forwarding
		outReq := r.Clone(r.Context())
		outReq.RequestURI = "" // Must be empty for Client.Do / RoundTrip

		// Remove hop-by-hop headers
		for _, h := range hopHeaders {
			outReq.Header.Del(h)
		}

		resp, err = transport.RoundTrip(outReq)
		if err != nil {
			log.Printf("Error forwarding request %s: %v", r.URL, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	defer resp.Body.Close()

	// Remove hop-by-hop headers from response
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}

	// Copy headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
