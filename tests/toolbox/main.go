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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: toolbox <server|client|probe> [args]")
	}

	mode := os.Args[1]
	switch mode {
	case "server":
		runServer()
	case "client":
		if len(os.Args) < 3 {
			log.Fatal("Usage: toolbox client <url>")
		}
		runClient(os.Args[2])
	case "probe":
		if len(os.Args) < 3 {
			log.Fatal("Usage: toolbox probe <tcp|dns> [args]")
		}
		runProbe(os.Args[2:])
	default:
		log.Fatalf("Unknown mode: %s", mode)
	}
}

func runServer() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s (Host: %s)", r.Method, r.URL.Path, r.Host)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Failed to read body: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := map[string]any{
			"headers": headers,
			"body":    string(body),
			"method":  r.Method,
			"path":    r.URL.Path,
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("Failed to encode response: %v", err)
		}
	})

	log.Printf("Starting echo server on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func runClient(targetURL string) {
	log.Printf("Sending request to %s", targetURL)
	resp, err := http.Get(targetURL)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Body: %s\n", string(body))
}

func runProbe(args []string) {
	if len(args) < 2 {
		log.Fatal("Usage: toolbox probe tcp <host:port> [timeout] OR toolbox probe dns <server> <name> [timeout]")
	}

	probeType := args[0]
	switch probeType {
	case "tcp":
		target := args[1]
		timeout := 3 * time.Second
		if len(args) >= 3 {
			d, err := time.ParseDuration(args[2])
			if err != nil {
				log.Fatalf("invalid duration %q: %v", args[2], err)
			}
			timeout = d
		}
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err != nil {
			log.Fatalf("tcp dial to %s failed: %v", target, err)
		}
		if err := conn.Close(); err != nil {
			log.Fatalf("failed to close connection to %s: %v", target, err)
		}
		fmt.Printf("CONNECTED %s\n", target)
		os.Exit(0)

	case "dns":
		if len(args) < 3 {
			log.Fatal("Usage: toolbox probe dns <server> <name> [timeout]")
		}
		server := args[1]
		name := args[2]
		timeout := 3 * time.Second
		if len(args) >= 4 {
			d, err := time.ParseDuration(args[3])
			if err != nil {
				log.Fatalf("invalid duration %q: %v", args[3], err)
			}
			timeout = d
		}

		if server == "cluster" || server == "default" {
			deadline := time.Now().Add(timeout)
			backoff := 50 * time.Millisecond
			maxBackoff := 500 * time.Millisecond
			var lastErr error

			for {
				remaining := time.Until(deadline)
				if remaining <= 0 {
					break
				}
				attemptTimeout := remaining
				if attemptTimeout > 1*time.Second {
					attemptTimeout = 1 * time.Second
				}
				ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
				ips, err := net.DefaultResolver.LookupHost(ctx, name)
				cancel()
				if err == nil {
					fmt.Printf("RESOLVED %s: %v\n", name, ips)
					os.Exit(0)
				}
				lastErr = err

				if time.Until(deadline) <= 0 {
					break
				}
				sleepTime := backoff
				if rem := time.Until(deadline); sleepTime > rem {
					sleepTime = rem
				}
				time.Sleep(sleepTime)
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}

			resolv, err := os.ReadFile("/etc/resolv.conf")
			if err != nil {
				log.Printf("failed to read /etc/resolv.conf: %v", err)
			} else {
				fmt.Fprintf(os.Stderr, "/etc/resolv.conf:\n%s\n", string(resolv))
			}
			log.Fatalf("dns lookup of %s failed: %v", name, lastErr)
		}

		serverAddr := server
		if !strings.Contains(serverAddr, ":") {
			serverAddr = serverAddr + ":53"
		}

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", serverAddr)
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		ips, err := r.LookupHost(ctx, name)
		if err != nil {
			log.Fatalf("dns lookup of %s via %s failed: %v", name, serverAddr, err)
		}
		fmt.Printf("RESOLVED %s via %s: %v\n", name, serverAddr, ips)
		os.Exit(0)

	case "mitm-escape":
		if len(args) < 4 {
			log.Fatal("Usage: toolbox probe mitm-escape <proxyAddr> <connectHost> <innerHost> [path]")
		}
		proxyAddr := args[1]
		connectHost := args[2]
		innerHost := args[3]
		path := "/mitm-escape-test"
		if len(args) >= 5 {
			path = args[4]
		}

		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			log.Fatalf("dial proxy %s failed: %v", proxyAddr, err)
		}
		defer func() {
			if err := conn.Close(); err != nil {
				log.Printf("Failed to close conn: %v", err)
			}
		}()

		connectReq := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n", connectHost, connectHost)
		if auth := os.Getenv("PROXY_AUTHORIZATION"); auth != "" {
			connectReq += fmt.Sprintf("Proxy-Authorization: %s\r\n", auth)
		}
		connectReq += "\r\n"
		if _, err := conn.Write([]byte(connectReq)); err != nil {
			log.Fatalf("write CONNECT failed: %v", err)
		}

		br := bufio.NewReader(conn)
		connectResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			log.Fatalf("read CONNECT response failed: %v", err)
		}
		if connectResp.StatusCode != http.StatusOK {
			log.Fatalf("CONNECT returned %s", connectResp.Status)
		}

		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         connectHost,
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			log.Fatalf("TLS handshake failed: %v", err)
		}
		defer func() {
			if err := tlsConn.Close(); err != nil {
				log.Printf("Failed to close tlsConn: %v", err)
			}
		}()

		innerReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, innerHost)
		if _, err := tlsConn.Write([]byte(innerReq)); err != nil {
			log.Fatalf("write inner request failed: %v", err)
		}

		tlsBr := bufio.NewReader(tlsConn)
		resp, err := http.ReadResponse(tlsBr, &http.Request{Method: http.MethodGet})
		if err != nil {
			log.Fatalf("read inner response failed: %v", err)
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				log.Printf("Failed to close response body: %v", err)
			}
		}()

		fmt.Printf("STATUS: %d %s\n", resp.StatusCode, resp.Status)
		if resp.StatusCode == http.StatusForbidden {
			fmt.Println("BLOCKED")
			os.Exit(0)
		}
		os.Exit(1)

	default:
		log.Fatalf("Unknown probe type: %s", probeType)
	}
}
