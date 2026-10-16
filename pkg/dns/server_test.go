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

package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func sendDNSQueryUDP(t *testing.T, serverAddr, qname string, qtype dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		t.Fatalf("failed to dial UDP DNS: %v", err)
	}
	defer conn.Close()

	req := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               1234,
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
	if _, err := conn.Write(packed); err != nil {
		t.Fatalf("failed to send query: %v", err)
	}

	buf := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read DNS response: %v", err)
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}
	return resp
}

func sendDNSQueryTCP(t *testing.T, serverAddr, qname string, qtype dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("failed to dial TCP DNS: %v", err)
	}
	defer conn.Close()

	req := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               5678,
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

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(packed)))
	if _, err := conn.Write(lenBuf); err != nil {
		t.Fatalf("failed to write TCP length: %v", err)
	}
	if _, err := conn.Write(packed); err != nil {
		t.Fatalf("failed to write TCP query: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		t.Fatalf("failed to read TCP response length: %v", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf)
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatalf("failed to read TCP response payload: %v", err)
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(respBuf); err != nil {
		t.Fatalf("failed to unpack TCP response: %v", err)
	}
	return resp
}

func TestDNSServer_Match_A(t *testing.T) {
	matcher := RuleMatcherFunc(func(host string) bool {
		return host == "api.github.com" || host == "gemini.backend"
	})

	proxyIP := net.ParseIP("127.0.0.2")
	srv, err := NewServer(Config{
		BindAddr:  "127.0.0.1:0",
		ProxyIPv4: proxyIP,
		Matcher:   matcher,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()

	addr := srv.UDPAddr().String()

	resp := sendDNSQueryUDP(t, addr, "api.github.com.", dnsmessage.TypeA)
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
	expectedIP := [4]byte{127, 0, 0, 2}
	if aRecord.A != expectedIP {
		t.Errorf("expected IP %v, got %v", expectedIP, aRecord.A)
	}
}

func TestDNSServer_Match_AAAA(t *testing.T) {
	matcher := RuleMatcherFunc(func(host string) bool {
		return host == "api.github.com"
	})

	proxyIPv6 := net.ParseIP("::1")
	srv, err := NewServer(Config{
		BindAddr:  "127.0.0.1:0",
		ProxyIPv4: net.ParseIP("127.0.0.2"),
		ProxyIPv6: proxyIPv6,
		Matcher:   matcher,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()

	addr := srv.UDPAddr().String()

	resp := sendDNSQueryUDP(t, addr, "API.GITHUB.COM.", dnsmessage.TypeAAAA)
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
	expectedIP := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if aaaaRecord.AAAA != expectedIP {
		t.Errorf("expected IPv6 %v, got %v", expectedIP, aaaaRecord.AAAA)
	}
}

func TestDNSServer_Match_OtherTypes_NoData(t *testing.T) {
	matcher := RuleMatcherFunc(func(host string) bool {
		return host == "api.github.com"
	})

	srv, err := NewServer(Config{
		BindAddr: "127.0.0.1:0",
		Matcher:  matcher,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()

	addr := srv.UDPAddr().String()

	resp := sendDNSQueryUDP(t, addr, "api.github.com.", dnsmessage.TypeTXT)
	if resp.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("expected RCodeSuccess (NODATA), got %v", resp.RCode)
	}
	if len(resp.Answers) != 0 {
		t.Fatalf("expected 0 answers for TXT, got %d", len(resp.Answers))
	}
}

func TestDNSServer_Deny_NXDOMAIN(t *testing.T) {
	matcher := RuleMatcherFunc(func(host string) bool {
		return host == "api.github.com"
	})

	srv, err := NewServer(Config{
		BindAddr:      "127.0.0.1:0",
		DefaultAction: "Deny",
		Matcher:       matcher,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()

	addr := srv.UDPAddr().String()

	resp := sendDNSQueryUDP(t, addr, "unlisted.example.com.", dnsmessage.TypeA)
	if resp.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected NXDOMAIN (RCodeNameError), got %v", resp.RCode)
	}
	if len(resp.Answers) != 0 {
		t.Fatalf("expected 0 answers on NXDOMAIN, got %d", len(resp.Answers))
	}
}

func TestDNSServer_Forward_Allow(t *testing.T) {
	// 1. Mock upstream DNS server
	mockUpstreamIP := [4]byte{93, 184, 216, 34}
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet for mock upstream: %v", err)
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
			if len(req.Questions) > 0 && strings.EqualFold(strings.TrimSuffix(req.Questions[0].Name.String(), "."), "example.com") {
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  req.Questions[0].Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   300,
					},
					Body: &dnsmessage.AResource{A: mockUpstreamIP},
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

	upstreamAddr := upstreamConn.LocalAddr().String()

	// 2. Setup sidecar DNS server configured with DefaultAction: Allow
	matcher := RuleMatcherFunc(func(host string) bool {
		return host == "api.github.com"
	})

	srv, err := NewServer(Config{
		BindAddr:        "127.0.0.1:0",
		DefaultAction:   "Allow",
		UpstreamServers: []string{upstreamAddr},
		Matcher:         matcher,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()

	addr := srv.UDPAddr().String()

	resp := sendDNSQueryUDP(t, addr, "example.com.", dnsmessage.TypeA)
	if resp.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("expected RCodeSuccess from forwarded query, got %v", resp.RCode)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer from forwarded query, got %d", len(resp.Answers))
	}
	aRecord, ok := resp.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("expected *dnsmessage.AResource, got %T", resp.Answers[0].Body)
	}
	if aRecord.A != mockUpstreamIP {
		t.Errorf("expected IP %v from upstream, got %v", mockUpstreamIP, aRecord.A)
	}
}

func TestDNSServer_TCP(t *testing.T) {
	matcher := RuleMatcherFunc(func(host string) bool {
		return host == "api.github.com"
	})

	proxyIP := net.ParseIP("127.0.0.2")
	srv, err := NewServer(Config{
		BindAddr:  "127.0.0.1:0",
		ProxyIPv4: proxyIP,
		Matcher:   matcher,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()

	addr := srv.TCPAddr().String()

	resp := sendDNSQueryTCP(t, addr, "api.github.com.", dnsmessage.TypeA)
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
	expectedIP := [4]byte{127, 0, 0, 2}
	if aRecord.A != expectedIP {
		t.Errorf("expected IP %v, got %v", expectedIP, aRecord.A)
	}
}
