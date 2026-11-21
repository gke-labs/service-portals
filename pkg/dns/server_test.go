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

func sendDNSQueryUDPOpts(t *testing.T, serverAddr, qname string, qtype dnsmessage.Type, edns bool) (dnsmessage.Message, int) {
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
	if edns {
		req.Additionals = append(req.Additionals, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: 4096,
			},
			Body: &dnsmessage.OPTResource{},
		})
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
	return resp, n
}

func sendDNSQueryUDP(t *testing.T, serverAddr, qname string, qtype dnsmessage.Type) dnsmessage.Message {
	msg, _ := sendDNSQueryUDPOpts(t, serverAddr, qname, qtype, false)
	return msg
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
	evaluator := QueryEvaluatorFunc(func(_ context.Context, host string, _ dnsmessage.Type, _ net.Addr) QueryDecision {
		if host == "api.github.com" || host == "gemini.backend" {
			return DecisionAllow
		}
		return DecisionDefault
	})

	proxyIP := net.ParseIP("127.0.0.2")
	srv, err := NewServer(Config{
		BindAddr:  "127.0.0.1:0",
		ProxyIPv4: proxyIP,
		Evaluator: evaluator,
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
	evaluator := QueryEvaluatorFunc(func(_ context.Context, host string, _ dnsmessage.Type, _ net.Addr) QueryDecision {
		if host == "api.github.com" {
			return DecisionAllow
		}
		return DecisionDefault
	})

	proxyIPv6 := net.ParseIP("::1")
	srv, err := NewServer(Config{
		BindAddr:  "127.0.0.1:0",
		ProxyIPv4: net.ParseIP("127.0.0.2"),
		ProxyIPv6: proxyIPv6,
		Evaluator: evaluator,
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
	evaluator := QueryEvaluatorFunc(func(_ context.Context, host string, _ dnsmessage.Type, _ net.Addr) QueryDecision {
		if host == "api.github.com" {
			return DecisionAllow
		}
		return DecisionDefault
	})

	srv, err := NewServer(Config{
		BindAddr:  "127.0.0.1:0",
		Evaluator: evaluator,
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
	evaluator := QueryEvaluatorFunc(func(_ context.Context, host string, _ dnsmessage.Type, _ net.Addr) QueryDecision {
		if host == "api.github.com" {
			return DecisionAllow
		}
		return DecisionDefault
	})

	srv, err := NewServer(Config{
		BindAddr:      "127.0.0.1:0",
		DefaultAction: "Deny",
		Evaluator:     evaluator,
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
	evaluator := QueryEvaluatorFunc(func(_ context.Context, host string, _ dnsmessage.Type, _ net.Addr) QueryDecision {
		if host == "api.github.com" {
			return DecisionAllow
		}
		return DecisionDefault
	})

	srv, err := NewServer(Config{
		BindAddr:        "127.0.0.1:0",
		DefaultAction:   "Allow",
		UpstreamServers: []string{upstreamAddr},
		Evaluator:       evaluator,
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
	evaluator := QueryEvaluatorFunc(func(_ context.Context, host string, _ dnsmessage.Type, _ net.Addr) QueryDecision {
		if host == "api.github.com" {
			return DecisionAllow
		}
		return DecisionDefault
	})

	proxyIP := net.ParseIP("127.0.0.2")
	srv, err := NewServer(Config{
		BindAddr:  "127.0.0.1:0",
		ProxyIPv4: proxyIP,
		Evaluator: evaluator,
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

func TestDNSServer_Forward_Truncation(t *testing.T) {
	// Create mock upstream that listens on UDP and TCP on same port
	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP for mock upstream: %v", err)
	}
	defer udpListener.Close()

	upstreamAddr := udpListener.LocalAddr().String()

	tcpListener, err := net.Listen("tcp", upstreamAddr)
	if err != nil {
		t.Fatalf("failed to listen TCP for mock upstream: %v", err)
	}
	defer tcpListener.Close()

	makeLargeResponse := func(req dnsmessage.Message) dnsmessage.Message {
		resp := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       req.Header.ID,
				Response: true,
				RCode:    dnsmessage.RCodeSuccess,
			},
			Questions: req.Questions,
		}
		// Add 30 A records so that the response length exceeds 512 bytes (~700 bytes)
		for i := 0; i < 30; i++ {
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  req.Questions[0].Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   300,
				},
				Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, byte(i + 1)}},
			})
		}
		return resp
	}

	// Upstream UDP handler
	go func() {
		buf := make([]byte, 4096)
		for {
			n, clientAddr, err := udpListener.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Message
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			resp := makeLargeResponse(req)
			packed, err := resp.Pack()
			if err == nil {
				_, _ = udpListener.WriteTo(packed, clientAddr)
			}
		}
	}()

	// Upstream TCP handler
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				lenBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, lenBuf); err != nil {
					return
				}
				reqLen := binary.BigEndian.Uint16(lenBuf)
				reqBuf := make([]byte, reqLen)
				if _, err := io.ReadFull(c, reqBuf); err != nil {
					return
				}
				var req dnsmessage.Message
				if err := req.Unpack(reqBuf); err != nil {
					return
				}
				resp := makeLargeResponse(req)
				packed, err := resp.Pack()
				if err != nil {
					return
				}
				binary.BigEndian.PutUint16(lenBuf, uint16(len(packed)))
				if _, err := c.Write(lenBuf); err != nil {
					return
				}
				_, _ = c.Write(packed)
			}(conn)
		}
	}()

	// Setup sidecar DNS server configured with DefaultAction: Allow
	srv, err := NewServer(Config{
		BindAddr:        "127.0.0.1:0",
		DefaultAction:   "Allow",
		UpstreamServers: []string{upstreamAddr},
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

	srvUDP := srv.UDPAddr().String()
	srvTCP := srv.TCPAddr().String()

	// 1. Query over UDP without EDNS -> should be truncated with TC set, size <= 512
	respUDP, rawLen := sendDNSQueryUDPOpts(t, srvUDP, "large.example.com.", dnsmessage.TypeA, false)
	if !respUDP.Header.Truncated {
		t.Errorf("expected Truncated bit to be set for >512 byte UDP response without EDNS")
	}
	if rawLen > 512 {
		t.Errorf("expected datagram size <= 512, got %d", rawLen)
	}

	// 2. Query over TCP -> should receive full response with all 30 records, Truncated=false
	respTCP := sendDNSQueryTCP(t, srvTCP, "large.example.com.", dnsmessage.TypeA)
	if respTCP.Header.Truncated {
		t.Errorf("expected Truncated bit to be false over TCP")
	}
	if len(respTCP.Answers) != 30 {
		t.Errorf("expected 30 answers over TCP, got %d", len(respTCP.Answers))
	}

	// 3. Query over UDP with EDNS -> should receive full response without truncation
	respEDNS, _ := sendDNSQueryUDPOpts(t, srvUDP, "large.example.com.", dnsmessage.TypeA, true)
	if respEDNS.Header.Truncated {
		t.Errorf("expected Truncated bit to be false for UDP query with EDNS")
	}
	if len(respEDNS.Answers) != 30 {
		t.Errorf("expected 30 answers over UDP with EDNS, got %d", len(respEDNS.Answers))
	}
}

type dropAndMatch struct {
	dropHosts  map[string]bool
	matchHosts map[string]bool
}

func (d *dropAndMatch) EvaluateQuery(_ context.Context, host string, _ dnsmessage.Type, _ net.Addr) QueryDecision {
	if d.dropHosts[host] {
		return DecisionDrop
	}
	if d.matchHosts[host] {
		return DecisionAllow
	}
	return DecisionDefault
}

func TestDNSServer_Drop_UDP(t *testing.T) {
	matcher := &dropAndMatch{
		dropHosts:  map[string]bool{"unbound.example.com": true},
		matchHosts: map[string]bool{"allowed.example.com": true},
	}

	srv, err := NewServer(Config{
		BindAddr:      "127.0.0.1:0",
		DefaultAction: "Deny",
		Evaluator:     matcher,
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

	// 1. Dropped host: no answer sent, client read times out
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("failed to dial UDP: %v", err)
	}
	defer conn.Close()

	req := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               1111,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("unbound.example.com."),
				Type:  dnsmessage.TypeA,
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

	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("expected read timeout for dropped host, got %d bytes", n)
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected timeout error, got %v", err)
	}

	// 2. Allowed host: answered with proxy IP
	resp := sendDNSQueryUDP(t, addr, "allowed.example.com.", dnsmessage.TypeA)
	if resp.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("expected NOERROR for allowed host, got %v", resp.RCode)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer for allowed host, got %d", len(resp.Answers))
	}

	// 3. Denied host: answered with NXDOMAIN
	respDenied := sendDNSQueryUDP(t, addr, "denied.example.com.", dnsmessage.TypeA)
	if respDenied.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected NXDOMAIN for denied host, got %v", respDenied.RCode)
	}
}

func TestDNSServer_Drop_TCP(t *testing.T) {
	evaluator := &dropAndMatch{
		dropHosts:  map[string]bool{"unbound.example.com": true},
		matchHosts: map[string]bool{"allowed.example.com": true},
	}

	srv, err := NewServer(Config{
		BindAddr:      "127.0.0.1:0",
		DefaultAction: "Deny",
		Evaluator:     evaluator,
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

	// 1. Dropped host: no answer sent, held without reset until client closes
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial TCP: %v", err)
	}
	defer conn.Close()

	req := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               2222,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("unbound.example.com."),
				Type:  dnsmessage.TypeA,
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
		t.Fatalf("failed to write len: %v", err)
	}
	if _, err := conn.Write(packed); err != nil {
		t.Fatalf("failed to write query: %v", err)
	}

	// Read should time out with no data sent by server (held, not closed or reset)
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("expected timeout reading from held TCP conn, got %d bytes", n)
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected timeout error, got %v", err)
	}

	// Client closes connection; server must cleanly release HoldConnection
	_ = conn.Close()

	// 2. Allowed host over TCP: answered
	respTCP := sendDNSQueryTCP(t, addr, "allowed.example.com.", dnsmessage.TypeA)
	if respTCP.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("expected NOERROR for allowed host over TCP, got %v", respTCP.RCode)
	}
}

func TestHoldConnection(t *testing.T) {
	t.Run("unblocks when peer closes", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()

		done := make(chan struct{})
		go func() {
			HoldConnection(t.Context(), serverConn)
			close(done)
		}()

		select {
		case <-done:
			t.Fatal("expected HoldConnection to block while connection is open")
		case <-time.After(50 * time.Millisecond):
		}

		_ = clientConn.Close()
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("expected HoldConnection to unblock after peer closed connection")
		}
	})

	t.Run("unblocks when context is cancelled", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			HoldConnection(ctx, serverConn)
			close(done)
		}()

		select {
		case <-done:
			t.Fatal("expected HoldConnection to block while connection is open")
		case <-time.After(50 * time.Millisecond):
		}

		cancel()
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("expected HoldConnection to unblock after context cancelled")
		}
	})
}

func TestDNSServer_NXDomain_OverridesDefaultActionForward(t *testing.T) {
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
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  req.Questions[0].Name,
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   60,
						},
						Body: &dnsmessage.AResource{A: mockUpstreamIP},
					},
				},
			}
			packed, err := resp.Pack()
			if err == nil {
				_, _ = upstreamConn.WriteTo(packed, clientAddr)
			}
		}
	}()

	upstreamAddr := upstreamConn.LocalAddr().String()

	evaluator := QueryEvaluatorFunc(func(_ context.Context, host string, _ dnsmessage.Type, _ net.Addr) QueryDecision {
		if host == "reject.example.com" {
			return DecisionNXDomain
		}
		return DecisionDefault
	})

	srv, err := NewServer(Config{
		BindAddr:        "127.0.0.1:0",
		DefaultAction:   "Allow",
		UpstreamServers: []string{upstreamAddr},
		Evaluator:       evaluator,
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

	// 1. DecisionNXDomain -> answers NXDOMAIN despite DefaultAction forwarding
	respNXDomain := sendDNSQueryUDP(t, addr, "reject.example.com.", dnsmessage.TypeA)
	if respNXDomain.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected NXDOMAIN (RCodeNameError) for DecisionNXDomain, got %v", respNXDomain.RCode)
	}
	if len(respNXDomain.Answers) != 0 {
		t.Fatalf("expected 0 answers on DecisionNXDomain, got %d", len(respNXDomain.Answers))
	}

	// 2. DecisionDefault -> forwarded upstream because DefaultAction is Allow
	respDefault := sendDNSQueryUDP(t, addr, "forward.example.com.", dnsmessage.TypeA)
	if respDefault.RCode != dnsmessage.RCodeSuccess || len(respDefault.Answers) != 1 {
		t.Fatalf("expected 1 answer from upstream for DecisionDefault, got rcode=%v answers=%d", respDefault.RCode, len(respDefault.Answers))
	}
	if aRecord, ok := respDefault.Answers[0].Body.(*dnsmessage.AResource); !ok || aRecord.A != mockUpstreamIP {
		t.Errorf("expected upstream IP %v, got %v", mockUpstreamIP, respDefault.Answers[0].Body)
	}
}

func TestDNSServer_UnknownDecision_FailsClosed(t *testing.T) {
	// Set up mock upstream DNS server returning 9.9.9.9 for all queries
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP for mock upstream: %v", err)
	}
	defer upstreamConn.Close()

	mockUpstreamIP := [4]byte{9, 9, 9, 9}
	go func() {
		buf := make([]byte, 512)
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
					ID:                 req.Header.ID,
					Response:           true,
					OpCode:             req.Header.OpCode,
					Authoritative:      true,
					RecursionDesired:   req.Header.RecursionDesired,
					RecursionAvailable: true,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: req.Questions,
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  req.Questions[0].Name,
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   60,
						},
						Body: &dnsmessage.AResource{A: mockUpstreamIP},
					},
				},
			}
			packed, err := resp.Pack()
			if err == nil {
				_, _ = upstreamConn.WriteTo(packed, clientAddr)
			}
		}
	}()

	upstreamAddr := upstreamConn.LocalAddr().String()

	const unknownDecision QueryDecision = 999
	evaluator := QueryEvaluatorFunc(func(_ context.Context, host string, _ dnsmessage.Type, _ net.Addr) QueryDecision {
		if host == "unknown.example.com" {
			return unknownDecision
		}
		return DecisionDefault
	})

	srv, err := NewServer(Config{
		BindAddr:        "127.0.0.1:0",
		DefaultAction:   "Allow",
		UpstreamServers: []string{upstreamAddr},
		Evaluator:       evaluator,
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

	// 1. Unknown decision -> fails closed with NXDOMAIN even though DefaultAction is Allow
	respUnknown := sendDNSQueryUDP(t, addr, "unknown.example.com.", dnsmessage.TypeA)
	if respUnknown.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected NXDOMAIN (RCodeNameError) for unknown decision, got %v", respUnknown.RCode)
	}
	if len(respUnknown.Answers) != 0 {
		t.Fatalf("expected 0 answers on unknown decision, got %d", len(respUnknown.Answers))
	}

	// 2. DecisionDefault -> forwarded upstream because DefaultAction is Allow
	respDefault := sendDNSQueryUDP(t, addr, "forward.example.com.", dnsmessage.TypeA)
	if respDefault.RCode != dnsmessage.RCodeSuccess || len(respDefault.Answers) != 1 {
		t.Fatalf("expected 1 answer from upstream for DecisionDefault, got rcode=%v answers=%d", respDefault.RCode, len(respDefault.Answers))
	}
	if aRecord, ok := respDefault.Answers[0].Body.(*dnsmessage.AResource); !ok || aRecord.A != mockUpstreamIP {
		t.Errorf("expected upstream IP %v, got %v", mockUpstreamIP, respDefault.Answers[0].Body)
	}
}
