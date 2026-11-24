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
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// QueryDecision represents the handling decision for a DNS query.
type QueryDecision int

const (
	// DecisionDefault indicates the evaluator has no opinion and defers to the server's default action (forward or NXDOMAIN).
	DecisionDefault QueryDecision = iota
	// DecisionAllow indicates the query is allowed and should be answered with the proxy IP.
	DecisionAllow
	// DecisionDrop indicates the query should be silently dropped without response.
	DecisionDrop
	// DecisionNXDomain indicates the query is actively rejected and should be answered with NXDOMAIN regardless of DefaultAction.
	DecisionNXDomain
)

// QueryEvaluator evaluates a DNS query for a client in a single decision step.
type QueryEvaluator interface {
	EvaluateQuery(ctx context.Context, host string, qtype dnsmessage.Type, clientAddr net.Addr) QueryDecision
}

// QueryEvaluatorFunc is an adapter function implementing QueryEvaluator.
type QueryEvaluatorFunc func(ctx context.Context, host string, qtype dnsmessage.Type, clientAddr net.Addr) QueryDecision

// EvaluateQuery calls the underlying function.
func (f QueryEvaluatorFunc) EvaluateQuery(ctx context.Context, host string, qtype dnsmessage.Type, clientAddr net.Addr) QueryDecision {
	return f(ctx, host, qtype, clientAddr)
}

// Config specifies the configuration for the sidecar DNS server.
type Config struct {
	// BindAddr is the listen address for the DNS server (e.g. "127.0.0.1:53" or ":53").
	BindAddr string
	// ProxyIPv4 is the IPv4 address of the proxy to return for matching hosts (e.g. 127.0.0.2).
	ProxyIPv4 net.IP
	// ProxyIPv6 is the IPv6 address of the proxy to return for matching hosts (optional).
	ProxyIPv6 net.IP
	// Evaluator determines the handling decision for a DNS query in a single step.
	Evaluator QueryEvaluator
	// DefaultAction specifies what to do when a hostname does not match a rule.
	// Defaults to "Deny" (return NXDOMAIN). If "Allow", forwards to UpstreamServers.
	DefaultAction string
	// UpstreamServers are the upstream DNS resolvers used when forwarding queries (e.g. ["10.96.0.10:53"]).
	UpstreamServers []string
	// ForwardTimeout is the timeout for forwarding queries to upstream resolvers.
	ForwardTimeout time.Duration
	// TTL is the time-to-live for generated A and AAAA records in seconds. Defaults to 60.
	TTL uint32
}

// defaultTCPReadTimeout bounds how long the TCP DNS listener waits to read a client query.
const defaultTCPReadTimeout = 5 * time.Second

// Server serves DNS requests over UDP and TCP using golang.org/x/net/dns/dnsmessage.
type Server struct {
	config         Config
	tcpReadTimeout time.Duration
	udpConn        net.PacketConn
	tcpListener    net.Listener
	mu             sync.Mutex
	started        bool
}

// NewServer creates a new sidecar DNS Server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.BindAddr == "" {
		cfg.BindAddr = "127.0.0.1:53"
	}
	if cfg.ProxyIPv4 == nil {
		cfg.ProxyIPv4 = net.ParseIP("127.0.0.2")
	}
	if cfg.ForwardTimeout <= 0 {
		cfg.ForwardTimeout = 3 * time.Second
	}
	if cfg.TTL == 0 {
		cfg.TTL = 60
	}

	return &Server{
		config:         cfg,
		tcpReadTimeout: defaultTCPReadTimeout,
	}, nil
}

func (s *Server) handleQuery(ctx context.Context, reqBytes []byte, clientAddr net.Addr, isTCP bool) ([]byte, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(reqBytes); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	if len(msg.Questions) == 0 {
		resp := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       msg.Header.ID,
				Response: true,
				RCode:    dnsmessage.RCodeSuccess,
			},
		}
		return resp.Pack()
	}

	q := msg.Questions[0]
	qname := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")

	decision := DecisionDefault
	if s.config.Evaluator != nil {
		decision = s.config.Evaluator.EvaluateQuery(ctx, qname, q.Type, clientAddr)
	}

	switch decision {
	case DecisionAllow:
		return s.allowResponse(&msg, q)
	case DecisionDefault:
		return s.applyDefaultAction(reqBytes, &msg, qname, isTCP)
	case DecisionDrop:
		return nil, nil
	case DecisionNXDomain:
		return nxdomainResponse(&msg)
	default:
		// Unknown decision value fails closed (not answered as allowed).
		return nxdomainResponse(&msg)
	}
}

func (s *Server) allowResponse(msg *dnsmessage.Message, q dnsmessage.Question) ([]byte, error) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 msg.Header.ID,
			Response:           true,
			OpCode:             msg.Header.OpCode,
			Authoritative:      true,
			RecursionDesired:   msg.Header.RecursionDesired,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: msg.Questions,
	}

	switch q.Type {
	case dnsmessage.TypeA:
		if s.config.ProxyIPv4 != nil {
			ip4 := s.config.ProxyIPv4.To4()
			if ip4 != nil {
				var a [4]byte
				copy(a[:], ip4)
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   s.config.TTL,
					},
					Body: &dnsmessage.AResource{A: a},
				})
			}
		}
	case dnsmessage.TypeAAAA:
		if s.config.ProxyIPv6 != nil {
			ip6 := s.config.ProxyIPv6.To16()
			if ip6 != nil {
				var aaaa [16]byte
				copy(aaaa[:], ip6)
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  dnsmessage.TypeAAAA,
						Class: dnsmessage.ClassINET,
						TTL:   s.config.TTL,
					},
					Body: &dnsmessage.AAAAResource{AAAA: aaaa},
				})
			}
		}
	default:
		// For non-address queries (TXT, MX, etc.) on matched policy hosts,
		// respond with NOERROR and empty answer (RFC NODATA).
	}
	return resp.Pack()
}

func (s *Server) applyDefaultAction(reqBytes []byte, msg *dnsmessage.Message, qname string, isTCP bool) ([]byte, error) {
	if strings.EqualFold(s.config.DefaultAction, "Allow") {
		respBytes, err := s.forward(reqBytes, isTCP)
		if err != nil {
			log.Printf("DNS forward failed for %q: %v", qname, err)
			resp := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:       msg.Header.ID,
					Response: true,
					RCode:    dnsmessage.RCodeServerFailure,
				},
				Questions: msg.Questions,
			}
			return resp.Pack()
		}

		if !isTCP && len(respBytes) > 512 {
			hasEDNS := false
			for _, extra := range msg.Additionals {
				if extra.Header.Type == dnsmessage.TypeOPT {
					hasEDNS = true
					break
				}
			}
			if !hasEDNS {
				var respMsg dnsmessage.Message
				if err := respMsg.Unpack(respBytes); err != nil {
					log.Printf("DNS unpack for truncation failed: %v", err)
				} else {
					respMsg.Header.Truncated = true
					respMsg.Answers = nil
					respMsg.Authorities = nil
					respMsg.Additionals = nil
					truncated, err := respMsg.Pack()
					if err != nil {
						log.Printf("DNS pack for truncation failed: %v", err)
					} else {
						return truncated, nil
					}
				}
			}
		}

		return respBytes, nil
	}

	// Default: deny with NXDOMAIN
	return nxdomainResponse(msg)
}

func nxdomainResponse(msg *dnsmessage.Message) ([]byte, error) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 msg.Header.ID,
			Response:           true,
			OpCode:             msg.Header.OpCode,
			Authoritative:      true,
			RecursionDesired:   msg.Header.RecursionDesired,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeNameError,
		},
		Questions: msg.Questions,
	}
	return resp.Pack()
}

func closeQuietly(c io.Closer) {
	if err := c.Close(); err != nil {
		log.Printf("Failed to close connection: %v", err)
	}
}

func (s *Server) forward(reqBytes []byte, clientIsTCP bool) ([]byte, error) {
	if len(s.config.UpstreamServers) == 0 {
		return nil, errors.New("no upstream DNS servers configured")
	}

	timeout := s.config.ForwardTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	var lastErr error
	for _, server := range s.config.UpstreamServers {
		target := server
		if !strings.Contains(target, ":") {
			target = net.JoinHostPort(target, "53")
		}

		if clientIsTCP {
			d := net.Dialer{Timeout: timeout}
			conn, err := d.Dial("tcp", target)
			if err != nil {
				lastErr = err
				continue
			}

			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, uint16(len(reqBytes)))
			if _, err := conn.Write(lenBuf); err != nil {
				closeQuietly(conn)
				lastErr = err
				continue
			}
			if _, err := conn.Write(reqBytes); err != nil {
				closeQuietly(conn)
				lastErr = err
				continue
			}

			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				closeQuietly(conn)
				lastErr = err
				continue
			}
			respLen := binary.BigEndian.Uint16(lenBuf)
			respBuf := make([]byte, respLen)
			if _, err := io.ReadFull(conn, respBuf); err != nil {
				closeQuietly(conn)
				lastErr = err
				continue
			}
			closeQuietly(conn)
			return respBuf, nil
		}

		// Forward via UDP
		d := net.Dialer{Timeout: timeout}
		conn, err := d.Dial("udp", target)
		if err != nil {
			lastErr = err
			continue
		}

		if _, err := conn.Write(reqBytes); err != nil {
			closeQuietly(conn)
			lastErr = err
			continue
		}

		buf := make([]byte, 4096)
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			closeQuietly(conn)
			lastErr = err
			continue
		}
		n, err := conn.Read(buf)
		closeQuietly(conn)
		if err != nil {
			lastErr = err
			continue
		}

		// If truncated (TC bit in flags byte 2: 0x02), retry over TCP
		if n >= 4 && (buf[2]&0x02) != 0 {
			tcpConn, err := d.Dial("tcp", target)
			if err != nil {
				lastErr = err
				continue
			}
			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, uint16(len(reqBytes)))
			if _, err := tcpConn.Write(lenBuf); err != nil {
				closeQuietly(tcpConn)
				lastErr = err
				continue
			}
			if _, err := tcpConn.Write(reqBytes); err != nil {
				closeQuietly(tcpConn)
				lastErr = err
				continue
			}
			if _, err := io.ReadFull(tcpConn, lenBuf); err != nil {
				closeQuietly(tcpConn)
				lastErr = err
				continue
			}
			respLen := binary.BigEndian.Uint16(lenBuf)
			respBuf := make([]byte, respLen)
			if _, err := io.ReadFull(tcpConn, respBuf); err != nil {
				closeQuietly(tcpConn)
				lastErr = err
				continue
			}
			closeQuietly(tcpConn)
			return respBuf, nil
		}

		return buf[:n], nil
	}

	return nil, fmt.Errorf("all upstream DNS servers failed: %w", lastErr)
}

// Start listens and starts serving DNS over UDP and TCP.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return errors.New("server already started")
	}

	udpConn, err := net.ListenPacket("udp", s.config.BindAddr)
	if err != nil {
		return fmt.Errorf("failed to listen UDP on %s: %w", s.config.BindAddr, err)
	}

	tcpListener, err := net.Listen("tcp", s.config.BindAddr)
	if err != nil {
		if closeErr := udpConn.Close(); closeErr != nil {
			log.Printf("Failed to close UDP conn: %v", closeErr)
		}
		return fmt.Errorf("failed to listen TCP on %s: %w", s.config.BindAddr, err)
	}

	s.udpConn = udpConn
	s.tcpListener = tcpListener
	s.started = true

	tcpReadTimeout := s.tcpReadTimeout
	if tcpReadTimeout <= 0 {
		tcpReadTimeout = defaultTCPReadTimeout
	}

	// Serve UDP
	go func() {
		buf := make([]byte, 4096)
		for {
			n, clientAddr, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			reqBytes := make([]byte, n)
			copy(reqBytes, buf[:n])
			go func(req []byte, addr net.Addr) {
				respBytes, err := s.handleQuery(ctx, req, addr, false)
				if err != nil {
					log.Printf("DNS UDP handle error: %v", err)
					return
				}
				if len(respBytes) == 0 {
					return
				}
				if _, err := udpConn.WriteTo(respBytes, addr); err != nil {
					log.Printf("DNS UDP write error: %v", err)
				}
			}(reqBytes, clientAddr)
		}
	}()

	// Serve TCP
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer closeQuietly(c)
				lenBuf := make([]byte, 2)
				for {
					if err := c.SetReadDeadline(time.Now().Add(tcpReadTimeout)); err != nil {
						return
					}
					if _, err := io.ReadFull(c, lenBuf); err != nil {
						return
					}
					reqLen := binary.BigEndian.Uint16(lenBuf)
					reqBuf := make([]byte, reqLen)
					if _, err := io.ReadFull(c, reqBuf); err != nil {
						return
					}
					respBytes, err := s.handleQuery(ctx, reqBuf, c.RemoteAddr(), true)
					if err != nil {
						log.Printf("DNS TCP handle error: %v", err)
						return
					}
					if len(respBytes) == 0 {
						// Clear the query read deadline so dropped queries stay held
						// until the peer closes or ctx is cancelled.
						if err := c.SetReadDeadline(time.Time{}); err != nil {
							return
						}
						HoldConnection(ctx, c)
						return
					}
					binary.BigEndian.PutUint16(lenBuf, uint16(len(respBytes)))
					if _, err := c.Write(lenBuf); err != nil {
						return
					}
					if _, err := c.Write(respBytes); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	go func() {
		<-ctx.Done()
		if err := s.Shutdown(context.Background()); err != nil {
			log.Printf("DNS server shutdown error: %v", err)
		}
	}()

	return nil
}

// HoldConnection holds a connection open without sending data until the peer closes it
// or ctx is cancelled. Any data sent by the peer while held is discarded.
func HoldConnection(ctx context.Context, c net.Conn) {
	done := make(chan struct{})
	go func() {
		// Use a standard read buffer to efficiently drain and discard any data
		// the peer sends while the connection is held.
		buf := make([]byte, 4096)
		for {
			if _, err := c.Read(buf); err != nil {
				close(done)
				return
			}
		}
	}()

	if ctx != nil && ctx.Done() != nil {
		select {
		case <-done:
		case <-ctx.Done():
		}
	} else {
		<-done
	}
}

// UDPAddr returns the bound local UDP address.
func (s *Server) UDPAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpConn != nil {
		return s.udpConn.LocalAddr()
	}
	return nil
}

// TCPAddr returns the bound local TCP address.
func (s *Server) TCPAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcpListener != nil {
		return s.tcpListener.Addr()
	}
	return nil
}

// Shutdown gracefully terminates the DNS server listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return nil
	}
	s.started = false

	var errs []error
	if s.udpConn != nil {
		if err := s.udpConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.tcpListener != nil {
		if err := s.tcpListener.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
