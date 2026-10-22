package scopedhttp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/protocol/socks"
)

type Session struct {
	ctx          context.Context
	cancel       context.CancelFunc
	plan         *Plan
	proxyDial    func(context.Context, string, M.Socksaddr) (net.Conn, error)
	transport    *http.Transport
	client       *http.Client
	access       sync.Mutex
	conns        map[*ownedConn]struct{}
	cache        map[string][]netip.Addr
	closed       bool
	closeOnce    sync.Once
	stopInstance func() bool
	proxyScope   *adapter.Scope
}

func NewSession(ctx, instanceContext context.Context, plan *Plan) (*Session, error) {
	if err := deadlineContext(ctx); err != nil {
		return nil, err
	}
	if instanceContext == nil || plan == nil {
		return nil, errors.New("missing scoped session dependency")
	}
	// NewDefault installs the core's platform socket protection/interface controls.
	// Its target is always numeric; no ResolveDialer or global DNS transport exists
	// anywhere in this private graph. TCP fast open remains explicitly disabled.
	bottom, err := dialer.NewDefault(instanceContext, option.DialerOptions{})
	if err != nil {
		return nil, err
	}
	s := newSession(ctx, instanceContext, plan)
	proxyAddr := M.ParseSocksaddr(net.JoinHostPort(plan.proxy.server, strconv.Itoa(int(plan.proxy.port))))
	if plan.proxy.typ == "shadowsocks" {
		outbound, scope, err := newScopedShadowsocks(instanceContext, plan.proxy.tag, plan.proxy.server, plan.proxy.port, plan.proxy.method, plan.proxy.password)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.access.Lock()
		if s.closed || s.ctx.Err() != nil {
			s.access.Unlock()
			_ = scope.Close()
			s.Close()
			return nil, context.Canceled
		}
		s.proxyScope = scope
		s.access.Unlock()
		s.proxyDial = outbound.DialContext
	} else if plan.proxy.typ == "socks" {
		client := socks.NewClient(bottom, proxyAddr, socks.Version5, plan.proxy.username, plan.proxy.password)
		s.proxyDial = client.DialContext
	} else {
		s.proxyDial = func(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
			if network != "tcp" {
				return nil, errors.New("HTTP scoped proxy supports only TCP")
			}
			raw, err := bottom.DialContext(ctx, N.NetworkTCP, proxyAddr)
			if err != nil {
				return nil, err
			}
			stop := context.AfterFunc(ctx, func() { raw.Close() })
			defer stop()
			if deadline, ok := ctx.Deadline(); ok {
				raw.SetDeadline(deadline)
			}
			request := &http.Request{Method: http.MethodConnect, URL: nil, Host: target.String(), Header: make(http.Header)}
			if plan.proxy.username != "" || plan.proxy.password != "" {
				request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(plan.proxy.username+":"+plan.proxy.password)))
			}
			// Write CONNECT ourselves: target has already been reduced to a numeric
			// IP, so a proxy never resolves a provider name on our behalf.
			_, err = fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target.String(), target.String())
			if err == nil {
				err = request.Header.Write(raw)
			}
			if err == nil {
				_, err = io.WriteString(raw, "\r\n")
			}
			limit := &handshakeReader{Conn: raw, remaining: 8192}
			reader := bufio.NewReader(limit)
			var response *http.Response
			if err == nil {
				response, err = http.ReadResponse(reader, request)
			}
			if err != nil {
				raw.Close()
				return nil, err
			}
			if response.StatusCode != http.StatusOK {
				raw.Close()
				return nil, fmt.Errorf("proxy CONNECT status %d", response.StatusCode)
			}
			limit.remaining = -1
			if err = ctx.Err(); err != nil {
				raw.Close()
				return nil, err
			}
			return &bufferedConn{Conn: raw, reader: reader}, nil
		}
	}
	return s, nil
}

func newSession(ctx, instanceContext context.Context, plan *Plan) *Session {
	queryCtx, cancel := context.WithCancel(ctx)
	s := &Session{ctx: queryCtx, cancel: cancel, plan: plan, conns: make(map[*ownedConn]struct{}), cache: make(map[string][]netip.Addr)}
	s.transport = &http.Transport{Proxy: nil, DialContext: s.dialHTTP, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: adapter.RootPoolFromContext(instanceContext), Time: ntp.TimeFuncFromContext(instanceContext)},
		MaxResponseHeaderBytes: 8192, DisableCompression: true}
	s.client = &http.Client{Transport: s.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	s.stopInstance = context.AfterFunc(instanceContext, cancel)
	context.AfterFunc(queryCtx, s.Close)
	return s
}

type handshakeReader struct {
	net.Conn
	remaining int
}

func (h *handshakeReader) Read(b []byte) (int, error) {
	if h.remaining == 0 {
		return 0, errors.New("proxy response headers too large")
	}
	if h.remaining > 0 && len(b) > h.remaining {
		b = b[:h.remaining]
	}
	n, e := h.Conn.Read(b)
	if h.remaining > 0 {
		h.remaining -= n
	}
	return n, e
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

type ownedConn struct {
	net.Conn
	owner *Session
	once  sync.Once
}

func (c *ownedConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.owner.access.Lock(); delete(c.owner.conns, c); c.owner.access.Unlock() })
	return err
}
func (s *Session) own(conn net.Conn) (net.Conn, error) {
	c := &ownedConn{Conn: conn, owner: s}
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed || s.ctx.Err() != nil {
		conn.Close()
		return nil, context.Canceled
	}
	s.conns[c] = struct{}{}
	return c, nil
}
func (s *Session) dialPinned(network string, target M.Socksaddr) (net.Conn, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	if target.IsDomain() {
		return nil, errors.New("unresolved destination cannot enter pinned proxy")
	}
	conn, err := s.proxyDial(s.ctx, network, target)
	if err != nil {
		return nil, err
	}
	if deadline, ok := s.ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	return s.own(conn)
}
func (s *Session) dialHTTP(_ context.Context, network, address string) (net.Conn, error) {
	// net/http may detach a dial context for connection pooling. Never use it as
	// the lifetime source: every socket follows the explicit whole-query context.
	if network != "tcp" {
		return nil, errors.New("unsupported scoped HTTP network")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portNum, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, err
	}
	addresses, err := s.lookup(host, 0)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range addresses {
		conn, err := s.dialPinned("tcp", M.SocksaddrFrom(ip, uint16(portNum)))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("scoped DNS returned no addresses")
	}
	return nil, last
}

func (s *Session) exchange(name string, qtype uint16, network string) (*dns.Msg, error) {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), qtype)
	wire, err := query.Pack()
	if err != nil {
		return nil, err
	}
	var responseWire []byte
	if network == "https" || network == "tls" {
		responseWire, err = s.encryptedDNS(wire)
		if err != nil {
			return nil, err
		}
	} else {
		conn, err := s.dialPinned(network, M.ParseSocksaddr(s.plan.dns.address))
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		if network == "tcp" {
			frame := make([]byte, 2+len(wire))
			binary.BigEndian.PutUint16(frame, uint16(len(wire)))
			copy(frame[2:], wire)
			if _, err = io.Copy(conn, strings.NewReader(string(frame))); err != nil {
				return nil, err
			}
			var prefix [2]byte
			if _, err = io.ReadFull(conn, prefix[:]); err != nil {
				return nil, err
			}
			n := int(binary.BigEndian.Uint16(prefix[:]))
			if n < 12 {
				return nil, errors.New("invalid DNS frame")
			}
			responseWire = make([]byte, n)
			if _, err = io.ReadFull(conn, responseWire); err != nil {
				return nil, err
			}
		} else {
			if _, err = conn.Write(wire); err != nil {
				return nil, err
			}
			buffer := make([]byte, 65535)
			n, e := conn.Read(buffer)
			if e != nil {
				return nil, e
			}
			responseWire = buffer[:n]
		}
	}
	answer := new(dns.Msg)
	if err = answer.Unpack(responseWire); err != nil {
		return nil, err
	}
	if !answer.Response || answer.Id != query.Id || answer.Opcode != dns.OpcodeQuery || len(answer.Question) != 1 ||
		!strings.EqualFold(answer.Question[0].Name, query.Question[0].Name) || answer.Question[0].Qtype != qtype || answer.Question[0].Qclass != dns.ClassINET {
		return nil, errors.New("DNS response identity mismatch")
	}
	if answer.Truncated {
		if network == "udp" {
			return s.exchange(name, qtype, "tcp")
		}
		return nil, errors.New("truncated TCP DNS response")
	}
	if answer.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("scoped DNS status %d", answer.Rcode)
	}
	return answer, nil
}
func (s *Session) lookup(name string, depth int) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(name); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if depth >= 8 {
		return nil, errors.New("DNS CNAME chain too deep")
	}
	name = strings.ToLower(dns.Fqdn(name))
	s.access.Lock()
	cached := append([]netip.Addr(nil), s.cache[name]...)
	s.access.Unlock()
	if len(cached) > 0 {
		return cached, nil
	}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		answer, err := s.exchange(name, qtype, s.plan.dns.typ)
		if err != nil {
			return nil, err
		}
		current := name
		for links := 0; links < 8; links++ {
			var addresses []netip.Addr
			next := ""
			for _, rr := range answer.Answer {
				if !strings.EqualFold(rr.Header().Name, current) {
					continue
				}
				switch rr := rr.(type) {
				case *dns.A:
					if qtype == dns.TypeA {
						if ip, ok := netip.AddrFromSlice(rr.A); ok {
							addresses = append(addresses, ip.Unmap())
						}
					}
				case *dns.AAAA:
					if qtype == dns.TypeAAAA {
						if ip, ok := netip.AddrFromSlice(rr.AAAA); ok {
							addresses = append(addresses, ip.Unmap())
						}
					}
				case *dns.CNAME:
					next = strings.ToLower(dns.Fqdn(rr.Target))
				}
			}
			if len(addresses) > 0 {
				s.access.Lock()
				s.cache[name] = append([]netip.Addr(nil), addresses...)
				s.access.Unlock()
				return addresses, nil
			}
			if next == "" {
				if current != name {
					return s.lookup(current, depth+1)
				}
				break
			}
			current = next
			if links == 7 {
				return nil, errors.New("DNS answer CNAME chain too deep")
			}
		}
	}
	return nil, errors.New("scoped DNS has no A/AAAA answer")
}
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		s.access.Lock()
		s.closed = true
		connections := make([]*ownedConn, 0, len(s.conns))
		for c := range s.conns {
			connections = append(connections, c)
		}
		proxyScope := s.proxyScope
		s.access.Unlock()
		for _, c := range connections {
			c.Close()
		}
		s.transport.CloseIdleConnections()
		if s.stopInstance != nil {
			s.stopInstance()
		}
		if proxyScope != nil {
			_ = proxyScope.Close()
		}
	})
}
