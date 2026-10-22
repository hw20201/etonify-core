package scopedhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
)

func dnsReply(wire []byte) []byte {
	q := new(dns.Msg)
	if q.Unpack(wire) != nil {
		return nil
	}
	r := new(dns.Msg)
	r.SetReply(q)
	rr, _ := dns.NewRR(q.Question[0].Name + " 30 IN A 203.0.113.42")
	r.Answer = []dns.RR{rr}
	out, _ := r.Pack()
	return out
}

func dohSession(t *testing.T, ctx context.Context, server *httptest.Server, hostname bool) (*Session, *atomic.Int32) {
	t.Helper()
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	bootstrap := ""
	if hostname {
		host = "example.com"
		bootstrap = `,"domain_resolver":"dns-local"`
	}
	config := fmt.Sprintf(`{"outbounds":[{"type":"http","tag":"leaf","server":"192.0.2.10","server_port":8080,"tcp_multi_path":false,"tcp_fast_open":false}],"dns":{"final":"d","servers":[{"tag":"d","type":"https","server":%q,"server_port":%s,"path":"/dns-query","detour":"leaf"%s}]}}`, host, port, bootstrap)
	plan, err := NewPlan([]byte(config), []string{"leaf"})
	if err != nil {
		t.Fatal(err)
	}
	s := newSession(ctx, context.Background(), plan)
	t.Cleanup(s.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	s.transport.TLSClientConfig.RootCAs = pool
	calls := &atomic.Int32{}
	s.proxyDial = func(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
		calls.Add(1)
		if network != "tcp" || target.String() != net.JoinHostPort(host, port) {
			return nil, fmt.Errorf("DNS escaped configured proxy endpoint: %s %s", network, target)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	return s, calls
}

func TestAppDefaultDoHUsesPrivatePinnedBootstrap(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
			t.Error("wrong DoH request")
		}
		wire, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(dnsReply(wire))
	}))
	defer server.Close()
	for _, hostname := range []bool{false, true} {
		t.Run(fmt.Sprint(hostname), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			s, calls := dohSession(t, ctx, server, hostname)
			addresses, err := s.lookup("api.ipquery.io", 0)
			if err != nil || len(addresses) != 1 || addresses[0].String() != "203.0.113.42" {
				t.Fatalf("addresses=%v err=%v", addresses, err)
			}
			if calls.Load() != 1 {
				t.Fatal("unexpected bootstrap/provider dial count")
			}
		})
	}
}

func TestDoHRejectsRedirectAndSharesWholeDeadline(t *testing.T) {
	for _, mode := range []string{"redirect", "slow", "wrong-type", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					w.Header().Set("Location", "https://other.invalid/")
					w.WriteHeader(302)
				case "slow":
					time.Sleep(150 * time.Millisecond)
				case "wrong-type":
					w.Write([]byte("not DNS"))
				case "oversized":
					w.Header().Set("Content-Type", "application/dns-message")
					w.Write(make([]byte, 65536))
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
			defer cancel()
			s, calls := dohSession(t, ctx, server, false)
			start := time.Now()
			if _, err := s.lookup("api.ipquery.io", 0); err == nil {
				t.Fatal("invalid DoH succeeded")
			}
			if time.Since(start) > time.Second {
				t.Fatal("whole-query deadline not respected")
			}
			if calls.Load() != 1 {
				t.Fatal("redirect or fallback opened another connection")
			}
		})
	}
}

func TestDoTUsesPrivateTLSAndNumericProviderDNS(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer certificateServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", certificateServer.TLS.Clone())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		var hdr [2]byte
		if _, err = io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		wire := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err = io.ReadFull(c, wire); err != nil {
			return
		}
		response := dnsReply(wire)
		binary.BigEndian.PutUint16(hdr[:], uint16(len(response)))
		c.Write(hdr[:])
		c.Write(response)
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	snapshot := strings.Replace(validSnapshot, `"type":"tcp","tag":"d","server":"192.0.2.53"`, `"type":"tls","tag":"d","server":"127.0.0.1","server_port":`+port, 1)
	// Build explicitly rather than rely on fixture field ordering.
	snapshot = fmt.Sprintf(`{"outbounds":[{"type":"http","tag":"leaf","server":"192.0.2.10","server_port":8080}],"dns":{"final":"d","servers":[{"tag":"d","type":"tls","server":"127.0.0.1","server_port":%s,"detour":"leaf"}]}}`, port)
	p, err := NewPlan([]byte(snapshot), []string{"leaf"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := newSession(ctx, context.Background(), p)
	defer s.Close()
	pool := x509.NewCertPool()
	pool.AddCert(certificateServer.Certificate())
	s.transport.TLSClientConfig.RootCAs = pool
	s.proxyDial = func(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
		if target.String() != listener.Addr().String() {
			return nil, fmt.Errorf("unexpected destination: %v", target)
		}
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}
	addresses, err := s.lookup("api.ipquery.io", 0)
	if err != nil || len(addresses) != 1 {
		t.Fatalf("%v %v", addresses, err)
	}
	<-done
}

func TestEncryptedDNSRejectsUnsafeOptions(t *testing.T) {
	base := `{"outbounds":[{"type":"http","tag":"leaf","server":"192.0.2.10","server_port":8080}],"dns":{"final":"d","servers":[{"tag":"d","type":"https","server":"example.com","domain_resolver":"dns-local","detour":"leaf"EXTRA}]}}`
	for _, extra := range []string{`,"tls":{"insecure":true}`, `,"tls":{"enabled":false}`, `,"path":"//evil.invalid/"`, `,"path":"https://evil.invalid/"`, `,"headers":{"Host":"evil.invalid"}`} {
		if _, err := NewPlan([]byte(strings.Replace(base, "EXTRA", extra, 1)), []string{"leaf"}); err == nil {
			t.Fatalf("unsafe option accepted: %s", extra)
		}
	}
	if _, err := NewPlan([]byte(strings.Replace(strings.Replace(base, "EXTRA", "", 1), `"dns-local"`, `"another-resolver"`, 1)), []string{"leaf"}); err == nil {
		t.Fatal("arbitrary bootstrap graph accepted")
	}
}
