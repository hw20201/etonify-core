//go:build with_utls

package scopedhttp

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/endpointpin"
	boxlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	boxvless "github.com/sagernet/sing-box/protocol/vless"
	vless "github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const pinTestUUID = "00000000-0000-4000-8000-000000000001"

type pinTestRouter struct {
	adapter.DNSRouter
	calls atomic.Int32
}

func (r *pinTestRouter) Lookup(_ context.Context, domain string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.calls.Add(1)
	if domain != "node.example.invalid" {
		return nil, fmt.Errorf("unexpected runtime DNS name")
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

type pinTestHandler struct {
	seen    chan string
	errors  chan error
	certDER []byte
	certKey *rsa.PrivateKey
}

func (h *pinTestHandler) NewConnectionEx(_ context.Context, c net.Conn, _ M.Socksaddr, target M.Socksaddr, _ N.CloseHandlerFunc) {
	h.seen <- target.String()
	var err error
	if target.String() == "dns.cloudflare.com:443" {
		tlsConn := stdtls.Server(c, &stdtls.Config{Certificates: []stdtls.Certificate{{Certificate: [][]byte{h.certDER}, PrivateKey: h.certKey}}, MinVersion: stdtls.VersionTLS12})
		if err = tlsConn.Handshake(); err == nil {
			var req *http.Request
			req, err = http.ReadRequest(bufio.NewReader(tlsConn))
			if err == nil && (req.Method != "POST" || req.URL.Path != "/dns-query" || req.Header.Get("Content-Type") != "application/dns-message") {
				err = fmt.Errorf("wrong DoH request")
			}
			if err == nil {
				wire, e := io.ReadAll(req.Body)
				if e != nil {
					err = e
				} else {
					q := new(dns.Msg)
					err = q.Unpack(wire)
					if err == nil && (len(q.Question) != 1 || (q.Question[0].Name != "api.ipquery.io." && q.Question[0].Name != "ip-api.com." && q.Question[0].Name != "ipwho.is.") || q.Question[0].Qtype != dns.TypeA) {
						err = fmt.Errorf("unexpected DoH question: %v", q.Question)
					}
					if err == nil {
						answer := new(dns.Msg)
						answer.SetReply(q)
						rr, _ := dns.NewRR(q.Question[0].Name + " 30 IN A 203.0.113.7")
						answer.Answer = []dns.RR{rr}
						wire, err = answer.Pack()
						if err == nil {
							_, err = fmt.Fprintf(tlsConn, "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(wire))
							if err == nil {
								_, err = tlsConn.Write(wire)
							}
						}
					}
				}
			}
		}
	} else if target.String() == "192.0.2.53:53" {
		var prefix [2]byte
		_, err = io.ReadFull(c, prefix[:])
		if err != nil {
			h.errors <- err
			return
		}
		wire := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
		_, err = io.ReadFull(c, wire)
		if err != nil {
			h.errors <- err
			return
		}
		q := new(dns.Msg)
		if err = q.Unpack(wire); err != nil {
			h.errors <- err
			return
		}
		if q.Question[0].Name != "ip-api.com." {
			h.errors <- fmt.Errorf("unexpected tunnel DNS question: %s", q.Question[0].Name)
			return
		}
		answer := new(dns.Msg)
		answer.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR("ip-api.com. 30 IN A 203.0.113.7")
			answer.Answer = []dns.RR{rr}
		}
		wire, err = answer.Pack()
		if err == nil {
			binary.BigEndian.PutUint16(prefix[:], uint16(len(wire)))
			_, err = c.Write(append(prefix[:], wire...))
		}
	} else if target.String() == "203.0.113.7:443" {
		tlsConn := stdtls.Server(c, &stdtls.Config{Certificates: []stdtls.Certificate{{Certificate: [][]byte{h.certDER}, PrivateKey: h.certKey}}})
		if err = tlsConn.Handshake(); err == nil {
			var req *http.Request
			req, err = http.ReadRequest(bufio.NewReader(tlsConn))
			if err == nil {
				var body string
				if req.Host == "api.ipquery.io" && req.URL.Path == "/" {
					body = "203.0.113.7\n"
				} else if req.Host == "api.ipquery.io" && req.URL.Path == "/203.0.113.7" {
					body = `{"ip":"203.0.113.7","location":{"city":"Test"}}`
				} else if req.Host == "ipwho.is" {
					body = `{"ip":"203.0.113.7","success":true}`
				} else {
					err = fmt.Errorf("unexpected TLS provider request %s%s", req.Host, req.URL)
				}
				if err == nil {
					_, err = fmt.Fprintf(tlsConn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
				}
			}
		}
	} else if target.String() == "203.0.113.7:80" {
		var req *http.Request
		req, err = http.ReadRequest(bufio.NewReader(c))
		if err == nil && req.Host != "ip-api.com" {
			err = fmt.Errorf("wrong provider HTTP host")
		}
		if err == nil {
			body := `{"status":"success","query":"203.0.113.7","country":"Test"}`
			_, err = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		}
	} else if target.String() == "203.0.113.99:80" {
		_, err = io.Copy(c, c) // A normal authenticated VPN tunnel, separate from queries.
	} else {
		err = fmt.Errorf("unexpected VLESS destination: %s", target.String())
	}
	if err != nil {
		h.errors <- err
	}
}
func (h *pinTestHandler) NewPacketConnectionEx(_ context.Context, c N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	c.Close()
	h.errors <- fmt.Errorf("unexpected UDP")
}

type pinRealityFixture struct {
	snapshot   []byte
	store      *endpointpin.Store
	instance   context.Context
	router     *pinTestRouter
	handler    *pinTestHandler
	generation *atomic.Uint64
	options    option.VLESSOutboundOptions
}

func newPinRealityFixture(t *testing.T, flow string, doh ...bool) *pinRealityFixture {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com", "dns.cloudflare.com", "api.ipquery.io", "ipwho.is"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &certKey.PublicKey, certKey)
	if err != nil {
		t.Fatal(err)
	}
	decoy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { decoy.Close() })
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			c, e := decoy.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(4 * time.Second))
				_ = stdtls.Server(c, &stdtls.Config{Certificates: []stdtls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: certKey}}, MinVersion: stdtls.VersionTLS13, MaxVersion: stdtls.VersionTLS13}).Handshake()
			}()
		}
	}()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	realityConfig := &utls.RealityConfig{Config: utls.Config{SessionTicketsDisabled: true}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", decoy.Addr().String())
	}, ServerNames: map[string]bool{"example.com": true}, PrivateKey: key.Bytes(), ShortIds: map[[8]byte]bool{{1, 2, 3, 4, 5, 6, 7, 8}: true}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	handler := &pinTestHandler{seen: make(chan string, 64), errors: make(chan error, 64), certDER: certDER, certKey: certKey}
	svc := vless.NewService[int](boxlog.NewNOPFactory().Logger(), handler)
	svc.UpdateUsers([]int{0}, []string{pinTestUUID}, []string{flow})
	serverCtx := ctx
	go func() {
		defer wg.Done()
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				tlsConn, e := utls.RealityServer(serverCtx, c, realityConfig)
				if e != nil {
					return
				}
				_ = svc.NewConnection(serverCtx, tlsConn, M.Socksaddr{}, nil)
			}()
		}
	}()
	// Close listeners before waiting for active handlers. Their explicit deadlines
	// also bound cleanup if a failed test never reached Session.Close.
	t.Cleanup(func() { listener.Close(); decoy.Close(); stop(); wg.Wait() })
	dnsConfig := `"type":"tcp","tag":"dns","server":"192.0.2.53","server_port":53,"detour":"select"`
	if len(doh) > 0 && doh[0] {
		dnsConfig = `"type":"https","tag":"dns","server":"dns.cloudflare.com","server_port":443,"path":"/dns-query","detour":"select","domain_resolver":"dns-local"`
	}
	snapshot := []byte(fmt.Sprintf(`{"outbounds":[{"type":"selector","tag":"select","outbounds":["reality"]},{"type":"vless","tag":"reality","server":"node.example.invalid","server_port":%d,"uuid":%q,"flow":%q,"tls":{"enabled":true,"server_name":"example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":%q,"short_id":"0102030405060708"}},"tcp_fast_open":false,"tcp_multi_path":false}],"dns":{"final":"dns","servers":[{%s}]},"route":{"default_domain_resolver":"dns-local"}}`, listener.Addr().(*net.TCPAddr).Port, pinTestUUID, flow, base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), dnsConfig))
	var parsed struct{ Outbounds []json.RawMessage }
	if err = json.Unmarshal(snapshot, &parsed); err != nil {
		t.Fatal(err)
	}
	var opts option.VLESSOutboundOptions
	if err = json.Unmarshal(parsed.Outbounds[1], &opts); err != nil {
		t.Fatal(err)
	}
	generation := new(atomic.Uint64)
	generation.Store(7)
	store, err := endpointpin.New(snapshot, "test-core", generation.Load)
	if err != nil {
		t.Fatal(err)
	}
	router := new(pinTestRouter)
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, &endpointDependencyManager{items: map[string]adapter.DNSTransport{"dns-local": &endpointDependencyTransport{tag: "dns-local"}}})
	ctx = service.ContextWith[adapter.DNSRouter](ctx, router)
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &endpointDependencyNetwork{resolver: "dns-local"})
	ctx = service.ContextWithPtr(ctx, store)
	return &pinRealityFixture{snapshot: snapshot, store: store, instance: ctx, router: router, handler: handler, generation: generation, options: opts}
}

func (f *pinRealityFixture) warm(t *testing.T) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.instance, 3*time.Second)
	t.Cleanup(cancel)
	out, err := boxvless.NewOutbound(f.instance, nil, boxlog.NewNOPFactory().Logger(), "reality", f.options)
	if err != nil {
		t.Fatal(err)
	}
	c, err := out.DialContext(ctx, "tcp", M.ParseSocksaddr("203.0.113.99:80"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err = io.WriteString(c, "ping"); err != nil {
		t.Fatal(err)
	}
	var b [4]byte
	if _, err = io.ReadFull(c, b[:]); err != nil || string(b[:]) != "ping" {
		t.Fatalf("normal Reality tunnel: %q %v", b, err)
	}
	return c
}

func TestDomainRealityAuthenticatedPinProviderRoundTrip(t *testing.T) {
	for _, flow := range []string{"", "xtls-rprx-vision"} {
		t.Run("flow="+flow, func(t *testing.T) {
			f := newPinRealityFixture(t, flow)
			if _, ok := f.store.Load("reality", 7); ok {
				t.Fatal("cold store unexpectedly pinned")
			}
			if p, e := NewPlan(f.snapshot, []string{"select", "reality"}); p != nil || e == nil {
				t.Fatal("cold graph accepted")
			}
			normal := f.warm(t)
			pin, ok := f.store.Load("reality", 7)
			if !ok {
				t.Fatal("successful real Reality authentication did not publish pin")
			}
			plan, err := NewPlanWithEndpointPin(f.snapshot, []string{"select", "reality"}, pin, "test-core", 7)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			s, err := NewSession(ctx, f.instance, plan)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			body, err := s.Lookup("ipApi")
			if err != nil {
				t.Fatal(err)
			}
			var result map[string]any
			if json.Unmarshal(body, &result) != nil || result["query"] != "203.0.113.7" {
				t.Fatalf("wrong result: %s", body)
			}
			s.Close()
			if f.router.calls.Load() != 1 {
				t.Fatalf("query re-entered runtime endpoint DNS: %d", f.router.calls.Load())
			}
			// Query teardown must not cancel or close the pre-existing normal VPN socket.
			if _, err = io.WriteString(normal, "stay"); err != nil {
				t.Fatal(err)
			}
			var echoed [4]byte
			if _, err = io.ReadFull(normal, echoed[:]); err != nil || string(echoed[:]) != "stay" {
				t.Fatalf("query damaged normal VPN: %q %v", echoed, err)
			}
			if service.PtrFromContext[endpointpin.Store](f.instance) != f.store {
				t.Fatal("private registry erased normal producer")
			}
			for _, target := range []string{"203.0.113.99:80", "192.0.2.53:53", "203.0.113.7:80"} {
				select {
				case got := <-f.handler.seen:
					if got != target {
						t.Fatalf("dest=%s want=%s", got, target)
					}
				case <-time.After(time.Second):
					t.Fatal("missing VLESS destination")
				}
			}
			select {
			case err := <-f.handler.errors:
				t.Fatal(err)
			default:
			}
		})
	}
}

func TestVisionDoHAuthenticatedPinAllProviders(t *testing.T) {
	f := newPinRealityFixture(t, "xtls-rprx-vision", true)
	if _, ok := f.store.Load("reality", 7); ok {
		t.Fatal("cold store unexpectedly pinned")
	}
	normal := f.warm(t)
	pin, ok := f.store.Load("reality", 7)
	if !ok {
		t.Fatal("successful real Reality authentication did not publish pin")
	}
	plan, err := NewPlanWithEndpointPin(f.snapshot, []string{"select", "reality"}, pin, "test-core", 7)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := NewSession(ctx, f.instance, plan)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	cert, err := x509.ParseCertificate(f.handler.certDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(cert)
	s.transport.TLSClientConfig.RootCAs = roots
	defer s.Close()
	for _, provider := range []string{"ipApi", "ipQuery", "ipWho"} {
		body, lookupErr := s.Lookup(provider)
		if lookupErr != nil {
			t.Fatalf("%s: %v", provider, lookupErr)
		}
		var result map[string]any
		if json.Unmarshal(body, &result) != nil {
			t.Fatalf("%s invalid result: %s", provider, body)
		}
		ip := result["ip"]
		if provider == "ipApi" {
			ip = result["query"]
		}
		if ip != "203.0.113.7" {
			t.Fatalf("%s wrong result: %s", provider, body)
		}
	}
	if f.router.calls.Load() != 1 {
		t.Fatalf("query re-entered runtime DNS; calls=%d want=1", f.router.calls.Load())
	}
	if _, err = io.WriteString(normal, "stay"); err != nil {
		t.Fatal(err)
	}
	var echoed [4]byte
	if _, err = io.ReadFull(normal, echoed[:]); err != nil || string(echoed[:]) != "stay" {
		t.Fatalf("query damaged normal VPN: %q %v", echoed, err)
	}
	if service.PtrFromContext[endpointpin.Store](f.instance) != f.store {
		t.Fatal("private registry erased normal producer")
	}
	want := map[string]int{"203.0.113.99:80": 1, "dns.cloudflare.com:443": 3, "203.0.113.7:80": 1, "203.0.113.7:443": 3}
	gotCounts := make(map[string]int)
	for i := 0; i < 8; i++ {
		select {
		case target := <-f.handler.seen:
			gotCounts[target]++
		case <-time.After(time.Second):
			t.Fatal("missing VLESS destination")
		}
	}
	for target, count := range want {
		if gotCounts[target] != count {
			t.Fatalf("destination %s count=%d want=%d; all=%v", target, gotCounts[target], count, gotCounts)
		}
	}

	select {
	case got := <-f.handler.seen:
		t.Fatalf("unexpected additional VLESS destination: %s", got)
	default:
	}
	select {
	case e := <-f.handler.errors:
		t.Fatal(e)
	default:
	}
}
