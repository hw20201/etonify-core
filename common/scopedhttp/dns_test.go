package scopedhttp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
)

func TestDNSAAAACNAMEUseSameScopedServer(t *testing.T) {
	for _, mode := range []string{"AAAA", "CNAME"} {
		t.Run(mode, func(t *testing.T) {
			s, seen := testSession(t, func(q *dns.Msg) *dns.Msg {
				r := new(dns.Msg)
				r.SetReply(q)
				var rr dns.RR
				if mode == "AAAA" && q.Question[0].Qtype == dns.TypeAAAA {
					rr, _ = dns.NewRR(q.Question[0].Name + " 30 IN AAAA 2001:db8::1")
				}
				if mode == "CNAME" {
					if q.Question[0].Name == "service.invalid." {
						rr, _ = dns.NewRR("service.invalid. 30 IN CNAME target.invalid.")
					} else {
						rr, _ = dns.NewRR("target.invalid. 30 IN A 203.0.113.3")
					}
				}
				if rr != nil {
					r.Answer = []dns.RR{rr}
				}
				return r
			})
			addresses, err := s.lookup("service.invalid", 0)
			if err != nil {
				t.Fatal(err)
			}
			expected := "203.0.113.3"
			if mode == "AAAA" {
				expected = "2001:db8::1"
			}
			if len(addresses) != 1 || addresses[0] != netip.MustParseAddr(expected) {
				t.Fatalf("wrong DNS answer: %v", addresses)
			}
			for i := 0; i < 2; i++ {
				select {
				case address := <-seen:
					if address != "192.0.2.53:53" {
						t.Fatal("DNS escaped pinned server")
					}
				case <-time.After(time.Second):
					t.Fatal("expected second scoped DNS exchange")
				}
			}
		})
	}
}
func TestDNSUDPTruncationTCPFallbackUsesSameProxy(t *testing.T) {
	snapshot := strings.Replace(strings.Replace(validSnapshot, `"type":"http"`, `"type":"socks"`, 1), `"type":"tcp"`, `"type":"udp"`, 1)
	plan, err := NewPlan([]byte(snapshot), []string{"leaf"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := newSession(ctx, context.Background(), plan)
	defer s.Close()
	seen := make(chan string, 4)
	s.proxyDial = func(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
		seen <- network + " " + target.String()
		client, peer := net.Pipe()
		go func() {
			defer peer.Close()
			var wire []byte
			var hdr [2]byte
			if network == "tcp" {
				if _, err := io.ReadFull(peer, hdr[:]); err != nil {
					return
				}
				wire = make([]byte, binary.BigEndian.Uint16(hdr[:]))
				if _, err := io.ReadFull(peer, wire); err != nil {
					return
				}
			} else {
				buffer := make([]byte, 65535)
				n, err := peer.Read(buffer)
				if err != nil {
					return
				}
				wire = buffer[:n]
			}
			q := new(dns.Msg)
			if q.Unpack(wire) != nil {
				return
			}
			r := new(dns.Msg)
			r.SetReply(q)
			if network == "udp" {
				r.Truncated = true
			} else {
				rr, _ := dns.NewRR(q.Question[0].Name + " 30 IN A 203.0.113.11")
				r.Answer = []dns.RR{rr}
			}
			out, _ := r.Pack()
			if network == "tcp" {
				binary.BigEndian.PutUint16(hdr[:], uint16(len(out)))
				peer.Write(hdr[:])
			}
			peer.Write(out)
		}()
		return client, nil
	}
	addresses, err := s.lookup("provider.invalid", 0)
	if err != nil || len(addresses) != 1 {
		t.Fatalf("addresses=%v err=%v", addresses, err)
	}
	if first, second := <-seen, <-seen; first != "udp 192.0.2.53:53" || second != "tcp 192.0.2.53:53" {
		t.Fatalf("DNS fallback changed route %s %s", first, second)
	}
}
func TestPlanRejectsUnauditedDependencies(t *testing.T) {
	for _, test := range []struct{ name, old, replacement string }{
		{"detour", `"server_port":8080`, `"server_port":8080,"detour":"other"`},
		{"proxy-DNS", `"192.0.2.10"`, `"proxy.example"`},
		{"mux", `"server_port":8080`, `"server_port":8080,"multiplex":{"enabled":true}`},
		{"DNS-other-outbound", `"detour":"leaf"`, `"detour":"other"`},
		{"DNS-shared-type", `"type":"tcp"`, `"type":"local"`},
		{"DNS-rules", `"final":"d"`, `"final":"d","rules":[{"domain":"x","server":"other"}]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewPlan([]byte(strings.Replace(validSnapshot, test.old, test.replacement, 1)), []string{"leaf"}); err == nil {
				t.Fatal("unaudited dependency accepted")
			}
		})
	}
	grouped := strings.Replace(validSnapshot, `"outbounds":[`, `"outbounds":[{"type":"selector","tag":"group","outbounds":["leaf"]},`, 1)
	if _, err := NewPlan([]byte(grouped), []string{"group", "leaf"}); err != nil {
		t.Fatal(err)
	}
	for _, chain := range [][]string{{"group"}, {"leaf", "group"}, {"group", "unknown"}} {
		if _, err := NewPlan([]byte(grouped), chain); err == nil {
			t.Fatalf("invalid group chain accepted %v", chain)
		}
	}
}
