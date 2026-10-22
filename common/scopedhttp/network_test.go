package scopedhttp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
)

// A deterministic proxy mock: every socket is a net.Pipe and the peer sees only
// the numeric destination passed by the scoped session.
func testSession(t *testing.T, dnsHandler func(*dns.Msg) *dns.Msg) (*Session, <-chan string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	p, err := NewPlan([]byte(validSnapshot), []string{"leaf"})
	if err != nil {
		t.Fatal(err)
	}
	s := newSession(ctx, context.Background(), p)
	seen := make(chan string, 32)
	var wg sync.WaitGroup
	s.proxyDial = func(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
		if network != "tcp" {
			return nil, context.DeadlineExceeded
		}
		if target.IsDomain() {
			t.Errorf("proxy received domain target: %s", target)
			return nil, context.Canceled
		}
		seen <- target.String()
		client, peer := net.Pipe()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer peer.Close()
			if target.Port == 53 {
				var hdr [2]byte
				if _, e := io.ReadFull(peer, hdr[:]); e != nil {
					return
				}
				qwire := make([]byte, int(binary.BigEndian.Uint16(hdr[:])))
				if _, e := io.ReadFull(peer, qwire); e != nil {
					return
				}
				q := new(dns.Msg)
				if q.Unpack(qwire) != nil {
					return
				}
				r := dnsHandler(q)
				r.Id = q.Id
				r.Question = q.Question
				r.Response = true
				wire, e := r.Pack()
				if e != nil {
					return
				}
				binary.BigEndian.PutUint16(hdr[:], uint16(len(wire)))
				if _, e = peer.Write(hdr[:]); e == nil {
					_, _ = peer.Write(wire)
				}
				return
			}
			// Tests which exercise HTTP can install their own mock; fail promptly here.
			peer.SetDeadline(time.Now().Add(150 * time.Millisecond))
		}()
		return client, nil
	}
	t.Cleanup(func() { s.Close(); wg.Wait() })
	return s, seen
}

func TestNetworkLookupAAndAAAAUsesPinnedProxy(t *testing.T) {
	s, seen := testSession(t, func(q *dns.Msg) *dns.Msg {
		r := new(dns.Msg)
		r.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(q.Question[0].Name + " 30 IN A 203.0.113.7")
			r.Answer = []dns.RR{rr}
		}
		return r
	})
	got, err := s.lookup("service.invalid", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("lookup = %v", got)
	}
	select {
	case target := <-seen:
		if target != "192.0.2.53:53" {
			t.Fatalf("unexpected DNS proxy target %s", target)
		}
	case <-time.After(time.Second):
		t.Fatal("missing DNS proxy exchange")
	}
}

func TestNetworkLiteralLookupNeverCallsProxyOrResolver(t *testing.T) {
	s, seen := testSession(t, func(q *dns.Msg) *dns.Msg { return new(dns.Msg) })
	got, err := s.lookup("192.0.2.44", 0)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.44") {
		t.Fatalf("got=%v err=%v", got, err)
	}
	select {
	case target := <-seen:
		t.Fatalf("unexpected proxy dial %s", target)
	default:
	}
}

func TestProviderURLWhitelistIsExact(t *testing.T) {
	good := []string{ipAPIURL, "https://ipwho.is/", "https://api.ipquery.io/", "https://api.ipquery.io/203.0.113.1?format=json"}
	for _, u := range good {
		if !providerURLAllowed(u) {
			t.Errorf("rejected approved URL %q", u)
		}
	}
	bad := []string{
		"https://api.ipquery.io.evil/203.0.113.1?format=json", "https://api.ipquery.io:443/203.0.113.1?format=json",
		"https://user@api.ipquery.io/203.0.113.1?format=json", "https://api.ipquery.io/203.0.113.1/extra?format=json",
		"https://api.ipquery.io/203.0.113.1?format=json&x=1", "https://api.ipquery.io/203.0.113.1#x",
		"http://api.ipquery.io/", "http://ip-api.com/json/?fields=status,message,query,country,countryCode,regionName,city,isp,org,as&x=1",
	}
	for _, u := range bad {
		if providerURLAllowed(u) {
			t.Errorf("accepted forged URL %q", u)
		}
	}
}
