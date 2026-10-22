package endpointpin

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const snapshot = `{"outbounds":[{"type":"vless","tag":"edge-tag","server":"edge.example","server_port":443,"tls":{"enabled":true,"reality":{"enabled":true}}},{"type":"vless","tag":"edge-backup","server":"edge.example","server_port":8443,"tls":{"enabled":true,"reality":{"enabled":true}}},{"type":"vless","tag":"disabled-reality","server":"disabled.example","server_port":443,"tls":{"enabled":true,"reality":{"enabled":false}}}]}`

func newTestStore(t *testing.T, raw string, generation func() uint64) *Store {
	t.Helper()
	s, err := New([]byte(raw), "core-a", generation)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func tcp(ip string, port int) *net.TCPAddr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: port} }

func TestObserveUsesTagAndSupportsIPv4IPv6(t *testing.T) {
	var gen atomic.Uint64
	gen.Store(7)
	s := newTestStore(t, snapshot, gen.Load)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	cases := []struct {
		tag, server, ip string
		port            uint16
	}{
		{"edge-tag", "edge.example", "203.0.113.8", 443},
		{"edge-backup", "edge.example", "2001:db8::8", 8443},
	}
	for _, tc := range cases {
		if !s.Observe(tc.tag, tc.server, tc.port, tcp(tc.ip, int(tc.port)), 7) {
			t.Fatalf("valid observation rejected for tag %q", tc.tag)
		}
		p, ok := s.Load(tc.tag, 7)
		want := netip.MustParseAddr(tc.ip)
		if !ok || p.Addr != want || p.Leaf != tc.tag || p.Server != tc.server {
			t.Fatalf("Load(%q) = %#v, %v; want %s", tc.tag, p, ok, want)
		}
		if !p.Valid([]byte(snapshot), []string{"intermediate.example", tc.tag}, "core-a", 7, now) {
			t.Fatalf("valid pin rejected for tag %q", tc.tag)
		}
	}
	if _, ok := s.Load("edge.example", 7); ok {
		t.Fatal("hostname was incorrectly used as pin key")
	}
}

func TestObserveRejectsInvalidObservationsAndDisabledReality(t *testing.T) {
	var gen atomic.Uint64
	gen.Store(1)
	s := newTestStore(t, snapshot, gen.Load)
	cases := []struct {
		name, tag, server string
		port              uint16
		peer              net.Addr
		generation        uint64
	}{
		{"wrong tag", "edge.example", "edge.example", 443, tcp("192.0.2.1", 443), 1},
		{"unknown tag", "unknown", "edge.example", 443, tcp("192.0.2.1", 443), 1},
		{"wrong server", "edge-tag", "other.example", 443, tcp("192.0.2.1", 443), 1},
		{"wrong configured port", "edge-tag", "edge.example", 8443, tcp("192.0.2.1", 8443), 1},
		{"wrong peer port", "edge-tag", "edge.example", 443, tcp("192.0.2.1", 444), 1},
		{"nil peer", "edge-tag", "edge.example", 443, nil, 1},
		{"non tcp peer", "edge-tag", "edge.example", 443, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, 1},
		{"invalid address", "edge-tag", "edge.example", 443, &net.TCPAddr{Port: 443}, 1},
		{"bad zone", "edge-tag", "edge.example", 443, &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443, Zone: "eth0"}, 1},
		{"unspecified v4", "edge-tag", "edge.example", 443, tcp("0.0.0.0", 443), 1},
		{"unspecified v6", "edge-tag", "edge.example", 443, tcp("::", 443), 1},
		{"multicast v4", "edge-tag", "edge.example", 443, tcp("224.0.0.1", 443), 1},
		{"multicast v6", "edge-tag", "edge.example", 443, tcp("ff02::1", 443), 1},
		{"stale generation", "edge-tag", "edge.example", 443, tcp("192.0.2.1", 443), 2},
		{"disabled reality", "disabled-reality", "disabled.example", 443, tcp("192.0.2.1", 443), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if s.Observe(tc.tag, tc.server, tc.port, tc.peer, tc.generation) {
				t.Fatal("invalid observation accepted")
			}
		})
	}
}

func TestSameHostnameDifferentTagsAreNotInterchangeable(t *testing.T) {
	var gen atomic.Uint64
	gen.Store(3)
	s := newTestStore(t, snapshot, gen.Load)
	if !s.Observe("edge-tag", "edge.example", 443, tcp("192.0.2.1", 443), 3) {
		t.Fatal("observe failed")
	}
	if _, ok := s.Load("edge-backup", 3); ok {
		t.Fatal("pin for one tag was bound to another tag with same hostname")
	}
}

func TestSnapshotRequirementsAndDuplicateTags(t *testing.T) {
	var gen atomic.Uint64
	gen.Store(1)
	for name, raw := range map[string]string{
		"transport":  `{"outbounds":[{"type":"vless","tag":"x","server":"x.example","server_port":443,"transport":{"type":"tcp"},"tls":{"enabled":true,"reality":{"enabled":true}}}]}`,
		"mux":        `{"outbounds":[{"type":"vless","tag":"x","server":"x.example","server_port":443,"multiplex":{"enabled":true},"tls":{"enabled":true,"reality":{"enabled":true}}}]}`,
		"detour":     `{"outbounds":[{"type":"vless","tag":"x","server":"x.example","server_port":443,"detour":"proxy","tls":{"enabled":true,"reality":{"enabled":true}}}]}`,
		"encryption": `{"outbounds":[{"type":"vless","tag":"x","server":"x.example","server_port":443,"encryption":"none","tls":{"enabled":true,"reality":{"enabled":true}}}]}`,
		"domain":     `{"outbounds":[{"type":"vless","tag":"x","server":"bad..example","server_port":443,"tls":{"enabled":true,"reality":{"enabled":true}}}]}`,
		"ip literal": `{"outbounds":[{"type":"vless","tag":"x","server":"192.0.2.1","server_port":443,"tls":{"enabled":true,"reality":{"enabled":true}}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestStore(t, raw, gen.Load)
			if s.Observe("x", "x.example", 443, tcp("192.0.2.1", 443), 1) {
				t.Fatal("ineligible outbound accepted")
			}
		})
	}
	duplicate := `{"outbounds":[{"type":"vless","tag":"x","server":"a.example","server_port":443},{"type":"vless","tag":"x","server":"b.example","server_port":443}]}`
	if _, err := New([]byte(duplicate), "core-a", gen.Load); err == nil {
		t.Fatal("duplicate tags accepted")
	}
}

func TestPinValidIntegrityAndContext(t *testing.T) {
	var gen atomic.Uint64
	gen.Store(5)
	s := newTestStore(t, snapshot, gen.Load)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if !s.Observe("edge-tag", "edge.example", 443, tcp("192.0.2.1", 443), 5) {
		t.Fatal("observe failed")
	}
	p, ok := s.Load("edge-tag", 5)
	if !ok {
		t.Fatal("load failed")
	}
	if !p.Valid([]byte(snapshot), []string{"root", "edge-tag"}, "core-a", 5, now) {
		t.Fatal("valid pin rejected")
	}
	mutations := []struct {
		name string
		edit func(*Pin)
	}{
		{"address", func(p *Pin) { p.Addr = netip.MustParseAddr("192.0.2.2") }},
		{"server", func(p *Pin) { p.Server = "other.example" }},
		{"port", func(p *Pin) { p.Port++ }},
		{"leaf", func(p *Pin) { p.Leaf = "other" }},
		{"expiry", func(p *Pin) { p.Expires = p.Expires.Add(time.Second) }},
		{"config id", func(p *Pin) { p.ConfigID = "changed" }},
		{"core id", func(p *Pin) { p.CoreID = "changed" }},
		{"network generation", func(p *Pin) { p.NetworkGeneration++ }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			changed := p
			tc.edit(&changed)
			if changed.Valid([]byte(snapshot), []string{"root", "edge-tag"}, "core-a", 5, now) {
				t.Fatal("tampered copy validated")
			}
		})
	}
	for name, args := range map[string]struct {
		snapshot   []byte
		chain      []string
		core       string
		generation uint64
		now        time.Time
	}{
		"different snapshot":   {[]byte(snapshot + " "), []string{"edge-tag"}, "core-a", 5, now},
		"different core":       {[]byte(snapshot), []string{"edge-tag"}, "core-b", 5, now},
		"different generation": {[]byte(snapshot), []string{"edge-tag"}, "core-a", 6, now},
		"chain leaf mismatch":  {[]byte(snapshot), []string{"edge.example"}, "core-a", 5, now},
		"expired":              {[]byte(snapshot), []string{"edge-tag"}, "core-a", 5, now.Add(TTL)},
	} {
		t.Run(name, func(t *testing.T) {
			if p.Valid(args.snapshot, args.chain, args.core, args.generation, args.now) {
				t.Fatal("mismatched context validated")
			}
		})
	}
	gen.Store(6)
	if _, ok := s.Load("edge-tag", 5); ok {
		t.Fatal("stale generation loaded")
	}
}

func TestObserveRejectsGenerationChangeDuringCapture(t *testing.T) {
	var gen atomic.Uint64
	gen.Store(9)
	var calls atomic.Int32
	generation := func() uint64 {
		if calls.Add(1) == 2 {
			gen.Store(10)
		}
		return gen.Load()
	}
	s := newTestStore(t, snapshot, generation)
	if s.Observe("edge-tag", "edge.example", 443, tcp("192.0.2.1", 443), 9) {
		t.Fatal("accepted observation across network generation change")
	}
}

func TestConcurrentObserveLoadAndNetworkAdvance(t *testing.T) {
	var gen atomic.Uint64
	gen.Store(1)
	s := newTestStore(t, snapshot, gen.Load)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				g := gen.Load()
				s.Observe("edge-tag", "edge.example", 443, tcp("192.0.2.1", 443), g)
				s.Load("edge-tag", g)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			gen.Add(1)
		}
	}()
	wg.Wait()
}
