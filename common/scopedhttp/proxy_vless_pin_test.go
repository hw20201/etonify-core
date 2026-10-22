package scopedhttp

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/endpointpin"
)

func syntheticRealityPin(t *testing.T, snapshot []byte) endpointpin.Pin {
	t.Helper()
	store, err := endpointpin.New(snapshot, "core-one", func() uint64 { return 7 })
	if err != nil {
		t.Fatal(err)
	}
	if !store.Observe("domain-reality", "node.example.invalid", 443, &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443}, 7) {
		t.Fatal("synthetic authenticated observation rejected")
	}
	pin, ok := store.Load("domain-reality", 7)
	if !ok {
		t.Fatal("missing synthetic pin")
	}
	return pin
}
func TestPrivateRealityPlanRequiresBoundAuthenticatedObservation(t *testing.T) {
	snapshot, err := os.ReadFile("testdata/app-default-vless-reality-domain.json")
	if err != nil {
		t.Fatal(err)
	}
	chain := []string{"select", "domain-reality"}
	pin := syntheticRealityPin(t, snapshot)
	p, err := NewPlanWithEndpointPin(snapshot, chain, pin, "core-one", 7)
	if err != nil {
		t.Fatal(err)
	}
	if p.vless == nil || p.vless.Server != "192.0.2.10" || p.vless.TLS.ServerName != "camouflage.example.invalid" || p.vless.TCPFastOpen || p.vless.TCPMultiPath {
		t.Fatal("private endpoint lost pin/SNI or retained unsafe socket acceleration")
	}
	if p.dns.typ != "https" || p.dns.host != "dns.cloudflare.com" {
		t.Fatal("application DNS graph substituted")
	}
	for _, tt := range []struct {
		name       string
		snapshot   []byte
		pin        endpointpin.Pin
		core       string
		generation uint64
	}{
		{"missing proof", snapshot, endpointpin.Pin{}, "core-one", 7},
		{"different snapshot", append(append([]byte{}, snapshot...), byte(' ')), pin, "core-one", 7},
		{"different core", snapshot, pin, "core-two", 7},
		{"different network", snapshot, pin, "core-one", 8},
		{"mutated numeric endpoint", snapshot, func() endpointpin.Pin { p := pin; p.Addr = netip.MustParseAddr("192.0.2.20"); return p }(), "core-one", 7},
		{"forged expiry", snapshot, func() endpointpin.Pin { p := pin; p.Expires = time.Now().Add(time.Hour); return p }(), "core-one", 7},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, e := NewPlanWithEndpointPin(tt.snapshot, chain, tt.pin, tt.core, tt.generation)
			if p != nil || e == nil || e.Error() != "[PIP_CFG:outbound.bootstrap.pin_required]" {
				t.Fatalf("unsafe plan: %v %v", p, e)
			}
		})
	}
	// A consumer cannot use a pin for another selected leaf, even in one snapshot.
	if pin.Valid(snapshot, []string{"select", "different-leaf"}, "core-one", 7, time.Now()) {
		t.Fatal("cross-leaf pin reuse")
	}
	if pin.Valid(snapshot, chain, "core-one", 7, pin.Expires) {
		t.Fatal("expired pin accepted")
	}
}
func TestPrivateRealityOptionWhitelist(t *testing.T) {
	snapshot, err := os.ReadFile("testdata/app-default-vless-reality-domain.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		change func(map[string]json.RawMessage)
	}{
		{"detour", func(o map[string]json.RawMessage) { o["detour"] = json.RawMessage(`"direct"`) }},
		{"resolver", func(o map[string]json.RawMessage) { o["domain_resolver"] = json.RawMessage(`"dns-local"`) }},
		{"transport", func(o map[string]json.RawMessage) { o["transport"] = json.RawMessage(`{"type":"ws"}`) }},
		{"multiplex", func(o map[string]json.RawMessage) { o["multiplex"] = json.RawMessage(`{"enabled":true}`) }},
		{"post quantum encryption", func(o map[string]json.RawMessage) { o["encryption"] = json.RawMessage(`"unsupported-private-value"`) }},
		{"TLS ECH dependency", func(o map[string]json.RawMessage) {
			var tls map[string]json.RawMessage
			_ = json.Unmarshal(o["tls"], &tls)
			tls["ech"] = json.RawMessage(`{"enabled":true}`)
			o["tls"], _ = json.Marshal(tls)
		}},
		{"insecure TLS", func(o map[string]json.RawMessage) {
			var tls map[string]json.RawMessage
			_ = json.Unmarshal(o["tls"], &tls)
			tls["insecure"] = json.RawMessage(`true`)
			o["tls"], _ = json.Marshal(tls)
		}},
		{"certificate file", func(o map[string]json.RawMessage) {
			var tls map[string]json.RawMessage
			_ = json.Unmarshal(o["tls"], &tls)
			tls["certificate_path"] = json.RawMessage(`"private-path"`)
			o["tls"], _ = json.Marshal(tls)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var root struct{ Outbounds []map[string]json.RawMessage }
			if err := json.Unmarshal(snapshot, &root); err != nil {
				t.Fatal(err)
			}
			leaf := root.Outbounds[1]
			tt.change(leaf)
			if opts, e := parseVLESSRealityProxy(leaf); opts != nil || e == nil {
				t.Fatal("unsafe dependency admitted")
			}
		})
	}
}
func TestPrivateRealityPinExpiryCancelsOnlyQuery(t *testing.T) {
	snapshot, err := os.ReadFile("testdata/app-default-vless-reality-domain.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPlanWithEndpointPin(snapshot, []string{"select", "domain-reality"}, syntheticRealityPin(t, snapshot), "core-one", 7)
	if err != nil {
		t.Fatal(err)
	}
	// Shorten an already verified plan's internal lifetime to simulate time passing.
	p.pin.Expires = time.Now().Add(30 * time.Millisecond)
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := newSession(parent, parent, p)
	defer s.Close()
	select {
	case <-s.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("pin expiry did not cancel query")
	}
	if parent.Err() != nil {
		t.Fatal("query expiry canceled shared parent")
	}
	if p.EndpointPinCurrent() {
		t.Fatal("expired endpoint still current")
	}
}
