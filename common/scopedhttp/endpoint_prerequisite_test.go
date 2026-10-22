package scopedhttp

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRealityEndpointPrerequisiteNeverEnablesProtocol(t *testing.T) {
	fixture, err := os.ReadFile("testdata/app-default-vless-reality-domain.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, code string
		change     func(map[string]any, map[string]any)
	}{
		{"confirmed domain Reality", "outbound.bootstrap.pin_required", func(_, _ map[string]any) {}},
		{"numeric endpoint remains unaudited", "outbound.protocol.vless", func(_, leaf map[string]any) { leaf["server"] = "192.0.2.10" }},
		{"IPv6 endpoint remains unaudited", "outbound.protocol.vless", func(_, leaf map[string]any) { leaf["server"] = "2001:db8::10" }},
		{"invalid hostname", "outbound.protocol.vless", func(_, leaf map[string]any) { leaf["server"] = "private-host/invalid" }},
		{"TLS absent", "outbound.protocol.vless", func(_, leaf map[string]any) { delete(leaf, "tls") }},
		{"TLS malformed", "outbound.protocol.vless", func(_, leaf map[string]any) { leaf["tls"] = "private-value" }},
		{"TLS disabled", "outbound.protocol.vless", func(_, leaf map[string]any) { leaf["tls"].(map[string]any)["enabled"] = false }},
		{"TLS string true rejected", "outbound.protocol.vless", func(_, leaf map[string]any) { leaf["tls"].(map[string]any)["enabled"] = "true" }},
		{"Reality absent", "outbound.protocol.vless", func(_, leaf map[string]any) { delete(leaf["tls"].(map[string]any), "reality") }},
		{"Reality malformed", "outbound.protocol.vless", func(_, leaf map[string]any) { leaf["tls"].(map[string]any)["reality"] = []any{true} }},
		{"Reality disabled", "outbound.protocol.vless", func(_, leaf map[string]any) {
			leaf["tls"].(map[string]any)["reality"].(map[string]any)["enabled"] = false
		}},
		{"Reality string true rejected", "outbound.protocol.vless", func(_, leaf map[string]any) {
			leaf["tls"].(map[string]any)["reality"].(map[string]any)["enabled"] = "true"
		}},
		{"no remote DNS substitution", "outbound.bootstrap.pin_required", func(root, _ map[string]any) { root["route"].(map[string]any)["default_domain_resolver"] = "dns-remote" }},
		{"no explicit local DNS fallback", "outbound.bootstrap.pin_required", func(_, leaf map[string]any) { leaf["domain_resolver"] = "dns-local" }},
		{"no explicit direct DNS fallback", "outbound.bootstrap.pin_required", func(_, leaf map[string]any) { leaf["domain_resolver"] = "dns-direct" }},
		{"no explicit remote DNS recursion", "outbound.bootstrap.pin_required", func(_, leaf map[string]any) { leaf["domain_resolver"] = "dns-remote" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var root map[string]any
			if err := json.Unmarshal(fixture, &root); err != nil {
				t.Fatal(err)
			}
			leaf := root["outbounds"].([]any)[1].(map[string]any)
			tt.change(root, leaf)
			snapshot, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := NewPlan(snapshot, []string{"select", "domain-reality"})
			if plan != nil || err == nil || err.Error() != "[PIP_CFG:"+tt.code+"]" {
				t.Fatalf("unreviewed graph accepted or wrong safe rejection: plan=%v err=%v", plan, err)
			}
		})
	}
}
