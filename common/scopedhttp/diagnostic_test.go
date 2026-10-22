package scopedhttp

import (
	"encoding/json"
	"strings"
	"testing"
)

// These fixtures start from the app-generated defaults, not a hand-written
// minimal DNS graph. Node types/addresses are synthetic; no user node is inferred.
func TestAppDefaultDependencyDiagnostics(t *testing.T) {
	tests := []struct {
		name, code string
		change     func(map[string]any, map[string]any, map[string]any)
	}{
		{"vless", "outbound.protocol.vless", func(_ map[string]any, leaf, _ map[string]any) { leaf["type"] = "vless"; leaf["uuid"] = "private-uuid" }},
		{"vless Reality hostname precedes TLS bootstrap and DNS", "outbound.protocol.vless", func(root map[string]any, leaf, _ map[string]any) {
			leaf["type"] = "vless"
			leaf["server"] = "private-endpoint.example"
			leaf["uuid"] = "private-uuid"
			leaf["flow"] = "xtls-rprx-vision"
			leaf["tls"] = map[string]any{
				"enabled": true, "server_name": "private-sni.example",
				"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{"enabled": true, "public_key": "private-public-key", "short_id": "private-short-id"},
			}
			root["dns"].(map[string]any)["rules"] = []any{map[string]any{"domain": "private-rule.example", "server": "dns-direct"}}
		}},
		{"trojan", "outbound.protocol.trojan", func(_ map[string]any, leaf, _ map[string]any) { leaf["type"] = "trojan" }},
		{"direct", "outbound.protocol.direct", func(_ map[string]any, leaf, _ map[string]any) { leaf["type"] = "direct" }},
		{"unknown protocol redacted", "outbound.protocol.other", func(_ map[string]any, leaf, _ map[string]any) { leaf["type"] = "private-protocol" }},
		{"hostname SOCKS", "outbound.bootstrap.domain", func(_ map[string]any, leaf, _ map[string]any) { leaf["server"] = "private-endpoint.example" }},
		{"hostname SS", "outbound.bootstrap.domain", func(_ map[string]any, leaf, _ map[string]any) {
			leaf["type"] = "shadowsocks"
			leaf["method"] = "aes-128-gcm"
			leaf["password"] = "private-password"
			leaf["server"] = "private-endpoint.example"
		}},
		{"multihop", "outbound.option.detour", func(_ map[string]any, leaf, _ map[string]any) { leaf["detour"] = "private-other-node" }},
		{"TLS", "outbound.option.tls", func(_ map[string]any, leaf, _ map[string]any) {
			leaf["tls"] = map[string]any{"server_name": "private-sni.example"}
		}},
		{"unknown option redacted", "outbound.option.unknown", func(_ map[string]any, leaf, _ map[string]any) { leaf["private-key"] = "private-value" }},
		{"MPTCP", "outbound.option.tcp_multi_path", func(_ map[string]any, leaf, _ map[string]any) { leaf["tcp_multi_path"] = true }},
		{"DNS rules", "dns.rules", func(root map[string]any, _, _ map[string]any) {
			root["dns"].(map[string]any)["rules"] = []any{map[string]any{"domain": "private-rule.example", "server": "dns-direct"}}
		}},
		{"DNS detour", "dns.detour", func(_ map[string]any, _, dns map[string]any) { dns["detour"] = "direct" }},
		{"DNS resolver", "dns.bootstrap", func(_ map[string]any, _, dns map[string]any) { dns["domain_resolver"] = "private-resolver" }},
		{"DNS nested resolver", "dns.invalid", func(_ map[string]any, _, dns map[string]any) {
			dns["domain_resolver"] = map[string]any{"server": "private-resolver"}
		}},
		{"DNS unknown option redacted", "dns.option.unknown", func(_ map[string]any, _, dns map[string]any) { dns["private-key"] = "private-value" }},
		{"DNS TLS option", "dns.option.insecure", func(_ map[string]any, _, dns map[string]any) { dns["tls"] = map[string]any{"insecure": true} }},
		{"DNS unsupported type", "dns.type", func(_ map[string]any, _, dns map[string]any) { dns["type"] = "private-dns-type" }},
		{"DNS invalid final", "dns.invalid", func(root map[string]any, _, _ map[string]any) {
			root["dns"].(map[string]any)["final"] = "private-missing-tag"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var root map[string]any
			if err := json.Unmarshal(appDefaultSOCKS, &root); err != nil {
				t.Fatal(err)
			}
			leaf := root["outbounds"].([]any)[1].(map[string]any)
			dns := root["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			tt.change(root, leaf, dns)
			snapshot, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := NewPlan(snapshot, []string{"select", "literal-socks"})
			want := "[PIP_CFG:" + tt.code + "]"
			if plan != nil || err == nil || err.Error() != want {
				t.Fatalf("plan=%v err=%v want=%s", plan, err, want)
			}
			if strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), "literal-socks") {
				t.Fatal("configuration content leaked")
			}
		})
	}
}

func TestMalformedAndSelectionDiagnostics(t *testing.T) {
	for _, tt := range []struct {
		snapshot string
		chain    []string
		code     string
	}{
		{`{"private-token":`, []string{"secret-node"}, "snapshot.invalid"},
		{validSnapshot, []string{"secret-node"}, "selection.invalid"},
		{validSnapshot, nil, "selection.invalid"},
	} {
		p, err := NewPlan([]byte(tt.snapshot), tt.chain)
		if p != nil || err == nil || err.Error() != "[PIP_CFG:"+tt.code+"]" {
			t.Fatalf("unexpected result: %v %v", p, err)
		}
	}
}

func TestOptionDiagnosticDeterministic(t *testing.T) {
	for i := 0; i < 100; i++ {
		var root map[string]any
		if err := json.Unmarshal([]byte(validSnapshot), &root); err != nil {
			t.Fatal(err)
		}
		leaf := root["outbounds"].([]any)[0].(map[string]any)
		leaf["transport"] = map[string]any{"type": "ws"}
		leaf["detour"] = "private-tag"
		snapshot, _ := json.Marshal(root)
		_, err := NewPlan(snapshot, []string{"leaf"})
		if err == nil || err.Error() != "[PIP_CFG:outbound.option.detour]" {
			t.Fatalf("unstable diagnostic: %v", err)
		}
	}
}
