package scopedhttp

import (
	"encoding/json"
	"strings"
)

// requiresRealityEndpointPin identifies the warm-only domain/Reality shape.
// It is not an option validator, resolver or pin store. A positive result
// requires an authenticated, fully bound observation before the separate
// strict VLESS/TLS validator runs; missing proof fails before network allocation.
// A negative result still goes through the ordinary protocol allowlist.
func requiresRealityEndpointPin(leaf map[string]json.RawMessage) bool {
	if text(leaf, "type") != "vless" || !validDNSHostname(text(leaf, "server")) {
		return false
	}
	if _, err := literal(text(leaf, "server")); err == nil {
		return false
	}
	var tlsOptions map[string]json.RawMessage
	if json.Unmarshal(leaf["tls"], &tlsOptions) != nil || !explicitTrue(tlsOptions["enabled"]) {
		return false
	}
	var reality map[string]json.RawMessage
	return json.Unmarshal(tlsOptions["reality"], &reality) == nil && explicitTrue(reality["enabled"])
}

func explicitTrue(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "true"
}
