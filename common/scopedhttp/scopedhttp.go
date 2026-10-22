// Package scopedhttp owns every DNS and HTTP socket for one immutable query.
// It deliberately rejects protocols/options whose dependency graph is unaudited.
package scopedhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const bodyLimit = 16 << 10

type proxyConfig struct {
	typ, tag, server, username, password, method string
	port                                         uint16
}
type dnsConfig struct{ typ, address, host, serverName, path string }

// Plan never retains caller-owned slices, live selectors, managers or outbound
// objects. Credentials are private and only a digest leaves the core.
type Plan struct {
	id    string
	proxy proxyConfig
	dns   dnsConfig
}

func (p *Plan) ID() string {
	if p == nil {
		return ""
	}
	return p.id
}

func text(o map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(o[key], &value)
	return value
}
func keysOnly(o map[string]json.RawMessage, allowed ...string) error {
	for key := range o {
		ok := false
		for _, name := range allowed {
			if key == name {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("unsupported scoped option: %s", key)
		}
	}
	return nil
}
func port(o map[string]json.RawMessage, fallback uint16) (uint16, error) {
	v := uint64(fallback)
	if raw, exists := o["server_port"]; exists {
		if err := json.Unmarshal(raw, &v); err != nil {
			return 0, errors.New("invalid server port")
		}
	}
	if v == 0 || v > 65535 {
		return 0, errors.New("invalid server port")
	}
	return uint16(v), nil
}

// Query sockets deliberately disable TFO even when the VPN enables it. It is
// a performance hint, not a route/credential dependency; disabling it avoids
// cancellation-detached connect probes. The normal VPN configuration is untouched.
func validateProxySocketOptions(o map[string]json.RawMessage) error {
	if raw, ok := o["tcp_fast_open"]; ok {
		value := strings.TrimSpace(string(raw))
		if value != "true" && value != "false" {
			return errors.New("invalid scoped tcp_fast_open option")
		}
	}
	if raw, ok := o["tcp_multi_path"]; ok && strings.TrimSpace(string(raw)) != "false" {
		return errors.New("unsupported scoped tcp_multi_path option: must be false")
	}
	return nil
}
func literal(raw string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, errors.New("scoped server must be a non-zoned literal IP")
	}
	return ip.Unmap(), nil
}

func NewPlan(snapshot []byte, chain []string) (*Plan, error) {
	if len(chain) == 0 || len(chain) > 32 {
		return nil, errors.New("invalid scoped outbound chain")
	}
	var root struct {
		Outbounds []map[string]json.RawMessage `json:"outbounds"`
		DNS       struct {
			Final   string                       `json:"final"`
			Rules   []json.RawMessage            `json:"rules"`
			Servers []map[string]json.RawMessage `json:"servers"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(snapshot, &root); err != nil {
		return nil, fmt.Errorf("invalid scoped snapshot: %w", err)
	}
	byTag := make(map[string]map[string]json.RawMessage)
	for _, outbound := range root.Outbounds {
		tag := text(outbound, "tag")
		if tag == "" {
			continue
		}
		if byTag[tag] != nil {
			return nil, errors.New("duplicate outbound identity")
		}
		byTag[tag] = outbound
	}
	seen := make(map[string]bool)
	for i, tag := range chain {
		o := byTag[tag]
		if tag == "" || seen[tag] || o == nil {
			return nil, errors.New("unknown or cyclic scoped outbound identity")
		}
		seen[tag] = true
		typ := text(o, "type")
		if i == len(chain)-1 {
			if typ == "selector" || typ == "urltest" {
				return nil, errors.New("unresolved scoped group")
			}
			continue
		}
		if typ != "selector" && typ != "urltest" {
			return nil, errors.New("non-group in scoped selection chain")
		}
		var members []string
		if err := json.Unmarshal(o["outbounds"], &members); err != nil {
			return nil, errors.New("group has no frozen members")
		}
		found := false
		for _, member := range members {
			if member == chain[i+1] {
				found = true
			}
		}
		if !found {
			return nil, errors.New("selected member not in snapshot group")
		}
	}
	leaf := byTag[chain[len(chain)-1]]
	typ := text(leaf, "type")
	if typ != "socks" && typ != "http" && typ != "shadowsocks" {
		return nil, fmt.Errorf("unsupported scoped outbound type: %s", typ)
	}
	method, password := "", ""
	var err error
	if typ == "shadowsocks" {
		method, password, err = parseShadowsocksProxy(leaf)
		if err != nil {
			return nil, err
		}
	} else {
		// A whitelist, not a blacklist: future options cannot silently add DNS,
		// detours, multiplexing, TLS fetching, TFO or transport side dependencies.
		if err := keysOnly(leaf, "type", "tag", "server", "server_port", "username", "password", "version", "tcp_fast_open", "tcp_multi_path"); err != nil {
			return nil, err
		}
		if err := validateProxySocketOptions(leaf); err != nil {
			return nil, err
		}
		if typ == "socks" {
			if v := text(leaf, "version"); v != "" && v != "5" {
				return nil, errors.New("only SOCKS5 is scoped")
			}
		} else if raw := leaf["version"]; len(raw) > 0 && string(raw) != "0" && string(raw) != "1" {
			return nil, errors.New("only HTTP/1 CONNECT is scoped")
		}
	}
	ip, err := literal(text(leaf, "server"))
	if err != nil {
		return nil, fmt.Errorf("proxy bootstrap DNS forbidden: %w", err)
	}
	proxyPort, err := port(leaf, 0)
	if err != nil {
		return nil, err
	}
	proxyPassword := text(leaf, "password")
	if typ == "shadowsocks" {
		proxyPassword = password
	}
	p := &Plan{proxy: proxyConfig{typ: typ, tag: chain[len(chain)-1], server: ip.String(), port: proxyPort, username: text(leaf, "username"), password: proxyPassword, method: method}}
	if strings.ContainsAny(p.proxy.username+p.proxy.password, "\r\n") || len(p.proxy.username) > 255 || len(p.proxy.password) > 255 {
		return nil, errors.New("invalid scoped proxy credentials")
	}
	// Routing rules are not silently ignored. Supporting a rule-dependent DNS
	// graph requires freezing its result for every dependency first.
	if len(root.DNS.Rules) > 0 {
		return nil, errors.New("rule-dependent DNS is not yet safely scoped")
	}
	if root.DNS.Final == "" {
		return nil, errors.New("explicit scoped DNS.final required")
	}
	var selected map[string]json.RawMessage
	for _, server := range root.DNS.Servers {
		if text(server, "tag") == root.DNS.Final {
			if selected != nil {
				return nil, errors.New("duplicate DNS identity")
			}
			selected = server
		}
	}
	if selected == nil {
		return nil, errors.New("scoped DNS.final missing")
	}
	if !seen[text(selected, "detour")] {
		return nil, errors.New("DNS must explicitly detour through the pinned selection chain")
	}
	p.dns, err = parseDNSConfig(selected, typ)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	digest.Write(snapshot)
	digest.Write([]byte{0})
	digest.Write([]byte(strings.Join(chain, "\x00")))
	p.id = hex.EncodeToString(digest.Sum(nil))
	return p, nil
}

// Assert the public constructor's context contract before allocating sockets.
func deadlineContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("missing scoped query context")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("whole scoped query requires a deadline")
	}
	return ctx.Err()
}
