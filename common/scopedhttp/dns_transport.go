package scopedhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
)

// DNS endpoint hostnames are bootstrapped by the frozen proxy, not the device's
// local resolver. This is a query-specific privacy policy: the app's dns-local
// bootstrap hint is never allowed to create a direct/system socket here.
// Provider hostnames still use the configured DNS service and numeric proxy
// destinations; only the configured DNS endpoint may enter the proxy as a name.
func parseDNSConfig(o map[string]json.RawMessage, proxyType string) (dnsConfig, error) {
	if err := keysOnly(o, "type", "tag", "server", "server_port", "detour", "path", "tls", "domain_resolver"); err != nil {
		return dnsConfig{}, err
	}
	for _, key := range []string{"type", "tag", "server", "detour", "path", "domain_resolver"} {
		if raw, ok := o[key]; ok {
			var value string
			if string(raw) == "null" || json.Unmarshal(raw, &value) != nil {
				return dnsConfig{}, errors.New("invalid scoped DNS string option")
			}
		}
	}
	d := dnsConfig{typ: text(o, "type"), host: text(o, "server"), path: text(o, "path")}
	fallback := uint16(53)
	switch d.typ {
	case "tcp", "udp":
	case "tls":
		fallback = 853
	case "https":
		fallback = 443
	default:
		return d, reject("dns.type")
	}
	if d.typ == "udp" && proxyType != "socks" {
		return d, reject("dns.type")
	}
	if ip, err := literal(d.host); err == nil {
		d.host = ip.String()
	} else {
		if net.ParseIP(d.host) != nil || strings.Contains(d.host, ":") {
			return d, errors.New("invalid scoped DNS endpoint address")
		}
		if d.typ != "https" && d.typ != "tls" {
			return d, reject("dns.bootstrap")
		}
		if !validDNSHostname(d.host) {
			return d, errors.New("unsupported scoped DNS endpoint")
		}
		// Only the app's bootstrap hint is understood. An arbitrary resolver graph
		// cannot be discarded or replaced by this deliberately scoped policy.
		if resolver := text(o, "domain_resolver"); resolver != "dns-local" {
			return d, reject("dns.bootstrap")
		}
	}
	if raw, ok := o["domain_resolver"]; ok && string(raw) != "\"dns-local\"" {
		return d, reject("dns.bootstrap")
	}
	p, err := port(o, fallback)
	if err != nil {
		return d, err
	}
	d.address = net.JoinHostPort(d.host, strconv.Itoa(int(p)))
	d.serverName = d.host
	if raw, ok := o["tls"]; ok {
		if d.typ != "tls" && d.typ != "https" {
			return d, errors.New("unsupported scoped DNS TLS option")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return d, errors.New("invalid scoped DNS TLS options")
		}
		if err := keysOnly(fields, "enabled", "server_name"); err != nil {
			return d, err
		}
		if value, ok := fields["enabled"]; ok && string(value) != "true" {
			return d, errors.New("scoped DNS TLS cannot be disabled")
		}
		if raw, ok := fields["server_name"]; ok {
			var name string
			if string(raw) == "null" || json.Unmarshal(raw, &name) != nil {
				return d, errors.New("invalid scoped DNS TLS name")
			}
		}
		if name := text(fields, "server_name"); name != "" {
			if !validDNSHostname(name) {
				return d, errors.New("invalid scoped DNS TLS name")
			}
			d.serverName = name
		}
	}
	if d.typ == "https" {
		if d.path == "" {
			d.path = "/dns-query"
		}
		u, err := url.ParseRequestURI(d.path)
		if err != nil || !strings.HasPrefix(d.path, "/") || strings.HasPrefix(d.path, "//") || u.IsAbs() || u.Host != "" || u.Fragment != "" {
			return d, errors.New("invalid scoped DoH path")
		}
	} else if _, ok := o["path"]; ok {
		return d, errors.New("unsupported scoped DNS path")
	}
	return d, nil
}

func validDNSHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (s *Session) dialDNSEndpoint() (net.Conn, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	target := M.ParseSocksaddr(s.plan.dns.address)
	// This is the ONLY domain destination admitted to the proxy bootstrap lane.
	if target.IsDomain() && target.Fqdn != s.plan.dns.host {
		return nil, errors.New("scoped DNS endpoint identity mismatch")
	}
	conn, err := s.proxyDial(s.ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	if deadline, ok := s.ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	return s.own(conn)
}

func (s *Session) encryptedDNS(wire []byte) ([]byte, error) {
	config := s.transport.TLSClientConfig.Clone()
	config.ServerName = s.plan.dns.serverName
	if s.plan.dns.typ == "https" {
		// A distinct private transport, never the provider transport/global client.
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
			ForceAttemptHTTP2: false, TLSClientConfig: config, MaxResponseHeaderBytes: 8192,
			DialContext: func(context.Context, string, string) (net.Conn, error) { return s.dialDNSEndpoint() },
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		endpoint := url.URL{Scheme: "https", Host: s.plan.dns.address}
		// Parse path/query separately to avoid escaping a configured query as path.
		path, _ := url.ParseRequestURI(s.plan.dns.path)
		endpoint.Path = path.Path
		endpoint.RawPath = path.RawPath
		endpoint.RawQuery = path.RawQuery
		request, err := http.NewRequestWithContext(s.ctx, http.MethodPost, endpoint.String(), bytes.NewReader(wire))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/dns-message")
		request.Header.Set("Accept", "application/dns-message")
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("scoped DoH status %d", response.StatusCode)
		}
		if ct := strings.Split(response.Header.Get("Content-Type"), ";")[0]; ct != "application/dns-message" {
			return nil, errors.New("invalid scoped DoH content type")
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 65536))
		if err != nil {
			return nil, err
		}
		if len(data) < 12 || len(data) > 65535 {
			return nil, errors.New("invalid scoped DoH body size")
		}
		return data, nil
	}
	raw, err := s.dialDNSEndpoint()
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	conn := tls.Client(raw, config)
	if err = conn.HandshakeContext(s.ctx); err != nil {
		return nil, err
	}
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	if _, err = io.Copy(conn, bytes.NewReader(frame)); err != nil {
		return nil, err
	}
	var prefix [2]byte
	if _, err = io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(prefix[:]))
	if n < 12 {
		return nil, errors.New("invalid scoped DoT frame")
	}
	result := make([]byte, n)
	_, err = io.ReadFull(conn, result)
	return result, err
}
