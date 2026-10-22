// Package endpointpin stores short-lived observations of authenticated Reality
// peers. It never resolves a name, reads DNS caches, opens a socket or refreshes.
package endpointpin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
)

const TTL = 60 * time.Second

var ErrInvalidSnapshot = errors.New("endpointpin: invalid configuration snapshot")

type Pin struct {
	Addr              netip.Addr
	Server            string
	Port              uint16
	Leaf              string
	ConfigID          string
	CoreID            string
	NetworkGeneration uint64
	Expires           time.Time
	// Private integrity marker prevents consumers accidentally mutating a copied
	// observation into a different endpoint. This is an internal capability, not
	// an external serialized pin format or a credential.
	observed [32]byte
}

type endpoint struct {
	server string
	port   uint16
	source [32]byte
}
type Store struct {
	mu               sync.RWMutex
	configID, coreID string
	allowed          map[string]endpoint
	generation       func() uint64
	now              func() time.Time
	pins             map[string]Pin
}

func New(snapshot []byte, coreID string, generation func() uint64) (*Store, error) {
	if len(snapshot) == 0 || coreID == "" || generation == nil {
		return nil, ErrInvalidSnapshot
	}
	var cfg struct {
		Outbounds []struct {
			Type, Tag, Server string
			Port              uint16 `json:"server_port"`
			TLS               *struct {
				Enabled bool
				Reality *struct{ Enabled bool }
			}
			Transport          json.RawMessage
			Multiplex          json.RawMessage
			Encryption, Detour string
		}
	}
	if json.Unmarshal(snapshot, &cfg) != nil {
		return nil, ErrInvalidSnapshot
	}
	var raw struct{ Outbounds []json.RawMessage }
	if json.Unmarshal(snapshot, &raw) != nil {
		return nil, ErrInvalidSnapshot
	}
	allowed := make(map[string]endpoint)
	seen := make(map[string]bool)
	for i, o := range cfg.Outbounds {
		if o.Tag == "" {
			continue
		}
		if seen[o.Tag] {
			return nil, ErrInvalidSnapshot
		}
		seen[o.Tag] = true
		if o.Type != "vless" || o.Port == 0 || o.Detour != "" || present(o.Transport) || present(o.Multiplex) || o.Encryption != "" || o.TLS == nil || !o.TLS.Enabled || o.TLS.Reality == nil || !o.TLS.Reality.Enabled {
			continue
		}
		if _, err := netip.ParseAddr(o.Server); err == nil || !hostname(o.Server) {
			continue
		}
		var options option.VLESSOutboundOptions
		if json.Unmarshal(raw.Outbounds[i], &options) != nil {
			continue
		}
		source, ok := sourceIdentity(options)
		if !ok {
			continue
		}
		allowed[o.Tag] = endpoint{server: o.Server, port: o.Port, source: source}
	}
	return &Store{configID: configID(snapshot), coreID: coreID, allowed: allowed, generation: generation, now: time.Now, pins: make(map[string]Pin)}, nil
}

func sourceIdentity(options option.VLESSOutboundOptions) ([32]byte, bool) {
	wire, err := json.Marshal(options)
	if err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(wire), true
}

// MatchesSource is checked when the live producer is constructed, before any
// observation. Matching only a hostname/port would miss changed Reality keys,
// UUIDs or other connection options under an accidentally reused leaf tag.
func (s *Store) MatchesSource(leaf string, options option.VLESSOutboundOptions) bool {
	want, ok := s.allowed[leaf]
	if !ok {
		return false
	}
	actual, ok := sourceIdentity(options)
	return ok && actual == want.source
}

func present(v json.RawMessage) bool { return len(v) > 0 && strings.TrimSpace(string(v)) != "null" }
func configID(snapshot []byte) string {
	sum := sha256.Sum256(snapshot)
	return hex.EncodeToString(sum[:])
}
func hostname(s string) bool {
	if s == "" || len(s) > 253 || strings.HasSuffix(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func (s *Store) Generation() uint64 { return s.generation() }

// Observe may ONLY be called after successful Reality identity verification,
// with the actual bottom TCP peer, never after raw TCP or ordinary TLS success.
// Generation must be captured before the normal VPN's endpoint dial starts.
func (s *Store) Observe(leaf, server string, port uint16, peer net.Addr, startedGeneration uint64) bool {
	want, ok := s.allowed[leaf]
	if !ok || want.server != server || want.port != port || peer == nil {
		return false
	}
	tcp, ok := peer.(*net.TCPAddr)
	if !ok || tcp == nil || tcp.Zone != "" || tcp.Port != int(port) {
		return false
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	if !validAddr(ip) || s.generation() != startedGeneration {
		return false
	}
	pin := Pin{Addr: ip, Server: server, Port: port, Leaf: leaf, ConfigID: s.configID, CoreID: s.coreID, NetworkGeneration: startedGeneration, Expires: s.now().Add(TTL)}
	pin.observed = pin.marker()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation() != startedGeneration {
		return false
	}
	s.pins[leaf] = pin
	return true
}
func (s *Store) Load(leaf string, expectedGeneration uint64) (Pin, bool) {
	s.mu.RLock()
	pin, ok := s.pins[leaf]
	s.mu.RUnlock()
	if !ok || s.generation() != expectedGeneration || pin.NetworkGeneration != expectedGeneration || !s.now().Before(pin.Expires) {
		return Pin{}, false
	}
	return pin, true
}
func (p Pin) Valid(snapshot []byte, chain []string, coreID string, generation uint64, now time.Time) bool {
	return len(chain) > 0 && chain[len(chain)-1] == p.Leaf && coreID != "" && p.CoreID == coreID && p.ConfigID == configID(snapshot) && p.NetworkGeneration == generation && now.Before(p.Expires) && validAddr(p.Addr) && p.Port != 0 && p.observed != ([32]byte{}) && p.observed == p.marker()
}
func (p Pin) marker() [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s\x00%s\x00%d\x00%s", p.Addr, p.Server, p.Port, p.Leaf, p.ConfigID, p.CoreID, p.NetworkGeneration, p.Expires.Format(time.RFC3339Nano))))
}
func validAddr(ip netip.Addr) bool {
	return ip.IsValid() && ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast()
}
