//go:build with_utls

package scopedhttp

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// Synthetic application-shaped configuration: valid UUID, Reality public-key
// encoding, short ID and uTLS fingerprint. Neither endpoint is a real user node.
//
//go:embed testdata/app-default-vless-reality-domain.json
var appDefaultDomainReality []byte

var errUnpinnedEndpointResolution = errors.New("test blocked unpinned endpoint resolution")

type endpointDependencyTransport struct {
	adapter.DNSTransport
	tag string
}

func (t *endpointDependencyTransport) Tag() string { return t.tag }

type endpointDependencyManager struct {
	adapter.DNSTransportManager
	items map[string]adapter.DNSTransport
}

func (m *endpointDependencyManager) Transport(tag string) (adapter.DNSTransport, bool) {
	t, ok := m.items[tag]
	return t, ok
}

type endpointDependencyRouter struct {
	adapter.DNSRouter
	calls            int
	domain, resolver string
}

func (r *endpointDependencyRouter) Lookup(_ context.Context, domain string, opts adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.calls++
	r.domain = domain
	r.resolver = opts.Transport.Tag()
	// Do not delegate to any DNS transport, system resolver or socket. This test
	// characterizes a blocked dependency, NOT a successful end-to-end IP lookup.
	return nil, errUnpinnedEndpointResolution
}

type endpointDependencyNetwork struct {
	adapter.NetworkManager
	resolver string
}

func (n *endpointDependencyNetwork) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (n *endpointDependencyNetwork) AutoDetectInterface() bool                { return false }
func (n *endpointDependencyNetwork) AutoRedirectOutputMarkFunc() control.Func { return nil }
func (n *endpointDependencyNetwork) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{DomainResolver: n.resolver}
}

func domainRealityOptions(t *testing.T) option.VLESSOutboundOptions {
	t.Helper()
	var root struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(appDefaultDomainReality, &root); err != nil {
		t.Fatal(err)
	}
	var options option.VLESSOutboundOptions
	if err := json.Unmarshal(root.Outbounds[1], &options); err != nil {
		t.Fatal(err)
	}
	return options
}

// Bypassing only the scoped protocol allowlist and handing the live outbound to
// the HTTP client would silently re-enter the runtime endpoint resolver. Exercise
// the REAL VLESS + Reality constructor and dial path, with the DNS boundary
// intercepted before any network access, rather than substituting a SOCKS node.
func TestDomainRealityLiveOutboundStillNeedsEndpointBootstrap(t *testing.T) {
	for _, tt := range []struct {
		name, defaultResolver, explicitResolver, want string
	}{
		{"app inherited local resolver", "dns-local", "", "dns-local"},
		{"explicit local resolver", "dns-remote", "dns-local", "dns-local"},
		{"explicit direct resolver", "dns-local", "dns-direct", "dns-direct"},
		{"remote resolver creates same-node dependency", "dns-remote", "", "dns-remote"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, tfo := range []bool{false, true} {
				router := new(endpointDependencyRouter)
				manager := &endpointDependencyManager{items: map[string]adapter.DNSTransport{}}
				for _, tag := range []string{"dns-local", "dns-direct", "dns-remote"} {
					manager.items[tag] = &endpointDependencyTransport{tag: tag}
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				ctx = service.ContextWith[adapter.DNSTransportManager](ctx, manager)
				ctx = service.ContextWith[adapter.DNSRouter](ctx, router)
				ctx = service.ContextWith[adapter.NetworkManager](ctx, &endpointDependencyNetwork{resolver: tt.defaultResolver})
				options := domainRealityOptions(t)
				options.TCPFastOpen = tfo
				if tt.explicitResolver != "" {
					options.DomainResolver = &option.DomainResolveOptions{Server: tt.explicitResolver}
				}
				outbound, err := vless.NewOutbound(ctx, nil, boxlog.NewNOPFactory().Logger(), "domain-reality", options)
				if err != nil {
					t.Fatalf("real VLESS Reality construction (TFO=%v): %v", tfo, err)
				}
				conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddr("203.0.113.7:443"))
				if conn != nil {
					conn.Close()
					t.Fatal("unexpected connection past blocked bootstrap")
				}
				if !errors.Is(err, errUnpinnedEndpointResolution) {
					t.Fatalf("TFO=%v: expected bootstrap sentinel, got %v", tfo, err)
				}
				if router.calls != 1 || router.domain != "node.example.invalid" || router.resolver != tt.want {
					t.Fatalf("unexpected endpoint dependency: calls=%d domain=%s resolver=%s", router.calls, router.domain, router.resolver)
				}
			}
		})
	}
}

func TestDomainRealityApplicationGraphFailsClosedWithoutEndpointPin(t *testing.T) {
	var root struct {
		DNS struct {
			Final   string `json:"final"`
			Servers []struct {
				Tag, Type, Server, Detour string
				DomainResolver            string `json:"domain_resolver"`
			} `json:"servers"`
		} `json:"dns"`
		Route struct {
			DefaultResolver string `json:"default_domain_resolver"`
		} `json:"route"`
	}
	if err := json.Unmarshal(appDefaultDomainReality, &root); err != nil {
		t.Fatal(err)
	}
	if root.Route.DefaultResolver != "dns-local" || root.DNS.Final != "dns-remote" {
		t.Fatal("fixture no longer represents application defaults")
	}
	remote := root.DNS.Servers[0]
	if remote.Tag != "dns-remote" || remote.Type != "https" || remote.Detour != "select" || remote.DomainResolver != "dns-local" {
		t.Fatal("fixture lost the remote-DNS/bootstrap/selected-node dependency")
	}
	// Numeric provider destinations do not eliminate the dependency: the node's
	// own server is a domain, while remote DNS itself needs this same node first.
	plan, err := NewPlan(appDefaultDomainReality, []string{"select", "domain-reality"})
	if plan != nil || err == nil || err.Error() != "[PIP_CFG:outbound.bootstrap.pin_required]" {
		t.Fatalf("unproven full dependency chain accepted: plan=%v err=%v", plan, err)
	}
}
