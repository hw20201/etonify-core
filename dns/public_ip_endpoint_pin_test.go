package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
)

// These are blocker-characterization tests, NOT permission to use runtime DNS
// for a scoped public-IP query. All transports and persistent data are synthetic;
// no resolver, listener, socket, user node or system DNS is contacted.
func TestPublicIPEndpointPinCacheIsNotConfigurationBound(t *testing.T) {
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	first := &fakeDNSTransport{tag: "dns-remote", address: netip.MustParseAddr("192.0.2.10")}
	reconfigured := &fakeDNSTransport{tag: "dns-remote", address: netip.MustParseAddr("192.0.2.20")}
	options := adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	addresses, err := client.Lookup(ctx, first, "node.example.invalid", options, nil)
	if err != nil || len(addresses) != 1 || addresses[0] != first.address {
		t.Fatalf("seed cache: addresses=%v err=%v", addresses, err)
	}
	addresses, err = client.Lookup(ctx, reconfigured, "node.example.invalid", options, nil)
	if err != nil || len(addresses) != 1 || addresses[0] != first.address || reconfigured.queryCount.Load() != 0 {
		t.Fatalf("expected tag-keyed cached result without new exchange: addresses=%v err=%v calls=%d", addresses, err, reconfigured.queryCount.Load())
	}
	// A different resolver tag IS isolated; this is not a cross-resolver cache bug.
	other := &fakeDNSTransport{tag: "dns-local", address: reconfigured.address}
	addresses, err = client.Lookup(ctx, other, "node.example.invalid", options, nil)
	if err != nil || len(addresses) != 1 || addresses[0] != other.address || other.queryCount.Load() != 1 {
		t.Fatalf("resolver identity isolation: addresses=%v err=%v calls=%d", addresses, err, other.queryCount.Load())
	}
}

type publicIPExpiredCache struct {
	adapter.DNSCacheStore
	wire    []byte
	expired time.Time
}

func (s *publicIPExpiredCache) LoadDNSCache(_, _ string, _ uint16) ([]byte, time.Time, bool) {
	return append([]byte(nil), s.wire...), s.expired, true
}

func publicIPExpiredResponse(t *testing.T) *publicIPExpiredCache {
	t.Helper()
	message := new(mDNS.Msg)
	message.SetQuestion("node.example.invalid.", mDNS.TypeA)
	response := FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.10")}, 300)
	wire, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return &publicIPExpiredCache{wire: wire, expired: time.Now().Add(-time.Minute)}
}

func TestPublicIPEndpointPinDisableExpireDoesNotProveFreshness(t *testing.T) {
	store := publicIPExpiredResponse(t)
	client := NewClient(ClientOptions{Context: context.Background(), DisableExpire: true,
		DNSCache: func() adapter.DNSCacheStore { return store }, Logger: log.NewNOPFactory().Logger()})
	client.Start()
	transport := &fakeDNSTransport{tag: "dns-local", address: netip.MustParseAddr("192.0.2.20")}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	addresses, err := client.Lookup(ctx, transport, "node.example.invalid", adapter.DNSQueryOptions{
		Strategy: C.DomainStrategyIPv4Only, DisableOptimisticCache: true,
	}, nil)
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("192.0.2.10") || transport.queryCount.Load() != 0 {
		t.Fatalf("expired cache accepted under disable_expire: addresses=%v err=%v calls=%d", addresses, err, transport.queryCount.Load())
	}
}

type publicIPRefreshTransport struct {
	adapter.DNSTransport
	started  chan context.Context
	finished chan struct{}
}

func (t *publicIPRefreshTransport) Tag() string { return "dns-local" }
func (t *publicIPRefreshTransport) Exchange(ctx context.Context, _ *mDNS.Msg) (*mDNS.Msg, error) {
	t.started <- ctx
	<-ctx.Done()
	close(t.finished)
	return nil, ctx.Err()
}

func TestPublicIPEndpointPinOptimisticLookupIsNotQueryOwned(t *testing.T) {
	store := publicIPExpiredResponse(t)
	coreCtx, stopCore := context.WithCancel(context.Background())
	defer stopCore()
	client := NewClient(ClientOptions{Context: coreCtx, OptimisticTimeout: time.Hour,
		DNSCache: func() adapter.DNSCacheStore { return store }, Logger: log.NewNOPFactory().Logger()})
	client.Start()
	transport := &publicIPRefreshTransport{started: make(chan context.Context, 1), finished: make(chan struct{})}
	queryCtx, cancelQuery := context.WithTimeout(coreCtx, time.Second)
	defer cancelQuery()
	addresses, err := client.Lookup(queryCtx, transport, "node.example.invalid", adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only}, nil)
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("optimistic stale lookup: addresses=%v err=%v", addresses, err)
	}
	var refreshCtx context.Context
	select {
	case refreshCtx = <-transport.started:
	case <-queryCtx.Done():
		t.Fatal("missing synthetic refresh")
	}
	cancelQuery()
	if refreshCtx.Err() != nil {
		t.Fatalf("expected refresh to belong to core, not query: %v", refreshCtx.Err())
	}
	stopCore()
	select {
	case <-transport.finished:
	case <-time.After(time.Second):
		t.Fatal("synthetic refresh did not stop with core")
	}
}
