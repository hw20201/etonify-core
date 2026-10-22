package daemon

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type publicIPTestManager struct {
	adapter.OutboundManager
	items map[string]adapter.Outbound
}

func (m publicIPTestManager) Outbound(tag string) (adapter.Outbound, bool) {
	v, ok := m.items[tag]
	return v, ok
}

type publicIPTestLeaf struct {
	adapter.Outbound
	tag string
}

func (l publicIPTestLeaf) Tag() string { return l.tag }

type publicIPTestGroup struct {
	publicIPTestLeaf
	selected adapter.Outbound
}

func (g *publicIPTestGroup) Selected(string) adapter.Outbound  { return g.selected }
func (g *publicIPTestGroup) All() []string                     { return []string{"leaf"} }
func (g *publicIPTestGroup) AttachConnection(io.Closer) func() { return func() {} }

func TestFreezePublicIPChainSelectedLeafAndFailClosed(t *testing.T) {
	leaf := publicIPTestLeaf{tag: "leaf"}
	group := &publicIPTestGroup{publicIPTestLeaf: publicIPTestLeaf{tag: "group"}, selected: leaf}
	m := publicIPTestManager{items: map[string]adapter.Outbound{"group": group, "leaf": leaf}}
	chain, err := freezePublicIPChain(m, "group")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || chain[0] != "group" || chain[1] != "leaf" {
		t.Fatalf("frozen chain: %v", chain)
	}
	group.selected = nil
	if chain[1] != "leaf" {
		t.Fatal("frozen chain changed with selector")
	}
	if _, err = freezePublicIPChain(m, "group"); err == nil {
		t.Fatal("empty selector accepted")
	}
	group.selected = group
	if _, err = freezePublicIPChain(m, "group"); err == nil {
		t.Fatal("cycle accepted")
	}
	if _, err = freezePublicIPChain(m, "missing"); err == nil {
		t.Fatal("missing accepted")
	}
}
func TestWatchPublicIPGenerationCancelsOnlyItsQuery(t *testing.T) {
	var generation atomic.Uint64
	generation.Store(7)
	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	go watchPublicIPGeneration(ctx, cancel, 7, generation.Load)
	select {
	case <-ctx.Done():
		t.Fatal("cancel without change")
	case <-time.After(40 * time.Millisecond):
	}
	generation.Add(1)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("network watcher did not cancel")
	}
	if parent.Err() != nil {
		t.Fatal("watcher cancelled shared core")
	}
}
func TestPublicIPRPCFailClosed(t *testing.T) {
	s := new(StartedService)
	for _, req := range []*PublicIPLookupRequest{nil, {RequestID: "r", OutboundTag: "out", Provider: "unknown"}, {RequestID: "r", OutboundTag: "out", Provider: "ipQuery", TimeoutMillis: 10001}, {RequestID: "r", OutboundTag: "out", Provider: "ipQuery"}} {
		if _, err := s.LookupPublicIP(context.Background(), req); err == nil {
			t.Fatalf("accepted invalid or nonrunning request: %+v", req)
		}
	}
}

func TestPublicIPRPCConfigurationDiagnostic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	leaf := publicIPTestLeaf{tag: "private-node"}
	group := &publicIPTestGroup{publicIPTestLeaf: publicIPTestLeaf{tag: "select"}, selected: leaf}
	s := &StartedService{
		serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
		instance: &Instance{
			ctx:                   ctx,
			outboundManager:       publicIPTestManager{items: map[string]adapter.Outbound{"select": group, "private-node": leaf}},
			urlTestHistoryStorage: urltest.NewHistoryStorage(),
			publicIPConfig:        []byte(`{"outbounds":[{"type":"selector","tag":"select","outbounds":["private-node"]},{"type":"vless","tag":"private-node","server":"private-host.example","uuid":"private-uuid"}]}`),
		},
	}
	request := &PublicIPLookupRequest{RequestID: "diagnostic", OutboundTag: "select", Provider: "ipQuery", TimeoutMillis: 1000}
	result, err := s.LookupPublicIP(ctx, request)
	if result != nil || status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "unsupported scoped query configuration: [PIP_CFG:outbound.protocol.vless]" {
		t.Fatalf("unexpected RPC rejection: %v %v", result, err)
	}
	// A missing selection must not include its sensitive tag in the RPC error.
	request.OutboundTag = "private-missing-node"
	result, err = s.LookupPublicIP(ctx, request)
	if result != nil || status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "unsupported scoped query configuration: [PIP_CFG:selection.invalid]" {
		t.Fatalf("unexpected selection rejection: %v %v", result, err)
	}
}
