package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/scopedhttp"
	N "github.com/sagernet/sing/common/network"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const publicIPDefaultTimeout = 3 * time.Second
const publicIPMaximumTimeout = 10 * time.Second

// freezePublicIPChain reads each group exactly once. Only the resulting tag
// values enter a plan; no live outbound/group pointer is used for network I/O.
func freezePublicIPChain(manager adapter.OutboundManager, tag string) ([]string, error) {
	var chain []string
	for len(chain) < 32 {
		if tag == "" || slices.Contains(chain, tag) {
			return nil, fmt.Errorf("invalid or cyclic scoped outbound chain")
		}
		outbound, loaded := manager.Outbound(tag)
		if !loaded {
			return nil, fmt.Errorf("scoped outbound not found: %s", tag)
		}
		chain = append(chain, tag)
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			return chain, nil
		}
		selected := group.Selected(N.NetworkTCP)
		if selected == nil {
			return nil, fmt.Errorf("scoped group has no selected outbound")
		}
		tag = selected.Tag()
	}
	return nil, fmt.Errorf("scoped outbound chain too deep")
}

func (s *StartedService) LookupPublicIP(ctx context.Context, request *PublicIPLookupRequest) (*PublicIPLookupResponse, error) {
	if request == nil || strings.TrimSpace(request.RequestID) == "" || len(request.RequestID) > 128 ||
		request.OutboundTag == "" || request.NetworkGeneration < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid scoped query identity")
	}
	switch request.Provider {
	case "ipQuery", "ipApi", "ipWho":
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown public IP provider")
	}
	timeout := time.Duration(request.TimeoutMillis) * time.Millisecond
	if timeout <= 0 {
		timeout = publicIPDefaultTimeout
	}
	if timeout > publicIPMaximumTimeout {
		return nil, status.Error(codes.InvalidArgument, "scoped query deadline exceeds 10 seconds")
	}
	// One deadline starts before plan creation and is never renewed between
	// DNS, TCP/TLS, provider calls or response body reads.
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	s.serviceAccess.RLock()
	instance := s.instance
	if instance == nil || s.serviceStatus.Status != ServiceStatus_STARTED || len(instance.publicIPConfig) == 0 {
		s.serviceAccess.RUnlock()
		return nil, status.Error(codes.FailedPrecondition, "scoped query requires a running snapshotted core")
	}
	chain, err := freezePublicIPChain(instance.outboundManager, request.OutboundTag)
	networkGeneration := instance.urlTestHistoryStorage.Generation()
	s.serviceAccess.RUnlock()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "unsupported scoped query configuration: [PIP_CFG:selection.invalid]")
	}
	stopInstance := context.AfterFunc(instance.ctx, cancel)
	defer stopInstance()
	// Query-only watcher. It neither resets nor closes any shared VPN/DNS client.
	go watchPublicIPValidity(queryCtx, cancel, func() bool {
		s.serviceAccess.RLock()
		defer s.serviceAccess.RUnlock()
		if s.instance != instance || s.serviceStatus.Status != ServiceStatus_STARTED || networkGeneration != instance.urlTestHistoryStorage.Generation() {
			return false
		}
		current, err := freezePublicIPChain(instance.outboundManager, request.OutboundTag)
		return err == nil && slices.Equal(chain, current)
	})
	var plan *scopedhttp.Plan
	if instance.publicIPEndpoints != nil {
		if pin, ok := instance.publicIPEndpoints.Load(chain[len(chain)-1], networkGeneration); ok {
			plan, err = scopedhttp.NewPlanWithEndpointPin(instance.publicIPConfig, chain, pin, instance.publicIPGeneration, networkGeneration)
		} else {
			plan, err = scopedhttp.NewPlan(instance.publicIPConfig, chain)
		}
	} else {
		plan, err = scopedhttp.NewPlan(instance.publicIPConfig, chain)
	}
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "unsupported scoped query configuration: %v", err)
	}
	session, err := scopedhttp.NewSession(queryCtx, instance.ctx, plan)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	body, err := session.Lookup(request.Provider)
	if err != nil {
		return nil, err
	}
	if err := queryCtx.Err(); err != nil {
		return nil, err
	}
	if !plan.EndpointPinCurrent() {
		return nil, status.Error(codes.Aborted, "scoped query endpoint observation expired")
	}
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.instance != instance || s.serviceStatus.Status != ServiceStatus_STARTED ||
		instance.ctx.Err() != nil || networkGeneration != instance.urlTestHistoryStorage.Generation() {
		return nil, status.Error(codes.Aborted, "scoped query core or network generation changed")
	}
	currentChain, err := freezePublicIPChain(instance.outboundManager, request.OutboundTag)
	if err != nil || !slices.Equal(chain, currentChain) {
		return nil, status.Error(codes.Aborted, "scoped query outbound selection changed")
	}
	// Public audit identity binds the immutable full configuration, resolved
	// plan, provider and both core/network generations without leaking secrets.
	audit := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d", plan.ID(), request.Provider,
		instance.publicIPGeneration, networkGeneration, request.NetworkGeneration)))
	return &PublicIPLookupResponse{
		Json: string(body), PlanID: hex.EncodeToString(audit[:]), CoreGeneration: instance.publicIPGeneration,
		NetworkGeneration: request.NetworkGeneration, OutboundTag: request.OutboundTag,
	}, nil
}

func watchPublicIPGeneration(ctx context.Context, cancel context.CancelFunc, initial uint64, generation func() uint64) {
	watchPublicIPValidity(ctx, cancel, func() bool { return generation() == initial })
}

func watchPublicIPValidity(ctx context.Context, cancel context.CancelFunc, valid func() bool) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !valid() {
				cancel()
				return
			}
		}
	}
}
