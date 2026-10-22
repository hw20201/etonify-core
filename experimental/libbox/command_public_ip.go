package libbox

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/daemon"
)

// PublicIPLookupResult contains provider JSON plus an opaque audit identity.
// Neither credentials nor the configuration snapshot cross this API.
type PublicIPLookupResult struct {
	JSON              string
	PlanID            string
	CoreGeneration    string
	NetworkGeneration int64
	OutboundTag       string
}

type publicIPRequestEntry struct {
	cancel context.CancelFunc
	until  time.Time
}

type publicIPRequestRegistry struct {
	access  sync.Mutex
	entries map[string]publicIPRequestEntry
}

// Retain short-lived tombstones so a cancellation racing worker dispatch cannot
// accidentally start a query, and a late cancellation cannot affect another ID.
// The bounded registry fails closed instead of dropping active cancellation state.
func (r *publicIPRequestRegistry) pruneLocked() {
	now := time.Now()
	if r.entries == nil {
		r.entries = make(map[string]publicIPRequestEntry)
	}
	for id, entry := range r.entries {
		if entry.cancel == nil && now.After(entry.until) {
			delete(r.entries, id)
		}
	}
}

func (r *publicIPRequestRegistry) begin(parent context.Context, id string, timeout time.Duration) (context.Context, func(), error) {
	if strings.TrimSpace(id) == "" || len(id) > 128 {
		return nil, nil, fmt.Errorf("invalid public IP request ID")
	}
	r.access.Lock()
	defer r.access.Unlock()
	r.pruneLocked()
	if _, exists := r.entries[id]; exists {
		return nil, nil, fmt.Errorf("public IP request ID already used or cancelled")
	}
	if len(r.entries) >= 2048 {
		return nil, nil, fmt.Errorf("too many public IP request identities")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	r.entries[id] = publicIPRequestEntry{cancel: cancel}
	finish := func() {
		cancel()
		r.access.Lock()
		r.entries[id] = publicIPRequestEntry{until: time.Now().Add(time.Minute)}
		r.access.Unlock()
	}
	return ctx, finish, nil
}

func (r *publicIPRequestRegistry) cancel(id string) error {
	if strings.TrimSpace(id) == "" || len(id) > 128 {
		return fmt.Errorf("invalid public IP request ID")
	}
	r.access.Lock()
	defer r.access.Unlock()
	r.pruneLocked()
	if entry, exists := r.entries[id]; exists {
		if entry.cancel != nil {
			entry.cancel()
		}
		return nil
	}
	if len(r.entries) >= 2048 {
		return fmt.Errorf("too many public IP request identities")
	}
	r.entries[id] = publicIPRequestEntry{until: time.Now().Add(time.Minute)}
	return nil
}

func (c *CommandClient) LookupPublicIP(requestID, outboundTag, provider string, networkGeneration int64, timeoutMillis int32) (*PublicIPLookupResult, error) {
	timeout := time.Duration(timeoutMillis) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if timeout > 10*time.Second {
		return nil, fmt.Errorf("public IP deadline exceeds 10 seconds")
	}
	c.clientAccess.RLock()
	parent := c.ctx
	c.clientAccess.RUnlock()
	if parent == nil {
		return nil, fmt.Errorf("command client has no context")
	}
	ctx, finish, err := c.publicIPRequests.begin(parent, requestID, timeout)
	if err != nil {
		return nil, err
	}
	defer finish()
	client, connectionCtx, err := c.getClientForCall()
	if err != nil {
		return nil, err
	}
	// Also follow the selected connection lifetime if a reconnect occurred.
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(connectionCtx, cancel)
	defer stop()
	if err := callCtx.Err(); err != nil {
		return nil, err
	}
	result, err := client.LookupPublicIP(callCtx, &daemon.PublicIPLookupRequest{
		RequestID: requestID, OutboundTag: outboundTag, Provider: provider,
		NetworkGeneration: networkGeneration, TimeoutMillis: timeoutMillis,
	})
	if err != nil {
		return nil, err
	}
	if err := callCtx.Err(); err != nil {
		return nil, err
	}
	return &PublicIPLookupResult{JSON: result.Json, PlanID: result.PlanID,
		CoreGeneration: result.CoreGeneration, NetworkGeneration: result.NetworkGeneration,
		OutboundTag: result.OutboundTag}, nil
}

func (c *CommandClient) CancelPublicIP(requestID string) error {
	return c.publicIPRequests.cancel(requestID)
}
