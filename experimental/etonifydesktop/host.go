package etonifydesktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing/service/filemanager"
	"google.golang.org/protobuf/types/known/emptypb"
)

type HostBackend interface {
	Start(context.Context, StartRequest) (Snapshot, error)
	Stop(context.Context, string) error
	Snapshot() Snapshot
	Call(context.Context, Request) (json.RawMessage, error)
	Events() <-chan Event
}

type HostOptions struct {
	DataRoot   string
	Privileged bool
	Emit       func(Event)
}

// PeerIdentity is a transport-verified identity, not a caller JSON assertion.
// B2 must hold ProcessHandle for the complete GUI/agent lease.
type PeerIdentity struct {
	SID           string
	SessionID     uint32
	PID           uint32
	ProcessHandle uintptr
	Nonce         string
}

type AgentOptions struct {
	InstallationID string
	DataRoot       string
	Nonce          string
	ParentPID      uint32
	Owner          PeerIdentity
}

// No backend is created until the platform runner verifies its owner and pipe.
func RunAgent(ctx context.Context, options AgentOptions) error {
	return runPlatformAgent(ctx, options)
}

type Host struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	options               HostOptions
	operation             sync.Mutex
	mu                    sync.RWMutex
	daemon                *daemon.StartedService
	state                 Snapshot
	issued                int64
	events                chan Event
	streamCancel          context.CancelFunc
	streamWG              sync.WaitGroup
	closeOnce             sync.Once
	emitMu                sync.RWMutex
	closed                bool
	chunkInit             sync.Once
	rpcChunkSlots         chan struct{}
	subscriptionChunkSlot chan struct{}
}

var _ HostBackend = (*Host)(nil)

// NewHost is the in-process facade only. It does not authenticate a peer or
// grant privileges; B2 must bind one host to its authenticated GUI lease.
func NewHost(ctx context.Context, options HostOptions) (*Host, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(options.DataRoot) {
		return nil, runtimeFailure("invalid_data_root", "Data root must be absolute")
	}
	if err := os.MkdirAll(options.DataRoot, 0700); err != nil {
		return nil, runtimeFailure("data_root_unavailable", "Data root is unavailable")
	}
	ctx, cancel := context.WithCancel(include.Context(ctx))
	ctx = filemanager.WithDefault(ctx, options.DataRoot, "", os.Getuid(), os.Getgid())
	h := &Host{ctx: ctx, cancel: cancel, options: options, events: make(chan Event, 128)}
	h.state = Snapshot{Phase: "stopped", Modes: DefaultModes(), CoreVersion: C.Version, DaemonAPIVersion: daemon.APIVersion, Capabilities: Capabilities{LocalProxy: true}}
	h.daemon = h.newDaemon()
	go func() { <-ctx.Done(); h.Close() }()
	return h, nil
}

func (h *Host) newDaemon() *daemon.StartedService {
	return daemon.NewStartedService(daemon.ServiceOptions{Context: h.ctx, Handler: desktopPlatformHandler{}, LogMaxLines: 512})
}

// desktopPlatformHandler implements only the existing daemon handler, not the
// boxdd managed/native platform. include.Context retains platform registrations
// supplied by the embedding caller; otherwise core uses its default platform.
type desktopPlatformHandler struct{}

func (desktopPlatformHandler) WriteDebugMessage(string) {}
func (desktopPlatformHandler) ConnectSSHAgent() (int32, error) {
	return -1, runtimeFailure("unsupported_method", "SSH agent is unavailable")
}

func (h *Host) Start(ctx context.Context, request StartRequest) (Snapshot, error) {
	h.operation.Lock()
	defer h.operation.Unlock()
	if err := ctx.Err(); err != nil {
		return h.Snapshot(), err
	}
	if h.ctx.Err() != nil {
		return h.Snapshot(), runtimeFailure("closed", "Host is closed")
	}
	if request.SessionID == "" || request.ConfigGeneration <= 0 || request.NetworkGeneration < 0 {
		return h.Snapshot(), runtimeFailure("invalid_request", "Invalid runtime identity")
	}
	h.mu.Lock()
	if request.ConfigGeneration <= h.issued {
		h.mu.Unlock()
		return h.Snapshot(), runtimeFailure("stale_generation", "Configuration generation was already issued")
	}
	h.issued = request.ConfigGeneration // Failed proposals cannot be reused.
	h.mu.Unlock()
	if request.Modes.TunEnabled || request.Modes.SystemProxyEnabled || len(request.Modes.ProcessPaths) != 0 || request.Modes.ProcessRoutingMode == "onlySelected" {
		return h.Snapshot(), runtimeFailure("unavailable", "Privileged modes and process ownership require B2/B3/B4/B5")
	}
	if request.Modes.ProcessRoutingMode != "allExceptSelected" {
		return h.Snapshot(), runtimeFailure("invalid_request", "Invalid process routing mode")
	}
	listener, err := localProxyAddress(request.Config)
	if err != nil {
		return h.Snapshot(), err
	}
	// Validate before replacing an active instance. Invalid proposals leave the
	// actual host tuple untouched; Dispatch still echoes the pending request tuple.
	if err = h.daemon.CheckConfig(ctx, request.Config); err != nil {
		return h.Snapshot(), runtimeFailure("invalid_config", "Configuration validation failed")
	}
	h.endStreams()
	_ = h.daemon.CloseService()
	h.daemon.Close()
	// A fresh daemon subscriber set per generation prevents buffered updates from
	// the previous instance being labelled with a new config/session identity.
	h.mu.Lock()
	h.daemon = h.newDaemon()
	s := h.state
	s.SessionID, s.ConfigGeneration, s.NetworkGeneration = request.SessionID, request.ConfigGeneration, request.NetworkGeneration
	s.Phase, s.SelectedTag, s.Error = "starting", "", nil
	s.Modes = DefaultModes()
	h.state = s
	d := h.daemon
	h.mu.Unlock()
	if err = h.publishSnapshot(ctx, s); err != nil {
		return h.failStart(ctx, d, s, err)
	}
	cancellationDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() { _ = d.CloseService(); close(cancellationDone) })
	err = d.StartOrReloadService(ctx, request.Config, nil)
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		started, e := d.GetStartedAt(ctx, &emptypb.Empty{})
		if e != nil || started == nil || started.StartedAt <= 0 || d.Instance() == nil {
			err = errors.New("daemon not ready")
		}
	}
	if err == nil {
		var c net.Conn
		c, err = (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", listener)
		if c != nil {
			_ = c.Close()
		}
	}
	// Join any callback before releasing the lifecycle operation, so cancelled
	// cleanup cannot later tear down an instance belonging to a subsequent Start.
	if !stopCancellation() {
		<-cancellationDone
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return h.failStart(ctx, d, s, err)
	}
	s.Phase, s.Modes = "connected", request.Modes
	if err = h.setState(ctx, s); err != nil {
		return h.failStart(ctx, d, s, err)
	}
	h.beginStreams(d, s)
	return s, nil
}

// An undelivered Start transition is not a successful runtime operation. Keep
// actual state available to snapshot(), close the instance, and preserve the
// cause for Dispatch without publishing raw daemon/config diagnostics.
func (h *Host) failStart(ctx context.Context, d *daemon.StartedService, s Snapshot, cause error) (Snapshot, error) {
	closeErr := d.CloseService()
	s.Phase, s.SelectedTag, s.Modes = "failed", "", DefaultModes()
	s.Error = &RuntimeError{Code: "start_failed", Message: "Daemon or local listener failed to start"}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		s.Error = &RuntimeError{Code: "cancelled", Message: "Runtime operation cancelled"}
	}
	deliveryErr := h.setState(ctx, s)
	return s, &hostError{code: s.Error.Code, message: s.Error.Message, cause: errors.Join(cause, closeErr, deliveryErr)}
}

func localProxyAddress(config string) (string, error) {
	var value struct {
		Inbounds []struct {
			Type        string `json:"type"`
			Listen      string `json:"listen"`
			Port        int    `json:"listen_port"`
			SystemProxy bool   `json:"set_system_proxy"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(config), &value); err != nil {
		return "", runtimeFailure("invalid_config", "Invalid configuration JSON")
	}
	var address string
	for _, in := range value.Inbounds {
		if in.Type == "tun" || in.SystemProxy {
			return "", runtimeFailure("unavailable", "TUN and system proxy are unavailable in this host")
		}
		if in.Type != "mixed" {
			return "", runtimeFailure("invalid_config", "Desktop local host requires loopback mixed inbounds")
		}
		ip, err := netip.ParseAddr(in.Listen)
		if err != nil || !ip.IsLoopback() || in.Port <= 0 || in.Port > 65535 {
			return "", runtimeFailure("invalid_config", "Local proxy must bind a fixed loopback port")
		}
		if address == "" {
			address = net.JoinHostPort(in.Listen, fmt.Sprint(in.Port))
		}
	}
	if address == "" {
		return "", runtimeFailure("invalid_config", "Local proxy listener is required")
	}
	return address, nil
}

func (h *Host) Stop(ctx context.Context, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.RLock()
	d := h.daemon
	h.mu.RUnlock()
	// Interrupt an in-progress start before waiting for the host lifecycle lock.
	if err := d.CloseService(); err != nil {
		return runtimeFailure("stop_failed", "Daemon stop failed")
	}
	h.operation.Lock()
	defer h.operation.Unlock()
	h.endStreams()
	_ = h.daemon.CloseService()
	s := h.Snapshot()
	s.Phase, s.Error, s.SelectedTag = "stopped", nil, ""
	s.Modes = DefaultModes()
	return h.setState(ctx, s)
}

func (h *Host) Snapshot() Snapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := h.state
	s.Modes.ProcessPaths = append([]string{}, s.Modes.ProcessPaths...)
	if s.Error != nil {
		e := *s.Error
		s.Error = &e
	}
	return s
}
func (h *Host) setState(ctx context.Context, s Snapshot) error {
	h.mu.Lock()
	h.state = s
	h.mu.Unlock()
	return h.publishSnapshot(ctx, s)
}
func (h *Host) publishSnapshot(ctx context.Context, s Snapshot) error {
	payload, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return h.emit(ctx, Event{Version: ProtocolVersion, Kind: "event", SessionID: s.SessionID, ConfigGeneration: s.ConfigGeneration, NetworkGeneration: s.NetworkGeneration, Method: "snapshot", Payload: payload})
}
func (h *Host) emit(ctx context.Context, e Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.emitMu.RLock()
	if h.closed || h.ctx.Err() != nil {
		h.emitMu.RUnlock()
		return context.Canceled
	}
	select {
	case <-ctx.Done():
		h.emitMu.RUnlock()
		return ctx.Err()
	case <-h.ctx.Done():
		h.emitMu.RUnlock()
		return h.ctx.Err()
	case h.events <- e:
	}
	if e.Method == "streamChunk" && e.ID != "" {
		if fence, ok := ctx.Value(responseFenceKey{}).(*responseFence); ok {
			fence.publishedChunk()
		}
	}
	h.emitMu.RUnlock()
	if h.options.Emit != nil {
		h.options.Emit(e)
	}
	return ctx.Err()
}
func (h *Host) Events() <-chan Event { return h.events }
func (h *Host) Close() {
	h.closeOnce.Do(func() {
		h.cancel()
		_ = h.Stop(context.Background(), "host_closed")
		h.daemon.Close()
		h.emitMu.Lock()
		h.closed = true
		close(h.events)
		h.emitMu.Unlock()
	})
}
