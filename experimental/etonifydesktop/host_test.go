package etonifydesktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing/service"
)

func fillEventQueue(h *Host) {
	for {
		select {
		case h.events <- Event{Method: "test-saturation"}:
		default:
			return
		}
	}
}

func awaitHostPhase(t *testing.T, h *Host, phase string) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		if h.Snapshot().Phase == phase {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("host did not reach phase %s", phase)
		default:
			runtime.Gosched()
		}
	}
}

func TestHostSaturatedStartingPublicationHonorsCancellation(t *testing.T) {
	h := newTestHost(t)
	fillEventQueue(h)
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		defer close(done)
		_, err := h.Start(ctx, startRequest(localConfig(port), 1))
		result <- err
	}()
	t.Cleanup(func() { h.Close(); <-done })
	awaitHostPhase(t, h, "starting")
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("starting publication outlived caller cancellation")
	}
	if s := h.Snapshot(); s.Phase != "failed" || h.daemon.Instance() != nil {
		t.Fatalf("cancelled start left actual runtime: %+v", s)
	}
}

func TestHostSaturatedConnectedPublicationHonorsCancellation(t *testing.T) {
	var h *Host
	var err error
	h, err = NewHost(context.Background(), HostOptions{DataRoot: t.TempDir(), Emit: func(e Event) {
		if e.Method != "snapshot" {
			return
		}
		var s Snapshot
		json.Unmarshal(e.Payload, &s)
		if s.Phase == "starting" && s.ConfigGeneration == 1 {
			fillEventQueue(h)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	result := make(chan Event, 1)
	port := freePort(t)
	start := startRequest(localConfig(port), 1)
	payload, err := json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Version: 1, Kind: "request", ID: "saturated-connected", SessionID: start.SessionID, ConfigGeneration: start.ConfigGeneration, NetworkGeneration: start.NetworkGeneration, Method: "start", Payload: payload}
	go func() { defer close(done); result <- Dispatch(ctx, h, request) }()
	t.Cleanup(func() { h.Close(); <-done })
	awaitHostPhase(t, h, "connected")
	cancel()
	select {
	case response := <-result:
		if response.Error == nil || response.Error.Code != "cancelled" || len(response.Payload) != 0 || response.ID != request.ID {
			t.Fatalf("lost wire cancellation/correlation: %+v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("connected publication outlived caller cancellation")
	}
	if s := h.Snapshot(); s.Phase != "failed" || h.daemon.Instance() != nil {
		t.Fatalf("undelivered start remained successful: %+v", s)
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err == nil {
		c.Close()
		t.Fatal("undelivered connected transition leaked listener")
	}
	// A cancelled operation cannot leave delayed cleanup for a later generation.
	for len(h.events) > 0 {
		<-h.events
	}
	if _, err = h.Start(context.Background(), startRequest(localConfig(freePort(t)), 2)); err != nil {
		t.Fatalf("later generation blocked/failed: %v", err)
	}
	if h.daemon.Instance() == nil || h.Snapshot().Phase != "connected" {
		t.Fatal("cancelled generation tore down the following start")
	}
}

func TestHostSaturatedFatalPublicationJoinsOnSubscriptionCancellation(t *testing.T) {
	h := newTestHost(t)
	if _, err := h.Start(context.Background(), startRequest(localConfig(freePort(t)), 1)); err != nil {
		t.Fatal(err)
	}
	fillEventQueue(h)
	h.daemon.SetError(errors.New("private fatal detail"))
	awaitHostPhase(t, h, "failed")
	done := make(chan struct{})
	go func() { h.operation.Lock(); defer h.operation.Unlock(); h.endStreams(); close(done) }()
	t.Cleanup(func() { h.Close(); <-done })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fatal publication prevented cancelled subscription join")
	}
	if h.daemon.Instance() != nil {
		t.Fatal("fatal cleanup left active instance")
	}
	if s := h.Snapshot(); s.Phase != "failed" || s.Error == nil || strings.Contains(s.Error.Message, "private") {
		t.Fatalf("actual fatal snapshot lost/sensitive: %+v", s)
	}
}

func TestHostSaturatedStopPublicationHonorsDeadline(t *testing.T) {
	h := newTestHost(t)
	fillEventQueue(h)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	result := make(chan error, 1)
	go func() { defer close(done); result <- h.Stop(ctx, "test") }()
	t.Cleanup(func() { h.Close(); <-done })
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("stop delivery reported success/lost deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop publication outlived caller deadline")
	}
	if h.Snapshot().Phase != "stopped" {
		t.Fatal("delivery failure falsified actual stopped phase")
	}
}

// Passive boundary instrumentation: preserve the actual direct outbound and
// expose existing core interface-reset completion without changing the monitor.
type observedDirect struct {
	*direct.Outbound
	updates chan struct{}
	count   *atomic.Int64
}

func (o *observedDirect) InterfaceUpdated(ctx context.Context) {
	o.Outbound.InterfaceUpdated(ctx)
	o.count.Add(1)
	select {
	case o.updates <- struct{}{}:
	default:
	}
}

func observedHost(t *testing.T) (*Host, <-chan struct{}, *atomic.Int64) {
	t.Helper()
	ctx := include.Context(context.Background())
	registry := service.FromContext[adapter.OutboundRegistry](ctx).(*outbound.Registry)
	updates := make(chan struct{}, 8)
	count := &atomic.Int64{}
	outbound.Register[option.DirectOutboundOptions](registry, C.TypeDirect, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DirectOutboundOptions) (adapter.Outbound, error) {
		v, err := direct.NewOutbound(ctx, router, logger, tag, options)
		if err != nil {
			return nil, err
		}
		return &observedDirect{v.(*direct.Outbound), updates, count}, nil
	})
	h, err := NewHost(ctx, HostOptions{DataRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h, updates, count
}

func TestHostDaemonFatalStatusClearsConnectedAndClosesListener(t *testing.T) {
	h := newTestHost(t)
	if _, err := h.Start(context.Background(), startRequest(localConfig(freePort(t)), 1)); err != nil {
		t.Fatal(err)
	}
	h.daemon.SetError(errors.New("secret token must not leave host"))
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s := h.Snapshot()
		if s.Phase == "failed" && h.daemon.Instance() == nil {
			if s.Error == nil || strings.Contains(s.Error.Message, "secret") {
				t.Fatalf("raw daemon error escaped: %+v", s)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("fatal daemon remained connected/active")
}

func TestHostParentCancellationClosesActualListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	h, err := NewHost(ctx, HostOptions{DataRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	port := freePort(t)
	if _, err = h.Start(context.Background(), startRequest(localConfig(port), 1)); err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err != nil {
			return
		}
		c.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("parent lifetime ended but proxy still listens")
}

func TestHostCloseRejectsLatePublisher(t *testing.T) {
	h := newTestHost(t)
	h.Close()
	for i := 0; i < 100; i++ {
		if err := h.emit(context.Background(), Event{Method: "traffic"}); err == nil {
			t.Fatal("closed host accepted event")
		}
	}
}

func TestHostUnavailableNativeAgentNeverStartsHost(t *testing.T) {
	err := RunAgent(context.Background(), AgentOptions{InstallationID: "test", DataRoot: t.TempDir(), Nonce: "nonce", ParentPID: 123})
	if err == nil || !strings.Contains(err.Error(), "B2") {
		t.Fatalf("unauthenticated agent accepted: %v", err)
	}
}

func TestHostRejectsUnsupportedModesAndConfigSideEffects(t *testing.T) {
	for _, tt := range []struct {
		name, config string
		modes        Modes
	}{
		{"tun-mode", "", Modes{TunEnabled: true, ProcessRoutingMode: "allExceptSelected"}},
		{"system-proxy-mode", "", Modes{SystemProxyEnabled: true, ProcessRoutingMode: "allExceptSelected"}},
		{"hidden-tun", `{"inbounds":[{"type":"tun"}]}`, DefaultModes()},
		{"wildcard", `{"inbounds":[{"type":"mixed","listen":"0.0.0.0","listen_port":1080}]}`, DefaultModes()},
		{"system-proxy-config", `{"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":1080,"set_system_proxy":true}]}`, DefaultModes()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHost(t)
			_, err := h.Start(context.Background(), StartRequest{Config: tt.config, Modes: tt.modes, SessionID: "x", ConfigGeneration: 1})
			if err == nil || h.daemon.Instance() != nil {
				t.Fatal("unsupported mode/config started")
			}
		})
	}
}

func hostCall(t *testing.T, h *Host, method, payload string) map[string]any {
	t.Helper()
	s := h.Snapshot()
	raw, err := h.Call(context.Background(), Request{Method: method, SessionID: s.SessionID, ConfigGeneration: s.ConfigGeneration, NetworkGeneration: s.NetworkGeneration, Payload: json.RawMessage(payload)})
	if err != nil {
		t.Fatalf("%s: %v (local diagnostic cause: %v)", method, err, errors.Unwrap(err))
	}
	var result map[string]any
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestHostConfigPathAndMetadata(t *testing.T) {
	h := newTestHost(t)
	p := hostCall(t, h, "getConfigPath", `{}`)["path"].(string)
	if p != filepath.Join(h.options.DataRoot, "config.json") {
		t.Fatalf("unexpected prepared path %q", p)
	}
	if err := os.WriteFile(p, []byte("promoted-config"), 0600); err != nil {
		t.Fatal(err)
	}
	hostCall(t, h, "checkConfig", fmt.Sprintf(`{"config":%q}`, localConfig(freePort(t))))
	hostCall(t, h, "getCoreVersion", `{}`)
	caps := hostCall(t, h, "getCoreCapabilities", `{}`)
	if caps["api_version"] != float64(4) || caps["supports_url_test_handoff"] != false || caps["supports_config_check"] != true {
		t.Fatalf("untruthful capabilities: %+v", caps)
	}
	_, err := h.Start(context.Background(), startRequest(localConfig(freePort(t)), 1))
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(p)
	if err != nil || string(bytes) != "promoted-config" {
		t.Fatal("start overwrote prepared config")
	}
}

func TestHostFailedConfigRetainsActualSnapshotAndConsumesGeneration(t *testing.T) {
	h := newTestHost(t)
	s, err := h.Start(context.Background(), startRequest(localConfig(freePort(t)), 1))
	if err != nil {
		t.Fatal(err)
	}
	invalid := startRequest(`{"inbounds":true}`, 2)
	actual, err := h.Start(context.Background(), invalid)
	if err == nil || actual.SessionID != s.SessionID || actual.ConfigGeneration != 1 || actual.Phase != "connected" {
		t.Fatalf("invalid proposal changed actual state: %+v %v", actual, err)
	}
	invalid.Config = localConfig(freePort(t))
	if _, err := h.Start(context.Background(), invalid); err == nil {
		t.Fatal("failed generation reused")
	}
	if _, err := h.Start(context.Background(), startRequest(localConfig(freePort(t)), 3)); err != nil {
		t.Fatal(err)
	}
}

func TestHostRPCUsesExistingDaemonAndLegacyShapes(t *testing.T) {
	h, initialReset, _ := observedHost(t)
	config := localConfig(freePort(t))
	var object map[string]any
	json.Unmarshal([]byte(config), &object)
	object["outbounds"] = []any{map[string]any{"type": "direct", "tag": "direct"}, map[string]any{"type": "selector", "tag": "select", "outbounds": []string{"direct"}}}
	encoded, _ := json.Marshal(object)
	if _, err := h.Start(context.Background(), startRequest(string(encoded), 1)); err != nil {
		t.Fatal(err)
	}
	// Start/listener ready is not physical-network settled. The existing core
	// dispatches its initial ResetNetwork asynchronously; it closes active
	// tracked connections before calling this real direct outbound callback.
	select {
	case <-initialReset:
	case <-time.After(time.Second):
		t.Fatal("initial core interface reset did not complete")
	}
	groups := hostCall(t, h, "groups", `{}`)["groups"].([]any)
	if len(groups) != 1 || groups[0].(map[string]any)["tag"] != "select" {
		t.Fatalf("groups mapping: %+v", groups)
	}
	hostCall(t, h, "selectOutbound", `{"groupTag":"select","outboundTag":"direct"}`)
	if h.Snapshot().SelectedTag != "direct" {
		t.Fatal("selection snapshot not updated")
	}
	s := h.Snapshot()
	if _, err := h.Call(context.Background(), Request{Method: "selectOutbound", SessionID: s.SessionID, ConfigGeneration: s.ConfigGeneration, NetworkGeneration: s.NetworkGeneration, Payload: json.RawMessage(`{"groupTag":"select","outboundTag":"missing"}`)}); err == nil {
		t.Fatal("invalid selector member accepted")
	}
	hostCall(t, h, "traffic", `{}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Desktop", "yes")
		w.Write([]byte("local-only"))
	}))
	defer server.Close()
	result := hostCall(t, h, "fetchUrlViaOutbound", fmt.Sprintf(`{"outboundTag":"direct","url":%q,"headers":{"X-Test":"unit"},"maxBytes":1024,"timeoutMillis":1000}`, server.URL))
	body := result["body"].([]any)
	if len(body) != 10 || body[0] != float64('l') || result["statusCode"] != float64(200) || result["headersJson"] == nil {
		t.Fatalf("fetch mapping: %+v", result)
	}
	hostCall(t, h, "urlTest", fmt.Sprintf(`{"groupTag":"select","url":%q,"timeoutMillis":1000,"deadlineMillis":2000,"force":true,"mode":"manual","logicalSessionId":"test","physicalNetworkEpoch":2}`, server.URL))
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-h.Events():
			if e.Method != "urlTest" {
				continue
			}
			var p map[string]any
			json.Unmarshal(e.Payload, &p)
			if r, ok := p["result"].(map[string]any); ok && r["tag"] == "direct" {
				if r["revision"] == nil {
					t.Fatal("missing result revision")
				}
				hostCall(t, h, "cancelUrlTest", `{"groupTag":"select"}`)
				return
			}
		case <-deadline:
			t.Fatal("missing existing daemon URLTest delta")
		}
	}
}

func TestHostSequentialStartStopRestartClosesEveryListener(t *testing.T) {
	h := newTestHost(t)
	for generation := int64(1); generation <= 3; generation++ {
		port := freePort(t)
		s, err := h.Start(context.Background(), startRequest(localConfig(port), generation))
		if err != nil || s.Phase != "connected" || s.ConfigGeneration != generation {
			t.Fatalf("restart %d: %+v %v", generation, s, err)
		}
		if err = h.Stop(context.Background(), "sequential-regression"); err != nil {
			t.Fatal(err)
		}
		if h.daemon.Instance() != nil || h.Snapshot().Phase != "stopped" {
			t.Fatal("instance survived stop")
		}
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			c.Close()
			t.Fatalf("generation %d listener survived stop", generation)
		}
	}
}

func localConfig(port int) string {
	return fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":"mixed","tag":"desktop","listen":"127.0.0.1","listen_port":%d,"set_system_proxy":false}],"outbounds":[{"type":"direct","tag":"direct"}]}`, port)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func newTestHost(t *testing.T) *Host {
	t.Helper()
	h, err := NewHost(context.Background(), HostOptions{DataRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func startRequest(config string, generation int64) StartRequest {
	return StartRequest{Config: config, Modes: DefaultModes(), SessionID: "gui-session", ConfigGeneration: generation, NetworkGeneration: 2}
}

func TestHostLocalProxyStartsWithoutTUN(t *testing.T) {
	h := newTestHost(t)
	port := freePort(t)
	s, err := h.Start(context.Background(), startRequest(localConfig(port), 1))
	if err != nil {
		t.Fatal(err)
	}
	if s.Phase != "connected" || !s.Capabilities.LocalProxy || s.Capabilities.Tun || s.Capabilities.SystemProxy || s.Modes.TunEnabled {
		t.Fatalf("untruthful actual state: %+v", s)
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("connected before listener: %v", err)
	}
	c.Close()
	if err := h.Stop(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	if h.Snapshot().Phase != "stopped" || h.daemon.Instance() != nil {
		t.Fatal("active host after stop")
	}
	c, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err == nil {
		c.Close()
		t.Fatal("listener survived stop")
	}
}

func TestHostDoesNotReportConnectedBeforeListenerReady(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	h := newTestHost(t)
	s, err := h.Start(context.Background(), startRequest(localConfig(l.Addr().(*net.TCPAddr).Port), 1))
	if err == nil || s.Phase == "connected" || h.daemon.Instance() != nil {
		t.Fatalf("failed listener accepted: %+v %v", s, err)
	}
	for {
		select {
		case e := <-h.Events():
			if e.Method == "snapshot" {
				var s Snapshot
				json.Unmarshal(e.Payload, &s)
				if s.Phase == "connected" {
					t.Fatal("false connected event")
				}
			}
		default:
			return
		}
	}
}

func TestDispatchRejectsUnknownMethod(t *testing.T) {
	h := &fakeHostBackend{state: Snapshot{Phase: "stopped", Modes: DefaultModes()}}
	r := Request{Version: 1, Kind: "request", ID: "123", SessionID: "pending", ConfigGeneration: 91, NetworkGeneration: 32, Method: "shell", Payload: json.RawMessage(`{}`)}
	e := Dispatch(context.Background(), h, r)
	if e.Error == nil || e.Error.Code != "unsupported_method" || len(e.Payload) != 0 {
		t.Fatalf("unknown method accepted: %+v", e)
	}
	if e.ID != r.ID || e.SessionID != r.SessionID || e.ConfigGeneration != r.ConfigGeneration || e.NetworkGeneration != r.NetworkGeneration || e.Method != r.Method || e.Kind != "response" {
		t.Fatalf("correlation changed: %+v", e)
	}
	r.Method = "snapshot"
	e = Dispatch(context.Background(), h, r)
	var actual Snapshot
	if err := json.Unmarshal(e.Payload, &actual); err != nil {
		t.Fatal(err)
	}
	if actual.SessionID == r.SessionID || actual.ConfigGeneration == r.ConfigGeneration {
		t.Fatal("snapshot body relabeled as request")
	}
}

// The deliberately permissive fake proves dispatch itself bounds the interface,
// rather than relying on each injected backend to reject dangerous RPC names.
type fakeHostBackend struct{ state Snapshot }

func (f *fakeHostBackend) Start(context.Context, StartRequest) (Snapshot, error) { return f.state, nil }
func (f *fakeHostBackend) Stop(context.Context, string) error                    { return nil }
func (f *fakeHostBackend) Snapshot() Snapshot                                    { return f.state }
func (f *fakeHostBackend) Call(context.Context, Request) (json.RawMessage, error) {
	return json.RawMessage(`{}`), nil
}
func (f *fakeHostBackend) Events() <-chan Event { return nil }
