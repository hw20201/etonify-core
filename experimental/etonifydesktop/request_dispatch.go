package etonifydesktop

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/libbox"
	"google.golang.org/protobuf/types/known/emptypb"
)

type hostError struct {
	code, message string
	cause         error
}

func (e *hostError) Error() string              { return e.message }
func (e *hostError) Unwrap() error              { return e.cause }
func runtimeFailure(code, message string) error { return &hostError{code: code, message: message} }

func hostRPCMethod(method string) bool {
	switch method {
	case "getConfigPath", "getCoreVersion", "getCoreCapabilities", "checkConfig", "selectOutbound", "urlTest", "cancelUrlTest", "groups", "traffic", "logs", "lookupOutboundExternalInfo", "fetchUrlViaOutbound", "prepareStartupUrlTest", "startProbe", "stopProbe", "reload", "getNetworkInterfaceState":
		return true
	default:
		return false
	}
}

func (h *Host) Call(ctx context.Context, request Request) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.ctx.Err() != nil {
		return nil, runtimeFailure("closed", "Host is closed")
	}
	// No reflection or generic daemon invocation: this is the complete RPC list.
	if !hostRPCMethod(request.Method) {
		return nil, runtimeFailure("unsupported_method", "Unsupported desktop runtime method")
	}
	switch request.Method {
	case "prepareStartupUrlTest", "startProbe", "stopProbe", "reload", "getNetworkInterfaceState":
		return nil, runtimeFailure("unavailable", "Operation requires the B5 session/network manager")
	}
	h.mu.RLock()
	d, generation := h.daemon, h.state
	h.mu.RUnlock()
	if request.SessionID != generation.SessionID || request.ConfigGeneration != generation.ConfigGeneration || request.NetworkGeneration != generation.NetworkGeneration {
		return nil, runtimeFailure("stale_generation", "Request does not target the actual runtime generation")
	}
	var payload any
	var err error
	switch request.Method {
	case "getConfigPath":
		payload = map[string]any{"path": filepath.Join(h.options.DataRoot, "config.json")}
	case "getCoreVersion":
		payload = map[string]any{"version": generation.CoreVersion, "daemonApiVersion": generation.DaemonAPIVersion}
	case "getCoreCapabilities":
		var caps map[string]any
		if err = json.Unmarshal([]byte(libbox.EtonifyCapabilities()), &caps); err != nil {
			return nil, runtimeFailure("unavailable", "Core capabilities are unavailable")
		}
		// Compiled core protocol features are not native host availability.
		caps["supports_url_test_handoff"] = false
		caps["supports_close_connections"] = false
		caps["tun_stacks"] = []string{}
		payload = caps
	case "checkConfig":
		var p struct {
			Config string `json:"config"`
		}
		if err = json.Unmarshal(request.Payload, &p); err == nil {
			_, err = localProxyAddress(p.Config)
			if err == nil {
				err = d.CheckConfig(ctx, p.Config)
			}
		}
		if err != nil {
			return nil, runtimeFailure("invalid_config", "Configuration validation failed")
		}
		payload = map[string]any{}
	case "selectOutbound":
		var p daemon.SelectOutboundRequest
		if err = json.Unmarshal(request.Payload, &p); err == nil {
			_, err = d.SelectOutbound(ctx, &p)
		}
		if err == nil {
			h.mu.Lock()
			if h.state.SessionID == generation.SessionID && h.state.ConfigGeneration == generation.ConfigGeneration {
				h.state.SelectedTag = p.OutboundTag
			}
			h.mu.Unlock()
		}
		payload = map[string]any{}
	case "cancelUrlTest":
		var p struct {
			GroupTag string `json:"groupTag"`
			Target   string `json:"targetOutboundTag"`
		}
		if err = json.Unmarshal(request.Payload, &p); err == nil {
			_, err = d.CancelURLTest(ctx, &daemon.URLTestCancelRequest{OutboundTag: p.GroupTag, TargetOutboundTag: p.Target})
		}
		payload = map[string]any{}
	case "urlTest":
		var p struct {
			GroupTag    string   `json:"groupTag"`
			URL         string   `json:"url"`
			Target      string   `json:"targetOutboundTag"`
			Priority    string   `json:"priorityOutboundTag"`
			Exclude     string   `json:"excludeOutboundTag"`
			Timeout     int32    `json:"timeoutMillis"`
			Concurrency int32    `json:"concurrency"`
			Deadline    int32    `json:"deadlineMillis"`
			Force       bool     `json:"force"`
			Mode        string   `json:"mode"`
			Include     []string `json:"includeOutboundTags"`
			Logical     string   `json:"logicalSessionId"`
			Epoch       uint64   `json:"physicalNetworkEpoch"`
			Lease       int64    `json:"startupLeaseToken"`
		}
		if err = json.Unmarshal(request.Payload, &p); err == nil {
			if p.Lease != 0 {
				return nil, runtimeFailure("unavailable", "Startup URLTest lease requires B5")
			}
			_, err = d.URLTest(ctx, &daemon.URLTestRequest{OutboundTag: p.GroupTag, UrlTestUrl: p.URL, TargetOutboundTag: p.Target, PriorityOutboundTag: p.Priority, ExcludeOutboundTag: p.Exclude, TimeoutMillis: p.Timeout, Concurrency: p.Concurrency, DeadlineMillis: p.Deadline, Force: p.Force, Mode: p.Mode, IncludeOutboundTags: p.Include, LogicalSessionId: p.Logical, PhysicalNetworkEpoch: p.Epoch})
		}
		payload = map[string]any{}
	case "lookupOutboundExternalInfo":
		var p daemon.OutboundExternalInfoRequest
		if err = json.Unmarshal(request.Payload, &p); err == nil {
			payload, err = d.LookupOutboundExternalInfo(ctx, &p)
		}
	case "fetchUrlViaOutbound":
		var p daemon.OutboundHTTPFetchRequest
		if err = json.Unmarshal(request.Payload, &p); err == nil {
			var result *daemon.OutboundHTTPFetchResponse
			result, err = d.FetchURLViaOutbound(ctx, &p)
			if err == nil {
				body := make([]int, len(result.Body))
				for i, b := range result.Body {
					body[i] = int(b)
				}
				headers, _ := json.Marshal(result.Headers)
				payload = map[string]any{"statusCode": result.StatusCode, "body": body, "headersJson": string(headers), "finalUrl": result.FinalUrl}
			}
		}
	case "groups":
		var result *daemon.Groups
		err = d.SubscribeGroups(&emptypb.Empty{}, &daemonStream[daemon.Groups]{ctx, func(v *daemon.Groups) error { result = v; return errCaptured }})
		if errors.Is(err, errCaptured) {
			err = nil
			var e Event
			e, err = MapDaemonEvent("groups", result, generation)
			payload = e.Payload
		}
	case "traffic":
		var result *daemon.Status
		err = d.SubscribeStatus(&daemon.SubscribeStatusRequest{}, &daemonStream[daemon.Status]{ctx, func(v *daemon.Status) error { result = v; return errCaptured }})
		if errors.Is(err, errCaptured) {
			err = nil
			payload = result
		}
	case "logs":
		lines := d.SavedLog()
		logs := make([]*daemon.Log_Message, 0, len(lines))
		for _, line := range lines {
			logs = append(logs, &daemon.Log_Message{Level: daemon.LogLevel(line.Level), Message: line.Message})
		}
		payload = map[string]any{"logs": logs, "reset": true}
	}
	if err != nil {
		return nil, &hostError{code: "daemon_error", message: "Daemon operation failed", cause: err}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	event := Event{Version: ProtocolVersion, Kind: "event", ID: request.ID, SessionID: generation.SessionID, ConfigGeneration: generation.ConfigGeneration, NetworkGeneration: generation.NetworkGeneration, Method: request.Method, Payload: raw}
	chunks, descriptor, err := chunkEvent(event)
	if err != nil {
		return nil, err
	}
	if descriptor == nil {
		return raw, nil
	}
	release, err := h.leaseChunkReply(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	for _, chunk := range chunks {
		if err = h.emit(ctx, chunk); err != nil {
			return nil, err
		}
	}
	return descriptor, nil
}

// Dispatch does not authenticate. The transport must select its owned backend
// before dispatch; caller envelope identity is correlation, never authorization.
func Dispatch(ctx context.Context, backend HostBackend, request Request) Event {
	response := request
	response.Kind, response.Payload, response.Error = "response", nil, nil
	var payload json.RawMessage
	var err error
	if request.Kind != "request" {
		err = runtimeFailure("invalid_request", "Expected request envelope")
	} else {
		err = request.Validate()
	}
	if err == nil {
		switch request.Method {
		case "snapshot":
			payload, err = json.Marshal(backend.Snapshot())
		case "start", "applyModes":
			var start StartRequest
			if err = json.Unmarshal(request.Payload, &start); err == nil {
				if start.SessionID != request.SessionID || start.ConfigGeneration != request.ConfigGeneration || start.NetworkGeneration != request.NetworkGeneration {
					err = runtimeFailure("invalid_request", "Start identity does not match envelope")
				} else {
					var snapshot Snapshot
					snapshot, err = backend.Start(ctx, start)
					if err == nil {
						payload, err = json.Marshal(snapshot)
					}
				}
			}
		case "stop":
			var stop struct {
				Reason string `json:"reason"`
			}
			if err = json.Unmarshal(request.Payload, &stop); err == nil {
				err = backend.Stop(ctx, stop.Reason)
				payload = json.RawMessage(`{}`)
			}
		default:
			if !hostRPCMethod(request.Method) {
				err = runtimeFailure("unsupported_method", "Unsupported desktop runtime method")
			} else {
				payload, err = backend.Call(ctx, request)
			}
		}
	}
	if err != nil {
		response.Error = &RuntimeError{Code: "runtime_error", Message: "Runtime operation failed"}
		var typed *hostError
		if errors.As(err, &typed) {
			response.Error = &RuntimeError{Code: typed.code, Message: typed.message}
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			response.Error = &RuntimeError{Code: "cancelled", Message: "Runtime operation cancelled"}
		}
	} else {
		response.Payload = payload
	}
	return response
}
