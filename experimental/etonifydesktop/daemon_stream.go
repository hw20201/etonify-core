package etonifydesktop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

const MaximumChunkFrame = 64 * 1024
const MaximumAssemblyLength = MaximumBodyLength
const chunkDataLength = 44 * 1024

var streamSequence atomic.Uint64
var errCaptured = errors.New("desktop stream sample captured")

// daemonStream adapts existing typed gRPC streaming handlers in-process. There
// is no network listener, gRPC server, broad RPC registry, or new URLTest engine.
type daemonStream[T any] struct {
	ctx  context.Context
	send func(*T) error
}

func (s *daemonStream[T]) Context() context.Context   { return s.ctx }
func (s *daemonStream[T]) Send(value *T) error        { return s.send(value) }
func (*daemonStream[T]) SetHeader(metadata.MD) error  { return nil }
func (*daemonStream[T]) SendHeader(metadata.MD) error { return nil }
func (*daemonStream[T]) SetTrailer(metadata.MD)       {}
func (*daemonStream[T]) SendMsg(any) error {
	return runtimeFailure("unsupported_method", "Untyped stream send unavailable")
}
func (*daemonStream[T]) RecvMsg(any) error {
	return runtimeFailure("unsupported_method", "Stream receive unavailable")
}

func (h *Host) beginStreams(d *daemon.StartedService, generation Snapshot) {
	ctx, cancel := context.WithCancel(h.ctx)
	dataCtx, cancelData := context.WithCancel(ctx)
	h.streamCancel = cancel
	start := func(owner context.Context, run func() error) {
		h.streamWG.Add(1)
		go func() {
			defer h.streamWG.Done()
			if err := run(); err != nil && owner.Err() == nil {
				h.streamError(owner, generation)
			}
		}()
	}
	send := func(kind string, message proto.Message) error {
		event, err := MapDaemonEvent(kind, message, generation)
		if err != nil {
			return err
		}
		_, err = h.publishBounded(dataCtx, event)
		return err
	}
	start(dataCtx, func() error {
		return d.SubscribeGroups(&emptypb.Empty{}, &daemonStream[daemon.Groups]{dataCtx, func(v *daemon.Groups) error { return send("groups", v) }})
	})
	start(dataCtx, func() error {
		return d.SubscribeStatus(&daemon.SubscribeStatusRequest{Interval: int64(time.Second)}, &daemonStream[daemon.Status]{dataCtx, func(v *daemon.Status) error { return send("traffic", v) }})
	})
	start(dataCtx, func() error {
		return d.SubscribeLog(&emptypb.Empty{}, &daemonStream[daemon.Log]{dataCtx, func(v *daemon.Log) error { return send("logs", v) }})
	})
	start(dataCtx, func() error {
		return d.SubscribeURLTestUpdates(&emptypb.Empty{}, &daemonStream[daemon.URLTestUpdate]{dataCtx, func(v *daemon.URLTestUpdate) error { return send("urlTest", v) }})
	})
	start(ctx, func() error {
		return d.SubscribeServiceStatus(&emptypb.Empty{}, &daemonStream[daemon.ServiceStatus]{ctx, func(v *daemon.ServiceStatus) error {
			if v.Status != daemon.ServiceStatus_FATAL {
				return nil
			}
			// A daemon fatal must not leave the GUI connected or a proxy active.
			// Never forward raw config/credential-bearing daemon diagnostics.
			// Stop sibling producers without cancelling this fatal publication.
			// endStreams owns the outer cancellation and can always join us.
			cancelData()
			defer cancel()
			_ = d.CloseService()
			h.mu.Lock()
			s := h.state
			current := s.SessionID == generation.SessionID && s.ConfigGeneration == generation.ConfigGeneration
			if current {
				s.Phase = "failed"
				s.Modes = DefaultModes()
				s.Error = &RuntimeError{Code: "daemon_failed", Message: "Daemon reported a fatal runtime error"}
				h.state = s
			}
			h.mu.Unlock()
			if current {
				if err := h.publishSnapshot(ctx, s); err != nil {
					return err
				}
			}
			return errCaptured
		}})
	})
}

func (h *Host) endStreams() {
	if h.streamCancel != nil {
		h.streamCancel()
		h.streamWG.Wait()
		h.streamCancel = nil
	}
}

func (h *Host) streamError(ctx context.Context, generation Snapshot) {
	payload := json.RawMessage(`{"code":"stream_failed","message":"Daemon stream failed; request a fresh snapshot"}`)
	_ = h.emit(ctx, Event{Version: ProtocolVersion, Kind: "event", SessionID: generation.SessionID, ConfigGeneration: generation.ConfigGeneration, NetworkGeneration: generation.NetworkGeneration, Method: "runtimeError", Payload: payload})
}

// chunkEvent returns either the original <=64KiB event or bounded base64-JSON
// chunks. Receivers must enforce the same 16MiB assembly cap, exact identity,
// contiguous indices, total/totalBytes, one active stream per id, and EOF expiry.
// Assembly/decode belongs off the UI isolate in B2, not in the Dart adapter.
func chunkEvent(event Event) ([]Event, json.RawMessage, error) {
	if len(event.Payload) > MaximumAssemblyLength {
		return nil, nil, runtimeFailure("resource_limit", "Stream assembly exceeds 16 MiB")
	}
	if err := event.Validate(); err != nil {
		return nil, nil, err
	}
	if len(event.Payload) <= MaximumChunkFrame {
		frame, err := EncodeFrame(event)
		if err != nil {
			return nil, nil, err
		}
		if len(frame) <= MaximumChunkFrame {
			return []Event{event}, nil, nil
		}
	}
	id := fmt.Sprintf("%d", streamSequence.Add(1))
	total := (len(event.Payload) + chunkDataLength - 1) / chunkDataLength
	result := make([]Event, 0, total)
	for offset, index := 0, 0; offset < len(event.Payload); offset, index = offset+chunkDataLength, index+1 {
		end := min(offset+chunkDataLength, len(event.Payload))
		p, err := json.Marshal(map[string]any{"streamId": id, "method": event.Method, "encoding": "base64-json", "index": index, "total": total, "totalBytes": len(event.Payload), "data": base64.StdEncoding.EncodeToString(event.Payload[offset:end])})
		if err != nil {
			return nil, nil, err
		}
		chunk := event
		chunk.Method, chunk.Payload = "streamChunk", p
		f, err := EncodeFrame(chunk)
		if err != nil || len(f) > MaximumChunkFrame {
			return nil, nil, runtimeFailure("resource_limit", "Chunk frame exceeds 64 KiB")
		}
		result = append(result, chunk)
	}
	descriptor, err := json.Marshal(map[string]any{"streamId": id, "method": event.Method, "encoding": "base64-json", "total": total, "totalBytes": len(event.Payload)})
	return result, descriptor, err
}

func (h *Host) publishBounded(ctx context.Context, event Event) (json.RawMessage, error) {
	h.initChunkFlow()
	// One subscription's chunks are contiguous in Events even when RPC chunks
	// interleave. Stop can cancel both the current publication and its waiters.
	select {
	case h.subscriptionChunkSlot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-h.ctx.Done():
		return nil, h.ctx.Err()
	}
	defer func() { <-h.subscriptionChunkSlot }()
	chunks, descriptor, err := chunkEvent(event)
	if err != nil {
		return nil, err
	}
	for _, chunk := range chunks {
		if err = h.emit(ctx, chunk); err != nil {
			return nil, err
		}
	}
	return descriptor, nil
}
