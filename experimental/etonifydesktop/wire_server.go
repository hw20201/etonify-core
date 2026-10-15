package etonifydesktop

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// ServeConnection serves exactly one already-authenticated owner's backend.
// It does not establish identity; RunAgent must authorize the pipe first.
// Events and responses share one bounded writer, including chunks emitted
// while a request is still running. No goroutine survives disconnection.
func ServeConnection(parent context.Context, conn net.Conn, backend HostBackend) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer conn.Close()
	type packet struct {
		event Event
		fence *responseFence
	}
	outgoing := make(chan packet, 8)
	var responseFences sync.Map
	faults := make(chan error, 1)
	var workers sync.WaitGroup
	fail := func(err error) {
		select {
		case faults <- err:
		default:
		}
		cancel()
		conn.Close()
	}
	enqueue := func(event Event, fence *responseFence) bool {
		select {
		case outgoing <- packet{event, fence}:
			return true
		case <-ctx.Done():
			return false
		}
	}
	workers.Add(3)
	go func() { defer workers.Done(); <-ctx.Done(); conn.Close() }()
	go func() {
		defer workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case item := <-outgoing:
				frame, err := EncodeFrame(item.event)
				if err != nil {
					fail(runtimeFailure("protocol_error", "Invalid desktop response"))
					return
				}
				for len(frame) > 0 {
					written, err := conn.Write(frame)
					if err != nil {
						fail(err)
						return
					}
					if written <= 0 {
						fail(io.ErrShortWrite)
						return
					}
					frame = frame[written:]
				}
				if item.fence != nil {
					if item.event.Kind == "response" {
						item.fence.responseWritten()
					} else {
						item.fence.chunkWritten()
					}
				}
			}
		}
	}()
	go func() {
		defer workers.Done()
		events := backend.Events()
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-events:
				if !ok {
					fail(io.EOF)
					return
				}
				var fence *responseFence
				if event.Method == "streamChunk" && event.ID != "" {
					if value, ok := responseFences.Load(event.ID); ok {
						fence = value.(*responseFence)
					}
				}
				if !enqueue(event, fence) {
					return
				}
			}
		}
	}()
	slots := make(chan struct{}, 8)
	type pending struct {
		method string
		cancel context.CancelFunc
	}
	active := make(map[string]pending)
	var activeLock sync.Mutex
	lifecycleTail := make(chan struct{})
	close(lifecycleTail)
	decoder := NewFrameDecoder(conn)
	for ctx.Err() == nil {
		request, err := decoder.Next()
		if err != nil {
			fail(err)
			break
		}
		if request.Kind != "request" || request.ID == "" || len(request.ID) > 128 || len(request.SessionID) > 128 || len(request.Method) > 128 {
			fail(runtimeFailure("protocol_error", "Invalid desktop request"))
			break
		}
		activeLock.Lock()
		_, duplicate := active[request.ID]
		if duplicate {
			activeLock.Unlock()
			fail(runtimeFailure("protocol_error", "Duplicate pending request"))
			break
		}
		if request.Method == "stop" {
			for _, prior := range active {
				if prior.method == "start" || prior.method == "applyModes" {
					prior.cancel()
				}
			}
		}
		// Reserve the eighth slot for Stop so ordinary RPC saturation cannot
		// prevent a user from revoking accepted starts.
		admitted := request.Method == "stop" || len(slots) < 7
		if admitted {
			select {
			case slots <- struct{}{}:
			default:
				admitted = false
			}
		}
		if !admitted {
			activeLock.Unlock()
			response := request
			response.Kind, response.Payload = "response", nil
			response.Error = &RuntimeError{Code: "busy", Message: "Too many pending desktop requests"}
			enqueue(response, nil)
			continue
		}
		operation, cancelOperation := context.WithTimeout(ctx, 15*time.Second)
		active[request.ID] = pending{request.Method, cancelOperation}
		activeLock.Unlock()
		var before <-chan struct{}
		var finished chan struct{}
		if request.Method == "start" || request.Method == "applyModes" || request.Method == "stop" {
			before, finished = lifecycleTail, make(chan struct{})
			lifecycleTail = finished
		}
		workers.Add(1)
		go func(request Request) {
			defer workers.Done()
			defer func() { activeLock.Lock(); delete(active, request.ID); activeLock.Unlock(); <-slots }()
			defer cancelOperation()
			fence := newResponseFence()
			defer fence.finish()
			responseFences.Store(request.ID, fence)
			defer responseFences.Delete(request.ID)
			operation = context.WithValue(operation, responseFenceKey{}, fence)
			// Keep the chain until predecessors exit, even if this operation was
			// revoked while queued. Stop must never overtake a still-live Start.
			if before != nil {
				select {
				case <-before:
				case <-ctx.Done():
				}
			}
			var response Event
			if operation.Err() != nil {
				response = request
				response.Kind, response.Payload = "response", nil
				response.Error = &RuntimeError{Code: "cancelled", Message: "Runtime operation cancelled"}
			} else {
				response = Dispatch(operation, backend, request)
			}
			if finished != nil {
				close(finished)
			}
			fence.seal()
			if enqueue(response, fence) {
				select {
				case <-fence.done:
				case <-ctx.Done():
				}
			}
		}(request)
	}
	cancel()
	conn.Close()
	workers.Wait()
	// Cancellation is already visible: Stop tears down actual resources without
	// waiting forever to publish into a now-undrained event channel.
	_ = backend.Stop(ctx, "transport_lost")
	if parent.Err() != nil {
		return parent.Err()
	}
	select {
	case err := <-faults:
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return runtimeFailure("transport_lost", "Desktop connection ended")
	default:
		return nil
	}
}
