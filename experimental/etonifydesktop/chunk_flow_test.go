package etonifydesktop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// The three RPC permits remain held through response delivery, leaving the
// fourth receiver assembly for serialized subscription publication.
func TestWireLargeReplyAdmissionWaitsForDescriptorWrite(t *testing.T) {
	h := newTestHost(t)
	var fences []*responseFence
	for i := 0; i < 3; i++ {
		fence := newResponseFence()
		fences = append(fences, fence)
		ctx := context.WithValue(context.Background(), responseFenceKey{}, fence)
		release, err := h.leaseChunkReply(ctx)
		if err != nil {
			t.Fatal(err)
		}
		release() // Returning from Call is not permission to start a fourth reply.
	}
	_, err := h.leaseChunkReply(context.Background())
	var failure *hostError
	if !errors.As(err, &failure) || failure.code != "busy" {
		t.Fatalf("fourth stream was admitted: %v", err)
	}
	fences[0].publishedChunk()
	fences[0].publishedChunk()
	fences[0].seal()
	fences[0].responseWritten()
	if _, err := h.leaseChunkReply(context.Background()); err == nil {
		t.Fatal("descriptor overtook chunks and released slot early")
	}
	fences[0].chunkWritten()
	if _, err := h.leaseChunkReply(context.Background()); err == nil {
		t.Fatal("partial body released slot early")
	}
	fences[0].chunkWritten()
	release, err := h.leaseChunkReply(context.Background())
	if err != nil {
		t.Fatal("completed descriptor did not release slot")
	}
	release()
	for _, fence := range fences {
		fence.finish()
	}
}

func TestWireSaturatedSubscriptionPublicationCancelsAllWaiters(t *testing.T) {
	h := newTestHost(t)
	large, _ := json.Marshal(map[string]string{"value": string(make([]byte, 50000))})
	fillEventQueue(h)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() {
		_, err := h.publishBounded(ctx, Event{Version: 1, Kind: "event", Method: "groups", Payload: large})
		first <- err
	}()
	go func() {
		_, err := h.publishBounded(ctx, Event{Version: 1, Kind: "event", Method: "logs", Payload: large})
		second <- err
	}()
	// Both producers are cancelled while saturated. Neither may outlive Stop.
	cancel()
	if !errors.Is(<-first, context.Canceled) || !errors.Is(<-second, context.Canceled) {
		t.Fatal("subscription cancellation lost")
	}
}

type chunkWireBackend struct {
	wireBackend
	host    *Host
	seen    chan bool
	release chan struct{}
	payload json.RawMessage
}

func (b *chunkWireBackend) Call(ctx context.Context, request Request) (json.RawMessage, error) {
	release, err := b.host.leaseChunkReply(ctx)
	if err != nil {
		b.seen <- false
		return nil, err
	}
	defer release()
	event := request
	event.Kind, event.Payload = "event", b.payload
	chunks, descriptor, err := chunkEvent(event)
	if err != nil {
		return nil, err
	}
	if err = b.host.emit(ctx, chunks[0]); err != nil {
		return nil, err
	}
	b.seen <- true
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	for _, chunk := range chunks[1:] {
		if err = b.host.emit(ctx, chunk); err != nil {
			return nil, err
		}
	}
	return descriptor, nil
}
func TestWireFiveLargeRepliesAndSubscriptionStayWithinReceiverBudget(t *testing.T) {
	h := newTestHost(t)
	large, _ := json.Marshal(map[string]string{"value": strings.Repeat("x", 100000)})
	b := &chunkWireBackend{host: h, seen: make(chan bool, 5), release: make(chan struct{}), payload: large}
	b.events = h.events
	server, client := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(4 * time.Second))
	done := make(chan error, 1)
	go func() { done <- ServeConnection(context.Background(), server, b) }()
	events := make(chan Event, 128)
	go func() {
		defer close(events)
		decoder := NewFrameDecoder(client)
		for {
			event, err := decoder.Next()
			if err != nil {
				return
			}
			events <- event
		}
	}()
	for i := 0; i < 5; i++ {
		r := wireRequest()
		r.ID = string(rune('1' + i))
		frame, _ := EncodeFrame(r)
		if _, err := client.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	admitted := 0
	for i := 0; i < 5; i++ {
		select {
		case accepted := <-b.seen:
			if accepted {
				admitted++
			}
		case <-time.After(time.Second):
			t.Fatal("reply admission stalled")
		}
	}
	if admitted != 3 {
		t.Fatalf("admitted %d large replies, want 3", admitted)
	}
	subDone := make(chan error, 1)
	go func() {
		_, err := h.publishBounded(context.Background(), Event{Version: 1, Kind: "event", Method: "groups", Payload: large})
		subDone <- err
	}()
	close(b.release)
	type assembly struct {
		chunks, total   int
		rpc, descriptor bool
	}
	active := make(map[string]*assembly)
	completed, responses, busy := 0, 0, 0
	for completed < 4 || responses < 5 {
		event, ok := <-events
		if !ok {
			t.Fatal("valid concurrent streams ended the transport")
		}
		if event.Kind == "response" {
			responses++
			if event.Error != nil {
				if event.Error.Code != "busy" {
					t.Fatal(event.Error)
				}
				busy++
				continue
			}
		}
		var part struct {
			StreamID string `json:"streamId"`
			Total    int    `json:"total"`
		}
		if err := json.Unmarshal(event.Payload, &part); err != nil || part.StreamID == "" {
			t.Fatal("invalid stream control")
		}
		state := active[part.StreamID]
		if state == nil {
			state = &assembly{total: part.Total, rpc: event.ID != ""}
			active[part.StreamID] = state
		}
		if event.Method == "streamChunk" {
			state.chunks++
		} else {
			state.descriptor = true
		}
		if len(active) > 4 {
			t.Fatal("sender exceeded four receiver assemblies")
		}
		if state.chunks == state.total && (!state.rpc || state.descriptor) {
			delete(active, part.StreamID)
			completed++
		}
	}
	if busy != 2 {
		t.Fatalf("want two bounded busy responses, got %d", busy)
	}
	if err := <-subDone; err != nil {
		t.Fatal(err)
	}
	client.Close()
	awaitWire(t, done)
}
