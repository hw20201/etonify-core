package etonifydesktop

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type wireBackend struct {
	fakeHostBackend
	events    chan Event
	entered   chan struct{}
	cancelled chan struct{}
}

func (b *wireBackend) Events() <-chan Event { return b.events }
func (b *wireBackend) Call(ctx context.Context, _ Request) (json.RawMessage, error) {
	if b.entered != nil {
		close(b.entered)
		<-ctx.Done()
		close(b.cancelled)
		return nil, ctx.Err()
	}
	return json.RawMessage(`{"groups":[]}`), nil
}
func wireRequest() Request {
	return Request{Version: 1, Kind: "request", ID: "1", Method: "groups", Payload: json.RawMessage(`{}`)}
}
func awaitWire(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("wire goroutines did not terminate")
		return nil
	}
}
func TestWirePartialFramesPreserveCorrelation(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := &wireBackend{}
	done := make(chan error, 1)
	go func() { done <- ServeConnection(ctx, server, backend) }()
	frame, _ := EncodeFrame(wireRequest())
	for _, value := range frame {
		if _, err := client.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	response, err := NewFrameDecoder(client).Next()
	if err != nil {
		t.Fatal(err)
	}
	if response.Kind != "response" || response.ID != "1" || response.Method != "groups" || response.Error != nil {
		t.Fatalf("wrong response: %+v", response)
	}
	client.Close()
	awaitWire(t, done)
}
func TestWireDisconnectCancelsPendingRequest(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	backend := &wireBackend{entered: make(chan struct{}), cancelled: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- ServeConnection(context.Background(), server, backend) }()
	frame, _ := EncodeFrame(wireRequest())
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request never entered backend")
	}
	client.Close()
	awaitWire(t, done)
	select {
	case <-backend.cancelled:
	default:
		t.Fatal("request context survived disconnect")
	}
}

type observedWriter struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *observedWriter) Write(bytes []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(bytes)
}
func TestWireCancellationUnblocksPendingWrite(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	observed := &observedWriter{Conn: server, entered: make(chan struct{})}
	backend := &wireBackend{events: make(chan Event, 1)}
	event := wireRequest()
	event.Kind = "event"
	event.ID = ""
	event.Method = "traffic"
	backend.events <- event
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeConnection(ctx, observed, backend) }()
	select {
	case <-observed.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not enter blocked pipe")
	}
	cancel()
	awaitWire(t, done)
}
func TestWireOversizedLengthClosesConnection(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- ServeConnection(context.Background(), server, &wireBackend{}) }()
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, MaximumBodyLength+1)
	if _, err := client.Write(header); err != nil {
		t.Fatal(err)
	}
	if err := awaitWire(t, done); err == nil {
		t.Fatal("oversized header accepted")
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("malformed transport remained open")
	}
}

type lifecycleWireBackend struct {
	wireBackend
	entered, release chan struct{}
	running          atomic.Bool
}

func (b *lifecycleWireBackend) Start(ctx context.Context, r StartRequest) (Snapshot, error) {
	close(b.entered)
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	case <-b.release:
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		b.running.Store(true)
		return Snapshot{Phase: "connected", SessionID: r.SessionID, ConfigGeneration: r.ConfigGeneration}, nil
	}
}
func (b *lifecycleWireBackend) Stop(context.Context, string) error {
	b.running.Store(false)
	return nil
}
func TestWireStopRevokesEarlierStartBeforeItCanCreateResource(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	backend := &lifecycleWireBackend{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- ServeConnection(context.Background(), server, backend) }()
	start := wireRequest()
	start.Method, start.SessionID, start.ConfigGeneration = "start", "s", 1
	start.Payload, _ = json.Marshal(StartRequest{SessionID: "s", ConfigGeneration: 1, Modes: DefaultModes()})
	frame, _ := EncodeFrame(start)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.entered:
	case <-time.After(time.Second):
		t.Fatal("start not admitted")
	}
	stop := wireRequest()
	stop.ID, stop.Method = "2", "stop"
	frame, _ = EncodeFrame(stop)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	decoder := NewFrameDecoder(client)
	startReplied := false
	for {
		response, err := decoder.Next()
		if err != nil {
			t.Fatal(err)
		}
		if response.ID == "1" {
			startReplied = true
		}
		if response.ID == "2" {
			if response.Error != nil {
				t.Fatal(response.Error)
			}
			break
		}
	}
	close(backend.release)
	if !startReplied {
		response, err := decoder.Next()
		if err != nil || response.ID != "1" {
			t.Fatalf("missing start completion: %+v %v", response, err)
		}
	}
	resurrected := backend.running.Load()
	client.Close()
	awaitWire(t, done)
	if resurrected {
		t.Fatal("older Start created a live resource after successful Stop")
	}
}
