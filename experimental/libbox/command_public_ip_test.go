package libbox

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

type publicIPBufServer struct {
	daemon.UnimplementedStartedServiceServer
	entered   chan string
	mu        sync.Mutex
	cancelled map[string]bool
	finished  chan string
}

func (s *publicIPBufServer) LookupPublicIP(ctx context.Context, req *daemon.PublicIPLookupRequest) (*daemon.PublicIPLookupResponse, error) {
	s.entered <- req.RequestID
	<-ctx.Done()
	s.mu.Lock()
	s.cancelled[req.RequestID] = true
	s.mu.Unlock()
	s.finished <- req.RequestID
	return nil, ctx.Err()
}
func (s *publicIPBufServer) GetVersion(context.Context, *emptypb.Empty) (*daemon.Version, error) {
	return &daemon.Version{}, nil
}

func TestCommandClientPublicIPCancellationIsRequestScopedOverSharedGRPC(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	mock := &publicIPBufServer{entered: make(chan string, 8), finished: make(chan string, 8), cancelled: map[string]bool{}}
	daemon.RegisterStartedServiceServer(server, mock)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	c := &CommandClient{ctx: ctx, cancel: stop, grpcConn: conn, grpcClient: daemon.NewStartedServiceClient(conn)}
	results := make(chan error, 2)
	for _, id := range []string{"A", "B"} {
		id := id
		go func() { _, e := c.LookupPublicIP(id, "out", "ipQuery", 1, 5000); results <- e }()
	}
	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case id := <-mock.entered:
			seen[id] = true
		case <-time.After(3 * time.Second):
			t.Fatal("both lookups did not reach server")
		}
	}
	if err := c.CancelPublicIP("A"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-results:
		if err == nil {
			t.Fatal("cancelled lookup unexpectedly succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not interrupt lookup A")
	}
	// A's cancellation must not affect B or the shared command connection.
	select {
	case <-results:
		t.Fatal("lookup B was cancelled with A")
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := c.grpcClient.GetVersion(context.Background(), &emptypb.Empty{}); err != nil {
		t.Fatalf("shared GetVersion failed after cancellation: %v", err)
	}
	if err := c.CancelPublicIP("unknown-late"); err != nil {
		t.Fatalf("unknown cancel: %v", err)
	}
	// A canceled identity is tombstoned; duplicate IDs cannot take over the old request.
	if _, err := c.LookupPublicIP("A", "out", "ipQuery", 1, 100); err == nil {
		t.Fatal("reused canceled request ID was accepted")
	}
	if err := c.CancelPublicIP("B"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-results:
		if err == nil {
			t.Fatal("B cancellation unexpectedly succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not interrupt lookup B")
	}
	for i := 0; i < 2; i++ {
		select {
		case <-mock.finished:
		case <-time.After(time.Second):
			t.Fatal("server did not observe per-request context cancellation")
		}
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	if !mock.cancelled["A"] || !mock.cancelled["B"] {
		t.Fatalf("server contexts not independently cancelled: %#v", mock.cancelled)
	}
}

func TestPublicIPRequestRegistryCancelBeforeStartAndDeadline(t *testing.T) {
	var registry publicIPRequestRegistry
	if err := registry.cancel("early"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.begin(context.Background(), "early", time.Second); err == nil {
		t.Fatal("cancel-before-start identity accepted")
	}
	ctx, finish, err := registry.begin(context.Background(), "deadline", 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("deadline did not expire")
	}
	if _, _, err := registry.begin(context.Background(), "deadline", time.Second); err == nil {
		t.Fatal("duplicate identity accepted")
	}
}
