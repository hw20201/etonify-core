package scopedhttp

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type scopedSSEcho struct{}

func (*scopedSSEcho) NewConnection(_ context.Context, c net.Conn, metadata M.Metadata) error {
	if metadata.Destination.String() != "203.0.113.7:443" {
		return fmt.Errorf("wrong pinned destination: %v", metadata.Destination)
	}
	var data [4]byte
	if _, err := io.ReadFull(c, data[:]); err != nil {
		return err
	}
	if string(data[:]) != "ping" {
		return fmt.Errorf("decrypted payload mismatch: %q", data)
	}
	if _, err := c.Write([]byte("pong")); err != nil {
		return err
	}
	var end [1]byte
	if _, err := c.Read(end[:]); err == nil {
		return fmt.Errorf("private socket remained open after query close")
	}
	return nil
}
func (*scopedSSEcho) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return fmt.Errorf("unexpected UDP")
}
func (*scopedSSEcho) NewError(context.Context, error) {}

func TestScopedShadowsocksDecryptRoundTripAndClose(t *testing.T) {
	service, err := shadowaead.NewService("aes-128-gcm", nil, "test-secret", 60, &scopedSSEcho{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		finished <- service.NewConnection(context.Background(), c, M.Metadata{})
	}()
	snapshot := fmt.Sprintf(`{"outbounds":[{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":%d,"method":"aes-128-gcm","password":"test-secret","tcp_multi_path":false,"tcp_fast_open":false}],"dns":{"final":"dns","servers":[{"type":"tcp","tag":"dns","server":"192.0.2.53","detour":"ss"}]}}`, listener.Addr().(*net.TCPAddr).Port)
	plan, err := NewPlan([]byte(snapshot), []string{"ss"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, err := NewSession(ctx, context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := s.dialPinned("tcp", M.ParseSocksaddr("203.0.113.7:443"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(c, "ping"); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err = io.ReadFull(c, response[:]); err != nil || string(response[:]) != "pong" {
		t.Fatalf("response=%q err=%v", response, err)
	}
	s.Close()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("private socket not closed")
	}
}

func TestScopedFalseOptionsAreStrict(t *testing.T) {
	for _, value := range []string{"true", "null", "0", `"false"`} {
		for _, key := range []string{"tcp_fast_open", "tcp_multi_path"} {
			if key == "tcp_fast_open" && value == "true" {
				continue
			}
			snapshot := fmt.Sprintf(`{"outbounds":[{"type":"http","tag":"leaf","server":"192.0.2.1","server_port":8080,%q:%s}],"dns":{"final":"dns","servers":[{"type":"tcp","tag":"dns","server":"192.0.2.53","detour":"leaf"}]}}`, key, value)
			if _, err := NewPlan([]byte(snapshot), []string{"leaf"}); err == nil {
				t.Fatalf("accepted %s=%s", key, value)
			}
		}
	}
}
