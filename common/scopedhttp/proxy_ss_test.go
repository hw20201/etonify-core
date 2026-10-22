package scopedhttp

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestPrivateShadowsocksOutboundEncryptedTCPAndClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	portText := listener.Addr().(*net.TCPAddr).Port
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		data := make([]byte, 256)
		n, _ := conn.Read(data)
		received <- data[:n]
	}()
	snapshot := []byte(`{"outbounds":[{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":` + strconv.Itoa(portText) + `,"method":"aes-128-gcm","password":"test-secret"}],"dns":{"final":"dns","servers":[{"type":"tcp","tag":"dns","server":"192.0.2.53","detour":"ss"}]}}`)
	plan, err := NewPlan(snapshot, []string{"ss"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := NewSession(ctx, context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := session.proxyDial(ctx, "tcp", M.ParseSocksaddr("203.0.113.7:443"))
	if err != nil {
		session.Close()
		t.Fatal(err)
	}
	if _, err = io.WriteString(conn, "scoped encrypted payload"); err != nil {
		session.Close()
		t.Fatal(err)
	}
	select {
	case data := <-received:
		if len(data) < 40 {
			t.Fatalf("expected encrypted Shadowsocks stream, got %d bytes", len(data))
		}
		if string(data) == "scoped encrypted payload" {
			t.Fatal("plaintext reached Shadowsocks server")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for encrypted TCP stream")
	}
	session.Close()
	if session.proxyScope == nil {
		t.Fatal("private outbound lifecycle scope missing")
	}
	if err := session.ctx.Err(); err == nil {
		t.Fatal("session close did not cancel query lifetime")
	}
}

func TestScopedShadowsocksRejectsUnauditedOptions(t *testing.T) {
	for _, field := range []string{`"plugin":"x"`, `"multiplex":{"enabled":true}`, `"udp_over_tcp":{"enabled":true}`, `"detour":"other"`} {
		snapshot := []byte(`{"outbounds":[{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":8388,"method":"aes-128-gcm","password":"secret",` + field + `}],"dns":{"final":"dns","servers":[{"type":"tcp","tag":"dns","server":"192.0.2.53","detour":"ss"}]}}`)
		if _, err := NewPlan(snapshot, []string{"ss"}); err == nil {
			t.Fatalf("accepted unaudited option %s", field)
		}
	}
}
