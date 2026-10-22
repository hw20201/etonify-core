//go:build with_utls

package scopedhttp

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	boxtls "github.com/sagernet/sing-box/common/tls"
	boxlog "github.com/sagernet/sing-box/log"
	boxvless "github.com/sagernet/sing-box/protocol/vless"
	M "github.com/sagernet/sing/common/metadata"
)

func TestRealityFailedAuthenticationCannotPublishEndpoint(t *testing.T) {
	f := newPinRealityFixture(t, "")
	wrongKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts := f.options
	tlsOptions := *opts.TLS
	realityOptions := *tlsOptions.Reality
	realityOptions.PublicKey = base64.RawURLEncoding.EncodeToString(wrongKey.PublicKey().Bytes())
	tlsOptions.Reality = &realityOptions
	opts.TLS = &tlsOptions
	out, err := boxvless.NewOutbound(f.instance, nil, boxlog.NewNOPFactory().Logger(), "reality", opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(boxtls.WithRealityFallbackDisabled(f.instance), time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddr("203.0.113.99:80"))
	if conn != nil {
		conn.Close()
		t.Fatal("wrong Reality identity accepted")
	}
	if err == nil {
		t.Fatal("wrong Reality identity was not rejected")
	}
	if _, ok := f.store.Load("reality", 7); ok {
		t.Fatal("rawTCP/failedTLS published authenticated pin")
	}
}
func TestRealityQueryCancellationLeavesOtherQueryAndVPNAlive(t *testing.T) {
	f := newPinRealityFixture(t, "xtls-rprx-vision")
	normal := f.warm(t)
	pin, ok := f.store.Load("reality", 7)
	if !ok {
		t.Fatal("missing authenticated peer")
	}
	plan, err := NewPlanWithEndpointPin(f.snapshot, []string{"select", "reality"}, pin, "test-core", 7)
	if err != nil {
		t.Fatal(err)
	}
	ctxA, cancelA := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelA()
	ctxB, cancelB := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelB()
	a, err := NewSession(ctxA, f.instance, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewSession(ctxB, f.instance, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ca, err := a.dialPinned("tcp", M.ParseSocksaddr("203.0.113.99:80"))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := b.dialPinned("tcp", M.ParseSocksaddr("203.0.113.99:80"))
	if err != nil {
		t.Fatal(err)
	}
	echo := func(c net.Conn, text string) {
		t.Helper()
		if _, e := io.WriteString(c, text); e != nil {
			t.Fatal(e)
		}
		reply := make([]byte, len(text))
		if _, e := io.ReadFull(c, reply); e != nil || string(reply) != text {
			t.Fatalf("echo=%q error=%v", reply, e)
		}
	}
	echo(ca, "A")
	echo(cb, "B")
	cancelA()
	select {
	case <-a.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("cancel did not reach session")
	}
	_ = ca.SetReadDeadline(time.Now().Add(time.Second))
	var end [1]byte
	if _, err = ca.Read(end[:]); err == nil {
		t.Fatal("canceled query socket remains open")
	}
	if b.ctx.Err() != nil || f.instance.Err() != nil {
		t.Fatal("cancel propagated beyond query")
	}
	echo(cb, "still-B")
	echo(normal, "still-VPN")
	if f.router.calls.Load() != 1 {
		t.Fatalf("private queries performed runtimeDNS: %d", f.router.calls.Load())
	}
}
