//go:build windows

package etonifydesktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

func ownedTestPipe(t *testing.T) (PeerIdentity, net.Conn, net.Conn, []byte) {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	owner, err := captureWindowsPeer(uint32(os.Getpid()), hex.EncodeToString(nonce))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(windows.Handle(owner.ProcessHandle)) })
	options := AgentOptions{InstallationID: "12345678-1234-1234-1234-123456789abc", ParentPID: owner.PID, Owner: owner, Nonce: owner.Nonce, DataRoot: t.TempDir()}
	listener, err := ListenUserPipe(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	path, err := UserPipeName(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type accepted struct {
		conn net.Conn
		err  error
	}
	ready := make(chan accepted, 1)
	go func() {
		conn, err := listener.Accept()
		ready <- accepted{conn, err}
	}()
	client, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	result := <-ready
	if result.err != nil {
		t.Fatal(result.err)
	}
	server := result.conn
	t.Cleanup(func() { server.Close() })
	return owner, server, client, nonce
}
func TestPipeAuthenticatesActualHeldOwner(t *testing.T) {
	owner, server, client, nonce := ownedTestPipe(t)
	if _, err := client.Write(nonce); err != nil {
		t.Fatal(err)
	}
	if err := AuthorizePeer(server, owner); err != nil {
		t.Fatalf("real owner rejected: %v", err)
	}
}
func TestPipeRejectsWrongSessionAndParent(t *testing.T) {
	for _, change := range []string{"session", "pid", "sid", "nonce"} {
		t.Run(change, func(t *testing.T) {
			owner, server, client, nonce := ownedTestPipe(t)
			switch change {
			case "session":
				owner.SessionID++
			case "pid":
				owner.PID++
			case "sid":
				owner.SID = "S-1-0-0"
			case "nonce":
				nonce[0] ^= 0xff
			}
			if _, err := client.Write(nonce); err != nil {
				t.Fatal(err)
			}
			if err := AuthorizePeer(server, owner); err == nil {
				t.Fatal("wrong owner accepted")
			}
		})
	}
}
func TestPeerRejectsPidWithoutHeldProcessHandle(t *testing.T) {
	owner, server, client, nonce := ownedTestPipe(t)
	if _, err := client.Write(nonce); err != nil {
		t.Fatal(err)
	}
	owner.ProcessHandle = 0
	if err := AuthorizePeer(server, owner); err == nil {
		t.Fatal("PID alone accepted as authority")
	}
}
func TestPipeRejectsPrecreatedEndpoint(t *testing.T) {
	owner, _, _, _ := ownedTestPipe(t)
	options := AgentOptions{InstallationID: "12345678-1234-1234-1234-123456789abc", ParentPID: owner.PID, Owner: owner, Nonce: owner.Nonce, DataRoot: t.TempDir()}
	other, err := ListenUserPipe(options)
	if other != nil {
		other.Close()
	}
	if err == nil {
		t.Fatal("existing pipe endpoint silently reused")
	}
}

func TestPeerAgentRejectsCallerSuppliedParent(t *testing.T) {
	err := RunAgent(context.Background(), AgentOptions{
		ParentPID: uint32(os.Getpid()), Nonce: hex.EncodeToString(make([]byte, 32)),
		InstallationID: "12345678-1234-1234-1234-123456789abc", DataRoot: t.TempDir(),
	})
	var failure *hostError
	if !errors.As(err, &failure) || failure.code != "unauthorized" {
		t.Fatalf("expected parent ownership rejection, got %v", err)
	}
}
