//go:build windows

package etonifydesktop

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func agentOwner(options AgentOptions) (PeerIdentity, error) {
	var basic windows.PROCESS_BASIC_INFORMATION
	size := uint32(unsafe.Sizeof(basic))
	if err := windows.NtQueryInformationProcess(windows.CurrentProcess(), windows.ProcessBasicInformation, unsafe.Pointer(&basic), size, &size); err != nil ||
		basic.InheritedFromUniqueProcessId != uintptr(options.ParentPID) || options.ParentPID == 0 {
		return PeerIdentity{}, runtimeFailure("unauthorized", "Agent was not launched by the claimed owner")
	}
	owner, err := captureWindowsPeer(options.ParentPID, options.Nonce)
	if err != nil {
		return PeerIdentity{}, err
	}
	parent, err := verifiedWindowsOwner(owner)
	current, currentErr := inspectWindowsPeer(windows.CurrentProcess())
	if err != nil || currentErr != nil || parent.sid != current.sid || parent.session != current.session || parent.logonSID != current.logonSID ||
		!strings.EqualFold(filepath.Dir(parent.image), filepath.Dir(current.image)) || strings.EqualFold(parent.image, current.image) ||
		parent.created.HighDateTime > current.created.HighDateTime || parent.created.HighDateTime == current.created.HighDateTime && parent.created.LowDateTime > current.created.LowDateTime {
		windows.CloseHandle(windows.Handle(owner.ProcessHandle))
		return PeerIdentity{}, runtimeFailure("unauthorized", "Agent owner is not a co-packaged process in this logon")
	}
	return owner, nil
}

func runPlatformAgent(parent context.Context, options AgentOptions) error {
	owner, err := agentOwner(options)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(windows.Handle(owner.ProcessHandle))
	options.Owner = owner
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	leaseDone := make(chan struct{})
	go func() {
		defer close(leaseDone)
		for ctx.Err() == nil {
			state, err := windows.WaitForSingleObject(windows.Handle(owner.ProcessHandle), 100)
			if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
				cancel()
				return
			}
		}
	}()
	defer func() { cancel(); <-leaseDone }()
	listener, err := ListenUserPipe(options)
	if err != nil {
		return err
	}
	defer listener.Close()
	// Open is bounded even when the GUI never connects. Once authenticated the
	// process handle, not this startup timer, owns the lifetime.
	startup, finishStartup := context.WithTimeout(ctx, 15*time.Second)
	stopAccept := context.AfterFunc(startup, func() { listener.Close() })
	conn, err := listener.Accept()
	stopAccept()
	finishStartup()
	if err != nil {
		return runtimeFailure("transport_lost", "Owner did not open desktop channel")
	}
	listener.Close()
	defer conn.Close()
	stopConnection := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopConnection()
	if err = AuthorizePeer(conn, owner); err != nil {
		return err
	}
	host, err := NewHost(ctx, HostOptions{DataRoot: options.DataRoot})
	if err != nil {
		return err
	}
	defer host.Close()
	if err = acknowledgeOwner(conn); err != nil {
		return err
	}
	return ServeConnection(ctx, conn, host)
}

func acknowledgeOwner(conn net.Conn) error {
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	ack := []byte("ETNYIPC1")
	for len(ack) > 0 {
		n, err := conn.Write(ack)
		if err != nil || n <= 0 {
			return runtimeFailure("transport_lost", "Owner handshake failed")
		}
		ack = ack[n:]
	}
	return conn.SetWriteDeadline(time.Time{})
}
