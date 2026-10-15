//go:build windows

package etonifydesktop

import (
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsPeerDetails struct {
	pid                  uint32
	sid, logonSID, image string
	session              uint32
	created              windows.Filetime
}

func inspectWindowsPeer(handle windows.Handle) (windowsPeerDetails, error) {
	var result windowsPeerDetails
	state, err := windows.WaitForSingleObject(handle, 0)
	if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		return result, runtimeFailure("unauthorized", "Owner process is not alive")
	}
	result.pid, err = windows.GetProcessId(handle)
	if err != nil {
		return result, err
	}
	var exit, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(handle, &result.created, &exit, &kernel, &user); err != nil {
		return result, err
	}
	var token windows.Token
	if err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return result, err
	}
	defer token.Close()
	account, err := token.GetTokenUser()
	if err != nil {
		return result, err
	}
	result.sid = account.User.Sid.String()
	var length uint32
	if err = windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&result.session)), 4, &length); err != nil {
		return result, err
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return result, err
	}
	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
			result.logonSID = group.Sid.String()
			break
		}
	}
	if result.logonSID == "" {
		return result, runtimeFailure("unauthorized", "Owner logon identity is unavailable")
	}
	image := make([]uint16, 32768)
	length = uint32(len(image))
	if err = windows.QueryFullProcessImageName(handle, 0, &image[0], &length); err != nil {
		return result, err
	}
	result.image = windows.UTF16ToString(image[:length])
	return result, nil
}

// Caller owns the returned process handle for the complete authenticated lease.
func captureWindowsPeer(pid uint32, nonce string) (PeerIdentity, error) {
	bytes, err := hex.DecodeString(nonce)
	if pid == 0 || err != nil || len(bytes) != 32 {
		return PeerIdentity{}, runtimeFailure("unauthorized", "Invalid owner launch context")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return PeerIdentity{}, runtimeFailure("unauthorized", "Cannot hold owner process")
	}
	details, err := inspectWindowsPeer(handle)
	if err != nil {
		windows.CloseHandle(handle)
		return PeerIdentity{}, runtimeFailure("unauthorized", "Cannot verify owner process")
	}
	return PeerIdentity{SID: details.sid, SessionID: details.session, PID: pid, ProcessHandle: uintptr(handle), Nonce: nonce}, nil
}

func verifiedWindowsOwner(owner PeerIdentity) (windowsPeerDetails, error) {
	details, err := inspectWindowsPeer(windows.Handle(owner.ProcessHandle))
	if err != nil || details.pid != owner.PID || details.sid != owner.SID || details.session != owner.SessionID {
		return windowsPeerDetails{}, runtimeFailure("unauthorized", "Owner identity does not match held process")
	}
	return details, nil
}

// The pipe's real client PID, token, logon and held process object are checked
// before reading the fixed binary nonce. A caller-supplied PID is never proof.
// The preface is 32 random nonce bytes; runtime JSON framing follows after the
// runner's fixed ETNYIPC1 acknowledgement. C++ needs no second JSON model.
func AuthorizePeer(conn net.Conn, owner PeerIdentity) error {
	expected, err := verifiedWindowsOwner(owner)
	if err != nil {
		return err
	}
	pipe, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return runtimeFailure("unauthorized", "Expected a local Windows pipe")
	}
	var actualPID uint32
	if err = windows.GetNamedPipeClientProcessId(windows.Handle(pipe.Fd()), &actualPID); err != nil || actualPID != owner.PID {
		return runtimeFailure("unauthorized", "Pipe client is not the owner process")
	}
	actual, err := captureWindowsPeer(actualPID, owner.Nonce)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(windows.Handle(actual.ProcessHandle))
	details, err := verifiedWindowsOwner(actual)
	if err != nil || details.created != expected.created || details.sid != expected.sid || details.session != expected.session ||
		details.logonSID != expected.logonSID || !strings.EqualFold(details.image, expected.image) {
		return runtimeFailure("unauthorized", "Pipe client process identity changed")
	}
	nonce, err := hex.DecodeString(owner.Nonce)
	if err != nil || len(nonce) != 32 {
		return runtimeFailure("unauthorized", "Invalid launch nonce")
	}
	if err = conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return runtimeFailure("unauthorized", "Cannot bound pipe authentication")
	}
	var presented [32]byte
	_, readErr := io.ReadFull(conn, presented[:])
	resetErr := conn.SetReadDeadline(time.Time{})
	if readErr != nil || resetErr != nil || subtle.ConstantTimeCompare(presented[:], nonce) != 1 {
		return runtimeFailure("unauthorized", "Pipe launch authentication failed")
	}
	if _, err = verifiedWindowsOwner(owner); err != nil {
		return err
	}
	return nil
}
