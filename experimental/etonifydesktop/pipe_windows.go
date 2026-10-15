//go:build windows

package etonifydesktop

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

func UserPipeName(launch AgentOptions) (string, error) {
	if launch.ParentPID == 0 || launch.ParentPID != launch.Owner.PID || launch.Nonce != launch.Owner.Nonce {
		return "", runtimeFailure("unauthorized", "Invalid pipe launch owner")
	}
	id := launch.InstallationID
	if len(id) != 36 {
		return "", runtimeFailure("unauthorized", "Invalid installation identity")
	}
	for index, value := range id {
		separator := index == 8 || index == 13 || index == 18 || index == 23
		if separator && value != '-' || !separator && !strings.ContainsRune("0123456789abcdefABCDEF", value) {
			return "", runtimeFailure("unauthorized", "Invalid installation identity")
		}
	}
	nonce, err := hex.DecodeString(launch.Nonce)
	if err != nil || len(nonce) != 32 {
		return "", runtimeFailure("unauthorized", "Invalid pipe launch nonce")
	}
	owner, err := verifiedWindowsOwner(launch.Owner)
	if err != nil {
		return "", err
	}
	logon := sha256.Sum256([]byte(owner.logonSID))
	return fmt.Sprintf(`\\.\pipe\Etonify-v1-%s-%x-%d-%s`, id, logon[:8], owner.session, launch.Nonce), nil
}

func ListenUserPipe(launch AgentOptions) (net.Listener, error) {
	name, err := UserPipeName(launch)
	if err != nil {
		return nil, err
	}
	owner, err := verifiedWindowsOwner(launch.Owner)
	if err != nil {
		return nil, err
	}
	current, err := inspectWindowsPeer(windows.CurrentProcess())
	if err != nil {
		return nil, err
	}
	if current.sid != owner.sid || current.session != owner.session || current.logonSID != owner.logonSID {
		return nil, runtimeFailure("unauthorized", "Agent does not belong to owner logon")
	}
	// Pinned go-winio uses FILE_CREATE for the first instance (no squatting
	// reuse) and FILE_PIPE_REJECT_REMOTE_CLIENTS for every instance.
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{
		SecurityDescriptor: fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;%s)", owner.logonSID),
		InputBufferSize:    65536, OutputBufferSize: 65536,
	})
	if err != nil {
		return nil, runtimeFailure("pipe_unavailable", "Cannot create private owner pipe")
	}
	return listener, nil
}
