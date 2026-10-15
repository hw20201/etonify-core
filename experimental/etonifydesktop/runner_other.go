//go:build !windows

package etonifydesktop

import "context"

func runPlatformAgent(context.Context, AgentOptions) error {
	return runtimeFailure("unavailable", "Desktop agent requires Windows")
}
