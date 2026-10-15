// etonify-desktop is the bounded desktop agent entry point. Native peer/parent
// authentication is wired by B2; until then RunAgent fails closed, not connected.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/sagernet/sing-box/experimental/etonifydesktop"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "agent" {
		fmt.Fprintln(os.Stderr, "usage: etonify-desktop agent --parent-pid <pid> --install-id <id> --data-root <path> --nonce <nonce>; service requires B3")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	parent := flags.Uint64("parent-pid", 0, "GUI process identifier (not authentication)")
	installation := flags.String("install-id", "", "installation identifier")
	dataRoot := flags.String("data-root", "", "absolute user data root")
	nonce := flags.String("nonce", "", "launch nonce (not authentication)")
	if err := flags.Parse(os.Args[2:]); err != nil || flags.NArg() != 0 || *parent == 0 || *parent > uint64(^uint32(0)) || *installation == "" || *dataRoot == "" || *nonce == "" {
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := etonifydesktop.RunAgent(ctx, etonifydesktop.AgentOptions{InstallationID: *installation, DataRoot: *dataRoot, Nonce: *nonce, ParentPID: uint32(*parent)}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
