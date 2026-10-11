package kernelports

import (
	"net"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/stretchr/testify/require"
)

func TestPoolWindowsReservationLifecycle(t *testing.T) {
	// Initialize Winsock as a real Windows network consumer would.
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	p, err := New()
	if err != nil {
		t.Skipf("OS reservation unavailable (not verified): %v", err)
	}
	defer p.Close()
	require.NotEmpty(t, p.PortSelectorRanges(uint8(header.TCPProtocolNumber)))
	require.NotEmpty(t, p.PortSelectorRanges(uint8(header.UDPProtocolNumber)))
	require.NoError(t, p.Close())
	require.Empty(t, p.PortSelectorRanges(uint8(header.TCPProtocolNumber)))
}
