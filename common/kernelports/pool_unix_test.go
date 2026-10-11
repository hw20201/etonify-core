//go:build !windows

package kernelports

import (
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/stretchr/testify/require"
)

func TestPoolReserveOccupiedSocket(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	p, err := New()
	require.NoError(t, err)
	defer p.Close()
	addr := netip.MustParseAddrPort(l.Addr().String())
	require.False(t, p.ReserveSelector(uint8(header.TCPProtocolNumber), addr))
	require.True(t, p.ReserveSelector(uint8(header.UDPProtocolNumber), addr))
}
