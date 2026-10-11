package kernelports

import (
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/stretchr/testify/require"
)

func TestPoolCannotReopenAfterClose(t *testing.T) {
	p := &Pool{}
	require.NoError(t, p.Close())
	_, err := p.Acquire(uint8(header.TCPProtocolNumber))
	require.ErrorIs(t, err, net.ErrClosed)
	require.False(t, p.ReserveSelector(uint8(header.UDPProtocolNumber), netip.MustParseAddrPort("127.0.0.1:40000")))
}

func TestPoolContainsRangeBoundaries(t *testing.T) {
	p := &Pool{}
	ranges := []tun.SelectorRange{{Start: 40000, Count: 3}, {Start: 50000, Count: 0}}
	p.tcp.Store(&ranges)
	for _, tc := range []struct {
		port uint16
		want bool
	}{{39999, false}, {40000, true}, {40002, true}, {40003, false}, {50000, false}} {
		require.Equal(t, tc.want, p.Contains(uint8(header.TCPProtocolNumber), tc.port))
	}
}
func TestPoolProtocolRangesIndependent(t *testing.T) {
	p := &Pool{}
	tcp := []tun.SelectorRange{{Start: 40000, Count: 2}}
	udp := []tun.SelectorRange{{Start: 50000, Count: 2}}
	p.tcp.Store(&tcp)
	p.udp.Store(&udp)
	require.True(t, p.Contains(uint8(header.TCPProtocolNumber), 40000))
	require.False(t, p.Contains(uint8(header.UDPProtocolNumber), 40000))
	require.True(t, p.Contains(uint8(header.UDPProtocolNumber), 50000))
}
func TestPoolCloseIdempotent(t *testing.T) {
	p := &Pool{}
	ranges := []tun.SelectorRange{{Start: 40000, Count: 3}}
	p.tcp.Store(&ranges)
	p.udp.Store(&ranges)
	require.NoError(t, p.Close())
	require.NoError(t, p.Close())
	require.Empty(t, p.PortSelectorRanges(uint8(header.TCPProtocolNumber)))
	require.Empty(t, p.PortSelectorRanges(uint8(header.UDPProtocolNumber)))
}
func TestPoolConcurrentRangesAndClose(t *testing.T) {
	p := &Pool{}
	ranges := []tun.SelectorRange{{Start: 40000, Count: 3}}
	p.tcp.Store(&ranges)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = p.Contains(uint8(header.TCPProtocolNumber), 40000); _ = p.Close() }()
	}
	wg.Wait()
	require.Empty(t, p.PortSelectorRanges(uint8(header.TCPProtocolNumber)))
}
