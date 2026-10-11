package forwardnat_test

import (
	"encoding/binary"
	"net/netip"
	"testing"

	tun "github.com/sagernet/sing-tun"
	"github.com/stretchr/testify/require"
)

// Split the UDP datagram after 16 bytes (header + 8 payload bytes). The
// transport checksum belongs to the entire datagram, not either fragment.
func fragmentPackets(t *testing.T, packet []byte, id uint32) [][]byte {
	t.Helper()
	h := ipHeaderLength(packet)
	transport := packet[h:]
	require.Greater(t, len(transport), 16)
	fragments := make([][]byte, 2)
	for i, part := range [][]byte{transport[:16], transport[16:]} {
		if h == 20 {
			p := append(append([]byte(nil), packet[:h]...), part...)
			binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
			binary.BigEndian.PutUint16(p[4:], uint16(id))
			flags := uint16(2)
			if i == 0 {
				flags = 0x2000
			}
			binary.BigEndian.PutUint16(p[6:], flags)
			p[10], p[11] = 0, 0
			binary.BigEndian.PutUint16(p[10:], internetChecksum(p[:h]))
			fragments[i] = p
		} else {
			p := make([]byte, h+8+len(part))
			copy(p, packet[:h])
			p[6] = 44
			binary.BigEndian.PutUint16(p[4:], uint16(8+len(part)))
			p[h] = 17
			flags := uint16(16)
			if i == 0 {
				flags = 1
			}
			binary.BigEndian.PutUint16(p[h+2:], flags)
			binary.BigEndian.PutUint32(p[h+4:], id)
			copy(p[h+8:], part)
			fragments[i] = p
		}
	}
	return fragments
}

func TestForwardNATIPv4FragmentReturn(t *testing.T) { testFragmentReturn(t, false) }
func TestForwardNATIPv6FragmentReturn(t *testing.T) { testFragmentReturn(t, true) }
func testFragmentReturn(t *testing.T, ipv6 bool) {
	f := newForwardFixture(t, tun.UDPNatOptions{})
	c, s := client, server
	if ipv6 {
		c = netip.MustParseAddrPort("[fd00::2]:12345")
		s = netip.MustParseAddrPort("[2001:db8::2]:443")
	}
	nat, _ := packetEndpoints(f.send(c, s, "request"))
	payload := []byte("fragmented UDP response with checksum")
	fragments := fragmentPackets(t, udpPacket(t, s, nat, payload), 42)
	for _, fragment := range fragments {
		require.Empty(t, f.port.returnPath.ReturnPackets([][]byte{fragment}))
	}
	require.Len(t, f.writeback.packets, 2)
	var restored []byte
	for _, p := range f.writeback.packets {
		src, dst := packetAddresses(p)
		require.Equal(t, s.Addr(), src)
		require.Equal(t, c.Addr(), dst)
		h := ipHeaderLength(p)
		if h == 20 {
			require.Zero(t, internetChecksum(p[:h]))
		} else {
			h += 8
		}
		restored = append(restored, p[h:]...)
	}
	require.Equal(t, c.Port(), binary.BigEndian.Uint16(restored[2:]))
	require.Equal(t, payload, restored[8:])
	require.Zero(t, internetChecksum(append(udpPseudoHeader(s.Addr(), c.Addr(), len(restored)), restored...)), "reassembled UDP checksum")
}

func TestForwardNATFragmentBeforeFirst(t *testing.T) {
	f := newForwardFixture(t, tun.UDPNatOptions{})
	nat, _ := packetEndpoints(f.send(client, server, "request"))
	fragments := fragmentPackets(t, udpPacket(t, server, nat, []byte("long enough fragment payload")), 42)
	original := append([]byte(nil), fragments[1]...)
	left := f.port.returnPath.ReturnPackets([][]byte{fragments[1]})
	require.Len(t, left, 1)
	require.Equal(t, original, left[0])
	require.Empty(t, f.writeback.packets)
	// A valid association for ID 42 must never rewrite a tail for ID 43.
	require.Empty(t, f.port.returnPath.ReturnPackets([][]byte{fragments[0]}))
	other := fragmentPackets(t, udpPacket(t, server, nat, []byte("different fragment identifier")), 43)[1]
	original = append([]byte(nil), other...)
	left = f.port.returnPath.ReturnPackets([][]byte{other})
	require.Len(t, left, 1)
	require.Equal(t, original, left[0])
	require.Len(t, f.writeback.packets, 1)
}

func TestForwardNATMalformedFragments(t *testing.T) {
	f := newForwardFixture(t, tun.UDPNatOptions{})
	f.send(client, server, "request")
	ipv6 := udpPacket(t, netip.MustParseAddrPort("[2001:db8::2]:443"), netip.MustParseAddrPort("[2001:db8::1]:50000"), nil)
	ipv6[6] = 44
	for _, length := range []int{0, 1, 19, 39, 40, 41, 47} {
		packet := append([]byte(nil), ipv6[:length]...)
		require.NotPanics(t, func() {
			left := f.port.returnPath.ReturnPackets([][]byte{packet})
			require.Len(t, left, 1)
		})
	}
	require.Empty(t, f.writeback.packets)
}

func TestForwardNATFragmentAfterFlowClose(t *testing.T) {
	f := newForwardFixture(t, tun.UDPNatOptions{})
	nat, _ := packetEndpoints(f.send(client, server, "request"))
	fragments := fragmentPackets(t, udpPacket(t, server, nat, []byte("long enough fragment payload")), 42)
	require.Empty(t, f.port.returnPath.ReturnPackets([][]byte{fragments[0]}))
	require.Len(t, f.writeback.packets, 1)
	f.handler.trackers[0].handle.CloseFlow()
	left := f.port.returnPath.ReturnPackets([][]byte{fragments[1]})
	require.Empty(t, left, "closed-flow tail must be dropped, not forwarded to another handler")
	require.Len(t, f.writeback.packets, 1)
}
