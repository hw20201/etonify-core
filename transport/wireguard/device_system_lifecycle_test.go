package wireguard

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/common/kernelports"
	"github.com/sagernet/sing-tun"
	wgTun "github.com/sagernet/wireguard-go/tun"
	"github.com/stretchr/testify/require"
)

type lifecycleTun struct {
	tun.Tun
	closes atomic.Int32
}

func (t *lifecycleTun) Close() error { t.closes.Add(1); return nil }
func seededSystemDevice() (*systemDevice, *lifecycleTun) {
	t := &lifecycleTun{}
	d := &systemDevice{device: t, events: make(chan wgTun.Event, 1)}
	d.ports.Store(&kernelports.Pool{})
	return d, t
}
func TestWireGuardSystemDeviceStartAfterClose(t *testing.T) {
	d, _ := seededSystemDevice()
	require.NoError(t, d.Close())
	require.NotPanics(t, func() { require.ErrorIs(t, d.Start(), net.ErrClosed) })
}
func TestWireGuardSystemDeviceCloseClearsUpstreamPort(t *testing.T) {
	d, tun := seededSystemDevice()
	require.NoError(t, d.Close())
	require.Nil(t, d.UpstreamPort())
	require.NoError(t, d.Close())
	require.EqualValues(t, 1, tun.closes.Load())
}
func TestWireGuardSystemDeviceConcurrentStartClose(t *testing.T) {
	d, tun := seededSystemDevice()
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if p := recover(); p != nil {
					results <- fmt.Errorf("Start panic: %v", p)
				}
			}()
			err := d.Start()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				results <- err
			}
			_ = d.UpstreamPort()
			_ = d.Close()
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		t.Error(err)
	}
	_ = d.Close()
	require.Nil(t, d.UpstreamPort())
	require.EqualValues(t, 1, tun.closes.Load())
}
