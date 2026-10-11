package device

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/common/kernelports"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/stretchr/testify/require"
)

type lifecycleTun struct {
	tun.Tun
	closes atomic.Int32
	err    error
}

func (t *lifecycleTun) Close() error { t.closes.Add(1); return t.err }
func seededSystemDevice() (*systemDevice, *lifecycleTun) {
	t := &lifecycleTun{}
	return &systemDevice{device: t, ports: &kernelports.Pool{}, options: Options{Logger: log.NewNOPFactory().Logger()}}, t
}
func TestSystemDeviceRepeatedStartKeepsPool(t *testing.T) {
	d, _ := seededSystemDevice()
	t.Cleanup(func() { _ = d.Close() })
	p := d.UpstreamPort()
	require.NoError(t, d.Start())
	require.NoError(t, d.Start())
	require.Same(t, p, d.UpstreamPort())
}
func TestSystemDeviceCloseReleasesPool(t *testing.T) {
	d, tun := seededSystemDevice()
	sentinel := errors.New("TUN close failure")
	tun.err = sentinel
	require.ErrorIs(t, d.Close(), sentinel)
	require.Nil(t, d.UpstreamPort())
	require.NoError(t, d.Close())
	require.EqualValues(t, 1, tun.closes.Load())
}
func TestSystemDeviceStartAfterClose(t *testing.T) {
	d, _ := seededSystemDevice()
	require.NoError(t, d.Close())
	require.ErrorIs(t, d.Start(), net.ErrClosed)
}
func TestSystemDeviceConcurrentStartClose(t *testing.T) {
	d, tun := seededSystemDevice()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := d.Start()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
			_ = d.UpstreamPort()
			_ = d.Close()
		}()
	}
	wg.Wait()
	require.Nil(t, d.UpstreamPort())
	require.EqualValues(t, 1, tun.closes.Load())
}
