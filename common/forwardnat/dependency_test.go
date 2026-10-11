package forwardnat_test

import (
	"testing"

	"github.com/sagernet/sing-tun"
	"github.com/stretchr/testify/require"
)

func TestForwardNATDependencyDNSDefault(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options tun.Options
		want    string
	}{
		{"no auto route", tun.Options{}, tun.DNSModeDisabled},
		{"auto route", tun.Options{AutoRoute: true}, tun.DNSModeHijack},
		{"explicit disabled", tun.Options{AutoRoute: true, DNSMode: tun.DNSModeDisabled}, tun.DNSModeDisabled},
		{"explicit hijack", tun.Options{DNSMode: tun.DNSModeHijack}, tun.DNSModeHijack},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.want, tc.options.DNSModeOrDefault()) })
	}
}
