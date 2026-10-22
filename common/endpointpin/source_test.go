package endpointpin

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestSourceIdentityIncludesAllVLESSOptions(t *testing.T) {
	raw := []byte(`{"outbounds":[{"type":"vless","tag":"edge","server":"edge.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0102030405060708"}},"tcp_fast_open":true}]}`)
	s, err := New(raw, "core", func() uint64 { return 1 })
	if err != nil {
		t.Fatal(err)
	}
	var root struct{ Outbounds []json.RawMessage }
	if err = json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		change func(*option.VLESSOutboundOptions)
	}{
		{"UUID", func(o *option.VLESSOutboundOptions) { o.UUID = "different-user" }},
		{"flow", func(o *option.VLESSOutboundOptions) { o.Flow = "" }},
		{"key", func(o *option.VLESSOutboundOptions) { o.TLS.Reality.PublicKey = "different-key" }},
		{"shortID", func(o *option.VLESSOutboundOptions) { o.TLS.Reality.ShortID = "01" }},
		{"SNI", func(o *option.VLESSOutboundOptions) { o.TLS.ServerName = "different.example" }},
		{"fingerprint", func(o *option.VLESSOutboundOptions) { o.TLS.UTLS.Fingerprint = "firefox" }},
		{"socket options", func(o *option.VLESSOutboundOptions) { o.TCPFastOpen = false }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var o option.VLESSOutboundOptions
			if err := json.Unmarshal(root.Outbounds[0], &o); err != nil {
				t.Fatal(err)
			}
			if !s.MatchesSource("edge", o) {
				t.Fatal("original options rejected")
			}
			tt.change(&o)
			if s.MatchesSource("edge", o) {
				t.Fatal("changed source identity accepted")
			}
		})
	}
}
