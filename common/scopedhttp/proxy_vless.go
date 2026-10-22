package scopedhttp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/endpointpin"
	boxtls "github.com/sagernet/sing-box/common/tls"
	boxlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/service"
)

func parseVLESSRealityProxy(o map[string]json.RawMessage) (*option.VLESSOutboundOptions, error) {
	if err := keysOnly(o, "type", "tag", "server", "server_port", "uuid", "flow", "tls", "tcp_fast_open", "tcp_multi_path", "packet_encoding"); err != nil {
		return nil, err
	}
	if err := validateProxySocketOptions(o); err != nil {
		return nil, err
	}
	if _, err := uuid.FromString(text(o, "uuid")); err != nil {
		return nil, errors.New("invalid scoped VLESS identity")
	}
	if flow := text(o, "flow"); flow != "" && flow != "xtls-rprx-vision" {
		return nil, errors.New("unsupported scoped VLESS flow")
	}
	var tlsOptions, utls, reality map[string]json.RawMessage
	if json.Unmarshal(o["tls"], &tlsOptions) != nil || !explicitTrue(tlsOptions["enabled"]) {
		return nil, errors.New("missing scoped Reality TLS")
	}
	if err := keysOnly(tlsOptions, "enabled", "server_name", "utls", "reality", "alpn", "insecure"); err != nil {
		return nil, err
	}
	if raw, ok := tlsOptions["insecure"]; ok && string(raw) != "false" {
		return nil, errors.New("insecure scoped Reality forbidden")
	}
	if !validDNSHostname(text(tlsOptions, "server_name")) {
		return nil, errors.New("explicit scoped Reality server name required")
	}
	if json.Unmarshal(tlsOptions["utls"], &utls) != nil || !explicitTrue(utls["enabled"]) {
		return nil, errors.New("scoped Reality requires uTLS")
	}
	if err := keysOnly(utls, "enabled", "fingerprint"); err != nil {
		return nil, err
	}
	if text(utls, "fingerprint") == "" {
		return nil, errors.New("explicit uTLS fingerprint required")
	}
	if json.Unmarshal(tlsOptions["reality"], &reality) != nil || !explicitTrue(reality["enabled"]) {
		return nil, errors.New("scoped Reality required")
	}
	if err := keysOnly(reality, "enabled", "public_key", "short_id"); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	var options option.VLESSOutboundOptions
	if err = json.Unmarshal(wire, &options); err != nil {
		return nil, err
	}
	// No resolver/detour/transport/multiplex/encryption can enter this graph. The
	// numeric server is assigned only after a validated authenticated observation.
	options.TCPFastOpen = false
	options.TCPMultiPath = false
	return &options, nil
}

func newScopedVLESS(ctx context.Context, tag string, options option.VLESSOutboundOptions) (adapter.Outbound, *adapter.Scope, error) {
	// Registry helpers mutate their registry: clone it before shadowing the
	// observation store, never erase a shared running VPN's store.
	ctx = service.ExtendContext(ctx)
	ctx = service.ContextWithPtr[endpointpin.Store](ctx, nil)
	ctx = boxtls.WithRealityFallbackDisabled(ctx)
	logger := boxlog.NewNOPFactory().Logger()
	scope := adapter.NewScope(ctx, logger)
	out, err := vless.NewOutbound(scope.Context(), nil, logger, tag, options)
	if err != nil {
		_ = scope.Close()
		return nil, nil, err
	}
	if lifecycle, ok := out.(adapter.Lifecycle); ok {
		if err = scope.Start("scoped VLESS Reality", lifecycle, adapter.StartStateInitialize); err != nil {
			_ = scope.Close()
			return nil, nil, err
		}
	}
	return out, scope, nil
}
