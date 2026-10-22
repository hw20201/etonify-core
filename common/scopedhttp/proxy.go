package scopedhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	boxlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
)

// newScopedShadowsocks constructs an outbound that is private to one session.
// Its options are populated only after NewPlan's strict field whitelist has run.
func newScopedShadowsocks(ctx context.Context, tag, server string, serverPort uint16, method, password string) (adapter.Outbound, *adapter.Scope, error) {
	if ctx == nil {
		return nil, nil, errors.New("missing scoped outbound context")
	}
	logger := boxlog.NewNOPFactory().Logger()
	scope := adapter.NewScope(ctx, logger)
	out, err := shadowsocks.NewOutbound(scope.Context(), nil, logger, tag, option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{Server: server, ServerPort: serverPort},
		Method:        method, Password: password,
	})
	if err != nil {
		_ = scope.Close()
		return nil, nil, fmt.Errorf("create scoped Shadowsocks outbound: %w", err)
	}
	if lifecycle, ok := out.(adapter.Lifecycle); ok {
		if err = scope.Start("scoped Shadowsocks", lifecycle, adapter.StartStateInitialize); err != nil {
			_ = scope.Close()
			return nil, nil, err
		}
	}
	return out, scope, nil
}

func parseShadowsocksProxy(o map[string]json.RawMessage) (method, password string, err error) {
	allowed := []string{"type", "tag", "server", "server_port", "method", "password", "tcp_fast_open", "tcp_multi_path"}
	if err = keysOnly(o, allowed...); err != nil {
		return
	}
	if err = validateProxySocketOptions(o); err != nil {
		return
	}
	method, password = text(o, "method"), text(o, "password")
	if method == "" || password == "" {
		err = errors.New("scoped Shadowsocks requires method and password")
	}
	return
}
