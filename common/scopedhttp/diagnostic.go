package scopedhttp

import "errors"

// configurationError carries only a reviewed, static code. Never put snapshot
// values, node tags, endpoint names, credentials or untrusted option keys here.
type configurationError struct{ code string }

func (e *configurationError) Error() string { return "[PIP_CFG:" + e.code + "]" }
func reject(code string) error              { return &configurationError{code: code} }

type optionError struct{ key string }

func (e *optionError) Error() string { return "unsupported scoped option" }

// Only known schema keys are allowed into diagnostics. Unknown keys can contain
// arbitrary subscription/user input and must be collapsed to 'unknown'.
func safeOption(key string) string {
	switch key {
	case "detour", "domain_resolver", "tls", "transport", "multiplex", "plugin", "plugin_opts", "udp_over_tcp", "network", "bind_interface", "inet4_bind_address", "inet6_bind_address", "routing_mark", "reuse_addr", "connect_timeout", "tcp_fast_open", "tcp_multi_path", "client_subnet", "strategy", "address_resolver", "certificate", "certificate_path", "insecure", "utls", "reality", "enabled", "server_name", "path", "version":
		return key
	default:
		return "unknown"
	}
}

func configurationDiagnostic(err error, stage string) error {
	if err == nil {
		return nil
	}
	var diagnostic *configurationError
	if errors.As(err, &diagnostic) {
		return diagnostic
	}
	var option *optionError
	if errors.As(err, &option) {
		if stage == "dns.invalid" {
			return reject("dns.option." + safeOption(option.key))
		}
		return reject("outbound.option." + safeOption(option.key))
	}
	return reject(stage)
}
