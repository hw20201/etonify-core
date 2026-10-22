package tls

import "context"

type realityFallbackDisabledKey struct{}

// WithRealityFallbackDisabled disables the camouflage HTTP request after a
// Reality verification failure. Query-style callers should apply it to their
// handshake context so failed verification cannot start an unowned request.
// The default remains unchanged for ordinary VPN connections.
func WithRealityFallbackDisabled(ctx context.Context) context.Context {
	return context.WithValue(ctx, realityFallbackDisabledKey{}, true)
}

func realityFallbackDisabled(ctx context.Context) bool {
	disabled, _ := ctx.Value(realityFallbackDisabledKey{}).(bool)
	return disabled
}
