# Scoped public-IP query contract

A public-IP query is one RPC, one deadline and one immutable configuration plan. The plan is built from a configuration snapshot encoded before `Box.New`, plus the currently resolved selector/URLTest tag chain. Network I/O never calls a live selector or reuses an outbound object from the running manager. Its opaque audit identity also includes the provider, core instance and network generations. Configuration contents and credentials are not returned.

## Deliberately restricted support

The audited subset is SOCKS5, HTTP/1 CONNECT and basic Shadowsocks with a literal-IP proxy server. Shadowsocks uses a session-private core outbound and lifecycle scope, not the running outbound manager. Explicit selector/URLTest memberships are validated against the snapshot. The application's explicit TCP options are recognized. Query-only sockets always disable Fast Open (even if `tcp_fast_open:true` accelerates normal VPN sockets), because a query must not leave a cancellation-detached TFO probe. This changes only query transport performance, not the VPN setting. `tcp_multi_path:false` is accepted; enabled multipath and non-boolean values are rejected. Direct outbounds, domain proxy servers, hidden detours, multiplexing, Shadowsocks plugins/UoT, TLS/transport side dependencies, enabled multipath and other unreviewed outbound options fail closed. VLESS, Trojan and other unlisted protocols remain unsupported by this isolated query path.

DNS must have an explicit `final`, no rule-dependent selection, and an explicit detour naming the same frozen outbound selection chain. TCP, UDP, HTTPS (DoH) and TLS (DoT) are supported. UDP requires SOCKS5. DoH/DoT preserve certificate verification, configured endpoint/path and optional TLS server name; insecure TLS, redirects and unaudited dependencies are rejected. A literal-IP resolver needs no bootstrap. For a hostname DoH/DoT endpoint carrying the application's `domain_resolver:"dns-local"` bootstrap hint, this query-specific privacy policy deliberately resolves **only that DNS endpoint hostname at the pinned proxy**, instead of using the device's local DNS. This differs from normal VPN endpoint bootstrap: no device/OS DNS lookup is performed. Other bootstrap graphs fail closed. Provider names are still resolved using the configured DNS service, and their numeric addresses enter the proxy. No default server, direct fallback or second outbound is substituted. UDP truncation falls back to TCP through that same private proxy; there is no shared TCP/UDP multiplexer or cancellation-detached probe.

The application must start the query at the `select` root, not directly at its leaf: its default `dns-remote.detour` names `select`. The core freezes that root's current selector/URLTest chain and rejects changed selections before returning.

## Safe configuration diagnostics

Rejected plans return a static `[PIP_CFG:<code>]` token through the existing FailedPrecondition RPC. It identifies the **first** blocked dependency, not a complete list or a promise that removing it makes the remaining graph safe. Outbound validation precedes DNS validation; unsupported option keys are checked in sorted order for reproducibility. Codes distinguish VLESS/Trojan/direct/other protocols, domain proxy bootstrap, known outbound options such as `detour`, DNS rules, DNS detour/bootstrap/type/options, malformed snapshots and invalid selections. Unknown protocol names and option keys collapse to `other`/`unknown`. No node tag, endpoint, rule value, credential or raw parse error is included. The application must recognize only reviewed codes and must never display raw exceptions.

The app-generated default SOCKS fixture is a compatibility fixture, **not** the user's selected node configuration. Tests also mutate it into synthetic VLESS, Trojan, domain-proxy, multihop and DNS-dependent cases and assert the exact safe rejection. A screenshot containing only a node label and a generic unsupported message cannot identify which case occurred. This diagnostic change deliberately does not broaden supported protocols, invoke a resolver, alter the VPN or introduce any fallback.

## Domain VLESS + Reality bootstrap blocker

`testdata/app-default-vless-reality-domain.json` models the separately confirmed protocol/address shape with synthetic, constructor-valid UUID/Reality/uTLS parameters. The application builder currently leaves the node hostname intact and normally inherits `route.default_domain_resolver: dns-local`. Its remote DoH service follows `select` and itself carries a local-bootstrap hint. Allowing VLESS alone would therefore re-enter local endpoint DNS. Changing the node's resolver to that remote service does not establish a bootstrap route: contacting remote DNS first requires the same still-unresolved node.

`TestDomainRealityLiveOutboundStillNeedsEndpointBootstrap` constructs the real VLESS + Reality outbound under `with_utls` and intercepts its runtime DNS lookup before any exchange/socket, including with TFO enabled and disabled. It verifies the effective node-domain resolver for inherited-local, explicit-local, explicit-direct and remote-resolver variants. The RPC regression uses the full fixture for all three providers. These are **blocked-dependency tests, not successful end-to-end Reality/provider tests**; no Reality handshake or provider HTTP request is claimed.

The current configuration snapshot and frozen selection tags contain no numeric endpoint pin. The live VLESS outbound and public DNS interfaces expose no immutable, unexpired endpoint-address snapshot bound to the node identity, full configuration and core/network generations. A live `DialContext`, an unqualified cache lookup, or an arbitrary established connection is not a substitute for that state. Supporting the domain case requires a reviewed source of such endpoint pins (without a new system/direct DNS lookup), generation-safe capture/validation, a query-private VLESS/Reality dependency graph and complete success/failure/cancellation tests. Reality's existing verification-failure camouflage work also needs query-lifetime review before reuse. Until those prerequisites exist, this path remains fail-closed; no resolver or direct-internet fallback is added.

```sh
go test -race -tags with_utls -count=1 ./common/scopedhttp ./daemon ./experimental/libbox ./cmd/internal/build_libbox
```

## Ownership and lifetime

The bottom dialer preserves the running core's platform socket protection. Every provider destination is resolved by the private DNS exchange and passed as a numeric address to the proxy, so the proxy is never asked to resolve provider hostnames. TLS retains provider hostname verification, the core certificate pool and the core time source.

The whole-query context covers plan creation, DNS, proxy handshake, dial, TLS, both ipquery calls and all response body reads. `Close` cancels only this session and closes only its sockets/transport. The gomobile client's request-ID registry cancels one gRPC context and does not disconnect its command client. Network/core changes cancel or reject old results; a changed outbound selection is rejected before returning.

Only three fixed provider flows exist. ipquery uses `https://api.ipquery.io/` followed by `https://api.ipquery.io/<IP>?format=json`; the second response must identify the same normalized IP. ipwho uses `https://ipwho.is/`. The sole plaintext exception is the exact ip-api URL and minimal fields in `provider.go`. Redirects, arbitrary URLs, oversized bodies and cross-provider fallbacks are rejected.

## Evidence and limits

Source tests cover real local SOCKS5/CONNECT sockets, a decrypting Shadowsocks server with bidirectional payloads and session-owned socket closure, DNS-to-provider numeric destinations on one proxy, DoH/DoT certificate verification and proxy-only endpoint bootstrap, A/AAAA/CNAME, UDP-to-TCP DNS fallback, snapshot/group validation, redirect rejection, IP consistency, bounded bodies, shared deadlines and request cancellation with other sessions/the shared gRPC client alive. Run:

```sh
go test -race -count=1 ./common/scopedhttp ./daemon ./experimental/libbox
```

These tests prove the source/API contract in a controlled environment, not device-level absence of leaks. Android platform socket protection, vivo X200 firmware, actual VPN split routes, physical network transitions and packet captures still require on-device validation. Network change cancellation follows core notifications and is not a claim of atomic physical-interface isolation.
