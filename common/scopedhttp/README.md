# Scoped public-IP query contract

A public-IP query is one RPC, one deadline and one immutable configuration plan. The plan is built from a snapshot encoded before `Box.New`, plus the frozen selector/URLTest tag chain. Query I/O never calls a live selector or reuses an outbound from the running manager. Its opaque audit identity includes the provider, core instance and network generation. Configuration contents and credentials are not returned.

## Audited support

SOCKS5, HTTP/1 CONNECT and basic Shadowsocks support literal-IP proxy servers. Domain-addressed TCP VLESS + Reality is supported **only when an unexpired, fully bound authenticated endpoint observation is available** (see below). VLESS without Reality, literal-IP VLESS, transports, multiplexing, detours, VLESS encryption extensions, Shadowsocks plugins/UoT, Trojan, direct and other unreviewed graphs fail closed. Session-private core outbounds and lifecycle scopes are used for Shadowsocks and Reality, not the running outbound manager.

Query sockets always disable Fast Open, even if `tcp_fast_open:true` accelerates normal VPN sockets: a query must not leave a cancellation-detached TFO probe. `tcp_multi_path:false` is accepted; enabled multipath and non-boolean socket options are rejected. This affects only query sockets, not normal VPN settings.

DNS must have an explicit `final`, no rule-dependent selection, and an explicit detour naming the same frozen outbound selection chain. TCP, UDP, HTTPS (DoH) and TLS (DoT) are supported; UDP requires SOCKS5. DoH/DoT preserve certificate verification, configured endpoint/path and optional TLS server name. Insecure TLS, redirects and unreviewed dependencies are rejected. For a hostname DoH/DoT endpoint carrying the application's `domain_resolver:"dns-local"` hint, this query-specific policy resolves **only that DNS endpoint hostname at the pinned proxy**, rather than using device DNS. Provider names are resolved by that configured DNS service; provider destinations entering the proxy are numeric. No default resolver, direct fallback or second outbound is substituted. UDP truncation falls back to TCP through the same private proxy.

The application must start at the `select` root rather than its leaf: its default `dns-remote.detour` names `select`. The core freezes the current selector/URLTest chain, watches it and rechecks it before returning.

## Warm-only domain VLESS + Reality

`common/endpointpin` is a per-instance observation store injected before outbound construction. It never invokes a resolver, reads a DNS cache, opens a socket or refreshes a record. The ordinary VPN retains its existing resolver and socket behavior. This repair does **not** assert that normal VPN bootstrap itself avoids local DNS; it prevents the **public-IP query** from introducing local/system/direct DNS or direct-internet fallback.

The normal VLESS producer must match the complete normalized frozen VLESS options, including UUID, flow, Reality key/short ID, TLS/SNI/fingerprint and socket options. It must use a domain, no detour/transport/multiplexing/encryption extension, and an actual Reality TLS profile. It captures network generation before dialing. Only a successful Reality identity handshake and successful VLESS connection-wrapper construction can publish the actual numeric bottom TCP `RemoteAddr`; raw TCP or ordinary TLS success cannot. This proves the Reality peer, **not remote acceptance of a VLESS user**. The query still authenticates with its own frozen UUID/flow and fails if the server rejects it.

Each observation binds the full configuration SHA-256, core UUID, exact leaf tag, original hostname/port, actual IP/port, network generation and a 60-second expiry. Address/port validity and generation are checked at publication; record consumption checks generation and expiry. Plan construction checks the full identity again. The private marker detects accidental mutation of a copied observation. Records cannot be serialized/imported as an external pin format. No stale-while-refresh behavior exists.

The query constructs a **new private VLESS + Reality outbound** with the observed numeric endpoint and original TLS server name, Reality key and VLESS identity. The private context clones its service registry before removing the producer store; it never erases the running VPN's store. Every dial checks expiry. Session lifetime is bounded by both the query deadline and pin expiry. Instance/network/selection changes cancel or reject the query, with a final state check before returning.

No valid observation means `[PIP_CFG:outbound.bootstrap.pin_required]` before query sockets. The user may first use the selected node normally to create a fresh authenticated observation, then retry. Cold startup, old network records, expired records, another core/config/leaf, failed Reality verification or an unsupported graph never trigger a query-time endpoint DNS lookup or fallback. The feature is deliberately warm-only, not a general bootstrap resolver.

Reality's verification-failure camouflage path is explicitly disabled for the query, both through the private constructor context and its dial context. The failed handshake socket is closed; no background camouflage HTTP request can escape query cancellation. Normal VPN Reality camouflage behavior is unchanged.

## Diagnostics

Rejected plans return a static `[PIP_CFG:<code>]` token through FailedPrecondition. It identifies the **first** blocked dependency, not a complete list or a promise that removing it is sufficient. Outbound validation precedes DNS validation; unsupported keys are checked in sorted order. Unknown keys/protocols collapse to `unknown`/`other`. No node tag, endpoint, rule value, credential or raw parser exception is displayed by the application.

`testdata/app-default-vless-reality-domain.json` models the user's confirmed protocol/address shape with synthetic constructor-valid credentials; it is not the user's secret node configuration. The earlier SOCKS fixture is also synthetic and must not be described as the user's selected node.

## Why runtime DNS cache is not a pin source

`dns/public_ip_endpoint_pin_test.go` demonstrates that runtime cache results do not bind full node/Reality configuration and core/network identity; `disable_expire` can return old persistent records, and optimistic refresh may run under the core context after query cancellation. These are synthetic boundary tests, not assertions about the user's enabled cache settings. The new source is authenticated peer observation, **not** a promoted DNS answer or arbitrary established connection.

`TestDomainRealityLiveOutboundStillNeedsEndpointBootstrap` still demonstrates that an ordinary uncached VLESS domain dial enters its configured runtime resolver. It is a dependency test, not the warm-only query path. The no-observation RPC regression still refuses all three providers.

## Ownership and fixed provider flows

The bottom dialer preserves platform socket protection. All provider TLS retains hostname verification, the core root pool and core time source. The whole-query context covers DNS, proxy and TLS handshakes, HTTP and body reads, including both ipquery calls. `Close` cancels only this query and closes only its sockets/scope/transport. The gomobile request-ID registry cancels one gRPC context without disconnecting the shared command client.

Only three fixed provider flows exist: ipquery's `https://api.ipquery.io/` plus `https://api.ipquery.io/<IP>?format=json`, ipwho's `https://ipwho.is/`, and the exact minimal plaintext ip-api URL in `provider.go`. The ipquery second-stage IP must match. Arbitrary URLs, redirects, oversized bodies and cross-provider fallback are rejected.

## Evidence and device limits

Tests use real local Reality handshakes, VLESS and Vision payloads, a normal VPN producer and private query consumer, authenticated-peer publication, TCP DNS and hostname DoH through the proxy, certificate-verified provider TLS, all three provider flows and numeric provider destinations. Runtime endpoint DNS is called for normal warm-up only, never by the private query. Authentication failure cannot publish a pin; cancellation of one query leaves another query and the normal VPN socket alive. Store tests cover config/core/leaf/network mismatch, expiry, changed source options, IPv4/IPv6, malformed peers and concurrent observation/invalidation.

Run normal tagged and untagged suites. Vision's existing `sing-vmess` implementation uses uintptr-based TLS field access which triggers Go checkptr under `-race`; the Vision race run therefore disables **checkptr, not race instrumentation**. This is a dependency limitation, not evidence of device-level leak freedom:

```sh
go test -tags with_utls -count=1 ./common/endpointpin ./common/tls ./common/scopedhttp ./protocol/vless ./daemon ./experimental/libbox ./cmd/internal/build_libbox ./dns
go test -race -count=1 ./common/endpointpin ./common/scopedhttp ./daemon ./experimental/libbox
go test -race -gcflags=all=-d=checkptr=0 -tags with_utls -count=1 ./common/endpointpin ./common/tls ./common/scopedhttp ./protocol/vless ./daemon ./experimental/libbox ./cmd/internal/build_libbox ./dns
```

These controlled source/API tests are **not** a successful test of the user's actual subscription node or phone. Android socket protection, vivo X200 firmware, split routes, physical network transitions and packet captures require device validation. State-change cancellation follows core notifications and polling; it is not atomic physical-interface isolation. No signed APK or release is implied by these tests.
