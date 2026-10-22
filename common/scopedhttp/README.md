# Scoped public-IP query contract

A public-IP query is one RPC, one deadline and one immutable configuration plan. The plan is built from a configuration snapshot encoded before `Box.New`, plus the currently resolved selector/URLTest tag chain. Network I/O never calls a live selector or reuses an outbound object from the running manager. Its opaque audit identity also includes the provider, core instance and network generations. Configuration contents and credentials are not returned.

## Deliberately restricted support

The initial audited subset is SOCKS5 and HTTP/1 CONNECT with a literal-IP proxy server and the basic server/port/credential options only. Explicit selector/URLTest memberships are validated against the snapshot. Direct outbounds, domain proxy servers, hidden detours, multiplexing, TLS/transport side dependencies, TFO and other unreviewed outbound options fail closed.

DNS must have an explicit `final`, no rule-dependent selection, a literal-IP TCP or UDP server, and an explicit detour naming the same frozen outbound selection chain. UDP requires SOCKS5. Local/system/HTTPS/TLS and other unreviewed DNS types fail closed. No default server, OS resolver, direct fallback or second outbound is substituted. DNS requests are raw session-owned exchanges through the private proxy. UDP truncation falls back to TCP through that same private proxy; there is no shared TCP/UDP multiplexer or cancellation-detached probe.

## Ownership and lifetime

The bottom dialer preserves the running core's platform socket protection. Every provider destination is resolved by the private DNS exchange and passed as a numeric address to the proxy, so the proxy is never asked to resolve provider hostnames. TLS retains provider hostname verification, the core certificate pool and the core time source.

The whole-query context covers plan creation, DNS, proxy handshake, dial, TLS, both ipquery calls and all response body reads. `Close` cancels only this session and closes only its sockets/transport. The gomobile client's request-ID registry cancels one gRPC context and does not disconnect its command client. Network/core changes cancel or reject old results; a changed outbound selection is rejected before returning.

Only three fixed provider flows exist. ipquery uses `https://api.ipquery.io/` followed by `https://api.ipquery.io/<IP>?format=json`; the second response must identify the same normalized IP. ipwho uses `https://ipwho.is/`. The sole plaintext exception is the exact ip-api URL and minimal fields in `provider.go`. Redirects, arbitrary URLs, oversized bodies and cross-provider fallbacks are rejected.

## Evidence and limits

Source tests cover real local SOCKS5/CONNECT sockets, DNS-to-provider numeric destinations on one proxy, A/AAAA/CNAME, UDP-to-TCP DNS fallback, snapshot/group validation, redirect rejection, IP consistency, bounded bodies, shared deadlines and request cancellation with other sessions/the shared gRPC client alive. Run:

```sh
go test -race -count=1 ./common/scopedhttp ./daemon ./experimental/libbox
```

These tests prove the source/API contract in a controlled environment, not device-level absence of leaks. Android platform socket protection, vivo X200 firmware, actual VPN split routes, physical network transitions and packet captures still require on-device validation. Network change cancellation follows core notifications and is not a claim of atomic physical-interface isolation.
