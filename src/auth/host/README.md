# host — host-based authentication for the `root://` stream protocol

## Overview

This subsystem implements the XRootD **`host`** security protocol (the wire
equivalent of upstream `XrdSecProtocolhost`) for `root://`/`roots://` clients.
It is XRootD's weakest and oldest scheme: the client merely *selects* `host` and
asserts no identity of its own. The server reverse-resolves the peer's socket
address to a hostname and, if that hostname matches a configured allowlist,
authenticates the connection **as that hostname**. It is one of several
pluggable stream credential types (`gsi`, `token`, `sss`, `unix`, `krb5`,
`pwd`, `host`), all dispatched from the single `kXR_auth` handler in
`../gsi/auth.c`.

Because a hostname (and, lacking DNSSEC, DNS itself) is spoofable, `host` is
**fail-closed and for trusted closed networks only**: it must be explicitly
selected (`xrootd_auth host`), an allowlist **must** be configured
(`xrootd_host_allow`; empty = deny all), and the identity always comes from the
socket's reverse-DNS — never from any client-asserted name. Isolating the scheme
in this one file keeps the spoofable surface in a single auditable place.

In the request lifecycle this sits at the **stream login/auth stage**. After the
handshake and `kXR_login`, the client sends a `kXR_auth` request whose credential
type is `host`; the dispatcher in `../gsi/auth.c` calls
`xrootd_handle_host_auth()` here. Only the `root://` stream path uses it; the
WebDAV/HTTPS and S3 paths use GSI certs, bearer tokens, and SigV4 and never enter
this code.

## Files

| File | Responsibility |
|---|---|
| `auth.c` | `xrootd_handle_host_auth(ctx, c, conf)` — per-connection runtime auth. Reverse-resolves the peer via `xrootd_acc_resolve_peer()` (the same circuit-breaker-bounded `getnameinfo` path XrdAcc host rules use), matches it against `xrootd_host_allow`, and on a match sets the connection identity (`ctx->dn` = the resolved hostname) + session registry entry + metrics, returning `kXR_ok`; otherwise `kXR_NotAuthorized`. Static helpers: `xrootd_host_pattern_match` (exact or leading-`.` domain-suffix match, case-insensitive) and `xrootd_host_allowed` (allowlist scan). |

There are no headers in this directory. The public entry point
`xrootd_handle_host_auth` is declared in `../ngx_xrootd_module.h`; the allowlist
(`xrootd_host_allow`) and `auth` selector live on `ngx_stream_xrootd_srv_conf_t`.
