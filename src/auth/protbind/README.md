# protbind — per-host authentication-protocol binding (XRootD `sec.protbind`)

## Overview

This subsystem answers one question for every incoming connection: **which
credential sources may this particular peer use, and in what order?** It is the
BriX implementation of XRootD's `sec.protbind` directive:

```
sec.protbind   <host-template> [ none | [only] <prot> [<prot> ...] ]
brix_protbind  <host-template> [ none | [only] <proto> [<proto> ...] ]   # root://
brix_webdav_protbind <host-template> [ none | [only] <proto> ... ]       # HTTP/WebDAV
```

Before this existed, `brix_auth <mode>` gave one global answer for the whole
listener — and `both` (ztn + gsi) was the only way to offer more than a single
scheme, in one hard-coded order. A site that wants "GSI only from the WAN,
token-or-unix from the local farm, no auth at all from the monitoring box"
could not express it. `brix_auth` is still the default and still decides alone
when no rule is written; a matching rule *replaces* that decision with its own
**ordered** protocol list.

That list drives two things which must never disagree:

1. **Advertisement** — the `&P=<proto>[,<parms>]` blocks concatenated into the
   `kXR_login` security token (`../../protocols/root/session/login.c`), emitted
   in the resolved order so a stock XRootD client picks the site's preferred
   scheme first. This is the "true multi-protocol sectoken": one block per
   bound protocol rather than one pre-baked string per `brix_auth` mode.
2. **Enforcement** — the credential type actually accepted at `kXR_auth`
   (`../gsi/auth.c`) and the credential sources actually run in the WebDAV
   access phase (`../../protocols/webdav/access_auth.c`). A client may send any
   credtype regardless of what was advertised, so membership is re-checked at
   use; advertisement is a hint, the set is the policy.

The engine is deliberately **protocol-agnostic** — `match.c`, `policy.c` and
`config.c` know nothing about `brix_ctx_t`, `ngx_http_request_t` or the XRootD
wire. Only `peer.c` binds to a stream connection. That is what lets the HTTP
frontend consume the identical rules, grammar and error messages, so one policy
written in the config means the same thing on `root://` and on `https://`. A
rule may name a scheme that has no transport on a given frontend (`sss` over
HTTP, say); that entry is simply skipped there rather than rejected at parse
time, mirroring how a single upstream `sec.protbind` line serves every XRootD
protocol at once.

Semantics follow upstream exactly:

| Form | Meaning |
|---|---|
| `<tpl> <p1> <p2>` | `p1`, `p2` first, then the remaining protocols of the base set |
| `<tpl> only <p1>` | `p1` and **nothing** else |
| `<tpl> none` | matching hosts authenticate with nothing (anonymous) |

**First matching rule wins**, so a `*` catch-all must be written last — an
XRootD operator's existing muscle memory transfers unchanged. A template is
matched against the peer's reverse-resolved hostname first and then its IP
literal, and follows `XrdOucNList`: at most one `*`, splitting the template
into a prefix and a suffix that must *both* match, case-insensitively.

Reverse DNS blocks the event loop, so it is paid for at most once per
connection and only when some template could actually consult a name: a
wildcard-only ruleset (`brix_protbind * ztn gsi`, the dominant configuration)
never resolves at all. When a lookup is needed it goes through
`brix_acc_resolve_peer()` — the circuit-breaker-bounded path XrdAcc `h <host>`
rules already use — and lands in the one per-connection cache that both
subsystems read, so a session using both features resolves once.

## Files

| File | Responsibility |
|---|---|
| `protbind.h` | Public API. `brix_protbind_rule_t` (one parsed directive: template + mode + ordered `BRIX_AUTH_*` ids), `brix_protbind_set_t` (a resolved decision: ordered ids + `require_auth`), and the `BRIX_PROTBIND_ALL`/`ONLY`/`NONE` modes. `BRIX_PROTBIND_MAX_PROTOS` (8) caps a rule; a set is by-value, so no allocation happens on the request path. |
| `match.c` | Name↔id mapping and host-template matching, no policy. `brix_protbind_proto_id()` parses a protocol word (`gsi`, `ztn`/`token`, `sss`, `unix`, `krb5`, `host`, `pwd`) into a `BRIX_AUTH_*` id. `brix_protbind_host_match()` implements the `XrdOucNList` glob; `brix_protbind_needs_hostname()` reports whether any template is more than a bare `*` — the DNS short-circuit. |
| `policy.c` | The pure decision function. `brix_protbind_base_set()` projects a `brix_auth` mode onto a set (`both` → `{token, gsi}`, preserving the historical order so an un-ruled config is byte-identical); `brix_protbind_http_base()` does the same for the HTTP gate's cert→token→basic order. `brix_protbind_resolve()` walks the rules, first match wins, and applies the mode. `brix_protbind_allows()` is the enforcement predicate. |
| `config.c` | `brix_protbind_conf(cf, cmd, &rules)` — the shared directive parser behind both frontends' setters, so a setter is a single tail call. Lazily creates the array, rejects an empty template, an unknown or duplicated protocol, an over-long list, `none` with trailing arguments and `only` with none. Rejections are logged here as an `[emerg]` prefixed with `cmd->name`, so the two directives cannot report differently. |
| `peer.c` | The only impure file: binds the engine to a `root://` connection. `brix_protbind_peer_host_cached()` owns the per-connection reverse-DNS cache (including a negative result — a peer with no PTR record must not re-resolve every round); `brix_protbind_peer_host()` adds the wildcard-only short-circuit; `brix_protbind_resolve_ctx()` builds the base set from `conf->auth` and hands the resolver the peer's name and IP. |

Consumers: `../../core/config/policy.c` and `../../protocols/webdav/module_directives.c`
(directive setters), `../../protocols/root/session/login.c` (sec-token
emission), `../gsi/auth.c` (credtype admission),
`../../protocols/webdav/access_auth.c` (HTTP credential-source ordering), and
`../authz/auth_gate.c` (shares the peer-hostname cache).
