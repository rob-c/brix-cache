# unix — XRootD `unix` (UNIX-name) authentication handler

## Overview

This subsystem implements the XRootD `unix` security protocol: the simplest
client-asserted authentication scheme, in which the client merely *declares* a
user name (and optional group) and the server takes it at face value. There is
no cryptographic proof of identity — `unix` is the moral equivalent of XRootD's
"trust the peer" mode. Because it is unverified, this handler is deliberately
**fail-closed**: by default it is only honoured for loopback peers, and it must
be explicitly selected (`brix_auth unix`) before the stream dispatcher will
ever route to it.

It sits in the **stream / `root://`** request lifecycle, downstream of
`kXR_login` and inside the `kXR_auth` dispatcher. The umbrella auth router
`brix_handle_auth_inner()` in [`../gsi/auth.c`](../gsi/auth.c) reads the
4-byte `credtype` field from the kXR_auth payload; when it sees `"unix"` and the
server is configured with `conf->auth == BRIX_AUTH_UNIX`, it calls
`brix_handle_unix_auth()` — the single public entry point exported by this
folder. (`unix` is not reachable over WebDAV/S3; those use cert/token/SigV4.)

The handler's job is narrow but security-sensitive: gate the request to trusted
peers, parse and *validate the characters* of the asserted user/group strings,
populate the per-connection identity (`ctx->dn`, `ctx->vo_list`,
`ctx->primary_vo`, and the canonical `ctx->identity`), register the session,
emit auth metrics, write a sanitised audit-log line, and reply `kXR_ok`. From
that point on the rest of the stack treats the connection exactly like any other
authenticated session — path ACLs, VO policy, and write gating all key off the
identity fields this handler fills in.

Why it exists: real grid sites need an unauthenticated/loopback path for
trusted local clients, sidecars, and intra-host tooling that should not have to
mint a proxy cert or token. Keeping `unix` in its own file (rather than inline
in the GSI dispatcher) isolates its trust assumptions and validation rules so a
reviewer can audit the entire attack surface of "the client names itself" in one
place.

## Files

| File | Responsibility |
|---|---|
| `auth.c` | The whole subsystem. Exports `brix_handle_unix_auth()` (declared in `../ngx_brix_module.h`). Internals: `brix_unix_peer_is_loopback()` (peer-address trust gate), `brix_unix_name_byte_ok()` + `brix_unix_copy_name()` (allow-list character validation + bounded copy of user/group), and `brix_unix_track_identity()` (VO-activity / unique-user metrics). |

## Key types & data structures

This subsystem defines no types of its own; it reads/writes shared ones:

- **`brix_ctx_t`** (`../types/context.h`) — per-TCP-connection session
  context. On success this handler sets `auth_done = 1`, clears
  `token_auth = 0`, and fills `dn[512]`, `vo_list[512]`, `primary_vo[128]`,
  and the canonical `identity` pointer. It reads the accumulated request via
  `ctx->payload` / `ctx->cur_dlen` and the issued `ctx->sessid`.
- **`ngx_stream_brix_srv_conf_t`** (`../types/config.h`) — server config; only
  field consulted is `unix_trust_remote` (the `NGX_CONF_UNSET`/merge-default-`0`
  flag behind the `brix_unix_trust_remote on|off` directive).
- **`brix_identity_t`** (`../types/identity.h`) — the canonical Phase-2
  identity object; populated via `brix_identity_set_dn(..., BRIX_AUTHN_UNIX)`
  and `brix_identity_set_vos_csv()`. `BRIX_AUTHN_UNIX` (`0x10`) is the
  auth-method tag stamped onto the identity and into metrics.
- **Size caps** (`../types/tunables.h`): `BRIX_SSS_USER_MAX` (128) and
  `BRIX_SSS_GROUP_MAX` (64) bound the parsed names; the `safe_user`/
  `safe_group` log buffers are `×4` to leave room for `\xNN` escaping.

## Control & data flow

**Entry:** `brix_handle_unix_auth(ctx, c, conf)` is called only from
`brix_handle_auth_inner()` in [`../gsi/auth.c`](../gsi/auth.c) (the kXR_auth
credtype router), which is itself reached from the stream handshake dispatcher
[`../handshake/dispatch.c`](../../protocols/root/handshake/dispatch.c) after `kXR_login`.

**Wire payload parsed:** the kXR_auth body for this scheme is
`"unix\0"` followed by `user[ group]` (space-separated). The handler validates
the `"unix\0"` tag, skips leading spaces, then extracts the user token and an
optional group token.

**Calls out to:**
- `../session/registry.h` → `brix_session_register(sessid, dn, vo_list, 0)`
  records the authenticated session for `kXR_bind` / cluster coordination.
- `../metrics/unified.h` → `brix_metric_auth(BRIX_PROTO_STREAM,
  BRIX_AUTHN_UNIX, ok)` on every outcome; plus `brix_track_vo_activity()`
  and `brix_track_unique_user()` (via `brix_metrics_shared()`) on success.
- `../types/identity.h` identity setters for the canonical identity object.
- `brix_sanitize_log_string()` (project-wide helper) before logging any
  wire-derived bytes.
- Response/exit is via the `BRIX_RETURN_OK` / `BRIX_RETURN_ERR` macros
  (`../types/tunables.h`) which fold access-log + per-op metric + `kXR_ok`/
  `kXR_error` framing into one call; `kXR_NoMemory` errors go through
  `brix_send_error()` directly.

**Return:** `NGX_OK`-class wire reply (`kXR_ok`) on success; a `kXR_error`
reply (always `kXR_NotAuthorized`, or `kXR_NoMemory` on alloc failure) on any
rejection. After success the connection proceeds to the normal opcode handlers
([`../read/`](../../protocols/root/read/), [`../write/`](../../protocols/root/write/), etc.), where the identity this
handler set drives [`../path/`](../../fs/path/) ACL/VO authorization.

## Invariants, security & gotchas

- **Fail-closed peer gate (`auth.c:167`).** Unless `conf->unix_trust_remote` is
  on, the request is rejected unless `brix_unix_peer_is_loopback(c)` is true.
  Loopback = IPv4 `127.0.0.0/8`, IPv6 `::1`, or `AF_UNIX`. Because `unix` is
  *unauthenticated*, exposing it to remote peers is an identity-spoofing hole —
  the directive default (`0`) plus the loopback check make remote use opt-in.
- **Only reachable when explicitly configured.** The dispatcher in
  `../gsi/auth.c` returns `kXR_NotAuthorized` ("unix auth not enabled") unless
  `conf->auth == BRIX_AUTH_UNIX`. This handler never runs for `auth both`,
  `gsi`, `token`, etc.
- **Strict character allow-list (`brix_unix_name_byte_ok`).** User/group names
  may contain only `[A-Za-z0-9_.@+-]`. Anything else → `kXR_NotAuthorized`.
  This keeps the asserted name safe to use as a metric label, log token, and
  identity/ACL key, and blocks injection of control bytes, spaces, or
  path-traversal characters into downstream policy matching.
- **Bounded copy, no overflow (`brix_unix_copy_name`).** Rejects empty names
  and any `len >= dst_len`; NUL-terminates. Names are then stored with
  `ngx_cpystrn` (size-bounded) into the fixed `ctx->dn` / `ctx->vo_list` /
  `ctx->primary_vo` buffers — never strcpy/strlen on wire data.
- **Group → VO mapping.** The optional UNIX group is copied into *both*
  `ctx->vo_list` and `ctx->primary_vo`, so VO-scoped path policy treats the
  asserted group as the VO. If no group is given, the VO fields stay empty and
  `brix_track_vo_activity()` is skipped.
- **Identity is fail-closed on OOM.** If `ctx->identity` is present but
  `set_dn`/`set_vos_csv` fails to allocate, the handler returns
  `kXR_NoMemory` rather than continuing with a half-populated identity.
- **Every exit path emits a metric.** Both success and each rejection call
  `brix_metric_auth(..., BRIX_AUTHN_UNIX, 0|1)` so auth-failure rate is
  observable. Metric labels stay low-cardinality (the method tag, not the user
  name); the *name* only ever appears in the sanitised audit log line.
- **Log strings are always sanitised.** `brix_sanitize_log_string()` is
  applied to user and group before the `unix auth OK` INFO line — even though
  they already passed the allow-list — keeping the audit log injection-proof.
- **Event-loop safe.** This handler does only in-memory parsing and SHM metric
  bumps — no blocking I/O — so it runs inline on the stream worker with no AIO
  offload (cf. [`../aio/`](../../core/aio/)).

## Entry points / extending

- **Add a new asserted-identity field** (e.g. honour a supplementary group):
  extend the parser in `brix_handle_unix_auth()` after the group block,
  validate it with `brix_unix_copy_name()`, and feed it through the identity
  setters — do not relax `brix_unix_name_byte_ok()` without a security review.
- **Adjust the trust policy:** the directive `brix_unix_trust_remote` is wired
  in the live `ngx_stream_brix_commands[]` table in
  [`../stream/module.c`](../../protocols/root/stream/module.c)
  → field `unix_trust_remote` in `../types/config.h`, defaulted in
  [`../config/server_conf.c`](../../core/config/server_conf.c). To add finer-grained
  trust (e.g. a CIDR allow-list) extend `brix_unix_peer_is_loopback()` and the
  config plumbing — keep the default fail-closed.
- **Add a sibling auth scheme:** mirror this file's shape (peer gate → parse →
  validate → fill identity → register → metric/log → return) and register the
  new credtype branch in `brix_handle_auth_inner()` in `../gsi/auth.c`.

## See also

- [`../gsi/auth.c`](../gsi/auth.c) — kXR_auth credtype dispatcher and the GSI
  sibling scheme; the only caller of this handler.
- [`../sss/`](../sss/) and [`../krb5/`](../krb5/) — peer auth schemes routed from
  the same dispatcher; `unix` reuses the SSS size caps (`BRIX_SSS_*`).
- [`../token/`](../token/) — WLCG/JWT bearer auth (HTTP + stream `ztn`).
- [`../session/`](../../protocols/root/session/) — `brix_session_register()` and the session
  registry that `kXR_bind`/cluster mode read.
- [`../metrics/`](../../observability/metrics/) — `brix_metric_auth`, VO-activity and
  unique-user tracking.
- [`../path/`](../../fs/path/) — consumes the identity (`dn`/`vo_list`) for ACL/VO
  authorization on every subsequent operation.
- [`../types/`](../../core/types/) — `brix_ctx_t`, `brix_identity_t`, config fields,
  and `BRIX_SSS_*` / `BRIX_AUTHN_UNIX` constants.
- [`../README.md`](../README.md) — master subsystem index.
