# session — XRootD session lifecycle, identity binding & cross-worker registry

## Overview

This subsystem owns the **XRootD session layer** for `root://`/`roots://` stream
connections: the opcodes a client must complete *before* any file I/O, and the
shared-memory bookkeeping that keeps a session coherent across nginx worker
processes. It sits immediately after the raw TCP handshake/recv state machine
(`../connection/`) and just before the read/write/namespace handlers take over.
Every stream connection passes through here to establish protocol capabilities,
log in, optionally authenticate, and (for parallel transfers) bind secondary
data channels. None of this applies to the HTTP-side protocols (WebDAV/S3) — they
carry their own per-request auth and never enter this layer.

The canonical XRootD login sequence implemented here is:
`kXR_protocol` (capability negotiation) → `kXR_login` (username + session id) →
`kXR_auth` (credential exchange, GSI/token/SSS/krb5/unix — handled in `../gsi/`,
`../token/`, etc.) → file ops → `kXR_endsess` (graceful teardown). `kXR_protocol`
must be the first request; `kXR_ping` is allowed at any time. All other opcodes
require both `ctx->logged_in` **and** `ctx->auth_done` set on `brix_ctx_t`.
When `brix_auth=none`, `auth_done` is set immediately at login; otherwise it is
deferred until `kXR_auth` succeeds.

Two cross-cutting concerns live here because they are session-scoped but must
survive across worker boundaries. First, the **session registry** maps
`sessid → {dn, vo_list, token_auth}` in shared memory so a `kXR_bind` secondary
connection (or proxy-mode forwarding) can inherit a primary's authenticated
identity without re-authenticating. Second, the **published-handle table** lets a
secondary stream reopen and re-validate a primary's readable file handles even
when the primary was served by a *different* worker — nginx workers do not share
descriptors opened after fork, so the secondary reopens the canonical confined
path and verifies `device`/`inode` against the published entry.

This layer also configures **in-protocol TLS** (`kXR_ableTLS`/`kXR_wantTLS`),
arming a per-server `SSL_CTX` so a single listener can serve both cleartext
`root://` and TLS-upgraded `roots://` without a dedicated port, and implements
**request signing** (`kXR_sigver`), the HMAC-SHA256 anti-forgery/anti-replay
envelope used on GSI sessions.

## Files

| File | Responsibility |
|---|---|
| `protocol.c` | `kXR_protocol` handler — builds the 8-byte `ServerProtocolBody` (version + capability bitmask) and the optional `SecurityInfo` trailer. Caps are computed live from `conf`: always `kXR_isServer \| kXR_suppgrw \| kXR_supposc`, plus `kXR_isManager` (manager/supervisor/virtual-redirector), `kXR_attrSuper`, `kXR_attrVirtRdr`, `kXR_attrMeta`, `kXR_attrProxy`, `kXR_attrCache`, `kXR_collapseRedir`, `kXR_recoverWrts`, and `kXR_haveTLS\|kXR_gotoTLS\|kXR_tlsLogin` when TLS is offered. The trailer advertises offered auth methods (4-char tags `sss`/`unix`/`krb5`/`ztn`/`gsi`, in that order) and a `ServerResponseReqs_Protocol` carrying `seclvl=conf->security_level` (and `kXR_secOData` when `seclvl>=4`). Arms `ctx->tls_pending`; rejects `kXR_wantTLS` with `kXR_TLSRequired` when no TLS context is configured. |
| `login.c` | `kXR_login` handler — copies the 8-byte null-padded ASCII username and **rejects NUL/non-printable bytes** (blocks `"a\x00evil"` truncation impersonation), stores `login_user`/`login_pid`, sets `logged_in=1`. For `auth=none` it also sets `auth_done=1`, registers the session, and replies sessid-only; otherwise it re-fetches the live merged `srv_conf` and replies `sessid + "&P=..."` naming the required plugin (`ztn,v:10000` / `sss,0.+<lifetime>:` / `unix` / `krb5,<principal>` / `ztn`+`gsi` for both / `gsi,...,ca:<hash>`). Refuses login with `kXR_Overloaded` if `conf->cms_suspended`. Counts the `LOGIN` op-ok metric and writes the access log. |
| `lifecycle.c` | `kXR_ping` (no-op liveness reply) and `kXR_endsess` (graceful teardown). **`endsess` is session-scoped**: it terminates the session NAMED by `req->sessid`, not merely the connection it arrives on. If the named sessid is NOT this connection's own (e.g. the official client's reconnect recovery releasing its previous, dropped session on a freshly re-logged-in connection), it only `brix_session_unregister()`s that session and leaves THIS connection authenticated. Only an endsess for the connection's OWN session forwards the upstream frame (proxy), runs `brix_on_disconnect` + `brix_close_all_files`, and **clears `logged_in`/`auth_done`** (enforces GSI proxy-expiry / session-end). Clearing auth on a *foreign*-session endsess (the old behavior) made the official client's recovery `kXR_open` fail with `kXR_NotAuthorized` on a lossy link. Guarded by `tests/test_endsess_session_scope.py`. |
| `bind.c` | `kXR_bind` handler — attaches a read-only secondary data channel. Looks up the primary's sessid via `brix_session_lookup`, inherits its identity (DN/VO/token_auth → `ctx->identity` via `brix_identity_set_*`), assigns a `pathid` from a static counter cycling 1–253 (0 reserved for the primary), sets `is_bound/logged_in/auth_done=1`, and replies with the single-byte pathid. Fails closed (`kXR_NotAuthorized`) if the sessid is unknown. |
| `signing.c` | `kXR_sigver` handler — phase-1 of request signing. Parses `expectrid` (u16) + `seqno` (u64 BE via `be64toh`); when `signing_active`, enforces strictly-increasing `seqno` (replay rejection) and, for `kXR_SHA256_sig` without `kXR_rsaKey_sig`, stores the expected 32-byte HMAC + `expectrid`/`nodata` as pending state on `ctx`. RSA-signed requests are accepted unverified; non-GSI sessions accept sigver without enforcement. Phase-2 verification happens in `../handshake/`. |
| `tls_config.c` | `brix_configure_tls()` — postconfig builder for the in-protocol TLS `SSL_CTX` (TLSv1.2/1.3, server cert+key from `conf->certificate`/`certificate_key`), optional kTLS send-offload (`SSL_OP_ENABLE_KTLS`, gated on `tls_ktls`, enables sendfile over TLS) and the OCSP-stapling status callback `brix_ocsp_stapling_cb`. Runs once per TLS-enabled server block; emerg-fails if cert/key are missing. |
| `registry.c` | Shared-memory **session registry**: zone creation/sizing (`brix_configure_session_registry`, sized by runtime `slots`), `*_shm_init_zone`, and the `register`/`lookup`/`unregister` lifecycle. Includes the Phase-27 LRU reap-on-full (evict the global-LRU slot older than `BRIX_SESSION_REAP_MIN_AGE_MS` to defeat slot-exhaustion DoS) and emits `session_registry_full_total`/`session_evict_total` metrics. |
| `handles.c` | Shared-memory **published-handle table**: `publish`/`lookup`/`lookup_hint`/`unpublish`/`unpublish_all` plus the `brix_shared_handle_same_key` key matcher and zone init. Publishes only *readable* primary handles (write-only/`path==NULL` → entry removal); carries `device`/`inode`/`cached_size`/`path` for secondary reopen + identity re-validation. `lookup_hint` adds a caller-cached slot index for O(1) per-read revalidation on hot bound streams (Phase 33 C2). |
| `registry.h` | Types/prototypes/capacities for both shared tables: `brix_session_entry_t`, `brix_shared_handle_entry_t`, table structs (shmtx `lock` first), the sizing factors, and the full registry/handle API. |
| `session.h` | Documents the login state machine and declares the session opcode handlers + the GSI bucket/x509 helpers (`gsi_find_bucket`, `brix_gsi_parse_x509`, `brix_handle_auth` — **implemented in `../gsi/`**, declared here for the dispatcher). |

## Key types & data structures

- **`brix_session_entry_t`** (`registry.h`) — one registry slot: `sessid[16]`,
  `dn[512]`, `vo_list[512]`, `token_auth`, `in_use`, and `last_seen` (the LRU key
  for reap-on-full). Models the *identity* a bound secondary or proxy inherits.
- **`brix_shared_handle_entry_t`** (`registry.h`) — one published-handle slot,
  keyed by `sessid + handle_index`: `readable`/`writable`/`from_cache`/`is_regular`
  flags, `device`/`inode` (stale-reference defence), `cached_size`, and the
  canonical confined `path[BRIX_MAX_PATH+1]` for reopen. Write-only handles are
  never published.
- **`brix_session_table_t` / `brix_shared_handle_table_t`** (`registry.h`) —
  the shared regions. Each embeds an `ngx_shmtx_sh_t lock` **as its first field**
  (required by `ngx_shmtx_create`). The session table is variable-length
  (`slots[]`, sized by the runtime `capacity` field); the handle table is fixed at
  `BRIX_SESSION_HANDLE_SLOTS` (`BRIX_SESSION_HANDLE_SESSIONS 512 ×
  BRIX_SESSION_HANDLES_PER_SESSION 8 = 4096`, deliberately decoupled from the
  per-connection `BRIX_MAX_FILES=16` to bound idle RAM — see the ~50 MB sizing
  note in `registry.h`).
- **Session state on `brix_ctx_t`** (`../types/context.h`) — set here and read
  everywhere downstream: `logged_in`, `auth_done`, `sessid`, `login_user`,
  `login_pid`, `is_bound`, `bound_sessid`, `pathid`, `token_auth`, `tls_pending`,
  plus the sigver pending block (`sigver_pending`, `sigver_hmac[32]`,
  `sigver_expectrid`, `sigver_seqno`, `sigver_nodata`, `last_seqno`,
  `signing_active`).
- **`ServerProtocolBody` / `SecurityInfo` / `ServerResponseReqs_Protocol`** —
  the on-wire structs assembled in `protocol.c`; the 8-byte body always precedes
  the optional security trailer.

## Control & data flow

**Entry.** The stream dispatcher (`../handshake/dispatch.c` →
`../handshake/dispatch_session.c`) routes opcodes here:
`kXR_protocol → brix_handle_protocol`, `kXR_login → brix_handle_login`,
`kXR_auth → brix_handle_auth` (in `../gsi/`), `kXR_ping → brix_handle_ping`,
`kXR_endsess → brix_handle_endsess`, `kXR_bind → brix_handle_bind`.
`kXR_sigver` is gated/routed by the signing dispatcher in `../handshake/`, which
also consumes the pending HMAC stored by `signing.c` *before* the next opcode runs.

**Calls out to.**
- `../gsi/`, `../token/`, `../sss/`, `../krb5/`, `../unix/` — actual credential
  verification (`kXR_auth`); on success they populate DN/VO and call
  `brix_session_register()`.
- `../crypto/` — HMAC-SHA256 for sigver; `../crypto/ocsp.h` for the stapling
  callback in `tls_config.c`.
- `../config/postconfiguration.c` — invokes `brix_configure_tls()` and
  `brix_configure_session_registry()` once at startup (the latter sized by the
  max `registry_slots` across server blocks).
- `../metrics/` — `op_ok[BRIX_OP_LOGIN]`, `op_ok[BRIX_OP_PING]`,
  `session_registry_full_total`, `session_evict_total`.
- `../proxy/` — `lifecycle.c` forwards `kXR_endsess` to the upstream; proxy and
  bound paths call `brix_session_lookup()`/`brix_session_handle_lookup()`.

**Called into (registry/handles consumers).**
- Primaries publish handles from the open path (`../read/`) and `../tpc/` via
  `brix_session_handle_publish()`.
- Secondaries revalidate via `../connection/fd_table.c`
  (`brix_session_handle_lookup_hint`) and the proxy forwarding helpers in
  `../proxy/`.
- `brix_session_unregister()` is driven by `kXR_endsess` and the disconnect
  path, and transitively unpublishes all of that session's handles.

## Invariants, security & gotchas

- **Fail-closed auth boundary.** Downstream handlers require `logged_in &&
  auth_done`. `kXR_endsess` resets both to 0 **only when it names this
  connection's own session** (`req->sessid == ctx->sessid`) so a client cannot
  keep operating after its own session end or GSI proxy expiry; an endsess naming
  a *different* session unregisters that session but leaves this connection
  authenticated (required for official-client reconnect recovery).
  `kXR_bind` only sets them after a successful registry lookup (`bind.c:78`).
- **Username sanitisation.** `login.c` rejects NUL and non-printable bytes
  (`< 0x20 || > 0x7e`) in the 8-byte username field; a mid-field NUL would
  otherwise truncate `"a\x00evil"` to `"a"` and impersonate another user
  (`login.c:85-93`).
- **Bound streams are read-only data channels.** `handles.c` refuses to publish
  write-only handles (`!file->readable` or `path==NULL` → treated as removal of
  any stale entry), and bound connections may not open/close/write/stat. Pathid 0
  is reserved for the primary; the counter cycles 1–253 (`bind.c:111-115`).
- **Stale-reference defence.** Secondaries never inherit a raw fd; they reopen the
  published canonical `path` and re-check `device`/`inode` (and `cached_size`)
  against the entry. A replaced/deleted path fails the match and the read is
  declined. `lookup_hint` keeps the full key (`in_use + sessid + handle_index`)
  re-check under the lock, so a primary close/reuse (which clears `in_use`)
  correctly revokes the fast path (`handles.c:209-245`).
- **Sigver replay protection.** `seqno` must *strictly increase*
  (`signing.c:85`); only `kXR_SHA256_sig` without `kXR_rsaKey_sig` is actually
  verified (RSA path accepted unchecked). Sigver on non-GSI sessions
  (`!signing_active`) is accepted but not enforced (some clients send it
  unsolicited).
- **Shared-memory discipline.** Every table access is serialised by its zone
  shmtx (`brix_session_mutex` / `brix_handle_mutex`); the `lock` field **must
  be first** in each table struct. Zone init uses the `(void *) 1` sentinel in
  `->data` to detect "already initialised by another worker"; `session_table()` /
  `handle_table()` return `NULL` until init completes, and every op no-ops
  gracefully on `NULL`.
- **Reap-on-full, not reject-only.** A full session table evicts the global-LRU
  slot if it is older than `BRIX_SESSION_REAP_MIN_AGE_MS` (60 s) so an attacker
  cannot permanently deny logins; fresh slots are never thrashed. The reap
  unpublishes the victim's handles *after* releasing the session mutex —
  preserving the canonical lock order (session-mutex then handle-mutex, matching
  `brix_session_unregister`) to avoid deadlock (`registry.c:281-289`).
- **TLS vs cleartext.** `tls_config.c` only *builds* the context and `protocol.c`
  arms `tls_pending`; the actual upgrade and the memory-buffer-vs-sendfile
  decision live in `../connection/` and `../read/`. kTLS is opt-in
  (`SSL_OP_ENABLE_KTLS`), only helps with HW-offload NICs, and OpenSSL silently
  falls back to userspace TLS when the cipher/kernel can't offload — the read path
  re-checks `BIO_get_ktls_send()` per connection.
- **`kXR_protocol` must be first; capability flags are computed from live
  `conf`** (manager/supervisor/virtual-redirector/cache/proxy/meta/collapse/
  recover), so changing server mode changes what clients are told without touching
  this file's logic.

## Entry points / extending

- **New session opcode:** add `brix_handle_<op>()` here, declare it in
  `session.h` (and `../ngx_brix_module.h` if the dispatcher needs it), then
  register the case in `../handshake/dispatch_session.c`. Add the 3 required tests
  (success + error + security-negative).
- **New advertised capability flag:** OR the bit into the `caps` computation in
  `protocol.c` (gated on the relevant `conf` field) and, if it is an auth method,
  add its 4-char tag to the `SecurityInfo` trailer (in `protocol.c`) **and** the
  `&P=` block in `login.c`.
- **New session/handle registry field:** extend the struct in `registry.h`,
  populate it in `register`/`publish`, and bump the consumers
  (`../connection/fd_table.c`, `../proxy/`). Mind the fixed handle-table sizing
  factors in `registry.h` if you grow the entry.
- **New TLS knob:** add the directive/field in `../config/`, then apply it inside
  `brix_configure_tls()` (guard new OpenSSL options with `#ifdef`).

## See also

- `../handshake/README.md` — opcode dispatcher; sigver phase-2 verification.
- `../connection/README.md` — accept/recv state machine; `fd_table.c` bound-handle
  reopen/validation.
- `../gsi/README.md`, `../token/README.md` — `kXR_auth` credential verification
  that feeds `brix_session_register()`.
- `../proxy/README.md` — endsess forwarding and bound/session lookup in proxy
  mode.
- `../read/README.md`, `../tpc/README.md` — primaries that publish handles.
- `../crypto/README.md` — HMAC + OCSP helpers used by `signing.c`/`tls_config.c`.
- `../config/README.md`, `../metrics/README.md` — postconfig wiring and counters.
- `../README.md` — master subsystem index.
