# handshake — XRootD stream request entry point and opcode dispatcher

## Overview

This subsystem is the front door for the native XRootD binary protocol
(`root://` / `roots://`). After `connection/recv.c` has accumulated a complete
wire frame, control enters here twice: once for the very first 20-byte
*ClientInitHandShake* (handled by `xrootd_process_handshake`), and thereafter,
for every request header + payload, through the central router
`xrootd_dispatch`. Nothing in this directory touches the filesystem or builds an
operation response itself — it validates the protocol prologue, enforces the
session/auth/write/signing gates, and routes each opcode to the correct handler
in a sibling subsystem.

`xrootd_dispatch` is a layered fall-through router. It runs a fixed sequence of
phases — sigver verification, security-level enforcement, then four category
sub-dispatchers (session, read, write, signing) — short-circuited by proxy mode
and rate-limit/mirror hooks. Each sub-dispatcher inspects `ctx->cur_reqid` (the
parsed opcode) and either handles it or returns the sentinel
`XROOTD_DISPATCH_CONTINUE` (= `NGX_DECLINED`) so routing continues to the next
phase. An opcode that no sub-dispatcher claims falls through every layer and is
answered with `kXR_Unsupported`.

The gates in `policy.c` (`require_login`, `require_auth`, `require_write`) and
the request-signing logic in `sigver.c` are the fail-closed security spine of
the stream protocol: they are invoked *before* any handler runs, so a handler is
only ever reached for a session that has logged in, authenticated, and (for
mutations) been granted write access and a valid signature where policy demands
one. This is the stream-side analogue of the HTTP access-phase checks in
[`../webdav/`](../webdav/README.md) and [`../s3/`](../s3/README.md).

This subsystem is used by every `root://` request lifecycle: anonymous,
GSI-proxy, WLCG-token, SSS, and Kerberos sessions, as well as proxy/redirector
deployments (it hands off to [`../proxy/`](../proxy/README.md) and
[`../manager/`](../manager/README.md) once login completes in those modes).

## Files

| File | Responsibility |
|---|---|
| `handshake.h` | Internal prototypes shared across the dispatcher files: the four `xrootd_dispatch_*_opcode` sub-dispatchers, the three `xrootd_dispatch_require_*` gates, and the two signing helpers. Defines `XROOTD_DISPATCH_CONTINUE` (= `NGX_DECLINED`), the "not my opcode / keep routing" sentinel. |
| `client_hello.c` | `xrootd_process_handshake` — validates the initial 20-byte *ClientInitHandShake* (only the two magic fields `fourth==4` and `fifth==ROOTD_PQ` are checked), then replies with an 8-byte v5 body (`kXR_PROTOCOLVERSION` + `kXR_DataServer`) framed in a `ServerResponseHdr` with `streamid={0,0}`. Runs once per connection before any opcode. |
| `dispatch.c` | `xrootd_dispatch` — the central router. Sets `ctx->req_start`, runs sigver verify → security-level enforce → session dispatcher → (proxy short-circuit) → rate-limit gate → read dispatcher → write dispatcher → signing dispatcher, with mirror/wmirror hooks fired after read/write. Unclaimed opcode → `kXR_Unsupported`. |
| `dispatch_session.c` | `xrootd_dispatch_session_opcode` — routes the pre-auth / session-lifecycle opcodes: `kXR_protocol`, `kXR_login`, `kXR_auth`, `kXR_ping`, `kXR_set` (login-gated), `kXR_endsess`, `kXR_bind`. Handlers live in [`../session/`](../session/README.md). |
| `dispatch_read.c` | `xrootd_dispatch_read_opcode` — routes non-mutating / metadata opcodes (`kXR_stat`, `kXR_open` read-open, `kXR_read`, `kXR_close`, `kXR_dirlist`, `kXR_readv`, `kXR_query`, `kXR_prepare`, `kXR_pgread`, `kXR_locate`, `kXR_statx`, `kXR_fattr`, `kXR_clone`). Each case runs `require_auth` (via the `DISPATCH_RD`/`DISPATCH_RD_BOUND` macros) first; bound (secondary) streams are restricted to plain reads. |
| `dispatch_write.c` | `xrootd_dispatch_write_opcode` — routes mutating / namespace opcodes (`kXR_write`, `kXR_pgwrite`, `kXR_sync`, `kXR_truncate`, `kXR_mkdir`, `kXR_rm`, `kXR_writev`, `kXR_rmdir`, `kXR_mv`, `kXR_chmod`, `kXR_chkpoint`). Each case runs `require_write` (the `DISPATCH_WR` macro) — a stricter gate than `require_auth`. |
| `dispatch_signing.c` | `xrootd_dispatch_signing_opcode` — the final routing phase; claims only `kXR_sigver`, login-gates it, and calls `xrootd_handle_sigver` (in [`../session/`](../session/README.md)) which records the pending envelope for the *next* request. |
| `policy.c` | The access gates used by every sub-dispatcher: `xrootd_dispatch_require_login`, `xrootd_dispatch_require_auth`, `xrootd_dispatch_require_write` (auth + not-bound + `allow_write`). Also `xrootd_check_token_scope` — applies WLCG token read/write scope checks to a *logical* path (only when `ctx->token_auth`). |
| `sigver.c` | Request-signing verification: `xrootd_verify_pending_sigver` (checks the HMAC-SHA256 envelope queued by the previous `kXR_sigver` against the current header+payload) and `xrootd_signing_enforce_level` (rejects unsigned opcodes that the configured `security_level` 0–4 requires to be signed). |

## Key types & data structures

This subsystem owns no struct of its own; it manipulates the per-connection
`xrootd_ctx_t` (defined in [`../types/context.h`](../types/README.md)) and the
stream server config `ngx_stream_xrootd_srv_conf_t`. The fields it reads/writes:

- **Routing input:** `ctx->cur_reqid` (parsed opcode, host byte order, e.g.
  `kXR_open==3010`), `ctx->cur_dlen` (payload length), `ctx->hdr_buf[24]` (raw
  request header, `XRD_REQUEST_HDR_LEN`), `ctx->payload` (accumulated body).
- **Session/auth state (read by the gates):** `ctx->logged_in`,
  `ctx->auth_done`, `ctx->is_bound`, `ctx->token_auth`, and for token scope
  checks `ctx->identity` / `ctx->token_scopes` / `ctx->token_scope_count`.
- **Signing lifecycle (read/written by `sigver.c`):** `ctx->signing_active`,
  `ctx->signing_key[32]` (SHA-256 of the GSI DH shared secret),
  `ctx->sigver_pending`, `ctx->verified_signing`, `ctx->sigver_expectrid`,
  `ctx->sigver_seqno`, `ctx->sigver_nodata`, `ctx->sigver_hmac[32]`, and the
  cached `ctx->sigver_mac` / `ctx->sigver_mac_ctx` OpenSSL HMAC handles.
- **Config gates:** `conf->common.allow_write`, `conf->security_level`,
  `conf->proxy_enable`.
- **Wire structs (from `../protocol/`):** `ClientInitHandShake`,
  `ServerResponseHdr` (8 bytes, `XRD_RESPONSE_HDR_LEN`), and the opcode
  constants in `../protocol/opcodes.h` (`ROOTD_PQ`, `kXR_*`,
  `kXR_PROTOCOLVERSION`, `kXR_DataServer`).

`XROOTD_DISPATCH_CONTINUE` (a `#define` for `NGX_DECLINED`) is the routing
contract: any sub-dispatcher or gate returning it means "not handled / keep
going"; any other `ngx_int_t` is the final result for the request (usually the
return value of `xrootd_send_error` or `NGX_ERROR`).

## Control & data flow

**Entry.** [`../connection/recv.c`](../connection/README.md) is the only caller.
On the first frame of a connection it calls `xrootd_process_handshake`; on every
subsequent fully-framed request it calls `xrootd_dispatch(ctx, c, conf)`.

**`xrootd_dispatch` phase order (`dispatch.c`):**

```
connection/recv.c: ngx_stream_xrootd_recv()
  └─ handshake/dispatch.c: xrootd_dispatch()
       1. sigver.c: xrootd_verify_pending_sigver()   # check HMAC of prior kXR_sigver
       2. sigver.c: xrootd_signing_enforce_level()    # reject unsigned op if policy demands
       3. dispatch_session.c: xrootd_dispatch_session_opcode()  # protocol/login/auth/ping/set/endsess/bind
       4. [proxy_enable && logged_in] → proxy/forward.c: xrootd_proxy_dispatch()   # short-circuit
       5. ratelimit/ratelimit.c: xrootd_rl_stream_gate()  # may answer kXR_wait
       6. dispatch_read.c:  xrootd_dispatch_read_opcode()  → then stream mirror/wmirror hooks
       7. dispatch_write.c: xrootd_dispatch_write_opcode() → then stream mirror/wmirror hooks
       8. dispatch_signing.c: xrootd_dispatch_signing_opcode()  # kXR_sigver only
       9. fall-through → xrootd_send_error(kXR_Unsupported)
```

Each numbered step returns `XROOTD_DISPATCH_CONTINUE` to advance; any other
value is returned immediately to `recv.c`.

**Call-out targets.** The sub-dispatchers only route; the real work lives in
siblings:

- session opcodes → [`../session/`](../session/README.md) (login, auth, bind,
  ping, set, endsess, and `xrootd_handle_sigver`).
- read opcodes → [`../read/`](../read/README.md) (open/stat/statx/read/readv/
  pgread/locate/close/clone), [`../dirlist/`](../dirlist/README.md),
  [`../query/`](../query/README.md) (query/prepare), [`../fattr/`](../fattr/README.md).
- write opcodes → [`../write/`](../write/README.md)
  (write/pgwrite/writev/sync/truncate/mkdir/rm/rmdir/mv/chmod/chkpoint).
- proxy mode → [`../proxy/`](../proxy/README.md); rate limiting →
  [`../ratelimit/`](../ratelimit/README.md); shadow replay →
  [`../mirror/`](../mirror/README.md); responses framed via
  [`../response/`](../response/README.md) (`xrootd_send_error`,
  `xrootd_queue_response`).
- handlers themselves resolve client paths beneath the export root via
  [`../path/`](../path/README.md) and offload blocking I/O through
  [`../aio/`](../aio/README.md); this subsystem does neither directly.

**Auth happens elsewhere; gating happens here.** `dispatch_session.c` routes
`kXR_auth` to its handler `xrootd_handle_auth()`, which lives in
[`../gsi/`](../gsi/README.md) (`gsi/auth.c` — the credential-type front door),
*not* in `session/`. From there it dispatches by credential type to
[`../gsi/`](../gsi/README.md) (GSI proxy chains), [`../token/`](../token/README.md)
(JWT/WLCG bearer), [`../sss/`](../sss/README.md) (shared secret), and
[`../krb5/`](../krb5/README.md) (Kerberos). `session/` owns the *other*
session-lifecycle opcodes (login, bind, ping, set, endsess). The handshake gates
here only *enforce* the resulting `ctx->logged_in` / `ctx->auth_done` flags.

## Invariants, security & gotchas

- **Fall-through routing, fixed order.** Phases run in the exact order in
  `dispatch.c`. The signing dispatcher must remain last because
  `dispatch_signing.c` only handles `kXR_sigver`, while `sigver.c` (phase 1)
  inspects *every* request to validate the previously-queued envelope. Do not
  reorder; `kXR_bind` in particular must be tried before the login/auth gates
  because it legitimately arrives on a secondary connection *before* its login
  (`dispatch_session.c:149`).
- **Fail-closed gates.** `require_auth` returns access only when
  `logged_in && auth_done`; `require_write` additionally rejects bound streams
  and any session when `conf->common.allow_write == 0` (→ `kXR_fsReadOnly`,
  `policy.c:80`). `allow_write` is checked here, structurally before any token
  scope check — matching the project-wide invariant that write permission gates
  precede token scope.
- **Bound (secondary) streams are read-only.** `kXR_bind` channels exist for
  parallel reads of primary handles; every non-read file op on a bound stream is
  rejected with `kXR_NotAuthorized` (`dispatch_read.c:xrootd_reject_bound_nonread_file_op`,
  and again in `require_write`, `policy.c:75`).
- **Request signing is HMAC-SHA256 over seqno‖header‖payload.** `sigver.c`
  builds the MAC from a big-endian 8-byte seqno, the 24-byte `hdr_buf`, and (unless
  `sigver_nodata`) `cur_dlen` payload bytes, keyed by `ctx->signing_key` (SHA-256
  of the GSI DH secret). Comparison uses `CRYPTO_memcmp` (constant-time,
  `sigver.c:122`). An opcode mismatch between the sigver envelope and the covered
  request is `kXR_InvalidRequest`; a MAC mismatch is `kXR_NotAuthorized`.
- **`security_level` 0–4 escalation** (`xrootd_sigver_opcode_requires`,
  `sigver.c:188`): 0/1 require nothing; 2 ("standard") requires signatures on
  mutations + `kXR_open`; 3 requires signing for everything post-login; 4
  ("pedantic") additionally rejects a `sigver_nodata` envelope when a payload is
  present. Session-state opcodes (`login/protocol/auth/endsess/ping/sigver/bind`)
  are always allowed unsigned.
- **Token scope uses the *logical* path.** `xrootd_check_token_scope` must be
  passed the client-facing XRootD path (e.g. `/cms/store/x.root`), **not** the
  resolved filesystem path (`policy.c:12`). It is a no-op for non-token
  (`token_auth==0`) sessions — GSI/anonymous access is gated by `allow_write` and
  VO ACL instead. (Handlers, not this dispatcher, call it.)
- **Minimal handshake validation by design.** `client_hello.c` deliberately
  validates only the two magic fields it relies on (`fourth==4`,
  `fifth==ROOTD_PQ`); other prologue bytes are accepted. The reply uses
  `streamid={0,0}` because no request header exists yet. In XRootD v5 the client
  often packs handshake + `kXR_protocol` into one 44-byte TCP segment — framing
  of the trailing bytes is `recv.c`'s job, not this file's.
- **Single-threaded, no blocking here.** Dispatch runs on the worker event loop;
  it never sleeps, reads, or does filesystem I/O. Blocking work belongs to the
  handlers it routes to, which offload via [`../aio/`](../aio/README.md).

## Entry points / extending

**Add a new stream opcode:**
1. Decide its category and add a `case` to the matching file:
   `dispatch_session.c` (lifecycle), `dispatch_read.c` (non-mutating — wrap in
   `DISPATCH_RD` or `DISPATCH_RD_BOUND`), or `dispatch_write.c` (mutating — wrap
   in `DISPATCH_WR`). The macro applies the correct gate automatically; pass
   `conf` as a trailing arg only if the handler needs it.
2. Add the opcode constant to `../protocol/opcodes.h` and implement the
   `xrootd_handle_<op>` handler in the relevant sibling subsystem (declare its
   prototype where its peers are declared, e.g. `../read/*.h` / `../write/*.h`).
3. If the opcode should require a signature at some `security_level`, add it to
   the appropriate tier in `xrootd_sigver_opcode_requires` (`sigver.c`).
4. Update the routing comment block in `dispatch.c` and add the 3 standard tests
   (success + error + security-negative) per the project test rule.

**Add a new pre-dispatch gate** (e.g. a new policy check applied to all
requests): add a phase in `xrootd_dispatch` (`dispatch.c`) returning
`XROOTD_DISPATCH_CONTINUE` to proceed; keep the signing dispatcher last.

## See also

- [`../connection/README.md`](../connection/README.md) — frames bytes and
  invokes this subsystem (sole caller).
- [`../session/README.md`](../session/README.md) — login/auth/bind/ping/set/
  endsess and `kXR_sigver` handlers.
- [`../read/README.md`](../read/README.md),
  [`../write/README.md`](../write/README.md),
  [`../dirlist/README.md`](../dirlist/README.md),
  [`../query/README.md`](../query/README.md),
  [`../fattr/README.md`](../fattr/README.md) — opcode handlers.
- [`../proxy/README.md`](../proxy/README.md),
  [`../manager/README.md`](../manager/README.md) — proxy/redirector handoff.
- [`../ratelimit/README.md`](../ratelimit/README.md),
  [`../mirror/README.md`](../mirror/README.md) — the rate-limit gate and
  shadow-replay hooks fired inside `xrootd_dispatch`.
- [`../protocol/README.md`](../protocol/README.md),
  [`../types/README.md`](../types/README.md) — wire structs/opcodes and
  `xrootd_ctx_t`.
- [`../response/README.md`](../response/README.md) — `xrootd_send_error` /
  `xrootd_queue_response` framing helpers.
- [`../README.md`](../README.md) — source tree master index.
