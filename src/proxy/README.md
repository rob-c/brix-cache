# proxy — Transparent XRootD reverse proxy (`xrootd_proxy`)

## Overview

This subsystem turns nginx-xrootd into a **transparent reverse proxy** for an
existing XRootD storage cluster. When `xrootd_proxy on` is set in a `server {}`
block, the local node authenticates the client (token / GSI / SSS / anonymous),
terminates its TLS, and then forwards every post-login `root://` opcode verbatim
to a configured upstream XRootD server — collecting metrics, audit records, and
applying optional path rewriting along the way. The backend is invisible to
clients: they see one endpoint, while the proxy lazily opens a backend
connection, bootstraps it, translates file handles end-to-end, and relays
responses with the client's own streamid. This is the wire-level counterpart to
the HTTP/WebDAV proxy (`../webdav/proxy.c`); both live in front of a remote
origin, but this one speaks the binary XRootD protocol through nginx's **stream**
module.

Control enters here from a single short-circuit in the stream dispatcher:
`src/handshake/dispatch.c` calls `xrootd_proxy_dispatch()` for every opcode once
`conf->proxy_enable && ctx->logged_in` is true, *before* the local read/write
handlers run (so no local filesystem path is ever resolved in proxy mode). From
that point the proxy owns the request: it returns `NGX_OK`/`NGX_ERROR`/`NGX_DONE`
and drives an independent event-loop state machine on the **upstream** socket
(`xrootd_proxy_read_handler` / `xrootd_proxy_write_handler`) while the client
read loop is parked in the `XRD_ST_PROXY` state.

The proxy is fully event-driven and never blocks. It implements a multi-phase
upstream lifecycle — async TCP connect → optional TLS → XRootD bootstrap
(handshake + `kXR_protocol` + `kXR_login` + optional `kXR_auth`) → IDLE →
FORWARDING — plus several transparency features the client never sees:
file-handle translation, lazy-open for `kXR_bind` secondary channels,
`kXR_wait` retry with timers, `kXR_redirect` follow-through (up to 3 hops),
zero-copy `splice()` for plaintext reads, a worker-local connection pool keyed by
auth credentials, per-upstream health tracking, and JSON audit logging of file
and path-mutation operations.

Upstream credentialing supports anonymous login, forwarding the client's WLCG
bearer token as a `ztn` credential, SSS keys (global or per-upstream), and a
file-based token bridge — selected by `xrootd_proxy_auth` and per-endpoint
overrides on `xrootd_proxy_upstream`.

## Files

| File | Responsibility |
|---|---|
| `proxy.h` | Public API: `xrootd_proxy_dispatch()` (the dispatcher entry point), `xrootd_proxy_cleanup()`, and the four `xrootd_conf_set_proxy_*` directive handlers. Opaque `xrootd_proxy_ctx_t`. |
| `proxy_internal.h` | Internal contract: `xrootd_proxy_ctx_t` state struct, `xrootd_proxy_fh_entry_t` handle map, state-machine enums (`xrootd_proxy_up_state_t`, `xrootd_proxy_bs_t`), pool/health structs, constants, and all cross-file prototypes grouped by source file. |
| `forward_relay_dispatch.c` | `xrootd_proxy_dispatch()` — lazy-init the proxy ctx + connect on first opcode; queue requests in `saved_req` while bootstrapping; forward when IDLE. `xrootd_proxy_dispatch_pending()` flushes the queued request after bootstrap (with bound-secondary lazy-open check). Compiled standalone. |
| `connect_upstream.c` | `xrootd_proxy_connect()` — endpoint selection (redirect > pool > atomic round-robin across *healthy* upstreams > single host), `getaddrinfo` (tries each resolved address), non-blocking socket + async `connect()`, connect-timeout armed on the *write* timer, optional TLS start, and the 68-byte bootstrap frame builder (hello + `kXR_protocol` + `kXR_login`, with a unique virtual PID per connection and a login username resolved from `proxy_login_user`). TLS handshake-done callback. |
| `connect_lifecycle.c` | `xrootd_proxy_flush()` (drain `wbuf` to socket), `xrootd_proxy_abort()` (error handling with idle-reconnect budget), `xrootd_proxy_cleanup()` (audit abandoned handles, free buffers/timers/splice pipe, pool-return or close upstream — null `conn->data` first to prevent UAF). |
| `events_write.c` | `xrootd_proxy_write_handler()` — first write validates `SO_ERROR` after connect, starts TLS if configured, transitions to BOOTSTRAP; subsequent writes flush `wbuf` and arm the read event. |
| `events_read.c` | `xrootd_proxy_read_handler()` — edge-triggered drain loop: accumulate 8-byte response header + body (with `kXR_status` two-phase page-data expansion), relay `kXR_attn` frames out-of-band, then route to bootstrap handler or client relay by `proxy->state`. Manages read timeouts. |
| `events_bootstrap.c` | `xrootd_proxy_handle_bootstrap()` — the bootstrap phase machine; on `kXR_authmore` or a `P=ztn` login hint, builds and sends `kXR_auth` (`ztn` bearer-token, SSS credential, or file-token) per the effective auth policy; transitions to IDLE and dispatches any queued request. |
| `events_splice.c` (Linux) | Zero-copy fast path for plaintext `kXR_read`/`kXR_pgread` bodies: `xrootd_proxy_try_splice()` (gating + header send), `xrootd_proxy_splice_pump()` (upstream→pipe→client via a 1 MiB kernel pipe), client-writable handler, and post-splice byte accounting. |
| `forward_request.c` | `xrootd_proxy_forward_request()` — copy client header+payload, then per-opcode: translate file handles (`open`/`read`/`write`/`close`/`stat`/`readv`/`writev`/`clone`/...), rewrite paths, capture audit paths, trigger bound-secondary lazy-open, save a `kXR_wait` retry copy, queue+flush to upstream. |
| `forward_relay_response.c` | `xrootd_proxy_relay_to_client()` — the response state machine: lazy-open completion, `kXR_wait` absorb+retry, `kXR_redirect` follow-through, path-op audit, upstream→local fhandle translation, byte metrics, streaming `kXR_oksofar`/`kXR_status` partials, and final relay back to the client. Compiled standalone. |
| `forward_relay_audit.c` | `proxy_write_path_audit()` — JSON audit line for path-mutation ops (`rm`/`mkdir`/`rmdir`/`mv`/`chmod`/`truncate`) including user identity and status. Compiled standalone. |
| `forward_rewrite_helpers.c` | `proxy_rewrite_path()` (single-path strip/add prefix), `proxy_rewrite_prepare_payload()` (per-line rewrite for `kXR_prepare`), `proxy_translate_fh()` (1-byte local→upstream handle swap via `fh_map`). |
| `forward_session_helpers.c` | `proxy_write_audit()` (per-handle close audit), `xrootd_proxy_wait_handler()` (retry timer), `xrootd_proxy_alloc_local_fh()` (free-slot scan), `xrootd_proxy_lazy_open()` (synthetic anonymous `kXR_open` for a bound-secondary handle published by its primary). |
| `pool.c` | Worker-local idle-connection pool (`xrootd_proxy_pool_get/put/init`) keyed by upstream index + auth type + bearer-token MD5; `pool_get` does a *random-start* health-aware scan, `pool_put` evicts the oldest when full (`XROOTD_PROXY_POOL_SIZE`); idle-timeout keepalive timers (re-arm without ping — a sent-but-unread ping would leave a stray `kXR_ok` in the socket); a pool-safe read handler (`xrootd_proxy_pool_read_handler`) that evicts on a stray event; per-upstream health tracking (`up_status_init`/`up_mark_failed`/`up_mark_ok`). |
| `directives.c` | nginx config parsers: `xrootd_proxy_upstream host[:port] [anonymous\|forward\|sss\|sss:<keyname>]`, `xrootd_proxy_auth`, `xrootd_proxy_login_user anonymous\|passthrough\|fixed:<name>`, `xrootd_proxy_path_rewrite /strip /add`, plus the static `proxy_parse_host_port()` (IPv6 `[addr]:port`, IPv4/hostname `host:port`, default port `1094`). First `xrootd_proxy_upstream` also back-fills the legacy single `proxy_host`/`proxy_port`. |

## Key types & data structures

- **`xrootd_proxy_ctx_t`** (`proxy_internal.h`) — the per-client-session proxy
  state, allocated from the *client* connection pool and hung off `ctx->proxy`.
  Holds the upstream `ngx_connection_t`, the two state enums, the response
  accumulator (`rhdr`/`resp_status`/`resp_dlen`/`resp_body`), the upstream write
  buffer (`wbuf`), the in-flight-request metadata (`fwd_reqid`, `fwd_streamid`,
  `fwd_local_fh`, `fwd_payload_len`), the bootstrap-deferred `saved_req`, the
  `kXR_wait` retry copy, `kXR_redirect` follow-through state, the
  lazy-open pending-fh queue, the file-handle map, and the `splice` pipe state.
- **`xrootd_proxy_fh_entry_t`** — one slot of the `fh_map[XROOTD_MAX_FILES]`
  handle-translation table: `upstream_fh` (`-1` = free, `255` = open pending),
  the open path, open timestamp, and bytes read/written (for the close audit).
- **`xrootd_proxy_up_state_t`** — upstream socket phase:
  `CONNECTING → TLS_HANDSHAKE → BOOTSTRAP → IDLE → FORWARDING`.
- **`xrootd_proxy_bs_t`** — bootstrap sub-phase:
  `HANDSHAKE → PROTOCOL → LOGIN → AUTH → DONE`.
- **`xrootd_proxy_pooled_conn_t`** — a parked idle connection: the conn, its
  upstream index, auth type, bearer-token MD5, idle timestamp, and ping/idle
  timer. Reused only when index+auth+token-hash all match.
- **`xrootd_proxy_up_status_t`** — per-upstream health: consecutive `fails`,
  last `checked` time, `down` flag.
- **`xrootd_proxy_upstream_t`** (`../types/config.h`) — a configured endpoint
  (`host`, `port`, per-upstream `auth` (`-1` = inherit), optional `sss_keyname`),
  pushed onto `conf->proxy_upstreams`. Auth/login policy enums
  (`XROOTD_PROXY_AUTH_*`, `XROOTD_PROXY_LOGIN_*`) also live there.

## Control & data flow

**Entry.** `../handshake/dispatch.c` calls `xrootd_proxy_dispatch(ctx, c, conf)`
for every opcode once `conf->proxy_enable && ctx->logged_in`, *after* session
opcodes are handled and *before* local read/write dispatch or rate limiting. The
function never returns `XROOTD_DISPATCH_CONTINUE`.

**First opcode (lazy connect).** `xrootd_proxy_dispatch()` allocates the proxy
ctx (`fh_map` all free), calls `xrootd_proxy_connect()`, and parks the client in
`XRD_ST_PROXY`. Connect tries the pool first (`pool.c`); a pooled hit skips
bootstrap and dispatches immediately. Otherwise it resolves DNS, starts an async
`connect()`, optionally TLS, and queues the 68-byte bootstrap frame. The
upstream `write`/`read` handlers (`events_write.c` / `events_read.c`) drive
bootstrap through `events_bootstrap.c`, which may inject a `kXR_auth` frame
(bearer/SSS/file token). On `BS_DONE` the state goes IDLE, the reconnect budget
resets, and any `saved_req` is dispatched.

**Steady state (forward / relay).** `xrootd_proxy_forward_request()`
(`forward_request.c`) copies the client frame, translates handles/paths, saves a
retry copy, and flushes to the upstream (state → FORWARDING; client →
`XRD_ST_PROXY`). The upstream read handler accumulates the reply and calls
`xrootd_proxy_relay_to_client()` (`forward_relay_response.c`), which performs
upstream→local handle translation, audit/metrics, follows redirects, absorbs
`kXR_wait`, streams `kXR_oksofar`/`kXR_status` partials, and finally queues the
response (with the client's original streamid) and resumes the client read loop
(state → IDLE; client → `XRD_ST_REQ_HEADER`).

**Calls out to:**
- `../handshake/` — the sole caller (`dispatch.c`); proxy short-circuits local dispatch.
- `../session/registry.h` — `xrootd_session_handle_lookup()` for bound-secondary lazy-open (`forward_session_helpers.c`).
- `../connection/handler.h` — `xrootd_schedule_read_resume()`, `xrootd_queue_response()`, `ngx_stream_xrootd_send`, the client `XRD_ST_*` states.
- `../session/` (login/bind) — `ctx->bearer_token`, `ctx->login_user`, `ctx->is_bound`, `ctx->bound_sessid` drive auth-forwarding and lazy-open.
- `../sss/` — `xrootd_sss_build_proxy_credential()` for SSS upstream auth.
- `../token/file.h` — `xrootd_token_read_file()` for the file-token bridge.
- `../gsi/` — `gsi/auth.c` defines the `ztn` wire format this proxy reproduces.
- `../metrics/metrics_macros.h` — `XROOTD_PROXY_METRIC_INC/ADD` (aggregate) and `XROOTD_PROXY_UP_INC/ADD` (per-upstream) counters.
- `../protocol/` — XRootD wire structs/opcodes (`ClientLoginRequest`, `ServerResponseHdr`, `kXR_*`, `XRD_REQUEST_HDR_LEN`).
- Sibling at the HTTP layer: `../webdav/proxy.c` (the WebDAV/HTTPS reverse proxy).

## Invariants, security & gotchas

- **No local filesystem access in proxy mode.** Because dispatch short-circuits
  before the local read/write handlers, no client path is ever resolved against
  the local export — confinement (`../path/`) is the upstream server's job. The
  proxy only *rewrites* path prefixes (`proxy_rewrite_path`), it does not confine.
- **File handles are namespaced and must be translated both ways.** The client
  sees the proxy's local handle (slot index in `fh_map`); the upstream sees its
  own. `kXR_open` responses are rewritten so `body[0]` = local handle with
  bytes 1–3 zeroed (local convention); every `read`/`write`/`readv`/`writev`/
  `clone` request is translated via `proxy_translate_fh()`. Sentinel values:
  `XROOTD_PROXY_FH_FREE` (`-1`) = free, `255` = open in flight (treated as "open"
  by has-open scans but skipped by abandoned-handle audit).
- **Event loop only; the two sockets are decoupled.** The proxy runs its own
  state machine on the upstream fd while the client read loop is suspended in
  `XRD_ST_PROXY`. Edge-triggered epoll means the read handler must drain in a
  loop and must not `return` early after a bootstrap message — multiple bootstrap
  responses (or a trailing `kXR_ok` after `kXR_oksofar`) can arrive in one TCP
  segment with no further wakeup (`events_read.c`, `events_splice.c`).
- **TLS vs splice are mutually exclusive.** `splice()` bypasses the TLS layer, so
  `xrootd_proxy_try_splice()` declines if either side is `ssl != NULL`. Splice is
  only for plaintext `kXR_read`/`kXR_pgread` with `kXR_ok`/`kXR_oksofar`. The
  8-byte response header (with the client's streamid) is sent ahead of the body;
  if that small send is incomplete the path declines back to buffering. The kernel
  pipe is lazily `pipe2()`-created and best-effort enlarged to 1 MiB
  (`F_SETPIPE_SZ`) to cut syscalls ~16x; it is filled from upstream only when
  empty and drained to the client first to avoid spurious-EAGAIN wakeups /
  deadlock. After a spliced `kXR_oksofar` the upstream read event is re-posted
  (`ngx_post_event`) because edge-triggered epoll will not fire again for an
  already-buffered trailing `kXR_ok` (`events_splice.c`).
- **`kXR_status` two-phase framing.** pgread/pgwrite send a 24-byte fixed body
  with `bdy.dlen` more page bytes following; the read handler expands `resp_body`
  to `24 + extra` (`events_read.c`), but the relayed header keeps `dlen = 24`
  (`forward_relay_response.c`) — the client derives the trailer length from
  `body[12:16]`, and `resptype == kXR_PartialResult (0x01)` keeps the stream open.
- **Transparency features the client must not observe:** `kXR_wait` is absorbed
  and the request silently retried via a timer (max `XROOTD_PROXY_MAX_WAIT_RETRIES`,
  capped at `XROOTD_PROXY_MAX_WAIT_SECS`); `kXR_redirect` is followed in-process
  (max 3 hops) by reconnecting and re-issuing the saved request; `kXR_attn` is
  relayed using its *own* streamid and does not satisfy the FORWARDING state.
- **Use-after-free guards.** Pooled connections set `conn->data = pc` (not the
  proxy ctx, which lives in the client pool and is freed at session end) and
  install `xrootd_proxy_pool_read_handler` so a stray upstream event evicts
  cleanly. `cleanup()` nulls `conn->data` before `ngx_close_connection`. Read/
  write handlers bail if `proxy == NULL` or `ctx->destroyed`. The stale read
  timer is explicitly cancelled after a full relay to avoid a 60s-later
  spurious-IDLE abort (`events_read.c:268`).
- **Idle-only reconnect recovery.** `xrootd_proxy_abort()` transparently
  reconnects (re-bootstrapping) instead of failing the client *only* when the
  upstream dropped while `XRD_PX_IDLE` **and** no handle is open (`upstream_fh`
  neither free nor the `255` pending sentinel), drawing from a per-connection
  `reconnect_left` budget that is reset on every successful bootstrap. A drop
  mid-transfer (or with files open) is a hard abort → `kXR_IOError` to the client.
- **Login PID uniqueness.** Each upstream `kXR_login` mixes a monotonic counter
  into the PID (`connect_upstream.c`), because XRootD treats repeated logins from
  the same PID as reconnects and applies a backoff stall.
- **Auth domains stay separate / fail-closed.** Upstream auth uses the configured
  policy only (anonymous / forward-bearer-`ztn` / SSS / file-token); any
  `kXR_authmore` without a usable credential aborts the session. SSS keys may be
  per-upstream (`sss:<keyname>`).
- **Pool reuse is credential-scoped.** A pooled connection is reused only when
  upstream index, auth type, *and* bearer-token MD5 all match — a forwarded-token
  session never reuses another user's authenticated backend connection.
  Redirected connections are never pooled (too transient).
- **Audit & metric discipline.** Audit JSON is written with non-blocking
  `ngx_write_fd` only when `proxy_audit_log_fd != NGX_INVALID_FILE`; abandoned
  open handles are audited at cleanup. Metric labels remain low-cardinality
  (no paths) — paths live only in audit records, never in counter labels.

## Entry points / extending

- **Handle a new opcode that carries file handles:** add a `case` in the switch
  in `xrootd_proxy_forward_request()` (`forward_request.c`) to translate the
  handle byte(s) with `proxy_translate_fh()` at the correct payload offset, and a
  matching translation/metrics branch in `xrootd_proxy_relay_to_client()`
  (`forward_relay_response.c`). Anything without a case is forwarded verbatim.
- **Add a path-mutation audit op:** add the opcode to the `kXR_rm/...` capture
  switch in `forward_request.c` (set `fwd_path`/`fwd_path2`/`fwd_path_audit`) and
  to the `op_str` switch in `proxy_write_path_audit()` (`forward_relay_audit.c`).
- **Add a config directive:** declare the field in `../types/config.h`, register
  the `ngx_command_t` in `../config/directives.c`, and either reuse an existing
  `xrootd_conf_set_proxy_*` handler or add one in `directives.c`. New top-level
  blocks require `./configure`; field-only changes do not.
- **Add a proxy metric:** add the field to the proxy metric struct in
  `../metrics/`, then call `XROOTD_PROXY_METRIC_INC/ADD(ctx, field)` plus the
  per-upstream `XROOTD_PROXY_UP_INC/ADD(proxy, field)` at the callsite.
- **Add an upstream auth method:** extend `XROOTD_PROXY_AUTH_*` (`../types/config.h`),
  parse it in `xrootd_conf_set_proxy_auth` / per-upstream parser (`directives.c`),
  and build the `kXR_auth` frame in the `LOGIN` phase of `events_bootstrap.c`.

## See also

- `../handshake/README.md` — the dispatcher that short-circuits into this subsystem.
- `../session/README.md` — login/bind state, bound-secondary handle registry.
- `../sss/README.md`, `../gsi/README.md`, `../token/README.md` — upstream credential sources.
- `../webdav/README.md` — the HTTP-layer reverse proxy counterpart (`proxy.c`).
- `../metrics/README.md` — the `XROOTD_PROXY_*` counter macros.
- `../protocol/README.md` — XRootD wire structs and opcode constants.
- `../README.md` — master subsystem index.
