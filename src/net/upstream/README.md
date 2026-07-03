# upstream — outbound XRootD redirector/proxy client (manager-side server-to-server query)

## Overview

This subsystem is the **outbound** half of XRootD clustering: a small, fully
non-blocking XRootD *client* that the gateway speaks to a backend XRootD server
on its own. It is the mirror image of the inbound stream path — instead of
*serving* a `root://` client, it *connects out*, completes the XRootD bootstrap
(handshake → protocol → optional TLS upgrade → login → optional token auth), then
relays one saved client opcode and translates the backend's reply back to the
original client. It exists so that a node running in **manager / redirector mode**
can confirm a file with the data server that owns it and hand the client a
`kXR_redirect`, rather than blindly trusting its registry.

It is entered from two opcode handlers, both only when a local lookup misses and
`brix_upstream host:port` is configured. `src/protocols/root/read/locate.c` (kXR_locate) and
`src/protocols/root/read/open_request.c` (kXR_open) call `brix_upstream_start()` after
`brix_stat_beneath()` returns "not found locally"; the gateway then asks the
configured upstream to resolve the path and forwards whatever it answers
(redirect / ok / error / wait / waitresp) verbatim to the client. The flow is
opaque relay: the client never learns the upstream's identity, and file handles
and stream IDs are translated end-to-end so `xrdcp` can transparently follow the
chain.

The entire exchange runs on nginx's single-threaded stream event loop with no
blocking I/O. A dedicated outbound `ngx_connection_t` is created with its own
small pool and its own read/write handlers; the client-facing connection is
parked in state `XRD_ST_UPSTREAM` (its read event disarmed in
`src/protocols/root/connection/recv.c`) until the upstream answers or aborts. Three response
classes get special treatment: `kXR_wait` schedules a retry timer and re-sends
the same request later; `kXR_waitresp` flips the upstream into an async-reply
mode and tells the client to keep waiting; everything else terminates the query
(redirect/ok/error) and resumes the client read loop.

Only three opcodes are serialized outbound — `kXR_locate`, `kXR_open`,
`kXR_stat` — which is exactly the set needed for redirector resolution. This is
distinct from the inline transparent-forwarding *proxy mode* (`src/net/proxy/`,
`brix_proxy_upstream`) and from native third-party copy (`src/tpc/`); see
**See also**.

## Files

| File | Responsibility |
|---|---|
| `upstream.h` | Public API: `brix_upstream_start()` (begin an outbound query, parks the client in `XRD_ST_UPSTREAM`) and `brix_upstream_cleanup()` (release all resources, safe from the disconnect path even mid-flight). |
| `upstream_internal.h` | Shared internal types: bootstrap-phase enum `brix_up_bs_t`, connection-state enum `brix_up_state_t`, the `struct brix_upstream_s` state object, `BRIX_UP_WAIT_MAX` cap, and all internal function prototypes. |
| `start.c` | `brix_upstream_start()` — allocate the upstream context, save the client's opcode/streamid/path/options, resolve the address (pre-resolved `upstream_addr` fast path vs. per-request `getaddrinfo()` fallback), create a non-blocking socket + `ngx_connection_t`, build the bootstrap byte buffer, and issue `connect()`. |
| `bootstrap.c` | The bootstrap state machine. `brix_upstream_build_bootstrap()` lays the handshake (12 zeros + version words) + `ClientProtocolRequest` + `ClientLoginRequest` into one buffer; `brix_upstream_handle_bootstrap_response()` drives `HANDSHAKE → PROTOCOL → [TLS] → LOGIN → [AUTH] → DONE`, detecting `kXR_gotoTLS` and `kXR_authmore`. `brix_upstream_build_login()` rebuilds a fresh login for the post-TLS resend. |
| `tls.c` | `(NGX_SSL)` outbound TLS upgrade. `brix_upstream_start_tls()` wraps the live TCP connection in SSL (client mode), sets SNI (override directive wins, else host), and starts the handshake; `brix_upstream_tls_handshake_done()` is the `ssl->handler` callback that restores the normal read/write handlers and resends `kXR_login` over the encrypted channel. |
| `auth.c` | `brix_upstream_send_token_auth()` — when the server answers login with `kXR_authmore`/"ztn", synchronously read the configured WLCG/JWT token file and emit a `kXR_auth` frame (`"ztn\0"` credtype in both header and payload), advancing to `XRD_UP_BS_AUTH`. |
| `request.c` | Outbound request serialization + write flushing. `brix_upstream_send_request()` builds the wire frame for `kXR_locate`/`kXR_open`/`kXR_stat` from the saved client request and moves to `XRD_UP_REQUEST`; `brix_upstream_flush()` is the shared non-blocking write-drain helper (NGX_OK / NGX_AGAIN / NGX_ERROR) used by every send site. |
| `events.c` | The three event-loop callbacks: `brix_upstream_write_handler()` (detects TCP connect completion via `SO_ERROR`, drains partial writes), `brix_upstream_read_handler()` (accumulates a `ServerResponseHdr` + bounded body, then dispatches to bootstrap vs. forward), and `brix_upstream_wait_timer_handler()` (re-sends the request when a `kXR_wait` timer expires). |
| `response.c` | `brix_upstream_forward_response()` — translate the backend reply for the client: rewrap with a fresh header carrying the *client's* streamid, then handle `kXR_redirect` / `kXR_ok` / `kXR_error` (terminal), `kXR_wait` (schedule retry), and `kXR_waitresp` (go async, tell client to wait). |
| `lifecycle.c` | `brix_upstream_cleanup()` (idempotent teardown: del-timer, `ngx_close_connection`, null the back-pointers) and `brix_upstream_abort(up, reason)` (cleanup + send a `kXR_ServerError` to the client at the saved streamid + resume the client read so it can retry). |
| `directives.c` | `brix_conf_set_upstream()` — config-time parser for `brix_upstream host:port` (IPv6 `[::1]:1094` and host/IPv4 forms), port validation, and one-time `ngx_parse_url()` pre-resolution into `upstream_addr` so handlers never call `getaddrinfo()` on the event loop. |

## Key types & data structures

- **`struct brix_upstream_s`** (`upstream_internal.h`, aliased `brix_upstream_t`) — the per-query state object, allocated from the *client* connection's pool and pointed to by `ctx->upstream`. It holds: the outbound `conn`; high-level `state` and bootstrap `bs_phase`; the response accumulator (`rhdr`/`rhdr_pos`, `resp_status`, `resp_dlen`, `resp_body`/`resp_body_pos`); the write buffer (`wbuf`/`wbuf_len`/`wbuf_pos`); the `kXR_wait` retry `timer`; back-pointers `client_ctx`/`client_conn`; the **saved client request** (`req_opcode`, `req_streamid`, `req_path`, `req_options`, `req_open_mode`); and `authmore_count` to bound auth rounds.
- **`brix_up_bs_t`** — ordered bootstrap phases: `HANDSHAKE → PROTOCOL → TLS → LOGIN → AUTH → DONE`. Each phase consumes one server response; reaching `DONE` triggers `brix_upstream_send_request()`.
- **`brix_up_state_t`** — coarse connection state used by the read handler to choose its dispatch: `CONNECTING` (awaiting `SO_ERROR`), `BOOTSTRAP` (responses → state machine), `REQUEST` (response → `forward_response`), `ASYNC` (post-`kXR_waitresp`, also → `forward_response`).
- **`BRIX_UP_WAIT_MAX`** (60) — ceiling clamped onto any `kXR_wait` seconds value, bounding the retry timer.
- **Config fields** (in `ngx_stream_brix_srv_conf_t`, `../types/config.h`): `upstream_host`/`upstream_port`/`upstream_addr` (address), `upstream_tls`/`upstream_tls_ca`/`upstream_tls_name`/`upstream_tls_ctx` (outbound TLS, ctx built at postconfiguration in `../config/runtime_server.c`), and `upstream_token_file` (ztn credential).

## Control & data flow

**Entry.** Manager-mode opcode handlers `../read/locate.c` (kXR_locate) and
`../read/open_request.c` (kXR_open) call `brix_upstream_start(ctx, c, conf)`
only after the local `brix_stat_beneath()` misses *and* `upstream_host` is set.
`start.c` saves the client request, opens the outbound socket, sets
`ctx->state = XRD_ST_UPSTREAM`, and returns. While parked, `../connection/recv.c`
treats inbound bytes on the client connection as a no-op (just re-arms the read
event) so nothing reorders the in-flight query.

**Bootstrap → request → response.** The outbound socket's own
`brix_upstream_write_handler` / `brix_upstream_read_handler` (`events.c`)
drive the exchange: connect completion → flush bootstrap → `bootstrap.c` walks
the phase machine (calling out to `tls.c` on `kXR_gotoTLS` and `auth.c` on
`kXR_authmore`) → at `DONE`, `request.c` serializes the saved opcode →
`response.c` translates the reply. Terminal replies call
`brix_upstream_cleanup()`, queue the rewrapped frame via
`brix_queue_response()` / `brix_send_error()` (`../connection/`,
`../response/`), reset `ctx->state = XRD_ST_REQ_HEADER`, and call
`brix_schedule_read_resume()` (`../connection/event_sched.h`) to wake the
client read loop.

**Calls out to.** Path extraction `brix_extract_path()` (`../path/path.h`);
wire-header construction `brix_build_resp_hdr()` and `brix_send_waitresp()`
(`../response/`); client-side response queueing / error / resume
(`../connection/`); token file read `brix_token_read_file()` (`../token/file.h`);
wire constants and request/response structs (`../protocol/`). The outbound TLS
`ngx_ssl_t` context is assembled at config time in `../config/runtime_server.c`.

**Teardown.** On client disconnect, `../connection/disconnect.c` calls
`brix_upstream_cleanup(ctx->upstream)` so an in-flight query never leaks its
socket or timer.

## Invariants, security & gotchas

- **No blocking on the event loop — almost.** Everything is non-blocking
  (`ngx_recv`/`ngx_send`, `NGX_AGAIN` re-arm) *except* two synchronous reads that
  are deliberate: per-request `getaddrinfo()` in `start.c:115-116` (fallback only when
  pre-resolution at config time failed — logged as a WARN in `directives.c`), and
  the small local token-file read in `auth.c`. Keep the fast path
  (`conf->upstream_addr`) intact so DNS never runs in a handler.
- **Streamid translation is mandatory.** The outbound bootstrap/request frames
  use a fixed streamid `{0,1}` (`bootstrap.c`, `request.c`), but every frame
  delivered to the client is rebuilt with the *saved* `req_streamid`
  (`response.c:27-28`, `auth.c` echoes it for `kXR_auth`). Never forward an
  upstream frame to the client without rewrapping the header.
- **Bounded allocation against a hostile upstream.** The read handler caps the
  response body at `BRIX_MAX_PATH + 256` and aborts beyond that
  (`events.c:187`); the body buffer is pool-allocated with a trailing NUL.
  `kXR_wait` seconds are clamped to `BRIX_UP_WAIT_MAX` (`response.c`).
- **epoll edge-triggered recovery.** When several frames arrive in one TCP
  segment, `ngx_handle_read_event` is a no-op on an already-active fd, so a
  synthetic `ngx_post_event(... &ngx_posted_events)` is posted after each phase
  transition and after `kXR_wait`/`kXR_waitresp` so buffered bytes are drained
  this cycle, not on the next packet (`bootstrap.c:250`, `response.c:104,127`).
- **TLS is fail-closed.** If the server signals `kXR_gotoTLS` but
  `upstream_tls` is off / `upstream_tls_ctx` is NULL (or nginx was built without
  SSL), the query aborts (`bootstrap.c:142-161`). The plaintext `kXR_login`
  pre-sent in the bootstrap buffer is intentionally discarded by the server on
  upgrade and re-sent over TLS from the handshake callback.
- **Auth is single-round and fail-closed.** A second `kXR_authmore` aborts
  (`authmore_count` guard, `bootstrap.c:181`); `kXR_authmore` with no
  `upstream_token_file` configured aborts; only the "ztn" (WLCG/JWT) credential
  type is supported.
- **`cleanup()` must be idempotent and back-pointer-safe.** It null-checks every
  resource and clears `client_ctx->upstream`, because it is invoked both on the
  normal terminal paths and from the disconnect handler while the query may still
  be in flight; `*up` is invalid afterward.
- **`abort()` always tells the client.** Any failure routes through
  `brix_upstream_abort()`, which sends a `kXR_ServerError` at the saved
  streamid and resumes the client read, so `xrdcp` retries on a fresh connection
  instead of hanging.

## Entry points / extending

- **Support another outbound opcode** (beyond locate/open/stat): add a `case` to
  the `switch (up->req_opcode)` in `request.c` that fills the right
  `Client*Request` struct with streamid `{0,1}` and big-endian `dlen`/options;
  capture any extra request fields in `start.c` (as `req_open_mode` is captured
  for `kXR_open`) and add fields to `struct brix_upstream_s`; add the matching
  reply translation in `response.c` if it returns anything but ok/error/redirect.
- **Handle a new upstream response status**: add a `case` to
  `brix_upstream_forward_response()` in `response.c`, deciding terminal
  (cleanup + queue + resume) vs. waiting (re-arm read + post synthetic event).
- **Add an outbound auth mechanism** (beyond ztn): branch in `auth.c` /
  `bootstrap.c`'s `XRD_UP_BS_LOGIN` handler on the advertised credtype and add a
  config field + directive (the address directive parser lives here in
  `directives.c`; the `brix_upstream_tls*` / `brix_upstream_token_file`
  directives are registered in `../stream/module.c` and merged in
  `../config/`, with the SSL context built in `../config/runtime_server.c`).

## See also

- `../read/locate.c`, `../read/open_request.c` — the two call sites that start an upstream query.
- `../connection/recv.c`, `../connection/disconnect.c`, `../connection/event_sched.h` — client-connection parking, teardown hook, and read resume.
- `../response/` — `brix_build_resp_hdr`, `brix_send_error`, `brix_send_waitresp`.
- `../path/path.h` — `brix_extract_path`; `../token/file.h` — token file reader; `../protocol/` — wire structs/constants.
- `../config/runtime_server.c`, `../types/config.h` — upstream config fields and outbound TLS context.
- `../manager/` — the SHM server registry / redirect cache that decides *whether* to redirect; this subsystem confirms the chosen server.
- `../proxy/` — inline transparent XRootD forwarding (`brix_proxy_upstream`), a different mode from this redirector query.
- `../tpc/` — native third-party copy via the SHM key registry.
- `../README.md` — master subsystem index.
