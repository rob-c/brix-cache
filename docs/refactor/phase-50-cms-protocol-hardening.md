# Phase 50 — CMS (`cms://`) protocol hardening against timeouts, loss & bad actors

**Status:** IMPLEMENTED + TESTED 2026-06-22 (WS0–WS8 all landed).
**Scope:** `src/cms/` (client + server), `src/manager/` (read-only reuse),
config plumbing, tests, docs.
**Hard requirement:** **zero wire changes** — byte-for-byte interoperable with
official XRootD `cmsd`.

**Validation:** clean `make` (no warnings, `-Werror`), `nginx -t` parses all 10
new directives; **72 CMS tests green** — 8 new `tests/test_cms_resilience.py`
(login/idle/cap/oversize/client-failover/poisoned-redirect), 30
wire+state conformance (`test_cms_wire_pup_conformance.py` +
`test_cms_state_have_select.py`, the interop guardrail), and 34 fleet
client↔manager tests (`test_cms.py` 8 + `test_manager_mode.py` 26) against the
real handshake/registration/heartbeat/reconnect/redirect paths.

**Implementation note (WS1):** the client read deadline is armed exactly ONCE at
the login transition and reset ONLY on frames received FROM the manager — never on
our own heartbeat sends — so our outbound traffic cannot mask a manager that has
gone silent. The server idle watchdog is symmetric (reset only on inbound frames,
not on the manager's outbound pings).

**Implementation note (WS2):** the CMS client has no output-buffering layer, so a
stalled steady-state send already fails closed (immediate disconnect + backoff
reconnect). `cms_send_timeout` therefore governs the connect/first-write readiness
window; the "peer accepts into buffer but never drains" case is covered at kernel
level by WS5's `TCP_USER_TIMEOUT`.

**Implementation note (WS5):** factored as a header-only `static ngx_inline`
(`src/connection/netopt.h`) rather than a new `.c`, so the build source list is
unchanged; `src/connection/handler.c` was refactored to call it (no behaviour
change on the root:// path).

---

## 1. Context & motivation

The CMS (Cluster Management Services) stack lets an nginx-xrootd node act as a
**data server** registering *up* to a manager `cmsd`, as a **manager** accepting
registrations *down* from data nodes, or **both** (sub-manager). It speaks the real
XrdCms wire protocol — an 8-byte `CmsRRHdr` (`streamid:u32, rrCode:u8, modifier:u8,
dlen:u16`, big-endian) followed by an XrdOucPup payload — so it must remain exactly
interoperable with stock `cmsd`.

The **wire/parse layer is already well-hardened** and is *not* the target of this
phase:

- Every frame is capped at `NGX_XROOTD_CMS_MAX_FRAME` (4096); `dlen` is validated
  against it before use on both sides (`recv.c:356`, `server_recv.c:479`).
- The receive buffer is a **fixed stack array** (`inbuf[4096]`) — no heap
  allocation is ever sized from an attacker-controlled length.
- TLV/Pup parsing is fully bounds-checked (`tlv_read_next`,
  `cms_srv_read_string`).
- `kYR_state` path probes are **kernel-confined** via `xrootd_stat_beneath`
  (openat2 `RESOLVE_BENEATH`) with a `..` pre-check, so a hostile manager cannot
  make a node answer `kYR_have` for a path outside its export root.

The weakness is the **I/O and connection-lifecycle layer**.

### 1.1 Confirmed gaps (file:line)

1. **Client (node→manager) never arms a read deadline.** After connect+login no
   `c->read` timer is set, so the `ev->timedout` branch at `src/cms/recv.c:314` is
   effectively dead code. A manager that **black-holes** (TCP stays up but stops
   responding) is never detected: the node keeps "heartbeating" into a dead socket
   forever and never fails over.

2. **Server (manager) arms no timer until *after* login.**
   `xrootd_cms_srv_handler` (`src/cms/server_handler.c`) installs handlers and
   reads immediately, but the `ping_timer` is only armed inside
   `cms_srv_complete_login` (`server_recv.c:304`). A peer that connects and never
   completes LOGIN — or **trickles a partial header** — holds a ~4 KB ctx + an fd
   **forever** (slowloris / idle-slot exhaustion). Post-login, liveness is detected
   only when a *ping send* fails, but a black-holed peer accepts buffered sends, so
   a silently-dead node is never reaped from the connection **or** the registry.

3. **No cap on accepted CMS connections.** The W1b CIDR allowlist
   (`xrootd_cms_server_allow`) is **off by default** (back-compat), so a single
   actor can open unbounded connections, each allocating a ctx + fd → memory/fd
   exhaustion.

4. **TCP-level dead-peer reaping isn't applied to CMS sockets.** The phase-39
   `SO_KEEPALIVE` / `TCP_USER_TIMEOUT` block exists only in
   `src/connection/handler.c:109-135` for `root://` accepts — neither the CMS
   client connect socket nor CMS server accept sockets get it.

5. **Manager-supplied redirect host is not validated.**
   `cms_wake_pending_session` (`src/cms/recv.c:63`) passes the `kYR_select` /
   `kYR_try` host straight into `xrootd_send_redirect` with no character check, so
   a compromised/hostile manager can inject control bytes into the redirect string
   the client parses.

6. **Hot-path debug-log flood.** `src/cms/connect.c` and `src/cms/recv.c` emit
   `NGX_LOG_WARN` on **every** heartbeat, **every** `recv`, and **every** frame
   (e.g. `connect.c:96,142,153,164,170`; `recv.c:310,320,328,352,373,387`). A
   hostile manager flooding frames amplifies into unbounded WARN logging (disk-fill
   / log-pipeline DoS). These are leftover debug lines.

**Goal:** no malformed, slow, silent, half-open, or flooding peer can make a CMS
connection hang, spin, leak, or be DoS'd — while a conformant official
`cmsd`/data-node is **never** dropped.

---

## 2. Hard constraints

- **No wire changes.** No new/changed opcodes, header layout, Pup encoding, or
  framing. Identical bytes on the wire.
- **Backwards compatible with official `cmsd`.** All new deadlines are generous
  multiples of the heartbeat interval (real `cmsd` pings within its interval; real
  nodes heartbeat within theirs), chosen so a conformant peer is never tripped.
  Socket options are non-fatal.
- Repo rules: **no `goto`**, functional/modular helpers, reuse existing helpers,
  3 tests per change (success + error + security-negative).

---

## 3. Reusable building blocks (do not reinvent)

| Helper / pattern | Location | Reused for |
|---|---|---|
| `ngx_add_timer` / `ngx_del_timer` / `ev->timedout` | `src/cms/connect.c`, `server_recv.c` | all new deadlines |
| `xrootd_net_host_chars_valid()` | `src/manager/registry.c` (W1c choke point) | WS6 redirect-host gate |
| `xrootd_sanitize_log_string()` | `src/path/helpers.c` | wire-derived log lines |
| phase-39 `SO_KEEPALIVE`/`TCP_USER_TIMEOUT` setsockopt block | `src/connection/handler.c:109-135` | WS5 shared helper |
| `NGX_CONF_UNSET*` → `ngx_conf_merge_*` → `ngx_command_t` | `src/config/server_conf.c`, `src/stream/module.c`, `src/cms/server_module.c` | WS7 directives |
| Registry `last_seen` staleness | `src/manager/registry.c` | complements WS3 (selection-steer vs slot-reap) |

---

## 4. Design — workstreams

### WS0 — Quiet the hot-path log flood (correctness + anti-amplification)
Downgrade the leftover per-heartbeat / per-recv / per-frame `NGX_LOG_WARN` lines in
`src/cms/connect.c` (write handler, timer) and `src/cms/recv.c` (read handler) to
`ngx_log_debug*`. Keep genuine error/notice transitions (disconnect, login sent,
suspend/resume) at their current level.

### WS1 — Client read-liveness watchdog (manager→node)
Arm a `c->read` inactivity deadline on the CMS client socket so a silent /
black-holed manager is detected and the node fails over (reconnect with the
existing backoff + jitter).
- New tunable `cms_read_timeout`, default `max(3 × cms_interval, 90s)` — matches
  real `cmsd`'s ~90s ping window; never trips a healthy manager.
- Arm/replace `ngx_add_timer(c->read, cms_read_timeout)` at the end of the write
  handler (after a heartbeat) and after each fully-processed inbound frame in
  `ngx_xrootd_cms_read_handler`. Measures bounded silence since the last manager
  activity / our last send.
- The `ev->timedout` branch (`recv.c:314`) already does `disconnect +
  schedule_retry` — this WS just *activates* that dead code.
- `ngx_xrootd_cms_disconnect` already deletes `c->read`/`c->write` timers →
  teardown stays clean (no stale-timer UAF).

### WS2 — Client send-stall deadline (node→manager)
Bound a stalled/half-open manager that stops draining our heartbeats.
- New tunable `cms_send_timeout`, default ~10s.
- When a heartbeat/login send cannot complete (socket-buffer-full / partial
  write), arm `c->write` deadline; on `wev->timedout` → `disconnect +
  schedule_retry`. Make the stall case explicit rather than waiting for TCP to
  eventually error.

### WS3 — Server accept-side handshake + idle deadlines (the untrusted surface)
- **Login deadline:** at accept in `xrootd_cms_srv_handler`, arm a `c->read` timer
  (`cms_server_login_timeout`, default ~10s) covering the whole LOGIN (+ sss
  `kYR_xauth`, when required) handshake. The existing `if (ev->timedout)
  xrootd_cms_srv_close(ctx)` at `server_recv.c:451` handles the fire; we just arm
  it. Disarm/replace on `cms_srv_complete_login`.
- **Post-login idle watchdog:** track last inbound-frame time; if no frame arrives
  within `cms_server_idle_timeout` (default `max(3 × interval, 90s)`), close →
  `xrootd_cms_srv_close` (already unregisters + 30s blacklists). Reset on every
  received frame. Implemented as a `c->read` timer re-armed in the read loop (the
  `ping_timer` keeps pushing liveness; this watchdog reaps the *connection/slot*).
  Add `ngx_del_timer(c->read)` in `xrootd_cms_srv_close` alongside the existing
  `ping_timer` cancel.

### WS4 — Accepted-CMS-connection cap (server)
- New tunable `cms_server_max_connections` (default 4096; `0` = off).
- Per-worker counter incremented at accept in `xrootd_cms_srv_handler`,
  decremented in `xrootd_cms_srv_close`; over the cap → finalize the session
  (`NGX_STREAM_FORBIDDEN`) before allocating frame state.
- Document pairing with W1b CIDR allow and/or nginx stream `limit_conn`.

### WS5 — TCP-level dead-peer reaping on CMS sockets
- Factor the phase-39 setsockopt block into a shared helper
  `xrootd_net_apply_deadpeer_opts(fd, keepalive_flag, user_timeout_ms, log)`;
  refactor `handler.c` to call it (no behavior change there).
- Call it on the CMS client socket right after `ngx_event_connect_peer`
  (`connect.c`) and on the CMS server accept socket in `xrootd_cms_srv_handler`.
- New tunables `cms_tcp_keepalive` / `cms_tcp_user_timeout` (+ server analogs);
  setsockopt failures stay non-fatal.

### WS6 — Redirect-host validation (defense in depth vs hostile manager)
In `cms_wake_pending_session` (`recv.c`), before `xrootd_send_redirect`, validate
the manager-supplied host with `xrootd_net_host_chars_valid(host, len)`; on reject,
drop the redirect (leave the client in `XRD_ST_WAITING_CMS` to hit its own locate
timeout) and log once via `xrootd_sanitize_log_string`. Apply to both `kYR_select`
and `kYR_try`.

### WS7 — Config / tunables plumbing
Standard `NGX_CONF_UNSET` → merge → `ngx_command_t` pattern.
- **Client-side** (`ngx_stream_xrootd_srv_conf_t`, alongside `cms_interval`):
  `xrootd_cms_read_timeout`, `xrootd_cms_send_timeout`, `xrootd_cms_tcp_keepalive`,
  `xrootd_cms_tcp_user_timeout`.
- **Server-side** (`ngx_stream_xrootd_cms_srv_conf_t`, `src/cms/server.h`):
  `xrootd_cms_server_login_timeout`, `xrootd_cms_server_idle_timeout`,
  `xrootd_cms_server_max_connections`, `xrootd_cms_server_tcp_keepalive`,
  `xrootd_cms_server_tcp_user_timeout`.
- Derive timeout defaults from the heartbeat/ping interval so one knob keeps
  working; cache merged values on the ctx at start/accept (no hot-path conf
  lookup).
- *(Optional)* low-cardinality metrics counters (client read-timeouts, server
  login-timeouts, idle-closes, cap-rejections) via `XROOTD_*_METRIC_INC` — no
  per-host/path labels.

### WS8 — Tests + docs
- New `tests/test_cms_resilience.py` (dedicated high ports; reuse the in-process
  `CmsManagerPeer` / `_ManagerPeer` harness from
  `test_cms_wire_pup_conformance.py` / `test_cms_state_have_select.py`):
  1. Manager black-holes after login → node fails over within `cms_read_timeout`.
  2. Server accept slowloris (partial header, never LOGIN) → closed at login
     timeout; ctx/fd reclaimed.
  3. Post-login idle node → closed + unregistered at idle timeout.
  4. Connection-cap rejection.
  5. Oversized/malformed frame still closes cleanly (regression).
  6. `kYR_select` host with control bytes → redirect refused.
- **Interop regression:** `tests/test_cms*.py`, `test_manager_mode.py`,
  `test_e2e_cluster_matrix.py`, `test_cms_mesh_interop.py` must stay green.
- Update `docs/04-protocols/cms-protocol.md` directives table.

---

## 5. Default posture (decided)

Ship the new deadlines and caps **ON by default, set generous** — protected out of
the box, safe with real `cmsd`:

| Tunable | Default |
|---|---|
| `cms_read_timeout` / `cms_server_idle_timeout` | `max(3 × interval, 90s)` |
| `cms_server_login_timeout` | ~10s |
| `cms_send_timeout` | ~10s |
| `cms_server_max_connections` | 4096 (`0` disables) |
| TCP keepalive (client + server) | **on**, tight probes (30s idle / 10s intvl / 3 cnt) |
| `cms_tcp_user_timeout` | generous backstop (≈ idle timeout) |

All operator-overridable; setsockopt stays non-fatal. The WS8 interop regression
suite is the guardrail that these generous defaults never trip a conformant peer.

---

## 6. Backwards-compatibility guarantees

- No opcode/header/Pup/framing change — bytes on the wire are identical.
- Every new deadline is a generous multiple of the heartbeat interval; a conformant
  `cmsd` (pings within interval) and a conformant node (heartbeats within interval)
  never trip them. Login/idle windows explicitly bracket the sss `kYR_xauth`
  round-trip.
- Socket options non-fatal; timeout/cap directives have safe defaults and can be
  disabled (`0`/`off`).

---

## 7. Files to modify (representative)

- `src/cms/connect.c` — WS0 log levels; WS1 read-deadline arming; WS2 send-stall
  deadline; WS5 client socket opts.
- `src/cms/recv.c` — WS0 log levels; WS1 re-arm read deadline per frame; WS6
  redirect-host validation.
- `src/cms/cms_internal.h` — new timing constants/defaults + ctx fields (cached
  timeouts, last-activity).
- `src/cms/server_handler.c` — WS3 login deadline + WS4 conn cap + WS5 socket opts.
- `src/cms/server_recv.c` — WS3 idle-watchdog re-arm + read-timer cancel in close.
- `src/cms/server.h` / `src/cms/server_module.c` — WS7 server-side conf + directives
  + merge.
- `src/types/config.h`, `src/config/server_conf.c`, `src/stream/module.c` — WS7
  client-side conf + directives + merge.
- `src/connection/handler.c` + new shared helper unit — WS5 setsockopt refactor
  (register new `.c` in `src/config/config.h` `NGX_ADDON_SRCS`; run `./configure`
  once).
- `tests/test_cms_resilience.py` (new); `docs/04-protocols/cms-protocol.md`.

---

## 8. Verification

```bash
# Build (configure once for the new helper .c; otherwise incremental)
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf   # config valid

# New resilience suite
PYTHONPATH=tests pytest tests/test_cms_resilience.py -v --tb=short

# Interop regression — must stay green (real-cmsd-shaped peers not dropped)
PYTHONPATH=tests pytest tests/ -k "cms or manager or cluster" -v --tb=short
```

Manual sanity: start a CMS client against an in-process peer that accepts TCP then
goes silent → confirm reconnect fires after `cms_read_timeout` (not before). Start
the CMS server, open a socket that sends a partial header and stalls → confirm
close at `cms_server_login_timeout` and that the fd/registry slot is reclaimed.
