# cms — XRootD CMS cluster membership (heartbeat client + manager-side server)

## Overview

This subsystem speaks the **XRootD Cluster Management Service (CMS)** wire
protocol — the binary control channel a real `cmsd` uses to form a redirector
cluster. It lets an nginx-xrootd node participate in a CMS mesh in either (or
both) of two roles, implemented as two cooperating halves:

- **Heartbeat client** (`connect.c`, `recv.c`, `send.c`, `wire.c`, `space.c`,
  `config.c`, `frame_io.c`) — a data node opens a persistent TCP connection
  *up* to a parent CMS manager (`brix_cms_manager host:port`), announces
  itself with a `kYR_login`, then sends periodic load/space heartbeats so the
  manager keeps it active and eligible for client selection. This half is
  compiled into the main module and started per-worker from
  `../config/process.c` (`ngx_brix_cms_start`).
- **Manager-side server** (`server_*.c`, `server.h`) — a separate stream
  module, `ngx_stream_brix_cms_srv_module`, enabled with
  `brix_cms_server on;`. It *accepts* CMS connections *down* from data nodes,
  parses their logins/heartbeats, and records them in the shared server
  registry (`../manager/registry.h`) so the manager can later redirect clients
  to the best node.

These two halves close the loop that makes nginx-xrootd usable as a CMS
redirector/manager. When a client issues `kXR_locate`/`kXR_open`/`kXR_stat`/
`kXR_query` against a node running in manager mode, the read-path handlers
(`../read/locate.c`, `../read/open_request.c`, `../read/stat.c`,
`../query/checksum_qcksum.c`) suspend the client session (`XRD_ST_WAITING_CMS`),
record a pending-locate entry (`../manager/pending.c`), and emit a CMS
`kYR_locate` upstream via this subsystem's `ngx_brix_cms_send_locate`. When
the manager answers with `kYR_select`/`kYR_try`, `recv.c` wakes the suspended
client and replies `kXR_redirect`.

This subsystem only carries cluster *control* traffic; it never moves file
data. The on-demand selection model (`kYR_state` → `kYR_have`) and the SSS
cluster-auth handshake (`kYR_xauth`) are implemented to match real `cmsd`
behaviour, so an nginx node can interoperate with stock XRootD managers and
data servers in either direction.

## Files

### Heartbeat client (main module)

| File | Responsibility |
|------|----------------|
| `config.c` | Directive parser for `brix_cms_manager host:port`: resolves and stores the manager `ngx_addr_t` in the stream server conf (`cms_addr`/`cms_manager`); rejects duplicates and missing ports. |
| `connect.c` | Connection lifecycle and timer engine: `ngx_brix_cms_start` (per-worker init), `_connect` (`ngx_event_connect_peer`), write handler (login → status → load), `_timer` (periodic heartbeat / reconnect), `_disconnect`, `_schedule`, and exponential-backoff `_schedule_retry`. |
| `send.c` | Outgoing client frames: `_send_login` (CmsLoginData with space/port/paths), `_send_status` (Resume\|noStage), `_send_load` (heartbeat), `_send_avail` (reply to `kYR_space`), `_send_pong` (reply to `kYR_ping`), `_send_locate` (forward client locate), `_send_have` (answer `kYR_state`), `_next_streamid`. |
| `recv.c` | Inbound read loop + opcode dispatch: accumulates a frame, then handles `kYR_ping`→pong, `kYR_space`→avail, `kYR_status`→suspend/resume, `kYR_select`/`kYR_try`→redirect a waiting client (`cms_wake_pending_session`), `kYR_state`→`kYR_have` (kernel-confined existence probe). |
| `space.c` | Filesystem capacity via `statvfs`: `_export_paths` (cms_paths else root) and `_stat_space` (total_gb / free_mb / util_pct) feeding login and load frames. |
| `wire.c` | Big-endian scalar codecs (`get16`/`get32`/`put16`/`put32`) plus XrdOucPup-style packers: tagged `put_short`/`put_int` and bare length-prefixed `put_string`. |
| `cms_internal.h` | Client context `ngx_brix_cms_ctx_s`, all `kYR_*`/`CMS_*` wire constants, timing/sizing constants, and client-half prototypes. |

### Shared frame I/O

| File | Responsibility |
|------|----------------|
| `frame_io.c` / `frame_io.h` | Transport primitives used by both halves: `brix_cms_send_all` (loop `c->send` to completion) and `brix_cms_send_frame` (build the 8-byte header + dispatch payload). |

### Manager-side server (`ngx_stream_brix_cms_srv_module`)

| File | Responsibility |
|------|----------------|
| `server.h` | Server module API: per-connection `brix_cms_srv_ctx_t`, per-block `ngx_stream_brix_cms_srv_conf_t`, SSS handshake state enum `brix_cms_auth_state_t`, and all server-half prototypes. |
| `server_module.c` | Module descriptor, conf create/merge, and directives: `brix_cms_server` (installs `brix_cms_srv_handler` as the stream handler), `_interval`, `_allow` (CIDR list), `_sss_keytab`. |
| `server_handler.c` | Accept entry point `brix_cms_srv_handler`: allocates ctx, records peer host, runs the accept-time CIDR gate, sets initial SSS auth state, installs read/write handlers, arms first read. |
| `server_recv.c` | Inbound read loop + TLV/Pup parsers + frame dispatcher: `kYR_login`→parse + (optionally) SSS-challenge + `brix_srv_register`, `kYR_xauth`→verify + register, `kYR_load`/`kYR_avail`/`kYR_space`→`brix_srv_update_load`, `kYR_gone`→`brix_srv_unregister_path`, `kYR_pong`; ping timer; `brix_cms_srv_close` (blacklist + unregister on drop). |
| `server_send.c` | Server-side frame senders: `brix_cms_srv_send_ping` (liveness probe), `brix_cms_srv_send_xauth` (security challenge). |
| `server_auth.c` | Registration auth gates: `brix_cms_srv_check_peer` (CIDR allowlist, fail-open-with-warning when unset) and `brix_cms_srv_verify_xauth` (validate the data node's SSS credential via `../sss`). |

## Key types & data structures

- **`ngx_brix_cms_ctx_s`** (`cms_internal.h`) — per-manager client state, one
  per worker (heap-allocated in `init_process`, pointer kept in
  `srv_conf->cms_ctx`). Holds the `ngx_peer_connection_t`, active
  `connection`, reconnect/heartbeat `timer`, current `backoff`, `logged_in`
  flag, monotone `next_streamid` (locate correlation key), and the frame
  accumulation buffer (`inbuf`/`in_pos`/`in_need`).
- **`brix_cms_srv_ctx_t`** (`server.h`) — per-accepted-connection state on the
  manager side: peer `host`/`port`, parsed export `paths` (colon-delimited),
  last `free_mb`/`util_pct`, `logged_in`, `auth_state`, ping timer, and frame
  accumulation buffer.
- **`brix_cms_auth_state_t`** (`server.h`) — SSS handshake FSM:
  `NONE` (no keytab → not required) → `REQUESTED` → `CHALLENGED` (parms sent,
  awaiting credential) → `DONE` (verified, registration permitted).
- **`ngx_stream_brix_cms_srv_conf_t`** (`server.h`) — server-block config:
  `enable`, `interval`, CIDR `allow` array, `sss_keytab` path, parsed
  `sss_keys`.
- **CMS opcodes & encoding tags** (`cms_internal.h`) — `CMS_RR_*` request/reply
  codes (e.g. `LOGIN=0`, `LOCATE=2`, `AVAIL=12`, `HAVE=15`, `LOAD=16`,
  `SELECT=10`, `PING=17`, `STATE=20`, `STATUS=22`, `TRY=24`, `XAUTH=27`),
  `CMS_ST_*` status modifier bits, `CMS_MOD_RAW`/`CMS_HAVE_ONLINE`, and the
  `CMS_PT_SHORT (0x80)` / `CMS_PT_INT (0xa0)` Pup type tags.

## Control & data flow

**Wire frame format.** Every frame is an 8-byte big-endian header
(`streamid u32`, `rrCode u8`, `modifier u8`, `dlen u16`) followed by `dlen`
payload bytes (`NGX_BRIX_CMS_HDR_LEN` / `NGX_BRIX_CMS_MAX_FRAME = 4096`).
Scalars inside a payload carry a Pup type tag (`0x80` short, `0xa0` int);
strings are tagless, length-prefixed `[u16 len][bytes + trailing NUL]` where
`len` counts the NUL — matching `XrdOucPup`.

**Client half (this node is a data server).**
`../config/process.c` calls `ngx_brix_cms_start` once per worker when
`cms_addr` is configured. A one-shot timer (`INITIAL_DELAY = 1s`) fires
`_connect`; on connect the write handler sends `kYR_login`
(`CmsLoginData`: version/mode/PID/space/port/paths) then `kYR_status`
(`Resume|noStage`) then the first `kYR_load`, and arms the
`cms_interval` heartbeat. `recv.c` answers manager probes. Any I/O error →
`_disconnect` + exponential backoff (`BACKOFF_MAX = 60s`, also capped at
10× the interval for short test intervals).

**Manager half (this node is a redirector).** With `brix_cms_server on;`,
the stream core dispatches accepted connections to `brix_cms_srv_handler`.
After the CIDR/SSS gates, `kYR_login` is parsed and the node is registered in
`../manager/registry.h` via `brix_srv_register`; subsequent heartbeats call
`brix_srv_update_load`; disconnect blacklists the node for 30s and
unregisters it.

**Client-locate redirect loop (manager mode).** Read-path handlers
(`../read/locate.c`, `../read/open_request.c`, `../read/stat.c`,
`../query/checksum_qcksum.c`) that cannot serve a path locally call
`ngx_brix_cms_next_streamid` + `brix_pending_insert` (`../manager/pending.c`),
set the client session to `XRD_ST_WAITING_CMS`, and emit `ngx_brix_cms_send_locate`
upstream. The manager's `kYR_select`/`kYR_try` reply arrives on `recv.c`, which
in `cms_wake_pending_session` resolves the saved client fd within the same
worker, restores its stream id, and emits `kXR_redirect` via
`brix_send_redirect` + `brix_schedule_read_resume`.

**On-demand selection (`kYR_state` → `kYR_have`).** When the manager asks "do
you hold `<path>`?", `recv.c` answers `kYR_have` only if the node can serve it:
in manager mode by consulting `brix_srv_select` over the registry; on a data
node by a kernel-confined `brix_stat_beneath` probe (`../path/beneath.h`).
Otherwise it stays silent, so the manager won't select it.

Outbound bytes always go through `frame_io.c`; the read loops decode via
`wire.c` / the server TLV walkers; capacity numbers come from `space.c`;
SSS verification delegates to `../sss`.

## Invariants, security & gotchas

- **Per-worker, single-process redirect.** The CMS connection and the waiting
  client connection live in the *same* worker, so `cms_wake_pending_session`
  resolves the client by fd within `ngx_cycle` (`recv.c:73`). It revalidates
  `client_conn->number == pending->conn_number` and `state == XRD_ST_WAITING_CMS`
  before redirecting — guards against fd recycling after a client disconnect.
- **Kernel-confined existence probe for `kYR_state`.** A data node answering
  `kYR_have` must use `brix_stat_beneath` against the persistent export rootfd
  (`recv.c:268`), *not* a raw `stat`. A malicious manager could otherwise probe
  arbitrary paths, and a symlink under the export root (`/link -> /etc`) would
  leak files outside the root and poison the cluster. A cheap `..` pre-check is
  kept as defence-in-depth; a node with `rootfd < 0` never claims local files.
- **Registration is the trust boundary on the manager side.** Any peer reaching
  the CMS port can self-report arbitrary `host:port:paths` (redirect poisoning).
  Three layered, vanilla-compatible controls gate registration (`server_auth.c`):
  W1a SSS `kYR_xauth` credential check (fail-closed when a keytab is set), W1b
  accept-time CIDR allowlist, W1c host-character validation in `registry.c`.
  With neither allowlist nor keytab, the server fails *open* but warns once.
- **SSS registration is deferred until DONE.** When a keytab is configured,
  `kYR_login` does **not** register the node; the manager sends its parms
  (`&P=sss`) and registers only after `brix_cms_srv_verify_xauth` succeeds
  (`server_recv.c` `cms_srv_complete_login`).
- **Status frames drive eligibility.** The client must send `kYR_status`
  (`Resume|noStage`) right after login or a real `cmsd` keeps it suspended and
  never redirects to it (`connect.c:119`). Inbound `kYR_status` toggles
  `conf->cms_suspended`, which the login path consults to pause new logins.
- **Frame-size + bounds discipline.** Both read loops reject frames where
  `dlen + HDR_LEN > MAX_FRAME` and re-validate before parsing; `kYR_select`/
  `kYR_try`/`kYR_state` payload parsers bounds-check host/port/path spans
  against the received length before touching them.
- **`put_string` semantics.** Empty/NULL → a bare 2-byte zero length (no NUL);
  otherwise `len+1` (counting the NUL) followed by data + NUL, tagless — the
  parser distinguishes a string from a scalar by the absence of the `0x80` bit
  in the first length byte (`wire.c:74`). Do not add a type tag.
- **Event-loop only.** All I/O is non-blocking nginx event handlers; sends loop
  on `NGX_AGAIN`, reads accumulate across events, and timers (never sleeps)
  drive heartbeats and reconnects. `space.c`'s `statvfs` is the one blocking
  syscall, accepted as cheap and infrequent.
- **Stream-allocation discipline.** Client ctx is `ngx_pcalloc` on
  `cycle->pool`; server ctx on `c->pool` (auto-freed on connection close). Wire
  buffers are fixed-size stack/struct arrays — no per-frame heap churn.
- **The two halves are independent modules.** The client is part of the main
  module; the server is `ngx_stream_brix_cms_srv_module`. A node can run
  either, both, or neither; `manager_mode` makes the client aggregate
  cluster-wide space (`brix_srv_aggregate_space`) into its own load reports.

## Entry points / extending

- **Add a handled inbound opcode (client side):** add a `CMS_RR_*` constant in
  `cms_internal.h`, then a `case` in `ngx_brix_cms_process_frame`
  (`recv.c`); add a matching `_send_*` in `send.c` if a reply is needed. Bounds-
  check the payload against `ctx->in_need - HDR_LEN` before reading it.
- **Add a handled inbound opcode (manager side):** add a `case` in
  `cms_srv_process_frame` (`server_recv.c`), reusing `tlv_read_next` /
  `cms_srv_read_string` for Pup fields; gate state-changing opcodes on
  `ctx->logged_in`.
- **Add a CMS server directive:** add the field to
  `ngx_stream_brix_cms_srv_conf_t` (`server.h`), an `ngx_command_t` entry +
  setter in `server_module.c`, and a `ngx_conf_merge_*` line in
  `brix_cms_srv_merge_conf`.
- **Register a new source file:** add `.c` files to the build `config` at repo
  root (client list near line 397, server module list near line 678) — they are
  not compiled otherwise.

## See also

- [../manager/README.md](../manager/README.md) — SHM server registry, blacklist, `brix_srv_select`, and the pending-locate table this subsystem wakes.
- [../read/README.md](../read/README.md) — `locate`/`open`/`stat` handlers that originate `kYR_locate` and consume `kXR_redirect`.
- [../path/README.md](../path/README.md) — `brix_stat_beneath` / RESOLVE_BENEATH confinement used by the `kYR_state` probe.
- [../sss/README.md](../sss/README.md) — shared SSS keytab loader and credential verifier used for cluster auth (W1a).
- [../handshake/README.md](../handshake/README.md) and [../connection/README.md](../connection/README.md) — the stream client lifecycle whose sessions are suspended/redirected here.
- [../README.md](../README.md) — master subsystem index.
