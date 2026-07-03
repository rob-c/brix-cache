# mirror — fire-and-forget traffic mirroring (shadow replay) for XRootD and WebDAV

## Overview

The mirror subsystem (Phase 24) replays a sampled copy of live requests to one
or more **shadow** backends *after* the primary request has already been
answered, then compares the shadow's status against the primary's and counts any
divergence. The client never sees the shadow response and is never delayed by
it. Its purpose is operational validation: standing up a new storage backend (a
fresh nginx-xrootd, or a real `xrootd` daemon) behind a production gateway and
proving — against real traffic — that it answers the same way before any cutover.

Mirroring is **off by default** on every surface. It activates only when an
operator configures a target: `brix_mirror_url http[s]://host:port` on a
WebDAV location, or `brix_stream_mirror_url host:port` on a stream server
block. Up to `BRIX_MIRROR_MAX_TARGETS` (4) shadows may be configured per
context, all resolved to a `sockaddr` at config time so request handlers never
call `getaddrinfo` on the event loop. A per-request PRNG draw
(`brix_mirror_should_sample`) applies the configured sample percentage.

The subsystem covers three surfaces, all sharing one config block
(`brix_mirror_conf_t` in `mirror.h`) and one set of low-cardinality metrics:

- **HTTP/WebDAV** (`http_mirror.c`): qualifying read/write requests spawn one
  *background subrequest* per shadow, proxied to the shadow via nginx's upstream
  machinery with credentials stripped.
- **XRootD stream — stateless reads & metadata mutations** (`stream_mirror.c`):
  a self-contained async XRootD client opens a fresh shadow session
  (handshake → protocol → login), replays the *saved request frame*, reads one
  response, and discards it.
- **XRootD stream — data writes** (`stream_wmirror.c`, "W3"): the stateful
  `open(write) → write → close` sequence is buffered per file and, on close,
  replayed to an **isolated** shadow as `open(create) → write → close`.

In the lifecycles, the stream surfaces are invoked from
`../handshake/dispatch.c` *after* the primary read/write opcode has been
dispatched and its response queued; the HTTP surface runs as PRECONTENT- and
LOG-phase handlers registered from `../webdav/postconfig.c`.

## Files

| File | Responsibility |
|---|---|
| `mirror.h` | Protocol-agnostic shared config (`brix_mirror_conf_t`, `brix_mirror_target_t`), the HTTP method bitmask (`BRIX_MIRROR_M_*`) and XRootD opcode bitmask (`BRIX_MIRROR_OP_*`), and the inline `brix_mirror_should_sample()` / `brix_mirror_status_class()` helpers. Pulls in no HTTP- or stream-specific types so it is includable from either surface. |
| `http_mirror.h` | Public API for the HTTP/WebDAV mirror: the two phase handlers, the merge-time `brix_http_mirror_setup()`, and the `brix_mirror_url` / `brix_mirror_methods` directive setters. |
| `http_mirror.c` | HTTP/WebDAV mirror. PRECONTENT handler fires one background subrequest per target on the main request and, on each mirror subrequest, takes it over and proxies it to the shadow (upstream callbacks `mirror_create_request` / `mirror_process_status_line` / `mirror_finalize_request`). Handles credential stripping/injection, Destination/Depth/Overwrite rewrite for MOVE/COPY, request-body cloning for PUT, the `X-Xrootd-Mirror` loop guard, and the LOG handler that stamps the primary status for divergence. |
| `stream_mirror.h` | Public API for the stateless stream mirror: `brix_stream_mirror_maybe()` (the launch hook) plus the `brix_stream_mirror_url` / `brix_mirror_opcodes` / `brix_mirror_exclude_opcodes` directive setters. |
| `stream_mirror.c` | Stateless XRootD stream mirror. Decides replayability (`brix_mirror_request_replayable`), snapshots the request frame, and drives a per-target async client through `HANDSHAKE → PROTOCOL → LOGIN → REQUEST` (`brix_mir_*` state machine) reusing `brix_upstream_build_bootstrap()`. Compares shadow vs. primary status and counts divergence, treating `kXR_Unsupported` and TLS/auth demands as benign. Owns the opcode-name parser shared by the allow/exclude setters. |
| `stream_wmirror.h` | Public API for the data-write mirror (W3): `brix_stream_wmirror_on_open()`, `_observe()`, and `_cleanup()`, called from the open/dispatch/disconnect paths. |
| `stream_wmirror.c` | Stateful data-write mirror. Accumulates a write-open's sequential `kXR_write` payloads into a bounded per-file buffer hanging off `ctx->wmirror`; on `kXR_close` hands the complete file to a detached async replay (`wmir_*` state machine: `OPEN → WRITE → CLOSE`) against an isolated shadow. Aborts (counted, never blocking) on `kXR_pgwrite`, non-sequential offsets, or cap overflow. |
| `stream_mirror_io.{c,h}` | The shadow-socket framing shared by both stream mirrors: `brix_mirror_io_flush()` (non-blocking write-drain) and `brix_mirror_io_recv_frame()` (resumable `ServerResponseHdr` + bounded-body reader, cap `BRIX_MIRROR_MAX_RESP_BODY` = 64 KiB). `brix_mir_*`/`wmir_*` wrap these so the body-size bound lives in one place. |

## Key types & data structures

- **`brix_mirror_conf_t`** (`mirror.h`) — the shared knobs embedded in both the
  WebDAV location conf and the stream server conf: resolved `targets`,
  `sample_pct`, the HTTP `method_mask` and stream `opcode_mask` /
  `opcode_exclude_mask`, `strip_auth`, `log_diverge`, `timeout_ms`, an optional
  injected `token`, and `mirror_writes`. `enabled` is derived from targets.
- **`brix_mirror_target_t`** (`mirror.h`) — one resolved shadow: display `url`,
  `host` (Host:/SNI/log label), `port`, `ssl`, `url_base`
  (`scheme://host[:port]`, HTTP only), and the config-time-resolved `sockaddr` /
  `socklen`.
- **Opcode / method bitmasks** (`mirror.h`) — `BRIX_MIRROR_M_*` and
  `BRIX_MIRROR_OP_*`. Note `*_DEFAULT` vs `*_OP_ALL`: when mirroring is enabled
  with no explicit `brix_mirror_opcodes`, the stream default is `OP_ALL` (mirror
  everything, de-select via `brix_mirror_exclude_opcodes`). All write/mutation
  bits (`*_WRITE_ALL`) are deliberately excluded from the default sets and gated
  by a second independent flag, `mirror_writes`.
- **`brix_stream_mirror_t`** (`stream_mirror.c`) — the per-replay async client:
  its own `pool`/`conn`/`log`, the `brix_mir_phase_t` state, response
  accumulator (`rhdr`/`resp_status`/`resp_dlen`/`resp_body`), write buffer, a
  single deadline `tev` timer, the saved request frame
  (`saved_hdr[24]`/`saved_payload`/`saved_dlen`/`saved_opcode`), and `primary_ok`.
- **`brix_wmirror_conn_t` / `brix_wmirror_file_t`** (`stream_wmirror.c`) — the
  per-connection accumulation state (`ctx->wmirror`): a `files[BRIX_MAX_FILES]`
  array keyed by client file-handle slot, each holding the saved open header/path,
  a growable `data` buffer, the expected `next_off`, and `active`/`aborted` flags;
  `total_buffered` enforces the per-connection cap.
- **`brix_wmirror_replay_t`** (`stream_wmirror.c`) — the detached write-replay
  client, structurally parallel to `brix_stream_mirror_t` but driven through the
  `wmir_phase_t` (`HANDSHAKE → … → OPEN → WRITE → CLOSE`) machine and owning
  malloc'd `open_frame` / `data` / captured `shadow_fhandle`.
- **Metrics** — eight low-cardinality counters in `../metrics/metrics.h`
  (`metrics.h:496-503`): `mirror_{http,stream}_{total,errors_total,dropped_total,divergence_total}`. No per-target labels (metrics invariant 8).

## Control & data flow

**HTTP/WebDAV.** `brix_http_mirror_precontent_handler`
(`NGX_HTTP_PRECONTENT_PHASE`, registered in `../webdav/postconfig.c`) runs on
every request. On the **main** request it checks enable/method/loop-guard/sample,
marks `ctx->mirror_fired`, then fires one `NGX_HTTP_SUBREQUEST_BACKGROUND`
subrequest per target (for PUT it first reads the body so the shadow can forward
a clone). On a **mirror subrequest** (tagged `ctx->is_mirror`) it calls
`brix_http_mirror_proxy`, which builds an `ngx_http_upstream_t` against the
target's resolved `sockaddr` and proxies via the upstream callbacks; the WebDAV
access/content handlers skip `is_mirror` subrequests. `mirror_finalize_request`
compares status classes and bumps metrics; `brix_http_mirror_log_handler`
(`NGX_HTTP_LOG_PHASE`) stamps `ctx->primary_status`. Upstream conf (timeouts,
bufs, hide-headers hash, TLS ctx) is built once at merge time by
`brix_http_mirror_setup` (called from `../webdav/config.c`).

**Stream reads / metadata mutations.** `../handshake/dispatch.c` calls
`brix_stream_mirror_maybe()` immediately after a read- or write-opcode dispatch
returns. It applies the opcode/exclude/writes gates, the replayability test, the
payload-size bound, and sampling; then for each target it allocates a context
from a **fresh `ngx_create_pool(ngx_cycle->pool)`** (not the client pool),
snapshots the request frame, and launches an async client. The state machine
sends the pipelined bootstrap, then the saved frame with streamid rewritten to
`0x0002`, reads one response, and finishes — destroying its own pool.

**Stream data writes (W3).** Three hooks thread through the connection lifecycle:
`brix_stream_wmirror_on_open()` (from `../read/open_resolved_file.c` on a write
open) starts accumulation; `brix_stream_wmirror_observe()` (from
`../handshake/dispatch.c` after each write/pgwrite/close) appends sequential
bytes and, on close, calls `wmir_launch()` to start a detached replay that
transfers buffer ownership; `brix_stream_wmirror_cleanup()` (from
`../connection/disconnect.c`) frees any leftover per-file buffers.

**Calls out to.** `../upstream/README.md` (`brix_upstream_build_bootstrap`
wire framing), `../metrics/README.md` (`brix_metrics_shared`), `../webdav/`
(loc conf, req ctx, postconfig registration), `../handshake/` (dispatch hooks),
`../read/` (open hook), `../connection/` (disconnect cleanup), `../protocol/`
(`kXR_*` constants, `ServerResponseHdr`, frame lengths).

## Invariants, security & gotchas

- **Detached lifetime / no client-pool memory.** Stream and write replays own a
  pool created from `ngx_cycle->pool` and log to `ngx_cycle->log` — never the
  client connection's pool or log — because the client connection may close
  before the shadow exchange completes (`stream_mirror.c:599-609`,
  `stream_wmirror.c:445-450`). Using the client log here is a use-after-free.
- **Fire-and-forget, never blocking the client.** The primary response is already
  queued before any mirror runs; every failure path
  (`brix_mir_finish`/`wmir_finish`) just tears down the shadow and counts a
  metric. The client is never delayed or exposed to the shadow.
- **Writes are double-gated and require an isolated namespace.** A write op
  mirrors only when it is BOTH listed (method/opcode mask) AND `mirror_writes`
  is on (`http_mirror.c:582`, `stream_mirror.c:564`, `wmir_gate`). The shadow
  MUST NOT share the primary's backing store — replayed writes would corrupt it.
  This is the single most dangerous misconfiguration in the subsystem; it is
  documented in every relevant header and gated twice in code.
- **Stateless replayability is mandatory for reads.** `stream_mirror.c` replays
  only self-contained, side-effect-free frames: locate/dirlist/query, path-based
  stat/statx (`dlen>0`), and **read-only** opens (write open flags
  `BRIX_MIRROR_OPEN_WRITE_FLAGS` are rejected, `stream_mirror.c:139-171`).
  Handle-based read/readv/handle-stat carry the *primary's* file handle, which is
  meaningless on the shadow's separate session, so they are skipped — this is
  what lets the mirror sit in front of a real `xrootd` without spuriously
  diverging.
- **Benign-difference handling (mirror must "just work").** A shadow that returns
  `kXR_Unsupported` (e.g. Qcksum to an xrootd with no checksum configured), or
  demands `kXR_gotoTLS` / `kXR_authmore`, is treated as alive-but-different and
  NOT counted as divergence (`brix_mir_on_response`, `brix_mir_dispatch`).
- **Loop guard.** Every mirrored request is tagged so a shadow accidentally
  pointed back at this server declines to re-mirror: HTTP sends
  `X-Xrootd-Mirror: 1` (checked in the precontent handler), stream replays set
  streamid `0x0002`.
- **Auth handling.** HTTP: with a `token` configured it injects
  `Authorization: Bearer <token>`; with `strip_auth` on (the safe default) it
  sends no credentials; only with `strip_auth` off does it forward the client's
  `Authorization`. The stream replay performs an anonymous login and abandons the
  exchange if the shadow wants real credentials.
- **Bounded buffers.** Shadow response bodies are capped at 64 KiB
  (`stream_mirror.c:289`, `stream_wmirror.c:223`); replayed read payloads at
  `BRIX_MIRROR_MAX_PAYLOAD` (4 KiB); write accumulation at 4 MiB/file and
  16 MiB/connection (`stream_wmirror.c:34-35`). Over-cap, non-sequential, or
  `pgwrite` data aborts that file's mirror (counted via `mirror_stream_dropped_total`).
- **Body cloning for PUT (HTTP).** `brix_http_mirror_clone_body` duplicates only
  the `ngx_buf_t` bookkeeping (independent `pos`/`file_pos`) while sharing the
  underlying memory/temp-file read-only, and `r->preserve_body = 1` keeps it alive
  so the shadow send never disturbs the primary's own body consumption.
- **Low-cardinality metrics only.** Counters carry no per-target/path/UUID labels;
  divergence detail goes to the NOTICE log (when `log_diverge` is on), not metrics.

## Entry points / extending

- **Add a mirrorable HTTP method:** add a bit in `mirror.h` (`BRIX_MIRROR_M_*`),
  map it in `brix_http_mirror_method_bit`, accept its name in
  `brix_http_mirror_set_methods`, and (if write-implying) include it in
  `BRIX_MIRROR_M_WRITE_ALL` so `mirror_writes` gates it. If it carries a body,
  extend `brix_http_mirror_method_has_body` and the body-clone path.
- **Add a mirrorable XRootD opcode:** add a bit in `mirror.h`
  (`BRIX_MIRROR_OP_*`), map `kXR_*` → bit in `brix_mirror_opcode_bit`, decide
  replayability in `brix_mirror_request_replayable`, accept its name in
  `brix_mirror_parse_opcode_args`, and add it to `OP_ALL` (and, if a write,
  `OP_WRITE_ALL`).
- **Add a metric:** declare an `ngx_atomic_t mirror_*` field in
  `../metrics/metrics.h`, export it in `../metrics/`, and increment via the local
  `MIR_HTTP_INC` / `BRIX_MIR_METRIC_INC` / `BRIX_WMIR_METRIC_INC` macro.
- **Add a directive:** declare the field in `brix_mirror_conf_t`, register the
  `ngx_command_t` (WebDAV in `../webdav/module.c`, stream in
  `../stream/module.c`), and merge it in the surface's `merge_*_conf`. The setters
  here (`brix_http_mirror_set_url`, `brix_stream_mirror_set_url`, etc.) are the
  template.

## See also

- [`../handshake/README.md`](../handshake/README.md) — stream dispatch hooks that
  invoke `brix_stream_mirror_maybe` / `brix_stream_wmirror_observe`.
- [`../webdav/README.md`](../webdav/README.md) — HTTP method router; registers the
  mirror phase handlers and owns the loc conf / req ctx.
- [`../upstream/README.md`](../upstream/README.md) —
  `brix_upstream_build_bootstrap` and the health-check probe this mirror's wire
  framing is modelled on.
- [`../metrics/README.md`](../metrics/README.md) — the shared SHM counter struct.
- [`../read/README.md`](../read/README.md) — write-open hook
  (`open_resolved_file.c`) that starts data-write accumulation.
- [`../protocol/README.md`](../protocol/README.md) — `kXR_*` constants and wire
  structures used by the stream replays.
- [`../README.md`](../README.md) — subsystem master index.
