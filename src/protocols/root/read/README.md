# read — XRootD read-side opcodes and the file-handle lifecycle

## Overview

This subsystem implements the read-half of the XRootD binary wire protocol over the
nginx **stream** module: it opens files (`kXR_open`), serves their bytes
(`kXR_read`, `kXR_readv`, `kXR_pgread`), reports metadata (`kXR_stat`, `kXR_statx`,
`kXR_locate`), copies server-side ranges (`kXR_clone`), and tears handles down
(`kXR_close`). Despite the directory name, it owns more than reads: `kXR_open` is the
densest opcode in the protocol and seeds the per-handle bookkeeping (`brix_file_t`
slots 0–15, `BRIX_MAX_FILES`, in `../connection/fd_table.c`) that every later read **and write** opcode
reuses, so the open/close lifecycle lives here while the actual write opcodes live in
`../write/`.

Each handler is a leaf of the stream dispatcher: `../handshake/dispatch_read.c`
switches on the opcode via the `DISPATCH_RD` (handle-only) / `DISPATCH_RD_BOUND`
(`conf`-taking) macros and calls one `brix_handle_*()` once the request header and any
payload have been accumulated by `../connection/`. (That same switch also routes
`kXR_dirlist`, `kXR_query`, `kXR_prepare`, and `kXR_fattr`, whose bodies live in sibling
subsystems — see `../dirlist/`, `../query/`, `../fattr/`.) Handlers run on nginx's
single-threaded event loop and must never block — blocking `pread`/`preadv` is offloaded
to the thread pool in `../aio/`, with the completion callback rebuilding the response
chain identically to the synchronous path. Since phase-54 the AIO-offloaded and the
window-pump inline-fallback read/pgread/readv bodies run through the VFS-owned
thread-safe core `brix_vfs_io_execute()` ([`../fs/vfs_io_core.c`](../../../fs/README.md))
rather than a `pread` reimplemented here; these handlers own validation, framing, and
scheduling. The zero-copy `sendfile` branch and the `preadv2(RWF_NOWAIT)` warm-cache
probe stay separate by design (they move bytes without a core buffer). Responses are
framed by `../response/` and
queued via `brix_queue_response` / `brix_queue_response_chain`; the terse
metric+log+error exits use the `BRIX_RETURN_ERR` / `BRIX_RETURN_REDIR` /
`BRIX_RETURN_OK` / `BRIX_OP_OK` / `BRIX_OP_ERR` macros.

The read path is also where the gateway's three operating modes diverge. In a plain
**data server** the handlers resolve a path beneath the export root and serve local
bytes. In **manager/redirector** mode `kXR_open` / `kXR_stat` / `kXR_locate` do not touch
the filesystem — they pick a backend via `brix_srv_select()` (`../manager/`), reply
`kXR_redirect`, and fall back to a CMS `kYR_locate` round-trip (`../cms/`) on a registry
miss. The **XCache** path (`open_cache.c`, `slice_read.c`) serves reads from a local
cache root, filling whole files or per-slice fragments from an origin on miss.

This subsystem also enforces the read-side security gates: kernel path confinement
(`RESOLVE_BENEATH` via `../path/`), the authdb / VO-ACL / token-scope `brix_auth_gate`,
and the global `allow_write` policy for write-mode opens.

## Files

| File | Responsibility |
|---|---|
| `open.h` | Declares the three open entry points (`brix_handle_open`, `brix_open_resolved_file`, `brix_open_cached_read`). |
| `open_overview.c` | Module-level WHAT/WHY documentation for the open lifecycle; defines `open_extract_opaque()` (splits the CGI `?...` opaque string off the open payload, trimming a trailing NUL). |
| `open_request.c` | `brix_handle_open()` — the `kXR_open` protocol entry point: parses `ClientOpenRequest`, detects write-mode, parses TPC opaque params (destination *pull* vs source *serve* rendezvous via `tpc.key`/`tpc.dst`/`tpc.org`), runs manager-mode redirect / static-map / CMS-locate, strips the CGI query, validates depth, resolves the path (read = must-exist via `brix_stat_beneath`, write = `mkpath`-aware), runs the auth gate, then delegates to the cached-read or resolved-file opener. |
| `open_resolved_file.c` | `brix_open_resolved_file()` — derives `open(2)` flags from XRootD options, builds the POSC staging temp path, runs the pre-flight existence/type checks through `brix_open_probe` (a `brix_vfs_probe` wrapper) — *export* paths only; the upload-stage partial check stays raw-as-worker (marked) — allocates an `fhandle` slot, opens the **export** target through the VFS (`brix_vfs_open_fd_at`) while the separate **cache**/**stage** domains are opened raw-as-worker (svc-owned, behind `vfs-seam-allow` markers; the VFS would mis-resolve them under impersonation), `fstat`s and rejects directories, initialises all per-handle bookkeeping (readable/writable, device/inode, cached size, read-ahead cursors, write-through, write-recovery journal, dashboard slot), evaluates the write-through decision, and assembles the `ServerOpenBody` (+ optional `retstat`) response. |
| `open_cache.c` | `brix_open_cached_read()` — XCache read-open: VO-ACL check against the auth root (`brix_check_vo_acl_identity`), then either dispatch to slice caching (`brix_open_slice_handle`, when `cache_slice_size > 0` and an origin host is set), serve a whole-file cache hit (`brix_open_resolved_file` with `is_write=0`), or trigger a background origin fill (`brix_cache_open_or_fill`, in `../cache/`). |
| `slice_read.c` / `slice_read.h` | Phase 26 slice cache: `brix_open_slice_handle()` registers a "slice-mode" handle (fd parked on `/dev/null`) after an async fill of slice 0 yields the origin size; `brix_read_from_slices()` enumerates the slices covering a request, stitches per-slice cache files on a full hit, or schedules a fill of the first missing slice and suspends (re-entered by `brix_slice_read_resume`). |
| `read.c` | `brix_handle_read()` — `kXR_read`: validates the handle, caps `rlen` at `BRIX_READ_REQUEST_MAX`, then chooses one of four data paths: zero-copy sendfile (cleartext **or** active kTLS, `brix_ktls_send_active`), per-window `kXR_oksofar` streaming for large memory reads (`brix_read_window_pump`), a `preadv2(RWF_NOWAIT)` warm-cache fast path, or AIO/synchronous `pread` into scratch. Routes slice-mode handles to `brix_read_from_slices`, and (phase-42 W4) handles whose `read_codec` was negotiated to `brix_read_compressed`. |
| `read_compress.c` | Phase-42 W4 inline read compression: `brix_read_compressed()` — the opt-in `kXR_read` path for a handle opened with `?xrootd.compress=<codec>` (gated by `brix_read_compress`). Synchronously reads a `BRIX_READ_CHUNK_MAX`-bounded plaintext window, compresses it as one self-contained codec frame (`src/core/compat/codec_core.c`) into the `cmp_scratch` keep-slot, and queues it as a single response (the native client inflates). Strictly isolated so the default plaintext path in `read.c` is byte-identical; pgread/readv never reach it, preserving the pgread CRC32c invariant. |
| `readv.c` | `brix_handle_readv()` + `brix_readv_read_segments()` — `kXR_readv`: two-phase (validate all handles + size, then allocate one scratch buffer), builds the wire body up front so `preadv` lands bytes directly at `payload_ptr`, coalesces contiguous same-fd ranges (`brix_range_vector_next_coalesced_run`, max 64 iovecs) into fewer `preadv` syscalls, AIO-offloads or runs inline; rejects slice-mode handles with `kXR_Unsupported`. |
| `pgread.c` | `brix_handle_pgread()` + `brix_pgread_encode_pages()` — `kXR_pgread`: page-mode read with `kXR_status` (`ServerStatusResponse_pgRead`) framing and per-page CRC32c, computed in a single fused copy via `brix_crc32c_copy()`; AIO or inline `pread`; rejects slice-mode handles. |
| `prefetch.c` / `prefetch.h` | Best-effort `POSIX_FADV_WILLNEED` read-ahead: `brix_prefetch_fd_range` (basic fd-range hint, ≥1 MiB guard), `brix_prefetch_read_file` (sequential-pattern detection with windowed extension keyed on `read_last_end`/`read_ahead_end`), `brix_prefetch_flush`, and `brix_prefetch_readv_segments` (merge nearby same-fd ranges). HEP-tuned constants (1 MiB min, 32 MiB window, 8 MiB low-water). |
| `read.h` | Declarations + WHAT/WHY for the three byte-transfer opcodes and the shared `brix_pgread_encode_pages` page encoder. |
| `stat.c` / `stat.h` | `brix_handle_stat()` — `kXR_stat` dual-mode: path → `brix_stat_beneath`; handle → `fstat`, **except** a driver-backed handle (`files[idx].sd_obj.driver` non-default, e.g. pblock) reports via the driver's `fstat` so the logical object size is correct rather than block 0's (the bare fd is only block 0); zip-member → archive `fstat` + member `cached_size`; slice-mode → synthesized from `cached_size`. Manager-mode registry/CMS-locate redirect; `brix_cache_path_flag()` adds `kXR_cachersp`; body formatted by `brix_make_stat_body`. |
| `statx.c` / `statx.h` | `brix_handle_statx()` — `kXR_statx` batched stat of up to 256 NUL-separated paths into one inline-line response, applying the **full** authdb + VO-ACL + token-scope gate per path and emitting an `"0 0 0 0"` sentinel for inaccessible/missing entries; last `\n` replaced with `\0`. |
| `locate.c` / `locate.h` | `brix_handle_locate()` — `kXR_locate`: manager-mode registry / collapse-redir cache / CMS redirect, static-map redirect, wildcard (`*`) pass-through, or local existence + auth gate returning an `S<rw>host:port` endpoint string (IPv4/IPv6/localhost forms). |
| `close.c` / `close.h` | `brix_handle_close()` — `kXR_close`: logs throughput before freeing, performs the POSC `fsync` + atomic `rename`, runs the write-through close-time flush (`brix_wt_flush_on_close`), flushes the write-recovery journal (`brix_wrts_flush`), releases the dashboard slot, and `brix_free_fhandle()`s the slot. |
| `clone.c` / `clone.h` | `brix_handle_clone()` — `kXR_clone` (v5.2.0): batched server-side range copy (≤1024 `clone_item`s) from open source handles into one open destination handle via `brix_copy_range()` (`copy_file_range`/pread+pwrite fallback), validating each handle's read/write access. |

## Key types & data structures

- **`brix_file_t`** (defined in `../types/`, table in `../connection/fd_table.c`): the
  per-handle state object indexed by the single-byte `fhandle[0]`, of which only slots
  0–15 (`BRIX_MAX_FILES`) are allocated. `kXR_open`
  populates it (`fd`, `readable`/`writable`, `is_regular`, `from_cache`, `device`/`inode`,
  `cached_size`, `bytes_read`/`bytes_written`, `open_time`, the `read_last_end`/
  `read_ahead_end` prefetch cursors, the `wt_*` write-through fields, the `wrts_*`
  write-recovery ring, `posc_final_path`, `dashboard_slot`, and the `slice_mode` /
  `slice_size` / `slice_cache_path` / `slice_clean_path` cache fields); every other
  opcode reads it; `kXR_close` frees it. A slot is "in use" iff `fd >= 0`.
- **`brix_ctx_t`** (`../types/context.h`): the per-connection context carrying
  `files[]`, `cur_streamid`, `payload`/`cur_dlen`, the reusable AIO task handles
  (`read_aio_task`, `readv_aio_task`, `pgread_aio_task`), the `read_scratch` buffer and
  its size, the windowed-read cursor (`rd_win_*`), `session_bytes`, the
  `cms_wait_streamid`, and the `XRD_ST_*` state (`XRD_ST_AIO`, `XRD_ST_WAITING_CMS`,
  `XRD_ST_SENDING`, …) used to suspend/resume across AIO and CMS round-trips.
- **Wire request structs** (`../protocol/`, mirroring `XProtocol.hh`):
  `ClientOpenRequest`, `ClientReadRequest`, `ClientPgReadRequest`, `readahead_list`
  (one `kXR_readv` segment), `ClientStatRequest`, `ClientLocateRequest`,
  `ClientCloseRequest`, `ClientCloneRequest`/`clone_item`. Offsets are big-endian int64,
  lengths big-endian uint32 — always decoded with `be64toh`/`ntohl`. Response bodies use
  `ServerOpenBody`, `ServerStatusResponse_pgRead`, and `ServerResponseHdr`.
- **`brix_readv_seg_desc_t`**: per-segment descriptor built before I/O so `preadv`
  writes straight into the assembled response body at `payload_ptr`, with
  `header_read_length_ptr` pointing at the wire field rewritten with the actual length.
- **`brix_read_aio_t` / `brix_readv_aio_t` / `brix_pgread_aio_t`** (`../aio/`):
  the task payloads carrying `fd`, `offset`, `rlen`, the scratch pointer, and the
  `streamid` needed to restore the suspended request in the done callback.
- **`brix_cache_fill_t`** (`../cache/`): reused by `slice_read.c` to carry the slice
  index/start/len, cache/part/lock paths, and the original `kXR_read`
  (`slice_read_idx`/`_offset`/`_rlen`) so the read handler can be re-entered after a
  slice fill lands.

## Control & data flow

Entry is always `brix_dispatch_read_opcode()` in
[`../handshake/dispatch_read.c`](../handshake/README.md), which validates the session is
bound and calls one `brix_handle_*()`. From there:

- **Path confinement & resolution** → [`../path/`](../../../fs/path/README.md):
  `brix_extract_path` (strip CGI query), `brix_count_path_depth`,
  `brix_beneath_full_path` / `brix_beneath_rel` / `brix_open_beneath` /
  `brix_stat_beneath` (`openat2 RESOLVE_BENEATH`), and the `brix_auth_gate`
  (authdb + VO-ACL + token scope; statx open-codes the three checks inline).
- **Handle table** → [`../connection/`](../connection/README.md):
  `brix_alloc_fhandle` / `brix_free_fhandle` / `brix_set_fhandle_path` /
  `brix_validate_read_handle` / `brix_validate_file_handle` /
  `brix_validate_write_handle`, plus the memory budget (`../connection/budget.h`,
  `brix_budget_admit`/`_sync`) gating large allocations.
- **Async I/O** → [`../aio/`](../../../core/aio/README.md): `brix_aio_post_task`,
  `brix_read_aio_thread`/`_done` (and the readv/pgread variants), `brix_task_bind`,
  `brix_aio_restore_request`/`brix_aio_resume` for suspend/resume.
- **Response framing** → [`../response/`](../response/README.md):
  `brix_build_resp_hdr`, `brix_build_chunked_chain`, `brix_build_sendfile_chain`,
  `brix_build_pgread_status`, `brix_make_stat_body`,
  `brix_send_ok`/`_error`/`_wait`/`_redirect`/`_redirect_tpc`,
  `brix_queue_response`/`_chain`, `brix_release_read_buffer`.
- **Caching** → [`../cache/`](../../../fs/cache/README.md): `brix_cache_open_or_fill`,
  `brix_cache_slice_fill_thread`, slice enumeration (`brix_slice_enumerate`,
  `brix_slice_path`, `../cache/slice.h`); and the write-through decision/flush
  (`../cache/writethrough_*`, `conf->wt_decision.fn`).
- **Cluster** → [`../manager/`](../../../net/manager/README.md) (`brix_srv_select`,
  `brix_redir_cache_lookup`/`_insert`, `brix_manager_tried_exhausted`,
  `brix_find_manager_map`) and [`../cms/`](../../../net/cms/README.md)
  (`ngx_brix_cms_send_locate` + `../manager/pending.c` for the suspended-request table).
- **TPC** → [`../tpc/`](../../../tpc/README.md): `brix_tpc_parse_opaque`,
  `brix_tpc_key_register`/`_consume`/`_generate_key`, `brix_tpc_prepare_pull`,
  `brix_tpc_check_authz`, plus `brix_send_redirect_tpc`.
- **Upstream proxy** → [`../upstream/`](../../../net/upstream/README.md): `brix_upstream_start`
  when a local read/stat/locate misses but an upstream origin is configured.
- **Cross-cutting** → write-recovery journal (`../write/wrts_journal.h`,
  `brix_wrts_open`/`_flush`), POSC temp paths (`../compat/tmp_path.h`,
  `brix_make_tmp_path`), mirror replay (`../mirror/stream_wmirror.h`,
  `brix_stream_wmirror_on_open`), session publish (`../session/registry.h`,
  `brix_session_handle_publish`), rate-limit bandwidth charge (`brix_rl_charge_ctx`,
  `../ratelimit/`), and the live-transfer dashboard (`../dashboard/`,
  `brix_transfer_slot_*`).

## Invariants, security & gotchas

- **Kernel confinement is mandatory.** Every client path is opened/stat'd through
  `RESOLVE_BENEATH` against the per-worker `conf->rootfd` (`brix_open_beneath`,
  `brix_stat_beneath`). `open_resolved_file.c` strips `root_canon` to derive the
  relative path for `openat2`; never call a raw `open`/`stat` on a wire path. Cache-root
  files are the one pre-validated exception and use plain `open` + `O_CLOEXEC`.
- **`allow_write` is a hard gate, checked before token scope.** Write-mode opens on a
  read-only server return `kXR_fsReadOnly` (`open_request.c:253` for the normal path;
  the TPC-pull path checks `conf->common.allow_write` separately), *except* in
  `manager_mode` where the write is forwarded to a data server.
- **TLS vs cleartext buffers never mix.** The `kXR_read` sendfile fast path is gated on
  `is_regular && (!c->ssl || brix_ktls_send_active(c))` (`read.c:130–131`): cleartext
  and active kernel-TLS use file-backed `sendfile`; userspace TLS falls back to
  heap-buffered memory chains (`b->memory=1`). `pgread` always uses memory-backed buffers
  because of CRC interleaving.
- **`kXR_pgread` wire layout is `[CRC32c(4)][data]` per 4096-byte page**
  (`pgread.c:69–71`), matching `AsyncPageReader::InitIOV` — digest first, then page data —
  with a `kXR_status` header carrying the next expected offset. Getting the order or the
  per-page size (`kXR_pgPageSZ`) wrong silently corrupts xrdcp v5 transfers.
- **Slice-mode handles are read-only and `kXR_read`-only.** Their fd is parked on
  `/dev/null` as a "slot in use" sentinel; `readv`/`pgread`/`stat` must special-case
  them (`files[idx].slice_mode`) — `readv`/`pgread` reject with `kXR_Unsupported`,
  `stat` synthesizes the size from `cached_size`. A raw `pread` on the sentinel fd
  returns empty data, not cached bytes.
- **Memory budget + windowing bound resident heap.** Large memory-path reads admit only
  one `BRIX_READ_WINDOW` (~2 MiB) and stream via `kXR_oksofar` (`read.c`); `readv`
  admits its whole response (up to `BRIX_MAX_READV_TOTAL` = 256 MiB) against the
  SHM-global budget and defers with `kXR_wait` when over. readv is **not** windowed yet —
  the budget caps the aggregate, not a single request.
- **STATX must apply the same gate as STAT.** `statx.c` runs authdb + VO-ACL +
  token-scope per path; skipping authdb there once leaked metadata that single-path STAT
  would refuse. Denials fall through to the `"0 0 0 0"` sentinel, preserving partial
  results.
- **POSC is crash-safe via staging + rename.** Writes with `kXR_posc` open a
  `.posc.<pid>.<rand>` temp on the same filesystem; the handle's `path` points at the
  temp and `posc_final_path` at the target. A dropped session unlinks the temp via
  `brix_free_fhandle`; a clean `kXR_close` does `fsync` + atomic `rename`, then clears
  `posc_final_path` *after* the write-through flush so the flush mirrors the final path.
- **Manager-mode `tried`/`triedrc` stops redirect loops.** A read whose client has
  already visited every server holding a path (all `enoent`) gets `kXR_NotFound`, not
  another redirect (`brix_manager_tried_exhausted`, `open_request.c`/`stat.c`); writes
  are excluded because they create the file on the selected server.
- **Read-only file size is cached at open time.** Reads on read-only handles use
  `files[idx].cached_size` to skip a per-chunk `fstat`; writable handles
  (`kXR_open_updt`) re-stat so same-session writes are visible.
- **AIO/CMS suspension uses `streamid`, not the connection.** Done callbacks call
  `brix_aio_restore_request(ctx, streamid)` before touching `ctx`; if it returns false
  the original request is gone (client disconnected) and the callback must bail without
  resuming. The slice read-resume only resumes the connection when the re-run leaves
  `XRD_ST_AIO`. `readv` total bytes must equal the requested run or it errors as
  "past EOF".
- **`readv` segment math is overflow-checked.** `brix_size_mul`, the
  `BRIX_READV_MAXSEGS` cap, and per-segment offset+length overflow guards run before
  any `malloc`/`preadv` (`readv.c`) — defense in depth over the recv-layer payload cap
  (a malformed-payload `kXR_ArgInvalid` enters at `readv.c:214`). Note the documented
  `read_scratch` corruption gotcha (phase-29 blocker) when refactoring the shared
  scratch buffer across `read.c`/`readv.c`/`slice_read.c` — it is reused across requests
  on one connection, so a stale pointer or premature release silently corrupts data.

## Entry points / extending

To add a **new read-side opcode** (e.g. a hypothetical `kXR_foo`):

1. Add the opcode constant and any wire struct in `../protocol/` (mirror `XProtocol.hh`).
2. Create `foo.c` + `foo.h` here exporting `ngx_int_t brix_handle_foo(brix_ctx_t *,
   ngx_connection_t *, ...)`. Reuse the helpers — `brix_validate_*_handle`,
   `brix_extract_path` + `RESOLVE_BENEATH`, `brix_auth_gate`, the AIO offload
   pattern, and `../response/` framing — never reimplement them.
3. Register the case in `../handshake/dispatch_read.c` (`DISPATCH_RD` for
   handle-only ops, `DISPATCH_RD_BOUND` for ops taking `conf`).
4. Register `foo.c` in the top-level `config` script (the module's `ngx_module_srcs`
   / `NGX_ADDON_SRCS` list) and re-`./configure`.
5. Add a metric slot (`BRIX_OP_FOO`) and emit `BRIX_OP_OK`/`BRIX_OP_ERR` (or the
   `BRIX_RETURN_*` macros) on every exit path; log via `brix_log_access`.
6. Add the three required tests: success, error, and a security-negative (confinement /
   auth) case.

For a new **cache or prefetch tunable**, prefer extending `prefetch.h` constants or the
write-through decision engine in `../cache/` rather than threading new state through
`brix_file_t`.

## See also

- [`../README.md`](../README.md) — master subsystem index.
- [`../handshake/README.md`](../handshake/README.md) — opcode dispatch into this module.
- [`../write/README.md`](../write/README.md) — sibling write opcodes sharing the handle table.
- [`../path/README.md`](../../../fs/path/README.md) — confinement, resolution, and the auth gate.
- [`../aio/README.md`](../../../core/aio/README.md) — thread-pool offload and suspend/resume.
- [`../response/README.md`](../response/README.md) — wire framing and response chains.
- [`../cache/README.md`](../../../fs/cache/README.md) — XCache fill, slice cache, write-through.
- [`../connection/README.md`](../connection/README.md) — fd table, budget, send/recv.
- [`../manager/README.md`](../../../net/manager/README.md) / [`../cms/README.md`](../../../net/cms/README.md) — cluster redirect & locate.
- [`../tpc/README.md`](../../../tpc/README.md) — native third-party-copy key registry.
- [`../upstream/README.md`](../../../net/upstream/README.md) — upstream-origin fallthrough.
