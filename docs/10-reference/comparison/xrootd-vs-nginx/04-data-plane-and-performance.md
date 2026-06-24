Part of the [XRootD vs nginx-xrootd comparison set](./README.md).

# Data plane and performance: official XRootD vs nginx-xrootd

## Scope

This document compares the **data plane** — the code that actually moves
file bytes — between official XRootD and the `nginx-xrootd` module. It covers:

- the read path (`kXR_read`, `kXR_readv`, `kXR_pgread`);
- the write path (`kXR_write`, `kXR_writev`, `kXR_pgwrite`, `kXR_sync`);
- asynchronous I/O (thread pools, POSIX AIO, io_uring);
- zero-copy delivery (`sendfile`, kTLS / `SSL_sendfile`, memory-backed buffers);
- write pipelining;
- checksums (adler32, crc32, crc32c, crc64/XZ, crc64nvme, md5, sha\*);
- transparent read/write compression;
- the resulting performance characteristics and the directives an operator uses
  to tune them.

It does **not** cover authentication, the WebDAV/S3 surfaces, clustering, or
TPC except where they touch the byte-moving path. Every claim below is grounded
in source on both sides; file paths are given inline. Performance numbers are
attributed to the document or measurement that produced them, and anything not
independently confirmed is marked **not verified**.

The two projects make a fundamentally different structural bet:

- **Official XRootD** is a standalone multi-threaded C++ daemon: an epoll/poll
  readiness layer (`Xrd/XrdPoll*`) hands ready connections to a worker-thread
  pool (`XrdScheduler`), and disk asynchrony is POSIX `aio_*` completed by
  realtime signals on a dedicated wait thread.
- **nginx-xrootd** rides nginx's single-thread-per-worker event loop and never
  blocks it: blocking syscalls are pushed to an nginx thread pool, with an
  optional `io_uring` backend in front of it, and completions resume the
  connection on the event loop.

Both are correct designs for their host runtime; the comparison below shows
where each is strong.

## In official XRootD

The XRootD protocol engine lives in `XrdXrootd/`, sitting on the open-file-system
abstraction (`XrdOfs/`) and the storage layer (`XrdOss/`). The relevant entry
points are the protocol opcode handlers:

| Opcode | Handler | File |
|---|---|---|
| `kXR_read` | `XrdXrootdProtocol::do_Read` | `XrdXrootd/XrdXrootdXeq.cc:2543` |
| `kXR_readv` | `XrdXrootdProtocol::do_ReadV` | `XrdXrootd/XrdXrootdXeq.cc:2746` |
| `kXR_pgread` | `do_PgRead` / `do_PgRIO` | `XrdXrootd/XrdXrootdXeqPgrw.cc:113,214` |
| `kXR_write` | `do_Write` / `do_WriteAll` | `XrdXrootd/XrdXrootdXeq.cc:3310` |
| `kXR_pgwrite` | `do_PgWrite` / `do_PgWIORetry` | `XrdXrootd/XrdXrootdXeqPgrw.cc:361,565` |
| `kXR_sync` | `do_Sync` | `XrdXrootd/XrdXrootdXeq.cc:3210` |

Asynchronous I/O is `XrdXrootdNormAio` (normal read/write) and
`XrdXrootdPgrwAio` (paged), both derived from `XrdXrootdAioTask`, which *is a*
`XrdJob` scheduled onto the global `XrdScheduler` pool
(`XrdXrootd/XrdXrootdAioTask.{hh,cc}`). The disk side is POSIX `aio_read`/
`aio_write`/`aio_fsync` in `XrdOss/XrdOssAio.cc`, with completion delivered by
`SIGRTMIN`-based handlers consumed by a dedicated `XrdOssAioWait` thread.
Checksums are the `XrdCks/` framework (`XrdCksManager`, `XrdCksCalc`).

## In nginx-xrootd

The module mirrors those opcodes but maps each onto an nginx-native, never-block
implementation:

| Opcode | Handler | File |
|---|---|---|
| `kXR_read` | `xrootd_handle_read` | `src/read/read.c:77` |
| `kXR_readv` | `xrootd_handle_readv` | `src/read/readv.c:201` |
| `kXR_pgread` | `xrootd_handle_pgread` | `src/read/pgread.c:181` |
| `kXR_write` | `xrootd_handle_write` | `src/write/write.c:67` |
| `kXR_writev` | `xrootd_handle_writev` | `src/write/writev.c:35` |
| `kXR_pgwrite` | `xrootd_handle_pgwrite` | `src/write/pgwrite.c:146` |
| `kXR_sync` | `xrootd_handle_sync` | `src/write/sync.c:42` |

Asynchrony is the `src/aio/` subsystem: a thread-pool backend (nginx
`ngx_thread_pool`) plus an optional `io_uring` backend (`src/aio/uring*.c`,
Phase 44), both funnelled through one interposition point
`xrootd_aio_post_task()` (`src/aio/resume.c:68`). Checksums are a single C
kernel per family (`src/compat/crc32c.c`, `src/compat/crc64.c`,
`src/compat/checksum*.c`), with per-protocol encoding done at the edges. The
module additionally implements transparent read/write **compression**
(`src/compat/codec_*.c`) that has no equivalent in the official root:// path.

## Read path

### `kXR_read`

Official `do_Read` chooses one of four modes at request time
(`XrdXrootdXeq.cc:2587-2620`):

1. **mmap** — data sent directly from `mmAddr+offset` (zero-copy);
2. **sendfile** (`useSF`) — when `sfEnabled && !isTLS && IOLen >= as_minsfsz`
   (`as_minsfsz = 8192`), via `Response.Send(fdNum, offset, len)` →
   `XrdLinkXeq::Send(sfVec)`; **disabled for TLS** (`Xrd/XrdLinkXeq.cc:1402`);
3. **basic** — synchronous buffered `read()` into a `BPool` buffer;
4. **async** (`XrdXrootdNormAio`) — when `AsyncMode && IOLen >= as_miniosz`
   (`as_miniosz = 98304`) and per-link/per-server caps allow
   (`as_maxperlnk = 8`, `as_maxpersrv = 4096`), AIO quantum
   `as_segsize = 65536` (`XrdXrootdProtocol.cc:120-136`).

nginx-xrootd's `xrootd_handle_read` runs a comparable dispatch ladder
(`read.c:132-441`):

1. slice-cache mode (if enabled);
2. inline read-compression if the handle has a `read_codec` (see Compression);
3. **zero-copy sendfile** when the target is a regular file and the connection
   is cleartext *or* kTLS is active (`read.c:160-245`, gate
   `!c->ssl || xrootd_ktls_send_active()` at `read.c:66-75`);
4. **windowed memory streaming** when the total exceeds
   `XROOTD_READ_WINDOW = 2 MiB`, driven by `xrootd_read_window_pump`
   (`read.c:266-306`) to keep resident memory bounded;
5. **small single-shot read** otherwise.

The request length is capped at `XROOTD_READ_REQUEST_MAX = 64 MiB`
(`read.c:115`, `src/types/tunables.h`); the wire chunk is split at
`XROOTD_READ_CHUNK_MAX = 16 MiB`. For the small memory path the module first
tries a Phase-32 warm-cache probe — `preadv2(..., RWF_NOWAIT)` — and completes
inline when the page cache already holds the exact range, skipping the thread
pool entirely (`read.c:363-383`); otherwise it posts
`xrootd_read_aio_thread` to the configured pool, degrading to an inline `pread`
only when no pool is available (`read.c:385-441`).

The key structural difference: official picks sync-vs-async by request *size*
and may block a worker thread on basic reads; nginx-xrootd never blocks the
event loop — it either zero-copies, serves from a `RWF_NOWAIT` cache hit, or
hands off to a thread pool / io_uring.

### `kXR_readv`

Official `do_ReadV` reads a vector request into `rdVec[XrdProto::maxRvecsz+1]`
and rejects vectors with more than `maxRvecsz` segments
(`XrdXrootdXeq.cc:2746`, constant in `XProtocol/XProtocol.hh`).

nginx-xrootd's `xrootd_handle_readv` (`readv.c:201`) enforces several explicit
caps:

| Cap | Constant | Value | Where |
|---|---|---|---|
| Max segment count | `XROOTD_READV_MAXSEGS` | 1024 | `src/protocol/flags.h:223` |
| Per-segment header | `XROOTD_READV_SEGSIZE` | 16 B | `flags.h:222` |
| Per-element byte cap | `readv_segment_size` (= official `maxReadv_ior`) | 2 MiB − 16 = 2 097 136 | `config/server_conf.c:380` |
| Total response cap | `XROOTD_MAX_READV_TOTAL` | 256 MiB | `readv.c:57` |
| preadv scatter cap | `XROOTD_READV_PREADV_MAXIOV` | 64 iovecs/syscall | `readv.c:58` |

These map to the protocol's advertised `readv_ior_max` (per-element) and
`readv_iov_max` (segment count), reported through `kXR_query` Qconfig
(`query/config.c:138-154`). The implementation is two-phase — validate, then a
single scratch allocation — and lays the wire body out as
`[16B header][payload]…` *before* issuing I/O, so a coalesced `preadv` lands
directly into the payload pointers (`readv.c:320-363`). Contiguous same-fd runs
are grouped into one `preadv` (`readv.c:154-189`), and a short read past EOF is
a hard error.

### `kXR_pgread`

Both sides implement the paged-read protocol with the same on-wire shape:
4096-byte pages, each preceded by a 4-byte big-endian CRC32c, with a
`kXR_status` response that reports the next-expected offset and uses a
partial/"oksofar" frame for intermediate chunks.

| Property | Official | nginx-xrootd |
|---|---|---|
| Page size | `kXR_pgPageSZ = 4096`, unit `kXR_pgUnitSZ = 4100` (`XProtocol.hh:528-530`) | same constants (`flags.h:255-257`), CRC word `XROOTD_PG_CKSZ = 4` (`pgread.c:56`) |
| Per-page CRC | CRC-32C via `XrdOucCRC::Calc32C` (`XrdOucPgrwUtils.cc`), SSE4.2 with software fallback | `xrootd_crc32c_value`, SSE4.2 `_mm_crc32_u64` + software fallback, poly `0x82F63B78` (`crc32c.c:25`) |
| File-offset alignment | first/last page may be short (`csNum`/`csVer`) | short first page from `in_off = cur & (kXR_pgPageSZ-1)` (`pgread.c:115-116`) |
| Partial framing | `kXR_PartialResult` (0x01) intermediate, `kXR_FinalResult` last; iovec bounded `maxPGRD ≈ 2 093 056 B` (`XrdXrootdXeqPgrw.cc:219-242`) | `ServerStatusResponse_pgRead` next-offset header, oksofar chunking in `xrootd_build_pgread_chain`; batch ≤ `XROOTD_PGREAD_MAXIOV = 64` pages (`pgread.c:58,341`) |

The notable engineering difference is on the nginx-xrootd side:
`xrootd_pgread_read_encode_inplace()` (`pgread.c:88-165`) performs a
**zero-copy gapped `preadv` plus an in-place 3-way CRC**. It lays out a batch of
pages with the data positioned *after* each 4-byte CRC gap, `preadv`s the
contiguous file region straight into that gapped wire buffer, then runs the
read-only 3-way-pipelined CRC32c in place, writing each big-endian CRC into the
gap that precedes its page. This eliminates the older flat-buffer copy pass; the
verified result (see `docs/refactor/phase-32-data-plane-perf-parity.md` and the
project memory note "pgread zero-copy + CRC optimization") was a reduction of
the module's CRC-plus-copy cost from ~27.6% to ~10% of read CPU, while remaining
byte-identical to the reference encoding (`xrdp_pg_encode`). pgread is always
plaintext on both sides — it never consults a compression codec — preserving the
per-page-CRC integrity invariant.

### Async I/O backends

**Official.** AIO completion runs on the `XrdScheduler` worker pool, default
`minw=8, maxw=8192` workers (`Xrd/XrdScheduler.hh:90`), tunable via
`xrd.sched`. The disk I/O itself is POSIX `aio_read`/`aio_write`/`aio_fsync`
(`XrdOss/XrdOssAio.cc`), with completion delivered by realtime-signal handlers
consumed by a dedicated `XrdOssAioWait` thread. If the OSS lacks native AIO,
async is disabled (`as_aioOK = false`). This is a thread-per-active-request
model with an epoll readiness front end — strong on many-core servers because
each in-flight request can occupy its own worker.

**nginx-xrootd.** Asynchrony is a three-tier cascade behind one interposition
point, `xrootd_aio_post_task()` (`resume.c:68-122`):

1. **io_uring** (Phase 44, `src/aio/uring*.c`) when compiled in and enabled.
   Directive `xrootd_io_uring off|on|auto` (default `auto`,
   `server_conf.c:387`); `on` is fail-fast at `nginx -t`. Companion directives:
   `xrootd_io_uring_queue_depth` (default 256), `xrootd_io_uring_panic_file`
   (kill-switch), `xrootd_io_uring_admin`, `xrootd_io_uring_restrict`. It maps
   READ, WRITE, single-contiguous-group READV, and single-contiguous-fd WRITEV
   (with linked FSYNC for sync); pgread, dirlist, multi-fd, and gapped vector
   ops fall through to the thread pool (`uring_submit.c:100-121`). Submissions
   carry a `user_data = (generation<<32)|slot` cookie for UAF-safe completion
   (`uring.h`).
2. **nginx thread pool** otherwise — the `_thread` worker does only the blocking
   syscall, the `_done` callback runs on the event loop (`aio/README.md`). The
   pool is resolved by name (`xrootd_thread_pool`, default `"default"`) in
   `xrootd_configure_thread_pools` (`aio/config.c:18-69`).
3. **inline blocking syscall** if no pool is resolvable (logged degradation).

The safety-critical piece is the **destroyed-connection guard** in `resume.c`:
`xrootd_aio_restore_stream` checks `ctx->destroyed` first and returns 0 so the
completion callback touches nothing if the connection went away mid-flight
(`resume.c:21-32`); the io_uring slot adds a second generation-guard layer on
top of that (`uring.h:42-48`). This pattern is what lets a single-thread-per-
worker event loop safely fan work out to other threads/rings.

## Write path

### `kXR_write` and write pipelining

Official `do_Write` (`XrdXrootdXeq.cc:3310`) either runs `do_WriteAll`
synchronously or, for large writes within the per-link/per-server caps, allocates
`XrdXrootdNormAio` and issues `aioP->Write(offset, len)` — the same async
machinery as reads.

nginx-xrootd's `xrootd_handle_write` (`write.c:67`) validates a writable handle,
optionally decompresses, skips replayed writes during `kXR_recoverWrts`, then
either posts to AIO or does an inline `pwrite`; a short write surfaces as a hard
`kXR_IOError` ("short write (disk full?)", `write.c:159-163`).

On top of this the module adds **write pipelining**, which official XRootD does
not implement in this form. The recv loop keeps receiving the next request while
prior `pwrite`s are still in flight, bounded by `out_count + wr_inflight <
ctx->pipeline_depth` (`write.c:131-137`). The depth is the directive
`xrootd_pipeline_depth N`, default `XROOTD_PIPELINE_DEPTH_DEFAULT = 8`, clamped
to `[1, 64]` (`tunables.h:108-110`, `server_conf.c:456-465`). On a successful
post the payload is detached (`ctx->payload = NULL`), `wr_inflight++`, and the
handler returns while recv continues. Acks are **asynchronous**:
`xrootd_write_aio_done` decrements `wr_inflight` *before* the liveness check,
restores only the streamid, and sends the ack with `ctx->resp_async = 1` so it
is parked in `out_ring` without suspending recv, then schedules a read resume
(`aio/write.c:61-145`). Teardown is deferred: if the connection was destroyed
while writes were in flight, the last completion (`wr_inflight == 0` with
`finalize_pending`) runs `xrootd_run_deferred_teardown`, and the detached payload
is freed unconditionally first — a UAF-safe finalize at every completion site
(`aio/write.c:50-97`).

The verified effect (project memory note "Write pipelining (root:// kXR_write)"
and `docs/refactor/phase-32-data-plane-perf-parity.md`): n=8 root:// writes moved
from **~1550 MiB/s to ~1950 MiB/s**, crossing from behind to ahead of reference
xrootd, with byte-exact integrity and disconnect-stress verified. Full
pytest+ASAN sign-off was still outstanding at the time of that note — treat the
throughput figure as a single-host WSL2 measurement, not an audited benchmark.

`kXR_writev` (`writev.c:35-305`) validates all target handles before any write
(all-or-nothing), discovers segment count from `n*16 + sum(wlen) == dlen`, and
optionally fsyncs each touched fd on `kXR_wv_doSync`. pgwrite is deliberately
**not** pipelined — it runs serially with a full request-state restore
(`aio/write.c:148-155`).

### `kXR_pgwrite` and the CSE retransmit machine

nginx-xrootd implements the full per-page checksum-error (CSE) retransmit
protocol, matching official byte-for-byte.

Official `do_PgWrite` (`XrdXrootdXeqPgrw.cc:361`) re-verifies every page's CRC32c
with `XrdOucPgrwUtils::csVer`, records each bad page via `pgwCtl->boAdd`, and on
checksum errors appends a `ServerResponseBody_pgWrCSE` structure
(`XProtocol.hh:1117`): a `cseCRC`, `dlFirst`/`dlLast`, and a **list of file
offsets of the pages in error**. The client then resends only those pages with
the `kXR_pgRetry` flag (`kXR_pgRetry = 0x01`). The retry path
`do_PgWIORetry` (`:565`) enforces at most one page per retry and that the offset
was registered as in-error. At close, `do_PgClose` (`XrdXrootdXeq.cc:665`)
returns `kXR_ChkSumErr` while any page remains uncorrected.

nginx-xrootd's `xrootd_handle_pgwrite` (`pgwrite.c`) verifies **every** page via
the shared `xrdp_pg_decode_collect` (`compat/pgio.c`), writes all pages — good
and bad — to disk (accept-then-correct), and on any CRC failure replies with a
**success** `kXR_status` frame carrying the `pgWrCSE` trailer + the bad-page
offset list (`xrootd_send_pgwrite_cse`, `response/status.c`). Each uncorrected
page is registered in a per-handle "Fob" (`write/pgw_fob.c`, keyed exactly like
stock `XrdXrootdPgwFob`). A `kXR_pgRetry` resend is single-page-bounded, must
target a registered offset (else it is treated as a normal write), and clears
the Fob entry when the page re-verifies. `kXR_close` (`read/close.c`) returns
`kXR_ChkSumErr "<n> uncorrected checksum errors"` while the Fob is non-empty,
leaving the handle open so the client can correct and re-close — this close gate
is what preserves the integrity guarantee once corrupt bytes are on disk. The
per-request error cap (`kXR_pgMaxEpr = 128`) and per-file cap
(`kXR_pgMaxEos = 256`) both surface as `kXR_TooManyErrs`. The native client
(`client/lib/ops_file.c`) parses the CSE list and drives the `kXR_pgRetry`
resend loop. Malformed framing still returns `kXR_ArgInvalid`. Differential
conformance vs stock (`tests/test_conf_pgio.py`) confirms byte-exact parity of
the offset list, `dlFirst`/`dlLast`, the retry correction, and the close gate.

### `kXR_sync`

Official `do_Sync` (`XrdXrootdXeq.cc:3210`) calls `XrdSfsp->sync()` and supports
async completion via a callback. nginx-xrootd's `xrootd_handle_sync`
(`sync.c:42-106`) validates the handle, fsyncs the fd, and additionally flushes
the write-resilience journal (`xrootd_wrts_flush`) and any write-through dirty
data. It also dual-purposes sync on a TPC-destination handle: the first sync
arms the pull, the second triggers `xrootd_tpc_start_pull` (`sync.c:56-66`).

## Zero-copy and TLS

The hard invariant on both sides is that **sendfile and TLS do not mix** — but
the projects reach the same correctness conclusion through different mechanisms.

**Official.** sendfile (`useSF`) is chosen only when `!isTLS`
(`XrdXrootdXeq.cc:2588`), and `XrdLinkXeq::Send` explicitly avoids sendfile on
TLS links ("avoid using sendfile on TLS", `Xrd/XrdLinkXeq.cc:1402`). TLS reads
fall back to buffered userspace copies. On Linux the cleartext path uses
`sendfile()`; Solaris uses `sendfilev()`.

**nginx-xrootd.** The TLS buffer invariant (CLAUDE.md INVARIANT 2) is enforced
in the buffer layout: for TLS responses buffers are memory-backed (`b->memory =
1`), and for cleartext they are file-backed so nginx's `sendfile` engine can
zero-copy. The read handler picks the sendfile branch only when the connection
is not TLS *or* kTLS send is active (`read.c:66-75,160`). When the kernel has
negotiated **kTLS**, `xrootd_ktls_send_active()` (checking `BIO_get_ktls_send`)
lets the connection rejoin the zero-copy sendfile path because the kernel can
encrypt in place — this is the `SSL_sendfile` / kTLS gating verified in Phase 32
(`docs/refactor/phase-32-data-plane-perf-parity.md`: the TLS GET shows
`sendfile` once kTLS is active). The practical consequence: cleartext root://
and S3 reads zero-copy from the page cache; TLS reads zero-copy *only* when kTLS
is available, otherwise they take the windowed userspace path with bounded
resident memory.

## Checksums

Official XRootD provides checksums through the `XrdCks/` plugin framework
(`XrdCksManager`, `XrdCksCalc`). The built-in calculators are **adler32, crc32,
crc32c, md5** (`XrdCksManager.cc:87-90`), with a separately-built zlib crc32
module (`XrdCksCalczcrc32`); other algorithms are loadable plugins. Notably,
**crc64 is name-only** in official source: the only reference is a
length/format table entry `{"crc64", 16, 8}` in `XrdCks/XrdCksAssist.cc:51`, and
the manager ships **no crc64 compute engine** — it would have to come from an
external plugin, and there is no CRC-64/XZ vs CRC-64/NVME distinction.
`kXR_Qcksum` (`do_CKsum`, `XrdXrootdXeq.cc:436,513`) returns the result on the
wire as `"<algname> <hexvalue>\0"`.

nginx-xrootd parses and computes a broader set in a single small C kernel per
family (`xrootd_checksum_parse`, `src/compat/checksum.c:42-169`): **adler32,
crc32, crc32c, crc64 (alias crc64xz), crc64nvme, zcrc32, md5, sha1, sha256**.
The crc32c kernel is `src/compat/crc32c.c` (SSE4.2 + software, poly
`0x82F63B78`). The CRC64 kernel is the single engine in `src/compat/crc64.c`,
which builds one reflected 256-entry table per *variant* at constructor time:

| Variant | Reflected poly | Check value | Notes |
|---|---|---|---|
| `crc64` / `crc64xz` (CRC-64/XZ) | `0xC96C5795D7870F42` | `0x995DC9BBDF1939FA` | root:// + WebDAV |
| `crc64nvme` (CRC-64/NVME) | `0x9A6C9329AC4BC9B5` | `0xAE8B14860A799888` | S3 |

These polynomials are **different and not interchangeable** (CLAUDE.md
INVARIANT 9). Critically, the kernel returns only a raw `uint64_t`; **encoding
is done at the protocol edge, never in the kernel** (`crc64.h:30-32`). The
root:// and WebDAV paths emit 16 lowercase hex chars (`%016llx`), matching the
official wire format; the S3 path emits base64 of the 8 big-endian bytes for
`x-amz-checksum-crc64nvme`. `kXR_query` Qcksum reports the full supported list
(adler32 first, the xrdcp default) as a bare comma-separated string
(`query/config.c:119-130`). A `xrootd_crc64_combine` (GF(2) folding) supports
S3 multipart FULL_OBJECT composition.

Net: nginx-xrootd ships crc64 (both XZ and NVME flavours) as first-class,
in-tree, where official XRootD treats crc64 as an external plugin slot and
crc64nvme not at all. For the algorithms both support, the root:// wire format
is identical.

## Compression (nginx-forward)

Transparent on-the-fly read/write compression is an **nginx-xrootd extension
that has no equivalent in the official root:// data path**. Grepping the entire
official `XrdXrootd/`, `XrdOfs/`, and `XrdOss/` trees for any streaming codec
returns nothing; zlib is linked only for the optional crc32 checksum plugin. The
single compression-adjacent feature in official XRootD is a legacy *read-only
pre-compressed-file passthrough*: `XrdOssFile::isCompressed()` detects files
written in the old `oocx_CXFile` format and the `kXR_compress` open flag merely
sets `SFS_O_RAWIO` so the client reads the raw compressed bytes — the server
neither compresses nor decompresses, and such files cannot be opened for update.

nginx-xrootd implements real, negotiated codecs in `src/compat/codec_*.c`. The
codec table (`codec_core.c:81-90`) is IDENTITY, GZIP, DEFLATE, ZSTD, BROTLI, XZ
(lzma), BZIP2, LZ4; each backend compiles to an `available = 0` stub if its
library is absent. Decompression enforces an output cap and a maximum expansion
ratio to defeat decompression bombs (`XROOTD_CODEC_ERR_BOMB`). Integration into
root:// is **opt-in and off by default**:

- **Read** — `xrootd_read_compressed` (`src/read/read_compress.c:110-228`) runs
  only when the handle was opened with `?xrootd.compress=<codec>`
  (`read_codec != IDENTITY`); it compresses one bounded plaintext window
  (clamped to `XROOTD_READ_CHUNK_MAX = 16 MiB`) into a single frame.
- **Write** — `xrootd_write_compressed` decompresses inline before the `pwrite`
  (`write.c:96-98`).
- **pgread / pgwrite / readv never compress**, preserving the plaintext +
  per-page-CRC invariant.

Toggles are stream directives `xrootd_read_compress` / `xrootd_write_compress`
(both default off, `stream/module.c:556-572`), advertised via Qconfig
`cmpread`/`cmpwrite`, with per-protocol siblings `xrootd_webdav_compress` and
`xrootd_s3_compress`. Because this is an extension, a stock XRootD client will
simply never request it; interoperability is unaffected.

## Performance characteristics

The two runtimes are strong in different regimes.

**Official XRootD** is a multi-threaded daemon: epoll/poll readiness +
`XrdScheduler` worker pool (default up to 8192 workers) + POSIX disk AIO
completed by realtime signals. Each active request can occupy a worker, so on a
many-core box with many concurrent transfers it scales naturally with cores, and
a slow/blocking storage backend ties up a worker rather than stalling everyone.
It uses sendfile and mmap for cleartext zero-copy, but **falls back to userspace
buffering for all TLS reads**.

**nginx-xrootd** is event-loop + sendfile + thread-pool (+ optional io_uring).
A worker never blocks: the event loop multiplexes thousands of connections, disk
work is offloaded, and the read fast paths (cleartext sendfile, kTLS
`SSL_sendfile`, the `RWF_NOWAIT` warm-cache inline read, the gapped-preadv
in-place-CRC pgread, write pipelining) minimise both copies and syscalls. Its
distinctive wins over official are: zero-copy **on kTLS-negotiated TLS reads**
(official cannot sendfile over TLS at all); the lower-overhead pgread CRC path;
and write pipelining. Its structural limitation is the inverse of official's
strength — concurrency on one worker is bounded by the thread pool / io_uring
queue depth rather than by spawning a worker per request, so a deep backlog of
slow-storage operations is shaped by `xrootd_io_uring_queue_depth` and the
nginx thread-pool sizing rather than expanding unboundedly.

**Measurement caveats.** The concrete numbers cited here — pgread CRC+copy cost
~27.6%→~10%, write pipelining ~1550→~1950 MiB/s — come from this project's
Phase-32 data-plane work and the associated project-memory notes, measured on a
single **WSL2** developer host with no hardware PMU (CPU profiling used
task-clock + DWARF; see the "CPU flame-graph profiling" note). WSL2 throughput
and CPU figures are directional, not datacenter-representative; the project notes
themselves flag that several of these were validated for *integrity* (byte-exact,
disconnect-stress) before full ASAN/pytest throughput sign-off. No head-to-head
benchmark against official XRootD on production-grade hardware is recorded here,
so all cross-project performance comparisons above are **architectural, not
benchmarked** unless a specific verified figure is attributed.

## Admin tuning & end-user view

What an operator turns, and what an end user observes:

| Concern | Directive (nginx-xrootd) | Default | Official analogue |
|---|---|---|---|
| Thread pool (stream) | `xrootd_thread_pool` (resolves an nginx `thread_pool`) | `"default"` | `xrd.sched mint/maxt/avlt/idle` |
| Thread pool (WebDAV/S3) | `xrootd_webdav_thread_pool` / `xrootd_s3_thread_pool` | — | (same scheduler) |
| io_uring backend | `xrootd_io_uring off\|on\|auto` | `auto` | n/a (POSIX AIO only) |
| io_uring queue depth | `xrootd_io_uring_queue_depth` | 256 | n/a |
| io_uring kill-switch | `xrootd_io_uring_panic_file` | "" | n/a |
| readv per-element cap | `xrootd_readv_segment_size` | 2 MiB − 16 | `maxReadv_ior` |
| readv max segments | `XROOTD_READV_MAXSEGS` (compile constant) | 1024 | `XrdProto::maxRvecsz` |
| Write/read pipeline depth | `xrootd_pipeline_depth` | 8 (clamp 1–64) | n/a |
| Read compression | `xrootd_read_compress` | off | n/a |
| Write compression | `xrootd_write_compress` | off | n/a |
| Slice cache | `xrootd_cache_slice` | off | (PFC, separate) |
| Memory budget | `memory_budget` | 768 MiB | n/a (per-worker buffers) |
| Async I/O (official) | — | — | `xrootd.async maxperlnk/maxsegs/minsz/...` |

There is no separate "enable AIO" directive in nginx-xrootd: AIO is active
whenever a thread pool is resolvable, and io_uring is the only data-plane backend
toggle. The nginx core `thread_pool` directive sizes the pool the module
resolves by name.

From the **end user's** perspective the data plane is transparent: they see
throughput and correct bytes. Reads and writes of files using the algorithms
both servers share are byte-identical and checksum-compatible on the wire. A user
gets faster TLS reads from nginx-xrootd when the kernel offers kTLS, faster
streamed writes from pipelining, and — only if they explicitly opt in with
`?xrootd.compress=` and the operator enabled it — transparent compression that a
stock XRootD server would not offer. Integrity is never traded for speed: every
fast path here (warm-cache inline read, gapped-preadv pgread, pipelined write,
compressed read/write) was gated on byte-exact verification, and the per-page
CRC paths never compress.

## Source references

**Official XRootD** (`/tmp/xrootd-src/src/`):

- `XrdXrootd/XrdXrootdXeq.cc` — `do_Read:2543`, `do_ReadV:2746`, `do_Sync:3210`,
  `do_Write:3310`, `do_CKsum:436/513`; sendfile gate `:2588`; `SendFile:3832`.
- `XrdXrootd/XrdXrootdXeqPgrw.cc` — `do_PgRead:113`, `do_PgRIO:214`,
  `do_PgWrite:361`, `do_PgWIORetry:565`; iovec bound `:219-221`.
- `XrdXrootd/XrdXrootdProtocol.cc:120-136` — AIO tuning constants
  (`as_maxperlnk`, `as_miniosz`, `as_segsize`, `as_minsfsz`).
- `XrdXrootd/XrdXrootdAioTask.{hh,cc}`, `XrdXrootdNormAio.cc`,
  `XrdXrootdPgrwAio` — async task / scheduling.
- `XProtocol/XProtocol.hh` — `kXR_pgPageSZ:528`, `kXR_pgUnitSZ:530`,
  `kXR_pgRetry:537`, `ServerResponseBody_pgRead:1100`,
  `ServerResponseBody_pgWrite:1109`, `ServerResponseBody_pgWrCSE:1117`,
  `kXR_PartialResult:1293`.
- `XrdOuc/XrdOucPgrwUtils.cc`, `XrdOuc/XrdOucCRC32C.cc` — per-page CRC32C.
- `Xrd/XrdLinkXeq.cc:1402,724,783` — sendfile, TLS exclusion.
- `Xrd/XrdScheduler.{hh,cc}`, `Xrd/XrdPoll*` — worker pool + readiness.
- `XrdOss/XrdOssAio.cc` — POSIX disk AIO + wait thread.
- `XrdCks/XrdCksManager.cc:87-90`, `XrdCks/XrdCksAssist.cc:48-55` —
  checksum framework and the crc64 name-only entry.
- `XrdOss/XrdOssApi.cc:1287`, `XrdOfs/XrdOfs.cc:809-810` — legacy
  compressed-file passthrough (no streaming codec).

**nginx-xrootd** (`src/`):

- `read/read.c:66-499` — read dispatch, sendfile/kTLS gate, warm-cache probe,
  windowed streaming.
- `read/readv.c:54-466` — readv caps, two-phase layout, coalesced preadv.
- `read/pgread.c:56-367` — pgread framing; `xrootd_pgread_read_encode_inplace:88`
  (gapped preadv + in-place 3-way CRC).
- `read/read_compress.c:110-228` — opt-in read compression.
- `write/write.c:67-203` — write path, pipelining gate.
- `write/writev.c:35-305` — writev all-or-nothing.
- `write/pgwrite.c:99-296` — pgwrite CRC verify + hard-fail (CSE divergence).
- `write/sync.c:42-106` — sync + journal/WT flush + TPC arm.
- `aio/resume.c:21-171` — interposition point + destroyed-connection guard +
  resume.
- `aio/write.c:13-304` — async write done, async acks, deferred teardown.
- `aio/uring.{c,h}`, `aio/uring_submit.c`, `aio/config.c` — io_uring backend,
  op mapping, thread-pool resolution.
- `compat/crc32c.c:25`, `compat/crc64.{c,h}`, `compat/checksum.c:42-323` —
  checksum kernels and edge encoding.
- `compat/codec_core.c:81-243`, `compat/codec_*.c` — compression codecs.
- `protocol/flags.h`, `types/tunables.h`, `config/server_conf.c`,
  `stream/module.c` — caps, defaults, directives.
- `query/config.c:119-154` — Qcksum / readv-cap / compression advertisement.
- `docs/refactor/phase-32-data-plane-perf-parity.md`,
  `docs/refactor/phase-44-io-uring-backend.md` — verified perf work and io_uring
  status.
- `docs/10-reference/comparison/by-the-numbers.md` — source/footprint figures.
