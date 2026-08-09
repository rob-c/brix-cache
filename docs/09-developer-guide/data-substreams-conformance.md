# Data sub-streams (kXR_bind) — status, defaults, and conformance

**As-audited 2026-08-04.** The `kXR_bind` (request 3024) feature lets a client open secondary
TCP connections that carry data in parallel with the primary control connection. In BriX it is
gated by `brix_data_substreams` (default **ON**).

## Wire fact that shapes everything

`kXR_read` (`ClientReadRequest`) carries **no** pathid field; `kXR_write` does
(`fhandle[4] offset[8] pathid[1]`). Consequences:
- The server can only route a **read** by *which connection it arrives on* (a bound secondary
  vs the primary). A client that wants parallel reads must actually **issue read requests on the
  secondary sockets**.
- The server detects a **substream write** by the pathid byte in the write header, and can
  refuse it without desync when it has no write data-path.

## Server (default ON) — what is and isn't built

| capability | state | code |
|---|---|---|
| Accept `kXR_bind`, assign pathid 1–253, record bound state | ✅ | `src/protocols/root/session/bind.c:33` |
| Refuse bind when `brix_data_substreams off` (`kXR_Unsupported`, no disconnect) | ✅ | `bind.c:48` |
| Serve **reads** on a bound secondary (cross-worker via SHM handle table) | ✅ | `handles.c` publish/lookup; `open_resolved_file.c:130` |
| Restrict bound streams to reading primary-published handles (no open/close/mutate) | ✅ | `dispatch_read.c` `DISPATCH_RD_BOUND`; `policy.c:107` |
| Serve **writes** on a bound secondary for **fd-backed exports** (whole `kXR_write` on the secondary, cross-worker via SHM handle table) | ✅ **built (Phase 94)** | `fd_table.c` `brix_ensure_write_handle`/`brix_reopen_bound_write_handle`; `policy.c` bound-write gate; `recv_process.c` bound reopen |
| Serve bound writes for a **gateway → remote `root://` origin** (resume/POSC-staged) | ✅ **works (Phase 94, Phase 2)** — the writable gateway stages to a **local export-rooted `.part`** (`fd ≥ 0`), which Phase-1 publishes + fans out; the resume/POSC commit flushes the whole `.part` (incl. cross-worker bound writes) to the origin at close | `open_resolved_file_staging.c` (`.part`); `handles.c` publish; `test_data_substreams_gateway.py` |
| Serve bound writes for a **whole-object PUT** backend (S3/WebDAV, `needs_staged`, fd<0 `writer`) | ⚠️ **falls back safely** — a sequential whole-object staged writer is never published, so a bound write is refused cleanly and the client re-writes on the primary (byte-exact); parallel throughput straight into it (B-i/B-ii) is deferred | `open_resolved_file_dispatch.c` `brix_open_write_needs_staged`; `handles.c` publish gate |
| Large inline write fallback (streaming engine — the sink a write substream would feed) | ✅ | `write_stream.c` |

**Default:** `shared_conf.h:352` `ngx_conf_merge_value(..., 1)` → **ON**. Directive at
`stream/module.c:216`; field `shared_conf_types.h:267`.

**Net:** the server fully supports **parallel reads** *and* **parallel writes** over sub-streams
for kernel-fd-backed exports. A bound `kXR_write` carries the whole request (header+payload,
pathid 0) on the secondary; the server reopens the writable handle in that connection's worker
(dev/inode-validated) and pwrites at the self-addressing offset. **This also covers a gateway to a
remote `root://` origin** (Phase 2): a writable gateway stages the upload to a **local,
export-rooted `.part`** (resume/POSC, a real `fd ≥ 0` under the export root), which is exactly the
fd-backed shape above — so bound writes fan out cross-worker into the `.part`, and the resume/POSC
commit flushes the *whole* `.part` (including bytes a secondary pwrote on another worker) to the
origin at close. The only path that still degrades to the resilient primary is a **whole-object
PUT backend** (S3/WebDAV, `brix_open_write_needs_staged` → a sequential `file->writer`, `fd < 0`,
never published); that fallback is byte-exact, and parallel throughput straight into such a store
is a deferred throughput-only optimisation, not a correctness gap.

## Client (`brix-xrdcp` / lib) — current state

| capability | state | code |
|---|---|---|
| Open N-1 secondaries and `kXR_bind` them to the session | ✅ | `client/lib/net/streams.c` `brix_streams_open` |
| `-S`/`--streams N` option | ✅ | `client/apps/copy/xrdcp_parse_transport.c:179` |
| Default stream count | ✅ **4 / ON** | `xrdcp.c` `opts.streams = 4` |
| Move **upload** data over the secondaries (round-robin write fan-out, safe fallback) | ✅ **built (Phase 94)** | `copy_pump.c` `pump_sink_remote`; `copy_upload.c` |
| Move **download** data over the secondaries (round-robin read fan-out, safe fallback) | ✅ **built (Phase 94)** | `copy_pump.c` `pump_src_secondary`/`pump_src_remote`; `copy_local.c` |
| **TRUE concurrent** striped download (`--parallel`: one thread per stream, disjoint `pwrite` ranges) | ✅ **built (Phase 94, opt-in)** | `copy_local.c` `copy_download_parallel`/`dl_stripe_worker` |

So the BriX client now fans **both** upload chunks *and* download reads round-robin across
primary + bound secondaries by default. Each secondary op is best-effort: a write a secondary
won't take falls back to the resilient primary write at the same offset (idempotent pwrite), and
a read a secondary won't serve falls back to the primary read at the same offset — so a server
that does not service bound writes/reads (old / gateway) never fails or corrupts the transfer.
`kXR_read` carries no pathid, so a read issued on a bound secondary is routed to that connection
by the server and served against the primary-published handle (the cross-worker SHM read path).
`BRIX_STREAMS_DEBUG=1` prints `upload substreams=<n> chunks-on-secondaries=<m>` and
`download substreams=<n> chunks-on-secondaries=<m>`. The default serial fan-out distributes
chunks across sockets one in-flight op at a time (it keeps the full single-link resilient
ride-out); compressed (`--compress`) and paged/`--pgrw` transfers stay single-stream.

**`--parallel` — true concurrent striped download.** For real multi-stream throughput (hiding
RTT on high-latency links) the client offers an opt-in concurrent path: `copy_download_parallel`
splits a known-size local-file download into one **contiguous disjoint stripe per bound
connection**, runs a thread per connection (`dl_stripe_worker`), and each thread `pwrite`s its
range into the destination. The single read handle is a POD `brix_file` shared **read-only**
across the threads (the read path never mutates it and takes its streamid from each connection's
own `brix_send`), each thread owns its connection + `brix_status`, and the ranges are disjoint —
so no lock is needed. Writes route through the VFS (`brix_vfs_pwrite`, INV-12) with **io_uring
forced OFF** so `posix_pwrite` is a plain thread-safe `pwrite(2)` at an explicit offset; the
atomic temp+rename+commit is reused from the serial path. It is **fail-closed** (any stripe
error drops the temp and fails the copy — no single-link ride-out), which is why it is opt-in and
the resilient serial fan-out remains the default. `BRIX_STREAMS_DEBUG=1` prints
`parallel-download stripes=<n>`. Eligibility: `--parallel`, a real local-file destination, a
plain (non-`--compress`, non-`--pgrw`) known-size object ≥ 2 × `XRDC_COPY_CHUNK`; anything else
falls back to the serial pump.

## Cross-client behaviour with sub-streams ON

- **go-hep**: now **one extra sub-stream by default** (`defaultSubStreams = 1`, was 8;
  `WithSubStreams(n)` / `XRD_SUBSTREAMSPERCHANNEL` override) — it opens binds and (for writes)
  sends a non-zero-pathID header on the primary; BriX's safe pathid guard refuses that cleanly and
  go falls back to inline, so large writes succeed via the streaming engine. Reads round-trip.
- **stock xrdcp / XrdCl**: `-S N` opens binds; correctness unaffected.
- **XrdRust** (`/root/dev/XrdRust`): now **multi-stream by default**
  (`Config::data_streams`, default 1). Reads carry a path id on the control link
  and are answered on whichever link replies (conformant — safe against stock and
  BriX alike); writes travel whole on the bound link with an idempotent
  same-offset fallback to the control link, so a server that will not take the
  bound write (stock's non-arrival model) stays byte-exact.
- **PyXRootDClient** (`/root/dev/PyXRootDClient`, the pure-Python client, *not*
  the C++ XrdCl binding): now **multi-stream by default** (`data_streams`, default
  1) using an **arrival** routing that sends the whole request down the bound
  socket — proven byte-exact against a live BriX fd-export for both a 40 MiB
  upload and download, fanned across the secondary. A server that does not serve
  the op on the arrival socket is found out within the short `data_stream_timeout`
  (2 s) and the file latches back to the control link, byte-exact. Set
  `XRD_SUBSTREAMSPERCHANNEL=1` to disable.
- **XRootD.jl** (`/root/dev/XRootD.jl`, the **native pure-Julia** client — as of 0.3 no longer
  the XrdCl C++/CxxWrap binding): now **multi-stream by default** (`data_streams`, default **1**).
  A `File` binds its extra `kXR_bind` data path(s) at **open**, and reads and writes then ride
  those secondaries **round-robin** (a read is *issued on* the bound socket — `kXR_read` carries no
  pathid — and a write travels over it). Verified **byte-exact against a live official XRootD
  origin** for both a bound-path upload and download (default `data_streams=1`), and against the
  BriX benchmark gateway (which runs `brix_data_substreams off`) the bind is **refused cleanly**
  (`kXR_error`/`kXR_Unsupported`, no disconnect) and the file falls back to the control link
  byte-exact — the full 17-op benchmark (incl. `write_small`/`write_large`/`vector_read`) is green
  on both endpoints. `XRDC_DATA_STREAMS` (extra links, this client's own knob) or
  `XRD_SUBSTREAMSPERCHANNEL` (XrdCl's, counts the control link) override; `XRDC_DATA_STREAMS=0`
  keeps everything on the control link. Note: whole-file writes open `kXR_open_updt` (read+write),
  as the reference clients' `"wb"` does — a pure `kXR_open_wrto` open trips a BriX gateway
  staged-commit fd bug (see below). Unlike the Python/Rust clients it has **no arrival-timeout
  latch-back**: it relies on the server (BriX with substreams ON, or a stock origin) to serve the
  op on the bound link, which holds for every server tested here.
- **brix-xrdcp**: default `streams=4`; uploads *and* downloads fan out across the secondaries
  (writes land on bound conns for fd-exports, degrade to primary otherwise; reads are served on
  bound conns and degrade to primary otherwise). The fan-out is **capability-gated**: BriX serves
  full request frames on bound paths, stock treats them as `pathid`-directed data channels and
  never answers one (a fanned write would hang forever), so after binding, `brix_streams_open`
  probes `kXR_Qconfig "brix.substreams"` and tears the secondaries down again unless the reply
  carries the `=rw` marker (BriX answers it; stock echoes the unknown key). Covered by
  `test_gsi_handshake.py::TestNativeAgainstStock::test_native_write_stock` (primary-only against
  stock) and `test_xrdcp_client_options.py::test_qconfig_advertises_substreams_capability`.

All six clients produce byte-correct transfers with the server default (ON); no client
regresses when sub-streams are enabled, because the server degrades writes to inline safely and
serves reads on whichever connection they arrive on.

## The `kXR_open_wrto` staged-commit gateway bug (open-side)

Independent of sub-streams: a whole-file write **opened write-only** (`kXR_open_wrto`, no read
bit) through a `brix_stage`-backed gateway to a `root://` origin fails at close with
`kXR_IOError "staged commit failed"` (3007) — the POSC commit fsyncs an already-closed handle fd
(EBADF). The **official origin accepts either open mode**, and every reference client opens a
whole-file `"wb"` write as `kXR_open_updt` (read+write, e.g. Python `wb` → `delete|update|makepath`,
XrdCl `CopyProcess`, brix-xrdcp), so none of them exercise the broken path. The native XRootD.jl
benchmark driver likewise opens `Delete | Update | MakePath`, and commits cleanly. The write-only
staged-commit fd lifecycle is a genuine BriX server-side bug on the `wrto` branch and is tracked
for a server-side fix; it is *not* a client conformance gap.

## XRootD.jl native client internals (as of v0.3, 2026-08-04)

The Julia library at `/root/dev/XRootD.jl` (github rob-c/XRootD.jl, `main`)
underwent a **complete rewrite**: as of v0.3 it is a **native pure-Julia** XRootD
wire client over `Sockets` — no more CxxWrap/XrdCl C++ binding, no `XRootD_jll`
runtime dependency. It is a Julia translation of the nginx-xrootd `libxrdc` C
client, so its semantics track BriX's own client. Layers: `Wire` (codecs) ·
`Session` (connections/TLS/auth/env) · `XrdCl` (`File`/`FileSystem` public API) ·
`Storage` · `Tools`. After pulling, run `Pkg.resolve()` + `Pkg.instantiate()`
(new deps: HTTP, OpenSSL, URIs…).

`data_streams` plumbing:

- `Session.data_streams()` in `src/Session/env.jl`: `XRDC_DATA_STREAMS` (native,
  counts EXTRA links, wins) → else `XRD_SUBSTREAMSPERCHANNEL` (XrdCl's, counts the
  control link, so N→N-1) → else `DEFAULT_DATA_STREAMS=1`. Clamps ≥0;
  unparseable→default. Exported from `XrdCl`.
- `File` struct (`src/Client/file.jl`): replaced single `pathid::UInt8` with
  `pathids::Vector{UInt8}` + `rr::Int`. `Base.open(...; data_streams=Session.data_streams())`
  auto-binds that many `kXR_bind` data paths after a successful open (gated on
  `f.owns_conn`, non-fatal on refuse). `data_pathid` round-robins over the live
  bound paths; reads/writes already route through it.
- Julia tests: `test/session/test_env.jl` (env logic),
  `test/conformance/test_datapath.jl` (open-default auto-bind / ds=0 / ds=3
  round-robin). Auto-bind-on-open changed suite defaults, so `conf_file` in
  `test/conformance/server.jl` now pins `data_streams=0` to keep the
  explicit-bind conformance tests unaffected.

### brixbench Julia driver

`/root/dev/brixbench/drivers/bench_julia/bench_julia.jl` was rewritten for the
native API; `vector_read` is now implemented via `readv` (previously
"unsupported"). **17/17 ops green against BOTH** the official origin (`:21095`)
and the BriX benchmark gateway (`:21094`, which runs `brix_data_substreams off`
so bind is refused cleanly → control-link fallback). Wired into `run_matrix.sh`
as the `julia` client. go-hep's default was also confirmed lowered 8→1 in
`/root/dev/hep/xrootd/env.go`.

### `kXR_open_wrto` root cause (server side)

The staged-commit failure is in `brix_close_posc_commit`
(`src/protocols/root/read/close.c`): it fsyncs an already-closed
`ctx->files[idx].fd` → **EBADF**. Reproduces with stock XrdCl too. Latent BriX
server bug on the `wrto` branch (not yet fixed server-side).

## Tests

- `tests/test_session_bind.py` — ON/default acceptance + bound-read correctness (7 classes:
  valid bind, handle-slot cache, pathid cycling, invalid sessid, no-handshake, pathid-tag read,
  multiple secondaries).
- `tests/test_bind_substreams.py` — OFF refusal + no-desync (needs a substreams-off server on
  `BRIX_SUBSTREAMS_OFF_PORT`, default 21096).
- `tests/test_xrdcp_client_options.py::test_xrdcp_streams_uses_secondary_bind_and_round_trips` —
  client `--streams 4` establishes binds (access-log delta) and round-trips byte-exact.
- `tests/test_conf_sessions_b.py` — stock-parity: bogus/zero sessid bind refused by both.
- `tests/test_data_substreams_parallel.py` — multi-substream parallel-read correctness
  (`TestDataSubstreamsParallel`), **bound-write** correctness (`TestDataSubstreamWrites`: single
  bound write, striped 4-way parallel write, concurrent threaded writes, security-neg bound-open
  refusal, bound-write to an unpublished handle refused), client **upload** fan-out
  (`TestClientUploadFanout::test_default_upload_fans_out_byte_exact`), and client **download**
  read fan-out (`TestClientDownloadFanout::test_default_download_fans_out_byte_exact` — a 40 MiB
  file spans several 8 MiB read chunks so the round-robin reaches the secondaries; asserts
  `chunks-on-secondaries>0` + byte-exact), and the **`--parallel`** concurrent striped download
  (`TestClientDownloadFanout::test_parallel_striped_download_byte_exact` — 40 MiB / 4 stripes,
  asserts `stripes>=2` + byte-exact), and **checksum parity**
  (`TestSubwrittenChecksumParity::test_subwritten_file_checksum_matches_single_stream` — the same
  bytes uploaded sub-written (`streams=4`, asserting `chunks-on-secondaries>0`) and single-stream
  (`-S 1`) hash to the **same server checksum**, equal to an independent `adler32` of the source;
  the server checksums by re-reading the finished file, so out-of-order disjoint substream pwrites
  cannot skew the digest). All client tests assert the `BRIX_STREAMS_DEBUG`
  diagnostic proves secondaries carried data (not a silent fallback). Needs a
  `worker_processes ≥ 2` fd-export server; point it via `TEST_NGINX_ANON_PORT` +
  `BRIX_SUBS_EXPORT_DIR`.
- `tests/test_data_substreams_gateway.py` — **Phase 2 gateway fan-out**
  (`TestGatewayBoundWriteFanout`): stands up a `root://` origin + a BriX
  `brix_storage_backend root://origin` gateway (with a `brix_stage` tier, `worker_processes 2`),
  runs a default `--streams 4` upload, and asserts `chunks-on-secondaries>0` (real cross-worker
  fan-out) AND byte-exact **on the origin's own storage** (the gateway flushed the fanned-out
  `.part` to the remote origin). Heavyweight two-nginx rig; skips cleanly when the nginx binary /
  module `.so`s / a writable base are absent. Override via `TEST_NGINX_BIN` / `BRIX_MODULE_SO` /
  `TEST_P2_ORIGIN_PORT` / `TEST_P2_GATEWAY_PORT`.
