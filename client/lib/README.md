# `client/lib/` — native XRootD client library (`libbrix`)

Pure-C, libXrdCl-free implementation of the `root://` (+ HTTP/S3/WebDAV) client
that the `client/apps/` CLIs and the FUSE driver link against. The internal API
spine is `brix.h` (kept at the `lib/` root — it is the public umbrella, included
almost everywhere, alongside `brix_ops.h` / `brix_net.h` / `brix_auth.h`).

## Concept buckets (phase-69)

`client/lib/` mirrors the server `src/` concept-bucket layout — every file lives in
a single-purpose bucket, includes are root-relative from `lib/` (e.g.
`#include "fs/vfs.h"`, resolved by `-Ilib`), and same-bucket includes stay bare.
The exhaustive old→new move map is
[docs/refactor/phase-69-client-map.tsv](../../docs/refactor/phase-69-client-map.tsv).

| Bucket | Concern |
|---|---|
| `core/aio/` | epoll/io_uring event loop, buffers, per-connection lifecycle (`aio*`, `uring`) |
| `core/config/`, `core/types/` | rc-file parsing (`xrdrc`); status/kXR names + unit formatting |
| `net/` | connection/socket/stream/pool/TLS transport, URL parse, timeouts, resilience |
| `auth/` | auth driver + request signing; `cred/` credentials, `sec/` security protocols, `gsi/` X.509 proxy, `sss/` keytab |
| `fs/` | client VFS (`vfs*`, `iobuf`, `path`, `glob`, `fattr`); `overlay` writable-union core for `brixMount cvmfs-rw` (classify/copy-up/whiteouts/CLI); `backend/s3/` S3 VFS backend |
| `protocols/` | `root/` root:// ops + framing, `http/` HTTP client + webfile, `s3/` SigV4, `shared/` zip + checksums |
| `xfer/` | the `brix_copy` transfer engine (pump/local/remote/recursive/zip/block) |
| `posix/` | FUSE meta-op runner + POSIX stat translation |
| `cli/` | shared CLI helpers linked by `client/apps/` |
| `observability/` | trace/capture; `metabench/` benchmarking |

## File responsibilities (Phase-38 split groups)

These large translation units were split into single-responsibility siblings
sharing a private `*_internal.h` (behavior-identical refactor — see
[docs/refactor/phase-38-file-size-unix-modularity.md](../../docs/refactor/phase-38-file-size-unix-modularity.md)).
All siblings are listed in `LIB_SRCS` in `client/Makefile` and link into the one
static lib, so cross-file references resolve at link time. Filenames below are
basenames; their bucket paths are in the phase-69 map linked above.

| File | Responsibility |
|---|---|
| `aio.c` | The epoll/io_uring event loop (`loop_*`, `rc_worker_main`) + the public `brix_loop_*`/`brix_aio_*`/`brix_aconn_*` API. *(Phase 38: split.)* |
| `aio_buffers.c` | Growable byte buffer (`xbuf_*`), the streamid→request open-addressing map (`reqmap_*`), and request lifecycle (`areq_*`). |
| `aio_io.c` | Non-blocking socket read/write + frame parser + RTT/RTO (`aconn_do_read`/`_write`, `aconn_parse`, `aconn_dispatch_frame`) incl. the deferred-reply flow (`kXR_waitresp` parks the request; the unsolicited `kXR_attn(asynresp)` is unwrapped and dispatched by its inner streamid — see `tests/test_aio_waitresp.py`). |
| `aio_engine.c` | The pollset abstraction over epoll + io_uring poll (`io_engine_*`, `uring_*`). |
| `aio_conn.c` | Per-connection lifecycle: reconnect, keepalive/ping, teardown, deadlines, command submission. |
| `aio_internal.h` | Private split contract shared by `aio*.c` (the `aconn`/`areq`/loop structs + prototypes). |
| `http.c` | The minimal cleartext `brix_http_get` + connect/parse/dechunk helpers. *(Phase 38: split.)* |
| `http_req.c` | The generic request/response codec (`brix_http_req`, `httpx_exchange`). |
| `http_download.c` | The range/streaming download engine (`brix_http_download`, chunked/clen/eof framing). |
| `http_upload.c` | The resumable upload engine (`brix_http_upload{,_resumable}`, chunk + offset handling). |
| `http_internal.h` | Private split contract shared by `http*.c`. |
| `ops_file.c` | File open family (`brix_file_open_{read,write,update,opaque}`) + close + sync. *(Phase 38: split.)* |
| `ops_file_rw.c` | read/write/readv/writev + the gzip inflate/deflate frame helpers. |
| `ops_file_pg.c` | `kXR_pgread`/`kXR_pgwrite` with per-page CRC32c + `kXR_status` framing (Invariant 1). |
| `ops_internal.h` | Private split contract shared by `ops_file*.c`. |
| `zip.c` | ZIP central-directory reader + member extraction (`brix_zip_open/find/member_extract`). *(Phase 38: split.)* |
| `zip_write.c` | ZIP writer (`brix_zip_writer_*`, central-dir append). |
| `zip_internal.h` | Private split contract shared by `zip.c`/`zip_write.c`. |
| `copy.c` | The `brix_copy` entry + direction inference + single-file r2l/l2r; **keeps the `__attribute__((used))` VFS-backend link anchors** (`s_vfs_*_anchor`) in `copy.o`. *(Phase 38: split.)* |
| `copy_pump.c` | The chunked transfer pump (`transfer_pump` + `pump_*` + `write_all`). |
| `copy_local.c` | Download/upload to local + temp-file/atomic-dest helpers. |
| `copy_remote.c` | Remote→remote + native TPC (`copy_tpc`, key gen) + checksum verify. `copy_tpc` speaks the STOCK XrdOucTPC dialect (`tpc.src=host:port` + `tpc.lfn` + `tpc.stage=copy` + `oss.asize`/`tpc.dlgon`/..., dest-open→sync→src-open→sync), which stock XRootD and nginx-xrootd destinations both accept — see `tests/test_root_tpc.py::TestNativeClientRootTPC`. |
| `copy_recursive.c` | Recursive tree download/upload + web-auth headers. |
| `copy_internal.h` | Private split contract shared by `copy*.c` (anchors deliberately excluded). |

The **CLI apps** in `client/apps/` are grouped into tool families (`copy/ fs/
cksum/ auth/ diag/ scan/ prep/`). Each binary's translation units — including its
Phase-38 split siblings — are listed in a `<name>_OBJS` variable in
`client/Makefile`, which a single `.SECONDEXPANSION` link rule resolves: e.g.
`xrdcp` (→ `xrdcp_transfer`/`xrdcp_recursive`), `xrd` (→ `xrd_battery`/`xrd_doctor`/
`xrd_clockskew`/`xrd_mount`), `xrdfs` (→ `xrdfs_data`/`xrdfs_walk`/`xrdfs_fmt`),
`xrddiag` (→ `diag_check`/`diag_bench`/`diag_watch`/`diag_topology`/`diag_compare`).
The FUSE `xrootdfs` keeps bespoke compile/link rules (libfuse3 flags + its
async/legacy driver co-link) under `apps/fs/`.
