# `client/lib/` — native XRootD client library (`libxrdc`)

Pure-C, libXrdCl-free implementation of the `root://` (+ HTTP/S3/WebDAV) client
that the `client/apps/` CLIs and the FUSE driver link against. The internal API
spine is `xrdc.h`.

## Phase-38 split groups (file-size discipline)

The following large translation units were split into single-responsibility
siblings sharing a private `*_internal.h` (behavior-identical refactor — see
[docs/refactor/phase-38-file-size-unix-modularity.md](../../docs/refactor/phase-38-file-size-unix-modularity.md)).
All siblings are listed in `LIB_SRCS` in `client/Makefile` and link into the one
static lib, so cross-file references resolve at link time.

| File | Responsibility |
|---|---|
| `aio.c` | The epoll/io_uring event loop (`loop_*`, `rc_worker_main`) + the public `xrdc_loop_*`/`xrdc_aio_*`/`xrdc_aconn_*` API. *(Phase 38: split.)* |
| `aio_buffers.c` | Growable byte buffer (`xbuf_*`), the streamid→request open-addressing map (`reqmap_*`), and request lifecycle (`areq_*`). |
| `aio_io.c` | Non-blocking socket read/write + frame parser + RTT/RTO (`aconn_do_read`/`_write`, `aconn_parse`, `aconn_dispatch_frame`). |
| `aio_engine.c` | The pollset abstraction over epoll + io_uring poll (`io_engine_*`, `uring_*`). |
| `aio_conn.c` | Per-connection lifecycle: reconnect, keepalive/ping, teardown, deadlines, command submission. |
| `aio_internal.h` | Private split contract shared by `aio*.c` (the `aconn`/`areq`/loop structs + prototypes). |
| `http.c` | The minimal cleartext `xrdc_http_get` + connect/parse/dechunk helpers. *(Phase 38: split.)* |
| `http_req.c` | The generic request/response codec (`xrdc_http_req`, `httpx_exchange`). |
| `http_download.c` | The range/streaming download engine (`xrdc_http_download`, chunked/clen/eof framing). |
| `http_upload.c` | The resumable upload engine (`xrdc_http_upload{,_resumable}`, chunk + offset handling). |
| `http_internal.h` | Private split contract shared by `http*.c`. |
| `ops_file.c` | File open family (`xrdc_file_open_{read,write,update,opaque}`) + close + sync. *(Phase 38: split.)* |
| `ops_file_rw.c` | read/write/readv/writev + the gzip inflate/deflate frame helpers. |
| `ops_file_pg.c` | `kXR_pgread`/`kXR_pgwrite` with per-page CRC32c + `kXR_status` framing (Invariant 1). |
| `ops_internal.h` | Private split contract shared by `ops_file*.c`. |
| `zip.c` | ZIP central-directory reader + member extraction (`xrdc_zip_open/find/member_extract`). *(Phase 38: split.)* |
| `zip_write.c` | ZIP writer (`xrdc_zip_writer_*`, central-dir append). |
| `zip_internal.h` | Private split contract shared by `zip.c`/`zip_write.c`. |
| `copy.c` | The `xrdc_copy` entry + direction inference + single-file r2l/l2r; **keeps the `__attribute__((used))` VFS-backend link anchors** (`s_vfs_*_anchor`) in `copy.o`. *(Phase 38: split.)* |
| `copy_pump.c` | The chunked transfer pump (`transfer_pump` + `pump_*` + `write_all`). |
| `copy_local.c` | Download/upload to local + temp-file/atomic-dest helpers. |
| `copy_remote.c` | Remote→remote + native TPC (`copy_tpc`, key gen) + checksum verify. |
| `copy_recursive.c` | Recursive tree download/upload + web-auth headers. |
| `copy_internal.h` | Private split contract shared by `copy*.c` (anchors deliberately excluded). |

The **CLI apps** in `client/apps/` are split the same way, each with a per-binary
link rule in `client/Makefile` that links the extracted `apps/*.o` siblings:
`xrdcp` (→ `xrdcp_transfer`/`xrdcp_recursive`), `xrd` (→ `xrd_battery`/`xrd_doctor`/
`xrd_clockskew`/`xrd_mount`), `xrdfs` (→ `xrdfs_data`/`xrdfs_walk`/`xrdfs_fmt`),
`xrddiag` (→ `diag_check`/`diag_bench`/`diag_watch`/`diag_topology`/`diag_compare`).

> Not yet split (Phase-38 remaining): `client/apps/xrootdfs.c` (FUSE — custom
> compile/link rules + a thorny preamble), `client/lib/webfile.c` (watch tier), and
> `client/lib/xrdc.h` (mixed-ABI header). The rest of `client/lib/` (connection/auth/
> VFS/checksum layers) is not yet catalogued here.
