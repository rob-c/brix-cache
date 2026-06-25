# fs/backend — Storage Driver (SD) layer

The **Storage Driver** layer sits directly **below the VFS** (`src/fs/`). The VFS
owns policy — confinement re-check, metrics, access log, cache, page-CRC, buffer
shaping — and calls a driver for the raw "move these bytes / mutate this name"
primitives. POSIX is the default driver; block and object/S3 drivers register the
same way so an object store can become a first-class (ultimately primary) backend
without any protocol handler, metric, cache, or access-log code changing above the
seam.

Full design: [`../../../docs/refactor/phase-55-storage-backend-abstraction.md`](../../../docs/refactor/phase-55-storage-backend-abstraction.md).

## Status — POSIX driver mediates the VFS handle data plane + lifecycle

This directory ships the **interface + the POSIX driver + the registry**, and the
VFS now dispatches its handle operations through the driver rather than issuing
POSIX syscalls itself. What goes through a driver slot:

- **Raw byte/copy I/O** — `xrootd_vfs_pread_full`, `xrootd_vfs_pwrite_full`, the
  VFS I/O-core `write_counted` arm, the `kXR_readv`/`kXR_pgread` vectored readers,
  the `kXR_read` warm-cache `preadv2` probe, the HTTP/S3/WebDAV body spooling
  (`compat/http_body.c`, `http_compress.c`, `s3/aws_chunked.c`, `s3/post_object.c`,
  `webdav/tpc_curl.c`), the checksum readers (`compat/checksum_core.c`), the
  write-through cache flush (`cache/writethrough_flush.c`), the server-side copy
  (`compat/copy_range.c`, backing `kXR_clone` + WebDAV COPY), and the FRM queue
  files (`frm/reqfile.c`) all call `pread`/`pwrite`/`preadv`/`preadv2`/`copy_range`.
- **Lifecycle** — the handle (`xrootd_vfs_file_t`) carries an `xrootd_sd_obj_t`
  (fd + driver + instance); `close` → `driver->close`, open-time and live stat →
  `driver->fstat`.
- **Open (hot path)** — a confined open with a persistent rootfd routes through
  `driver->open` via a *borrowed-rootfd* POSIX instance (`xrootd_sd_posix_borrow_instance`);
  the driver performs the `RESOLVE_BENEATH` open.
- **Sendfile decision** — `vfs_read.c` asks `driver->read_sendfile_fd(off, len,
  want_zerocopy)`; the backend returns a sendfile-able fd or NGX_INVALID_FILE.

The driver slots are **single verbatim syscalls**; the VFS keeps all the
EINTR/short-I/O/coalescing/loop policy and builds the nginx buffers, so behaviour
is byte-identical to the pre-seam code on the POSIX backend.

Still **outside** the driver by design:
- `sendfile(2)` itself — issued by nginx's own output filter when the VFS emits a
  file-backed buffer; the VFS only supplies the (driver-blessed) fd.
- The **legacy open fallbacks** — `root_canon`-per-call (`xrootd_open_confined_canon`)
  and the raw `open()` for server-constructed paths with no export root. These do
  not fit the persistent-instance model (a per-call rootfd would leak under a
  long-lived instance) and remain VFS confinement policy.
- **Namespace mutation + path-stat** (mkdir/rename/unlink/lstat/xattr) — the metered
  VFS + `xrootd_ns_*` tier; driver slots exist but these entry points carry
  impersonation / `nofollow` / `parents` / `overwrite` semantics the minimal vtable
  does not yet express. Migrating them belongs with the object backend (55.E), where
  a real second backend justifies extending the namespace contract.
- Plain socket / log / temp-fd I/O — not file-data movement.

## Files

| File | Responsibility |
|---|---|
| `sd.h` | The capability bitmap (`XROOTD_SD_CAP_*`), the opaque handle types (`xrootd_sd_driver_t`/`instance`/`obj`/`dir`/`staged`), the POD `xrootd_sd_stat_t`/`xrootd_sd_dirent_t`, the driver vtable, the capability-gated accessors (`xrootd_sd_caps`/`fd`/`supports`/`backend_name`), and the registry API. |
| `sd_posix.c` | The POSIX driver `xrootd_sd_posix_driver` — a behaviour-preserving wrapper: every vtable slot delegates to an existing confined helper (`xrootd_open_beneath`, `xrootd_vfs_pread_full`/`pwrite_full`, `xrootd_ns_*`, `xrootd_lstat_beneath`, `*xattr_confined_canon`, `xrootd_staged_*`). Advertises all capabilities. |
| `sd_registry.c` | The driver table + name→driver lookup, per-export `xrootd_sd_instance_create`/`destroy`, and the accessor helper bodies. |

## Contract

- **Worker-safe raw ops.** `pread`/`pwrite`/`ftruncate`/`fsync`/`fstat` (and
  `staged_write`) must not touch an nginx pool, emit metrics/logs, or read cache
  state — they run on AIO worker threads. The POSIX bodies are exactly today's
  VFS raw-I/O primitives.
- **Confinement is the driver's job.** Instance-keyed ops take an already-confined
  *logical* path; the POSIX driver enforces physical confinement via the kernel
  `RESOLVE_BENEATH` API. An `EXDEV` still means an escape attempt.
- **Errno facts, not wire codes.** Drivers return `errno`-style facts; the VFS /
  protocol layers map them to `kXR_*` / HTTP / S3 status.

## Adding a driver

Add `sd_<name>.c` defining a `const xrootd_sd_driver_t`, append its `extern` to
`sd.h` and a row to the `sd_drivers[]` table in `sd_registry.c`, register the
`.c` in the top-level `config` (`NGX_ADDON_SRCS`), and re-run `./configure`. Set
only the capabilities the backend genuinely has — the VFS degrades or rejects on
the absent ones.
