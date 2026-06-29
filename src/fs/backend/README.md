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

## Layout — one subdirectory per driver

Each storage driver lives in its own subdirectory; the shared seam (`sd.h`), the
registry (`sd_registry.c`), the integrity tagstore (`csi_*`), and this README stay
at the top level:

```
fs/backend/
  sd.h  sd_registry.c  csi_*.{c,h}  README.md   ← shared seam + registry + integrity
  posix/   sd_posix.c                            ← default POSIX driver
  block/   sd_block.c                            ← raw block-device driver (block://)
  pblock/  sd_pblock.c  sd_pblock_catalog.{c,h}  + unittests   ← striped pseudo-block
  rados/   sd_ceph.{c,h}  sd_ceph_unittest.c     ← Ceph/RADOS driver
  s3/      sd_s3.{c,h}  sd_s3_transport.h        ← object/S3 driver + transport iface
  remote/  sd_remote.{c,h}                       ← read-only S3 remote-origin driver (cache)
  xroot/   sd_xroot.{c,h}                        ← read-only root:// remote-origin driver (cache)
```

A moved driver keeps its own header includes same-directory; it reaches the seam
via `../sd.h` and the rest of the tree via `../../…`. The registry references a
driver header by its subdir (`rados/sd_ceph.h`). The client/libxrdproto build
(`shared/xrdproto/Makefile`) and the standalone unit harnesses point at the subdir
paths.

## Files

| File | Responsibility |
|---|---|
| `sd.h` | The capability bitmap (`XROOTD_SD_CAP_*`), the opaque handle types (`xrootd_sd_driver_t`/`instance`/`obj`/`dir`/`staged`), the POD `xrootd_sd_stat_t`/`xrootd_sd_dirent_t`, the driver vtable, the capability-gated accessors (`xrootd_sd_caps`/`fd`/`supports`/`backend_name`), and the registry API. |
| `sd_posix.c` | The POSIX driver `xrootd_sd_posix_driver` — a behaviour-preserving wrapper: every vtable slot delegates to an existing confined helper (`xrootd_open_beneath`, `xrootd_vfs_pread_full`/`pwrite_full`, `xrootd_ns_*`, `xrootd_lstat_beneath`, `*xattr_confined_canon`, `xrootd_staged_*`). Advertises all capabilities. |
| `sd_block.c` | The block-device driver `xrootd_sd_block_driver` — raw fd I/O identical to POSIX (delegates the byte ops) plus a `BLKGETSIZE64`-aware `fstat`; opens the device in place (never create/truncate). |
| `sd_s3.c` / `sd_s3.h` | The object/S3 driver `xrootd_sd_s3_driver` — SigV4 signing, HEAD/Range-GET/single-PUT/multipart-PUT, XML parsing. Lives in `libxrdproto` (ngx-free) and is shared verbatim with the native clients; the actual HTTP is performed by an **injected transport vtable** (`sd_s3_transport.h`) so the same driver runs over the server's and the client's HTTP stacks. No fd ⇒ memory-backed reads. **Object metadata:** `sd_s3_get_meta` (signed HEAD → `x-amz-meta-<name>`), `sd_s3_set_meta` (copy-onto-self with `x-amz-metadata-directive: REPLACE`, signed via `sd_s3_sign_ext` so the extra `x-amz-*` headers are in the SigV4 SignedHeaders), and advisory `sd_s3_get/set_unixattr` (POSIX mode/uid/gid/mtime in `x-amz-meta-xrd-unixattr`, `meta_advisory.c`). Validated against the S3 server's user-metadata persistence (`src/s3/usermeta.c`): `tests/run_sd_s3_meta.sh`. Full design + the transport-vtable trick: [`vfs-shared-architecture.md`](../../../docs/09-developer-guide/vfs-shared-architecture.md) §5; the metadata matrix: [`storage-backend-drivers-deep-dive.md`](../../../docs/09-developer-guide/storage-backend-drivers-deep-dive.md) §1.1/§3.3. |
| `sd_s3_transport.h` | The HTTP transport interface the S3 driver calls (`request`/`upload`/…); the module and the client each supply their own implementation, keeping `sd_s3.c` transport-agnostic. |
| `xroot/sd_xroot.c` / `.h` | The **remote root:// driver** `xrootd_sd_xroot` (`CAP_RANGE_READ \| RANDOM_WRITE \| TRUNCATE`). The root:// sibling of `sd_remote`: it wraps the in-process XRootD origin wire client (`../../cache/origin_*.c`, which needs only a server conf + a logical path) behind the SD vtable — the per-open object holds a live origin connection + open file handle; `pread` issues a `kXR_read` range into a memory sink. **Write data path** (Phase 1 of the writable-remote-backend work): `pwrite`/`ftruncate`/`fsync` over `kXR_write`/`_truncate`/`_sync`; `open` with write intent uses `kXR_open`(update+delete+mkpath). `xrootd_sd_xroot_query_checksum()` exposes `kXR_Qcksum` for commit-then-verify. **Two roles:** (a) cache read-fill (built via `xrootd_sd_xroot_create(conf)`, `cache/fetch.c` driver→driver); (b) **registry-selectable PRIMARY backend** (`xrootd_storage_backend root://host:port`) → the export's storage is the remote server, read + transparent write-through (`tests/run_remote_backend_write.sh`). Making a no-fd backend a root:// *primary* required relaxing the kXR handle path's `fd<0` gates additively (gated on `sd_obj.driver`; see `src/connection/fd_table.c`, `src/fs/vfs_io_core.c`). **Auth: anonymous login** only; authenticated origins use the staging/native-client path (later phase). Namespace (mkdir/rename), xattr/setattr forwarding, the generic staged-write seam, and an optional local staging directory are later phases (spec: `docs/superpowers/specs/2026-06-29-writable-remote-root-staged-write-design.md`). E2E: `tests/run_cache_xroot_origin.sh` (read), `tests/run_remote_backend_write.sh` (write-through). |
| `remote/sd_remote.c` / `.h` | The **read-only remote-origin driver** `xrootd_sd_remote` (`CAP_RANGE_READ` only; every write/dir/xattr/staged slot NULL, so it can never be a writable export primary). Built by the read-through cache to front a remote object store: `s3://` delegates entirely to the shared `sd_s3` read path — the per-open SD object wraps an `sd_s3_file*`, `pread` is a signed Range GET, `stat`/`fstat` report the HEAD size. The HTTP transport is **injected by the cache** (server libcurl, `../../cache/origin/s3_transport.c`), keeping the backend layer free of any cache/libcurl dependency. Instances + objects are malloc-owned (no nginx pool), so they are built and used on the blocking cache-fill worker thread. Constructed via `xrootd_sd_remote_create()`; not registry-selectable (it is never an export backend). E2E: `tests/run_cache_s3_origin.sh`. |
| `sd_ceph.c` | The Ceph/RADOS driver `xrootd_sd_ceph_driver` (phase-60, **basic librados backend**) — maps a confined logical path to a flat RADOS object id and serves the data plane via raw `librados` (`rados_read`/`write`/`trunc`/`stat`/`remove`). Caps: range-read, random-write, truncate (no fd ⇒ no sendfile, served memory-backed; no real dirs; no atomic rename). Compiled only when `./configure` finds librados (`XROOTD_HAVE_CEPH`); otherwise the file contributes only its pure, libc-only LFN→object-key helpers (`sd_ceph_normalize`/`_key`/`_ino`, in `sd_ceph.h`) and the registry row is `#if`-compiled out, so a no-Ceph build is byte-for-byte unchanged. libradosstriper interop with stock XrdCeph (ADR-3), directory listing, rename, xattr and staged commit are deliberate follow-ons. |
| `sd_ceph_unittest.c` | Standalone (no librados, no cluster) suite for the security-critical LFN→object-key map: canonicalization, injectivity, `..`-escape rejection, key composition, inode hash. Driven by `tests/test_sd_ceph.py`. |
| `sd_pblock.c` | The pblock ("pseudo-block") driver `xrootd_sd_pblock_driver` — a **full-capability, block-based drop-in for POSIX**. Each object's bytes are **striped across fixed-size block files** (`data/<aa>/<bb>/<blob_id>/<index>`); the stripe size defaults to **64 MiB**, is configurable per export (`xrootd_sd_pblock_conf_t.block_size`), and is recorded **per file at creation** so retuning it only affects newer files. Block 0 is opened persistently as a real kernel fd (⇒ `CAP_FD`/`SENDFILE`/`IOURING` and zero-copy sendfile for offset-0 ranges within the first block); higher blocks are opened transiently per I/O. Reads/writes map `[off,off+len)` across blocks (holes read as zeros); `ftruncate` drops whole blocks past the new size and trims the boundary; `unlink` removes the block files + per-object dir. The entire logical namespace + metadata (stat, xattrs, path→blob map, per-file `block_size`) lives in a SQLite catalog (`sd_pblock_catalog.c`); the hot byte path never touches SQLite — only metadata boundaries (`open`, the `fsync` durability barrier which syncs every block, `close`, namespace ops) do. Advertises the **same caps as POSIX** and implements every slot. Fully `ngx`-free (libc + sqlite, `malloc`-owned state), identical in the module and the standalone test. Compiled only when `./configure` finds libsqlite3 (`XROOTD_HAVE_SQLITE`); otherwise the file is empty and the registry row is `#if`-compiled out, so a no-sqlite build is byte-for-byte unchanged. Live-traffic *selection* + the VFS `obj->driver` data-plane routing are the named Phase-2 follow-on. |
| `sd_pblock_catalog.c` / `.h` | The pblock SQLite metadata catalog — pure libc + sqlite3 (no nginx), so it is independently testable and carries none of the data-plane cost. Typed CRUD over the `objects` (namespace/stat/blob-map) and `xattrs` tables; subtree-aware rename; WAL + busy-timeout + `FULLMUTEX` so one per-export handle is safe across a worker's thread pool and separate worker processes contend cleanly. |
| `sd_pblock_catalog_unittest.c` / `sd_pblock_unittest.c` | Standalone (no nginx, no server) suites: the catalog API, and the full driver vtable driven through its function pointers — every slot plus **multi-thread + multi-process + async-interleave + fsync-durability** concurrency. Run via `tests/c/run_pblock_tests.sh`. |
| `sd_registry.c` | The driver table + name→driver lookup, per-export `xrootd_sd_instance_create`/`destroy`, and the accessor helper bodies. |
| `csi_tagstore.c` / `.h` | The **CSI page-checksum tagstore** (phase-59, `XrdOssCsi` parity): per-4096-byte-page CRC32C stored in a versioned `.xrdt`-style sidecar. Lives in `backend/` because all tag-file I/O must stay **below the seam** (the data-POSIX-confinement invariant) — the tag file is read/written through the backend, never by a protocol handler. Open/create the tagstore for a data fd, read-verify, write-update, RMW+verify-before-write on partial pages, hole/`nofill`/`nomissing` options. |
| `csi_verify.c` | The CSI verify/update logic over `csi_tagstore`: read-side page-CRC verification on `kXR_read`/GET, write-side tag update on `kXR_write`/`pgwrite` (pgWrite stores the client CRC directly — no recompute), and the partial-page read-modify-write path. |
| `csi_unittest.c` | Standalone suite for the CSI tagstore + verify logic (tag-header layout, per-page CRC round-trip, partial-page RMW, hole handling), run outside the module build. |

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

Create a subdirectory `<name>/` and add `<name>/sd_<name>.c` defining a
`const xrootd_sd_driver_t` (include the seam as `../sd.h`). Append the driver's
`extern` to `sd.h`, add a row to the `sd_drivers[]` table in `sd_registry.c`
(referencing any driver header by its subdir, e.g. `#include "<name>/sd_<name>.h"`),
register the `.c` at its subdir path in the top-level `config` (`NGX_ADDON_SRCS`),
and re-run `./configure`. Set only the capabilities the backend genuinely has —
the VFS degrades or rejects on the absent ones.

## See also

**Storage backend drivers deep-dive (the SD seam, `pblock`/`s3`/remote-`root://`,
the cache "fold", the origin auth matrix, and every lesson learned — ASCII
diagrams throughout):**
[`docs/09-developer-guide/storage-backend-drivers-deep-dive.md`](../../../docs/09-developer-guide/storage-backend-drivers-deep-dive.md).

**`pblock` deep-dive (block-striping, the SQLite catalog, the VFS↔backend wiring,
server-vs-client sharing — with ASCII diagrams throughout):**
[`docs/09-developer-guide/pblock-storage-backend.md`](../../../docs/09-developer-guide/pblock-storage-backend.md).

Hyper-detailed cross-tree reference — the object model, the full capability
matrix, the vtable grouped by caller, the S3 transport-vtable injection, every
data flow, and the dual-build (`ngx`-free) mechanism that compiles these drivers
into both the nginx module and the client's `libxrdproto`:
[`docs/09-developer-guide/vfs-shared-architecture.md`](../../../docs/09-developer-guide/vfs-shared-architecture.md).
