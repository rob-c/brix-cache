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

- **Raw byte/copy I/O** — `brix_vfs_pread_full`, `brix_vfs_pwrite_full`, the
  VFS I/O-core `write_counted` arm, the `kXR_readv`/`kXR_pgread` vectored readers,
  the `kXR_read` warm-cache `preadv2` probe, the HTTP/S3/WebDAV body spooling
  (`src/core/http/http_body.c`, `src/core/http/http_compress.c`, `src/protocols/s3/aws_chunked.c`, `src/protocols/s3/post_object.c`,
  `src/protocols/webdav/tpc_curl.c`), the checksum readers (`src/core/compat/checksum_core.c`), the
  write-stage flush (`stage/sd_stage_wb.c`), and the server-side copy
  (`src/core/compat/copy_range.c`, backing `kXR_clone` + WebDAV COPY) all call
  `pread`/`pwrite`/`preadv`/`preadv2`/`copy_range`.
- **Lifecycle** — the handle (`brix_vfs_file_t`) carries an `brix_sd_obj_t`
  (fd + driver + instance); `close` → `driver->close`, open-time and live stat →
  `driver->fstat`.
- **Open (hot path)** — a confined open with a persistent rootfd routes through
  `driver->open` via a *borrowed-rootfd* POSIX instance (`brix_sd_posix_borrow_instance`);
  the driver performs the `RESOLVE_BENEATH` open.
- **Sendfile decision** — `src/fs/vfs/vfs_read.c` asks `driver->read_sendfile_fd(off, len,
  want_zerocopy)`; the backend returns a sendfile-able fd or NGX_INVALID_FILE.

The driver slots are **single verbatim syscalls**; the VFS keeps all the
EINTR/short-I/O/coalescing/loop policy and builds the nginx buffers, so behaviour
is byte-identical to the pre-seam code on the POSIX backend.

Still **outside** the driver by design:
- `sendfile(2)` itself — issued by nginx's own output filter when the VFS emits a
  file-backed buffer; the VFS only supplies the (driver-blessed) fd.
- The **legacy open fallbacks** — `root_canon`-per-call (`brix_open_confined_canon`)
  and the raw `open()` for server-constructed paths with no export root. These do
  not fit the persistent-instance model (a per-call rootfd would leak under a
  long-lived instance) and remain VFS confinement policy.
- **Namespace mutation + path-stat** (mkdir/rename/unlink/lstat/xattr) — the metered
  VFS + `brix_ns_*` tier; driver slots exist but these entry points carry
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
  rados/   sd_ceph*.{c,h}  sd_cephfs_ro*.c  cephfs_{denc,layout}.{c,h}   ← Ceph/RADOS + read-only CephFS drivers
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
| `sd.h` | The capability bitmap (`BRIX_SD_CAP_*` — incl. phase-71 `DIRS_WRITE`/`XATTR_WRITE`/`MEMFILE` that split the implicit read-only/writable & memory-serve assumptions out of the VFS), the delegation-kind mask (`brix_sd_cred_kind_t` + driver `cred_accept`), the opaque handle types (`brix_sd_driver_t`/`instance`/`obj`/`dir`/`staged`), the POD `brix_sd_stat_t`/`brix_sd_dirent_t`, the driver vtable, the capability-gated accessors (`brix_sd_caps`/`fd`/`supports`/`backend_name`/`cred_accept`), and the registry API. The VFS branches ONLY on these (guard `tools/ci/check_vfs_identity_branch.py`), never on backend identity — see [docs/refactor/phase-71-vfs-capability-uniformity.md](../../../docs/refactor/phase-71-vfs-capability-uniformity.md). |
| `posix/sd_posix.c` | The POSIX driver `brix_sd_posix_driver` — a behaviour-preserving wrapper: every vtable slot delegates to an existing confined helper (`brix_open_beneath`, `brix_vfs_pread_full`/`pwrite_full`, `brix_ns_*`, `brix_lstat_beneath`, `*xattr_confined_canon`, `brix_staged_*`). Advertises all capabilities. |
| `block/sd_block.c` | The block-device driver `brix_sd_block_driver` — raw fd I/O identical to POSIX (delegates the byte ops) plus a `BLKGETSIZE64`-aware `fstat`; opens the device in place (never create/truncate). **Two planes from one implementation:** the ngx-free **client** plane (`block://` copy endpoints, `brix_sd_block_open_unconfined`) opens the device at absolute offsets; the **server** plane (`#ifndef XRDPROTO_NO_NGX`, selected by `brix_storage_backend block:<device>`) divides the device capacity into equal `extent_size` extents and exports them as a flat, read-only-namespace of logical objects `/0`..`/N-1` (`extent_size` 0 ⇒ the whole device is one extent `/0`). Each server object carries an extent window (`base`/`len`) that the shared `pread`/`preadv`/`pwrite` clamp + base-shift before delegating to the POSIX raw ops — a read past the tail is EOF, a boundary-crossing write is refused `ENOSPC`, and the namespace exposes only the extent indices (root `/` lists them; any non-numeric or out-of-range name is `ENOENT`) so a device export can never be walked into a host path. `read_sendfile_fd` is NULL so the extent base is always honoured. |
| `s3/sd_s3.c` / `s3/sd_s3.h` | The shared object/S3 driver kernel (`sd_s3_*`, consumed by the `remote`/`http` census drivers) — SigV4 signing, HEAD/Range-GET/single-PUT/multipart-PUT, XML parsing. Lives in `libxrdproto` (ngx-free) and is shared verbatim with the native clients; the actual HTTP is performed by an **injected transport vtable** (`s3/sd_s3_transport.h`) so the same driver runs over the server's and the client's HTTP stacks. No fd ⇒ memory-backed reads. **Object metadata:** `sd_s3_get_meta` (signed HEAD → `x-amz-meta-<name>`), `sd_s3_set_meta` (copy-onto-self with `x-amz-metadata-directive: REPLACE`, signed via `sd_s3_sign_ext` so the extra `x-amz-*` headers are in the SigV4 SignedHeaders), and advisory `sd_s3_get/set_unixattr` (POSIX mode/uid/gid/mtime in `x-amz-meta-xrd-unixattr`, `meta_advisory.c`). Validated against the S3 server's user-metadata persistence (`src/protocols/s3/usermeta.c`): `tests/c/sd_s3_meta_smoke.c` + `tests/test_cmd_s3_usermeta.py`. Full design + the transport-vtable trick: [`vfs-shared-architecture.md`](../../../docs/09-developer-guide/vfs-shared-architecture.md) §5; the metadata matrix: [`storage-backend-drivers-deep-dive.md`](../../../docs/09-developer-guide/storage-backend-drivers-deep-dive.md) §1.1/§3.3. |
| `s3/sd_s3_transport.h` | The HTTP transport interface the S3 driver calls (`request`/`upload`/…); the module and the client each supply their own implementation, keeping `s3/sd_s3.c` transport-agnostic. |
| `xroot/sd_xroot.c` / `.h` | The **remote root:// driver** `brix_sd_xroot_driver` (`CAP_RANGE_READ \| RANDOM_WRITE \| TRUNCATE`). The root:// sibling of `sd_remote`: it wraps the in-process XRootD origin wire client (`../../cache/origin_*.c`, which needs only a server conf + a logical path) behind the SD vtable — the per-open object holds a live origin connection + open file handle; `pread` issues a `kXR_read` range into a memory sink. **Write data path** (Phase 1 of the writable-remote-backend work): `pwrite`/`ftruncate`/`fsync` over `kXR_write`/`_truncate`/`_sync`; `open` with write intent uses `kXR_open`(update+delete+mkpath). `brix_sd_xroot_query_checksum()` exposes `kXR_Qcksum` for commit-then-verify. **Two roles:** (a) cache read-fill (built via `brix_sd_xroot_create(conf)`, `cache/fetch.c` driver→driver); (b) **registry-selectable PRIMARY backend** (`brix_storage_backend root://host:port`) → the export's storage is the remote server, read + transparent write-through (`tests/test_cmd_remote_backend.py`). Making a no-fd backend a root:// *primary* required relaxing the kXR handle path's `fd<0` gates additively (gated on `sd_obj.driver`; see `src/protocols/root/connection/fd_table.c`, `src/fs/vfs/vfs_io_core.c`). **Auth: anonymous login** only; authenticated origins use the staging/native-client path (later phase). Namespace (mkdir/rename), xattr/setattr forwarding, the generic staged-write seam, and an optional local staging directory are later phases (spec: `docs/superpowers/specs/2026-06-29-writable-remote-root-staged-write-design.md`). E2E: `tests/test_cmd_cache_xroot_origin.py` (read), `tests/test_cmd_remote_backend.py` (write-through). |
| `remote/sd_remote.c` / `.h` | The **remote-origin (`s3://`) driver** `brix_sd_remote_driver` (`CAP_RANGE_READ|CAP_MEMFILE`: ranged reads plus staged whole-object writes — `.staged_*` → single PUT or multipart upload — and `.unlink` DELETE, so as a primary it also accepts uploads). Built by the read-through cache to front a remote object store: `s3://` delegates entirely to the shared `sd_s3` read path — the per-open SD object wraps an `sd_s3_file*`, `pread` is a signed Range GET, `stat`/`fstat` report the HEAD size. The HTTP transport is **injected by the cache** (server libcurl, `../../cache/origin/s3_transport.c`), keeping the backend layer free of any cache/libcurl dependency. Instances + objects are malloc-owned (no nginx pool), so they are built and used on the blocking cache-fill worker thread. Constructed via `brix_sd_remote_create()`; not registry-selectable (it is never an export backend). E2E: `tests/test_cmd_cache_s3_origin.py`. |
| `rados/sd_ceph.c` (+ `rados/sd_ceph_io.c`, `rados/sd_ceph_object.c`, `rados/sd_ceph_cred.c`, `rados/sd_ceph_internal.h`) | The Ceph/RADOS driver `brix_sd_ceph_driver` (phase-60, completed by phase-89 §B) — maps a confined logical path to a flat RADOS object id. Split by the file-size guard: `rados/sd_ceph.c` = driver shell + registry row; `rados/sd_ceph_io.c` = worker-safe raw byte I/O, staged write, shared oid-level connection layer; `rados/sd_ceph_object.c` = object lifecycle + metadata (open/create/excl/trunc, stat, xattr); `rados/sd_ceph_cred.c` = per-user cred-conn cache, cred-scoped open, catalog enumeration. Caps: range-read, random-write, truncate, dirs, rename, xattr, staged commit (no fd ⇒ no sendfile, served memory-backed). Compiled only when `./configure` finds librados (`BRIX_HAVE_CEPH`); otherwise the files contribute only the pure, libc-only LFN→object-key helpers (`sd_ceph_normalize`/`_key`/`_ino`, in `rados/sd_ceph.h`) and the registry row is `#if`-compiled out, so a no-Ceph build is byte-for-byte unchanged. |
| `rados/sd_ceph_dir.c` | Directory iteration over the flat key namespace (phase-89 §B.1): opendir/readdir/closedir vtable slots via stripe-collapse listing (ADR-1 synthetic directories — RADOS has no real dirs). |
| `rados/sd_ceph_object_rename.c` | The rename vtable slot (phase-89 §B.2 / ADR-5): copy+delete rename with bare-oid existence/layout probe, ENOENT and noreplace-EEXIST semantics. |
| `rados/sd_ceph_striper.c` / `rados/sd_ceph_compat.c` (+ headers) | libradosstriper data-plane wrappers (gated on `BRIX_HAVE_RADOSSTRIPER`; empty TU otherwise) + pure striper layout helpers — stock-XrdCeph stripe-format interop. |
| `rados/sd_cephfs_ro.c` (+ `rados/sd_cephfs_ro_dir.c`, `rados/sd_cephfs_ro_resolve.c`, `rados/sd_cephfs_ro_internal.h`) | Read-only CephFS-via-RADOS driver ("cephfsro"): serves a real CephFS filesystem by decoding its on-RADOS structures directly (dentries from the metadata pool, file bytes from the data pool). |
| `rados/cephfs_denc.c` / `rados/cephfs_layout.c` (+ headers) | Pure decoders for CephFS on-RADOS metadata: bounds-checked sticky-error cursor over Ceph-encoded buffers + typed `inode_t`/dentry decoders mirroring Ceph v18.2.4 field order. |
| `rados/sd_ceph_unittest.c` | Standalone (no librados, no cluster) suite for the security-critical LFN→object-key map: canonicalization, injectivity, `..`-escape rejection, key composition, inode hash. Driven by `tests/test_sd_ceph.py`; live-cluster legs in `tests/ceph/sd_ceph_live_test.c` (`tests/test_ceph_live.py`). |
| `pblock/sd_pblock.c` | The pblock ("pseudo-block") driver `brix_sd_pblock_driver` — a **full-capability, block-based drop-in for POSIX**. Each object's bytes are **striped across fixed-size block files** (`data/<aa>/<bb>/<blob_id>/<index>`); the stripe size defaults to **64 MiB**, is configurable per export (`brix_sd_pblock_conf_t.block_size`), and is recorded **per file at creation** so retuning it only affects newer files. Block 0 is opened persistently as a real kernel fd (⇒ `CAP_FD`/`SENDFILE`/`IOURING` and zero-copy sendfile for offset-0 ranges within the first block); higher blocks are opened transiently per I/O. Reads/writes map `[off,off+len)` across blocks (holes read as zeros); `ftruncate` drops whole blocks past the new size and trims the boundary; `unlink` removes the block files + per-object dir. The entire logical namespace + metadata (stat, xattrs, path→blob map, per-file `block_size`) lives in a SQLite catalog (`pblock/sd_pblock_catalog.c`); the hot byte path never touches SQLite — only metadata boundaries (`open`, the `fsync` durability barrier which syncs every block, `close`, namespace ops) do. Advertises the **same caps as POSIX** and implements every slot. Fully `ngx`-free (libc + sqlite, `malloc`-owned state), identical in the module and the standalone test. Compiled only when `./configure` finds libsqlite3 (`BRIX_HAVE_SQLITE`); otherwise the file is empty and the registry row is `#if`-compiled out, so a no-sqlite build is byte-for-byte unchanged. Live-traffic *selection* + the VFS `obj->driver` data-plane routing are the named Phase-2 follow-on. |
| `pblock/sd_pblock_catalog.c` / `.h` | The pblock SQLite metadata catalog — pure libc + sqlite3 (no nginx), so it is independently testable and carries none of the data-plane cost. Typed CRUD over the `objects` (namespace/stat/blob-map) and `xattrs` tables; subtree-aware rename; WAL + busy-timeout + `FULLMUTEX` so one per-export handle is safe across a worker's thread pool and separate worker processes contend cleanly. |
| `pblock/sd_pblock_catalog_unittest.c` / `pblock/sd_pblock_unittest.c` | Standalone (no nginx, no server) suites: the catalog API, and the full driver vtable driven through its function pointers — every slot plus **multi-thread + multi-process + async-interleave + fsync-durability** concurrency. Run via the C-unit lane (`tests/test_c_regression_units.py`, suite `pblock`). |
| `ucred.c` / `ucred.h` | Per-user backend credential selection (phase-1 + phase-2 T2): maps a `brix_identity_t` to a pre-provisioned credential file under a configured directory. `brix_sd_ucred_principal` extracts the canonical principal (DN preferred over subject); `brix_sd_ucred_key` derives a filesystem-safe filename stem (verbatim for S3/JWT subjects that match `[A-Za-z0-9@._-]{1,64}`, `x5h-<32 hex>` SHA-256 hash otherwise); `brix_sd_ucred_select`/`_resolve` try `<key>.pem` (x509 proxy, expiry via `X509_cmp_current_time`) first, falling back to `<key>.token` (WLCG bearer) only when the `.pem` is absent — an *expired* `.pem` hard-declines rather than falling through to `.token`. No nginx pool dependency — all fields stored inline in `brix_sd_ucred_t`. |
| `cred_mint.c` / `cred_mint.h` | Opt-in x509 credential minting (phase-2 T9): `brix_cred_mint()` mints a fresh EC P-256 keypair + X509 signed by an operator-configured mint CA when no valid `<key>.pem` is cached, atomically written to `<cred_dir>/<key>.pem` (temp file + fsync + rename). Reuses an existing cached PEM with life left rather than re-signing every call. Gives bearer-only identities (S3 access keys, WLCG tokens with no pre-provisioned proxy) a per-user x509 identity at the origin without per-user file provisioning — **the origin must trust the mint CA**, since minting shifts a piece of trust-root authority to the frontend. Invoked only from the shared VFS credential gate (`fs/vfs/vfs_cred.c`), armed only by the HTTP data-plane call sites (`src/protocols/webdav/get.c`, `src/protocols/webdav/put.c`, `src/protocols/s3/util.c`) — never reachable from `root://` stream. |
| `sd_registry.c` | The driver table + name→driver lookup, per-export `brix_sd_instance_create`/`destroy`, and the accessor helper bodies. |
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
`const brix_sd_driver_t` (include the seam as `../sd.h`). Append the driver's
`extern` to `sd.h`, add a row to the `sd_drivers[]` table in `sd_registry.c`
(referencing any driver header by its subdir, e.g. `#include "<name>/sd_<name>.h"`),
register the `.c` at its subdir path in the top-level `config` (`NGX_ADDON_SRCS`),
and re-run `./configure`. Set only the capabilities the backend genuinely has —
the VFS degrades or rejects on the absent ones.

### Other files

| File | Responsibility |
|---|---|
| `cred_mint_cert.c` | The certificate-construction half of brix_cred_mint(): sanitize the principal into a CN-safe string, build the minted-proxy subject, generate a fresh EC P-256 keypair, and populate + sign an X509 leaf with the mint CA. |
| `cred_mint_internal.h` | The MINT_LOG NULL-tolerant log macro, the mint_ca_t / mint_material_t OpenSSL-object bundles, and the prototype for mint_build_cert() — the one EC-keygen + X509 build/sign entry point that crosses the cred_mint.c <-> cre. |
| `sd_cred_forward.h` | Route through the cred-scoped slot when a per-user credential is present AND the driver implements it; else the plain slot. |
| `sd_cred_types.h` | Borrowed pointers valid for the duration of the open() / staged_open() call. |
| `sd_fs_id.c` | Implements brix_fs_id_name() / brix_fs_id_from_name(), the name<->brix_fs_id_t mapping generated from the central filesystem declaration (core/types/fs_list.h). |
| `site_n2n.c` / `.h` | the tunable site name-translation. See the header. Pure libc. |
| `ucred_internal.h` | Declares the four credential-file readers (PEM/token/S3/keyring) that live in ucred_parse.c and are called from brix_sd_ucred_resolve() in ucred.c. |
| `ucred_parse.c` | Implements the four credential-file readers declared in ucred_internal.h — x509 PEM expiry check, bearer .token reader, .s3 SigV4 triple parser, and CephX .keyring section-header parser — plus their per-format static lin. |

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
