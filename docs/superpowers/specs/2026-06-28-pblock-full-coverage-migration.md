# pblock full-coverage migration — all file ops for root:// + WebDAV

**Goal:** every file operation on a `pblock`-backed export works for both `root://`
(stream) and WebDAV (HTTP), by migrating each storage pathway to a VFS method that
dispatches through `ctx->sd->driver` instead of hardcoding POSIX.

**Date:** 2026-06-28 · **Status:** Layers 1–4 DONE & verified; Layer 5 (cache) edge-deferred

## Implementation status

- **Layer 1 (VFS namespace ops → driver dispatch) — DONE.** `vfs_stat` (+probe),
  `vfs_dir` (opendir/readdir/readdir_kind/closedir), `vfs_mkdir`, `vfs_unlink`
  (incl. a generic driver `rmtree` for recursive DELETE), `vfs_rename`
  (+ ctx-less `rename_path`, now instance-aware), `vfs_xattr` (×4), and `vfs_copy`
  all dispatch through `ctx->sd->driver` when a non-POSIX backend is bound, else
  the POSIX path unchanged. `vfs_chmod` is a no-op on a driver backend (mode is
  catalog-fixed). pblock now seeds an implicit `/` root dir so stat/PROPFIND on
  the export root work before anything is written.
- **Layer 2 (threading) — DONE, via a registry.** New `vfs_backend_registry.{c,h}`:
  config time registers `{root_canon → pblock conf}` (webdav `merge_loc_conf`,
  stream `runtime_server.c`); `xrootd_vfs_ctx_init` resolves it (lazy per-worker
  SQLite instance), auto-threading **every** ctx-build site. Two hand-rolled ctx
  sites (`webdav/resource.c` `webdav_resolve_stat`, the MOVE offload task) were
  threaded explicitly. The old per-conf `storage_instance` + `process.c`
  init_process creation were removed in favour of the registry.
- **VERIFIED:** `tests/run_pblock_webdav.sh` — full WebDAV-on-pblock matrix passes
  (PUT/GET single + multi-block byte-exact + Range, HEAD, PROPFIND, MKCOL, MOVE,
  COPY, DELETE file/empty/non-empty). Standalone driver+catalog suite still green;
  module builds 0 warnings/errors. **WebDAV is fully functional on pblock.**
  root:// **metadata** (kXR_stat/statx/dirlist/mkdir/rm/mv) routes through the same
  migrated VFS namespace ops + registry.
- **Layer 3 (root:// data plane) — DONE.** The handle (`xrootd_file_t.sd_obj`) and
  every io_core job/segment carry an `xrootd_sd_obj_t`; `xrootd_vfs_effective_obj`
  routes data I/O through the driver when bound, else POSIX-wraps the bare fd
  (byte-for-byte the pre-Layer-3 path). `open_resolved_file.c` opens a driver-backed
  export through `driver->open` (keyed on the export-relative `/sub/file`, matching
  WebDAV/stat), synthesizes `struct stat` from the open snapshot, and `free_fhandle`
  closes via the driver. The read-open existence pre-check (`open_request.c`) and the
  zero-copy **sendfile gate** (`read.c`) are driver-aware: a striped backend's bare
  fd is block 0 only, so a driver handle takes the buffered io_core path (driver
  `preadv` spans blocks) instead of sendfile. Job builders thread the obj:
  read/readv/pgread/write/writev/pgwrite/sync/truncate (inline + AIO task structs).
  `pblock_make_obj` now fills `obj->snap` so the handle reports the real size.
- **Layer 4 (checksum readback) — DONE.** `checksum_core` gained obj-aware kernels
  (`_u32_obj/_u64_obj/_digest_obj`); `checksum.c` gained `xrootd_checksum_hex_obj`;
  `xrootd_integrity_get_fd` takes an `xrootd_sd_obj_t *obj` (NULL ⇒ POSIX fd, the
  unchanged default) and computes through the driver when bound. kXR_Qcksum (path +
  handle, inline + async) threads the handle's obj. S3/WebDAV/dirlist callers pass
  NULL today (POSIX) — those backends are not yet driver-bound for checksum-at-rest.
- **VERIFIED (root://):** `tests/run_pblock_root.sh` — PUT/GET single + multi-block
  byte-exact, stat size, **whole-file adler32 + crc32c checksum-at-rest** match the
  reference, mkdir/ls/rm. POSIX checksum + 3 MB sendfile roundtrip unchanged on the
  live fleet; WebDAV-on-pblock still ALL PASS.
- **Layer 5 (cache) — DEFERRED (edge).** The read-through cache (`cache_root`) is a
  separate **POSIX** storage domain by design — `from_cache` opens bypass the driver
  and write-through flush is an opt-in PFC feature. Engaging an xcache *in front of*
  a pblock origin works (cache stores pulled bytes as POSIX); making the cache itself
  pblock-backed, and routing write-through dirty-flush reads through a driver obj, is
  the only remaining gap and is not exercised by a default pblock export.

---


---

## 1. The architecture (good news first)

The protocol handlers **already call VFS methods** (`xrootd_vfs_stat`, `_open`,
`_mkdir`, `_rename_path`, `_opendir/_readdir`, `_unlink`, `_getxattr`, `_copy`,
`_io_execute`, `_staged_*`). So the migration is mostly **inside the VFS**, not in
the handlers. There are exactly **three gaps**:

1. **The VFS methods don't dispatch to the driver.** Open + staged + the GET
   read-serve were migrated this session; **every other VFS method still hardcodes
   POSIX** (`xrootd_lstat_confined_canon`, `xrootd_ns_*`, `xrootd_*xattr_confined_canon`,
   `xrootd_opendir_confined_canon`, and the fd-keyed `io_core`).
2. **`vctx.sd` is threaded at only 2 of ~50 ctx-init sites** (webdav `get`/`put`).
   Everywhere else `vctx.sd == NULL` ⇒ the default POSIX path, even on a pblock export.
3. **The data plane is fd/POSIX-pinned.** `xrootd_file_t` (root:// open-file slot)
   and the `io_core` job carry a bare `int fd`; read/write `posix_wrap` it.

## 2. Already migrated (this session — reference)

| Pathway | Method | Status |
|---|---|---|
| Open (handle) | `vfs_open` → `driver->open` + `adopt_obj` (any rootfd) | ✅ |
| Staged write (PUT) | `vfs_staged_open/write/commit/abort` → `driver->staged_*` | ✅ |
| GET read-serve | memory-backed fallback in `file_serve.c` via `vfs_file_pread` → `driver->pread` | ✅ |
| Logical-path keying | `xrootd_vfs_export_relative()` (root_canon strip) | ✅ |
| Obj ownership | `xrootd_sd_obj_t.heap_shell` + adopt frees shell | ✅ |
| Selection | `xrootd_{webdav}_storage_backend` directive + per-worker instance | ✅ |

---

## 3. Migration layers (the work)

### Layer 1 — VFS namespace ops → driver dispatch  ★ highest leverage

Each of these hardcodes POSIX; gate them: *if `ctx->sd` is non-default, call the
driver slot with `xrootd_vfs_export_relative(ctx, path)`; else the POSIX helper.*

| File | Current (POSIX) | → Driver slot | Unblocks |
|---|---|---|---|
| `src/fs/vfs_stat.c` | `xrootd_lstat_confined_canon` | `driver->stat` | root:// `kXR_stat`/`statx`, WebDAV **HEAD/PROPFIND**, conditional GET/PUT |
| `src/fs/vfs_dir.c` | `xrootd_opendir_confined_canon` + per-child `lstat` | `driver->opendir/readdir/closedir` (+ `stat`) | root:// `kXR_dirlist`, WebDAV **PROPFIND** depth:1 |
| `src/fs/vfs_mkdir.c` | `xrootd_ns_mkdir` (+ `xrootd_chmod_confined_canon`) | `driver->mkdir` | root:// `kXR_mkdir`, WebDAV **MKCOL** |
| `src/fs/vfs_unlink.c` | `xrootd_ns_delete` | `driver->unlink` | root:// `kXR_rm`/`kXR_rmdir`, WebDAV **DELETE** |
| `src/fs/vfs_rename.c` | `xrootd_ns_rename` | `driver->rename` | root:// `kXR_mv`, WebDAV **MOVE** |
| `src/fs/vfs_xattr.c` | `xrootd_*xattr_confined_canon` | `driver->getxattr/listxattr/setxattr/removexattr` | WebDAV **PROPPATCH/LOCK** dead-props, checksum xattrs |
| `src/fs/vfs_copy.c` | `xrootd_ns_local_copy` | `driver->server_copy` | root:// clone, WebDAV **COPY** |
| `src/fs/vfs_sync.c` | (data-plane fsync) | `driver->fsync` via the obj | `kXR_sync` durability |

*Risk:* low — gated; the POSIX path is byte-for-byte unchanged.
*Effort:* ~7 small files, one branch each.

### Layer 2 — thread `vctx.sd` at every storage-touching ctx-init  ★ mechanical

After each `xrootd_vfs_ctx_init(...)`, set `vctx.sd = <backend instance>`:

- **WebDAV** (instance via `xrootd_webdav_backend_instance(conf, log)`):
  `move.c`, `copy.c`, `namespace.c` (DELETE/MKCOL), `prop_xattr.c`, `dead_props.c`,
  `propfind_walk.c`, `methods_basic.c` (**HEAD**), lock paths. (`get`/`put` done.)
- **root://** (instance = `conf->common.storage_instance`, built at `init_process`):
  `read/stat.c`, `read/statx.c`, `read/open_resolved_file.c`, `dirlist/handler.c`,
  `write/mkdir.c`, `write/mv.c`, `write/truncate.c`, `write/rm.c`.

*Suggestion:* add a one-line helper `xrootd_vfs_ctx_set_backend(vctx, inst)` (or a
`*_init_backend` ctx-init variant) so the ~48 sites are consistent and greppable.

### Layer 3 — data plane: carry the driver object, not a bare fd  ★ hardest

Today the open returns an fd; `io_core` `posix_wrap`s it. For pblock that fd is
only **block 0** (or `NGX_INVALID_FILE`), so read/write are wrong/short.

- **3a. Carrier.** Add an `xrootd_sd_obj_t` (driver + per-open state) to the
  open-file slot `xrootd_file_t` (`src/core/types/file.h`) and to the `io_core` job
  (`src/fs/vfs_io_core.h`), beside the existing `fd`.
- **3b. Open → handle.** `read/open_resolved_file.c` uses `xrootd_vfs_open_fd_at`
  (bare fd). Route it through `xrootd_vfs_open` (handle) and store `fh->obj` in the
  slot. Same migration for the bare-fd helpers `xrootd_vfs_open_fd[_at]`
  (`vfs_walk.c`) used by **S3 PUT** (`s3/put.c:237`), **TPC** (`tpc/launch.c`,
  `webdav/tpc_curl.c`), **CMS** (`cms/recv.c`).
- **3c. io_core dispatch.** `src/fs/vfs_io_core.c` (`read/write/readv/pgread/writev/
  sync/truncate`) currently `xrootd_sd_posix_wrap(job->fd)`. Dispatch through the
  job's obj `driver` instead. Callers to pass the obj: `read/read.c`, `read/readv.c`,
  `read/pgread.c`, `write/write.c`, `write/pgwrite.c`, `write/sync.c`,
  `write/truncate.c`.

*Risk:* high — the hottest path + `fd_table` + `io_core` touch every transfer.
Gate on `obj.driver != default` so POSIX stays on the existing fd path.
*Note:* pgread/pgwrite per-page CRC + readv coalescing must still work over a
non-contiguous (block-striped) backend; `read_sendfile_fd` already returns
`INVALID` for cross-block ranges, so root:// read should serve via `driver->preadv`.

### Layer 4 — checksum / integrity read-back

`kXR_Qcksum`, WebDAV `checksum_on_write`, and dirlist checksum tokens reopen the
object to hash it:
- `src/core/compat/checksum_core.c` already calls `obj.driver->pread` — but the obj is
  built by `xrootd_sd_posix_wrap(fd)`, so `driver == posix`. Feed it the real obj.
- `src/protocols/webdav/put.c` `webdav_put_persist_checksums` reopens via `xrootd_vfs_open_fd`
  (bare fd ⇒ block-0 only). Migrate to a handle + `vfs_file_pread`.
- `src/protocols/root/dirlist/dcksm.c` (per-entry dirlist checksum) — same.

### Layer 5 — read-through cache (only if cache enabled on a pblock export)

`src/fs/cache/io.c`, `src/fs/cache/writethrough_flush.c` `posix_wrap`. The cache *store*
lives in `cache_root` (a separate POSIX domain — can stay POSIX), but write-through
**reads the export object** (pblock). Edge case; revisit after Layers 1–4.

---

## 4. SD-driver capability gaps to fill (pblock + the vtable)

Some POSIX namespace ops have **no driver slot** — they need either a new slot or
a documented degrade:

- **`chmod`** — `vfs_mkdir.c`/chmod uses `xrootd_chmod_confined_canon`; no
  `driver->chmod`. pblock should store/update `mode` in the catalog (add a slot, or
  fold into a metadata-set op).
- **`statfs`/space** — `kXR_Qspace`/`statvfs` has no driver slot (pblock could
  report the backing filesystem's space, or synthesize).
- **`symlink`/`readlink`/`link`** (`kXR_setattr` family, 3500–3503) — no slots;
  pblock has no symlink concept (reject `ENOTSUP`, or model in the catalog).
- **`truncate`-by-path** — currently `vfs_truncate` opens then `ftruncate`; works
  once Layer 3 lands (handle carries the obj).

---

## 5. Recommended order & impact

1. **Layer 1 + Layer 2** → unlocks **all metadata ops** for both protocols
   (stat, HEAD, PROPFIND, dirlist, DELETE, MKCOL, MOVE, COPY, xattr/PROPPATCH/LOCK).
   Low risk, ~7 VFS files + ~48 one-line threads. *This fixes the visible 404s.*
2. **Layer 3** → root:// `read/readv/pgread/write/pgwrite/sync/truncate` (and S3
   PUT / TPC / CMS via the bare-fd helpers). High risk; the data-plane carrier change.
3. **Layer 4** → checksums/integrity correct on pblock.
4. **Driver-slot gaps** (Layer 4 header §) as encountered.
5. **Layer 5** (cache) last, if needed.

WebDAV GET/PUT data already work (this session). After Layer 1+2, WebDAV is
**fully functional** on pblock except the cache edge. After Layer 3, root:// is too.

## 6. Out of scope (shared beneficiaries)

S3 GET/PUT/list ride the same VFS namespace + `vfs_open_fd`, so Layers 1/3 fix them
for free where they call VFS methods; S3 PUT's bare-fd open (`s3/put.c`) is part of
the Layer-3b bare-fd-helper migration.
