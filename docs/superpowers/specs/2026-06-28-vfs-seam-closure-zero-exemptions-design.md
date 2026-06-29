# VFS Data-Plane Seam Closure — Zero Exemptions

**Date:** 2026-06-28
**Status:** Approved directive (Rob), pre-implementation plan
**Goal:** Every code path that accesses file **data or namespace** goes through the
`xrootd_vfs_*` API. Zero exceptions, zero reviewed exemptions. The seam guard
backlog (`tools/ci/vfs_seam_backlog.txt`) shrinks to **empty** (comments only).

## Hard constraint (Rob)

Do not assume a missing VFS feature can't be added. The VFS is **expanded** to
cover every real need. The *only* permissible exemption is a capability that
cannot be expressed through the VFS/SD-backend split **for all known
filesystems** — and none has been found.

## Current state (verified 2026-06-28)

- The SD driver vtable (`src/fs/backend/sd.h`) already exposes: `open/close`,
  `pread/pwrite/preadv/copy_range/read_sendfile_fd/ftruncate/fsync/fstat`,
  `stat/unlink/mkdir/rename/server_copy`, `opendir/readdir/closedir`,
  `getxattr/listxattr/setxattr/removexattr`, `staged_open/write/commit/abort`.
  **Missing: `chmod`.**
- The `xrootd_vfs_*` API (`src/fs/vfs.h`) already wraps nearly all of it —
  including **impersonation-aware `xrootd_vfs_opendir`** (broker `fdopendir` as
  the mapped user) and **`xrootd_vfs_readdir` returning name + no-follow `lstat`**.
- BUT most VFS entrypoints are **unconsumed**: `xrootd_vfs_opendir/readdir`,
  `xrootd_vfs_read/write` have zero callers. Handlers still call the confined
  helpers (`xrootd_*_confined_canon`, `xrootd_*_beneath`) or the SD driver
  directly (`obj->driver->pread`). The backlog grandfathers ~56 such files.

So the work is **mostly migration onto existing-but-unproven VFS APIs**, plus a
few genuine VFS additions, plus hardening those APIs as their first consumer.

## VFS additions required (with backend-separation design)

1. **Async-safe `vfs_staged`.** Today `xrootd_vfs_staged_t` stores a `ctx`
   pointer; an async commit after the handler returns would dangle if the ctx was
   stack-allocated. Fix: make the handle **self-contained** — copy `root_canon`,
   `final_path`, `log`, and the `xrootd_staged_file_t` into the handle at open
   time; drop the `ctx` pointer. Backend-agnostic (the SD `staged_*` vtable is
   unchanged). Unblocks S3 chunked/aio PUT.
2. **`vfs_chmod` + SD vtable `chmod` slot.** Add `chmod(inst, path, mode)` to the
   driver vtable; POSIX impl = confined `fchmod`; object backends map to ACL/meta.
   Add `xrootd_vfs_chmod(ctx, mode)`. Unblocks CMS `CHMOD`.
3. **Pool-light namespace entry for control-plane.** CMS runs with no request
   pool. Either accept `ngx_cycle->pool` in `xrootd_vfs_ctx_init` for pure
   namespace ops (mkdir/unlink/rename/truncate/chmod, which allocate nothing), or
   add a `xrootd_vfs_ctx_init_np()` that takes no pool. Verify the namespace ops
   never allocate from the pool; if they do, fix to use a caller scratch buffer.

No other additions are needed — `opendir` (impersonation), `readdir` (lstat),
`open`, `stat`, `unlink`, `mkdir`, `rename`, `truncate`, `xattr`, `copy`,
`sendfile_fd`, and the byte ops all already exist on the seam.

## Migration, by capability-class (each: migrate → that suite green → drop backlog line)

The ~56 backlog files group into classes; migrate class-by-class so the VFS API
is hardened once per class:

| Class | Files (examples) | VFS target |
|---|---|---|
| Directory listing | `webdav/propfind_walk`, `dirlist/handler` | `vfs_opendir`/`readdir`/`closedir` |
| Namespace mutate | `write/mkdir`,`mv`,`truncate`, `cms/recv` | `vfs_mkdir/unlink/rename/truncate/chmod` |
| Crash-safe staging | `s3/put_aio`,`put_chunk`,`put_finalize` | self-contained `vfs_staged_*` |
| Confined read/serve | `dig/dig`, `read/open_resolved_file` | `vfs_open`/`vfs_file_sendfile_fd` |
| Data byte loops | `read/read`,`read/pgread`,`compat/http_body`, `compat/copy_range`,`compat/checksum_core`,`compat/http_compress` | `vfs_io_execute` / `vfs_read`/`vfs_write` (perf-checked) |
| xattr | `fattr/dispatch` | `vfs_getxattr`/`setxattr`/… |
| Checksum scan | `query/checksum_*` | `vfs_open` + `vfs_read` |

**Ordering (low-risk first, harden each API once):**
1. **Directory listing** — `propfind_walk` is the first `vfs_opendir/readdir`
   consumer; harden that API here. Then `dirlist/handler`.
2. **Namespace mutate** — add `vfs_chmod`; migrate `write/*` then `cms/recv`.
3. **Staging** — make `vfs_staged` async-safe; migrate the S3 PUT trio (this also
   makes the Phase-8 audit native, removing the manual `xrootd_xfer_finish`).
4. **Confined read/serve** — `dig`, then `read/open_resolved_file`.
5. **Data byte loops** — the hot path; route through `vfs_io_execute`, **benchmark
   each** (read/pgread/http_body) to confirm no regression vs the direct SD call;
   if the VFS layer adds measurable overhead, push the optimization *into* the VFS
   (it must be as fast as the direct call — that is the bar for closing this class
   without a perf exemption).
6. **xattr, checksum scan** — mechanical.

## Verification

- Per file: that protocol's pytest suite green; the seam guard no longer flags it;
  its backlog line deleted.
- Per class: the relevant cross-cutting suites (webdav, s3, root://, cms, frm).
- End state: `tools/ci/check_vfs_seam.sh` green **with an empty backlog** (the
  file holds only comments). The data-byte-loop class additionally needs a
  before/after throughput check (the existing `tests/profile_load.sh`).
- The one prior data-plane invariant (tier-1, raw syscalls) stays clean throughout.

## Out of scope

`zip_dir_unittest.c` (standalone parser test, not in the module build) stays
allowlisted — it is not in the running server and links no SD seam. Everything
else migrates.

## Risks

- **Unconsumed VFS APIs** (`opendir/readdir/read/write`) will surface rough edges
  at first use — budget for hardening them, not just calling them.
- **Hot-path perf** (data byte loops): the VFS layer must match direct-SD speed.
- **Impersonation / symlink-no-follow / async lifetime / depth caps**: behaviour
  must be preserved exactly — each migration keeps its existing test as the oracle.
