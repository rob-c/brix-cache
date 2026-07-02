# Phase 62 — Full VFS seam closure: namespace & metadata, not just bytes

**Status: DONE + verified (2026-06-28).** This phase completes phase-56's Pillar F
(`F-1` seam closure, `F-3` CI guard) by extending the "the VFS is the sole source
of storage truth" invariant from the **byte data plane** to the **entire
filesystem surface** — `open`, `stat`/`lstat`, `opendir`/`readdir`,
`unlink`/`rename`/`mkdir`/`rmdir`, `truncate`/`chmod`, and the **xattr** family —
across every protocol handler. The CI guard (`tools/ci/check_vfs_seam.sh`) now
enforces this with a third tier and is **green on all three tiers with every
backlog at 0**.

This is the authoritative description of how filesystem access works in `src/`
after the migration. The reference for the API itself lives in
[`src/fs/README.md`](../../src/fs/README.md); the cross-tree (client) layering in
[`docs/09-developer-guide/vfs-shared-architecture.md`](../09-developer-guide/vfs-shared-architecture.md).

---

## 0. The one-sentence model

> **Every component reaches export/cache/scratch storage ONLY through the VFS
> (`src/fs/`); the only raw libc filesystem calls left in handler code are
> (a) genuinely non-export resources and (b) separate svc-owned storage domains
> that must NOT be confined to the export root — and each of those carries an
> explicit `/* vfs-seam-allow: <reason> */` marker that the guard checks.**

Before this phase the seam guard only covered three *byte-data* classes:
positional syscalls (`pread`/`pwrite`/`copy_file_range`/`sendfile`), the confined
helper layer (`xrootd_*_confined_canon`/`_beneath`), and SD-vtable byte loops.
"Guard green at backlog 0" therefore proved the *data* plane was funneled — but a
handler could still call raw `open()`, `stat()`, `opendir()`, `unlink()`, or
`getxattr()` on an export path and the guard never noticed. This phase closes
that gap.

---

## 1. Why the namespace/metadata plane matters as much as the byte plane

The reasons are identical to the byte-plane argument, just applied to metadata:

1. **A non-POSIX backend.** The whole point of the Storage Driver seam (phase-55)
   is that an object/S3/Ceph backend can become primary. A handler that calls raw
   `stat()`/`opendir()`/`getxattr()` on a constructed path is POSIX-pinned exactly
   like a raw `pread()` is — it cannot follow the backend.
2. **Confinement.** A raw `open()`/`stat()` on a string path is only as safe as
   the lexical checks around it; the VFS routes through `openat2(RESOLVE_BENEATH)`
   (or the impersonation broker), which is the *kernel-enforced* boundary.
3. **Impersonation.** Under `xrootd_impersonation map`, namespace/metadata ops
   must run as the **mapped user** via the broker, not the worker (svc). A raw
   `getxattr()` runs as svc and silently diverges; the VFS routes it correctly.
4. **Observability.** Metadata ops are metered (`OP_STAT`, `OP_XATTR`,
   `OP_DIRLIST`, …) and access-logged once, in the VFS, instead of being invisible.

---

## 2. The enforcement model — three guard tiers

`tools/ci/check_vfs_seam.sh` now classifies a raw filesystem syscall into one of
three tiers. Run it in CI; `--regen` re-snapshots the backlogs after a deliberate
migration.

| Tier | What it catches | Rule | Backlog |
|---|---|---|---|
| **tier-1** | raw **positional byte** ops (`pread`/`pwrite`/`preadv`/`pwritev`/`copy_file_range`/`sendfile`) outside `src/fs/backend/` | **HARD** (no backlog) — data byte I/O must stay in the SD driver | none; `RAW_ALLOW` for documented non-export files |
| **tier-2 / 1.5** | a handler calls the **confined-helper layer** (`xrootd_*_confined_canon`/`_beneath`, `xrootd_ns_*`) or the **SD vtable** (`xrootd_sd_posix_driver.<byteop>`) directly instead of `xrootd_vfs_*` | backlog-grandfathered | `tools/ci/vfs_seam_backlog.txt` (**0** files) |
| **tier-3** *(new)* | a handler makes a **raw namespace/metadata syscall**: `open`/`openat`/`creat`, `stat`/`lstat`/`fstatat`, `opendir`/`readdir`/`fdopendir`, `unlink`/`unlinkat`/`rmdir`/`rename`/`renameat`/`mkdir`/`mkdirat`, `truncate`/`ftruncate`, `chmod`/`fchmod`/`chown`/`fchown`, `symlink`/`readlink`/`link`/`mknod`, and the **xattr** family | backlog-grandfathered + per-line marker | `tools/ci/vfs_seam_backlog_ns.txt` (**0** files) |

Tier-3 cannot be a hard rule like tier-1 for two unavoidable reasons, which drive
the whole design:

- **(a) Non-export resources are legitimate and pervasive.** Config/cert/token/
  keytab readers (`fopen`/`open`), `/tmp` credential temps, `/dev/null`, `/proc`
  fd-hygiene, sockets — none touch the export backend and must not be forced
  through it.
- **(b) Separate storage domains.** The read-through cache root, the upload stage
  dir, the FRM control/journal store, S3 multipart staging, and the checkpoint
  journal are **svc-owned roots OTHER than the export**. They are opened **as the
  worker** and must NOT go through the export-confined, impersonation-aware VFS —
  see §4.

So tier-3 (1) excludes the below-seam layer + config/auth dirs + the
separate-domain stores via `TIER3_ALLOW`, (2) skips any line carrying a
`vfs-seam-allow` marker, and (3) grandfathers the rest in `vfs_seam_backlog_ns.txt`
— rejecting only a **new** raw namespace/metadata syscall in a file not already
on that backlog. After this phase that backlog is empty: every genuine export
site was migrated, every separate-domain/non-export site was marked.

### The marker, precisely

```c
fd = open(part_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);  /* vfs-seam-allow: S3 multipart staging-dir domain */
```

The guard greps `vfs-seam-allow` on the **raw** source line *before* it strips
comments and string literals; the family-name match is then checked *after*
stripping (so an op name mentioned in a comment or a log string is never a false
hit). **The marker must be on the same physical line as the call.** Every marker
states which domain or non-export resource justifies the raw call.

---

## 3. What now flows through the VFS — the full surface

A handler builds an `xrootd_vfs_ctx_t` (export `root_canon` and/or the persistent
`rootfd`, the already-resolved confined path, identity, `allow_write`, proto) and
calls one entry point. The complete surface, grouped:

**Byte data plane** (phases 54–56, unchanged here)
- `xrootd_vfs_open` / `xrootd_vfs_close` (+ the `xrootd_vfs_file_*` accessors)
- `xrootd_vfs_read` / `xrootd_vfs_write` and the worker-safe
  `xrootd_vfs_io_execute()` core, `xrootd_vfs_pread_full` / `pwrite_full`

**Metadata**
- `xrootd_vfs_stat` (lstat, metered `OP_STAT`), `xrootd_vfs_statf` (follow
  in-export symlinks), and `xrootd_vfs_probe(ctx, nofollow, &vst)` — the
  **non-metered** existence/type pre-check used by op-resolution and ACL gates
  (routing every rm/mkdir pre-stat through the metered `stat` would record a
  phantom `OP_STAT`).
- `xrootd_vfs_stat_t` carries `size`, `mtime`, `ctime`, **`atime`** (added this
  phase for `kXR_Qxattr`'s `oss.at`), `mode`, `ino`, `dev`, `uid`, `gid`,
  `blocks`, `is_directory`, `is_regular`.

**Directory enumeration**
- `xrootd_vfs_opendir` (metered `OP_DIRLIST`) / `xrootd_vfs_opendir_quiet`
  (non-metered, for bulk recursive walks) / `xrootd_vfs_readdir` (with optional
  per-child lstat) / `xrootd_vfs_readdir_kind` (d_type only) /
  `xrootd_vfs_closedir`; `xrootd_vfs_dir_fd` for a TOCTOU-safe dirfd-relative
  per-entry open inside an already-opened confined stream.

**Namespace mutation**
- `xrootd_vfs_mkdir` / `rename` / `unlink` / `rmdir` / `copy` (ctx-based, metered,
  write-gated) and the thread-safe raw-path primitives for off-loop / bulk
  consumers: `xrootd_vfs_open_fd(log, root_canon, abs, flags, mode)`,
  `xrootd_vfs_open_fd_at(rootfd, logical, flags, mode)`,
  `xrootd_vfs_unlink_path(log, root_canon, abs)`,
  `xrootd_vfs_unlink_at(rootfd, logical, is_dir)`,
  `xrootd_vfs_mkdir_path`, `xrootd_vfs_rename_path`, and the
  `xrootd_vfs_walk`/`copyfile`/`copytree` confined-tree primitives.

**Extended attributes** (`vfs_xattr.c`)
- Path/ctx-based: `xrootd_vfs_getxattr` / `listxattr` / `setxattr` /
  `removexattr` (confined to `ctx->resolved`, metered `OP_XATTR`).
- **Open-handle (fd) variants, added this phase**: `xrootd_vfs_fgetxattr` /
  `flistxattr` / `fsetxattr` / `fremovexattr(ctx_or_NULL, fd, …)`. These operate
  on an fd the VFS already opened confined (so confinement travels with the
  descriptor — there is no path to re-resolve); `ctx` is optional and only
  attributes the metric. They exist so fattr's file-handle mode and
  `compat/integrity_info`'s checksum cache reach the backend through the VFS
  instead of calling `fgetxattr(2)` directly.

---

## 4. The critical correctness boundary: impersonation vs. separate domains

This is the single most important thing to understand before touching any of
this code.

`xrootd_vfs_open_fd` / `xrootd_vfs_probe` / the ctx-based xattr ops all delegate,
underneath, to the `*_confined_canon` / `*_beneath` helpers. Those helpers are
**impersonation-aware**: when `xrootd_impersonation map` is active they route the
syscall to the privileged broker, which performs it **as the mapped user under
the broker's own rootfd — the EXPORT root**. They also confine to a *single*
root.

Therefore:

- **Export-root paths** → always go through the VFS. Under impersonation the
  broker resolves the export-relative path under the export rootfd as the mapped
  user. Correct.
- **Separate svc-owned roots** (cache root, upload stage dir, FRM control dir, S3
  multipart staging, checkpoint journal) → **must stay raw, as the worker.**
  Routing them through `xrootd_vfs_open_fd("$cache_root", …)` would, under
  impersonation, make the broker open the path under the **export** rootfd as the
  mapped user — the *wrong root* and the *wrong identity* (these files are
  svc-owned and the cache worker writes them as svc). The original code used raw
  `open()`/`stat()` for exactly this reason. We preserved that and made the
  intent explicit with a `vfs-seam-allow` marker.

A second subtlety used throughout the migration: `*_confined_canon` takes the
**absolute** resolved path and strips `root_canon` itself (the impersonation
branch needs the export-relative form; the local branch uses the absolute path
directly). So callers pass the absolute path, never a pre-stripped one — passing
a pre-stripped relative path makes the prefix-strip fail and the open ENOENT.

---

## 5. The migration, cluster by cluster (what moved, and how verified)

All verification used the standalone `tests/_xrdcl_proxy` worker (the pytest
fattr/bindings lane is dead in this environment — an XrdCl-isolation infra issue,
not a code regression) plus raw-wire suites and direct `curl` for WebDAV.

### 5.1 xattr — fully closed (zero genuine raw calls remain)
- **`fattr/{get,set,del,list}.c` + `dispatch.c`** — the kXR_fattr handler. The
  dispatcher lifts a single `xrootd_vfs_ctx_t` to function scope and passes it to
  every sub-handler; **path mode** uses the ctx-based VFS xattr, **file-handle
  mode** uses the new fd-based variants. `fattr_list`'s `kXR_fa_recurse` subtree
  walk now uses `xrootd_vfs_opendir_quiet` + `xrootd_vfs_readdir` (whose per-child
  `lstat` is the same no-follow guarantee) + a per-file transient ctx for
  `listxattr`.
- **`query/metadata.c`** — `kXR_Qxattr` now does its stat via `xrootd_vfs_probe`
  (hence the new `atime` field) and its `listxattr`/`getxattr` via the VFS.
- **`webdav/lock.c`** — the startup lock-sweep removes each persisted lock xattr
  via `xrootd_vfs_removexattr` (the sweep now takes a pool to build a ctx per
  node). The live LOCK/PROPPATCH path (`prop_xattr.c`), WebDAV dead-properties
  (`dead_props.c`), and S3 object tagging (`s3/tagging.c`) were already on the VFS.
- **`compat/integrity_info.c`** — the checksum-at-rest xattr cache now uses
  `xrootd_vfs_fgetxattr`/`fsetxattr`/`fremovexattr`. (Its `.cks` sidecar fallback
  store and `fstat`-on-open-fd are a separate metadata domain — see §6.)

### 5.2 stat — the hot open path + the symlink-follow fallbacks
- **`read/open_resolved_file.c`** — the `kXR_open` path. A new static helper
  `xrootd_open_probe(log, root, abs, nofollow, &vst)` (a thin `xrootd_vfs_probe`
  wrapper; `vfs_probe` is non-metered and pool-free, so a `NULL` pool is fine)
  replaces all five export-path pre-flight `stat()`s (directory-reject on read and
  write, exclusive-create, resume-partial existence, in-place-update decision).
- **`read/stat.c`** and **`read/statx.c`** — the realpath-follow fallback (for an
  in-export symlink with a host-absolute target) now reads the confirmed-in-root
  target's metadata via `xrootd_vfs_probe` + the now-exported
  `xrootd_vfs_to_struct_stat`. The primary stat path was already on the VFS.

### 5.3 open / unlink — export sites
- **`read/open_resolved_file.c`** — the export branch opens via
  `xrootd_vfs_open_fd_at(conf->rootfd, logical, …)`.
- **`webdav/put.c`** — the checksum-on-write reopen of the just-committed export
  file → `xrootd_vfs_open_fd`.
- **`tpc/done.c`** — the failed-pull destination cleanup `unlink(dst_path)` (×3) →
  `xrootd_vfs_unlink_path(t->conf->common.root_canon, …)`.

### 5.4 marked `vfs-seam-allow` (separate domain / non-export — correctly raw)
cache + stage opens and the external-partial stat (`open_resolved_file.c`); cache
existence stats (`open_cache.c`, `read/stat.c`); `cms/recv.c` `fchmod`/`ftruncate`
on an already-VFS-opened fd; `fd_table.c` cache reopen + POSC/checkpoint cleanup;
`dcksm.c` dirfd-relative open within a `xrootd_vfs_dir_fd` stream;
`prepare_cmd.c` `/proc/self/fd` hygiene; `s3` HeadBucket / list-cache stats of the
export **root itself**; S3 multipart staging (`multipart_abort.c`,
`multipart_complete_upload_part_copy.c`); TPC `/tmp` cred temps
(`tpc_token.c`, `tpc_cred.c`) and transfer temps (`tpc_curl.c`, `tpc_marker.c`,
`tpc_thread.c`).

---

## 6. Domains classified as below-seam / separate-store (guard `TIER3_ALLOW`)

These directories make raw filesystem calls legitimately and are excluded from
tier-3 wholesale (they are the seam's own implementation, config readers, or
self-contained alternate stores with their own confinement):

- **The VFS + resolution layer**: `src/fs/`, `src/path/`, `src/core/compat/`,
  `src/auth/impersonate/`.
- **Separate storage/metadata domains**: `src/fs/cache/` (read-through cache),
  `src/observability/dashboard/` (admin browse, openat2-confined), `src/frm/` (residency
  markers + durable queue — a control/journal store keyed off a confined path,
  optionally under a separate `frm_g_control_dir`), `src/write/chkpoint` (the
  checkpoint journal), `src/read/slice_read` (the slice cache).
- **Config / cert / token / auth readers** (never the export backend):
  `src/auth/crypto/`, `src/auth/gsi/`, `src/auth/sss/`, `src/auth/pwd/`, `src/auth/token/`, `src/core/config/`,
  `src/auth/krb5/`, `src/auth/authz/acc/`, `src/auth/voms/`, `src/ssi/`, `src/dig/`, `src/core/aio/`.
- Unit tests (`*unittest*`, `*_test*`).

`compat/integrity_info.c`'s `.cks` sidecar fallback store and its `fstat` of an
already-open fd are in `src/core/compat/` (below-seam); its export-file xattr cache was
still migrated to the VFS fd-xattr primitives because that touches the real
export object.

`compat/http_body.c` is `RAW_ALLOW`'d at tier-1: its `pread` reads nginx's
**inbound request-body** buffers (`r->request_body`, spilled to `client_body_temp`
when large) to stream a PUT/POST upload into a staged export file — the source is
nginx's own temp, not export storage; the export *write* side goes through
`xrootd_vfs_staged`.

---

## 7. Rules for new code (the contract going forward)

1. **Touching the export?** Use `xrootd_vfs_*`. For a confined fd off the event
   loop, `xrootd_vfs_open_fd`/`_at`; for an existence/type check, `xrootd_vfs_probe`;
   for metadata, `xrootd_vfs_stat`/`statf`; for xattr, the path or fd variants.
   Pass the **absolute** path to the `root_canon` primitives.
2. **Touching a separate svc-owned store** (cache/stage/journal) **or a
   non-export resource** (config/cert/token/`/tmp`/socket/`/proc`)? A raw call is
   correct — add a same-line `/* vfs-seam-allow: <which domain/why> */` marker.
3. **Never** invent a new confined-helper call (`*_confined_canon`/`_beneath`) in
   a handler — that is tier-2; go through `xrootd_vfs_*`.
4. **Never** put data byte I/O (`pread`/`pwrite`/…) anywhere but
   `src/fs/backend/` — that is tier-1, a hard rule.
5. Run `tools/ci/check_vfs_seam.sh`. After a deliberate migration that empties a
   backlog line, `--regen` and justify it in the PR.

---

## 8. Verification summary

- `tools/ci/check_vfs_seam.sh` → **OK**: tier-1 clean, tier-2/1.5 backlog **0**,
  tier-3 ns backlog **0**.
- Build clean (`-Werror`), full module relink.
- Standalone `_xrdcl_proxy`: `root://` stat, `kXR_Qxattr`, fattr set/get/list/del
  (path and fd modes), read/write byte-exact, POSC round-trip, directory-open
  reject (read and write).
- WebDAV `PUT` 201 / `GET` 200 (byte-exact) / `DELETE` 204.
- `tests/test_readv_security.py`: 24 raw-wire pass (the 2 failures are the
  dead-XrdCl pytest lane, verified independently via the standalone proxy).

---

## 9. Known residuals / follow-ups

- **Worker-tier namespace mutation** (native TPC pull assembly, async/multipart S3
  PUT assembly, collection COPY/MOVE engines) still uses the `xrootd_ns_*` /
  `compat/staged_file` tier directly rather than a metered `xrootd_vfs_*` wrapper.
  Both tiers share the same `RESOLVE_BENEATH` confinement; only the metering/cache
  layer is skipped off-loop. This is the phase-56 F-1 worker-tier follow-up,
  tracked there, and is *not* a tier-3 raw-syscall bypass.
- **No fd-based VFS `truncate`/`chmod`**: `cms/recv.c` sets post-open mode/size on
  an already-VFS-opened fd via raw `fchmod`/`ftruncate` (marked). If a non-POSIX
  backend ever needs to intercept these, add `xrootd_vfs_fchmod`/`fchtruncate`
  fd primitives and migrate that one call site.
