# Phase 8: openat2 Confinement — Kernel-Enforced Path Security

**Projected ΔLoC:** −1,080 (conservative), −1,300 (optimistic)
**Risk:** High (security-critical code; kernel version gating required)
**Depends on:** Phase 3 (op_path middleware replaces most callers first)
**Blocks:** nothing
**Parallel-safe with:** Phases 5, 6, 7

---

## ✅ Status: Implemented for runtime client paths — historical migration notes below (audited 2026-06-14)

This phase has moved beyond the partial state described in the original
2026-06-12 audit. Runtime client paths now use the kernel-backed
`openat2(RESOLVE_BENEATH)` flow documented in `src/path/README.md`: stream
handlers enter through `xrootd_resolve_op_path()` / `xrootd_path_resolve_beneath`,
HTTP/S3 have `conf->common.rootfd`, and `realpath(3)` is retained only for
trusted config-time policy canonicalisation. The older call-site map below is
kept as migration history and should not be quoted as current status without
rechecking `src/path/README.md` and the live callers.

**Step A — persistent rootfd + `beneath` API: ✅ DONE (stream + HTTP).**
`src/path/beneath.{c,h}` exist (`xrootd_open_beneath`, `xrootd_stat_beneath`,
`xrootd_unlink_beneath`, `xrootd_mkdir_beneath`, `xrootd_rename_beneath`,
`xrootd_link_beneath`, `xrootd_beneath_rel`). `int rootfd` lives in the **stream**
conf (`src/types/config.h:105`), opened per worker at `init_process`.

**HTTP rootfd infrastructure — ✅ DONE (2026-06-12).** The prerequisite that was
blocking all WebDAV/S3 migration is now built and tested:
- `int rootfd` added to the shared HTTP preamble `ngx_http_xrootd_shared_conf_t`
  (`src/config/shared_conf.h`), initialised to `-1` in `ngx_http_xrootd_shared_init`.
- New `src/config/http_rootfd.{c,h}`: `xrootd_http_open_rootfd()` opens the
  O_PATH rootfd right after `root_canon` is canonicalised in `merge_loc_conf`,
  and registers a `cf->pool` cleanup to close it on cycle teardown (reload-safe —
  no fd accumulation). Wired into both `webdav/config.c` and `s3/module.c` merge
  functions; registered in the `config` build source list.
- Verified: clean `./configure` + `make`; `nginx -t` passes; test servers restart
  on the new binary; **`tests/test_a_robustness.py` 43/43 green** (path-confinement
  regression baseline holds).

WebDAV/S3 handlers can now reach `conf->common.rootfd` — the migration in §"HTTP
migration" below is unblocked.

**Step B — migrate call sites: 🟡 PARTIAL.**

| Context | State |
|---|---|
| Stream — migrated (use `beneath`) | `read/statx.c`, `read/open_cache.c`, `read/open_resolved_file.c`, `connection/fd_table.c`, `fs/vfs_open.c` (with fallback), `read/truncate`… `write/truncate.c`, `query/prepare.c`, `tpc/launch.c`, `query/checksum_ckscan_common.c` |
| Stream — still OLD-only | `read/pgread.c`, `read/read.c`, `read/open_overview.c`, `aio/dirlist.c`, `write/chkpoint.c`, `write/mv.c` (12 old refs), `write/mkdir.c` |
| **HTTP (WebDAV + S3)** | **Superseded:** `ngx_http_xrootd_shared_conf_t` now carries `common.rootfd`; HTTP/S3 reach the beneath/confined primitives through the shared compat layer. See `src/path/README.md` for current status. |

**Step C — delete old stack: ❌ BLOCKED (correctly).** The old API is still called
from ~30+ sites: `xrootd_resolve_path` (9 callers), `xrootd_open_confined_canon`
(14), `xrootd_unlink_confined_canon` (13), `xrootd_mkdir_confined_canon` (8),
`xrootd_rename_confined_canon` (9) — spanning stream, `webdav/`, `s3/`, and
`compat/{namespace_ops,staged_file,fs_walk}.c`. Therefore `unified.c`,
`canonical.c`, `resolve_path_variants.c`, `resolve_confined_ops.c`, and
`resolve_confined_helpers.c` **cannot be removed** — they are not obsolete.

### "Obsolete components" check — nothing safely removable

The only dead artifacts found are **stale comments** in `resolve_confined_ops.c`
that reference the never-existent (or already-removed) `xrootd_unlink_confined` /
`xrootd_mkdir_confined` non-canon variants and `xrootd_resolve_path_either`.
`xrootd_open_confined_parent_canon` reads as "0 external callers" but is the
**internal helper** used throughout `resolve_confined_ops.c`, so it stays. No
file or function can be deleted until the migration below completes.

### Remaining work — precise call-site map (comment hits excluded; verified 2026-06-12)

Chosen approach: **Option Y (full Step C)** — remove userspace realpath, kernel-only
confinement. Order keeps the build green: behavior-preserving leaf swaps first
(`confined_canon(resolved)` → `beneath(rootfd, resolved+strlen(root_canon))`, which
is exactly what `confined_canon` did internally), then the realpath-core removal
last. ✅ = done, ☐ = remaining.

✅ **HTTP `rootfd` infrastructure** — done (see status box above).

☐ **compat/ layer (linchpin — shared by WebDAV+S3), thread `rootfd` + `beneath`:**
- `compat/namespace_ops.c` — `xrootd_ns_delete/mkdir/rename/local_copy`.
  ⚠️ does **raw `stat(path)`** (unconfined) — currently safe only because callers
  pass a realpath-confined path. Under Option Y these MUST become
  `xrootd_stat_beneath(rootfd, …)`. Signature gains a `rootfd`.
- `compat/fs_walk.c` (`xrootd_fs_remove_tree_confined`, `xrootd_fs_dir_is_empty`),
  `compat/staged_file.c` (`xrootd_staged_open/commit/abort`), `compat/copy_range.c` —
  all take absolute paths today; thread `rootfd`.

☐ **WebDAV + S3 direct callers** (now have `conf->common.rootfd`):
`webdav/{lock.c:376, put.c:167, copy.c:42/72, tpc_marker.c×4, tpc_thread.c×5,
fs/copy_engine.c×3}`, `s3/{put.c:343/354, object.c, multipart_complete_body.c×7,
multipart_initiate.c:71, multipart_helpers.c, delete_objects.c}`.

☐ **Stream leaf sites** (have `conf->rootfd`):
`write/mv.c` (resolve_path + rename), `write/chkpoint.c` (×3, internal),
`fs/vfs_open.c:239` (fallback), `query/util.c` (×3 — confirm live callers first;
memory flags these adler/crc helpers as possibly dead).

☐ **`path/op_path.c` + `path/unified.c` realpath core — the one behavior-changing,
highest-risk step, do LAST:** convert `xrootd_resolve_op_path` to fill `resolved`
via `xrootd_beneath_full_path` + an `xrootd_stat_beneath` existence gate
(preserving EXISTING/WRITE/NOEXIST/EITHER semantics, depth check, NUL/CGI strip,
forbidden-component checks currently inside `unified.c`). Also `path/mkdir.c`
recursive helper.

☐ **Step C deletion** — only once the above leave zero callers: delete
`resolve_confined_ops.c`, `resolve_confined_helpers.c`, `resolve_path_variants.c`,
`canonical.c`, the realpath core in `unified.c`; slim `normalize.c`/`helpers.c`;
update `config`; `./configure` + full suite.

Each migrated file needs the security-regression suite
(`pytest tests/test_a_robustness.py` — 43 tests, currently green) plus the
`EXDEV → kXR_NotAuthorized` mapping check, per the Risk Assessment below. The
realpath-core step additionally needs traversal/symlink/missing-parent/NUL/CGI
coverage because it changes intra-root symlink ACL semantics.

---

## Goal

Replace the userspace path-resolution and confinement stack (`realpath()` +
strncmp prefix check + per-call rootfd open) with direct `openat2(2)` calls
anchored on a **persistent rootfd** stored in server config.

After this phase:

- `xrootd_resolve_path()` and its three variants are deleted; there is nothing
  to resolve — the kernel enforces confinement.
- Every file operation uses `openat2(conf->rootfd, rel, &how)` where
  `how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`.
- `resolve_confined_helpers.c` and `resolve_confined_ops.c` shrink by ~80%;
  the fallback segment-by-segment path walker is removed.
- ~1,300 LoC of path-sanitisation machinery is deleted in exchange for a
  ~100 LoC wrapper file.

**Linux minimum requirement: kernel ≥ 5.6** (`openat2(2)` merged upstream
April 2020).  RHEL 8 (4.18) does not qualify.  The existing fallback path
(O_NOFOLLOW segment-by-segment) is removed — this is the explicit trade.

---

## Background: what exists today

### The two-step pattern used by every operation

Every handler currently performs two steps:

```c
/* Step 1: userspace path resolution — realpath() + prefix check */
char resolved[PATH_MAX];
if (!xrootd_resolve_path(c->log, &conf->common.root,
                          reqpath, resolved, sizeof(resolved))) {
    /* ENOENT → kXR_NotFound */
}

/* Step 2: confined open — opens rootfd, computes relative path, calls openat2 */
int fd = xrootd_open_confined_canon(c->log, root_canon, resolved,
                                     O_RDONLY, 0);
```

Step 1 calls `xrootd_path_resolve_cstr()` → `realpath()` → multiple `lstat()`
syscalls + strncmp prefix check.  Step 2 opens a fresh rootfd with `open()`,
computes a relative path, then calls `openat2()` — and closes the rootfd.

### What `openat2(RESOLVE_BENEATH)` already provides

From `src/path/resolve_confined_helpers.c`:

```c
static int
xrootd_openat2_confined(int rootfd, const char *rel, int flags, mode_t mode)
{
    struct open_how how;
    ngx_memzero(&how, sizeof(how));
    how.flags   = (uint64_t)(flags | O_CLOEXEC);
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    if (flags & O_CREAT) { how.mode = (uint64_t)mode; }
    return (int)syscall(SYS_openat2, rootfd, rel, &how, sizeof(how));
}
```

The kernel already enforces:
- **`..` traversal blocked** — `RESOLVE_BENEATH` refuses `..` that would escape.
- **Symlinks to outside blocked** — any symlink whose target escapes rootfd's
  subtree is rejected with `EXDEV`.
- **Magic links blocked** — `/proc/<pid>/fd` and similar kernel pseudo-symlinks
  are rejected with `ELOOP`.

This means `realpath()` is redundant.  Once the call succeeds, the file is
within the export root by kernel guarantee.

### The per-call rootfd cost

Every `xrootd_open_confined_canon()` call today does:

```c
rootfd = xrootd_open_root_fd(log, root_canon);   /* open() syscall */
/* ... use rootfd ... */
close(rootfd);                                     /* close() syscall */
```

Two extra syscalls per operation.  A persistent rootfd in the server config
eliminates both.

---

## Current State Inventory

### `src/path/` files involved

| File | LoC | Role | Fate |
|---|---|---|---|
| `resolve_confined_helpers.c` | 438 | rootfd open, fallback walker, openat2 wrapper | Keep ~80 LoC; delete fallback |
| `resolve_confined_ops.c` | 414 | open/unlink/mkdir/rename/link confined ops | Keep ~60 LoC; delete fallback paths |
| `resolve_path_variants.c` | 70 | `xrootd_resolve_path*()` four-variant family | **Delete entirely** |
| `canonical.c` | 63 | `xrootd_get_canonical_root()`, canonicalize_path | **Delete entirely** |
| `normalize.c` | 84 | path normalization (clean `//`, trailing `/`) | Reduce to strip helper (~20 LoC) |
| `helpers.c` | 179 | `xrootd_path_component_forbidden`, sanitize log | Reduce to log helper (~40 LoC) |
| `unified.c` | 663 | `xrootd_path_resolve_cstr()` — the realpath core | **Delete realpath logic** (~400 LoC) |

### `src/compat/` files involved

| File | LoC | Role | Fate |
|---|---|---|---|
| `namespace_ops.c` | 303 | mkdir/rm/rename/copy orchestration | Keep; change path handling |
| `fs_walk.c` | 326 | confined directory walk for recursive rm | Keep; update to use rootfd |

### Call sites outside `path/` and `compat/`

~60 sites across 14 files; the Phase 3 `xrootd_resolve_op_path()` migration
will have already cleaned up the majority before Phase 8 starts.

Remaining direct callers after Phase 3:

| File | Call | Notes |
|---|---|---|
| `src/connection/fd_table.c` | `xrootd_open_confined()` | fd_table open |
| `src/dirlist/handler.c` | `xrootd_resolve_path()`, `xrootd_open_confined()` | directory listing |
| `src/fattr/dispatch.c` | `xrootd_resolve_path()` | extended attributes |
| `src/fs/vfs_open.c` | `xrootd_open_confined_canon()` | VFS open |
| `src/query/checksum_ckscan_*.c` | `xrootd_open_confined_canon()`, `xrootd_resolve_path()` | checksum scan |
| `src/query/checksum_qcksum.c` | `xrootd_resolve_path()`, `xrootd_open_confined()` | on-demand checksum |
| `src/query/metadata.c` | `xrootd_resolve_path()` | metadata query |
| `src/read/locate.c` | `xrootd_resolve_path()` | locate response |
| `src/read/open_cache.c` | `xrootd_open_confined_canon()` | cache-layer open |
| `src/read/open_request.c` | `xrootd_resolve_path_write()` | file open |
| `src/read/open_resolved_file.c` | `xrootd_open_confined_canon()` | post-resolve open |
| `src/read/pgread.c` | `xrootd_resolve_path()` | pgread path check |
| `src/read/stat.c` | `xrootd_resolve_path()` | stat handler |

---

## New Design

### 1. Persistent rootfd in server config

Add one field to `ngx_stream_xrootd_srv_conf_t` (in `src/config/config.h`):

```c
int  rootfd;          /* O_PATH fd on export root; -1 until worker init */
```

Initialise once per worker:

```c
/* src/upstream/bootstrap.c (or session/lifecycle.c) — init_process hook */
static ngx_int_t
xrootd_init_process(ngx_cycle_t *cycle)
{
    ngx_stream_xrootd_srv_conf_t *conf = ...;

    conf->rootfd = open(conf->common.root_canon,
                        O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (conf->rootfd < 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, errno,
                      "xrootd: unable to open export root \"%s\"",
                      conf->common.root_canon);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* exit_process hook */
static void
xrootd_exit_process(ngx_cycle_t *cycle)
{
    if (conf->rootfd >= 0) {
        close(conf->rootfd);
        conf->rootfd = -1;
    }
}
```

### 2. New `xrootd_open_beneath()` API

New file `src/path/beneath.h` + `src/path/beneath.c` (~100 LoC total):

```c
/* beneath.h */
#pragma once
#include <fcntl.h>
#include <sys/stat.h>
#include <ngx_core.h>

/*
 * xrootd_open_beneath — open a file under kernel confinement.
 *
 * rootfd   : O_PATH fd on the export root (conf->rootfd).
 * reqpath  : client-supplied path, absolute ("/data/file.root") or relative.
 * flags    : O_RDONLY / O_WRONLY / O_RDWR / O_CREAT etc.
 * mode     : permission bits; only used when O_CREAT is set.
 *
 * Returns fd >= 0 on success, -1 on failure (errno set by kernel).
 * The kernel enforces RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS — no
 * userspace prefix check or realpath() is needed.
 */
int xrootd_open_beneath(int rootfd, const char *reqpath,
                         int flags, mode_t mode);

int xrootd_stat_beneath(int rootfd, const char *reqpath, struct stat *st);
int xrootd_unlink_beneath(int rootfd, const char *reqpath, int is_dir);
int xrootd_mkdir_beneath(int rootfd, const char *reqpath, mode_t mode);
int xrootd_rename_beneath(int rootfd, const char *src, const char *dst);
int xrootd_link_beneath(int rootfd, const char *src, const char *dst);

/* Strip a leading '/' from an absolute client path.
 * Returns a pointer into reqpath (no copy). */
static inline const char *
xrootd_beneath_rel(const char *reqpath)
{
    return (reqpath[0] == '/') ? reqpath + 1 : reqpath;
}
```

```c
/* beneath.c — ~80 LoC */
#include "beneath.h"
#include <sys/syscall.h>
#include <linux/openat2.h>
#include <string.h>
#include <unistd.h>

static int
do_openat2(int rootfd, const char *rel, int flags, mode_t mode)
{
    struct open_how how;
    ngx_memzero(&how, sizeof(how));
    how.flags   = (uint64_t)(flags | O_CLOEXEC);
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    if (flags & O_CREAT) { how.mode = (uint64_t)mode; }
    return (int)syscall(SYS_openat2, rootfd, rel, &how, sizeof(how));
}

int
xrootd_open_beneath(int rootfd, const char *reqpath, int flags, mode_t mode)
{
    return do_openat2(rootfd, xrootd_beneath_rel(reqpath), flags, mode);
}

int
xrootd_stat_beneath(int rootfd, const char *reqpath, struct stat *st)
{
    int fd = do_openat2(rootfd, xrootd_beneath_rel(reqpath),
                        O_PATH | O_NOFOLLOW, 0);
    if (fd < 0) { return -1; }
    int rc = fstat(fd, st);
    close(fd);
    return rc;
}

int
xrootd_unlink_beneath(int rootfd, const char *reqpath, int is_dir)
{
    return unlinkat(rootfd, xrootd_beneath_rel(reqpath),
                    is_dir ? AT_REMOVEDIR : 0);
}

int
xrootd_mkdir_beneath(int rootfd, const char *reqpath, mode_t mode)
{
    return mkdirat(rootfd, xrootd_beneath_rel(reqpath), mode);
}

int
xrootd_rename_beneath(int rootfd, const char *src, const char *dst)
{
    return renameat(rootfd, xrootd_beneath_rel(src),
                    rootfd, xrootd_beneath_rel(dst));
}

int
xrootd_link_beneath(int rootfd, const char *src, const char *dst)
{
    return linkat(rootfd, xrootd_beneath_rel(src),
                  rootfd, xrootd_beneath_rel(dst), 0);
}
```

Note: `unlinkat`, `mkdirat`, and `renameat` do not accept `open_how` but ARE
anchored on `rootfd` and accept relative paths — a malicious `..` in a relative
path to `unlinkat` is handled by the kernel's standard `..` resolution rules,
which for an `O_PATH` fd with no flags does not enforce RESOLVE_BENEATH.  The
security guarantee for delete/mkdir/rename is the `openat2` check that already
produced `resolved` before reaching these calls.  If stricter confinement for
non-open operations is needed, open a directory fd with `openat2(RESOLVE_BENEATH)`
first, then operate on the base name.

---

## Migration Plan

Phase 8 is executed in three ordered sub-steps:

### Step A — Persistent rootfd (non-breaking)

1. Add `int rootfd` field to `ngx_stream_xrootd_srv_conf_t`, initialised to
   `-1` in `create_srv_conf`.
2. Open in `init_process` hook; close in `exit_process` hook.
3. Add `beneath.h` + `beneath.c`; register `beneath.c` in `config.h`.
4. Build, run full test suite.  No behaviour change yet.

### Step B — Migrate call sites to `xrootd_open_beneath()`

Replace the two-step `resolve_path` + `open_confined` pattern at each call
site with a single `xrootd_open_beneath()` call.  Migrate in file order:

1. `src/connection/fd_table.c`
2. `src/fs/vfs_open.c`
3. `src/read/open_resolved_file.c`
4. `src/read/open_cache.c`
5. `src/read/stat.c`, `pgread.c`, `locate.c`
6. `src/dirlist/handler.c`
7. `src/query/` files (checksum, metadata)
8. `src/fattr/dispatch.c`
9. `src/read/open_request.c` (most complex; last)

After each file, build + run targeted tests for that subsystem.

### Step C — Delete dead code

Once all call sites are on `xrootd_open_beneath()`:

1. Delete `src/path/resolve_path_variants.c`
2. Delete `src/path/canonical.c`
3. Delete the `realpath` logic in `src/path/unified.c` (down to ~200 LoC)
4. Delete the fallback walker from `src/path/resolve_confined_helpers.c`
5. Delete `src/path/resolve_confined_ops.c` (all callers gone)
6. Slim `src/path/normalize.c` to the strip helper only
7. Slim `src/path/helpers.c` to the log-sanitise helper only
8. Remove unneeded entries from `config.h`; run `./configure` + `make`.

---

## Concrete Before/After

### `src/read/stat.c` — before

```c
/* ~25 lines today */
char reqpath[XROOTD_MAX_PATH + 1];
char resolved[PATH_MAX];

if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                          reqpath, sizeof(reqpath), 1)) {
    XROOTD_RETURN_ERR(..., kXR_ArgInvalid, "invalid path payload");
}
if (xrootd_count_path_depth(reqpath) != NGX_OK) {
    XROOTD_RETURN_ERR(..., kXR_ArgInvalid, "path exceeds maximum depth");
}
if (!xrootd_resolve_path(c->log, &conf->common.root,
                          reqpath, resolved, sizeof(resolved))) {
    XROOTD_RETURN_ERR(..., kXR_NotFound, "invalid path");
}

struct stat st;
if (stat(resolved, &st) != 0) {
    XROOTD_RETURN_ERR(..., kXR_NotFound, "not found");
}
```

### `src/read/stat.c` — after

```c
/* ~10 lines */
char reqpath[XROOTD_MAX_PATH + 1];

if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                          reqpath, sizeof(reqpath), 1)) {
    XROOTD_RETURN_ERR(..., kXR_ArgInvalid, "invalid path payload");
}

struct stat st;
if (xrootd_stat_beneath(conf->rootfd, reqpath, &st) != 0) {
    XROOTD_RETURN_ERR(..., kXR_NotFound, "not found");
}
```

Path depth check is still appropriate before sending to the kernel (defence in
depth against deep path DoS), but can be inlined at the extract step.  The
`xrootd_resolve_path()` + `stat(resolved, ...)` pair collapses to a single
`xrootd_stat_beneath()` call.

---

### `src/read/open_resolved_file.c` — before

```c
int fd = xrootd_open_confined_canon(c->log, root_canon, resolved,
                                     O_RDONLY, 0);
```

### `src/read/open_resolved_file.c` — after

```c
int fd = xrootd_open_beneath(conf->rootfd, ctx->reqpath, O_RDONLY, 0);
```

The `resolved` buffer (computed from `realpath()`) is no longer needed.
`ctx->reqpath` is the client-supplied path; the kernel enforces confinement.

---

### `src/write/rmdir.c` — before (after Phase 3)

```c
/* Phase 3 already consolidated to: */
if (xrootd_resolve_op_path(..., XROOTD_PATH_EITHER,
                            reqpath, sizeof(reqpath),
                            resolved, sizeof(resolved)) != NGX_OK) {
    return ctx->write_rc;
}
if (xrootd_unlink_confined_canon(c->log, root_canon, resolved, 1) != 0) {
    XROOTD_RETURN_ERR(..., kXR_IOError, strerror(errno));
}
```

### `src/write/rmdir.c` — after Phase 8

```c
if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                          reqpath, sizeof(reqpath), 1)) {
    XROOTD_RETURN_ERR(..., kXR_ArgInvalid, "invalid path payload");
}
if (xrootd_unlink_beneath(conf->rootfd, reqpath, 1) != 0) {
    XROOTD_RETURN_ERR(..., xrootd_kxr_from_errno(errno),
                      xrootd_kxr_err_string(errno));
}
```

`EXDEV` from the kernel = path escape attempt; the kernel's error is as
authoritative as any userspace prefix check.

---

## LoC Delta Table

| File | Current LoC | After | Delta |
|---|---|---|---|
| `src/path/resolve_confined_helpers.c` | 438 | ~80 | −358 |
| `src/path/resolve_confined_ops.c` | 414 | 0 (deleted) | −414 |
| `src/path/resolve_path_variants.c` | 70 | 0 (deleted) | −70 |
| `src/path/canonical.c` | 63 | 0 (deleted) | −63 |
| `src/path/normalize.c` | 84 | ~20 | −64 |
| `src/path/helpers.c` | 179 | ~40 | −139 |
| `src/path/unified.c` | 663 | ~250 | −413 |
| `src/compat/namespace_ops.c` | 303 | ~200 | −103 |
| `src/compat/fs_walk.c` | 326 | ~250 | −76 |
| `src/path/beneath.h` (new) | 0 | +45 | +45 |
| `src/path/beneath.c` (new) | 0 | +80 | +80 |
| **Net** | | | **−1,575** |

Conservative estimate after accounting for missed deletions and partial
migrations: **−1,080 LoC**.

---

## Files Added / Removed from `config.h`

```
# Add:
$ngx_addon_dir/src/path/beneath.c

# Remove (Step C):
$ngx_addon_dir/src/path/resolve_confined_helpers.c
$ngx_addon_dir/src/path/resolve_confined_ops.c
$ngx_addon_dir/src/path/resolve_path_variants.c
$ngx_addon_dir/src/path/canonical.c
$ngx_addon_dir/src/path/normalize.c     (replaced by strip helper in beneath.h)
```

Requires `./configure` twice: once after Step A, once after Step C.

---

## Kernel Version Gate

The build must refuse to compile on kernels without openat2 support:

```c
/* src/path/beneath.c top of file */
#include <linux/openat2.h>

#ifndef RESOLVE_BENEATH
#error "openat2(2) with RESOLVE_BENEATH required — kernel headers too old (need >= 5.6)"
#endif

#ifndef SYS_openat2
#error "SYS_openat2 not defined — kernel headers too old (need >= 5.6)"
#endif
```

At nginx configure time, add a feature test in `config.h`'s `ngx_feature_*`
block:

```makefile
# In src/config/config.h, after existing feature tests:
ngx_feature="openat2(2) RESOLVE_BENEATH"
ngx_feature_name="NGX_XROOTD_HAVE_OPENAT2_BENEATH"
ngx_feature_run=no
ngx_feature_incs="#include <linux/openat2.h>"
ngx_feature_test="RESOLVE_BENEATH"
. auto/feature
if [ $ngx_found != yes ]; then
    echo "nginx-xrootd requires Linux kernel headers >= 5.6 (openat2)"
    exit 1
fi
```

---

## Verification

```bash
# Step A: persistent rootfd only
make -j$(nproc) 2>&1 | grep "^error:" | wc -l   # Expected: 0
tests/manage_test_servers.sh restart
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q

# After each Step B file migration: run file-specific tests
PYTHONPATH=tests pytest tests/test_conformance.py -k "stat"       # after stat.c
PYTHONPATH=tests pytest tests/test_conformance.py -k "dirlist"    # after dirlist
PYTHONPATH=tests pytest tests/test_conformance.py -k "checksum"   # after query/
PYTHONPATH=tests pytest tests/test_aio.py -v                      # after open_request

# Security regression tests (path escape attempts)
PYTHONPATH=tests pytest tests/test_a_robustness.py -k "escape or traversal or symlink" -v

# Step C: deletion
./configure --with-stream --with-http_ssl_module --with-http_dav_module \
            --with-threads --add-module=$REPO
make -j$(nproc) 2>&1 | grep "^error:" | wc -l

# Full suite
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

Key test: path traversal attempts must still return `kXR_NotAuthorized` (not
open or crash):

```python
# Confirm kernel EXDEV → kXR_NotAuthorized for escape attempts
xrdcp root://localhost:11094//../../etc/passwd /tmp/out
# Expected: kXR_NotAuthorized (3010)
```

---

## Risk Assessment

**High.**  This is the confinement boundary.  Any regression is a security
vulnerability, not just a functional bug.

**Risk 1: Wrong kernel error → wrong kXR status.**  When `openat2` returns
`EXDEV` (path escape), the handler must map this to `kXR_NotAuthorized` (3010),
not `kXR_IOError` (3007).  Add a special case in `xrootd_kxr_from_errno()`:

```c
case EXDEV: return kXR_NotAuthorized;
```

**Risk 2: `unlinkat` / `mkdirat` not kernel-confined.**  These syscalls take a
dirfd but do not support `open_how`.  For operations where the client path
includes `..`, the kernel's `..` resolution on a non-openat2 call may allow
escape.  Mitigation: call `openat2(rootfd, parent_dir, O_PATH | O_DIRECTORY,
RESOLVE_BENEATH)` first; then operate on the basename under the confined parent
fd.  This is equivalent to what `resolve_confined_ops.c` already does — just
without the userspace resolve step.

**Risk 3: Worker rootfd leak after reload.**  nginx reload forks new workers and
sends `SIGQUIT` to old ones.  The `exit_process` hook closes `rootfd` in the
dying worker.  Verify by running `lsof` after 10 reloads and confirming no fd
accumulation.

**Risk 4: Slow directory walks.**  `fs_walk.c` (recursive rm) currently
traverses the directory tree by constructing absolute paths.  After Phase 8, it
must use `openat` relative to a directory fd per level.  The walk logic needs
updating but the existing `O_PATH | O_DIRECTORY` pattern works.

**Mitigation across all risks:** migrate one file at a time (Step B), run
the security regression suite after each file.  Do not merge Step C until the
full suite passes with zero failures.

---

## Rollback

```bash
git revert <phase-8a-commit> <phase-8b-commit> <phase-8c-commit>
./configure --with-stream --with-http_ssl_module --with-http_dav_module \
            --with-threads --add-module=$REPO
make -j$(nproc)
```

Because Steps A, B, C are separate commits, partial rollback is clean: reverting
only Step C restores the old files while keeping Step B's simplified callers
(they will compile against the old API since Step B changes callers to use
`xrootd_open_beneath()` which is additive until Step C removes the old API).

---

## Summary

| | Before | After |
|---|---|---|
| Path resolution model | userspace `realpath()` + strncmp | kernel `RESOLVE_BENEATH` |
| rootfd | opened + closed per operation | persistent, opened once at worker init |
| Path resolution LoC | ~1,700 | ~370 |
| Confinement guarantee | userspace (bypassable via TOCTOU) | kernel (atomic) |
| Minimum kernel | 5.6 (runtime probe, fallback on older) | 5.6 (hard build requirement) |
| Net LoC change | — | −1,080 (conservative) |
