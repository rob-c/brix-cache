# Phase 60 — Ceph/RADOS storage backend, routed through the VFS — hyper-detailed design record

**Status:** plan / spec — **basic driver landed.** `src/fs/backend/sd_ceph.c`
(the `xrootd_sd_ceph_driver`) now ships: a flat LFN→RADOS-object-key map plus the
data plane over raw `librados` (`rados_read`/`write`/`trunc`/`stat`/`remove`),
compiled only when `./configure` finds librados (`XROOTD_HAVE_CEPH`) — otherwise
the file contributes only its pure libc LFN→key helpers and the registry row is
`#if`-compiled out (a no-Ceph build is byte-for-byte unchanged). Caps: range-read,
random-write, truncate (no fd ⇒ memory-backed reads, no dirs, no atomic rename).
A standalone `sd_ceph_unittest.c` covers the security-critical key map. **Still
open (the W-plan below):** live-traffic *selection*/routing of the bound
`xrootd_sd_obj_t` to this driver, libradosstriper interop with stock XrdCeph,
directory listing, rename, xattr, and staged commit. See
[`../../src/fs/backend/README.md`](../../src/fs/backend/README.md).
**Date:** 2026-06-27 · **Revised:** 2026-06-28 (re-baselined onto the unified `vfs`+`backend` core)
**Owner decisions:** see §Z (ADR log)
**Scope:** (a) finish de-POSIX-pinning the VFS data plane and (b) add one Ceph
Storage Driver `src/fs/backend/sd_ceph.c` that the VFS dispatches to — plus build
plumbing, config directives, per-worker cluster lifecycle, a single-node Ceph test
harness, and docs. **No protocol changes; no C++ plugin ABI; no RADOS symbol
anywhere above `src/fs/backend/`.**

> **Re-baseline note (2026-06-28).** The original W0 ("make the VFS data plane
> driver-generic") was written when the VFS verb loops still called the POSIX
> driver by name. The **unified VFS layering** work (waves 1–3 of
> [`docs/superpowers/specs/2026-06-27-unified-vfs-layering-design.md`](../superpowers/specs/2026-06-27-unified-vfs-layering-design.md))
> has since landed `src/fs/core/vfs_core.c` — the shared, ngx-free verb layer whose
> EINTR/short-I/O loops already dispatch through `obj->driver->*`. That is exactly
> the "one true change" the old §A.2 proposed, and it is now **done for both
> trees**: the server's `xrootd_vfs_pread_full`/`xvfs_*` wrappers *and* the
> userland clients (`client/lib/vfs_posix.c`, `vfs_block.c`) all run the same
> backend-neutral core. Two consequences for this phase:
> 1. **W0 shrinks.** The loop generalization is paid for; what remains is purely
>    *threading the bound `xrootd_sd_obj_t` from open → fd-table slot → io job*
>    instead of a bare fd (the boundary still POSIX-wraps an fd — see §0.1).
> 2. **Ceph becomes reachable from the clients for ~free.** Because `xrdcp` /
>    `xrootdfs` already ride the shared `vfs` core, an `sd_ceph` driver registered
>    as a client backend gives `root://…`-over-Ceph reads/writes from the native
>    tools with no second implementation (new **W5b**, §12).

---

## 0. The layering requirement (read this first)

Every byte of file I/O and every namespace mutation for a Ceph export MUST flow
**proto → VFS → SD driver → RADOS**. Nothing above `src/fs/` ever sees a
`rados_*` symbol; the protocol handlers (`src/protocols/root/read`, `src/protocols/root/write`, `src/protocols/webdav`,
`src/protocols/s3`, `src/tpc`) keep talking to the **VFS** (`src/fs/vfs*.c`) exactly as they
do for POSIX, and the VFS — not the handler — selects and calls the backend.

```
        ┌──────────────── protocol handlers (unchanged) ────────────────┐
        │ root:// read/write/readv/pgread/pgwrite/sync/truncate          │
        │ WebDAV/S3 GET/PUT/DELETE/PROPFIND   TPC   stat/dirlist/mkdir   │
        └───────────────────────────┬───────────────────────────────────┘
                                     │  xrootd_vfs_* API only
                       ┌─────────────▼──────────────┐
                       │   vfs_server (confined)     │  src/fs/vfs*.c
                       │ open(RESOLVE_BENEATH)/aio/  │  nginx-coupled policy shell
                       │ sendfile/metrics/staged     │
                       └─────────────┬──────────────┘
                                     │  obj + verbs
                       ┌─────────────▼──────────────┐      client (xrdcp/xrootdfs)
                       │   vfs core  (ngx-free)      │◀──── shares this layer
                       │ src/fs/core/vfs_core.c —    │      (waves 1–3, DONE)
                       │ pread/pwrite/fstat/trunc/   │
                       │ sync loops over obj->driver │
                       └─────────────┬──────────────┘
                                     │  xrootd_sd_driver_t vtable (caps-typed)
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                        ▼
      sd_posix.c (default)     sd_ceph.c  (NEW)        sd_block.c, sd_s3.c …
        POSIX fd I/O          librados + striper
```

The `vfs core` row is the recently-landed shared layer: it is already
driver-generic (its loops call `obj->driver->pread/...`, never `sd_posix_*`) and is
the **same code the userland clients run**. W0 below is what is left to let a no-fd
backend actually *reach* that generic core through the server's open + handle path.

This is the existing data-plane invariant (CLAUDE.md #11: *“raw `pread`/`pwrite`
… on file data live ONLY in `src/fs/backend/`”*) generalized from
"data-POSIX confinement" to **data-backend confinement**: the only file that may
`#include <rados/librados.h>` is `sd_ceph.c`.

### 0.1 Why this needs work: the loop layer is generic, the *handle* path is still POSIX-pinned

Three facts from the current tree (post-unification):

- **Good (seam):** `xrootd_vfs_ctx_t` already carries `xrootd_sd_instance_t *sd`
  (the bound driver instance, or NULL ⇒ default POSIX). The seam, capability model,
  and no-`CAP_FD` read fallback all exist (Phase 55).
- **Good (loop layer, NEW):** the EINTR/short-I/O verb bodies now live in
  `src/fs/core/vfs_core.c` (`xvfs_pread_full`/`xvfs_pwrite_full`/`xvfs_fsync`/
  `xvfs_ftruncate`/`xvfs_fstat`) and dispatch through `obj->driver->...`. They name
  **no** `sd_posix_*` symbol. This is the loop generalization the old W0 plan
  scheduled (old §A.2) — already done, and shared with the clients.
- **Gap (the remainder):** the *handle path* into that generic loop is still a bare
  fd that gets POSIX-wrapped at the server boundary:
  - `xrootd_vfs_pread_full(ngx_fd_t fd, …)` (`vfs_read.c`) and the sync/truncate
    executors in `vfs_io_core.c` do `xrootd_sd_posix_wrap(&obj, job->fd)` *then*
    call the generic core — i.e. POSIX is re-pinned one frame above the generic loop.
  - the io job (`xrootd_vfs_job_t`, `vfs_io_core.h`) carries `ngx_fd_t fd`, not an
    `xrootd_sd_obj_t *obj`; `xrootd_vfs_job_read_init(job, fd, …)`.
  - the fd-table slot (`xrootd_file_t`, `src/core/types/file.h:54`) holds `int fd`, no
    driver object; the upper handlers pass a raw `ctx->files[idx].fd`.
  - `xrootd_vfs_open()` produces a bare fd; the io-core validity guards key on
    `job->fd == NGX_INVALID_FILE`.

So a **no-fd** backend (RADOS) still cannot ride the path — not because the loop is
POSIX (it no longer is) but because everything that *feeds* the loop traffics in a
fd. **W0 (now smaller) threads the bound `xrootd_sd_obj_t` end-to-end** —
open → fd-table slot → io job → the already-generic core — and removes the
boundary `xrootd_sd_posix_wrap`. That is the prerequisite that turns "Ceph through
the VFS" from aspiration into mechanism, and every future non-POSIX backend reuses
it.

---

## 1. The SD seam (what a driver implements)

`xrootd_sd_driver_t` (`src/fs/backend/sd.h`): `.name`, `.caps`, ~25 function
pointers. Driver template = `sd_posix.c`: a `static const` driver, a private
per-instance `state`, and `xrootd_sd_obj_t` carrying `driver`/`inst`/`fd`.
Registration = append the symbol to `sd_drivers[]` in `sd_registry.c` and the
source to `./config`. Capabilities advertise what the VFS may do (e.g. only emit
a `sendfile` buffer when `CAP_SENDFILE`).

---

## 2. RADOS reality → capability bitmap

RADOS is a flat, striped object store: no kernel fd, no `sendfile`, no real
directory tree, no atomic rename. The Ceph driver advertises:

```c
.caps = XROOTD_SD_CAP_RANGE_READ      /* rados_striper_read at any offset      */
      | XROOTD_SD_CAP_RANDOM_WRITE    /* rados_striper_write at any offset      */
      | XROOTD_SD_CAP_TRUNCATE        /* rados_striper_trunc                    */
      | XROOTD_SD_CAP_XATTR           /* rados (striper) xattr / omap           */
      | XROOTD_SD_CAP_SERVER_COPY;    /* object read→write copy                 */
/* ABSENT (each already handled by the VFS):
 *   CAP_FD / CAP_SENDFILE  → no fd; VFS serves reads memory-backed
 *   CAP_DIRS               → key-prefix namespace (like S3)
 *   CAP_HARD_RENAME        → no atomic rename → copy+delete
 *   CAP_IOURING / CAP_FSCS / CAP_APPEND
 */
```

Reference = `XrdCeph` (~3,400 LoC C++, centred on `XrdCephPosix.cc` ~1,600 LoC
over `librados`+`libradosstriper`+`rados_aio`); we re-use the libraries, implement
only the SD slots, and skip the XrdOss glue.

---

## 3. W0 — make the VFS data plane driver-generic (the enabling work)

This is the heart of "go through the VFS." It is **backend-neutral** and lands
*before* any Ceph code; POSIX stays the default and behaves identically.

### 3.1 The io_core job carries the driver object, not a bare fd
`xrootd_vfs_job_t` (`vfs_io_core.h`) today has `ngx_fd_t fd`. Add a bound handle:
```c
xrootd_sd_obj_t *obj;   /* IN: the open backend object (driver lives in obj->driver) */
```
Keep `fd` for the POSIX fast paths that legitimately want it (sendfile, io_uring),
but it becomes derived (`xrootd_sd_fd(obj)`), not the dispatch key.

### 3.2 `xrootd_vfs_io_execute()` dispatches on `obj->driver`
The EINTR/short-I/O loops already dispatch generically — they were moved into
`src/fs/core/vfs_core.c` (`xvfs_pread_full`/`xvfs_pwrite_full`/`xvfs_fsync`/…) by
the unified-VFS work and call `obj->driver->pread/...` each iteration. **The only
residue is the boundary that re-POSIX-pins before entering them:**
```c
/* TODAY (vfs_io_core.c / vfs_read.c): generic loop, but fed a posix-wrapped fd */
xrootd_sd_posix_wrap(&obj, job->fd);
rc = xvfs_pwrite_full(&obj, buf, len, off, &w, &sh);   /* generic core, posix obj */
/* W0 TARGET: carry the bound obj, drop the wrap */
rc = xvfs_pwrite_full(job->obj, buf, len, off, &w, &sh);
```
So W0 §3.2 is no longer "replace the hardcoded POSIX call inside the loop" (done) —
it is "stop synthesizing a POSIX obj at the boundary and pass `job->obj` straight
through." Same for the `pread`/`fsync`/`ftruncate` executors. After this, the
string `xrootd_sd_posix_wrap` appears nowhere in `vfs_io_core.c`/`vfs_read.c`.

### 3.3 The open handle binds the driver object
`xrootd_vfs_open()` already has `ctx->sd`. Make it:
```c
const xrootd_sd_driver_t *drv = ctx->sd ? ctx->sd->driver
                                        : xrootd_sd_default_driver();
xrootd_sd_obj_t *obj = ctx->sd ? ctx->sd->driver->open(ctx->sd, path, sdflags, mode, &e)
                               : <posix open beneath rootfd>;
```
and store `obj` in the opaque `xrootd_vfs_file_t`. `xrootd_vfs_file_fd()` returns
`xrootd_sd_fd(obj)` (a real fd for POSIX, `NGX_INVALID_FILE` for Ceph);
`xrootd_vfs_file_sendfile_fd()`/`_can_sendfile()` already gate on
`CAP_FD|CAP_SENDFILE`, so they correctly return invalid/0 for Ceph.

### 3.4 The fd-table slot carries the VFS handle
`xrootd_file_t` (`src/core/types/file.h`) holds `int fd`. Add:
```c
xrootd_vfs_file_t *vfs;   /* the backend-generic open handle (NULL for legacy fd-only slots) */
```
The protocol handlers that build io jobs from `ctx->files[idx].fd`
(`src/protocols/root/read/read.c`, `src/protocols/root/write/write.c`, `readv.c`, `pgread.c`, `pgwrite.c`,
`sync.c`, `truncate.c`) instead build them from `ctx->files[idx].vfs` →
`job.obj = xrootd_vfs_file_obj(vfs)`. For POSIX nothing observable changes (the
obj wraps the same fd). This is the change that lets a no-fd backend reach the io
core at all.

### 3.5 Namespace + GET paths already call the VFS — just verify generic dispatch
- WebDAV/S3 **GET**: `xrootd_vfs_open` + `xrootd_vfs_file_sendfile_fd()` (→ invalid
  for Ceph) + memory-backed read via the VFS read job → `driver->pread`. Confirm
  every `sendfile_fd` consumer falls back to a copy-in read (it's the design;
  audit the call sites).
- **stat/dirlist/mkdir/rm/mv/xattr**: `xrootd_vfs_stat/opendir/mkdir/unlink/
  rename/getxattr…` already route to `ctx->sd->driver->*`; verify none shortcut to
  `openat2`/`rootfd` when `ctx->sd` is set.
- **PUT/upload**: `xrootd_vfs_staged_open/write/commit/abort` → `driver->staged_*`.
- **TPC / COPY**: `xrootd_vfs_copy` → `driver->server_copy`/`copy_range` (or a VFS
  read→write stream when the driver lacks `CAP_SERVER_COPY`).

### 3.6 Guardrails
- POSIX default unchanged: `ctx->sd == NULL` → default driver, `CAP_FD|CAP_SENDFILE`
  → sendfile/io_uring fast paths intact; existing tests must stay byte-for-byte
  green (regression gate for W0 before any Ceph work).
- A grep gate (`scripts`/CI): no `rados_` / `librados` outside `src/fs/backend/`.

---

## 4. Per-protocol data-flow (how each op reaches RADOS via the VFS)

| Client op | Handler | VFS call | Driver slot | RADOS |
|---|---|---|---|---|
| root:// `kXR_read` | `read/read.c` | io job `op=READ`, `obj` from slot | `pread` | `rados_striper_read` |
| `kXR_readv` | `read/readv.c` | io job `op=READV` | `preadv` (loop) | per-seg `rados_striper_read` |
| `kXR_pgread` | `read/pgread.c` | io job + CRC32c on the copied buf | `pread` | `rados_striper_read` |
| `kXR_write`/`pgwrite`/`writev` | `write/*.c` | io job `op=WRITE` | `pwrite` | `rados_striper_write` |
| `kXR_sync` | `write/sync.c` | io job `op=SYNC` | `fsync` (no-op) | — |
| `kXR_truncate` | `write/truncate.c` | io job `op=TRUNCATE` | `ftruncate` | `rados_striper_trunc` |
| `kXR_stat`/`statx` | `read/stat.c` | `xrootd_vfs_(file_)stat` | `fstat`/`stat` | `rados_striper_stat` |
| `kXR_dirlist` | `dirlist/handler.c` | `xrootd_vfs_opendir/readdir` | `opendir`/`readdir` | `rados_nobjects_list_*` |
| `kXR_mkdir`/`rm`/`rmdir`/`mv` | `write/*.c` | `xrootd_vfs_mkdir/unlink/rmdir/rename` | namespace slots | object ops |
| WebDAV/S3 **GET** | `webdav/get.c`,`s3/get.c` | `vfs_open`+`can_sendfile`(0)+read job | `pread` | `rados_striper_read` |
| WebDAV/S3 **PUT** | `webdav/put.c`,`s3/put.c` | `vfs_staged_*` | `staged_*` | temp object → commit |
| TPC / COPY | `tpc/*`,`webdav/copy.c` | `vfs_copy` | `server_copy`/`copy_range` | object copy |

Every row crosses the same VFS boundary; the only thing that changed vs POSIX is
which `xrootd_sd_driver_t` the VFS dispatches to.

---

## 5. Ceph driver data structures (`sd_ceph.c`)

```c
typedef struct {                 /* xrootd_sd_instance_t.state — one per export */
    rados_t          cluster;    /* per-WORKER handle (see §8)                   */
    rados_ioctx_t    ioctx;
    rados_striper_t  striper;
    char            *pool, *user, *conf_file, *keyring, *key_prefix;
    uint32_t         stripe_unit, stripe_cnt;
    uint64_t         obj_size;
    unsigned         connected:1;
} sd_ceph_state_t;

typedef struct {                 /* xrootd_sd_obj_t.priv (ADR-1)                 */
    char    *soid;               /* striped-object id = key_prefix + LFN         */
    uint64_t size;               /* cached size (stat-on-open; bumped on write)  */
    unsigned for_write:1;
} sd_ceph_obj_priv_t;

typedef struct { rados_list_ctx_t lc; char *prefix; size_t prefix_len; }
    sd_ceph_dir_priv_t;          /* prefix listing + stripe-collapse             */

typedef struct { char *tmp_soid, *final_soid; uint64_t written; }
    sd_ceph_staged_priv_t;
```
**ADR-1:** add `void *priv` to the SD opaque `obj`/`dir`/`staged` structs (POSIX
leaves NULL) rather than overload `fd`.

---

## 6. LFN → object key (namespace model)

`soid = key_prefix + lexically-normalized(LFN)`. No `openat2` (there is no fd);
normalize with the lexical helpers in `src/path/` (collapse `//`, resolve
`.`/`..`, reject climbs above the prefix) so two LFNs can't alias one object and
no key outside the prefix is addressable. Directories are implicit (the prefix);
`mkdir` is a no-op or writes a `<dir>/.keep` marker (`xrootd_ceph_dir_markers`).
Listing collapses striped components (`<soid>.0000000000000000`, `…0001`, …) to
one logical `soid`, exactly as `XrdCephOssDir` does; cost is O(objects-in-pool)
like S3 ListObjects.

---

## 7. Per-slot librados mapping + error table

| SD slot | librados / libradosstriper |
|---|---|
| `init`/`cleanup` | `rados_create`→`rados_conf_read_file`→`rados_connect`→`rados_ioctx_create`→`rados_striper_create`+layout setters; teardown reverse |
| `open`/`close` | build `soid`; stat-on-open (ADR-2) caches size; `O_TRUNC`→`rados_striper_trunc(.,0)`; `O_EXCL`→stat-then-`EEXIST` |
| `pread`/`preadv(2)` | `rados_striper_read` (per-seg loop for iov) |
| `pwrite` | `rados_striper_write`; bump cached size |
| `ftruncate` | `rados_striper_trunc` |
| `fsync` | no-op (acks are durable) / `rados_striper_aio_flush` if aio |
| `fstat`/`stat` | `rados_striper_stat` → size+mtime; mode 0644 reg; ino=hash(soid) |
| `read_sendfile_fd` | `return NGX_INVALID_FILE` |
| `copy_range`/`server_copy` | bounded read→write between two `soid`s |
| `unlink` | `rados_striper_remove` |
| `mkdir`/`rmdir` | no-op / `.keep` marker; rmdir checks prefix empty |
| `rename` | copy each stripe `src→dst` then `remove(src)` (non-atomic) |
| `getxattr`/`setxattr`/`listxattr`/`removexattr` | `rados_striper_(get/set/getxattrs/rm)xattr` (omap fallback) |
| `staged_*` | temp `soid` → write → commit copies to final (`noreplace`=stat first) → remove tmp; abort = remove tmp |

**Error map** (librados `-errno` → errno → kXR, via `xrootd_kxr_from_errno`):
`ENOENT`→NotFound(404); `EEXIST`→InvalidRequest; `EACCES`/`EPERM`→NotAuthorized(403);
`ENOSPC`→NoSpace(507); `ETIMEDOUT`/`EIO`→IOError(500); `ERANGE`→ArgInvalid.
Connect/keyring/pool failures fail the export closed at worker-init with an
`XROOTD_DIAG` cause/fix line.

---

## 8. Threading & per-worker lifecycle

- **One `rados_t` per worker**, created at `init_process` (where `rootfd`/pools are
  set up today); never per request. Same model as the CMS heartbeat client / uring
  pools.
- **Blocking `rados_*` runs on the nginx thread pool.** After W0, the VFS io core
  dispatches the driver primitive from the same `src/core/aio` worker-thread job it
  already uses for POSIX; the event loop never blocks. A **Ceph export REQUIRES a
  `thread_pool`** (enforced at `nginx -t`) — there is no acceptable non-blocking
  fallback for network object I/O (ADR-4).
- **Handle thread-safety:** `librados` permits concurrent ops on one
  `ioctx`/`striper`; the per-`obj` size cache is single-writer per handle. Verified
  by a concurrency stress test (W6).
- **No event-loop zero-copy:** `read_sendfile_fd` invalid ⇒ all reads memory-backed
  and bounded by the existing read window/budget (phase 31) — resident memory stays
  sane for large objects.

---

## 9. Build plumbing (`./config`)

```sh
if [ -f /usr/include/rados/librados.h ] && \
   [ -f /usr/include/radosstriper/libradosstriper.h ]; then
    CORE_INCS="$CORE_INCS /usr/include/rados /usr/include/radosstriper"
    # dynamic-module libs MUST go in ngx_module_libs, not CORE_LIBS, or dlopen
    # of the combined .so fails (rpm_packaging_three_packages).
    ngx_module_libs="$ngx_module_libs -lrados -lradosstriper"
    NGX_ADDON_SRCS="$NGX_ADDON_SRCS $ngx_addon_dir/src/fs/backend/sd_ceph.c"
    have=XROOTD_HAVE_CEPH . auto/have
fi
```
`sd_ceph.c` body wrapped in `#if XROOTD_HAVE_CEPH`; the `sd_drivers[]` row in
`sd_registry.c` is `#if`-guarded; `--without-ceph` force-disables. Re-run
`./configure` once (new source + detection). No-Ceph builds are byte-for-byte
unchanged.

---

## 10. Config directives

| Directive | Arg | Meaning |
|---|---|---|
| `xrootd_storage_driver` | `posix`\|`ceph` | per-export backend selector this phase introduces (default `posix`) |
| `xrootd_ceph_conf` | path | `ceph.conf` (default `/etc/ceph/ceph.conf`) |
| `xrootd_ceph_pool` | name | RADOS pool (required for ceph) |
| `xrootd_ceph_user` | name | ceph user (default `client.admin`) |
| `xrootd_ceph_keyring` | path | optional keyring override |
| `xrootd_ceph_layout` | `unit count objsz` | striper layout (default 4M/1/64M) |
| `xrootd_ceph_dir_markers` | on\|off | `.keep` markers for empty dirs |

`merge_srv_conf` resolves the name via `xrootd_sd_driver_find`, validates (ceph ⇒
pool set + `thread_pool` set), and `init_process` builds the per-worker instance
via `xrootd_sd_instance_create(pool, log, driver, &ceph_conf)`, storing it as the
export's `xrootd_vfs_ctx_t.sd`. `nginx -t` fails closed on misconfig.

---

## 11. Test harness (W6 — the schedule driver)

Single-node Ceph: `MON=1 OSD=1 MDS=0 vstart.sh -n -d` + `ceph osd pool create
xrdtest 32`, **or** the `quay.io/ceph/demo` all-in-one container (reproducible in
CI). Suite `tests/test_ceph_backend.py` gated on `TEST_CEPH=1`, skips cleanly
without a cluster / ceph build:
- round-trips via root://, WebDAV PUT/GET/DELETE, S3 PUT/GET/DELETE against a
  `xrootd_storage_driver ceph;` export;
- byte-exact + checksum across the cross-backend matrix
  (`TEST_CROSS_BACKEND=ceph`, reuse `test_integrity_matrix.py`);
- listing (stripe-collapse), rename (copy+delete), staged upload (`upload_resume`),
  large object (memory-backed window), concurrent read/write (thread-pool + shared
  striper);
- negatives: missing→404, no-space→507, bad pool→fail-closed.

W0 gets its own regression gate: the **full existing suite stays green on POSIX**
after the io-core generalization, before any Ceph code lands.

---

## 12. Workstreams & effort

| WS | Deliverable | Effort |
|---|---|---|
| **W0** | **Thread the bound `obj` end-to-end** (loop layer already generic post-unification — see §0.1): io_core job carries `xrootd_sd_obj_t *obj`; drop the boundary `xrootd_sd_posix_wrap` in `vfs_io_core.c`/`vfs_read.c` (pass `job->obj`); `xrootd_vfs_open` binds the driver obj; `xrootd_file_t.vfs` slot; read/write/readv/pgread/pgwrite/sync/truncate handlers feed the VFS handle; flip the `job->fd==INVALID` guards to `job->obj==NULL`; POSIX-default regression gate; CI grep gate (no `rados_` above `src/fs/backend`). | **0.75 wk** (was 1.5 — loop generalization paid for by the unified `vfs` core) |
| **W1** | Build: ceph detection, `XROOTD_HAVE_CEPH`, `ngx_module_libs` link, `--without-ceph`. | 0.5 wk |
| **W2** | Driver skeleton + lifecycle: `sd_ceph.c`, caps, `sd.h` `void *priv`, `sd_registry.c` conditional row, `sd_ceph_state_t`, per-worker connect. | 0.5 wk |
| **W3** | Data plane slots: open/close/pread/preadv(2)/pwrite/ftruncate/fstat/fsync/read_sendfile_fd + error map; validate root:// read/write/readv/pgread/pgwrite **through the VFS**. | 1.5 wk |
| **W4** | Namespace slots: stat/unlink/mkdir/rename(copy)/opendir/readdir(stripe-collapse)/xattr/staged_*. | 1.5 wk |
| **W5** | GET/PUT/TPC integration via the VFS (sendfile fallback, staged upload, copy); concurrency. | 1 wk |
| **W5b** | **Client reachability (NEW, cheap):** register `sd_ceph` as a client `vfs` backend + URL scheme so `xrdcp`/`xrootdfs` reach a Ceph export directly. Driver + verbs are already shared (waves 1–3); this is endpoint/scheme wiring + a couple of `test_native_*` round-trips, not a second I/O implementation. | 0.5 wk |
| **W6** | Ceph test harness + `test_ceph_backend.py` + cross-backend matrix. **Dominant cost.** | 1.5 wk |
| **W7** | Config directives + `-t` validation + `src/fs/backend/README.md` + ops docs. | 0.5 wk |

**Total ≈ 7.25 engineer-weeks** — down from the original ~8.5: the unified `vfs`
core absorbed ~0.75 wk of W0 (the loop generalization), and the same sharing makes
the new client-reachability W5b (+0.5 wk) nearly free instead of a second port.
W0 remains a one-time, backend-neutral investment every future non-POSIX backend
reuses.
**MVP ≈ 3.5–4.5 weeks:** W0 + W1 + W2 + W3 + minimal W4 (stat/unlink + listing) +
blocking-on-pool, validated through the VFS against a single-node cluster (W5b/W6
client + cross-backend layers fold in after).

---

## 13. Risks

- **W0 regression risk** — it touches the hot read/write path for *every* backend.
  Mitigation: POSIX-default behaviour must be provably unchanged (full suite green
  before any Ceph code); land W0 as its own reviewed PR.
- **Test infra, not code, is the critical path** (W6).
- **Blocking-on-pool throughput** caps concurrency at pool size; `rados_aio` is
  Phase 60.1.
- **Stripe-collapse listing** correctness + O(pool) cost.
- **Non-atomic rename** under concurrency (documented; staged commit narrows it).
- **librados/cluster version skew** — pin a tested client range.

## 14. Definition of done

`xrootd_storage_driver ceph;` on an export gives working root://, WebDAV, and S3
read/write/stat/list/delete **entirely through the VFS** (no `rados_` symbol above
`src/fs/backend/`); the cross-backend conformance + integrity matrix pass against
the Ceph export (gated on a live cluster); the full existing suite stays green on
POSIX after W0; a no-Ceph build is byte-for-byte unchanged; README + ops docs
landed.

---

## Z. ADR log / owner decisions

- **ADR-0 (this phase's spine):** route Ceph through the VFS by making the VFS
  data plane driver-generic (W0), not by special-casing Ceph in handlers. The
  enabling change is backend-neutral and reused by every future driver.
- **ADR-8 (re-baseline 2026-06-28):** build W0 on top of the unified `vfs`+`backend`
  core (`src/fs/core/vfs_core.c`), not the pre-unification POSIX-named loops. The
  shared core already dispatches `obj->driver->*`, so W0 is reduced to threading the
  bound `obj` through open/handle/job and is *also* what makes the driver reachable
  from the userland clients (W5b) — one driver, two consumers (server data plane +
  `xrdcp`/`xrootdfs`). Consequence: do **not** reintroduce `xrootd_sd_posix_wrap`
  on the io path; the only legitimate fd consumers left are the POSIX sendfile /
  io_uring fast paths, gated on `CAP_FD|CAP_SENDFILE`.
- **ADR-1:** add `void *priv` to the SD opaque `obj`/`dir`/`staged` structs.
- **ADR-2:** stat-on-open caches size; keeps range math / `fstat` POSIX-consistent.
- **ADR-3:** use `libradosstriper` (not raw RADOS) for on-disk interop with stock
  XrdCeph.
- **ADR-4:** v1 = synchronous `rados_*` on the nginx thread pool; a Ceph export
  **requires** `thread_pool` (enforced at `nginx -t`). `rados_aio` = Phase 60.1.
- **ADR-5:** no `CAP_FSCS` in v1 (checksum-at-rest via sidecar omap is a follow-on).
- **ADR-6 (non-goal):** EC *pools* are transparent (RADOS does EC below the driver)
  — **not** the `XrdEc` client-driven-striping gap (separate phase).
- **ADR-7 (non-goal):** the C++ `XrdOss`/`XrdCeph` plugin ABI — we ship a native SD
  driver dispatched by our VFS, not a loader for `libXrdCeph.so`.

---

# Appendix A — code-level skeletons (near-implementable)

Grounded on the current signatures: `xrootd_vfs_pread_full(ngx_fd_t fd, u_char*,
size_t, off_t, size_t*)` / `xrootd_vfs_pwrite_full(...)` (both wrap the fd in a
POSIX SD object today, `vfs_read.c`/`vfs_write.c`); `xrootd_vfs_io_execute()` op
switch (`vfs_io_core.c`); `xrootd_sd_instance_create(pool, log, name,
driver_conf, err_out)`; `xrootd_sd_fd(obj)` / `xrootd_sd_posix_wrap(obj, fd)`
(`sd.h`).

## A.1 W0 — struct changes (3 fields, all backend-neutral)

```c
/* src/fs/vfs/vfs_io_core.h — the job gains the bound backend object */
typedef struct {
    ...
    ngx_fd_t          fd;     /* kept: POSIX fast paths (sendfile/uring) only */
    xrootd_sd_obj_t  *obj;    /* NEW: dispatch key — obj->driver is the backend */
    ...
} xrootd_vfs_job_t;

/* src/fs/vfs.c — the opaque open handle gains the backend object + driver */
struct xrootd_vfs_file_s {
    ...
    xrootd_sd_obj_t          *obj;     /* NEW: open backend object              */
    const xrootd_sd_driver_t *driver;  /* = obj->driver (cached)                */
    /* fd field, if any, becomes xrootd_sd_fd(obj) */
};

/* src/core/types/file.h — the fd-table slot can carry the VFS handle */
typedef struct xrootd_file_s {
    int                 fd;    /* kept for legacy/POSIX + sendfile             */
    xrootd_vfs_file_t  *vfs;   /* NEW: backend-generic handle (NULL = fd-only) */
    ...
} xrootd_file_t;
```

## A.2 W0 — de-POSIX-pin the raw I/O helpers (mostly landed; see re-baseline)

> **Re-baseline (2026-06-28):** the loop body shown as "AFTER" below already exists
> as `xvfs_pread_full`/`xvfs_pwrite_full` in `src/fs/core/vfs_core.c` (shared with
> the clients). What is left of this skeleton is the *outer* change: the server
> wrappers in `vfs_read.c`/`vfs_io_core.c` still take `ngx_fd_t fd` and
> `xrootd_sd_posix_wrap` it before calling the generic core — W0 changes those
> signatures to take `xrootd_sd_obj_t *obj` and pass it straight through. Read the
> block below as "the loop is done; thread the obj into it."

```c
/* src/fs/vfs/vfs_read.c — BEFORE: fd in, posix-wrap inside */
ngx_int_t xrootd_vfs_pread_full(ngx_fd_t fd, u_char *buf, size_t len,
                                off_t off, size_t *out) {
    xrootd_sd_obj_t obj; xrootd_sd_posix_wrap(&obj, fd);
    ... n = xrootd_sd_posix_driver.pread(&obj, ...); ...
}
/* AFTER: object in, dispatch on its driver */
ngx_int_t xrootd_vfs_pread_full(xrootd_sd_obj_t *obj, u_char *buf, size_t len,
                                off_t off, size_t *out) {
    ... n = obj->driver->pread(obj, buf, len - done, off + done); ...
    /* identical EINTR / short-read accounting; only the target generalized */
}
/* src/fs/vfs/vfs_write.c — same shape for xrootd_vfs_pwrite_full(obj, ...) */

/* src/fs/vfs/vfs_io_core.c — callers pass job->obj instead of job->fd */
-   if (xrootd_vfs_pread_full(job->fd,  job->buf, job->length, job->offset, &n) ...)
+   if (xrootd_vfs_pread_full(job->obj, job->buf, job->length, job->offset, &n) ...)
-   xrootd_sd_posix_wrap(&obj, job->fd);  xrootd_sd_posix_driver.fsync(&obj);
+   job->obj->driver->fsync(job->obj);
-   xrootd_sd_posix_wrap(&obj, job->fd);  xrootd_sd_posix_driver.ftruncate(&obj, job->offset);
+   job->obj->driver->ftruncate(job->obj, job->offset);
```
The validity guard `job->fd == NGX_INVALID_FILE` in `execute_read/write` becomes
`job->obj == NULL` (a no-fd backend has a valid obj but no fd). After this, the
strings `sd_posix_` and `xrootd_sd_posix_wrap` appear **nowhere** in
`vfs_io_core.c` / `vfs_read.c` / `vfs_write.c`.

## A.3 W0 — bind the driver object at open

```c
/* src/fs/vfs/vfs_open.c */
xrootd_vfs_file_t *
xrootd_vfs_open(xrootd_vfs_ctx_t *ctx, int sdflags, mode_t mode, int *err) {
    const xrootd_sd_driver_t *drv =
        ctx->sd ? xrootd_sd_instance_driver(ctx->sd) : xrootd_sd_default_driver();
    xrootd_sd_obj_t *obj;

    if (ctx->sd) {                                   /* ceph/block/... */
        obj = drv->open(ctx->sd, ctx->resolved_rel, sdflags, mode, err);
    } else {                                         /* POSIX default: open beneath rootfd */
        int fd = xrootd_open_beneath(ctx->rootfd, ctx->resolved_rel,
                                     <O_* from sdflags>, mode);
        if (fd < 0) { *err = errno; return NULL; }
        obj = ngx_pcalloc(ctx->pool, sizeof(*obj));
        xrootd_sd_posix_wrap(obj, fd);  obj->inst = NULL;  /* posix obj */
    }
    if (!obj) return NULL;
    fh = ngx_pcalloc(ctx->pool, sizeof(*fh));
    fh->obj = obj; fh->driver = obj->driver; ...        /* size/mtime via drv->fstat */
    return fh;
}
/* xrootd_vfs_file_sendfile_fd()/_can_sendfile() already gate on CAP_FD|CAP_SENDFILE
 * → return NGX_INVALID_FILE / 0 for Ceph automatically. */
```

## A.4 W0 — handler bridge (feed the VFS handle, not a bare fd)

```c
/* src/protocols/root/read/read.c (and readv.c/pgread.c/write.c/sync.c/truncate.c): */
- fd = ctx->files[idx].fd;
- xrootd_vfs_job_read_init(&job, fd, offset, len, buf, cap);
+ xrootd_vfs_job_read_init(&job, ctx->files[idx].vfs, offset, len, buf, cap);
/* job_read_init now stores job->obj = xrootd_vfs_file_obj(vfs) (and job->fd =
 * xrootd_sd_fd(obj) for the POSIX sendfile/uring fast path only). */
```
For POSIX, `xrootd_sd_fd(obj)` is the same fd as before ⇒ zero observable change.
For Ceph, `job->fd == NGX_INVALID_FILE` and dispatch rides `job->obj->driver`.

## A.5 Read & write call chains (function-by-function, after W0)

```
root:// kXR_read:
  xrootd_handle_read (read/read.c)
   └ xrootd_vfs_job_read_init(job, ctx->files[idx].vfs, off, len, buf)
   └ thread-pool job → xrootd_vfs_io_execute(job)        [src/core/aio worker thread]
       └ xrootd_vfs_io_execute_read(job)
           └ xrootd_vfs_pread_full(job->obj, ...)
               └ job->obj->driver->pread(obj, ...)
                   • posix → pread(fd)         • ceph → rados_striper_read(soid)
   └ done-callback (event loop) → build kXR_ok chain, send

WebDAV/S3 GET:
  get handler → xrootd_vfs_open(ctx)            (ctx->sd = ceph instance)
   └ xrootd_vfs_file_can_sendfile(fh) == 0      (no CAP_SENDFILE) → memory path
   └ loop: xrootd_vfs_job_read_init + io_execute → driver->pread → output filter

root:// kXR_write / pgwrite:
  write handler → xrootd_vfs_job_write_init(job, vfs, off, buf, wlen)
   └ io_execute_write → xrootd_vfs_pwrite_full(job->obj,…) → driver->pwrite
```

## A.6 `sd_ceph.c` — representative slot bodies

```c
#if XROOTD_HAVE_CEPH
#include <rados/librados.h>
#include <radosstriper/libradosstriper.h>

/* lifecycle (per-worker; see A.7) */
static ngx_int_t sd_ceph_init(xrootd_sd_instance_t *inst, void *dc) {
    sd_ceph_state_t *st = inst->state;  *st = *(sd_ceph_conf_to_state(dc));
    if (rados_create(&st->cluster, st->user) < 0) return NGX_ERROR;
    rados_conf_read_file(st->cluster, st->conf_file);
    if (st->keyring) rados_conf_set(st->cluster, "keyring", st->keyring);
    if (rados_connect(st->cluster) < 0) return NGX_ERROR;          /* blocking */
    if (rados_ioctx_create(st->cluster, st->pool, &st->ioctx) < 0) return NGX_ERROR;
    rados_striper_create(st->ioctx, &st->striper);
    rados_striper_set_object_layout_stripe_unit(st->striper, st->stripe_unit);
    rados_striper_set_object_layout_stripe_count(st->striper, st->stripe_cnt);
    rados_striper_set_object_layout_object_size(st->striper, st->obj_size);
    st->connected = 1;  return NGX_OK;
}

static xrootd_sd_obj_t *sd_ceph_open(xrootd_sd_instance_t *inst, const char *path,
                                     int sdflags, mode_t mode, int *err) {
    sd_ceph_state_t *st = inst->state;
    xrootd_sd_obj_t *obj = ngx_pcalloc(inst->pool, sizeof(*obj));
    sd_ceph_obj_priv_t *p = ngx_pcalloc(inst->pool, sizeof(*p));
    p->soid = sd_ceph_key(inst->pool, st->key_prefix, path);      /* §6 mapping */
    uint64_t sz; time_t mt;
    int rc = rados_striper_stat(st->striper, p->soid, &sz, &mt);
    if (rc == -ENOENT && !(sdflags & XROOTD_SD_O_CREATE)) { *err = ENOENT; return NULL; }
    if (rc == 0 && (sdflags & XROOTD_SD_O_EXCL))          { *err = EEXIST; return NULL; }
    if (sdflags & XROOTD_SD_O_TRUNC) rados_striper_trunc(st->striper, p->soid, 0);
    p->size = (rc == 0) ? sz : 0;  p->for_write = !!(sdflags & XROOTD_SD_O_WRITE);
    obj->driver = inst->driver;  obj->inst = inst;  obj->fd = NGX_INVALID_FILE;
    obj->priv = p;  (void) mode;  return obj;
}

static ssize_t sd_ceph_pread(xrootd_sd_obj_t *o, void *buf, size_t len, off_t off){
    sd_ceph_state_t *st = o->inst->state;  sd_ceph_obj_priv_t *p = o->priv;
    int n = rados_striper_read(st->striper, p->soid, buf, len, (uint64_t) off);
    if (n < 0) { errno = -n; return -1; }  return n;          /* 0 = EOF */
}
static ssize_t sd_ceph_pwrite(xrootd_sd_obj_t *o, const void *buf, size_t len, off_t off){
    sd_ceph_state_t *st = o->inst->state;  sd_ceph_obj_priv_t *p = o->priv;
    int rc = rados_striper_write(st->striper, p->soid, buf, len, (uint64_t) off);
    if (rc < 0) { errno = -rc; return -1; }
    if ((uint64_t)(off+len) > p->size) p->size = off+len;  return (ssize_t) len;
}
static ngx_fd_t sd_ceph_read_sendfile_fd(xrootd_sd_obj_t *o, off_t off, size_t l,
                                         unsigned z){ (void)o;(void)off;(void)l;(void)z;
    return NGX_INVALID_FILE; }                 /* no fd ⇒ VFS serves memory-backed */
static ngx_int_t sd_ceph_fstat(xrootd_sd_obj_t *o, xrootd_sd_stat_t *s){
    sd_ceph_state_t *st=o->inst->state; sd_ceph_obj_priv_t *p=o->priv;
    uint64_t sz; time_t mt; int rc=rados_striper_stat(st->striper,p->soid,&sz,&mt);
    if(rc<0){errno=-rc;return NGX_ERROR;}
    s->size=sz; s->mtime=mt; s->ctime=mt; s->mode=0100644; s->ino=sd_ceph_ino(p->soid);
    s->is_reg=1; s->is_dir=0; return NGX_OK; }

const xrootd_sd_driver_t xrootd_sd_ceph_driver = {
    .name = "ceph",
    .caps = XROOTD_SD_CAP_RANGE_READ | XROOTD_SD_CAP_RANDOM_WRITE
          | XROOTD_SD_CAP_TRUNCATE | XROOTD_SD_CAP_XATTR | XROOTD_SD_CAP_SERVER_COPY,
    .init = sd_ceph_init, .cleanup = sd_ceph_cleanup,
    .open = sd_ceph_open, .close = sd_ceph_close,
    .pread = sd_ceph_pread, .pwrite = sd_ceph_pwrite,
    .preadv = sd_ceph_preadv, .preadv2 = sd_ceph_preadv2,
    .read_sendfile_fd = sd_ceph_read_sendfile_fd,
    .ftruncate = sd_ceph_ftruncate, .fsync = sd_ceph_fsync, .fstat = sd_ceph_fstat,
    .stat = sd_ceph_stat, .unlink = sd_ceph_unlink, .mkdir = sd_ceph_mkdir,
    .rename = sd_ceph_rename, .server_copy = sd_ceph_server_copy,
    .opendir = sd_ceph_opendir, .readdir = sd_ceph_readdir, .closedir = sd_ceph_closedir,
    .getxattr = sd_ceph_getxattr, .setxattr = sd_ceph_setxattr,
    .listxattr = sd_ceph_listxattr, .removexattr = sd_ceph_removexattr,
    .staged_open = sd_ceph_staged_open, .staged_write = sd_ceph_staged_write,
    .staged_commit = sd_ceph_staged_commit, .staged_abort = sd_ceph_staged_abort,
};
#endif /* XROOTD_HAVE_CEPH */
```

```c
/* readdir: collapse striped components <soid>.NNNNNNNNNNNNNNNN to one logical soid */
static ngx_int_t sd_ceph_readdir(xrootd_sd_dir_t *d, xrootd_sd_dirent_t *out) {
    sd_ceph_dir_priv_t *p = d->priv;  const char *entry; size_t klen;
    for (;;) {
        if (rados_nobjects_list_next(p->lc, &entry, NULL, NULL) < 0) return NGX_DONE;
        if (strncmp(entry, p->prefix, p->prefix_len) != 0) continue;     /* scope */
        if (!sd_ceph_is_first_stripe(entry)) continue;     /* emit base once */
        sd_ceph_logical_name(entry, out->name, sizeof(out->name));
        return NGX_OK;
    }
}
```

## A.7 Per-worker cluster connect (registry + init_process)

```c
/* sd_registry.c */
static const xrootd_sd_driver_t *const sd_drivers[] = {
    &xrootd_sd_posix_driver,
#if XROOTD_HAVE_CEPH
    &xrootd_sd_ceph_driver,
#endif
};

/* src/core/config/process.c (per-worker init_process) — connect once, store on the
 * export's vfs ctx (xrootd_vfs_ctx_t.sd) */
if (srv->storage_driver_is_ceph) {
    int e; xrootd_sd_instance_t *inst =
        xrootd_sd_instance_create(worker_pool, log, "ceph", &srv->ceph_conf, &e);
    if (!inst) { XROOTD_DIAG(log, "ceph connect failed",
                             "check ceph.conf/keyring/pool reachability"); return NGX_ERROR; }
    srv->sd_instance = inst;   /* used to populate xrootd_vfs_ctx_t.sd per request */
}
```

## A.8 Config wiring

```c
/* ngx_command_t (src/protocols/root/stream/module*.c) */
{ ngx_string("xrootd_storage_driver"), NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
  ngx_conf_set_str_slot, NGX_STREAM_SRV_CONF_OFFSET,
  offsetof(ngx_stream_xrootd_srv_conf_t, storage_driver), NULL },
{ ngx_string("xrootd_ceph_pool"), ... offsetof(..., ceph_conf.pool) ... },
/* + xrootd_ceph_conf/_user/_keyring/_layout/_dir_markers */

/* merge_srv_conf: resolve + validate */
if (ngx_strcmp(conf->storage_driver.data, "ceph") == 0) {
    if (!xrootd_sd_driver_find("ceph"))      return "built without Ceph support";
    if (conf->ceph_conf.pool.len == 0)       return "xrootd_ceph_pool is required";
    if (conf->common.thread_pool.len == 0)   return "ceph export requires a thread_pool";
}
```

## A.9 Test skeleton (`tests/test_ceph_backend.py`, `TEST_CEPH=1`)

```python
@pytest.fixture(scope="module")
def ceph_export():
    if not os.environ.get("TEST_CEPH"): pytest.skip("no Ceph cluster")
    # ceph.conf+keyring from the vstart/container harness; nginx with
    #   xrootd_storage_driver ceph; xrootd_ceph_pool xrdtest; thread_pool default;
    ...
def test_root_write_read_roundtrip(ceph_export):   # kXR_write -> kXR_read, byte-exact
def test_webdav_put_get_delete(ceph_export):       # GET goes memory-backed (no sendfile)
def test_s3_put_get_list_delete(ceph_export):      # ListObjects == stripe-collapsed dir
def test_large_object_memory_window(ceph_export):  # > read window, resident memory bounded
def test_concurrent_rw_shared_striper(ceph_export):# thread-pool + one striper
def test_missing_404_nospace_507(ceph_export):     # error map
# plus: TEST_CROSS_BACKEND=ceph reuse of test_integrity_matrix.py
```
