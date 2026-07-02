# Phase 55 — Storage-Backend Abstraction (Pluggable Storage Driver below the VFS)

**Date:** 2026-06-24
**Status:** PLAN — not yet implemented
**Depends on:** Phase 8 (openat2 confinement), Phase 54 (thread-safe VFS I/O core), the
unified VFS (`src/fs/`). This is the natural successor to Phase 54: now that *all*
disk I/O — event-loop and worker-thread alike — funnels through one VFS surface, we
can cut a clean seam *underneath* it and make the POSIX filesystem just one of several
interchangeable storage drivers.

> **One-line goal.** Lift every raw POSIX syscall out of `src/fs/` into a lower
> **Storage Driver (SD)** layer behind a capability-typed vtable, and let each export
> bind an independently-selectable **backend store** and **staging store** (both
> POSIX by default), so that a **block / object (S3) backend** can become a
> first-class — and ultimately the *primary* — storage backend, without any protocol
> handler, metrics, cache, or access-log code changing.

---

## 0. Reader contract / terminology

This phase deliberately adds one new layer, not a second VFS:

| Term | Meaning | Owns |
|---|---|---|
| **Protocol handler** | XRootD stream, WebDAV, S3 REST, CMS/data-server caller | wire parsing, auth decision orchestration, response framing |
| **VFS** | `src/fs/` public API (`xrootd_vfs_*`) | policy, confinement re-check, cache hooks, metrics, access log, buffer shaping, protocol-neutral result normalization |
| **Storage Driver (SD)** | new `src/fs/backend/` implementation selected per export | raw storage primitives: open/read/write/stat/namespace/staged commit |
| **SD instance** | one configured backend bound to one export root/location | driver config, root/key-prefix confinement state, credentials, transport handles |
| **Backend store** | the SD instance that holds the durable, client-visible data for an export | the canonical bytes; what a reopen/stat/list reflects |
| **Staging store** | the SD instance that holds in-progress uploads before commit | scratch temp objects; consumed by commit/promote, never client-visible by their temp names |
| **Store binding** | the (backend store, staging store) pair bound to one export | both default to POSIX; either may be reselected independently (§3.6) |
| **Promote** | the commit action that moves a completed staged object from the staging store into the backend store | native rename when both are the same store, else stream/multipart copy-then-delete |
| **SD object** | opaque open object returned by the driver | fd for POSIX, key/upload state for object, extent cursor for block |
| **Logical path** | canonical client/export path already normalized by `src/path/` | passed from VFS to SD; never trusted until the SD enforces its own confinement primitive |
| **Physical locator** | POSIX pathname, object key, block extent address, etc. | private to the SD; never leaks above `src/fs/backend/` |

**Rule of thumb:** if code needs to understand XRootD/WebDAV/S3 wire semantics, it
does **not** belong in the SD. If code calls `open`, `pread`, `CopyObject`, object
multipart APIs, block-device ioctls, or any equivalent raw storage primitive, it
does **not** belong above the SD.

The VFS remains the only protocol-facing data plane. The SD layer is intentionally
small, boring, and hard to misuse.

---

## 1. Problem statement

### 1.1 Where we are

`src/fs/` is the single protocol-agnostic data plane. The four front ends
(`root://`, WebDAV, S3 REST, CMS data-server I/O) all build an `xrootd_vfs_ctx_t`
and call `xrootd_vfs_*`; the VFS owns confinement re-check, metrics, access logging,
page-CRC, TLS/cleartext buffer shaping, and cache integration — **once**, for everyone.

But the VFS still **is** POSIX. Concretely, the POSIX assumption is hard-wired in
five places:

| Coupling | Where | Symptom for a non-POSIX backend |
|---|---|---|
| Raw syscalls | `vfs_open/read/write/dir/stat/sync/copy/staged/xattr.c` + `vfs_io_core.c` (~199 syscall sites) | `open`/`pread`/`pwrite`/`readdir`/`rename`/`copy_file_range` have no object-store meaning |
| `fd` as the universal handle | `struct xrootd_vfs_file_s.fd`; `xrootd_vfs_file_fd()` leaks through 4 use sites across 3 files (`webdav/get.c`, `s3/object.c`, `shared/file_serve.c`) | object stores have no fd; sendfile is impossible |
| Sendfile / file-backed bufs | `vfs_read.c` `make_file_chain()` `dup`s the fd, emits an `in_file` buf | requires a kernel fd the backend doesn't have |
| Kernel confinement = `RESOLVE_BENEATH` | `src/fs/path/beneath.h`, `xrootd_ns_*` in `src/core/compat/namespace_ops.c` | `openat2(RESOLVE_BENEATH)` is a filesystem concept; object stores confine by **key prefix** |
| Namespace mutation tier | `xrootd_ns_delete/mkdir/rename/local_copy` (also used directly by worker-thread code) | rename/mkdir/copy_file_range map to object COPY/no-op/multipart, not syscalls |

### 1.1.1 Current POSIX surface to migrate

The initial refactor should start from this inventory, because these are the places
where "VFS == POSIX" is still encoded:

| Area | Files | What moves into SD |
|---|---|---|
| Object lifecycle | `src/fs/vfs_open.c`, `src/fs/vfs_sync.c`, `src/fs/vfs_staged.c` | open/close/adopt, fstat, truncate, sync, staged temp lifecycle |
| Byte I/O | `src/fs/vfs_read.c`, `src/fs/vfs_write.c`, `src/fs/vfs_io_core.c` | full pread/pwrite loops, readv/writev segment execution, sendfile eligibility |
| Namespace | `src/fs/vfs_unlink.c`, `vfs_rename.c`, `vfs_mkdir.c`, `vfs_copy.c`, `src/core/compat/namespace_ops.c` | delete/rmdir/rename/mkdir/copy implementation and escape mapping |
| Directory/stat | `src/fs/vfs_dir.c`, `src/fs/vfs_stat.c`, dirlist scan in `vfs_io_core.c` | opendir/readdir/closedir, lstat/stat, directory-entry stat |
| Metadata | `src/fs/vfs_xattr.c` | user xattrs or backend metadata/tag/sidecar mapping |
| Confinement helpers | `src/fs/path/beneath.c`, `src/fs/path/beneath.h` | POSIX driver's physical confinement primitive only |

The migration is complete only when the above files contain VFS policy and result
normalization, but no storage primitive whose equivalent would have to be rewritten
for an object or block backend.

### 1.1.2 What must not move into SD

Keep these above the seam:

| Stays in VFS/protocol | Reason |
|---|---|
| authdb / VO / token-scope decisions | authorization is protocol/export policy, not storage-driver policy |
| `xrootd_path_result_t` parsing and canonicalization | shared security boundary for all front ends |
| XRootD `kXR_*` / HTTP status mapping | SD returns `errno`-style facts; protocol layers map to wire responses |
| metrics labels and access-log detail | labels must stay low-cardinality and protocol-aware |
| TLS vs cleartext buffer shape | nginx output-chain decision, not backend storage behaviour |
| cache read-through/write-through policy | initially VFS-owned; later may become a composing SD (§12.1) |
| write-recovery journal / dashboard counters | stream-session ownership and observability |

### 1.2 Where we want to be

```
        protocol handlers: root:// · WebDAV · S3 · CMS         (UNCHANGED)
                         │  build xrootd_vfs_ctx_t
                         ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  VFS layer  (src/fs/)   — POLICY, backend-agnostic               │
   │  confinement re-check · metrics · access log · cache ·           │
   │  page-CRC · TLS/cleartext buffer shaping · staged-write lifecycle│
   └─────────────────────────────────────────────────────────────────┘
                         │  xrootd_sd_* calls on an opaque object handle
                         │  + capability flags
                         ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  Storage Driver (SD) interface   (NEW: src/fs/backend/)          │
   │  a vtable of raw storage primitives + a capability bitmap        │
   └─────────────────────────────────────────────────────────────────┘
        │                       │                        │
        ▼                       ▼                        ▼
   posix driver            block driver             object/s3 driver
   (default, today's     (raw block dev /        (the future "main"
    openat2 + pread…)      O_DIRECT extent map)    backend: range GET/PUT,
                                                   multipart, CopyObject)
```

The VFS keeps everything that is *not* storage-specific. The SD layer owns *only*
the raw "move these bytes / mutate this name" primitives, plus a **capability
bitmap** the VFS consults to shape its behaviour (e.g. "this backend has no fd →
never emit a sendfile buf").

### 1.3 Why now

1. **Phase 54 already did the hard structural work.** Every disk op is now split
   PREPARE / EXECUTE / COMPLETE around a POD `xrootd_vfs_job_t`. The EXECUTE phase
   (`vfs_io_core.c`) is *already* the only place raw read/write/readv/pgread/opendir
   syscalls live for the worker path. That is exactly the cut line for a driver vtable.
2. **The S3 front end exists but is asymmetric.** Today S3 is a *protocol* on top of
   POSIX storage. Making object storage a *backend* lets `root://` and WebDAV serve
   from an object store too — the actual operational goal (replace xrootd gateways
   whose backend is object/tape, not local disk).
3. **The capability seam is the only honest abstraction.** We will *not* pretend an
   S3 bucket is a POSIX filesystem (that path is how FUSE-over-S3 gateways become
   slow and incorrect). Instead the VFS asks the driver what it can do and adapts.

### 1.4 Success criteria

This phase is successful when all four of these are true:

1. **POSIX parity:** `xrootd_storage_backend posix` is byte-for-byte and
   response-for-response identical to today's code, including error codes, access
   log detail, metrics, cache decisions, and sendfile/TLS behaviour.
2. **No POSIX leakage above SD:** outside `src/fs/backend/sd_posix.c` and narrowly
   documented POSIX-only helper files, `src/fs/` no longer calls raw POSIX storage
   syscalls directly. Any remaining `fd` exposure is private and capability-gated.
3. **Non-POSIX backend can be honest:** a driver without `FD`, `SENDFILE`,
   `RANDOM_WRITE`, `HARD_RENAME`, or `DIRS` can still pass the operations it
   advertises and return clear unsupported errors for the rest.
4. **Operationally reversible:** configs that omit `xrootd_storage_backend` keep
   using POSIX, and non-POSIX backends are inert until explicitly selected.

---

## 2. Design principles (non-negotiable)

1. **The VFS public API (`vfs.h`) does not change.** Protocol handlers keep building
   `xrootd_vfs_ctx_t` and calling `xrootd_vfs_*`. This phase is invisible above the VFS.
   The one exception is **retiring `xrootd_vfs_file_fd()`** as a public accessor
   (§6.1) — the only genuine POSIX leak above the seam.
2. **Capability-typed, not lowest-common-denominator.** The driver advertises
   capabilities; the VFS degrades gracefully (sendfile→memory-chain, server-side
   copy→stream-through, random-write→staged-rewrite). No feature is silently dropped
   without a metric + log line.
3. **One driver selected per export root, at config time.** A `location{}` / export
   binds to exactly one backend instance. No per-request backend switching in v1.
4. **Confinement is still re-verified at the seam.** The driver is handed an
   already-confined *logical* path (`xrootd_path_result_t`); each driver enforces its
   own confinement primitive (POSIX = `RESOLVE_BENEATH`; object = key-prefix bound).
   The VFS `require_confined`/`require_write` guards stay exactly where they are.
5. **Descriptor-driven dispatch, no `goto`, functional/modular** — per
   `docs/09-developer-guide/coding-standards.md`. The vtable *is* the descriptor table.
6. **Every phase leaves the tree green.** POSIX behaviour is byte-identical throughout;
   the object backend lands behind a config flag and is opt-in until it passes the
   full conformance + integrity matrix.
7. **3 tests per change** (success + error + security-negative), plus a backend-parity
   test matrix (§9).

---

## 3. The Storage Driver (SD) interface

New directory: **`src/fs/backend/`**.

```
src/fs/backend/
  sd.h              # the vtable, capability flags, opaque types, registry API
  sd_registry.c     # name→driver lookup; per-export instance binding
  sd_posix.c        # POSIX driver (wraps today's beneath/ns_* helpers verbatim)
  sd_block.c        # block-device driver (phase 55.D — later)
  sd_object.c       # object/S3 driver (phase 55.E — the headline)
  sd_object_s3.c    # S3 transport for the object driver (reuses src/protocols/s3 SigV4)
  README.md
```

### 3.1 Capability bitmap

```c
typedef enum {
    XROOTD_SD_CAP_FD            = 1u << 0,  /* exposes a real kernel fd            */
    XROOTD_SD_CAP_SENDFILE      = 1u << 1,  /* fd is sendfile/splice-able          */
    XROOTD_SD_CAP_RANDOM_WRITE  = 1u << 2,  /* pwrite at arbitrary offset          */
    XROOTD_SD_CAP_RANGE_READ    = 1u << 3,  /* pread at arbitrary offset           */
    XROOTD_SD_CAP_TRUNCATE      = 1u << 4,  /* ftruncate                           */
    XROOTD_SD_CAP_SERVER_COPY   = 1u << 5,  /* native copy (copy_file_range/COPY)  */
    XROOTD_SD_CAP_XATTR         = 1u << 6,  /* user.* xattrs / object metadata     */
    XROOTD_SD_CAP_HARD_RENAME   = 1u << 7,  /* atomic rename (else copy+delete)    */
    XROOTD_SD_CAP_DIRS          = 1u << 8,  /* real directories (else key-prefix)  */
    XROOTD_SD_CAP_APPEND        = 1u << 9,  /* O_APPEND semantics                  */
    XROOTD_SD_CAP_IOURING       = 1u << 10, /* fd is io_uring-submittable          */
} xrootd_sd_cap_t;
```

POSIX advertises all of them. The S3 object driver advertises
`RANGE_READ | SERVER_COPY | XATTR(tags-or-sidecar)` and crucially **not**
`FD | SENDFILE | RANDOM_WRITE | HARD_RENAME | DIRS | IOURING`. Those absences are
what drive the VFS adaptations in §6.

Capability rules:

| Capability absent | VFS behaviour |
|---|---|
| `CAP_FD` | never call `xrootd_sd_fd()`, never build file-backed buffers, never enter fd-cache/io_uring/sendfile paths |
| `CAP_SENDFILE` | read responses are memory-backed even for cleartext; access log and metrics are unchanged |
| `CAP_RANGE_READ` | reject `kXR_read`, WebDAV GET range, S3 GET with `ENOTSUP`; directory/stat may still work |
| `CAP_RANDOM_WRITE` | allow staged/sequential writes only; reject non-sequential `kXR_write`, writev, pgwrite, partial PUT |
| `CAP_TRUNCATE` | reject truncate and checkpoint rollback requiring shrink/extend |
| `CAP_SERVER_COPY` | stream-through copy when both source and destination are readable/writable; otherwise reject |
| `CAP_XATTR` | use sidecar metadata if configured; otherwise reject fattr/WebDAV dead-property ops clearly |
| `CAP_HARD_RENAME` | expose rename as non-atomic copy+delete only when config explicitly allows weak rename |
| `CAP_DIRS` | synthesize directories from key prefixes; mkdir/rmdir become prefix-marker operations or no-ops |
| `CAP_APPEND` | reject append-mode opens unless staged append emulation is explicitly enabled |
| `CAP_IOURING` | skip io_uring tier; thread-pool or inline fallback handles the op |

Every degradation path must do three things: return the correct client-visible
status, emit a low-cardinality metric, and leave an access-log detail string that
names the degraded operation without including paths as labels.

### 3.2 Opaque handle

The driver returns an opaque `xrootd_sd_obj_t *`. For POSIX it wraps an `fd`; for the
object driver it wraps `{ object_key, etag, size, staging_fd_or_-1, upload_id }`.
`struct xrootd_vfs_file_s.fd` is **replaced** by `xrootd_sd_obj_t *obj` (§6.1). The fd,
where one exists, is reached only via the capability-gated accessor
`xrootd_sd_fd(obj)` which returns `NGX_INVALID_FILE` when `!CAP_FD`.

The object lifetime contract is strict:

1. `open` returns either a fully initialized `xrootd_sd_obj_t *` or `NULL` with
   `*err_out` set. Half-open objects are cleaned inside the driver.
2. `close` is idempotent. It must release transport state and temporary resources,
   but it must not commit staged writes; commit is explicit.
3. Object metadata cached on the handle (`size`, `mtime`, `etag`, `generation`) is
   a snapshot unless the driver explicitly updates it after a successful write,
   truncate, or staged commit.
4. The VFS never dereferences driver-private fields. All access is through helper
   functions (`xrootd_sd_caps`, `xrootd_sd_fd`, `xrootd_sd_size`, etc.).
5. A driver may allocate from its instance pool or `ngx_alloc`, but worker-safe raw
   ops must not allocate from nginx request pools.

### 3.3 The vtable

```c
typedef struct xrootd_sd_driver_s xrootd_sd_driver_t;

struct xrootd_sd_driver_s {
    const char    *name;          /* "posix" | "block" | "s3"                  */
    uint32_t       caps;          /* xrootd_sd_cap_t bitmap                     */

    /* ---- instance lifecycle (per export, at config/worker init) ---- */
    ngx_int_t  (*init)   (xrootd_sd_instance_t *inst, ngx_log_t *log);
    void       (*cleanup)(xrootd_sd_instance_t *inst);

    /* ---- object lifecycle (logical path already confined by the VFS) ---- */
    xrootd_sd_obj_t *(*open) (xrootd_sd_instance_t *inst,
                              const char *logical_path, int sd_flags,
                              mode_t mode, int *err_out);
    ngx_int_t  (*close)(xrootd_sd_obj_t *obj);

    /* ---- raw byte I/O (worker-safe; the EXECUTE phase calls these) ---- */
    ssize_t    (*pread) (xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off);
    ssize_t    (*pwrite)(xrootd_sd_obj_t *obj, const void *buf, size_t len, off_t off);
    ngx_int_t  (*ftruncate)(xrootd_sd_obj_t *obj, off_t len);
    ngx_int_t  (*fsync) (xrootd_sd_obj_t *obj);
    ngx_int_t  (*fstat) (xrootd_sd_obj_t *obj, struct xrootd_sd_stat_s *out);

    /* ---- namespace (logical paths; replace the xrootd_ns_* tier) ---- */
    ngx_int_t  (*stat)  (xrootd_sd_instance_t *inst, const char *path,
                         struct xrootd_sd_stat_s *out);
    ngx_int_t  (*unlink)(xrootd_sd_instance_t *inst, const char *path, int is_dir);
    ngx_int_t  (*mkdir) (xrootd_sd_instance_t *inst, const char *path, mode_t mode);
    ngx_int_t  (*rename)(xrootd_sd_instance_t *inst, const char *src,
                         const char *dst, int noreplace);
    ngx_int_t  (*server_copy)(xrootd_sd_instance_t *inst, const char *src,
                              const char *dst, off_t *bytes_out);

    /* ---- directory iteration ---- */
    xrootd_sd_dir_t *(*opendir)(xrootd_sd_instance_t *inst, const char *path,
                                int *err_out);
    ngx_int_t  (*readdir)(xrootd_sd_dir_t *d, struct xrootd_sd_dirent_s *out);
    ngx_int_t  (*closedir)(xrootd_sd_dir_t *d);

    /* ---- xattr / object metadata ---- */
    ssize_t    (*getxattr)(xrootd_sd_instance_t *inst, const char *path,
                           const char *name, void *buf, size_t cap);
    ssize_t    (*listxattr)(xrootd_sd_instance_t *inst, const char *path,
                            void *buf, size_t cap);
    ngx_int_t  (*setxattr)(xrootd_sd_instance_t *inst, const char *path,
                           const char *name, const void *val, size_t len, int flags);
    ngx_int_t  (*removexattr)(xrootd_sd_instance_t *inst, const char *path,
                              const char *name);

    /* ---- staged/atomic write (multipart for object stores) ---- */
    xrootd_sd_staged_t *(*staged_open)(xrootd_sd_instance_t *inst,
                                       const char *final_path, mode_t mode,
                                       int *err_out);
    ssize_t    (*staged_write)(xrootd_sd_staged_t *st, const void *buf,
                               size_t len, off_t off);
    ngx_int_t  (*staged_commit)(xrootd_sd_staged_t *st, int noreplace);
    void       (*staged_abort) (xrootd_sd_staged_t *st);
};
```

**Notes on the contract:**
- All raw-I/O ops (`pread`/`pwrite`/`ftruncate`/`fsync`/`fstat`) are **worker-safe**:
  no nginx pool, no metrics, no log — exactly the Phase-54 EXECUTE contract. The POSIX
  driver's bodies are literally today's `xrootd_vfs_pread_full` etc.
- All `inst`-keyed ops take a **logical** path (root-relative-or-absolute as today);
  the driver applies its own confinement (POSIX `RESOLVE_BENEATH`, object key-prefix).
- `server_copy` returns `NGX_DECLINED` when `!CAP_SERVER_COPY`, and the VFS falls back
  to a stream-through read→write copy.
- The vtable is **flat and POD-pointer-only** so the object driver can run its blocking
  network calls inside the existing AIO thread pool with zero event-loop coupling.
- The `staged_*` ops are a driver's **own** atomic-publish lifecycle (POSIX temp+rename;
  object multipart). They are distinct from the VFS-level *promote* between a staging
  store and a backend store (§3.6): the VFS may drive a backend's `staged_*` using a
  staging-store object as the byte source. A driver implements `staged_*` without any
  knowledge of whether a separate staging store sits in front of it.

### 3.3.1 Required helper API around the vtable

Do not let callers poke at the vtable directly. Add small helpers in `sd.h`:

```c
uint32_t   xrootd_sd_caps(const xrootd_sd_obj_t *obj);
ngx_fd_t   xrootd_sd_fd(const xrootd_sd_obj_t *obj);
const char *xrootd_sd_backend_name(const xrootd_sd_instance_t *inst);

ngx_int_t  xrootd_sd_supports(const xrootd_sd_instance_t *inst,
    uint32_t required_caps);

void       xrootd_sd_stat_to_vfs(const xrootd_sd_stat_t *in,
    xrootd_vfs_stat_t *out);
```

The VFS should read as policy code:

```c
if (!xrootd_sd_supports(ctx->sd, XROOTD_SD_CAP_RANGE_READ)) {
    errno = ENOTSUP;
    return NGX_ERROR;
}
```

not as repeated `driver->caps & ...` branches scattered across protocol modules.

### 3.3.2 Error contract

Drivers return `NGX_OK`, `NGX_ERROR`, `NGX_DECLINED`, `NULL`, or byte counts, but
the authoritative reason is always an `errno`-style value captured immediately.

| Driver fact | VFS errno | XRootD mapping | HTTP mapping | Notes |
|---|---|---|---|---|
| missing object/path | `ENOENT` | `kXR_NotFound` | 404 | object HEAD miss maps here |
| denied by backend credentials or prefix confinement | `EACCES`/`EPERM` | `kXR_NotAuthorized` | 403 | prefix escape may use `EXDEV` internally, normalized by VFS |
| unsupported capability | `ENOTSUP` | `kXR_Unsupported` | 501 | must increment unsupported metric |
| conditional create failed | `EEXIST` | `kXR_ArgInvalid`/op-specific | 409/412 | preserve existing per-op semantics |
| stale generation / ETag mismatch | `ESTALE` | `kXR_IOError` unless op has conflict mapping | 409 | object driver uses this for optimistic commit failures |
| timeout | `ETIMEDOUT` | `kXR_IOError` | 504 | include backend name in log detail, not metric label |
| short write / incomplete upload part | `EIO` or `ENOSPC` | `kXR_IOError` | 500/507 | VFS preserves current "short write" text |

The driver must never call `xrootd_send_error`, set `XROOTD_OP_*`, or emit protocol
metrics. It returns storage facts; the VFS/protocol layers map them.

### 3.3.3 Path contract

All SD path-taking functions receive one of:

1. A VFS-confined logical path for an operation on a client-visible object.
2. A VFS-generated internal path for temp/staged/sidecar metadata.

The path is UTF-8/byte-preserving like today's POSIX path handling: the VFS does not
reinterpret valid path bytes into object-store semantics. The object driver maps
logical paths to keys with one reversible function:

```text
logical path: /store/data/a.root
prefix:       cms-prod/
object key:   cms-prod/store/data/a.root
```

Rules:
- normalize once in `src/path/`; never normalize again with string hacks in the SD;
- reject empty path except for explicit export-root directory/list operations;
- reject any physical locator outside the configured root/prefix;
- do not include credentials, bucket names, full keys, or paths in metric labels;
- preserve the existing log-sanitization path for all client-supplied strings.

### 3.4 `xrootd_sd_job_t` and the Phase-54 EXECUTE core

`vfs_io_core.c`'s `xrootd_vfs_job_t` currently carries `ngx_fd_t fd` / `int rootfd`.
We generalize it: the job carries an `xrootd_sd_obj_t *obj` (and, for readv/writev, an
array of `{obj, off, len}` segments). `xrootd_vfs_io_execute()` dispatches the raw op
through `obj->driver->pread/pwrite/...` instead of calling `pread(2)` directly.

For the POSIX driver these indirections inline to the same syscalls (the hot path is
one predicted indirect call — measured in §10). **io_uring is preserved**: when
`CAP_IOURING` is set the io_uring submit path reads `xrootd_sd_fd(obj)` exactly as it
reads the fd today; non-fd backends never reach the io_uring tier (capability-gated in
`xrootd_aio_post_task`).

---

### 3.5 Observability contract

The first POSIX-only phases should not change existing metrics. New metrics appear
only once capability degradation or a non-POSIX backend is selectable:

| Metric | Labels | Purpose |
|---|---|---|
| `xrootd_sd_ops_total` | `backend`, `op`, `status` | count SD-level operations; status is low-cardinality (`ok`, `error`, `unsupported`, `degraded`) |
| `xrootd_sd_bytes_total` | `backend`, `op`, `direction` | raw bytes read/written by the backend |
| `xrootd_sd_latency_seconds` | `backend`, `op` | histogram for blocking backend operations, especially object-store calls |
| `xrootd_sd_degraded_total` | `backend`, `op`, `reason` | sendfile fallback, stream-through copy, weak rename, sidecar xattrs |
| `xrootd_sd_unsupported_total` | `backend`, `op` | explicit unsupported capability responses |

Do **not** add path, bucket, object key, upload id, host, token issuer, ETag, or user
identity labels. Those belong in sanitized access/debug logs only.

Access-log detail should stay protocol-specific. The SD can supply a short reason
string such as `backend=s3 degraded=stream_copy`, but the protocol/VFS layer owns the
final access-log event.

### 3.6 Per-export store binding: backend store + staging store

An export does **not** bind to a single storage driver — it binds to a **pair**:

| Role | Holds | Default | Selectable? |
|---|---|---|---|
| **Backend store** | durable, client-visible bytes | `posix` (today's export root) | yes — `xrootd_storage_backend` |
| **Staging store** | in-progress uploads until commit | `posix` (today's in-root temp dir) | yes — `xrootd_storage_staging` |

Both default to POSIX, and — critically — **both default to the *same* POSIX
instance rooted at the export root**, which reproduces today's behaviour exactly:
the staged temp is an `O_EXCL` file created inside the export root and committed by an
atomic `renameat2`. Nothing changes for an unconfigured deployment.

Why split them at all? Because the staging store and the backend store have *opposite*
capability needs:

- **Staging wants `RANDOM_WRITE | TRUNCATE | APPEND`** — an in-flight upload may arrive
  out of order (`kXR_write` at varying offsets), be checkpointed, truncated, or resumed.
  POSIX scratch (local NVMe, tmpfs, a dedicated fast mount) is ideal.
- **The backend may have *none* of those** — an object store only accepts a finished,
  sequential, whole-object PUT (or multipart). It is excellent at durable, replicated,
  cheap-at-rest storage and terrible at random mutation.

Binding them independently lets the gateway **stage on POSIX and land on object**: the
client does arbitrary random/checkpointed writes against a full-featured POSIX staging
file, and **commit promotes** the finished object into the object backend as one
sequential multipart PUT. This is the clean resolution of the §5.3 random-write
limitation for the *upload* path — the only writes the backend ever sees are the
sequential bytes of a completed object.

#### 3.6.1 Commit / promote decision

`xrootd_vfs_staged_commit()` becomes a VFS-orchestrated decision over the two
instances rather than a single driver call:

| Staging store | Backend store | Commit action | Atomic? |
|---|---|---|---|
| POSIX inst X | **same** POSIX inst X | `rename` via the backend driver (today's `renameat2`) | yes (kernel rename) |
| POSIX inst X | different POSIX inst Y (other mount) | `server_copy`/stream X→Y, then `unlink` X | publish-rename within Y is atomic; cross-mount move is not |
| POSIX staging | object backend | read staging object → backend `staged_*` multipart PUT (the *backend's* staged lifecycle), then `unlink` staging | object commit (CompleteMultipartUpload) is the atomic point |
| object staging | object backend | backend-side `server_copy` (CopyObject) then delete, or direct multipart if same bucket | per store |

The decision is made once, in the VFS staged-commit body, keyed on
`staging.instance == backend.instance` and the backend's `CAP_HARD_RENAME`. When the
two instances are identical the fast native-rename path is taken with **zero extra
copy** — so the common POSIX deployment pays nothing for the abstraction.

#### 3.6.2 Two SD-staged lifecycles, composed

Note the recursion: the *staging store* exposes the normal object/byte vtable (the
client writes into it via `open`/`pwrite`/`ftruncate`), and the *backend store*
exposes its own `staged_*` lifecycle (multipart). Promotion drives the backend's
`staged_open`/`staged_write`/`staged_commit` using the staging object as the byte
source. The VFS owns this orchestration; neither driver knows about the other.

```text
client writes ──► STAGING store (POSIX scratch: random write, truncate, checkpoint)
                       │   (upload complete; protocol layer calls commit)
                       ▼
   VFS promote: pread staging object  ──►  BACKEND store staged_write (multipart part)
                       │                          │
                       ▼                          ▼
              unlink staging temp        backend staged_commit  ──► durable object
```

#### 3.6.3 Confinement & accounting across two stores

- Each store enforces its **own** confinement primitive independently (POSIX
  `RESOLVE_BENEATH` for the staging mount; key-prefix for the backend). A staging temp
  name can never escape the staging root; a promoted key can never escape the backend
  prefix.
- The staging temp is **never** client-visible: it has no logical-path mapping in the
  backend namespace, and stat/list/read of the *final* path before commit returns
  `ENOENT` exactly as today.
- Metrics: promotion that crosses stores increments `xrootd_sd_degraded_total{op=commit,
  reason=promote}` and records `xrootd_sd_bytes_total` against the **backend** store
  (the durable write). The intra-store fast rename records no promote bytes.
- Failure atomicity is unchanged in spirit: a failed promote runs `staged_abort` on the
  backend (aborting the multipart upload) and leaves the staging temp for the
  abort/cleanup path; the final backend path is published only on a fully successful
  backend commit.

#### 3.6.4 Why this is the right default story

This split means the **headline operational mode** — "fast local staging in front of a
cheap durable object backend" — is expressible with two one-line directives and needs
*no* random-write emulation, *no* read-modify-write, and *no* dishonest POSIX-over-S3
pretence. It also subsumes a chunk of the FRM/tape-staging shape (Phase 35): a tape or
object backend with a POSIX disk staging buffer is just `staging=posix backend=<slow>`.

## 4. POSIX driver = behaviour-preserving wrapper (Phase 55.A/B)

`sd_posix.c` is **not new logic** — it is the current `src/fs/` and
`src/core/compat/namespace_ops.c` / `src/path/beneath.*` bodies, moved behind the vtable:

| SD op | POSIX implementation (existing) |
|---|---|
| `open` | `xrootd_open_beneath` / `xrootd_open_confined_canon` (the `vfs_open.c` cascade) |
| `pread`/`pwrite` | `xrootd_vfs_pread_full` / `xrootd_vfs_pwrite_full` |
| `fstat` | `fstat(2)` (the `adopt_fd` body) |
| `stat` | `xrootd_lstat_beneath` |
| `unlink`/`mkdir`/`rename`/`server_copy` | `xrootd_ns_delete` / `_mkdir` / `_rename` / `_local_copy` |
| `opendir`/`readdir` | `vfs_dir.c` / the `vfs_io_core.c` `fdopendir` scan |
| `getxattr`…`removexattr` | the `*xattr_confined_canon` helpers |
| `staged_*` | `compat/staged_file` (`xrootd_vfs_staged.c`) |

The persistent per-worker `rootfd` (O_PATH) moves into the POSIX
`xrootd_sd_instance_t`. The `xrootd_ns_*` entry points **stay** (worker-thread TPC/S3
assembly still call them) but become thin forwarders to `sd_posix`'s namespace ops so
there is one implementation.

**Acceptance for 55.A/B:** POSIX-only build, full suite green, zero wire/log/metric
diffs, the §10 perf gate within noise. This is a pure refactor — the entire risk is
"did we preserve POSIX semantics," verified by the existing ~5180-test suite.

### 4.1 POSIX driver implementation order

Move POSIX code in the order that minimizes blast radius:

1. **Introduce wrappers without callsite changes.** `sd_posix.c` calls the same
   helpers `src/fs/` calls today. Unit tests can instantiate the driver directly.
2. **Move byte I/O first.** Change `xrootd_vfs_io_execute()` to call
   `obj->driver->pread/pwrite/fsync/ftruncate` while `obj` still wraps the old fd.
3. **Move open/adopt/close.** Replace `fh->fd` ownership with `fh->obj`; keep
   `xrootd_vfs_file_fd()` temporarily as a POSIX-only compatibility accessor.
4. **Move namespace and metadata.** Replace `xrootd_ns_*` bodies with calls through
   the POSIX driver; keep exported helper names as compatibility shims.
5. **Retire public fd access.** Remove or make private every caller that built its
   own sendfile buffer from `xrootd_vfs_file_fd()`.

After each step, run the static scan:

```bash
rg -n '\b(open|openat|pread|pwrite|fsync|ftruncate|stat|fstat|lstat|rename|unlink|mkdir|opendir|fdopendir|readdir|copy_file_range)\s*\(' src/fs src/core/compat/namespace_ops.c src/fs/path/beneath.c
```

The only remaining matches should be inside `src/fs/backend/sd_posix.c` (plus
documented compatibility shims during 55.B/55.C).

---

## 5. The five hard problems (and their resolutions)

These are the reasons this is a *plan* and not a one-shot edit. Each is a real
abstraction leak that the capability model resolves explicitly.

### 5.1 The fd / sendfile leak  → capability-gated buffer shaping
`vfs_read.c` chooses memory-backed vs file-backed (sendfile) chains. Today the choice
is `is_tls || want_pgcrc`. New rule: **file-backed/sendfile only when
`CAP_SENDFILE`**; otherwise always memory-backed (`pread` into `ngx_pnalloc`,
`b->memory=1`). Object backends thus serve reads as memory chains — correct and
already the TLS path. `xrootd_vfs_file_fd()` is retired from `vfs.h`; the 3 external
callers (§6.1) switch to a capability-aware read helper.

### 5.2 Confinement is a filesystem concept → per-driver confinement primitive
`RESOLVE_BENEATH` is POSIX-only. We keep the VFS `require_confined` logical-path guard
(unchanged), and each driver enforces *physical* confinement itself: POSIX via
`openat2`; object via "logical path → `key_prefix + path`, reject `..`/escape after
normalization." The `EXDEV`-means-escape contract is preserved as a driver-returned
status the VFS maps to `kXR_NotAuthorized`/403 exactly as today.

### 5.3 Random write & rename atomicity → staged-write is the universal write path
Object stores can't `pwrite` at arbitrary offsets and have no atomic `rename`. The
**staged-write lifecycle already models exactly what object PUT needs**: open a temp,
write sequentially, commit atomically. For object backends:
`staged_open`→multipart-init, `staged_write`→buffer/part-upload, `staged_commit`→
complete-multipart (the atomic publish), `staged_abort`→abort-multipart. Random-write
opcodes (`kXR_write` at non-append offsets, WebDAV partial PUT) on a `!RANDOM_WRITE`
backend are rejected with `ENOTSUP`→`kXR_Unsupported`/501, surfaced via a metric — *not*
silently emulated with read-modify-write (an explicit v1 limitation, §8).

Detailed write policy for `!RANDOM_WRITE` backends:

| Operation | Accept? | Requirement |
|---|---|---|
| create new object via WebDAV PUT / S3 PUT / root open+sequential write+close | yes | use staged lifecycle; writes must be contiguous from offset 0 |
| append open | maybe | only if `CAP_APPEND` or staged append emulation explicitly enabled |
| `kXR_write` offset 0 then increasing contiguous offsets | yes | driver may buffer/upload parts; VFS validates monotonicity |
| `kXR_write` hole / rewrite existing offset | no in v1 | `ENOTSUP` + unsupported metric |
| `kXR_pgwrite` | no in v1 for object | page checksums are fine, random page mutation is not |
| `kXR_writev` | no in v1 for object | sparse/multi-offset mutation |
| checkpoint `ckpXeq` write/truncate | no in v1 for object | relies on random mutation and rollback by copy |

This explicit policy is preferable to hidden read-modify-write, which is expensive,
non-atomic, and misleading under concurrent writers.

**The staging store removes most of the pain.** The table above is the policy for
writes that reach the *backend* directly. But uploads do not have to: with a POSIX
**staging store** in front of an object backend (§3.6), the random/out-of-order/
checkpointed writes land on the POSIX staging file — which *does* have
`RANDOM_WRITE | TRUNCATE | APPEND` — and only the finished, sequential object is
promoted to the backend. So a `kXR_write` hole, a `pgwrite`, a `writev`, or a
checkpoint during an **upload in progress** is fully supported as long as the staging
store supports it; the `ENOTSUP` cases above apply only to attempts to randomly mutate
an **already-committed** backend object in place (a true object-store limitation). The
default `staging=posix, backend=posix` deployment supports everything, exactly as today.

### 5.4 `copy_file_range` / CopyObject → `server_copy` cap with stream-through fallback
`xrootd_vfs_copy` (WebDAV COPY, S3 CopyObject) calls `server_copy`; POSIX =
`copy_file_range`, object = S3 `CopyObject`. When `!CAP_SERVER_COPY` (e.g. block
driver, or cross-bucket), the VFS falls back to its own pread→pwrite stream-through
loop (which already exists inside `xrootd_copy_range`).

### 5.5 Blocking network I/O off the event loop → the AIO tier already exists
Object-store ops are blocking network calls; running them on the event loop would
stall a worker (cf. the shmtx postmortem). But Phase 54 already routes the raw-I/O
EXECUTE phase through the AIO thread pool. The object driver's `pread`/`pwrite`/
`server_copy`/`staged_*` simply *are* the thread-pool bodies. Namespace ops
(`stat`/`mkdir`/`rename`/`opendir`) that today run inline on the loop for POSIX
(fast syscalls) must, for the object driver, be offloaded too — so a small number of
currently-inline VFS namespace entry points (`vfs_stat`, `vfs_dir` open, `vfs_mkdir`,
`vfs_rename`, `vfs_unlink`) gain an "offload when `!CAP_DIRS`/object" branch reusing
`xrootd_aio_post_task`. This is the one place the *upper* VFS gains backend-aware code.

---

## 6. Surgical changes above the seam

### 6.1 Retire `xrootd_vfs_file_fd()` (the only real API change)
Callers and their replacement:
- `webdav/get.c`, `s3/object.c`, `shared/file_serve.c` use the fd to build a sendfile
  buf directly. Replace with a new `xrootd_vfs_read()`-family call that returns the
  capability-correct chain (memory or file-backed) — they already have a memory-chain
  path for TLS, so this collapses two branches into one VFS-owned decision.
- `vfs_open.c` internal use stays (now `xrootd_sd_fd(obj)`).

### 6.2 `struct xrootd_vfs_file_s`
`ngx_fd_t fd` → `xrootd_sd_obj_t *obj`. Cached `size/mtime/ctime/ino/mode` stay
(filled from `fstat`→`xrootd_sd_stat_s`). The `stat_current` optimization (phase-45)
is unchanged — it is metadata caching, backend-agnostic.

### 6.3 `xrootd_vfs_ctx_t`
Add **two** instance pointers — the store binding (§3.6):

```c
xrootd_sd_instance_t *sd;          /* backend store — durable, client-visible    */
xrootd_sd_instance_t *sd_staging;  /* staging store — in-progress uploads         */
```

When unconfigured, `sd_staging == sd` (the same POSIX instance rooted at the export
root), so the staged-commit fast path detects identity and uses native rename. The
existing `root_canon`/`rootfd` fields remain meaningful only for the POSIX driver and
move into the POSIX instance; the ctx keeps `root_canon` for logging/identity but the
VFS stops treating it as "the place to syscall."

Read/stat/list/namespace ops always target `sd` (the backend). Only the staged-write
lifecycle consults `sd_staging`, and only commit/promote spans both.

### 6.4 Config / wiring
- Two directives, per server/location, declared alongside the existing storage
  directives in `src/protocols/root/stream/module_cache_proxy_directives.c` (mirror the
  `xrootd_cache_root` string-slot directive), with the conf fields added to the
  `ngx_stream_xrootd_srv_conf_t` struct in `src/core/types/config.h` and merged in
  `src/core/config/server_conf.c` (exact hunks in §17.17–§17.19):
  - `xrootd_storage_backend posix|block|s3 [args…];` — the durable store. Default
    `posix`.
  - `xrootd_storage_staging posix|s3|same [args…];` — the staging store. Default
    `same` (alias = "use the backend instance"), which reproduces today's in-root
    temp+rename exactly.
- Either directive omitted ⇒ POSIX backend + staging-equals-backend ⇒ **zero behaviour
  change** for every existing deployment.
- `sd_registry.c` resolves each name to a `xrootd_sd_driver_t*` and constructs the
  per-export `xrootd_sd_instance_t`(s) at postconfiguration / worker init. When staging
  resolves to `same`, the registry hands back the identical pointer (not a copy) so the
  commit fast-path identity check is a pointer compare.
- New source files registered in the top-level `config` script `NGX_ADDON_SRCS` (this
  needs a `./configure`, per BUILD GOVERNANCE).

### 6.5 Configuration shape

Keep config boring and explicit. Proposed v1:

```nginx
# default; equivalent to omitting both directives (POSIX backend, in-root staging)
xrootd_storage_backend posix;
xrootd_storage_staging  same;

# headline mode: fast POSIX staging in front of a durable object backend
xrootd_storage_backend s3;
xrootd_storage_s3_endpoint https://s3.example.org;
xrootd_storage_s3_bucket cms-prod-data;
xrootd_storage_s3_prefix exports/main/;
xrootd_storage_s3_region us-east-1;
xrootd_storage_s3_auth env;          # env | file | webidentity | static
xrootd_storage_s3_weak_rename off;   # default off; copy+delete only when on
xrootd_storage_s3_xattrs sidecar;    # tags | sidecar | off

xrootd_storage_staging posix;        # stage uploads on a fast local mount...
xrootd_storage_staging_root /var/lib/xrootd/staging;   # ...rooted here
```

Config validation:
- reject a non-POSIX backend **or** non-POSIX staging without a configured thread pool
  for blocking network ops;
- reject `weak_rename on` unless the operator explicitly accepts non-atomic rename;
- when `staging != backend`, **require** that the staging store advertise at least the
  capabilities the enabled protocols need for in-flight writes
  (`RANDOM_WRITE | TRUNCATE` for checkpoint/partial PUT) — else fail `nginx -t` with a
  message naming the missing capability, rather than failing at upload time;
- warn (not fail) when `staging == backend` and the backend lacks `RANDOM_WRITE`: that
  config supports only whole-object sequential PUT, which is legal but surprising —
  point the operator at a POSIX staging store;
- validate bucket/prefix/staging-root syntax at config time, but do not make network
  calls during `nginx -t` unless a future `validate_backend on` directive asks for it;
- include **both** store names + capability bitmaps in startup logs and `/healthz`.

### 6.6 In-memory config structs

Add small config objects rather than inflating `ngx_stream_xrootd_srv_conf_t` with
backend-specific fields:

```c
typedef struct {
    ngx_str_t  name;              /* "posix", "s3", "same", ... */
    void      *driver_conf;       /* parsed backend-specific config */
    uint32_t   required_caps;     /* optional future policy gate */
} xrootd_storage_store_conf_t;
```

`ngx_stream_xrootd_srv_conf_t` should hold the pair:

```c
xrootd_storage_store_conf_t  backend_store;     /* parsed durable-store config  */
xrootd_storage_store_conf_t  staging_store;     /* parsed staging-store config  */
xrootd_sd_instance_t        *backend_instance;  /* built at postconfig/init     */
xrootd_sd_instance_t        *staging_instance;  /* == backend_instance for "same" */
```

The backend-specific parser owns validation of its fields; the registry owns turning
the parsed config into instances and collapsing `staging=same` to a shared pointer.

---

## 7. Phasing (each phase: green tree, 3 tests, perf gate)

| Phase | Scope | Risk | Backend behaviour |
|---|---|---|---|
| **55.A** | Scaffolding: `sd.h` vtable + caps + opaque types + `sd_registry.c`; `xrootd_storage_backend` directive (only `posix` accepted); `xrootd_sd_instance_t` on the ctx; **no callsite rewired yet** | Low | identical |
| **55.B** | `sd_posix.c`: move raw-I/O EXECUTE bodies behind the vtable; `xrootd_vfs_job_t` carries `xrootd_sd_obj_t*`; rewire `vfs_io_core.c` + `vfs_read/write.c` to dispatch via driver. POSIX-only. | Medium | identical |
| **55.C** | Move namespace + dir + stat + xattr + staged + copy behind `sd_posix`; collapse `xrootd_ns_*` to forwarders; retire `xrootd_vfs_file_fd()` (§6.1). Re-express staged-commit as the §3.6.1 decision over `(staging,backend)` instances — but both still POSIX-same, so native rename is the only path exercised. Full POSIX parity. | Medium | identical |
| **55.D** | `sd_block.c`: raw block-device / extent-map driver (`O_DIRECT`, no dirs → flat key map in a superblock). Off by default. Proves the abstraction with a *second* non-trivial backend before S3. | High | new (opt-in) |
| **55.E** | `sd_object.c` + `sd_object_s3.c`: object/S3 driver. Reuses `src/protocols/s3` SigV4/transport. Range-GET reads, multipart-on-staged-commit writes, CopyObject, tag-xattrs, key-prefix dirs. AIO-offloaded namespace ops. **Cross-store promote** (POSIX staging → object backend) lands here: the §3.6.2 composed-staged-lifecycle and the `xrootd_storage_staging` directive become live. Off by default. | High | new (opt-in) |
| **55.F** | Promote object backend: capability-degradation polish, the `!RANDOM_WRITE`/`!SENDFILE` adaptation paths, metrics for every degraded path, full conformance + integrity matrix vs POSIX, docs. Object backend becomes a *supported* (then *recommended*) main backend. | High | parity-gated |

55.A–55.C are a pure refactor (the entire existing suite is the oracle). 55.D–55.F add
capability and are independently revertible (`git revert` the phase commit) and gated
behind `xrootd_storage_backend`.

### 7.1 Detailed work breakdown

#### 55.A — Scaffolding, inert

Deliverables:
- add `src/fs/backend/sd.h`, `sd_registry.c`, `sd_posix.c` stub, README;
- add the `xrootd_storage_backend` **and** `xrootd_storage_staging` directives plus the
  paired config structs (§6.6), defaulting to POSIX backend + `staging=same`;
- the registry collapses `staging=same` to a shared instance pointer;
- register new sources in `config`;
- expose **both** store names/caps in debug logs and `/healthz`;
- add tests for config parse success, unknown backend/staging error, inheritance/default,
  and the staging-capability validation gate (§6.5).

Acceptance:
- no VFS callsite behaviour changes;
- `xrootd_storage_backend posix; xrootd_storage_staging same;` and omitting both produce
  identical config and an identical `sd == sd_staging` pointer;
- unknown backend or staging name fails `nginx -t` with a clear message;
- a `staging != backend` config missing a required staging capability fails `nginx -t`.

#### 55.B — Byte I/O behind SD

Deliverables:
- define `xrootd_sd_obj_t` for POSIX wrapping an fd and stat snapshot;
- change `xrootd_vfs_job_t` from fd-centric to object-centric;
- route READ/WRITE/PGREAD/READV/WRITEV/SYNC/TRUNCATE execute arms through SD ops;
- keep event-loop prepare/complete, cache, metrics, and protocol counters unchanged.

Acceptance:
- no raw `pread`/`pwrite`/`fsync`/`ftruncate` in `src/fs/` except POSIX driver;
- existing read/write/pgread/readv/writev/sync/truncate tests pass;
- perf delta within §10 gate.

#### 55.C — Namespace and fd leak removal

Deliverables:
- move stat/opendir/readdir/mkdir/unlink/rmdir/rename/copy/xattr/staged lifecycle
  behind SD;
- convert `xrootd_ns_*` helpers to POSIX-driver shims or retire direct uses;
- replace public `xrootd_vfs_file_fd()` callers with VFS-owned read/send helpers;
- add a static-check test that fails on new raw storage syscalls outside SD.

Acceptance:
- no public fd accessor needed by protocol/shared-file serving code;
- WebDAV GET, S3 GET, and shared file serving still use sendfile on POSIX when allowed;
- namespace security-negative tests still reject escapes and symlink tricks.

#### 55.D — Block proof backend

Deliverables:
- minimal `sd_block.c` with an extent-map or fixed-size object table;
- no dirs by default; flat key namespace with explicit stat/read/write support;
- O_DIRECT optional, not required for first correctness landing.

Acceptance:
- backend matrix passes for advertised capabilities;
- unsupported operations return `ENOTSUP` and increment the metric;
- no protocol code has block-specific branches.

#### 55.E — Object/S3 backend

Deliverables:
- `sd_object.c` policy core: key mapping, capability checks, metadata model;
- `sd_object_s3.c` transport: HEAD, range GET, PUT/multipart, DELETE, CopyObject,
  ListObjectsV2 prefix listing, tag/sidecar metadata;
- AIO offload for object namespace ops that would block the event loop;
- **cross-store promote**: wire the §3.6.1 commit decision so `staging=posix,
  backend=s3` drives the backend's `staged_*` multipart lifecycle from the POSIX
  staging object, then unlinks the staging temp; make `xrootd_storage_staging` live;
- credential loading, retry/timeout policy, and sanitized error reporting.

Acceptance:
- byte-exact read/write/create/delete/copy for capability-supported operations;
- with a POSIX staging store, **random/out-of-order/checkpointed uploads succeed** and
  land as a single sequential backend object (promote verified byte-exact + cksum);
- attempts to randomly mutate an *already-committed* object still fail predictably;
- failed promote aborts the backend multipart and leaves no visible final object, while
  the staging temp is cleaned by the abort path;
- object key prefix escapes — and staging-root escapes — are refused even if path
  normalization is bypassed in tests;
- cancellation/abort cleans multipart uploads and staging temps.

#### 55.F — Productization

Deliverables:
- docs and operator examples;
- conformance matrix in CI profile that can run against MinIO or a mock S3 server;
- degraded-path metrics and alert examples;
- clear guidance for when object backend is safe as the primary storage backend.

Acceptance:
- documented limitation matrix matches actual runtime behaviour;
- full POSIX suite still passes;
- object backend promoted only after a representative backend matrix is green.

### 7.2 Suggested review boundaries

Keep PRs reviewable:

1. `sd.h` + registry + config only.
2. POSIX object handle + byte I/O only.
3. Namespace/copy/staged/xattr migration.
4. fd accessor retirement and file-serving cleanup.
5. block backend proof.
6. object backend transport.
7. object backend conformance + docs.

Do not mix backend config parsing with byte-I/O rewiring in the same change; if it
breaks, the failure mode becomes too broad to bisect quickly.

---

## 8. Explicit v1 limitations (documented, metric-surfaced — never silent)

- **No arbitrary random write *in place* on already-committed object backends.**
  Non-append/non-sequential writes against a durable object → `ENOTSUP`/501 +
  `xrootd_sd_unsupported_total{op,backend}` counter. (RMW emulation is a deliberate
  later option, not v1.) **Mitigation:** a POSIX **staging store** (§3.6) makes
  random/out-of-order/checkpointed *uploads* work — the limitation is only about
  re-mutating an object that has already been promoted to the backend.
- **No `rename` atomicity guarantee on object backends** unless the store offers it;
  `rename` = server-copy + delete with a clearly-logged non-atomic window.
- **`fdatasync`/durability** semantics differ — object commit *is* the durability point;
  per-write `fsync` is a no-op on object backends (documented).
- **xattr ⊆ object tags** — object stores cap tag count/size; oversized xattr sets
  (WebDAV dead-properties, lock DB) fall back to a sidecar object, or are rejected with
  a clear error if the sidecar is disabled.
- **One backend per export.** No hybrid/tiered backend in this phase (that is the FRM /
  Phase-35 tape-staging story, which can later be re-expressed as a *tiering driver*).

---

## 9. Test strategy

1. **POSIX parity (55.A–C):** the existing ~5180-test suite must stay green with zero
   diffs. This is the primary correctness oracle for the refactor.
2. **Backend-parity matrix (55.D–F):** a new `tests/test_storage_backend_matrix.py`
   parametrizing the *same* operation set across `posix` / `block` / `s3` instances,
   asserting byte-identical reads, correct checksums (CRC32c/CRC64/page-CRC), and
   identical wire/HTTP/S3 responses where the capability is present — and the *correct
   error* (501/`kXR_Unsupported` + the metric) where it is absent.
3. **Confinement security-negative per driver:** path-escape (`..`, absolute, symlink),
   key-prefix escape for object, must all be refused (`EXDEV`/`kXR_NotAuthorized`/403) —
   reuse `tests/test_attack_vectors.py` against each backend.
4. **Integrity matrix reuse:** run `tests/test_integrity_matrix.py` (byte-exact + cksum
   r/w) with the object backend as the export, across direct/proxy/cache topologies.
5. **3 tests per change** throughout (success + error + security-negative), per
   `AGENTS.md`.

### 9.1 Backend conformance matrix

Each backend test should declare the capability it is testing and whether success or
unsupported is expected:

| Operation family | POSIX | block | object/S3 | Required assertions |
|---|---|---|---|---|
| open/read/close | success | success | success | byte-exact, EOF semantics, correct stat size |
| cleartext sendfile path | success | maybe | unsupported/degraded | POSIX emits file-backed path; object emits memory path |
| TLS/memory read | success | success | success | same bytes and counters as cleartext |
| range read | success | success | success | offset/length correctness, EOF short read |
| sequential create/write/commit | success | success | success | final bytes, durable after reopen |
| random write (direct to backend) | success | maybe | unsupported | object returns `kXR_Unsupported`/501 and metric increments |
| random/out-of-order upload via POSIX staging → object backend | success | n/a | success | promote lands one sequential object; byte-exact + cksum; staging temp gone |
| staged-commit fast path (`staging==backend`, POSIX) | atomic rename | atomic rename | n/a | no promote bytes recorded; identical to today |
| cross-store promote bytes | n/a | n/a | counted on backend | `xrootd_sd_degraded_total{op=commit,reason=promote}` increments |
| pgread | success | maybe | success if range-read only | per-page CRC framing identical |
| pgwrite/writev | success | maybe | unsupported v1 | no partial mutation on unsupported result |
| truncate | success | maybe | unsupported v1 | no size change when unsupported |
| rename | atomic success | maybe | unsupported or weak when enabled | weak rename logs degradation |
| copy | server/local copy | stream or native | CopyObject or stream | byte-exact, overwrite policy |
| dirlist | real dirs | maybe | prefix listing | dot entries hidden, stat format stable |
| xattr/fattr | user xattrs | unsupported | tags/sidecar | size limits and errors explicit |
| checkpoint | success | unsupported | unsupported v1 | rollback integrity for POSIX |

### 9.2 Static checks

Add a cheap CI check once 55.C lands:

```bash
rg -n '\b(open|openat|pread|pwrite|fsync|ftruncate|stat|fstat|lstat|rename|unlink|mkdir|opendir|fdopendir|readdir|copy_file_range|getxattr|setxattr|listxattr|removexattr)\s*\(' \
  src/fs src/core/compat/namespace_ops.c src/fs/path/beneath.c \
  | rg -v 'src/fs/backend/sd_posix\.c|allowed_compat_shim'
```

The allowlist must be small, named, and documented. Comments and docs are fine; new
runtime syscall sites outside SD are not.

### 9.3 Failure-injection tests

Object backend needs storage-specific failures that POSIX cannot exercise:

- HEAD returns 404 after LIST showed a key: read/open maps to missing object cleanly.
- multipart upload fails part N: staged abort runs and leaves no visible final object.
- CompleteMultipartUpload returns ETag mismatch/stale generation: commit fails with
  no silent success.
- CopyObject succeeds but DeleteObject fails during weak rename: destination exists,
  source remains, log names non-atomic cleanup failure.
- credential expires mid-transfer: retry/refresh policy is exercised or the op fails
  with `ETIMEDOUT`/`EACCES` as configured.
- ListObjectsV2 pagination: dirlist emits all entries without duplicate/skipped keys.
- promote crash window: kill the worker between backend `staged_commit` success and
  staging-temp `unlink` — restart leaves the durable object present and at most a stale
  staging temp (reclaimed by the staging-store sweeper), never a missing object.
- staging store full (`ENOSPC`) mid-upload: the upload fails before any backend write;
  no partial object is created in the backend.

---

## 10. Performance gate

The POSIX hot path gains exactly one predicted indirect call per raw op (`obj->driver->
pread`). Gate: `tests/profile_load.sh` + `run_load_test.sh` read/write throughput and
p99 latency must stay within measurement noise (≤1%) of the pre-phase baseline for the
POSIX backend. If the indirection shows up, the POSIX driver's `pread`/`pwrite` get a
`static ngx_inline` fast-path keyed on `caps & CAP_FD` (devirtualization) before the
vtable call — the same trick io_uring uses. Object-backend latency is governed by the
network, not the abstraction, and is measured separately against a real/MinIO endpoint.

Detailed measurements:

| Gate | Command/profile | Pass condition |
|---|---|---|
| POSIX read throughput | `tests/profile_load.sh` read profile | median and p99 within 1% of baseline |
| POSIX write throughput | `run_load_test.sh` write profile | median and p99 within 1% of baseline |
| sendfile preservation | cleartext WebDAV/S3/root reads | still uses file-backed buffers when `CAP_SENDFILE` |
| TLS memory path | roots/WebDAV TLS reads | no regression beyond noise |
| AIO saturation | concurrent read/write with thread pool | no queue growth/regression vs Phase 54 |
| object baseline | MinIO/local S3 profile | report only until backend is supported; not compared to POSIX |

If POSIX indirection is measurable, first try devirtualizing only the hot byte-I/O
path. Do not undo the SD seam or special-case protocol handlers.

---

## 11. Documentation deliverables

- `src/fs/backend/README.md` — the SD contract, capability semantics, how to write a
  driver, the worker-safe rule for raw ops.
- Update `src/fs/README.md` — the "POSIX-filesystem data plane" framing becomes
  "pluggable storage data plane"; add the SD seam to the control-flow section and the
  event-loop-only boundary note.
- Update `AGENTS.md` HELPERS/INVARIANTS — add the `xrootd_sd_*` seam and the
  capability-degradation rule (sendfile only on `CAP_SENDFILE`).
- A `docs/10-reference/storage-backends.md` operator guide — choosing a backend, the
  capability/limitation matrix, S3 endpoint config, the v1 limitations from §8.

Also update examples:
- add a minimal POSIX config proving the default is unchanged;
- add a MinIO/dev object-backend config with explicit limitations;
- add an operator warning block for weak rename and unsupported random writes;
- document which protocols are safe with object backend v1 (`GET`, full-object PUT,
  stat/list/copy where configured) and which are not (`writev`, checkpoint, arbitrary
  mutation).

---

## 12. Open questions (resolve before 55.E)

1. **Caching interplay.** The read-through/write-through cache (`src/fs/cache/`) is itself
   a POSIX store. With an object *main* backend, the cache likely becomes the POSIX
   driver in front of the object driver — i.e. caching is naturally re-expressed as a
   **two-driver tiering stack**. Decide whether to model the cache as a composing
   `sd_cache.c` driver (clean, recursive) or keep the existing cache hooks (less churn).
   *Recommendation: model it as a tiering driver in 55.F — it subsumes Phase-26 slice
   caching and the Phase-35 tape tier under one composition mechanism.*
2. **CMS / FRM.** Does the cluster/manager plane need backend awareness (e.g.
   space reporting from object-store quotas)? Probably yes for `kXR_query` space — scope
   into 55.F or defer.
3. **Impersonation (Phase-40).** The root broker opens POSIX fds with dropped privilege.
   Object backends authenticate to the store with a service credential — per-user
   impersonation maps to per-user store credentials or request-signing identity. Define
   the object-driver identity model before 55.E.
4. **io_uring (Phase-44).** Confirmed orthogonal: `CAP_IOURING` gates the io_uring tier;
   non-fd backends never enter it. No io_uring code changes beyond the capability check.
5. **Staging-temp reclamation.** A separate staging store needs a sweeper for temps
   orphaned by crashes mid-promote (the §9.3 crash window). Decide whether to reuse the
   existing staged-file cleanup timer or add a staging-store-scoped sweep with a
   configurable max-temp-age. *Recommendation: extend the existing `compat/staged_file`
   cleanup to scan the staging root; gate behind `xrootd_storage_staging_reap_age`.*
6. **Staging sizing / backpressure.** With POSIX staging in front of a slow backend, a
   burst of large uploads can fill the staging mount before promotes drain it. Decide the
   admission-control story: reuse the Phase-31 memory-budget / `kXR_wait` mechanism to
   shed when the staging store crosses a high-water mark, vs hard `ENOSPC`. Scope into
   55.F.

---

## 13. Rollback & safety

- Each phase is one atomic commit; rollback is `git revert <phase-commit>`.
- 55.D–55.F are inert unless `xrootd_storage_backend` names a non-POSIX backend, so they
  cannot regress any existing deployment.
- The `xrootd_storage_backend posix` default means a config that doesn't mention the
  directive behaves exactly as today, forever.
- Keep POSIX as the only backend enabled in default test configs until 55.F. Non-POSIX
  tests should opt in with an environment flag or dedicated config file.
- Do not migrate persistent on-disk metadata automatically. If a backend needs sidecar
  metadata, version it and make migration an explicit operator action.
- Never make object backend the default in the same change that introduces it.

### 13.1 Pre-implementation checklist

Before starting 55.A:

- refresh a POSIX baseline: build, `nginx -t`, focused read/write/namespace tests,
  and one load profile;
- save the static syscall inventory from §4.1;
- identify every public `xrootd_vfs_file_fd()` caller and write down its replacement;
- decide whether the first object test target is MinIO, moto/local mock, or a real S3
  endpoint;
- confirm the selected CI profile can run without external credentials by default.

---

## 14. Summary

Phase 54 made the VFS the single chokepoint for *all* I/O. Phase 55 cuts a
capability-typed driver seam directly beneath that chokepoint, turning "the VFS *is*
POSIX" into "the VFS *uses* a storage driver, of which POSIX is one." Each export binds
a **pair** of drivers — a durable **backend store** and an in-progress **staging
store**, both defaulting to the same POSIX instance so nothing changes for existing
deployments. Splitting them is what makes the headline mode honest: stage random,
checkpointed, out-of-order uploads on fast POSIX scratch, then **promote** the finished
object into a cheap durable object backend as one sequential multipart PUT — no
read-modify-write, no POSIX-over-S3 pretence. The POSIX driver is a behaviour-preserving
wrapper proven by the existing suite; the block and object drivers land behind config
flags and a parity matrix; and the object/S3 backend becomes a first-class — ultimately
primary — storage backend without a single protocol handler, metric, cache, or
access-log line changing above the seam.

---

# Implementation Appendices (Hyper-Detail)

> Sections 15–29 are the near-final implementation reference for Phase 55, in the
> style of the Phase-44 io_uring appendices: annotated source skeletons, exact edit
> hunks, sequence diagrams, concurrency proofs, error-mapping, capacity/failure
> models, observability, PR-by-PR rollout, CI gating, formal requirements +
> traceability, ADRs, and a glossary. Where an appendix names a concrete file or
> line number, treat `src/` as authoritative — verify before editing.

## 15. Annotated source skeletons — `sd.h`, `sd_registry.c`, `sd_posix.c`

This appendix turns §3 (the SD interface) and §4 (the POSIX wrapper) into
near-final source skeletons for the three files that land in **55.A/55.B**. They are
*scaffolding-complete*: every type from §3.1–§3.3.1 is fully declared, every vtable
slot has a concrete POSIX body that delegates to an **existing** helper, and the
registry has real bodies (no `// TODO`). Storage-specific work is always pushed into
the driver vtable; the registry and helpers stay backend-agnostic.

Conventions held throughout, per `docs/09-developer-guide/coding-standards.md` and the
project FAQ:

- nginx types only (`ngx_int_t`, `ngx_pool_t`, `ngx_log_t`, `ngx_fd_t`,
  `NGX_OK`/`NGX_ERROR`/`NGX_DECLINED`, `NGX_INVALID_FILE`);
- **no `goto`** — early-return + helper decomposition;
- every function carries a `/* ---- name — one-line ---- \n * WHAT:/WHY:/HOW: */`
  doc block;
- the raw-I/O ops (`pread`/`pwrite`/`ftruncate`/`fsync`/`fstat`) obey the Phase-54
  EXECUTE contract: **no nginx-pool allocation, no metrics, no logs** — they only
  touch the storage and the caller-owned buffers (§3.3 *Notes*);
- drivers return storage facts (`errno`-style), never wire status (§3.3.2); the VFS
  maps them.

The POSIX driver is a **behaviour-preserving wrapper** (§4): each body is literally
today's `src/fs/`, `src/core/compat/namespace_ops.c`, and `src/path/beneath.*` code, moved
behind the vtable. No new storage logic is introduced — the existing ~5180-test suite
is the oracle.

---

### 15.1 `src/fs/backend/sd.h`

The complete public header for the SD layer: the capability bitmap, the opaque
typedefs, the two POD result structs, the full vtable, the `XROOTD_SD_O_*` open-flag
constants, the helper API (§3.3.1), and the registry API (§6.4). Everything above the
`sd_*.c` files includes only this header — never a driver's private layout.

```c
/*
 * sd.h — the Storage Driver (SD) interface: capability-typed vtable below the VFS.
 *
 * WHAT: Declares the storage-driver seam introduced by Phase 55. Defines the
 *       capability bitmap (xrootd_sd_cap_t), the opaque handle/driver/instance
 *       typedefs (xrootd_sd_driver_t, xrootd_sd_instance_t, xrootd_sd_obj_t,
 *       xrootd_sd_dir_t, xrootd_sd_staged_t), the protocol-neutral POD result
 *       structs (xrootd_sd_stat_s, xrootd_sd_dirent_s), the SD open-flag
 *       constants (XROOTD_SD_O_*), the full driver vtable (struct
 *       xrootd_sd_driver_s), the capability-gated helper API, and the registry
 *       API used by config/postconfig to build per-export instances.
 *
 * WHY:  The VFS (src/fs/) must shape its behaviour (sendfile vs memory chain,
 *       random-write acceptance, server-copy vs stream-through) from what the
 *       backend can actually do, not from a hard-wired POSIX assumption. The
 *       vtable is the only place raw storage primitives live; the capability
 *       bitmap is the only honest abstraction over filesystem / block / object
 *       stores. Callers read capabilities through xrootd_sd_supports(), never by
 *       poking driver->caps, so policy stays in one place.
 *
 * HOW:  A driver provides a static xrootd_sd_driver_t with a caps bitmap and a
 *       flat table of POD-pointer function slots. The registry (sd_registry.c)
 *       resolves a config name to a driver and builds one xrootd_sd_instance_t
 *       per export (collapsing staging=same to a shared pointer). The VFS opens
 *       objects via the instance, dispatches worker-safe byte I/O through the
 *       handle's driver, and consults capabilities via the helpers below.
 */
#ifndef XROOTD_SD_H
#define XROOTD_SD_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../vfs.h"   /* xrootd_vfs_stat_t for xrootd_sd_stat_to_vfs() */

/* ---- capability bitmap (§3.1) ---------------------------------------------
 * WHAT: One bit per storage primitive a driver may or may not support.
 * WHY:  The VFS degrades gracefully on each absent capability (sendfile ->
 *       memory chain, server-copy -> stream-through, random-write -> reject),
 *       always with a metric + log line — never a silent drop (§3.1 table).
 * HOW:  A driver ORs the bits it honestly supports into its caps field. POSIX
 *       advertises all of them; the S3 object driver advertises
 *       RANGE_READ | SERVER_COPY | XATTR and crucially NOT FD | SENDFILE |
 *       RANDOM_WRITE | HARD_RENAME | DIRS | IOURING.
 */
typedef enum {
    XROOTD_SD_CAP_FD            = 1u << 0,  /* exposes a real kernel fd            */
    XROOTD_SD_CAP_SENDFILE      = 1u << 1,  /* fd is sendfile/splice-able          */
    XROOTD_SD_CAP_RANDOM_WRITE  = 1u << 2,  /* pwrite at arbitrary offset          */
    XROOTD_SD_CAP_RANGE_READ    = 1u << 3,  /* pread at arbitrary offset           */
    XROOTD_SD_CAP_TRUNCATE      = 1u << 4,  /* ftruncate                           */
    XROOTD_SD_CAP_SERVER_COPY   = 1u << 5,  /* native copy (copy_file_range/COPY)  */
    XROOTD_SD_CAP_XATTR         = 1u << 6,  /* user.* xattrs / object metadata     */
    XROOTD_SD_CAP_HARD_RENAME   = 1u << 7,  /* atomic rename (else copy+delete)    */
    XROOTD_SD_CAP_DIRS          = 1u << 8,  /* real directories (else key-prefix)  */
    XROOTD_SD_CAP_APPEND        = 1u << 9,  /* O_APPEND semantics                  */
    XROOTD_SD_CAP_IOURING       = 1u << 10, /* fd is io_uring-submittable          */
} xrootd_sd_cap_t;

/* The POSIX driver supports everything: the union of every capability bit. */
#define XROOTD_SD_CAPS_POSIX_ALL                                              \
    (XROOTD_SD_CAP_FD          | XROOTD_SD_CAP_SENDFILE  |                    \
     XROOTD_SD_CAP_RANDOM_WRITE| XROOTD_SD_CAP_RANGE_READ|                    \
     XROOTD_SD_CAP_TRUNCATE    | XROOTD_SD_CAP_SERVER_COPY|                   \
     XROOTD_SD_CAP_XATTR       | XROOTD_SD_CAP_HARD_RENAME|                   \
     XROOTD_SD_CAP_DIRS        | XROOTD_SD_CAP_APPEND    |                    \
     XROOTD_SD_CAP_IOURING)

/* ---- opaque types (§3.2) --------------------------------------------------
 * WHAT: Forward typedefs for the driver descriptor, a per-export instance, an
 *       open object handle, a directory iterator, and a staged-write handle.
 * WHY:  The VFS never dereferences driver-private fields (§3.2 rule 4). Each
 *       driver defines the concrete struct in its own .c; everyone else holds
 *       only the pointer and reaches state through the helper API.
 * HOW:  Concrete definitions live in sd_posix.c / sd_block.c / sd_object.c.
 */
typedef struct xrootd_sd_driver_s   xrootd_sd_driver_t;
typedef struct xrootd_sd_instance_s xrootd_sd_instance_t;
typedef struct xrootd_sd_obj_s      xrootd_sd_obj_t;
typedef struct xrootd_sd_dir_s      xrootd_sd_dir_t;
typedef struct xrootd_sd_staged_s   xrootd_sd_staged_t;

/* ---- SD open flags (map of XROOTD_VFS_O_* -> XROOTD_SD_O_*) ----------------
 * WHAT: Backend-neutral open intents passed to driver->open(). Distinct from
 *       both XROOTD_VFS_O_* (the public VFS surface) and raw POSIX O_* (a
 *       filesystem concept that must not leak below the seam as the contract).
 * WHY:  An object store has no O_PATH/O_NOFOLLOW and treats CREATE/EXCL as
 *       conditional-PUT semantics. Giving the driver intents (not POSIX bits)
 *       lets each driver translate to its own primitive. The POSIX driver maps
 *       these straight back to O_* (15.3).
 * HOW:  The VFS translates its XROOTD_VFS_O_* request into this set with
 *       xrootd_sd_flags_from_vfs() before calling driver->open().
 */
#define XROOTD_SD_O_READ      0x01   /* <- XROOTD_VFS_O_READ      */
#define XROOTD_SD_O_WRITE     0x02   /* <- XROOTD_VFS_O_WRITE     */
#define XROOTD_SD_O_CREATE    0x04   /* <- XROOTD_VFS_O_CREATE    */
#define XROOTD_SD_O_EXCL      0x08   /* <- XROOTD_VFS_O_EXCL      */
#define XROOTD_SD_O_TRUNC     0x10   /* <- XROOTD_VFS_O_TRUNC     */
#define XROOTD_SD_O_APPEND    0x20   /* <- XROOTD_VFS_O_APPEND    */

/* ---- xrootd_sd_stat_s — protocol-neutral stat result (POD) ----------------
 * WHAT: The fields the VFS needs from a stat/fstat, free of struct stat layout.
 * WHY:  Keeps `struct stat` (and its st_* fields) below the seam. Object stores
 *       fill it from HEAD metadata; POSIX fills it from fstat/lstat. The VFS
 *       copies it into xrootd_vfs_stat_t via xrootd_sd_stat_to_vfs().
 * HOW:  Drivers zero it, then set size/mtime/ctime/mode/ino and the two
 *       derived bits. mode carries POSIX-style type+perm bits where meaningful;
 *       a pure object store synthesizes a regular-file mode.
 */
typedef struct xrootd_sd_stat_s {
    off_t       size;
    time_t      mtime;
    time_t      ctime;
    mode_t      mode;
    ino_t       ino;
    unsigned    is_directory:1;
    unsigned    is_regular:1;
} xrootd_sd_stat_t;

/* ---- xrootd_sd_dirent_s — one directory entry (POD) -----------------------
 * WHAT: A single child name plus an optional child stat from a readdir step.
 * WHY:  The dirlist scan must not see DIR*/struct dirent (POSIX) or a paginated
 *       ListObjectsV2 page (object); both reduce to "name [+ stat]" here.
 * HOW:  closedir-bounded iteration writes name (NUL-terminated, <= name_cap)
 *       and, when have_stat, the child stat. "." and ".." are filtered by the
 *       driver, matching today's xrootd_vfs_readdir().
 */
typedef struct xrootd_sd_dirent_s {
    char              name[NAME_MAX + 1];
    xrootd_sd_stat_t  st;
    unsigned          have_stat:1;
} xrootd_sd_dirent_t;

/* ---- struct xrootd_sd_driver_s — the vtable (§3.3) -------------------------
 * WHAT: The flat, POD-pointer-only table of raw storage primitives plus the
 *       driver name and capability bitmap. This struct IS the descriptor table
 *       that replaces a branch ladder (coding-standards: descriptor-driven).
 * WHY:  One predicted indirect call per raw op (§10) buys a clean seam. Keeping
 *       the table flat lets the object driver run its blocking calls inside the
 *       existing AIO thread pool with zero event-loop coupling (§3.3 Notes).
 * HOW:  A driver provides a static const-initialized instance of this struct.
 *       inst-keyed ops take a *logical* (VFS-confined) path; obj-keyed ops take
 *       an open handle. Raw byte I/O is worker-safe (no pool/metrics/log).
 */
struct xrootd_sd_driver_s {
    const char    *name;          /* "posix" | "block" | "s3"                  */
    uint32_t       caps;          /* xrootd_sd_cap_t bitmap                     */

    /* ---- instance lifecycle (per export, at config/worker init) ---- */
    ngx_int_t  (*init)   (xrootd_sd_instance_t *inst, ngx_log_t *log);
    void       (*cleanup)(xrootd_sd_instance_t *inst);

    /* ---- object lifecycle (logical path already confined by the VFS) ---- */
    xrootd_sd_obj_t *(*open) (xrootd_sd_instance_t *inst,
                              const char *logical_path, int sd_flags,
                              mode_t mode, int *err_out);
    ngx_int_t  (*close)(xrootd_sd_obj_t *obj);

    /* ---- raw byte I/O (worker-safe; the EXECUTE phase calls these) ---- */
    ssize_t    (*pread) (xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off);
    ssize_t    (*pwrite)(xrootd_sd_obj_t *obj, const void *buf, size_t len, off_t off);
    ngx_int_t  (*ftruncate)(xrootd_sd_obj_t *obj, off_t len);
    ngx_int_t  (*fsync) (xrootd_sd_obj_t *obj);
    ngx_int_t  (*fstat) (xrootd_sd_obj_t *obj, struct xrootd_sd_stat_s *out);

    /* ---- namespace (logical paths; replace the xrootd_ns_* tier) ---- */
    ngx_int_t  (*stat)  (xrootd_sd_instance_t *inst, const char *path,
                         struct xrootd_sd_stat_s *out);
    ngx_int_t  (*unlink)(xrootd_sd_instance_t *inst, const char *path, int is_dir);
    ngx_int_t  (*mkdir) (xrootd_sd_instance_t *inst, const char *path, mode_t mode);
    ngx_int_t  (*rename)(xrootd_sd_instance_t *inst, const char *src,
                         const char *dst, int noreplace);
    ngx_int_t  (*server_copy)(xrootd_sd_instance_t *inst, const char *src,
                              const char *dst, off_t *bytes_out);

    /* ---- directory iteration ---- */
    xrootd_sd_dir_t *(*opendir)(xrootd_sd_instance_t *inst, const char *path,
                                int *err_out);
    ngx_int_t  (*readdir)(xrootd_sd_dir_t *d, struct xrootd_sd_dirent_s *out);
    ngx_int_t  (*closedir)(xrootd_sd_dir_t *d);

    /* ---- xattr / object metadata ---- */
    ssize_t    (*getxattr)(xrootd_sd_instance_t *inst, const char *path,
                           const char *name, void *buf, size_t cap);
    ssize_t    (*listxattr)(xrootd_sd_instance_t *inst, const char *path,
                            void *buf, size_t cap);
    ngx_int_t  (*setxattr)(xrootd_sd_instance_t *inst, const char *path,
                           const char *name, const void *val, size_t len, int flags);
    ngx_int_t  (*removexattr)(xrootd_sd_instance_t *inst, const char *path,
                              const char *name);

    /* ---- staged/atomic write (multipart for object stores) ---- */
    xrootd_sd_staged_t *(*staged_open)(xrootd_sd_instance_t *inst,
                                       const char *final_path, mode_t mode,
                                       int *err_out);
    ssize_t    (*staged_write)(xrootd_sd_staged_t *st, const void *buf,
                               size_t len, off_t off);
    ngx_int_t  (*staged_commit)(xrootd_sd_staged_t *st, int noreplace);
    void       (*staged_abort) (xrootd_sd_staged_t *st);
};

/* ---- capability-gated helper API (§3.3.1) ---------------------------------
 * WHAT: Small accessors so callers never touch driver->caps or driver-private
 *       struct fields directly. xrootd_sd_caps()/fd() are handle-keyed;
 *       backend_name()/supports() are instance-keyed; stat_to_vfs() is the one
 *       result translation.
 * WHY:  The VFS must read as policy ("if (!supports(RANGE_READ)) reject") not as
 *       repeated bit-twiddling scattered across protocol modules (§3.3.1).
 * HOW:  Each returns a safe default for a NULL argument (caps 0, fd
 *       NGX_INVALID_FILE, name "posix"/"", supports NGX_DECLINED) so callers
 *       need no NULL guards of their own.
 */
uint32_t    xrootd_sd_caps(const xrootd_sd_obj_t *obj);
ngx_fd_t    xrootd_sd_fd(const xrootd_sd_obj_t *obj);
const char *xrootd_sd_backend_name(const xrootd_sd_instance_t *inst);

/* NGX_OK iff the instance's driver advertises every bit in required_caps;
 * NGX_DECLINED otherwise (the caller sets errno=ENOTSUP and rejects). */
ngx_int_t   xrootd_sd_supports(const xrootd_sd_instance_t *inst,
                               uint32_t required_caps);

/* Copy an SD stat into the VFS stat the protocol layers already consume. */
void        xrootd_sd_stat_to_vfs(const xrootd_sd_stat_t *in,
                                  xrootd_vfs_stat_t *out);

/* Translate the VFS open-intent bitmap (XROOTD_VFS_O_*) into XROOTD_SD_O_*.
 * Pure; no allocation. Defined in sd_registry.c next to the helpers. */
int         xrootd_sd_flags_from_vfs(ngx_uint_t vfs_flags);

/* ---- registry API (§6.4) --------------------------------------------------
 * WHAT: driver registration + per-export instance construction/teardown.
 * WHY:  config/postconfig resolves a name ("posix"/"block"/"s3") to a driver
 *       and binds it to an export root/prefix once. staging=same collapses to a
 *       shared instance pointer so the §3.6.1 commit fast-path is a pointer
 *       compare with zero extra copy.
 * HOW:  Drivers self-register their static descriptor (typically from a module
 *       init). instance_create() looks up the name, allocates the instance from
 *       `pool`, stashes driver_conf, and calls driver->init().
 */
ngx_int_t xrootd_sd_driver_register(const xrootd_sd_driver_t *driver);

xrootd_sd_instance_t *xrootd_sd_instance_create(ngx_pool_t *pool, ngx_log_t *log,
    const char *driver_name, void *driver_conf);

void xrootd_sd_instance_destroy(xrootd_sd_instance_t *inst);

#endif /* XROOTD_SD_H */
```

---

### 15.2 `src/fs/backend/sd_registry.c`

The registry: a static table of registered drivers, the name→driver resolver, the
instance constructor with the `staging=same` pointer-collapse handled by the *caller*
(the registry only ever builds one instance; identity collapse is a pointer compare in
config wiring), and the helper bodies. The instance struct is defined here because the
helpers operate on its driver-agnostic head (`driver`, `driver_conf`); each driver
embeds this head as the first member of its own private instance struct so the registry
and the driver share one allocation.

```c
/*
 * sd_registry.c — name->driver lookup and per-export SD instance binding.
 *
 * WHAT: Owns the static table of registered storage drivers, resolves a config
 *       name to a driver, builds/destroys the driver-agnostic instance head,
 *       and implements the capability-gated helper API from sd.h (caps, fd,
 *       supports, stat_to_vfs, backend_name, flags_from_vfs).
 *
 * WHY:  Drivers must not know about each other and callers must not know about
 *       any driver's private layout. A single registry keeps name resolution,
 *       instance lifetime, and capability queries in one backend-agnostic place
 *       (§6.4). Storage-specific work stays in driver->init/open/... .
 *
 * HOW:  Drivers self-register a static descriptor. instance_create() looks up
 *       the name, pcalloc's an xrootd_sd_instance_t head from the caller pool,
 *       records driver+driver_conf+log, then calls driver->init(); the driver
 *       extends the head via container_of-style embedding (its struct's first
 *       member is the head). The helpers read only the head + driver->caps.
 */
#include "sd.h"

#include <errno.h>

/* The instance head every driver embeds as its first member. The registry and
 * the helpers touch only these fields; driver-private state follows in the
 * driver's own struct (see sd_posix.c xrootd_sd_instance_s). */
struct xrootd_sd_instance_s {
    const xrootd_sd_driver_t *driver;       /* resolved vtable + caps        */
    void                     *driver_conf;  /* parsed backend-specific config */
    ngx_log_t                *log;
    ngx_pool_t               *pool;
};

/* Bounded static registry — three drivers in the plan (posix/block/s3). */
#define XROOTD_SD_MAX_DRIVERS 8
static const xrootd_sd_driver_t *xrootd_sd_drivers[XROOTD_SD_MAX_DRIVERS];
static ngx_uint_t                xrootd_sd_driver_count;

/* ---- xrootd_sd_driver_register — record a driver descriptor -------------
 * WHAT: Append `driver` to the static registry if not already present.
 * WHY:  Drivers self-register their static vtable so the registry needs no
 *       compile-time list of every backend; the config name later selects one.
 * HOW:  Validate the descriptor has a name, reject duplicates by name, reject
 *       overflow, then store the pointer. Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t
xrootd_sd_driver_register(const xrootd_sd_driver_t *driver)
{
    ngx_uint_t i;

    if (driver == NULL || driver->name == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < xrootd_sd_driver_count; i++) {
        if (ngx_strcmp(xrootd_sd_drivers[i]->name, driver->name) == 0) {
            return NGX_OK;   /* idempotent: re-register is a no-op */
        }
    }

    if (xrootd_sd_driver_count >= XROOTD_SD_MAX_DRIVERS) {
        return NGX_ERROR;
    }

    xrootd_sd_drivers[xrootd_sd_driver_count++] = driver;
    return NGX_OK;
}

/* ---- xrootd_sd_driver_lookup — resolve a name to a descriptor -----------
 * WHAT: Linear scan of the registry for an exact name match.
 * WHY:  instance_create() and config validation both need name->driver; one
 *       private resolver keeps the lookup in a single spot.
 * HOW:  ngx_strcmp over the small static table; NULL when not found.
 */
static const xrootd_sd_driver_t *
xrootd_sd_driver_lookup(const char *name)
{
    ngx_uint_t i;

    if (name == NULL) {
        return NULL;
    }

    for (i = 0; i < xrootd_sd_driver_count; i++) {
        if (ngx_strcmp(xrootd_sd_drivers[i]->name, name) == 0) {
            return xrootd_sd_drivers[i];
        }
    }

    return NULL;
}

/* ---- xrootd_sd_instance_create — build one per-export SD instance --------
 * WHAT: Resolve driver_name, allocate the instance head from `pool`, attach the
 *       parsed driver_conf, and run driver->init().
 * WHY:  An export binds to exactly one backend instance at config/worker init
 *       (§2.3). The driver owns its root/prefix confinement state, opened here.
 * HOW:  Early-return NULL on unknown name or OOM (errno=EINVAL/ENOMEM); pcalloc
 *       the head; record driver/conf/log/pool; call driver->init() if present
 *       and return NULL when it fails. staging=same is NOT handled here — the
 *       caller reuses the returned pointer (a pointer compare drives the §3.6.1
 *       commit fast path), so the registry never duplicates an instance.
 */
xrootd_sd_instance_t *
xrootd_sd_instance_create(ngx_pool_t *pool, ngx_log_t *log,
    const char *driver_name, void *driver_conf)
{
    const xrootd_sd_driver_t *driver;
    xrootd_sd_instance_t     *inst;

    driver = xrootd_sd_driver_lookup(driver_name);
    if (driver == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd: unknown storage backend \"%s\"",
                      driver_name ? driver_name : "(null)");
        errno = EINVAL;
        return NULL;
    }

    inst = ngx_pcalloc(pool, sizeof(*inst));
    if (inst == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    inst->driver      = driver;
    inst->driver_conf = driver_conf;
    inst->log         = log;
    inst->pool        = pool;

    if (driver->init != NULL && driver->init(inst, log) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd: storage backend \"%s\" init failed", driver->name);
        return NULL;   /* driver->init left errno set and cleaned its own state */
    }

    return inst;
}

/* ---- xrootd_sd_instance_destroy — tear down an SD instance --------------
 * WHAT: Run the driver's cleanup hook (close root fds / transport handles).
 * WHY:  Worker shutdown / config reload must release backend resources; the
 *       instance head itself lives on the pool and is reclaimed with it.
 * HOW:  NULL-safe; call driver->cleanup() if provided. No free of the head.
 */
void
xrootd_sd_instance_destroy(xrootd_sd_instance_t *inst)
{
    if (inst == NULL || inst->driver == NULL) {
        return;
    }

    if (inst->driver->cleanup != NULL) {
        inst->driver->cleanup(inst);
    }
}

/* ---- xrootd_sd_supports — capability gate for a backend instance --------
 * WHAT: NGX_OK iff the instance's driver advertises every bit in required_caps.
 * WHY:  Lets VFS policy read as `if (!supports(RANGE_READ)) reject` instead of
 *       scattering `driver->caps & ...` across protocol modules (§3.3.1).
 * HOW:  Mask required_caps against driver->caps; NGX_DECLINED on any miss or a
 *       NULL instance. Does NOT set errno — the caller chooses ENOTSUP.
 */
ngx_int_t
xrootd_sd_supports(const xrootd_sd_instance_t *inst, uint32_t required_caps)
{
    if (inst == NULL || inst->driver == NULL) {
        return NGX_DECLINED;
    }

    if ((inst->driver->caps & required_caps) != required_caps) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/* ---- xrootd_sd_backend_name — driver name for logs/healthz --------------
 * WHAT: The backend's short name ("posix"/"block"/"s3").
 * WHY:  Startup logs, /healthz, and SD access-log detail name the backend
 *       (never as a high-cardinality metric label, §3.5).
 * HOW:  Return driver->name, or "" for a NULL/uninitialized instance.
 */
const char *
xrootd_sd_backend_name(const xrootd_sd_instance_t *inst)
{
    if (inst == NULL || inst->driver == NULL || inst->driver->name == NULL) {
        return "";
    }

    return inst->driver->name;
}

/* The handle head every driver embeds first in its own xrootd_sd_obj_s, so the
 * helpers can read caps/fd without knowing the driver-private layout. */
struct xrootd_sd_obj_head_s {
    const xrootd_sd_driver_t *driver;   /* dispatch + caps for this object   */
    ngx_fd_t                  fd;        /* real fd, or NGX_INVALID_FILE      */
};

/* ---- xrootd_sd_caps — capability bitmap behind an open object -----------
 * WHAT: The driver caps reachable from an open handle.
 * WHY:  vfs_read.c keys its buffer shape on CAP_SENDFILE of the *handle's*
 *       driver, not the ctx instance, since a handle may outlive a config view.
 * HOW:  Read the embedded head's driver->caps; 0 for a NULL handle.
 */
uint32_t
xrootd_sd_caps(const xrootd_sd_obj_t *obj)
{
    const struct xrootd_sd_obj_head_s *head =
        (const struct xrootd_sd_obj_head_s *) obj;

    if (head == NULL || head->driver == NULL) {
        return 0;
    }

    return head->driver->caps;
}

/* ---- xrootd_sd_fd — capability-gated real fd accessor -------------------
 * WHAT: The handle's kernel fd, or NGX_INVALID_FILE when there is none.
 * WHY:  Only fd-backed drivers (CAP_FD) can feed sendfile / io_uring; the VFS
 *       must never build a file-backed buffer for an object store (§3.2, §5.1).
 * HOW:  Return NGX_INVALID_FILE unless the embedded head's driver has CAP_FD;
 *       otherwise return the head's fd. One choke point replaces the retired
 *       public xrootd_vfs_file_fd() (§6.1).
 */
ngx_fd_t
xrootd_sd_fd(const xrootd_sd_obj_t *obj)
{
    const struct xrootd_sd_obj_head_s *head =
        (const struct xrootd_sd_obj_head_s *) obj;

    if (head == NULL || head->driver == NULL
        || (head->driver->caps & XROOTD_SD_CAP_FD) == 0)
    {
        return NGX_INVALID_FILE;
    }

    return head->fd;
}

/* ---- xrootd_sd_stat_to_vfs — SD stat -> VFS stat -----------------------
 * WHAT: Copy the protocol-neutral SD stat into xrootd_vfs_stat_t.
 * WHY:  Keeps `struct stat` below the seam; protocol handlers already consume
 *       xrootd_vfs_stat_t unchanged (§6.2).
 * HOW:  Zero *out, then field-by-field copy; mirror is_directory/is_regular.
 *       Silent no-op when either pointer is NULL (matches xrootd_vfs_fill_stat).
 */
void
xrootd_sd_stat_to_vfs(const xrootd_sd_stat_t *in, xrootd_vfs_stat_t *out)
{
    if (in == NULL || out == NULL) {
        return;
    }

    ngx_memzero(out, sizeof(*out));
    out->size         = in->size;
    out->mtime        = in->mtime;
    out->ctime        = in->ctime;
    out->mode         = in->mode;
    out->ino          = in->ino;
    out->is_directory = in->is_directory;
    out->is_regular   = in->is_regular;
}

/* ---- xrootd_sd_flags_from_vfs — XROOTD_VFS_O_* -> XROOTD_SD_O_* ---------
 * WHAT: Translate the VFS open-intent bitmap into backend-neutral SD intents.
 * WHY:  The driver->open() contract takes intents, not raw POSIX O_*; the POSIX
 *       driver re-expands these to O_* itself (15.3) so non-POSIX drivers never
 *       see a filesystem-only flag.
 * HOW:  Bit-for-bit map of the overlapping intents; MKDIRPATH/NOCACHE stay VFS
 *       policy and are NOT forwarded (the VFS pre-creates parents / bypasses
 *       cache above the seam).
 */
int
xrootd_sd_flags_from_vfs(ngx_uint_t vfs_flags)
{
    int sd = 0;

    if (vfs_flags & XROOTD_VFS_O_READ)   { sd |= XROOTD_SD_O_READ;   }
    if (vfs_flags & XROOTD_VFS_O_WRITE)  { sd |= XROOTD_SD_O_WRITE;  }
    if (vfs_flags & XROOTD_VFS_O_CREATE) { sd |= XROOTD_SD_O_CREATE; }
    if (vfs_flags & XROOTD_VFS_O_EXCL)   { sd |= XROOTD_SD_O_EXCL;   }
    if (vfs_flags & XROOTD_VFS_O_TRUNC)  { sd |= XROOTD_SD_O_TRUNC;  }
    if (vfs_flags & XROOTD_VFS_O_APPEND) { sd |= XROOTD_SD_O_APPEND; }

    return sd;
}
```

> **Note on `staging=same`.** The registry deliberately does **not** dedup or alias
> instances. The config layer (§6.6) builds the backend instance once and, when
> `staging` resolves to `same`, assigns the *identical pointer* to
> `staging_instance` (`staging_instance = backend_instance;`). The commit fast path in
> `xrootd_vfs_staged_commit()` then keys on `ctx->sd_staging == ctx->sd` — a pointer
> compare — and takes the native-rename path with zero extra copy (§3.6.1). Pushing the
> collapse into config keeps the registry's lifetime model trivial (one create, one
> destroy per real instance).

---

### 15.3 `src/fs/backend/sd_posix.c`

The POSIX driver — a behaviour-preserving wrapper (§4). Every vtable body delegates to
an **existing** helper; nothing here is new storage logic. The object handle wraps an
fd + the open-time stat snapshot; the instance carries the persistent per-worker
`rootfd` (O_PATH) and the canonical export root. Namespace bodies translate
`xrootd_ns_status_t` → errno via the existing `xrootd_vfs_ns_status_errno()`.

```c
/*
 * sd_posix.c — the POSIX storage driver: today's src/fs/ + namespace_ops +
 *              beneath helpers, moved verbatim behind the SD vtable.
 *
 * WHAT: Implements every xrootd_sd_driver_s slot for a local POSIX filesystem
 *       export. Defines the concrete xrootd_sd_obj_s / xrootd_sd_instance_s /
 *       xrootd_sd_dir_s / xrootd_sd_staged_s layouts and the static
 *       xrootd_sd_posix_driver descriptor with caps = ALL.
 *
 * WHY:  Phase 55.A/B is a pure refactor: POSIX behaviour must be byte- and
 *       response-identical (§1.4 success criterion 1). Reusing the proven
 *       helpers (xrootd_open_beneath, xrootd_vfs_pread_full/pwrite_full,
 *       xrootd_ns_*, xrootd_*xattr_confined_canon, compat/staged_file) means the
 *       existing ~5180-test suite validates this driver with zero new logic.
 *
 * HOW:  The instance holds the persistent O_PATH rootfd and root_canon. Object
 *       handles wrap an fd + open-time fstat snapshot. Raw byte I/O obeys the
 *       Phase-54 worker-safe contract (no pool/metrics/log). Namespace ops are
 *       inst-keyed and take logical paths; the driver enforces RESOLVE_BENEATH
 *       confinement via the beneath API and maps namespace status to errno with
 *       xrootd_vfs_ns_status_errno(). No goto; early-return throughout.
 */
#include "sd.h"

#include "../vfs_internal.h"             /* xrootd_vfs_pread_full/pwrite_full,
                                          * xrootd_vfs_ns_status_errno,
                                          * xrootd_vfs_fill_stat            */
#include "../../path/beneath.h"          /* xrootd_open_beneath, *_beneath  */
#include "../../compat/namespace_ops.h"  /* xrootd_ns_delete/mkdir/rename/  */
#include "../../compat/staged_file.h"    /* xrootd_staged_open/commit/abort */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>

/* ---- concrete layouts (private to this driver) ---------------------------
 * The first member of each is the registry head (driver [+ fd]) so the
 * capability helpers (xrootd_sd_caps/fd) work without driver knowledge.
 */

/* Per-export instance: persistent O_PATH rootfd + canonical export root. */
struct xrootd_sd_instance_s {
    const xrootd_sd_driver_t *driver;       /* registry head (must be first) */
    void                     *driver_conf;
    ngx_log_t                *log;
    ngx_pool_t               *pool;
    int                       rootfd;        /* persistent O_PATH, or -1      */
    char                     *root_canon;    /* NUL-terminated export root    */
};

/* Open object handle: head{driver,fd} + the open-time stat snapshot. */
struct xrootd_sd_obj_s {
    const xrootd_sd_driver_t *driver;        /* head: dispatch + caps         */
    ngx_fd_t                  fd;             /* head: real fd                 */
    xrootd_sd_instance_t     *inst;          /* owning export instance        */
    struct stat               snap;          /* fstat captured at open        */
};

/* Directory iterator: a DIR* obtained from fdopendir on a confined dir fd. */
struct xrootd_sd_dir_s {
    const xrootd_sd_driver_t *driver;
    DIR                      *dir;
    xrootd_sd_instance_t     *inst;
};

/* Staged-write handle: the compat temp-file primitive + owning instance. */
struct xrootd_sd_staged_s {
    const xrootd_sd_driver_t *driver;
    xrootd_staged_file_t      staged;        /* fd + tmp_path + active        */
    xrootd_sd_instance_t     *inst;
};

/* ---- posix_sd_flags_to_open — XROOTD_SD_O_* -> POSIX O_* -----------------
 * WHAT: Re-expand backend-neutral SD intents into the raw open(2) flag word.
 * WHY:  Only the POSIX driver understands O_*; this is where the filesystem
 *       concept is re-introduced, strictly below the seam.
 * HOW:  Choose the access mode from READ/WRITE, then OR the modifier bits.
 */
static int
posix_sd_flags_to_open(int sd_flags)
{
    int flags;

    if ((sd_flags & XROOTD_SD_O_WRITE) && (sd_flags & XROOTD_SD_O_READ)) {
        flags = O_RDWR;
    } else if (sd_flags & XROOTD_SD_O_WRITE) {
        flags = O_WRONLY;
    } else {
        flags = O_RDONLY;
    }

    if (sd_flags & XROOTD_SD_O_CREATE) { flags |= O_CREAT;  }
    if (sd_flags & XROOTD_SD_O_EXCL)   { flags |= O_EXCL;   }
    if (sd_flags & XROOTD_SD_O_TRUNC)  { flags |= O_TRUNC;  }
    if (sd_flags & XROOTD_SD_O_APPEND) { flags |= O_APPEND; }

    return flags;
}

/* ---- posix_stat_to_sd — struct stat -> xrootd_sd_stat_t ------------------
 * WHAT: Project a POSIX struct stat onto the protocol-neutral SD stat.
 * WHY:  Keeps st_* layout inside the POSIX driver; fstat/stat/readdir all share
 *       one translation.
 * HOW:  Zero *out, copy size/mtime/ctime/mode/ino, derive the type bits.
 */
static void
posix_stat_to_sd(const struct stat *st, xrootd_sd_stat_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->size         = st->st_size;
    out->mtime        = st->st_mtime;
    out->ctime        = st->st_ctime;
    out->mode         = st->st_mode;
    out->ino          = st->st_ino;
    out->is_directory = S_ISDIR(st->st_mode) ? 1 : 0;
    out->is_regular   = S_ISREG(st->st_mode) ? 1 : 0;
}

/* ===== instance lifecycle ================================================= */

/* ---- posix_init — open the persistent per-worker rootfd -----------------
 * WHAT: Anchor the beneath API by opening an O_PATH fd on the export root.
 * WHY:  Hot/per-request confined opens reuse one rootfd rather than reopening
 *       per call (beneath.h guidance). root_canon comes from the parsed config.
 * HOW:  Read root_canon out of driver_conf, open it with xrootd_beneath_open_root
 *       (O_PATH), stash the fd; early-return NGX_ERROR (errno preserved) on
 *       failure. driver_conf carries the validated export-root string.
 */
static ngx_int_t
posix_init(xrootd_sd_instance_t *inst, ngx_log_t *log)
{
    /* driver_conf is the parsed xrootd_storage_store_conf_t; for POSIX it
     * resolves to the canonical export root string. */
    const char *root_canon = (const char *) inst->driver_conf;

    if (root_canon == NULL || root_canon[0] == '\0') {
        errno = EINVAL;
        return NGX_ERROR;
    }

    inst->root_canon = (char *) root_canon;     /* borrowed; lives on conf pool */
    inst->rootfd = xrootd_beneath_open_root(root_canon);
    if (inst->rootfd < 0) {
        ngx_log_error(NGX_LOG_EMERG, log, errno,
                      "xrootd: posix backend cannot open export root");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- posix_cleanup — release the persistent rootfd ----------------------
 * WHAT: Close the O_PATH rootfd opened by posix_init.
 * WHY:  Worker shutdown / reload must not leak the anchor fd.
 * HOW:  Guarded close; mark the fd invalid so a double cleanup is a no-op.
 */
static void
posix_cleanup(xrootd_sd_instance_t *inst)
{
    if (inst->rootfd >= 0) {
        close(inst->rootfd);
        inst->rootfd = -1;
    }
}

/* ===== object lifecycle =================================================== */

/* ---- posix_open — confined open + fstat snapshot ------------------------
 * WHAT: Open logical_path beneath the export root and wrap the fd in a handle.
 * WHY:  This is the vfs_open.c cascade behind the vtable: kernel confinement
 *       (RESOLVE_BENEATH) plus the open-time fstat that fills the cached stat.
 * HOW:  Translate SD intents to O_*, call xrootd_open_beneath(inst->rootfd,...);
 *       on failure write *err_out and return NULL. On success pcalloc a handle
 *       from inst->pool, set the head (driver/fd), fstat into snap, and return.
 *       A failed fstat closes the fd and returns NULL (half-open cleanup, §3.2).
 */
static xrootd_sd_obj_t *
posix_open(xrootd_sd_instance_t *inst, const char *logical_path, int sd_flags,
    mode_t mode, int *err_out)
{
    xrootd_sd_obj_t *obj;
    int              flags;
    int              fd;

    flags = posix_sd_flags_to_open(sd_flags);

    fd = xrootd_open_beneath(inst->rootfd, logical_path, flags, mode);
    if (fd < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    obj = ngx_pcalloc(inst->pool, sizeof(*obj));
    if (obj == NULL) {
        close(fd);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    if (fstat(fd, &obj->snap) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        close(fd);
        return NULL;
    }

    obj->driver = inst->driver;     /* head: enables xrootd_sd_caps/fd */
    obj->fd     = fd;
    obj->inst   = inst;
    return obj;
}

/* ---- posix_close — close the handle's fd (idempotent) -------------------
 * WHAT: Close the underlying fd if still open.
 * WHY:  Matches xrootd_vfs_close idempotency; the handle struct is pool-owned.
 * HOW:  NULL-safe; close once, mark the fd invalid; NGX_ERROR (errno set) only
 *       on a real close(2) failure.
 */
static ngx_int_t
posix_close(xrootd_sd_obj_t *obj)
{
    if (obj == NULL || obj->fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    if (close(obj->fd) != 0) {
        return NGX_ERROR;
    }

    obj->fd = NGX_INVALID_FILE;
    return NGX_OK;
}

/* ===== raw byte I/O (worker-safe: no pool, no metrics, no log) ============ */

/* ---- posix_pread — full, EINTR-safe positional read --------------------
 * WHAT: Read up to len bytes at off into buf, returning the byte count.
 * WHY:  This is the EXECUTE-phase read; it is literally xrootd_vfs_pread_full
 *       behind the vtable, so the byte-for-byte loop semantics are unchanged.
 * HOW:  Delegate to xrootd_vfs_pread_full; on NGX_OK return *nread, else -1 with
 *       errno already set by the helper. No allocation, no observation.
 */
static ssize_t
posix_pread(xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    size_t nread = 0;

    if (xrootd_vfs_pread_full(obj->fd, buf, len, off, &nread) != NGX_OK) {
        return -1;
    }

    return (ssize_t) nread;
}

/* ---- posix_pwrite — full, EINTR-safe positional write ------------------
 * WHAT: Write exactly len bytes at off from buf.
 * WHY:  The EXECUTE-phase write; xrootd_vfs_pwrite_full behind the vtable, with
 *       the same short-write-is-error contract.
 * HOW:  Delegate; NGX_OK -> return len, else -1 (errno set by the helper).
 */
static ssize_t
posix_pwrite(xrootd_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    if (xrootd_vfs_pwrite_full(obj->fd, buf, len, off) != NGX_OK) {
        return -1;
    }

    return (ssize_t) len;
}

/* ---- posix_ftruncate — shrink/extend the open object -------------------
 * WHAT: ftruncate the fd to len.
 * WHY:  kXR truncate / checkpoint rollback need this; CAP_TRUNCATE advertises it.
 * HOW:  Raw ftruncate(2); NGX_ERROR (errno set) on failure. The VFS updates the
 *       cached fh->size; the snapshot here is intentionally not refreshed.
 */
static ngx_int_t
posix_ftruncate(xrootd_sd_obj_t *obj, off_t len)
{
    if (ftruncate(obj->fd, len) != 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- posix_fsync — durably flush the open object -----------------------
 * WHAT: fsync the fd to stable storage.
 * WHY:  kXR_sync / writev doSync / pre-rename durability; on POSIX this is the
 *       durability point (object backends document it as a no-op, §8).
 * HOW:  Raw fsync(2); NGX_ERROR (errno set) on failure.
 */
static ngx_int_t
posix_fsync(xrootd_sd_obj_t *obj)
{
    if (fsync(obj->fd) != 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- posix_fstat — live stat of the open object ------------------------
 * WHAT: fstat the fd into *out (protocol-neutral).
 * WHY:  The adopt_fd body; fills the VFS handle's cached size/mtime/mode/ino.
 * HOW:  fstat(2) into a local struct stat, project with posix_stat_to_sd;
 *       NGX_ERROR (errno set) on failure.
 */
static ngx_int_t
posix_fstat(xrootd_sd_obj_t *obj, xrootd_sd_stat_t *out)
{
    struct stat st;

    if (fstat(obj->fd, &st) != 0) {
        return NGX_ERROR;
    }

    posix_stat_to_sd(&st, out);
    return NGX_OK;
}

/* ===== namespace (inst-keyed, logical paths, RESOLVE_BENEATH) ============= */

/* ---- posix_ns_result_to_ngx — collapse a namespace result to NGX/errno --
 * WHAT: Map an xrootd_ns_result_t to NGX_OK/NGX_ERROR with errno set.
 * WHY:  The xrootd_ns_* tier returns a rich status; the vtable contract is
 *       NGX_* + errno. xrootd_vfs_ns_status_errno() already does the status->
 *       errno mapping that preserves ENOTEMPTY/EXDEV semantics (vfs_internal.h).
 * HOW:  On OK return NGX_OK; otherwise set errno from sys_errno when present,
 *       else from the status enum, and return NGX_ERROR.
 */
static ngx_int_t
posix_ns_result_to_ngx(xrootd_ns_result_t res)
{
    if (res.status == XROOTD_NS_OK) {
        return NGX_OK;
    }

    errno = res.sys_errno ? res.sys_errno
                          : xrootd_vfs_ns_status_errno(res.status);
    return NGX_ERROR;
}

/* ---- posix_stat — lstat a logical path ---------------------------------
 * WHAT: Confined lstat of path into *out (symlink reported, not followed).
 * WHY:  Mirrors xrootd_vfs_stat -> xrootd_lstat_beneath; kXR_stat NoFollow.
 * HOW:  xrootd_lstat_beneath(inst->rootfd, path, &st); NGX_ERROR (errno set,
 *       EXDEV on escape) on failure, else project with posix_stat_to_sd.
 */
static ngx_int_t
posix_stat(xrootd_sd_instance_t *inst, const char *path, xrootd_sd_stat_t *out)
{
    struct stat st;

    if (xrootd_lstat_beneath(inst->rootfd, path, &st) != 0) {
        return NGX_ERROR;
    }

    posix_stat_to_sd(&st, out);
    return NGX_OK;
}

/* ---- posix_unlink — remove a file or empty directory -------------------
 * WHAT: Delete path (is_dir selects file vs empty-dir semantics).
 * WHY:  Behind xrootd_vfs_unlink/rmdir; reuses xrootd_ns_delete so the escape
 *       mapping (DENIED/EXDEV) and idempotency live in one place.
 * HOW:  Build delete opts (require_directory mirrors rmdir semantics), call
 *       xrootd_ns_delete, collapse via posix_ns_result_to_ngx.
 */
static ngx_int_t
posix_unlink(xrootd_sd_instance_t *inst, const char *path, int is_dir)
{
    xrootd_ns_delete_opts_t opts;

    ngx_memzero(&opts, sizeof(opts));
    opts.require_directory = is_dir ? 1 : 0;
    opts.require_empty_dir = is_dir ? 1 : 0;

    return posix_ns_result_to_ngx(
        xrootd_ns_delete(inst->log, inst->root_canon, path, &opts));
}

/* ---- posix_mkdir — create a directory ----------------------------------
 * WHAT: mkdir path with mode beneath the export root.
 * WHY:  Behind xrootd_vfs_mkdir; xrootd_ns_mkdir owns EEXIST/DENIED mapping.
 * HOW:  Call xrootd_ns_mkdir (non-recursive here; the VFS pre-creates parents
 *       for MKDIRPATH), collapse the result.
 */
static ngx_int_t
posix_mkdir(xrootd_sd_instance_t *inst, const char *path, mode_t mode)
{
    return posix_ns_result_to_ngx(
        xrootd_ns_mkdir(inst->log, inst->root_canon, path, mode, 0));
}

/* ---- posix_rename — atomic move within the export root -----------------
 * WHAT: Rename src to dst (noreplace selects RENAME_NOREPLACE semantics).
 * WHY:  Behind xrootd_vfs_rename / staged-commit; xrootd_ns_rename enforces
 *       same-root confinement (EXDEV on cross-root) inside the kernel rename.
 * HOW:  Delegate to xrootd_ns_rename (overwrite_dirs follows from !noreplace),
 *       then collapse. noreplace==1 surfaces EEXIST when dst exists.
 */
static ngx_int_t
posix_rename(xrootd_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    xrootd_ns_result_t res;

    res = xrootd_ns_rename(inst->log, inst->root_canon, src, dst,
                           noreplace ? 0 : 1 /* overwrite_dirs */);

    if (noreplace && res.status == XROOTD_NS_EXISTS) {
        errno = EEXIST;
        return NGX_ERROR;
    }

    return posix_ns_result_to_ngx(res);
}

/* ---- posix_server_copy — native single-file copy -----------------------
 * WHAT: copy_file_range src -> dst within the root, reporting bytes copied.
 * WHY:  CAP_SERVER_COPY; behind xrootd_vfs_copy. xrootd_ns_local_copy already
 *       does copy_file_range with a read/write fallback inside xrootd_copy_range.
 * HOW:  Build copy opts (overwrite default), call xrootd_ns_local_copy, collapse;
 *       bytes_out is filled by the VFS from the post-copy size (the ns helper
 *       does not surface a byte count, so leave *bytes_out untouched here and
 *       let the VFS stat dst — preserving today's accounting).
 */
static ngx_int_t
posix_server_copy(xrootd_sd_instance_t *inst, const char *src, const char *dst,
    off_t *bytes_out)
{
    xrootd_ns_copy_opts_t opts;

    (void) bytes_out;   /* VFS measures dst size post-copy, as today */

    ngx_memzero(&opts, sizeof(opts));
    opts.overwrite = 1;

    return posix_ns_result_to_ngx(
        xrootd_ns_local_copy(inst->log, inst->root_canon, src, dst, &opts));
}

/* ===== directory iteration ================================================ */

/* ---- posix_opendir — confined directory open ---------------------------
 * WHAT: Open path as a directory stream beneath the root.
 * WHY:  Behind xrootd_vfs_opendir; the vfs_io_core.c fdopendir scan pattern.
 * HOW:  Open an O_DIRECTORY|O_RDONLY fd via xrootd_open_beneath, fdopendir it,
 *       wrap in a pool-allocated xrootd_sd_dir_t; *err_out on failure, NULL.
 */
static xrootd_sd_dir_t *
posix_opendir(xrootd_sd_instance_t *inst, const char *path, int *err_out)
{
    xrootd_sd_dir_t *d;
    DIR             *dir;
    int              fd;

    fd = xrootd_open_beneath(inst->rootfd, path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    dir = fdopendir(fd);             /* fdopendir adopts fd; closedir frees it */
    if (dir == NULL) {
        if (err_out != NULL) { *err_out = errno; }
        close(fd);
        return NULL;
    }

    d = ngx_pcalloc(inst->pool, sizeof(*d));
    if (d == NULL) {
        closedir(dir);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    d->driver = inst->driver;
    d->dir    = dir;
    d->inst   = inst;
    return d;
}

/* ---- posix_readdir — yield one entry (dot entries filtered) ------------
 * WHAT: Read the next child name into out, skipping "." and "..".
 * WHY:  Behind xrootd_vfs_readdir; the per-child lstat is left to the VFS so
 *       impersonation/broker routing stays above the seam (have_stat=0 here).
 * HOW:  Loop readdir(3) until a non-dot entry or end; copy d_name (bounded),
 *       NGX_DONE at end, NGX_ERROR (errno set) on a readdir failure.
 */
static ngx_int_t
posix_readdir(xrootd_sd_dir_t *d, xrootd_sd_dirent_t *out)
{
    struct dirent *de;

    for ( ;; ) {
        errno = 0;
        de = readdir(d->dir);
        if (de == NULL) {
            return errno != 0 ? NGX_ERROR : NGX_DONE;
        }

        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        {
            continue;   /* skip "." and ".." */
        }

        ngx_memzero(out, sizeof(*out));
        ngx_cpystrn((u_char *) out->name, (u_char *) de->d_name,
                    sizeof(out->name));
        out->have_stat = 0;     /* VFS performs the confined per-child lstat */
        return NGX_OK;
    }
}

/* ---- posix_closedir — close the directory stream -----------------------
 * WHAT: closedir the underlying DIR* (idempotent).
 * WHY:  Releases the dir fd adopted by fdopendir.
 * HOW:  NULL-safe; closedir once, clear the pointer; NGX_ERROR (errno) on fail.
 */
static ngx_int_t
posix_closedir(xrootd_sd_dir_t *d)
{
    if (d == NULL || d->dir == NULL) {
        return NGX_OK;
    }

    if (closedir(d->dir) != 0) {
        d->dir = NULL;
        return NGX_ERROR;
    }

    d->dir = NULL;
    return NGX_OK;
}

/* ===== xattr / metadata (user.* namespace) ================================ */
/* These wrap the existing *xattr_confined_canon helpers, which apply the same
 * RESOLVE_BENEATH confinement against the absolute (root_canon + path) target.
 * The VFS xattr ops are intentionally NOT allow_write-gated (vfs.h note), so the
 * driver makes no write-permission decision here. */

/* ---- posix_getxattr — read one user.* attribute -----------------------
 * WHAT: getxattr name on the confined target into buf (cap bytes).
 * WHY:  Behind xrootd_vfs_getxattr (fattr / WebDAV dead-properties / lock DB).
 * HOW:  Delegate to xrootd_getxattr_confined_canon; return its byte count or -1
 *       (errno set; ERANGE when cap is too small, as today).
 */
static ssize_t
posix_getxattr(xrootd_sd_instance_t *inst, const char *path, const char *name,
    void *buf, size_t cap)
{
    return xrootd_getxattr_confined_canon(inst->root_canon, path, name, buf, cap);
}

/* ---- posix_listxattr — list attribute names ---------------------------
 * WHAT: listxattr the confined target into buf (cap bytes).
 * WHY:  Behind xrootd_vfs_listxattr.
 * HOW:  Delegate to xrootd_listxattr_confined_canon; byte count or -1 (errno).
 */
static ssize_t
posix_listxattr(xrootd_sd_instance_t *inst, const char *path, void *buf,
    size_t cap)
{
    return xrootd_listxattr_confined_canon(inst->root_canon, path, buf, cap);
}

/* ---- posix_setxattr — write one user.* attribute ----------------------
 * WHAT: setxattr name=val (len bytes, flags) on the confined target.
 * WHY:  Behind xrootd_vfs_setxattr.
 * HOW:  Delegate to xrootd_setxattr_confined_canon; NGX_OK / NGX_ERROR (errno).
 */
static ngx_int_t
posix_setxattr(xrootd_sd_instance_t *inst, const char *path, const char *name,
    const void *val, size_t len, int flags)
{
    if (xrootd_setxattr_confined_canon(inst->root_canon, path, name, val, len,
                                       flags) != 0)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- posix_removexattr — delete one user.* attribute ------------------
 * WHAT: removexattr name on the confined target.
 * WHY:  Behind xrootd_vfs_removexattr.
 * HOW:  Delegate to xrootd_removexattr_confined_canon; NGX_OK / NGX_ERROR.
 */
static ngx_int_t
posix_removexattr(xrootd_sd_instance_t *inst, const char *path, const char *name)
{
    if (xrootd_removexattr_confined_canon(inst->root_canon, path, name) != 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ===== staged / atomic write (compat/staged_file) ========================= */

/* ---- posix_staged_open — open an O_EXCL temp for atomic publish --------
 * WHAT: Create a unique temp inside the export root for final_path.
 * WHY:  Behind xrootd_vfs_staged_open; the POSIX atomic-publish lifecycle is
 *       temp + renameat2, exactly today's compat/staged_file flow.
 * HOW:  pcalloc a handle, call xrootd_staged_open (O_EXCL inside root_canon);
 *       *err_out + NULL on failure, else set the head and return.
 */
static xrootd_sd_staged_t *
posix_staged_open(xrootd_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    xrootd_sd_staged_t *st;

    st = ngx_pcalloc(inst->pool, sizeof(*st));
    if (st == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    if (xrootd_staged_open(inst->log, inst->root_canon, final_path,
                           O_WRONLY | O_CREAT | O_EXCL, mode,
                           /* attempts */ 8, &st->staged) != NGX_OK)
    {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    st->driver = inst->driver;
    st->inst   = inst;
    return st;
}

/* ---- posix_staged_write — write into the staged temp ------------------
 * WHAT: Positional write of len bytes at off into the temp fd.
 * WHY:  Behind the staged-write data path; full POSIX random-write support
 *       (this is the side that makes CAP_RANDOM_WRITE staging honest, §3.6).
 * HOW:  Delegate to xrootd_vfs_pwrite_full on st->staged.fd; len or -1 (errno).
 */
static ssize_t
posix_staged_write(xrootd_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    if (xrootd_vfs_pwrite_full(st->staged.fd, buf, len, off) != NGX_OK) {
        return -1;
    }

    return (ssize_t) len;
}

/* ---- posix_staged_commit — atomically publish the temp ----------------
 * WHAT: Rename the temp onto its final path (noreplace = create-if-absent).
 * WHY:  Behind xrootd_vfs_staged_commit; CAP_HARD_RENAME makes this the atomic
 *       point. When staging==backend this is the §3.6.1 fast path.
 * HOW:  Choose the excl vs replacing commit helper; NGX_ERROR (errno, EEXIST on
 *       a noreplace collision) on failure.
 */
static ngx_int_t
posix_staged_commit(xrootd_sd_staged_t *st, int noreplace)
{
    const char *final_path = st->staged.tmp_path;   /* recorded final at open */

    if (noreplace) {
        return xrootd_staged_commit_excl(st->inst->log, st->inst->root_canon,
                                         &st->staged, final_path);
    }

    return xrootd_staged_commit(st->inst->log, st->inst->root_canon,
                                &st->staged, final_path);
}

/* ---- posix_staged_abort — discard the temp ----------------------------
 * WHAT: Close and unlink the staged temp.
 * WHY:  Behind xrootd_vfs_staged_abort; failure/cancel cleanup.
 * HOW:  Idempotent delegate to xrootd_staged_abort (remove_tmp=1).
 */
static void
posix_staged_abort(xrootd_sd_staged_t *st)
{
    if (st == NULL) {
        return;
    }

    xrootd_staged_abort(st->inst->log, st->inst->root_canon, &st->staged,
                        /* remove_tmp */ 1);
}

/* ===== the driver descriptor (caps = ALL) ================================= */

/* ---- xrootd_sd_posix_driver — the static POSIX vtable ------------------
 * WHAT: The const-initialized descriptor wiring every slot to a posix_* body,
 *       advertising the full capability set.
 * WHY:  POSIX supports every primitive, so it never triggers a VFS degradation
 *       path; this descriptor is the parity oracle for §1.4 criterion 1.
 * HOW:  Designated initializers keep the mapping readable and order-independent;
 *       register it once via xrootd_sd_driver_register() at module init.
 */
const xrootd_sd_driver_t xrootd_sd_posix_driver = {
    .name        = "posix",
    .caps        = XROOTD_SD_CAPS_POSIX_ALL,

    .init        = posix_init,
    .cleanup     = posix_cleanup,

    .open        = posix_open,
    .close       = posix_close,

    .pread       = posix_pread,
    .pwrite      = posix_pwrite,
    .ftruncate   = posix_ftruncate,
    .fsync       = posix_fsync,
    .fstat       = posix_fstat,

    .stat        = posix_stat,
    .unlink      = posix_unlink,
    .mkdir       = posix_mkdir,
    .rename      = posix_rename,
    .server_copy = posix_server_copy,

    .opendir     = posix_opendir,
    .readdir     = posix_readdir,
    .closedir    = posix_closedir,

    .getxattr    = posix_getxattr,
    .listxattr   = posix_listxattr,
    .setxattr    = posix_setxattr,
    .removexattr = posix_removexattr,

    .staged_open   = posix_staged_open,
    .staged_write  = posix_staged_write,
    .staged_commit = posix_staged_commit,
    .staged_abort  = posix_staged_abort,
};
```

**Why this skeleton is a pure refactor, not a rewrite.** Every `posix_*` body
delegates to a helper that already exists and is already test-covered:

| Vtable slot | Existing helper (verbatim behind the slot) |
|---|---|
| `open` | `xrootd_open_beneath` (the `vfs_open.c` cascade) + `fstat` |
| `close` | `close(2)` (idempotent, as `xrootd_vfs_close`) |
| `pread` / `pwrite` | `xrootd_vfs_pread_full` / `xrootd_vfs_pwrite_full` |
| `ftruncate` / `fsync` / `fstat` | `ftruncate(2)` / `fsync(2)` / `fstat(2)` |
| `stat` | `xrootd_lstat_beneath` |
| `unlink` / `mkdir` / `rename` / `server_copy` | `xrootd_ns_delete` / `_mkdir` / `_rename` / `_local_copy` |
| `opendir` / `readdir` / `closedir` | `xrootd_open_beneath` + `fdopendir` scan |
| `getxattr` … `removexattr` | the `xrootd_*xattr_confined_canon` helpers |
| `staged_*` | `xrootd_staged_open` / `_commit[_excl]` / `_abort` |

Namespace status is mapped to `errno` through the **existing**
`xrootd_vfs_ns_status_errno()` (`vfs_internal.h`), preserving the subtle cases
(`ENOTEMPTY` for a non-empty rmdir, `EXDEV` for a confinement escape). The persistent
per-worker `rootfd` simply migrates from the ctx into the POSIX instance, exactly as
§4 and §6.3 prescribe — so the common POSIX deployment pays nothing for the
abstraction beyond one predicted indirect call per raw op (§10).


## 16. Annotated source skeletons — object & block drivers (`sd_object.c`, `sd_object_s3.c`, `sd_block.c`)

This appendix turns the §3 vtable, §3.3.2 error contract and §3.6 store-binding/promote
prose into concrete, compilable-shaped skeletons for the two non-POSIX drivers landed in
55.D/55.E. It is deliberately split the same way the source is:

| File | Responsibility | Knows about |
|---|---|---|
| `sd_object.c` | **policy core** — key mapping, capability bitmap, vtable wiring, staged→multipart lifecycle, listing iterator, xattr→tag/sidecar policy | the SD vtable + `sd_object_s3.c` transport calls; **never** HTTP/SigV4 bytes |
| `sd_object_s3.c` | **transport** — HEAD/GET-range/PUT/multipart/DELETE/CopyObject/ListObjectsV2 over signed HTTP; HTTP-status→errno table; retry/timeout; credentials | SigV4 signing, HTTP wire; **never** the SD vtable or VFS types |
| `sd_block.c` | **proof backend** — extent-map / fixed-object-table over a block device or file | a superblock + `pread`/`pwrite` against one device fd; **never** dirs/copy |

Reuse note: the existing `src/protocols/s3/` module is the *server* (inbound) SigV4 path — it
**verifies** client signatures (`s3_verify_sigv4`, `build_canonical_qs`,
`s3_sigv4_derive_signing_key_cached` in `auth_sigv4_verify.c` / `auth_sigv4_canonical.c`).
The object driver is the *client* (outbound) signing path. The two share exactly one
kernel that is already factored and pure-pointer:

- `xrootd_sigv4_signing_key()` (`src/core/compat/sigv4.h`) — the 4-round HMAC chain;
- `xrootd_hmac_sha256()`, `xrootd_sha256()`, the streaming SHA256
  (`xrootd_sha256_stream_*`) (`src/core/compat/crypto.h`);
- `xrootd_hex_encode()` (`src/core/compat/hex.h`).

What does **not** yet exist as a reusable outbound seam (must be factored, see §16.2):

1. A **canonical-request builder for signing** (the inbound `build_canonical_qs` in
   `src/protocols/s3/auth_sigv4_canonical.c` is `static` and verify-shaped). Factor a shared
   `xrootd_s3_canonical_request()` into a new `src/core/compat/s3_canon.c` that *both* the
   server verify path and this driver call, so the canonical form can never drift.
2. A **blocking, worker-thread HTTP transport**. Two candidates exist:
   `src/protocols/webdav/tpc_curl.c` (libcurl, event-loop-coupled via nginx socket hooks) and
   `client/lib/http.c` (`xrdc_http_req`/`httpx_exchange`, pure-C, blocking, no nginx).
   The object driver's blocking calls run in the AIO thread pool (§5.5), so the
   nginx-coupled curl path is wrong here. Reuse the **`client/lib/http.c`** style —
   factor its core into `src/core/compat/httpc.c` (`xrootd_httpc_exchange()`), a blocking
   request/response with caller-supplied body source/sink and a timeout, no event loop.

---

### 16.1 `sd_object.c` — policy core (transport-agnostic)

#### 16.1.1 Object and instance layout

```c
/*
 * sd_object.c — object-store storage driver (policy core).
 *
 * WHAT: implements the xrootd_sd_driver_t vtable for an object (S3-style) backend.
 * WHY:  lets root://, WebDAV and S3 serve from a durable object store while the VFS
 *       above the seam stays backend-agnostic (§1.2). All wire/SigV4 bytes live in
 *       sd_object_s3.c; this file is pure policy + key mapping + lifecycle.
 * HOW:  every vtable slot validates capabilities, maps the logical path to a confined
 *       object key, then delegates to an s3_* transport call, capturing an errno-style
 *       fact per §3.3.2. Blocking transport calls run only in the AIO thread pool.
 */
#include "sd.h"
#include "sd_object_s3.h"          /* transport prototypes (this file's only backend) */

/* Per-open object handle. Opaque above the seam; reached only via xrootd_sd_* helpers.
 * NOTE: `staging_fd` is the POSIX *staging-store* fd when this object is being written
 * through a separate staging store (§3.6). For a pure-object handle it is -1; the
 * object driver itself never owns a kernel fd (it does NOT advertise CAP_FD). */
typedef struct {
    xrootd_sd_instance_t *inst;        /* owning instance (creds, bucket, prefix)     */
    char                 *key;         /* confined object key (inst-pool alloc)       */
    off_t                 size;        /* last-known object size (snapshot, §3.2.3)   */
    time_t                mtime;       /* last-known mtime from HEAD/PUT response      */
    char                  etag[64];    /* quoted ETag from HEAD/PUT/complete; ""=unset */
    int                   staging_fd;  /* POSIX staging fd, or -1 (object-only handle) */
    char                 *upload_id;   /* multipart UploadId when staged, else NULL    */
    int                   sd_flags;    /* the open flags (read vs staged-write)        */
    unsigned              size_valid:1;/* size/mtime/etag reflect a real HEAD/PUT      */
} xrootd_sd_obj_t;

/* Multipart staged-write handle. Returned by staged_open, consumed by staged_commit. */
typedef struct {
    xrootd_sd_instance_t *inst;
    char                 *final_key;   /* confined key the completed object publishes to */
    char                 *upload_id;   /* from CreateMultipartUpload                    */
    off_t                 next_off;    /* monotonic write cursor; enforces sequentiality */
    int                   part_no;     /* 1-based current part number (S3 max 10000)     */
    s3_part_etag_t       *parts;       /* {part_no, etag} array for CompleteMultipart    */
    size_t                part_count;
    char                 *buf;         /* part-accumulation buffer (>= 5 MiB min part)   */
    size_t                buf_len;
    size_t                buf_cap;     /* = inst->multipart_part_size                    */
    int                   aborted;     /* idempotency guard for staged_abort             */
} xrootd_sd_staged_t;

/* Per-export instance: parsed config + transport state. Built by sd_registry.c. */
typedef struct {
    /* binding identity */
    char       *endpoint;          /* "https://s3.example.org"  (scheme+host[:port])   */
    char       *bucket;            /* "cms-prod-data"                                  */
    char       *prefix;            /* "exports/main/" — confinement boundary, normalized*/
    size_t      prefix_len;
    char       *region;            /* "us-east-1"                                      */

    /* credentials (resolved per §16.2.6). The driver holds *resolved* creds; refresh
     * for webidentity happens in the transport layer behind a worker-safe mutex. */
    s3_creds_t  creds;             /* {mode, access_key, secret_key, session_token,..} */

    /* policy knobs from directives (§6.5) */
    enum { XATTR_TAGS, XATTR_SIDECAR, XATTR_OFF } xattr_mode;
    int         weak_rename;       /* 0 = rename→ENOTSUP; 1 = CopyObject+Delete         */
    size_t      multipart_part_size;   /* part buffer size, >= 5 MiB (S3 min)          */
    int         path_style;        /* 1 = path-style (bucket in path), 0 = vhost-style  */

    /* transport tunables (passed verbatim into every s3_* call) */
    s3_http_policy_t http;         /* timeouts, retry budget, backoff (see §16.2.5)     */

    ngx_log_t  *log;               /* config-time/worker-init log ONLY; never in raw ops */
} xrootd_sd_instance_t;
```

#### 16.1.2 Capability bitmap

```c
/*
 * WHAT: capability bitmap for the object driver.
 * WHY:  the VFS shapes its behaviour (sendfile, random-write, rename) off these bits
 *       (§3.1). Object stores can range-GET, server-copy and carry metadata, but have
 *       no fd, no random write, no atomic rename, no real directories.
 * HOW:  set the three supported caps; everything else stays clear and the VFS degrades
 *       or rejects per the §3.1 table.
 */
#define SD_OBJECT_CAPS  ( XROOTD_SD_CAP_RANGE_READ \
                        | XROOTD_SD_CAP_SERVER_COPY \
                        | XROOTD_SD_CAP_XATTR )
/* Explicitly NOT set (each absence drives a VFS adaptation or an ENOTSUP):
 *   CAP_FD            → no kernel fd; xrootd_sd_fd()==NGX_INVALID_FILE; no sendfile path
 *   CAP_SENDFILE      → reads always memory-backed (§5.1)
 *   CAP_RANDOM_WRITE  → in-place random write on a committed object → ENOTSUP (§5.3)
 *   CAP_TRUNCATE      → ftruncate → ENOTSUP
 *   CAP_HARD_RENAME   → rename is weak (copy+delete) or ENOTSUP (§16.1.7)
 *   CAP_DIRS          → directories synthesized from key prefixes (§16.1.8)
 *   CAP_APPEND        → append-mode open → ENOTSUP
 *   CAP_IOURING       → never enters the io_uring tier (no fd)
 */
```

#### 16.1.3 Logical-path → object-key mapping (reversible, prefix-confined)

```c
/*
 * WHAT: map a VFS-confined logical path to a physical object key, confined to the
 *       instance prefix; and the inverse used by the listing iterator.
 * WHY:  this is the object driver's *physical* confinement primitive (§5.2): the VFS
 *       already normalized the logical path, but the SD must still guarantee the
 *       resulting key cannot escape `prefix`. One reversible function (§3.3.3) keeps
 *       key↔path stable so listings round-trip.
 * HOW:  reject empty (except explicit root list), reject any "/../" or leading "../"
 *       AFTER the VFS normalization (defence in depth, never trust the caller), strip a
 *       single leading '/', then concatenate prefix + path. Reject if the result does
 *       not start with prefix (paranoia against a prefix that itself contains "..").
 *       No allocation in the hot validate; key buffer is caller-provided.
 */
static ngx_int_t
sd_obj_key_from_path(const xrootd_sd_instance_t *inst,
                     const char *logical_path, int allow_empty,
                     char *key_out, size_t key_cap)
{
    if (logical_path == NULL) { errno = EINVAL; return NGX_ERROR; }

    const char *p = logical_path;
    while (*p == '/') p++;                      /* logical root-relative; drop leading / */

    if (*p == '\0') {
        if (!allow_empty) { errno = EINVAL; return NGX_ERROR; }
        /* root list: key is exactly the prefix */
        if (sd_obj_strlcpy(key_out, inst->prefix, key_cap) >= key_cap) {
            errno = ENAMETOOLONG; return NGX_ERROR;
        }
        return NGX_OK;
    }

    /* Defence-in-depth: reject traversal even though src/path/ already normalized.
     * A bare ".." segment, a leading "../", or any "/../" is an escape attempt. */
    if (sd_obj_has_dotdot_segment(p)) { errno = EACCES; return NGX_ERROR; }   /* → 403 */

    int n = snprintf(key_out, key_cap, "%s%s", inst->prefix, p);
    if (n < 0 || (size_t) n >= key_cap) { errno = ENAMETOOLONG; return NGX_ERROR; }

    /* Final confinement assertion: the key must live under the prefix. */
    if (strncmp(key_out, inst->prefix, inst->prefix_len) != 0) {
        errno = EACCES; return NGX_ERROR;       /* → kXR_NotAuthorized / 403            */
    }
    return NGX_OK;
}

/*
 * WHAT: inverse map — physical key → logical path (for ListObjectsV2 → dirent).
 * WHY:  the listing iterator (§16.1.8) returns keys; the VFS expects logical paths.
 * HOW:  require the key to start with prefix (else skip — foreign key, never surface),
 *       return the suffix. Pure, no allocation.
 */
static const char *
sd_obj_path_from_key(const xrootd_sd_instance_t *inst, const char *key)
{
    if (strncmp(key, inst->prefix, inst->prefix_len) != 0) return NULL; /* not ours    */
    return key + inst->prefix_len;
}
```

#### 16.1.4 Vtable wiring + instance lifecycle

```c
/*
 * WHAT: the object driver descriptor. The vtable IS the dispatch table (§ design
 *       principle 5: descriptor-driven, no goto).
 * WHY:  sd_registry.c looks this up by name "s3" and binds it to an export instance.
 * HOW:  every slot points at an sd_obj_* policy function below. Slots whose capability
 *       is absent still have a body that returns the §3.3.2 fact + bumps the metric;
 *       they are NOT left NULL, so the VFS never has to null-check the vtable.
 */
const xrootd_sd_driver_t xrootd_sd_driver_object = {
    .name        = "s3",
    .caps        = SD_OBJECT_CAPS,

    .init        = sd_obj_init,
    .cleanup     = sd_obj_cleanup,

    .open        = sd_obj_open,
    .close       = sd_obj_close,

    .pread       = sd_obj_pread,        /* worker-safe: range GET                       */
    .pwrite      = sd_obj_pwrite,       /* ENOTSUP unless via staged lifecycle (§16.1.6)*/
    .ftruncate   = sd_obj_ftruncate,    /* ENOTSUP (no CAP_TRUNCATE)                     */
    .fsync       = sd_obj_fsync,        /* no-op OK: object commit is the durability pt */
    .fstat       = sd_obj_fstat,        /* HEAD-backed snapshot                          */

    .stat        = sd_obj_stat,         /* HEAD                                          */
    .unlink      = sd_obj_unlink,       /* DELETE                                        */
    .mkdir       = sd_obj_mkdir,        /* prefix has no dirs → no-op / marker (§16.1.8) */
    .rename      = sd_obj_rename,       /* weak: Copy+Delete; else ENOTSUP (§16.1.7)     */
    .server_copy = sd_obj_server_copy,  /* CopyObject (§16.1.7)                          */

    .opendir     = sd_obj_opendir,      /* ListObjectsV2 iterator (§16.1.8)              */
    .readdir     = sd_obj_readdir,
    .closedir    = sd_obj_closedir,

    .getxattr    = sd_obj_getxattr,     /* tag or sidecar (§16.1.9)                      */
    .listxattr   = sd_obj_listxattr,
    .setxattr    = sd_obj_setxattr,
    .removexattr = sd_obj_removexattr,

    .staged_open   = sd_obj_staged_open,   /* CreateMultipartUpload (§16.1.6)            */
    .staged_write  = sd_obj_staged_write,  /* buffer → UploadPart                        */
    .staged_commit = sd_obj_staged_commit, /* CompleteMultipartUpload (atomic publish)   */
    .staged_abort  = sd_obj_staged_abort,  /* AbortMultipartUpload                       */
};

/*
 * WHAT: per-export init — validate config, resolve credentials, warm the transport.
 * WHY:  fail fast at worker init, never at first request (§6.5). Config-time only:
 *       this runs on the event loop at init, so it MUST NOT do network I/O unless a
 *       future `validate_backend on` asks (then it offloads).
 * HOW:  normalize the prefix (ensure trailing '/', reject ".."), resolve creds by mode,
 *       precompute prefix_len, set multipart_part_size floor (5 MiB). Returns NGX_ERROR
 *       (with a clear log) on any invalid field.
 */
static ngx_int_t sd_obj_init(xrootd_sd_instance_t *inst, ngx_log_t *log);
static void      sd_obj_cleanup(xrootd_sd_instance_t *inst);
```

#### 16.1.5 open / pread / fstat (read path)

```c
/*
 * WHAT: open an object handle for reading (or to seed a staged write).
 * WHY:  the VFS open path needs a handle carrying size/etag so subsequent preads and
 *       the protocol stat are consistent without re-HEADing per read (§ INVARIANT 7).
 * HOW:  read intent → HEAD the key, fill {size, mtime, etag, size_valid=1}; ENOENT
 *       (HEAD 404) → NULL with *err_out=ENOENT. Write intent on a !RANDOM_WRITE backend
 *       is handled by the staged lifecycle, NOT here — a plain write-open that is not
 *       routed through staging returns ENOTSUP. No nginx pool: allocate the handle from
 *       the instance pool / ngx_alloc (§3.2.5).
 */
static xrootd_sd_obj_t *
sd_obj_open(xrootd_sd_instance_t *inst, const char *logical_path,
            int sd_flags, mode_t mode, int *err_out)
{
    char key[XROOTD_SD_KEY_MAX];
    if (sd_obj_key_from_path(inst, logical_path, /*allow_empty=*/0,
                             key, sizeof key) != NGX_OK) {
        *err_out = errno; return NULL;            /* EACCES/ENAMETOOLONG → mapped by VFS*/
    }

    if (sd_flags & (XROOTD_SD_O_TRUNC | XROOTD_SD_O_APPEND)) {
        /* truncate/append on an object backend are not first-class. */
        sd_metric_unsupported(inst, "open");      /* xrootd_sd_unsupported_total{op=open}*/
        *err_out = ENOTSUP; return NULL;          /* → kXR_Unsupported / 501            */
    }

    xrootd_sd_obj_t *obj = sd_obj_alloc(inst);
    if (obj == NULL) { *err_out = ENOMEM; return NULL; }
    obj->key = sd_obj_strdup(inst, key);
    obj->staging_fd = -1;
    obj->upload_id = NULL;
    obj->sd_flags = sd_flags;

    if (sd_flags & XROOTD_SD_O_RDONLY) {
        s3_stat_t hs;
        int rc = s3_head(inst, key, &hs);         /* worker-safe blocking HEAD          */
        if (rc != 0) { *err_out = rc; sd_obj_free(obj); return NULL; }  /* rc IS errno   */
        obj->size = hs.size; obj->mtime = hs.mtime;
        sd_obj_strlcpy(obj->etag, hs.etag, sizeof obj->etag);
        obj->size_valid = 1;
    }
    return obj;
}

/*
 * WHAT: worker-safe ranged read. WHY: the EXECUTE phase (vfs_io_core.c) calls this in
 *       the AIO thread pool; object reads are blocking network GETs (§5.5).
 * HOW:  issue a Range GET [off, off+len); return bytes copied or -1 with errno. Short
 *       read at EOF is normal (returns < len). NO nginx pool/metrics/log here.
 */
static ssize_t
sd_obj_pread(xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    return s3_get_range(obj->inst, obj->key, off, len, buf);   /* errno-on-(-1)         */
}

/*
 * WHAT: fstat from the cached snapshot, refreshing via HEAD only if invalid.
 * WHY:  avoid a network HEAD per stat when open already HEADed (§ INVARIANT 7).
 * HOW:  if size_valid, fill from the handle; else HEAD. Map S3 stat → xrootd_sd_stat_s
 *       with synthetic mode (regular file, 0644) — object stores have no POSIX mode.
 */
static ngx_int_t sd_obj_fstat(xrootd_sd_obj_t *obj, struct xrootd_sd_stat_s *out);
```

#### 16.1.6 staged_* → multipart (the only object write path)

```c
/*
 * WHAT: begin a multipart upload that will publish to `final_path` on commit.
 * WHY:  object stores accept only finished, sequential whole objects; the staged
 *       lifecycle IS the universal write path (§5.3). This is also the backend half of
 *       a cross-store promote (§3.6.2): the VFS drives staged_write from a POSIX
 *       staging object.
 * HOW:  map+confine the final key, CreateMultipartUpload, stash the UploadId, allocate
 *       the part-accumulation buffer (>= 5 MiB). next_off=0, part_no=1.
 */
static xrootd_sd_staged_t *
sd_obj_staged_open(xrootd_sd_instance_t *inst, const char *final_path,
                   mode_t mode, int *err_out)
{
    char key[XROOTD_SD_KEY_MAX];
    if (sd_obj_key_from_path(inst, final_path, 0, key, sizeof key) != NGX_OK) {
        *err_out = errno; return NULL;
    }
    char upload_id[256];
    int rc = s3_multipart_init(inst, key, upload_id, sizeof upload_id);  /* rc=errno    */
    if (rc != 0) { *err_out = rc; return NULL; }

    xrootd_sd_staged_t *st = sd_staged_alloc(inst);
    if (st == NULL) { s3_multipart_abort(inst, key, upload_id); *err_out = ENOMEM; return NULL; }
    st->final_key = sd_obj_strdup(inst, key);
    st->upload_id = sd_obj_strdup(inst, upload_id);
    st->buf_cap   = inst->multipart_part_size;
    st->buf       = sd_obj_alloc_buf(inst, st->buf_cap);
    st->part_no   = 1;
    return st;
}

/*
 * WHAT: append `len` bytes at `off` to the in-flight multipart upload.
 * WHY:  S3 parts must be uploaded sequentially and (except the last) be >= 5 MiB; the
 *       VFS/promote feeds bytes in order, so we accumulate into a part buffer and flush
 *       a full part via UploadPart.
 * HOW:  ENFORCE monotonic sequentiality — off MUST equal next_off (the staged lifecycle
 *       is sequential; a hole/rewrite is the §5.3 unsupported case). Copy into buf; when
 *       buf fills, s3_multipart_upload_part(), record {part_no, etag}, advance part_no.
 *       Worker-safe; no nginx pool.
 */
static ssize_t
sd_obj_staged_write(xrootd_sd_staged_t *st, const void *buf, size_t len, off_t off)
{
    if (off != st->next_off) {                    /* non-sequential → unsupported (§5.3)*/
        sd_metric_unsupported(st->inst, "staged_write");  /* xrootd_sd_unsupported_total*/
        errno = ENOTSUP; return -1;               /* → kXR_Unsupported / 501            */
    }
    size_t copied = 0;
    while (copied < len) {
        size_t take = sd_min(len - copied, st->buf_cap - st->buf_len);
        memcpy(st->buf + st->buf_len, (const char *) buf + copied, take);
        st->buf_len += take; copied += take;
        if (st->buf_len == st->buf_cap) {
            int rc = sd_obj_flush_part(st);        /* UploadPart, records etag           */
            if (rc != 0) { errno = rc; return -1; }/* EIO/ETIMEDOUT/ESTALE per §16.2     */
        }
    }
    st->next_off += (off_t) len;
    return (ssize_t) len;
}

/*
 * WHAT: atomically publish the staged object. WHY: CompleteMultipartUpload is the
 *       single atomic point that makes the final key visible (§5.3).
 * HOW:  flush the trailing partial part (any size for the last part), then
 *       CompleteMultipartUpload with the ordered {part_no, etag} list. A returned ETag
 *       mismatch / stale generation → ESTALE (commit fails, NOT silent success, §9.3).
 *       `noreplace` (conditional create) maps to an If-None-Match:* precondition →
 *       EEXIST on 412. On ANY failure: AbortMultipartUpload so no orphan parts linger.
 */
static ngx_int_t
sd_obj_staged_commit(xrootd_sd_staged_t *st, int noreplace)
{
    if (st->buf_len > 0) {                         /* final part may be < 5 MiB          */
        int rc = sd_obj_flush_part(st);
        if (rc != 0) { sd_obj_staged_abort(st); errno = rc; return NGX_ERROR; }
    }
    int rc = s3_multipart_complete(st->inst, st->final_key, st->upload_id,
                                   st->parts, st->part_count, noreplace);
    if (rc != 0) {                                 /* ESTALE / EEXIST / EIO / ETIMEDOUT  */
        sd_obj_staged_abort(st);
        errno = rc; return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT: idempotent abort. WHY: cancellation, failed commit, or a failed promote must
 *       leave no visible final object and no dangling multipart parts (§9.3).
 * HOW:  guard on `aborted`; AbortMultipartUpload(final_key, upload_id). Best-effort;
 *       a failed abort is logged by the VFS layer, never thrown here.
 */
static void sd_obj_staged_abort(xrootd_sd_staged_t *st);

/*
 * WHAT: plain pwrite on an object handle. WHY: random in-place write on a committed
 *       object is the headline v1 limitation (§5.3, §8).
 * HOW:  always ENOTSUP + metric. The supported write path is staged_* above; the VFS
 *       routes uploads through staging, never here.
 */
static ssize_t
sd_obj_pwrite(xrootd_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    sd_metric_unsupported(obj->inst, "pwrite");    /* xrootd_sd_unsupported_total        */
    errno = ENOTSUP; return -1;                    /* → kXR_Unsupported / 501            */
}

/*
 * WHAT: ftruncate. WHY: no CAP_TRUNCATE on an object backend (§3.1).
 * HOW:  always ENOTSUP + metric.
 */
static ngx_int_t
sd_obj_ftruncate(xrootd_sd_obj_t *obj, off_t len)
{
    sd_metric_unsupported(obj->inst, "ftruncate"); /* xrootd_sd_unsupported_total        */
    errno = ENOTSUP; return NGX_ERROR;             /* → kXR_Unsupported / 501            */
}

/*
 * WHAT: fsync. WHY: object commit IS the durability point; per-write fsync is a no-op
 *       (§8). HOW: return NGX_OK without a network call (NOT an error — durability is
 *       satisfied at staged_commit).
 */
static ngx_int_t sd_obj_fsync(xrootd_sd_obj_t *obj) { return NGX_OK; }
```

#### 16.1.7 server_copy → CopyObject; rename → weak or ENOTSUP

```c
/*
 * WHAT: server-side copy. WHY: WebDAV COPY / S3 CopyObject map to a single backend
 *       operation with zero data egress (§5.4). HOW: confine both keys; S3 CopyObject.
 *       Cross-bucket / cross-instance copy is not expressible as one CopyObject — that
 *       returns NGX_DECLINED so the VFS falls back to its stream-through pread→pwrite
 *       loop (xrootd_copy_range), exactly as §3.3 / §5.4 specify.
 */
static ngx_int_t
sd_obj_server_copy(xrootd_sd_instance_t *inst, const char *src,
                   const char *dst, off_t *bytes_out)
{
    char skey[XROOTD_SD_KEY_MAX], dkey[XROOTD_SD_KEY_MAX];
    if (sd_obj_key_from_path(inst, src, 0, skey, sizeof skey) != NGX_OK) return NGX_ERROR;
    if (sd_obj_key_from_path(inst, dst, 0, dkey, sizeof dkey) != NGX_OK) return NGX_ERROR;
    int rc = s3_copy_object(inst, skey, dkey, bytes_out);  /* rc=errno; 0=ok            */
    if (rc == 0) return NGX_OK;
    errno = rc; return NGX_ERROR;
}

/*
 * WHAT: rename. WHY: object stores have no atomic rename (no CAP_HARD_RENAME, §3.1).
 * HOW:  weak_rename off (default) → ENOTSUP + metric. weak_rename on → CopyObject then
 *       DeleteObject, with a non-atomic window the VFS logs as degraded
 *       (xrootd_sd_degraded_total{op=rename,reason=weak}). A Copy-ok / Delete-fail
 *       leaves the source behind; that is logged, never silently dropped (§9.3).
 */
static ngx_int_t
sd_obj_rename(xrootd_sd_instance_t *inst, const char *src,
              const char *dst, int noreplace)
{
    if (!inst->weak_rename) {
        sd_metric_unsupported(inst, "rename");     /* xrootd_sd_unsupported_total        */
        errno = ENOTSUP; return NGX_ERROR;         /* → kXR_Unsupported / 501            */
    }
    char skey[XROOTD_SD_KEY_MAX], dkey[XROOTD_SD_KEY_MAX];
    if (sd_obj_key_from_path(inst, src, 0, skey, sizeof skey) != NGX_OK) return NGX_ERROR;
    if (sd_obj_key_from_path(inst, dst, 0, dkey, sizeof dkey) != NGX_OK) return NGX_ERROR;

    int rc = s3_copy_object(inst, skey, dkey, NULL);
    if (rc != 0) { errno = rc; return NGX_ERROR; }
    sd_metric_degraded(inst, "rename", "weak");    /* xrootd_sd_degraded_total           */
    rc = s3_delete(inst, skey);
    if (rc != 0) {                                 /* dst exists, src remains — log it   */
        sd_log_nonatomic_rename_cleanup(inst, /*src*/skey);
        errno = rc; return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT: mkdir. WHY: no CAP_DIRS — directories are synthesized from key prefixes.
 * HOW:  default = no-op success (a prefix springs into existence when an object under
 *       it is written). If the operator wants explicit empty-dir markers, write a
 *       zero-byte "<key>/" marker object — but v1 keeps it a no-op to avoid marker
 *       litter. Never ENOTSUP (mkdir must succeed so PUT-into-new-prefix works).
 */
static ngx_int_t sd_obj_mkdir(xrootd_sd_instance_t *inst, const char *path, mode_t mode)
{ return NGX_OK; }
```

#### 16.1.8 opendir/readdir → ListObjectsV2 paginated iterator

```c
/*
 * WHAT: directory iterator backed by ListObjectsV2 with prefix + delimiter.
 * WHY:  object stores have no dirs (no CAP_DIRS); a "directory listing" is a prefix
 *       scan where '/' is the delimiter so sub-prefixes collapse to one synthetic
 *       directory entry (§3.1 CAP_DIRS-absent row).
 * HOW:  opendir computes the listing prefix = key_from_path(path) + (path needs a
 *       trailing '/'); the iterator holds the continuation token and the current page;
 *       readdir hands back one entry at a time, fetching the next page lazily when the
 *       page drains and IsTruncated was true. CommonPrefixes → dir entries; Contents →
 *       file entries. Worker-safe: the page fetch is a blocking LIST and runs in the
 *       AIO pool (§5.5).
 */
typedef struct {
    xrootd_sd_instance_t *inst;
    char       *list_prefix;       /* prefix + path + '/'                               */
    char       *cont_token;        /* ListObjectsV2 ContinuationToken; NULL = first page*/
    int         truncated;         /* IsTruncated from the last page                    */
    s3_list_page_t page;           /* parsed Contents[] + CommonPrefixes[]              */
    size_t      cursor;            /* index into the merged page entries                */
} xrootd_sd_dir_t;

static xrootd_sd_dir_t *
sd_obj_opendir(xrootd_sd_instance_t *inst, const char *path, int *err_out)
{
    char key[XROOTD_SD_KEY_MAX];
    if (sd_obj_key_from_path(inst, path, /*allow_empty=*/1, key, sizeof key) != NGX_OK) {
        *err_out = errno; return NULL;
    }
    xrootd_sd_dir_t *d = sd_dir_alloc(inst);
    if (d == NULL) { *err_out = ENOMEM; return NULL; }
    d->list_prefix = sd_obj_join_slash(inst, key);   /* ensure trailing '/'             */
    int rc = s3_list_v2(inst, d->list_prefix, /*delimiter=*/"/",
                        /*cont=*/NULL, &d->page, &d->truncated, &d->cont_token);
    if (rc != 0) { *err_out = rc; sd_dir_free(d); return NULL; }  /* ENOENT/EACCES/EIO   */
    return d;
}

/*
 * WHAT: yield one entry. WHY: VFS dirlist consumes one dirent at a time.
 * HOW:  if the page is drained and truncated, fetch the next page; map the next entry
 *       (CommonPrefix → DT_DIR, Contents → DT_REG) via sd_obj_path_from_key, hiding the
 *       prefix and the synthetic "<prefix>" self-key. Return NGX_DONE at true end.
 */
static ngx_int_t
sd_obj_readdir(xrootd_sd_dir_t *d, struct xrootd_sd_dirent_s *out)
{
    if (d->cursor >= sd_page_count(&d->page)) {
        if (!d->truncated) return NGX_DONE;          /* end of listing                  */
        int rc = s3_list_v2(d->inst, d->list_prefix, "/", d->cont_token,
                            &d->page, &d->truncated, &d->cont_token);
        if (rc != 0) { errno = rc; return NGX_ERROR; }
        d->cursor = 0;
        if (sd_page_count(&d->page) == 0) return NGX_DONE;
    }
    sd_page_entry_t *e = sd_page_at(&d->page, d->cursor++);
    const char *logical = sd_obj_path_from_key(d->inst, e->key);
    if (logical == NULL) return sd_obj_readdir(d, out);  /* skip foreign key (tail call) */
    sd_dirent_fill(out, sd_basename(logical), e->is_prefix ? DT_DIR : DT_REG, e->size);
    return NGX_OK;
}

static ngx_int_t sd_obj_closedir(xrootd_sd_dir_t *d);   /* free page + token, idempotent*/
```

#### 16.1.9 xattr → object tagging or sidecar

```c
/*
 * WHAT: xattr get/set/list/remove, mapped per `xattr_mode`.
 * WHY:  CAP_XATTR is advertised, but object stores carry metadata as bounded tags;
 *       large/overflowing sets (WebDAV dead-properties, lock DB) need a sidecar (§8).
 * HOW:  mode tags    → S3 GetObjectTagging/PutObjectTagging (cap: ~10 tags, small);
 *       mode sidecar → a companion object "<key>.xattr" (JSON map) read/modify/write;
 *       mode off     → every xattr op ENOTSUP + unsupported metric.
 *       In tags mode, a set that would exceed the tag-count/size cap returns EOVERFLOW
 *       (mapped to a clear 4xx) rather than silently truncating — unless sidecar is the
 *       configured fallback.
 */
static ngx_int_t
sd_obj_setxattr(xrootd_sd_instance_t *inst, const char *path, const char *name,
                const void *val, size_t len, int flags)
{
    if (inst->xattr_mode == XATTR_OFF) {
        sd_metric_unsupported(inst, "setxattr");   /* xrootd_sd_unsupported_total        */
        errno = ENOTSUP; return NGX_ERROR;         /* → kXR_Unsupported / 501            */
    }
    char key[XROOTD_SD_KEY_MAX];
    if (sd_obj_key_from_path(inst, path, 0, key, sizeof key) != NGX_OK) return NGX_ERROR;

    if (inst->xattr_mode == XATTR_TAGS)
        return sd_obj_tag_set(inst, key, name, val, len, flags);   /* PutObjectTagging   */
    return sd_obj_sidecar_set(inst, key, name, val, len, flags);   /* RMW "<key>.xattr"  */
}
/* getxattr / listxattr / removexattr mirror this: XATTR_OFF → ENOTSUP+metric; else
 * tag or sidecar. listxattr in sidecar mode reads the JSON map; in tags mode lists tag
 * keys. removexattr deletes the tag / sidecar entry. */
```

---

### 16.2 `sd_object_s3.c` — transport

Each transport function returns a **storage fact**: `0` (or a byte count `>= 0`) on
success, else a **positive errno** (NOT -1 — the policy core assigns it straight into
`errno`/`*err_out`). Every one is **worker-safe**: it runs only in the AIO thread pool,
touches no nginx pool/metrics/log, and does its own bounded retry.

#### 16.2.1 The signed-request seam

```c
/*
 * sd_object_s3.c — S3 transport for the object driver (worker-safe, blocking).
 *
 * WHAT: HEAD / ranged GET / PUT / multipart / DELETE / CopyObject / ListObjectsV2 over
 *       SigV4-signed HTTP, run inside the AIO thread pool.
 * WHY:  the policy core (sd_object.c) must stay transport-agnostic; all SigV4 + HTTP
 *       wire bytes live here. Reuses the shared signing-key kernel so the sign path
 *       (this file) and the server verify path (src/protocols/s3/auth_sigv4_*.c) can never drift.
 * HOW:  one private s3_signed_exchange() builds the canonical request via the shared
 *       xrootd_s3_canonical_request() (factored from src/protocols/s3/auth_sigv4_canonical.c),
 *       signs with xrootd_sigv4_signing_key()+xrootd_hmac_sha256(), and drives the
 *       blocking xrootd_httpc_exchange() (factored from client/lib/http.c). Each public
 *       op is a thin wrapper that sets method/headers/body-source/sink and maps the
 *       HTTP status to an errno.
 */
#include "../compat/sigv4.h"     /* xrootd_sigv4_signing_key()                          */
#include "../compat/crypto.h"    /* xrootd_hmac_sha256 / xrootd_sha256 / streaming      */
#include "../compat/hex.h"       /* xrootd_hex_encode                                   */
#include "../compat/s3_canon.h"  /* NEW: xrootd_s3_canonical_request() (shared sign/verify)*/
#include "../compat/httpc.h"     /* NEW: xrootd_httpc_exchange() (blocking, no event loop)*/

/* Result of one signed HTTP exchange, before status→errno mapping. */
typedef struct {
    int      http_status;          /* 0 = transport/timeout failure                     */
    int      transport_errno;      /* set when http_status==0 (ETIMEDOUT/ECONNREFUSED…) */
    char    *body;                 /* response body (XML for errors/list)               */
    size_t   body_len;
    char     etag[64];             /* parsed ETag header if present                     */
    /* ...content-length, x-amz-* echoed headers as needed... */
} s3_response_t;

/*
 * WHAT: build+sign+send one request; return the raw response for the caller to map.
 * WHY:  one signing chokepoint means the canonical form, header set and clock skew are
 *       handled once for every op.
 * HOW:  compute payload hash (SHA256 of body, or "UNSIGNED-PAYLOAD" for streamed PUT),
 *       build the canonical request (xrootd_s3_canonical_request), derive the signing
 *       key (xrootd_sigv4_signing_key — cache per {date,region} like the server's
 *       s3_sigv4_derive_signing_key_cached), HMAC the string-to-sign, assemble the
 *       Authorization header, then xrootd_httpc_exchange() with the instance timeout/
 *       retry policy. Pure ptr+len; uses a scratch arena, not an nginx pool.
 */
static int
s3_signed_exchange(xrootd_sd_instance_t *inst, const char *method,
                   const char *key, const s3_query_t *query,
                   const s3_hdr_t *extra_hdrs, size_t extra_n,
                   const void *body, size_t body_len,
                   s3_body_sink_t *sink, s3_response_t *resp);
```

#### 16.2.2 HTTP-status → errno table (§3.3.2)

```c
/*
 * WHAT: translate an S3/HTTP response into the §3.3.2 errno fact.
 * WHY:  drivers return errno; the VFS maps errno→kXR_*/HTTP. This table is the single
 *       place that knowledge lives.
 * HOW:  status-keyed switch; a body parse may refine 4xx (e.g. NoSuchKey vs
 *       AccessDenied) but the status is authoritative for the coarse mapping.
 */
static int
s3_status_to_errno(const s3_response_t *r)
{
    if (r->http_status == 0)                    /* transport failure / timeout          */
        return r->transport_errno ? r->transport_errno : ETIMEDOUT; /* → kXR_IOError/504 */
    switch (r->http_status) {
    case 200: case 201: case 204: case 206: return 0;            /* ok / partial / no-content */
    case 304:                               return 0;            /* conditional GET not-modified */
    case 404:                               return ENOENT;       /* → kXR_NotFound / 404 */
    case 401: case 403:                     return EACCES;       /* → kXR_NotAuthorized / 403 */
    case 412:                               return EEXIST;       /* precondition (If-None-Match)→409/EEXIST;
                                                                    If-Match stale → caller may remap ESTALE */
    case 409:                               return EEXIST;       /* conflict (op-specific)     */
    case 400:                               return EINVAL;       /* → kXR_ArgInvalid / 400     */
    case 408: case 504:                     return ETIMEDOUT;    /* → kXR_IOError / 504        */
    case 500: case 502: case 503:           return EIO;          /* → kXR_IOError (retryable)  */
    default:                                return (r->http_status >= 500) ? EIO : EINVAL;
    }
}
/* CompleteMultipartUpload is special: it can return 200 with an *error body* (S3 sends
 * the error inside a 200 to keep the connection warm). s3_multipart_complete() parses
 * the body and returns ESTALE on an ETag/precondition mismatch even on HTTP 200. */
```

#### 16.2.3 Retry / timeout policy hooks (§16.2.5 struct, applied here)

```c
/*
 * WHAT: bounded retry around s3_signed_exchange for idempotent ops.
 * WHY:  object stores routinely 503/throttle; a small retry-with-backoff on EIO/
 *       ETIMEDOUT (and ONLY on idempotent verbs) absorbs transient faults without
 *       masking real errors. Non-idempotent multipart-complete is retried only when the
 *       failure is provably pre-commit (transport error before any 2xx).
 * HOW:  loop up to http.max_retries; on EIO/ETIMEDOUT sleep http.backoff_ms * 2^attempt
 *       (+ jitter) using a worker-safe nanosleep (we are in the AIO thread, blocking is
 *       fine); honour http.deadline_ms as a hard ceiling. ENOENT/EACCES/EEXIST/EINVAL
 *       are returned immediately (not retried).
 */
static int
s3_exchange_retry(xrootd_sd_instance_t *inst, int idempotent, /*...same args...*/);
```

#### 16.2.4 Public transport ops (skeletons)

```c
/*
 * WHAT: HEAD an object → stat fact. WHY: open/stat/fstat need size+etag+mtime without a
 *       body. HOW: signed HEAD; 200 → fill s3_stat_t {size from Content-Length, mtime
 *       from Last-Modified, etag}; map status→errno (404→ENOENT). Idempotent → retried.
 */
int s3_head(xrootd_sd_instance_t *inst, const char *key, s3_stat_t *out);

/*
 * WHAT: ranged GET into `buf`. WHY: the worker-safe pread body (§16.1.5).
 * HOW: signed GET with Range: bytes=off-(off+len-1); 206/200 → copy body into buf,
 *      return byte count (>=0, short at EOF). On error return -1 with errno set from
 *      s3_status_to_errno (404→ENOENT, etc.). Idempotent → retried.
 */
ssize_t s3_get_range(xrootd_sd_instance_t *inst, const char *key,
                     off_t off, size_t len, void *buf);

/*
 * WHAT: whole-object PUT (small objects below the multipart threshold).
 * WHY: a single-shot create avoids multipart overhead for tiny files.
 * HOW: signed PUT with the body; payload hash = SHA256(body) or UNSIGNED-PAYLOAD;
 *      `noreplace` → If-None-Match:* (412→EEXIST). Returns 0 / errno.
 */
int s3_put(xrootd_sd_instance_t *inst, const char *key,
           const void *body, size_t len, int noreplace, char etag_out[64]);

/* ---- multipart (drives the staged lifecycle, §16.1.6) ---- */

/* WHAT: CreateMultipartUpload → UploadId. HOW: signed POST ?uploads; parse <UploadId>. */
int s3_multipart_init(xrootd_sd_instance_t *inst, const char *key,
                      char *upload_id_out, size_t cap);

/* WHAT: UploadPart → part ETag. WHY: each filled part buffer (§16.1.6). HOW: signed PUT
 *       ?partNumber=N&uploadId=…; parse ETag header. Idempotent per (uploadId,partNo). */
int s3_multipart_upload_part(xrootd_sd_instance_t *inst, const char *key,
                             const char *upload_id, int part_no,
                             const void *body, size_t len, char etag_out[64]);

/* WHAT: CompleteMultipartUpload → atomic publish. WHY: the commit point (§16.1.6).
 *       HOW: signed POST ?uploadId=… with the ordered <Part> list; PARSE the 200 body
 *       for an embedded error and return ESTALE on ETag/precondition mismatch. */
int s3_multipart_complete(xrootd_sd_instance_t *inst, const char *key,
                          const char *upload_id, const s3_part_etag_t *parts,
                          size_t n, int noreplace);

/* WHAT: AbortMultipartUpload. WHY: cleanup on abort/failed commit (§9.3). HOW: signed
 *       DELETE ?uploadId=…; best-effort, ENOENT treated as already-gone (return 0). */
int s3_multipart_abort(xrootd_sd_instance_t *inst, const char *key,
                       const char *upload_id);

/* WHAT: DELETE object. WHY: unlink + weak-rename second step. HOW: signed DELETE;
 *       204 → 0; 404 → ENOENT (caller may treat as success for idempotent unlink). */
int s3_delete(xrootd_sd_instance_t *inst, const char *key);

/* WHAT: CopyObject. WHY: server_copy + weak-rename first step (§16.1.7). HOW: signed PUT
 *       with x-amz-copy-source: /<bucket>/<srckey>; parse 200-or-error-in-200 like
 *       complete; ESTALE on copy-source-precondition mismatch. bytes_out from the copied
 *       object size (HEAD or the response). Same-bucket only; cross-bucket → caller gets
 *       NGX_DECLINED upstream so the VFS stream-copies. */
int s3_copy_object(xrootd_sd_instance_t *inst, const char *src_key,
                   const char *dst_key, off_t *bytes_out);

/* WHAT: ListObjectsV2 one page. WHY: the dir iterator (§16.1.8). HOW: signed GET
 *       ?list-type=2&prefix=…&delimiter=…[&continuation-token=…]; parse Contents[],
 *       CommonPrefixes[], IsTruncated, NextContinuationToken. Idempotent → retried. */
int s3_list_v2(xrootd_sd_instance_t *inst, const char *prefix, const char *delimiter,
               const char *cont_token, s3_list_page_t *page_out,
               int *truncated_out, char **next_token_out);
```

#### 16.2.5 Retry/timeout policy struct

```c
/* Transport tunables, parsed from directives, copied into the instance (§16.1.1). */
typedef struct {
    int  connect_ms;     /* TCP connect deadline                                    */
    int  io_ms;          /* per-request send/recv deadline                          */
    int  deadline_ms;    /* hard ceiling across all retries for one op              */
    int  max_retries;    /* idempotent-op retry budget (default ~3)                 */
    int  backoff_ms;     /* base backoff; doubled per attempt + jitter              */
    int  tls_verify;     /* verify the endpoint cert (default on)                   */
} s3_http_policy_t;
```

#### 16.2.6 Credential model + per-user impersonation (open question)

```c
/*
 * Credential modes (directive `xrootd_storage_s3_auth env|file|webidentity|static`):
 *   env         — AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN at init.
 *   file        — ~/.aws/credentials-style file; reloaded on config reload only.
 *   webidentity — OIDC token → AssumeRoleWithWebIdentity → temporary creds; the
 *                 transport refreshes before expiry behind a worker-safe mutex.
 *   static      — keys inline in config (test/dev only; warn at startup).
 *
 * OPEN QUESTION (cross-ref §12.3 — resolve before 55.E): per-user impersonation.
 * POSIX impersonation drops privilege per request (Phase-40 root broker). An object
 * backend authenticates with ONE service credential, so a request's user identity does
 * NOT propagate to the store by default. Two candidate models, undecided here:
 *   (a) one service credential per export (authorization stays a VFS/authdb decision
 *       above the seam; the store trusts the gateway) — simplest, the v1 default;
 *   (b) per-user store credentials / request-signing identity (map the authenticated
 *       principal to a store role via AssumeRole) — needed if the store itself must
 *       enforce per-user access. Deferred; v1 ships (a) with a clear doc note.
 */
typedef enum { S3_CRED_ENV, S3_CRED_FILE, S3_CRED_WEBIDENTITY, S3_CRED_STATIC } s3_cred_mode_t;

typedef struct {
    s3_cred_mode_t  mode;
    ngx_str_t       access_key;
    ngx_str_t       secret_key;
    ngx_str_t       session_token;   /* webidentity/temporary creds                    */
    time_t          expiry;          /* 0 = non-expiring; else refresh before this      */
} s3_creds_t;
```

---

### 16.3 `sd_block.c` — proof backend

```text
WHY IT EXISTS
-------------
sd_block.c is the 55.D "second non-trivial backend" landed BEFORE the S3 driver. Its job
is to prove the SD abstraction is honest with a backend that is neither POSIX nor object:
  - it has NO directories and NO server-side copy (forces the VFS stream-through and the
    synthesized/flat-namespace paths to be exercised by something other than S3);
  - it HAS random write + truncate + range read (the opposite capability profile to S3),
    so the capability matrix is tested from both ends;
  - it is fully local and deterministic (no network, no creds), so the backend-parity
    matrix (§9.1) and security-negative tests can run in CI with zero external deps.
If the vtable/caps model is wrong, sd_block.c breaks loudly here, cheaply, before the
much costlier S3 transport work.

CAPABILITIES
------------
caps = RANGE_READ | RANDOM_WRITE | TRUNCATE
NOT  = DIRS         (flat fixed object table — no hierarchy)
       SERVER_COPY  (no native copy; VFS stream-through pread→pwrite)
       SENDFILE     (maybe: a file-backed device COULD sendfile, but v1 keeps reads
                     memory-backed for simplicity → behaves like the object read path)
       FD/IOURING/HARD_RENAME/APPEND/XATTR  (none)
```

```text
SUPERBLOCK / EXTENT-MAP LAYOUT (on a block device or backing file)
------------------------------------------------------------------
offset 0      ┌──────────────────────────────────────────────┐
              │ superblock (one 4 KiB block)                  │
              │   magic   = "XRBLK\0\0\0"                     │
              │   version = 1                                 │
              │   block_size                                  │
              │   table_blocks      (# blocks for obj table)  │
              │   data_start_block  (first data extent block) │
              │   total_blocks                                │
              │   free_hint_block   (bump allocator cursor)   │
              └──────────────────────────────────────────────┘
block 1..T    ┌──────────────────────────────────────────────┐
              │ fixed object table: array of slots            │
              │   slot { name[224];  /* logical key, NUL-pad */│
              │          size;                                │
              │          start_block;  /* first data extent */ │
              │          nblocks;      /* contiguous extent  */ │
              │          flags;        /* 0=free,1=used,2=tomb*/│
              │          crc32c; }     /* slot integrity      */ │
              └──────────────────────────────────────────────┘
block D..N    data extents (one contiguous extent per object; v1 = no fragmentation;
              grow/truncate reallocates a new extent and frees the old via the bump/
              free-list — simple, correctness-first, not space-optimal)
```

```c
/*
 * sd_block.c — block-device / extent-map proof storage driver.
 *
 * WHAT: a flat, fixed-object-table driver over ONE block device or backing file.
 * WHY:  proves the SD abstraction with a non-POSIX, non-object backend whose capability
 *       profile is the inverse of S3 (random write yes, dirs/copy no) — see the WHY
 *       block above. Local + deterministic so it runs in CI with no external deps.
 * HOW:  a superblock + fixed slot table indexes logical keys to contiguous extents; all
 *       I/O is pread/pwrite against the device fd, guarded by a per-instance lock.
 *       Worker-safe ops run in the AIO pool exactly like POSIX. No goto; small fns.
 */

typedef struct {
    int        dev_fd;           /* O_RDWR (optionally O_DIRECT) device/file fd          */
    sb_t       sb;               /* cached superblock                                    */
    ngx_atomic_t lock;           /* serializes table mutation (extent alloc/truncate)    */
    ngx_log_t *log;              /* init-time only                                       */
} xrootd_sd_block_inst_t;

typedef struct {
    xrootd_sd_block_inst_t *inst;
    int      slot_idx;           /* index into the object table                          */
    off_t    size;               /* cached from the slot                                 */
} xrootd_sd_block_obj_t;

const xrootd_sd_driver_t xrootd_sd_driver_block = {
    .name        = "block",
    .caps        = XROOTD_SD_CAP_RANGE_READ | XROOTD_SD_CAP_RANDOM_WRITE
                 | XROOTD_SD_CAP_TRUNCATE,

    .init        = sd_block_init,        /* open device, read+validate superblock        */
    .cleanup     = sd_block_cleanup,
    .open        = sd_block_open,        /* find-or-create slot by key                    */
    .close       = sd_block_close,
    .pread       = sd_block_pread,       /* clamp to extent; read device at extent off    */
    .pwrite      = sd_block_pwrite,      /* random write within (or growing) the extent   */
    .ftruncate   = sd_block_ftruncate,   /* shrink in place / grow via realloc-extent     */
    .fsync       = sd_block_fsync,       /* fdatasync the device fd                        */
    .fstat       = sd_block_fstat,       /* size from slot                                 */
    .stat        = sd_block_stat,        /* table lookup by key                            */
    .unlink      = sd_block_unlink,      /* tombstone slot + free extent                   */

    /* ---- capability-absent slots: ENOTSUP + metric, NEVER left NULL ---- */
    .mkdir       = sd_block_enotsup_ns,  /* no dirs                                         */
    .rename      = sd_block_enotsup_ns,  /* no atomic rename                               */
    .server_copy = sd_block_decline_copy,/* NGX_DECLINED → VFS stream-through (§5.4)        */
    .opendir     = sd_block_enotsup_dir, /* no dirs → NULL + errno=ENOTSUP + metric         */
    .readdir     = NULL,                 /* unreachable: opendir always fails (documented)  */
    .closedir    = NULL,
    .getxattr    = sd_block_enotsup_xattr,
    .listxattr   = sd_block_enotsup_xattr,
    .setxattr    = sd_block_enotsup_xattr_set,
    .removexattr = sd_block_enotsup_xattr_rm,
    .staged_open = sd_block_staged_open, /* staged = write to a tomb-then-publish slot      */
    .staged_write= sd_block_staged_write,
    .staged_commit = sd_block_staged_commit,  /* flip slot flags free→used atomically       */
    .staged_abort  = sd_block_staged_abort,
};

/*
 * WHAT: directory open on a dir-less backend. WHY: no CAP_DIRS. HOW: ENOTSUP + metric.
 * (readdir/closedir are NULL because this never returns a dir handle — the VFS checks
 *  CAP_DIRS before calling, and the parity test asserts the ENOTSUP path.)
 */
static xrootd_sd_dir_t *
sd_block_enotsup_dir(xrootd_sd_instance_t *inst, const char *path, int *err_out)
{
    sd_metric_unsupported(inst, "opendir");   /* xrootd_sd_unsupported_total{op=opendir} */
    *err_out = ENOTSUP; return NULL;          /* → kXR_Unsupported / 501                 */
}

/*
 * WHAT: server_copy on block. WHY: no native copy. HOW: NGX_DECLINED so the VFS falls
 *       back to its own pread→pwrite stream-through (§5.4) — NOT ENOTSUP, because the
 *       copy still succeeds via the VFS, it just isn't backend-accelerated. The VFS
 *       records xrootd_sd_degraded_total{op=copy,reason=stream_copy}.
 */
static ngx_int_t
sd_block_decline_copy(xrootd_sd_instance_t *inst, const char *src,
                      const char *dst, off_t *bytes_out)
{ return NGX_DECLINED; }

/*
 * WHAT: namespace ops with no block equivalent (mkdir/rename). WHY: no dirs / no atomic
 *       rename. HOW: ENOTSUP + metric. One shared body keeps it DRY.
 */
static ngx_int_t
sd_block_enotsup_ns(xrootd_sd_instance_t *inst, /* path args ignored */ ...)
{
    sd_metric_unsupported(inst, "namespace"); /* xrootd_sd_unsupported_total             */
    errno = ENOTSUP; return NGX_ERROR;        /* → kXR_Unsupported / 501                 */
}
/* xattr get/list/set/remove likewise → ENOTSUP + xrootd_sd_unsupported_total{op=*xattr}.*/
```

```text
ENOTSUP / xrootd_sd_unsupported_total INVENTORY (every explicit unsupported site)
--------------------------------------------------------------------------------
sd_object.c:
  open (O_TRUNC|O_APPEND) ...... ENOTSUP + unsupported_total{op=open}
  pwrite (in-place random) ..... ENOTSUP + unsupported_total{op=pwrite}
  ftruncate .................... ENOTSUP + unsupported_total{op=ftruncate}
  staged_write (non-sequential)  ENOTSUP + unsupported_total{op=staged_write}
  rename (weak_rename off) ..... ENOTSUP + unsupported_total{op=rename}
  setxattr/getxattr/... (off) .. ENOTSUP + unsupported_total{op=*xattr}
  (server_copy cross-bucket) ... NGX_DECLINED → VFS stream-through (degraded, not unsup.)
  (rename weak_rename on) ...... degraded_total{op=rename,reason=weak} (NOT unsupported)
sd_block.c:
  mkdir / rename ............... ENOTSUP + unsupported_total{op=namespace}
  opendir (no dirs) ............ ENOTSUP + unsupported_total{op=opendir}
  getxattr/listxattr/set/remove  ENOTSUP + unsupported_total{op=*xattr}
  server_copy .................. NGX_DECLINED → VFS stream-through (degraded, not unsup.)
```


## 17. Exact edit hunks for existing files

This appendix is the surgical checklist for the 55.A–55.C refactor. Every hunk is
anchored to the real symbols and current code in the tree as of this writing. Line
numbers are advisory ("near line N") because earlier hunks shift later ones; match on
the quoted text, not the number. The cut order follows §4.1 (byte-I/O first, then
open/adopt/close, then namespace/fd-leak), so apply in subsection order. All new
`xrootd_sd_*` symbols come from the new `src/fs/backend/sd.h` defined in §3.

Conventions used below:
- `obj` is the `xrootd_sd_obj_t *` returned by the driver; `xrootd_sd_fd(obj)` returns
  the POSIX fd or `NGX_INVALID_FILE` when `!CAP_FD`.
- `inst` is the per-export `xrootd_sd_instance_t *` (POSIX wraps `rootfd`/`root_canon`).
- A POSIX driver call inlines to exactly today's syscall, so 55.A–55.C are byte-identical.

---

### 17.1 `src/fs/vfs_internal.h`

**Intent:** replace the raw fd in the open-handle struct with an opaque SD object,
keeping every cached metadata field and the `stat_current` optimization; update the
two helper prototypes that still take a bare `ngx_fd_t` to take `obj`.

`struct xrootd_vfs_file_s` (near line 47) — replace the `fd` member:

```diff
 struct xrootd_vfs_file_s {
-    ngx_fd_t          fd;
+    xrootd_sd_obj_t  *obj;          /* SD object handle; POSIX wraps an fd      */
     off_t             size;
     time_t            mtime;
     time_t            ctime;
     ino_t             ino;
     mode_t            mode;
     ngx_pool_t       *pool;
     ngx_log_t        *log;
     xrootd_vfs_ctx_t *ctx;
     char             *path;
     unsigned          from_cache:1;
     unsigned          is_tls:1;
     unsigned          cleanup_registered:1;
     /* phase-45 W2/R1: ... stat_current unchanged ... */
     unsigned          stat_current:1;
 };
```

`struct xrootd_vfs_staged_s` (near line 75) — gains the backend instance the
§3.6.1 commit decision keys on (the temp fd stays in `staged`):

```diff
 struct xrootd_vfs_staged_s {
     xrootd_staged_file_t  staged;   /* the compat temp-file primitive */
     xrootd_vfs_ctx_t     *ctx;      /* carries root_canon + final (resolved) path */
+    xrootd_sd_instance_t *backend;  /* ctx->sd: the durable store to promote into */
+    xrootd_sd_instance_t *staging;  /* ctx->sd_staging: where the temp actually lives */
     ngx_pool_t           *pool;
     ngx_log_t            *log;
 };
```

`xrootd_vfs_adopt_fd` prototype (near line 241) — still accepts a raw fd at the
POSIX seam (it is the body that wraps it in an obj), so the signature is unchanged but
its doc updates:

```c
/* (doc) Wrap an already-open fd in a freshly pcalloc'd handle: builds a POSIX
 * xrootd_sd_obj_t around fd via the ctx->sd driver, fstat()s for cached metadata,
 * dups path, records from_cache/is_tls.  *out adopts the obj (and the fd it owns). */
ngx_int_t xrootd_vfs_adopt_fd(xrootd_vfs_ctx_t *ctx, const char *path,
    ngx_fd_t fd, unsigned from_cache, xrootd_vfs_file_t **out);
```

`xrootd_vfs_pread_full` / `xrootd_vfs_pwrite_full` prototypes (near lines 248/254)
stay as-is: they remain POSIX-fd primitives used internally by `sd_posix.c`. They are
no longer called from `vfs_read.c`/`vfs_write.c` directly (those route through the
driver — §17.6/§17.7), but `sd_posix.c`'s `pread`/`pwrite` bodies *are* these, so keep
the declarations. Add `#include "backend/sd.h"` is **not** needed here because
`vfs_internal.h` includes `vfs.h` (§17.2) which now includes it.

---

### 17.2 `src/fs/vfs.h`

**Intent:** pull the SD types into the public surface (for `xrootd_vfs_ctx_t`), add the
backend+staging store binding to the ctx, and document `xrootd_vfs_file_fd()` as
retiring (it forwards to `xrootd_sd_fd(fh->obj)` internally and is removed for external
callers in §17.13–17.15).

Add the include (near line 35, after the existing includes):

```diff
 #include "../path/unified.h"
 #include "../types/identity.h"
 #include "../metrics/unified.h"
+#include "backend/sd.h"      /* xrootd_sd_instance_t / xrootd_sd_obj_t opaque types */
```

`xrootd_vfs_ctx_t` (near line 78) — add the two store pointers (§3.6/§6.3). Keep
`root_canon`/`rootfd` for logging/identity and for the POSIX instance to consume:

```diff
 typedef struct {
     ngx_pool_t          *pool;
     ngx_log_t           *log;
     xrootd_identity_t   *identity;
     xrootd_proto_t       metrics_proto;
     const char          *root_canon;
     const char          *cache_root_canon;
     int                  rootfd;           /* persistent O_PATH fd, or -1 */
     void                *cache_writethrough_cfg;
+    xrootd_sd_instance_t *sd;              /* backend store — durable, client-visible */
+    xrootd_sd_instance_t *sd_staging;      /* staging store — in-progress uploads;
+                                            * == sd when xrootd_storage_staging=same   */
     xrootd_path_result_t resolved;
     unsigned             allow_write:1;
     unsigned             is_tls:1;
     unsigned             want_pgcrc:1;
     unsigned             cache_enabled:1;
     unsigned             cache_writethrough:1;
 } xrootd_vfs_ctx_t;
```

`xrootd_vfs_file_fd()` declaration (near line 120) — annotate as deprecated/internal.
In 55.C the external callers (§17.13–17.15) are gone, so this becomes a POSIX-only
shim. Mark it so a non-POSIX backend can never silently leak a fake fd:

```diff
-/* Accessors over the handle's cached metadata (captured at open via fstat) —
- * no syscalls. fd: underlying descriptor or NGX_INVALID_FILE if fh is NULL. */
-ngx_fd_t xrootd_vfs_file_fd(const xrootd_vfs_file_t *fh);
+/* Accessors over the handle's cached metadata (captured at open via fstat) — no
+ * syscalls.
+ *
+ * DEPRECATED (Phase 55 §6.1): exposes a POSIX fd and is therefore capability-
+ * unsafe.  Internally this now returns xrootd_sd_fd(fh->obj), i.e.
+ * NGX_INVALID_FILE when the backend lacks XROOTD_SD_CAP_FD.  No protocol/shared
+ * code may call it; use xrootd_vfs_read() for the capability-correct chain.
+ * Retained only as a private POSIX-driver convenience during 55.B/55.C. */
+ngx_fd_t xrootd_vfs_file_fd(const xrootd_vfs_file_t *fh);
```

`xrootd_vfs_read()` doc (near line 135) — update the buffer-shape sentence from
"memory under TLS or want_pgcrc, else file-backed" to capability-gated wording, since
§17.6 changes the predicate:

```c
/* ... Buffer shape: memory-backed unless the backend advertises
 * XROOTD_SD_CAP_SENDFILE and neither TLS nor want_pgcrc forces memory; otherwise
 * file-backed for sendfile.  (Object backends never have CAP_SENDFILE → always
 * memory, exactly the TLS path.)  ... */
```

---

### 17.3 `src/fs/vfs_io_core.h`

**Intent:** make the worker-safe job object-centric. The job carries
`xrootd_sd_obj_t *obj` (and segment arrays carry `obj` instead of raw `fd`/`rootfd`),
so `xrootd_vfs_io_execute()` dispatches through `obj->driver->...`. The init helpers
take `obj`.

Segment descriptors (near lines 43/52) — swap `int fd` for `obj`:

```diff
 typedef struct {
-    int       fd;
+    xrootd_sd_obj_t *obj;
     int       handle_index;
     off_t     offset;
     uint32_t  read_length;
     u_char   *header_read_length_ptr;
     u_char   *payload_ptr;
 } xrootd_vfs_readv_seg_t;

 typedef struct {
-    int           fd;
+    xrootd_sd_obj_t *obj;
     int           handle_idx;
     off_t         offset;
     const u_char *data;
     uint32_t      wlen;
 } xrootd_vfs_writev_seg_t;
```

`xrootd_vfs_job_t` (near line 60) — replace the raw `fd`/`rootfd` IN fields with an
`obj` and a dir-instance pointer for OPENDIR (the object driver offloads opendir, §5.5,
so the job carries the instance + logical path, not a bare dirfd):

```diff
 typedef struct {
     /* IN: immutable once posted to a worker. */
     xrootd_vfs_io_op_e  op;
-    ngx_fd_t            fd;
+    xrootd_sd_obj_t    *obj;        /* SD object for READ/WRITE/PGREAD/SYNC/TRUNCATE */
     off_t               offset;
     size_t              length;
     u_char             *buf;
     size_t              buf_cap;
     void               *segs;
     size_t              nsegs;
     unsigned            want_pgcrc:1;
     unsigned            do_sync:1;
     unsigned            want_stat:1;
     unsigned            want_cksum:1;
-    int                 rootfd;
+    xrootd_sd_instance_t *dir_inst; /* OPENDIR: backend instance to scan          */
+    int                 rootfd;     /* OPENDIR (POSIX fast path): confined dir fd  */
     u_char              streamid[2];
     const char         *path;
     const char         *cksum_algo;
     ngx_log_t          *log;
     char               *err_msg;
     size_t              err_msg_cap;
     /* OUT: ... unchanged ... */
 } xrootd_vfs_job_t;
```

Note: `rootfd` is kept for the POSIX OPENDIR fast path (`fdopendir(dup(rootfd))` stays
byte-identical in 55.B); `dir_inst` is added so 55.E can route opendir through the
object driver. For 55.B/55.C only `rootfd` is populated.

Init helpers — change the four fd-taking initializers to take `obj`. Example, the
READ initializer (near line 101):

```diff
 static ngx_inline void
-xrootd_vfs_job_read_init(xrootd_vfs_job_t *job, ngx_fd_t fd, off_t offset,
-    size_t length, u_char *dst, size_t dst_cap, unsigned want_pgcrc)
+xrootd_vfs_job_read_init(xrootd_vfs_job_t *job, xrootd_sd_obj_t *obj, off_t offset,
+    size_t length, u_char *dst, size_t dst_cap, unsigned want_pgcrc)
 {
     ngx_memzero(job, sizeof(*job));
     job->op = XROOTD_VFS_IO_READ;
-    job->fd = fd;
+    job->obj = obj;
     job->offset = offset;
     job->length = length;
     job->buf = dst;
     job->buf_cap = dst_cap;
     job->want_pgcrc = want_pgcrc ? 1 : 0;
 }
```

Apply the identical `ngx_fd_t fd` → `xrootd_sd_obj_t *obj` / `job->fd = fd` →
`job->obj = obj` change to `xrootd_vfs_job_write_init` (near 125),
`xrootd_vfs_job_sync_init` (near 148), and `xrootd_vfs_job_truncate_init` (near 166).
`xrootd_vfs_job_opendir_init` (near 186) stays fd-based for the POSIX fast path; add an
overload-free `dir_inst` parameter set to the backend instance:

```c
"replace the signature
  ... ngx_int_t rootfd, ...
 with
  ... xrootd_sd_instance_t *dir_inst, int rootfd, ...
 and add inside the body:
  job->dir_inst = dir_inst;
 (everything else in the body is unchanged)"
```

---

### 17.4 `src/fs/vfs_io_core.c`

**Intent:** the six EXECUTE arms (READ/WRITE/PGREAD/READV/WRITEV/OPENDIR — plus the
trivial SYNC/TRUNCATE) dispatch the raw op through `obj->driver->pread/pwrite/...`
instead of calling `pread`/`pwrite`/`fdopendir` directly. POSIX driver bodies inline to
today's syscalls. The READ and WRITE arms are shown in full; the rest are summarized.

Add the include at the top (near line 21):

```diff
 #include "vfs_internal.h"
 #include "vfs_io_core.h"
+#include "backend/sd.h"
```

The counted-write helper `xrootd_vfs_io_write_counted` (near line 99) currently calls
`pwrite(2)` directly; it becomes object-driven. Change its signature from `ngx_fd_t fd`
to `xrootd_sd_obj_t *obj` and the inner call:

```diff
 static ngx_int_t
-xrootd_vfs_io_write_counted(ngx_fd_t fd, const u_char *buf, size_t len,
+xrootd_vfs_io_write_counted(xrootd_sd_obj_t *obj, const u_char *buf, size_t len,
     off_t offset, ssize_t *written, unsigned *short_io)
 {
     ...
     while (done < len) {
         ssize_t nwrite;
-        nwrite = pwrite(fd, buf + done, len - done, offset + (off_t) done);
+        nwrite = obj->driver->pwrite(obj, buf + done, len - done,
+                                     offset + (off_t) done);
         if (nwrite < 0) { ... EINTR/short-io handling unchanged ... }
         ...
     }
     ...
 }
```

**READ arm — full.** `xrootd_vfs_io_execute_read` (near line 154). The fd guard becomes
an obj guard; the pread loop routes through the driver. Because `xrootd_vfs_pread_full`
is itself a POSIX-fd loop, the EXECUTE arm now calls the driver's `pread` directly in a
short-read-tolerant loop (the POSIX driver's `pread` *is* `xrootd_vfs_pread_full` over
`xrootd_sd_fd(obj)`):

```diff
 static void
 xrootd_vfs_io_execute_read(xrootd_vfs_job_t *job)
 {
     size_t nread;

-    if (job->fd == NGX_INVALID_FILE || job->offset < 0
+    if (job->obj == NULL || job->offset < 0
         || (job->length > 0 && job->buf == NULL)
         || job->buf_cap < job->length)
     {
         job->nio = -1;
         job->io_errno = EINVAL;
         return;
     }

     nread = 0;
-    if (xrootd_vfs_pread_full(job->fd, job->buf, job->length, job->offset,
-                              &nread)
-        != NGX_OK)
+    if (xrootd_sd_pread_full(job->obj, job->buf, job->length, job->offset,
+                             &nread)
+        != NGX_OK)
     {
         job->nio = -1;
         job->out_size = nread;
         job->io_errno = errno;
         return;
     }

     job->nio = (ssize_t) nread;
     job->out_size = nread;
     if (job->want_pgcrc && nread > 0) {
         job->crc32c = xrootd_crc32c_value(job->buf, nread);
     }
 }
```

where `xrootd_sd_pread_full(obj, buf, len, off, *nread)` is a thin helper added in
`sd.h` that loops `obj->driver->pread` EINTR-safe and short-read-tolerant (the exact
body of today's `xrootd_vfs_pread_full`, with `pread(fd,...)` → `obj->driver->pread(obj,...)`).
For POSIX this is identical machine code.

**WRITE arm — full.** `xrootd_vfs_io_execute_write` (near line 197):

```diff
 static void
 xrootd_vfs_io_execute_write(xrootd_vfs_job_t *job)
 {
     ssize_t  written;
     unsigned short_io;

-    if (job->fd == NGX_INVALID_FILE || job->offset < 0
+    if (job->obj == NULL || job->offset < 0
         || (job->length > 0 && job->buf == NULL))
     {
         job->nio = -1;
         job->io_errno = EINVAL;
         return;
     }

     if (job->length == 0) {
         job->nio = 0;
         return;
     }

-    if (xrootd_vfs_io_write_counted(job->fd, job->buf, job->length,
+    if (xrootd_vfs_io_write_counted(job->obj, job->buf, job->length,
                                     job->offset, &written, &short_io)
         != NGX_OK)
     {
         job->nio = short_io ? written : -1;
         job->out_size = written > 0 ? (size_t) written : 0;
         job->short_io = short_io ? 1 : 0;
         job->io_errno = errno;
         return;
     }

     job->nio = written;
     job->out_size = (size_t) written;
 }
```

**Remaining arms — summarized (same mechanical pattern):**

- `xrootd_vfs_io_execute_pgread` (near 244): replace the `job->fd == NGX_INVALID_FILE`
  guard with `job->obj == NULL`, and call the driver-backed
  `xrootd_pgread_read_encode_inplace(xrootd_sd_fd(job->obj), ...)` — pgread is gated on
  `CAP_RANGE_READ` upstream (§3.1), and the inplace encoder stays an fd helper, so it
  reads `xrootd_sd_fd(obj)` exactly as io_uring does (§3.4). For non-CAP_FD backends the
  pgread op is rejected before reaching the worker.
- `xrootd_vfs_io_execute_readv` (near 282): the readv segment helper
  `xrootd_readv_read_segments` consumes `xrootd_readv_seg_desc_t` which carry a fd today;
  change that descriptor to carry `obj` and have the helper call `obj->driver->pread`
  (or `preadv` when `CAP_FD`). Guard unchanged otherwise.
- `xrootd_vfs_io_execute_writev` (near 327): the per-segment loop calls
  `xrootd_vfs_io_write_counted(segment->obj, ...)` (was `segment->fd`); the trailing
  `do_sync` loop calls `segments[i].obj->driver->fsync(segments[i].obj)` instead of
  `fsync(segments[i].fd)`.
- `xrootd_vfs_io_execute_sync` (near 398): guard `job->obj == NULL`; body
  `obj->driver->fsync(job->obj)` instead of `fsync(job->fd)`.
- `xrootd_vfs_io_execute_truncate` (near 426): guard `job->obj == NULL`; body
  `obj->driver->ftruncate(job->obj, job->offset)` instead of `ftruncate(job->fd, ...)`.
- `xrootd_vfs_io_execute_opendir` (near 662): in 55.B keep the POSIX
  `dup(job->rootfd)` + `fdopendir` scan **verbatim** (byte-identical dirlist wire body).
  In 55.E, branch at the top: `if (job->dir_inst && !xrootd_sd_supports(job->dir_inst,
  XROOTD_SD_CAP_DIRS)) { build the listing via the driver's opendir/readdir
  (ListObjectsV2 prefix scan) into the same buffer; } else { existing fdopendir path; }`.
  The chunked-buffer wire-emit helpers (`_emit_entry`, `_need_new_chunk`, `_flush_chunk`)
  are backend-neutral and stay untouched.

`xrootd_vfs_io_execute` dispatcher (near 804) is unchanged — it still switches on
`job->op`; only the arm bodies changed.

---

### 17.5 `src/fs/vfs_open.c`

**Intent:** the open cascade calls `ctx->sd->driver->open()`; `adopt_fd` wraps the
returned fd in an `xrootd_sd_obj_t`; close and every accessor read through the SD; the
fd accessor returns `xrootd_sd_fd(fh->obj)`.

Add the include (near line 28):

```diff
 #include "vfs_internal.h"
 #include "../cache/open.h"
 #include "../path/beneath.h"
+#include "backend/sd.h"
```

`xrootd_vfs_adopt_fd` (near line 141) — build a POSIX SD object around the fd, store it
on the handle instead of the raw fd. The fstat snapshot stays (POSIX driver could also
fill it, but keeping the fstat here preserves byte-identical metadata):

```diff
     if (fstat(fd, &st) != 0) {
         return NGX_ERROR;
     }

     fh = ngx_pcalloc(ctx->pool, sizeof(*fh));
     if (fh == NULL) { errno = ENOMEM; return NGX_ERROR; }

     fh->path = xrootd_vfs_copy_path(ctx->pool, path);
     if (fh->path == NULL) { return NGX_ERROR; }

-    fh->fd = fd;
+    fh->obj = xrootd_sd_posix_wrap_fd(ctx->sd, ctx->pool, fd, &st, path);
+    if (fh->obj == NULL) {
+        /* errno set by the wrap (ENOMEM); caller closes fd on the error path */
+        return NGX_ERROR;
+    }
     fh->pool = ctx->pool;
     ... (size/mtime/ctime/ino/mode/from_cache/is_tls/stat_current unchanged) ...
```

`xrootd_sd_posix_wrap_fd(inst, pool, fd, &st, path)` is the POSIX driver's adopt entry
(in `sd_posix.c`): it pcalloc's an `xrootd_sd_obj_t` carrying `{driver=&posix, fd}` and
returns it. It does not re-fstat (the caller already did).

`xrootd_vfs_open` cascade (near line 327) — the three-way confinement cascade moves
**into** `ctx->sd->driver->open()`. For the POSIX driver, `open()` *is* this cascade
(`xrootd_open_beneath` → `xrootd_open_confined_canon` → raw `open`). The VFS body
collapses to one driver call that returns the obj:

```diff
-    oflags = xrootd_vfs_open_flags(flags);
-    /* Confinement cascade, strongest first: ... (the big comment) ... */
-    if (ctx->rootfd >= 0) {
-        fd = xrootd_open_beneath(ctx->rootfd, path, oflags, 0644);
-    } else if (ctx->root_canon != NULL) {
-        fd = xrootd_open_confined_canon(ctx->log, ctx->root_canon, path,
-                                        oflags, 0644);
-    } else {
-        fd = open(path, oflags, 0644);
-    }
-
-    if (fd == NGX_INVALID_FILE) {
-        if (err_out != NULL) { *err_out = errno; }
-        return NULL;
-    }
-
-    if (xrootd_vfs_adopt_fd(ctx, path, fd, 0, &fh) != NGX_OK) {
-        int err = errno;
-        ngx_close_file(fd);
-        if (err_out != NULL) { *err_out = err; }
-        errno = err;
-        return NULL;
-    }
-
-    return fh;
+    {
+        int              sd_flags = xrootd_vfs_open_sd_flags(flags);
+        xrootd_sd_obj_t *obj;
+        int              oerr = 0;
+
+        /* The driver owns physical confinement: the POSIX driver runs exactly
+         * today's strongest-first cascade (rootfd+openat2 RESOLVE_BENEATH →
+         * root_canon confined → raw open) inside its open() body, consuming
+         * ctx->sd's rootfd/root_canon.  Object drivers enforce key-prefix bounds. */
+        obj = ctx->sd->driver->open(ctx->sd, path, sd_flags, 0644, &oerr);
+        if (obj == NULL) {
+            if (err_out != NULL) { *err_out = oerr; }
+            errno = oerr;
+            return NULL;
+        }
+
+        if (xrootd_vfs_adopt_obj(ctx, path, obj, 0, &fh) != NGX_OK) {
+            int err = errno;
+            ctx->sd->driver->close(obj);
+            if (err_out != NULL) { *err_out = err; }
+            errno = err;
+            return NULL;
+        }
+        return fh;
+    }
```

Two consequences:
- `xrootd_vfs_open_flags()` (returns POSIX `O_*`, near line 191) is renamed/retargeted to
  `xrootd_vfs_open_sd_flags()` returning the driver-neutral `XROOTD_SD_O_*` bitmap (the
  POSIX driver translates back to `O_*`). The translation table is the same; it just
  moves under the seam. Keep `O_*` mapping inside `sd_posix.c`.
- `xrootd_vfs_adopt_obj(ctx, path, obj, from_cache, &fh)` replaces the fd-wrapping
  `xrootd_vfs_adopt_fd` on the open path: it fstats via `obj->driver->fstat` (POSIX =
  the open-time fstat already captured by the driver), dups path, sets cached metadata.
  `xrootd_vfs_adopt_fd` is retained as the POSIX-only cache-layer shim that builds the
  obj first then calls `_adopt_obj`.

`xrootd_vfs_close` (near line 356) — close through the driver:

```diff
 ngx_int_t
 xrootd_vfs_close(xrootd_vfs_file_t *fh, ngx_log_t *log)
 {
-    if (fh == NULL || fh->fd == NGX_INVALID_FILE) {
+    if (fh == NULL || fh->obj == NULL) {
         return NGX_OK;
     }

-    if (ngx_close_file(fh->fd) != NGX_OK) {
+    if (fh->obj->driver->close(fh->obj) != NGX_OK) {
         ngx_log_error(NGX_LOG_ERR, log != NULL ? log : fh->log, ngx_errno,
                       "xrootd_vfs: close failed for \"%s\"",
                       fh->path != NULL ? fh->path : "-");
-        fh->fd = NGX_INVALID_FILE;
+        fh->obj = NULL;
         return NGX_ERROR;
     }

-    fh->fd = NGX_INVALID_FILE;
+    fh->obj = NULL;
     return NGX_OK;
 }
```

`xrootd_vfs_file_fd` (near line 375) — forward through the SD (returns
`NGX_INVALID_FILE` for non-CAP_FD backends, automatically, because `xrootd_sd_fd` is
capability-gated):

```diff
 ngx_fd_t
 xrootd_vfs_file_fd(const xrootd_vfs_file_t *fh)
 {
-    return fh != NULL ? fh->fd : NGX_INVALID_FILE;
+    return fh != NULL ? xrootd_sd_fd(fh->obj) : NGX_INVALID_FILE;
 }
```

`xrootd_vfs_file_stat` (near line 405) — the `fh->fd == NGX_INVALID_FILE` guard and the
fallback live-fstat both change to the obj:

```diff
-    if (fh == NULL || fh->fd == NGX_INVALID_FILE || stat_out == NULL) {
+    if (fh == NULL || fh->obj == NULL || stat_out == NULL) {
         errno = EINVAL;
         return NGX_ERROR;
     }
     ... stat_current fast path UNCHANGED ...
-    if (fstat(fh->fd, &st) != 0) {
-        return NGX_ERROR;
-    }
-    xrootd_vfs_fill_stat(&st, stat_out);
+    {
+        xrootd_sd_stat_t sst;
+        if (fh->obj->driver->fstat(fh->obj, &sst) != NGX_OK) {
+            return NGX_ERROR;
+        }
+        xrootd_sd_stat_to_vfs(&sst, stat_out);   /* §3.3.1 helper */
+    }
     return NGX_OK;
```

---

### 17.6 `src/fs/vfs_read.c`

**Intent:** gate sendfile/file-backed buffers on `XROOTD_SD_CAP_SENDFILE` instead of
`is_tls || want_pgcrc` alone; route the memory-chain pread and the file-chain `dup`
through the SD object.

`xrootd_vfs_make_memory_chain` (near line 81) — pread through the driver:

```diff
-    if (xrootd_vfs_pread_full(fh->fd, data, length, offset, &nread)
-        != NGX_OK)
+    if (xrootd_sd_pread_full(fh->obj, data, length, offset, &nread)
+        != NGX_OK)
     {
         return NGX_ERROR;
     }
```

`xrootd_vfs_make_file_chain` (near line 128) — `dup` the SD fd. This path is reached
only when `CAP_SENDFILE` is present (predicate change below), so `xrootd_sd_fd(fh->obj)`
is guaranteed valid here:

```diff
-    fd = dup(fh->fd);
+    fd = dup(xrootd_sd_fd(fh->obj));
     if (fd == NGX_INVALID_FILE) {
         return NGX_ERROR;
     }
```

`xrootd_vfs_read` (near lines 205 and 234) — guard on the obj and flip the buffer-shape
predicate (§5.1):

```diff
-    if (fh == NULL || fh->fd == NGX_INVALID_FILE || offset < 0) {
+    if (fh == NULL || fh->obj == NULL || offset < 0) {
         errno = EINVAL;
         ...
     }
```

```diff
-    if (fh->is_tls || (fh->ctx != NULL && fh->ctx->want_pgcrc)) {
+    /* §5.1: memory-backed unless the backend can sendfile AND neither TLS nor
+     * want_pgcrc forces memory.  Object backends (no CAP_SENDFILE) → always
+     * memory, which is exactly the TLS code path. */
+    if (fh->is_tls
+        || (fh->ctx != NULL && fh->ctx->want_pgcrc)
+        || fh->ctx == NULL
+        || !xrootd_sd_supports(fh->ctx->sd, XROOTD_SD_CAP_SENDFILE))
+    {
         rc = xrootd_vfs_make_memory_chain(fh, offset, capped, out, result);
     } else {
         rc = xrootd_vfs_make_file_chain(fh, offset, capped, out);
     }
```

For POSIX, `xrootd_sd_supports(sd, CAP_SENDFILE)` is always true, so the cleartext path
still selects `make_file_chain` — byte-identical to today.

---

### 17.7 `src/fs/vfs_write.c`

**Intent:** writes go through `ctx->sd` (the obj's driver); the `stat_current` clear is
already correct and stays.

`xrootd_vfs_pwrite_full` (near line 31) stays as a POSIX-fd primitive (it is what
`sd_posix.c`'s `pwrite` calls). The per-buffer writers route through the obj instead.

`xrootd_vfs_write_file_buf` (near line 93) — the source read stays an fd pread on the
**input** buffer's own fd (`b->file->fd` is an nginx in_file buf, not the SD object), but
the **destination** pwrite goes through the SD obj:

```diff
-        if (xrootd_vfs_pwrite_full(fh->fd, tmp, chunk, *dst_off) != NGX_OK) {
+        if (xrootd_sd_pwrite_full(fh->obj, tmp, chunk, *dst_off) != NGX_OK) {
             return NGX_ERROR;
         }
```

`xrootd_vfs_write_memory_buf` (near line 127) — destination pwrite through the obj:

```diff
-    if (xrootd_vfs_pwrite_full(fh->fd, b->pos, len, *dst_off) != NGX_OK) {
+    if (xrootd_sd_pwrite_full(fh->obj, b->pos, len, *dst_off) != NGX_OK) {
         return NGX_ERROR;
     }
```

`xrootd_vfs_write` (near line 189) — obj guard; the `fh->stat_current = 0;` at line 236
is unchanged and remains correct (a write invalidates the cached metadata regardless of
backend):

```diff
-    if (fh == NULL || fh->fd == NGX_INVALID_FILE || offset < 0) {
+    if (fh == NULL || fh->obj == NULL || offset < 0) {
         errno = EINVAL;
         ...
     }
```

`xrootd_sd_pwrite_full(obj, buf, len, off)` is the `sd.h` helper that loops
`obj->driver->pwrite` exactly like today's `xrootd_vfs_pwrite_full` (0-byte → EIO). POSIX
inlines to the same code.

---

### 17.8 `src/fs/vfs_sync.c`

**Intent:** truncate/sync go through the obj; the I/O-core jobs are now obj-initialized.

`xrootd_vfs_truncate` (near line 24):

```diff
-    if (fh == NULL || fh->fd == NGX_INVALID_FILE || length < 0) {
+    if (fh == NULL || fh->obj == NULL || length < 0) {
         errno = EINVAL;
         return NGX_ERROR;
     }

-    xrootd_vfs_job_truncate_init(&job, fh->fd, length);
+    xrootd_vfs_job_truncate_init(&job, fh->obj, length);
```

(`CAP_TRUNCATE` is enforced one level up for non-POSIX backends — §3.1; POSIX always
supports it so behaviour is unchanged.)

`xrootd_vfs_sync` (near line 47):

```diff
-    if (fh == NULL || fh->fd == NGX_INVALID_FILE) {
+    if (fh == NULL || fh->obj == NULL) {
         errno = EINVAL;
         return NGX_ERROR;
     }

-    xrootd_vfs_job_sync_init(&job, fh->fd);
+    xrootd_vfs_job_sync_init(&job, fh->obj);
```

---

### 17.9 `src/fs/vfs_dir.c`

**Intent:** delegate opendir/readdir to the SD; for `!CAP_DIRS` backends offload to the
AIO tier (§5.5). For POSIX (CAP_DIRS) the existing inline `opendir`/`readdir` stay.

`xrootd_vfs_opendir` (near line 79) — the `xrootd_opendir_confined_canon` call becomes a
driver call, with an AIO-offload branch for non-dir backends:

```diff
-    dh->dir = xrootd_opendir_confined_canon(ctx->log, ctx->root_canon, path);
-    if (dh->dir == NULL) { ... observe error ... return NULL; }
+    if (xrootd_sd_supports(ctx->sd, XROOTD_SD_CAP_DIRS)) {
+        /* POSIX fast path: inline opendir on the event loop (fast syscall). */
+        dh->dir = xrootd_opendir_confined_canon(ctx->log, ctx->root_canon, path);
+        if (dh->dir == NULL) { ... observe error ... return NULL; }
+    } else {
+        /* Object/prefix backend: opendir is a blocking network LIST → must run
+         * off the event loop.  Open the driver dir handle via the AIO tier
+         * (xrootd_aio_post_task); store it on dh->sd_dir.  §5.5. */
+        dh->sd_dir = ctx->sd->driver->opendir(ctx->sd, path, &saved_errno);
+        if (dh->sd_dir == NULL) { ... observe error ... return NULL; }
+    }
```

(Add `xrootd_sd_dir_t *sd_dir;` to `struct xrootd_vfs_dir_s` in §17.1 alongside the
existing `DIR *dir;`.)

`xrootd_vfs_readdir` (near line 113) — when the handle is driver-backed, pull entries
from `dh->sd_dir` via `ctx->sd->driver->readdir` and map `xrootd_sd_dirent_t` →
`name_out`/`stat_out` through `xrootd_sd_stat_to_vfs`; otherwise the existing POSIX
`readdir`/`fstatat` path runs verbatim. The "."/".." filter and `NGX_DONE` contract are
identical in both arms.

`xrootd_vfs_closedir` (near line 166) — branch: `closedir(dh->dir)` for POSIX, else
`ctx->sd->driver->closedir(dh->sd_dir)`.

---

### 17.10 `src/fs/vfs_stat.c`

**Intent:** delegate the path-stat to the SD; AIO-offload for object backends.

`xrootd_vfs_stat` (near line 50) — replace the direct `xrootd_lstat_confined_canon`:

```diff
-    if (xrootd_lstat_confined_canon(ctx->log, ctx->root_canon, path, &st, 1) != 0) {
-        saved_errno = errno;
-        ... observe error ...
-        return NGX_ERROR;
-    }
-    xrootd_vfs_fill_stat(&st, stat_out);
+    {
+        xrootd_sd_stat_t sst;
+        ngx_int_t        src;
+
+        /* POSIX runs the confined lstat inline (fast); object backends offload
+         * the HEAD/LIST to the AIO tier inside the driver's stat() (§5.5). */
+        src = ctx->sd->driver->stat(ctx->sd, path, &sst);
+        if (src != NGX_OK) {
+            saved_errno = errno;
+            ... observe error ...
+            return NGX_ERROR;
+        }
+        xrootd_sd_stat_to_vfs(&sst, stat_out);
+    }
```

The POSIX driver's `stat()` body is exactly today's `xrootd_lstat_confined_canon(...,
nofollow=1)` (preserving the impersonation broker routing documented in the existing
comment, which moves into `sd_posix.c`'s `stat`).

---

### 17.11 `src/fs/vfs_sync.c` durability note / `src/fs/vfs_copy.c`

**Intent (`vfs_copy.c`):** delegate the copy to `ctx->sd->driver->server_copy`; when
`!CAP_SERVER_COPY` fall back to the VFS stream-through loop (§5.4).

`xrootd_vfs_copy` (near line 64) — replace the direct `xrootd_ns_local_copy`:

```diff
-    res = xrootd_ns_local_copy(ctx->log, ctx->root_canon, src, dst_resolved,
-                               &ns_opts);
-    if (res.status != XROOTD_NS_OK) {
-        errno = res.sys_errno != 0 ? res.sys_errno
-                                   : xrootd_vfs_ns_status_errno(res.status);
-        ...
-    }
+    if (xrootd_sd_supports(ctx->sd, XROOTD_SD_CAP_SERVER_COPY)) {
+        off_t copied = 0;
+        if (ctx->sd->driver->server_copy(ctx->sd, src, dst_resolved, &copied)
+            != NGX_OK)
+        {
+            saved_errno = errno;
+            ... observe OP_COPY error ...
+            return NGX_ERROR;
+        }
+    } else {
+        /* §5.4: no native copy → VFS-owned pread→pwrite stream-through (the
+         * existing xrootd_copy_range loop), honoring ns_opts overwrite policy. */
+        if (xrootd_vfs_copy_streamthrough(ctx, src, dst_resolved, &ns_opts)
+            != NGX_OK)
+        {
+            saved_errno = errno;
+            ... observe OP_COPY error ...
+            return NGX_ERROR;
+        }
+    }
```

The POSIX driver's `server_copy` is today's `xrootd_ns_local_copy` (copy_file_range with
its own read/write fallback), so the `ns_opts` translation block (near line 55) is
**retained** and passed into the POSIX driver instance config / streamthrough; for POSIX
the result is byte-identical. The post-copy best-effort `lstat` for the metric byte count
stays, but now reads `ctx->sd->driver->stat(ctx->sd, dst_resolved, &sst)`.

---

### 17.12 `src/fs/vfs_staged.c`

**Intent:** re-express commit as the §3.6.1 decision over `(sd_staging, sd)` — native
rename when `sd_staging == sd`, else promote (read staging object → backend `staged_*`
multipart, then unlink staging temp). In 55.C both are POSIX-same, so only the native
rename path is exercised; the promote arm lands inert until 55.E.

`xrootd_vfs_staged_open` (near line 33) — record both instances on the handle (the temp
is created on the **staging** store):

```diff
     st->ctx  = ctx;
+    st->backend = ctx->sd;
+    st->staging = ctx->sd_staging;   /* == ctx->sd for the default config */
     st->pool = ctx->pool;
     st->log  = ctx->log;
     st->staged.fd = NGX_INVALID_FILE;

-    if (xrootd_staged_open(ctx->log, ctx->root_canon, final_path, O_WRONLY,
-                           mode, attempts, &st->staged) != NGX_OK)
+    /* Temp is created on the STAGING store's root (its own confinement). For the
+     * default same-instance config this is exactly today's in-root O_EXCL temp. */
+    if (st->staging->driver->staged_open == NULL
+        ? /* POSIX staging: today's compat temp */
+          xrootd_staged_open(ctx->log, ctx->root_canon, final_path, O_WRONLY,
+                             mode, attempts, &st->staged) != NGX_OK
+        : /* (object staging is a 55.E concern; not reached in 55.C) */ NGX_ERROR)
     {
         ...
     }
```

(For 55.C the POSIX branch is the only one compiled-live; the conditional is written so
55.E can slot the object-staging path without re-touching this function. If preferred,
keep the plain `xrootd_staged_open` call in 55.C and introduce the branch in 55.E.)

`xrootd_vfs_staged_commit` (near line 101) — the core change. Decide on
`staging == backend` and `CAP_HARD_RENAME`:

```diff
 ngx_int_t
 xrootd_vfs_staged_commit(xrootd_vfs_staged_t *st, unsigned excl)
 {
     const char *final_path;
     ngx_msec_t  start = ngx_current_msec;
     size_t      bytes = 0;
     struct stat sb;
     ngx_int_t   rc;
     int         saved_errno;

     if (st == NULL) { errno = EINVAL; return NGX_ERROR; }
     final_path = xrootd_vfs_ctx_path(st->ctx);

-    rc = excl
-         ? xrootd_staged_commit_excl(st->log, st->ctx->root_canon, &st->staged,
-                                     final_path)
-         : xrootd_staged_commit(st->log, st->ctx->root_canon, &st->staged,
-                                final_path);
+    if (st->staging == st->backend
+        && xrootd_sd_supports(st->backend, XROOTD_SD_CAP_HARD_RENAME))
+    {
+        /* §3.6.1 row 1: staging IS backend, atomic kernel rename.  The common
+         * POSIX deployment — zero extra copy, byte-identical to today. */
+        rc = excl
+             ? xrootd_staged_commit_excl(st->log, st->ctx->root_canon,
+                                         &st->staged, final_path)
+             : xrootd_staged_commit(st->log, st->ctx->root_canon,
+                                    &st->staged, final_path);
+    } else {
+        /* §3.6.1 rows 2-4: cross-store promote.  Read the staging temp and drive
+         * the BACKEND driver's staged_* lifecycle (object multipart), then unlink
+         * the staging temp.  Records xrootd_sd_degraded_total{op=commit,
+         * reason=promote} + backend bytes.  Lands live in 55.E; in 55.C this arm
+         * is unreachable because staging==backend for every config. */
+        rc = xrootd_vfs_staged_promote(st, final_path, excl);
+    }
     if (rc != NGX_OK) {
         saved_errno = errno;
         xrootd_vfs_observe_ctx_op(st->ctx, final_path, XROOTD_METRIC_OP_WRITE,
                                   NULL, 0, NGX_ERROR, saved_errno, start);
         return NGX_ERROR;
     }
     ... byte count via post-commit lstat + OP_WRITE observe (UNCHANGED) ...
 }
```

`xrootd_vfs_staged_abort` (near line 145) is unchanged for POSIX; in 55.E it also calls
`st->backend->driver->staged_abort` when a promote multipart is in flight.

`xrootd_vfs_staged_promote(st, final_path, excl)` is a new static helper (added in 55.E)
implementing the §3.6.2 composed lifecycle. Its declaration can be added in 55.C as a
stub returning `NGX_ERROR`/`ENOTSUP` so the branch compiles.

---

### 17.13 `src/fs/vfs_xattr.c`

**Intent:** delegate the four xattr ops to the SD (`CAP_XATTR`); reject with `ENOTSUP`
when absent. The guard/observe scaffolding is untouched.

Each of the four functions replaces its `xrootd_*xattr_confined_canon(...)` call with the
driver entry, behind a capability check. Pattern, shown for `xrootd_vfs_getxattr`
(near line 58):

```diff
     if (xrootd_vfs_require_confined(ctx) != NGX_OK) {
         return xrootd_vfs_xattr_observe_count(ctx, path, -1, start);
     }

-    n = xrootd_getxattr_confined_canon(ctx->log, ctx->root_canon, path, name,
-                                       buf, bufsz);
+    if (!xrootd_sd_supports(ctx->sd, XROOTD_SD_CAP_XATTR)) {
+        errno = ENOTSUP;
+        return xrootd_vfs_xattr_observe_count(ctx, path, -1, start);
+    }
+    n = ctx->sd->driver->getxattr(ctx->sd, path, name, buf, bufsz);
     return xrootd_vfs_xattr_observe_count(ctx, path, n, start);
```

Apply the analogous swap to `listxattr` (→ `driver->listxattr`), `setxattr` (→
`driver->setxattr`, near line 102), and `removexattr` (→ `driver->removexattr`, near
line 130). The POSIX driver bodies are the existing `*xattr_confined_canon` helpers
(with their impersonation routing), so POSIX behaviour — including the "not
allow_write-gated" semantics — is byte-identical.

---

### 17.14 `src/protocols/webdav/get.c`

**Intent:** replace `xrootd_vfs_file_fd()` + manual `dup`/sendfile-buf construction with
the capability-correct `xrootd_vfs_read()` chain (§6.1). The handle already exposes size
via `xrootd_vfs_file_stat`; the GET path must stop reaching for a raw fd.

The multi-range branch (near line 167) builds `send_fd = dup(fd)` and calls
`xrdhttp_handle_multipart_get(r, send_fd, &sb, 1)`. Replace the fd acquisition with a
VFS-served chain. Concretely:

```c
"Replace
     fd = xrootd_vfs_file_fd(fh);
     ...
     send_fd = dup(fd);
     ... webdav_register_send_fd_cleanup ...
     rc = xrdhttp_handle_multipart_get(r, send_fd, &sb, 1);
 with a capability-correct serve: keep using xrootd_http_serve_file_ranged() (already
 called on the single-range path at line 223) for ALL ranges, letting the VFS pick
 memory vs file-backed bufs.  The multipart byterange assembly must take the
 xrootd_vfs_file_t* (or an xrootd_vfs_read()-produced ngx_chain_t per sub-range) instead
 of a bare fd, so that an object backend (no CAP_FD) serves memory chains.  Drop the
 fd/dup/send_fd locals and webdav_register_send_fd_cleanup on this path."
```

The single-range path already goes through `xrootd_http_serve_file_ranged(r, fh, &vst,
...)` (line 223) which owns the buffer-shape decision in §17.6 — so once the multirange
path is converted to read via `fh`, **no** `xrootd_vfs_file_fd()` call remains in
`get.c`. The `from_cache`/`cache_path` accessors (lines 168-169) stay; only the `fd`
local and its `dup` usage are removed.

For POSIX this is behaviour-preserving: `xrootd_vfs_read`/`serve_file_ranged` still emit
file-backed (sendfile) buffers because `CAP_SENDFILE` is set.

---

### 17.15 `src/protocols/s3/object.c`

**Intent:** the only `xrootd_vfs_file_fd()` use (near line 148) feeds
`s3_echo_object_checksums(r, cfd, fs_path)`, which recomputes/echoes a stored checksum
from the fd. Replace with a fd-free path.

```diff
-    {
-        ngx_fd_t cfd = xrootd_vfs_file_fd(fh);
-
-        if (cfd != NGX_INVALID_FILE) {
-            s3_echo_object_checksums(r, cfd, fs_path);
-        }
-    }
+    /* §6.1: no raw fd above the seam.  Echo the *stored* full-object checksum via
+     * the VFS xattr/metadata surface (the value was written at upload time), so an
+     * object backend echoes it from object tags/sidecar with no fd and no recompute. */
+    s3_echo_object_checksums_vfs(r, &vctx, fs_path);
```

`s3_echo_object_checksums_vfs(r, &vctx, fs_path)` reads the cached checksum through
`xrootd_vfs_getxattr(&vctx, "user.xrootd.cksum.crc64nvme", ...)` (the same sidecar the
upload path writes), matching the existing "cache-only, never recompute on read"
contract noted in the surrounding comment. For POSIX this reads the identical xattr the
old fd-based helper read, so the echoed header is byte-identical. The subsequent
`xrootd_http_serve_file_ranged(r, fh, &vst, ...)` (line 168) is unchanged and owns the
buffer shape.

---

### 17.16 `src/protocols/shared/file_serve.c`

**Intent:** the three `xrootd_vfs_file_fd()` sites (compressed-send dup at line 127, the
`pre_header_send` callback at line 170, and the final range-send dup at line 181) must
become capability-correct. `xrootd_http_serve_file_ranged` already takes the
`xrootd_vfs_file_t *fh`, so the data plane can serve from the handle.

Final range-send (near line 181) — the dominant path. Today:

```c
fd      = xrootd_vfs_file_fd(fh);
...
send_fd = dup(fd);
... xrootd_vfs_close(fh, ...) ...
rc = xrootd_http_send_file_range(r, send_fd, fs_path, range_start, send_len, 1);
```

Replace with a capability switch: when `xrootd_sd_supports(vctx->sd, CAP_SENDFILE)`
keep the `dup(xrootd_sd_fd(fh->obj))` + `send_file_range` path (POSIX, byte-identical);
otherwise serve the range via `xrootd_vfs_read(fh, range_start, send_len, &chain, NULL)`
and `ngx_http_output_filter(r, chain)` (memory chain). Sketch:

```c
"if (xrootd_sd_supports(<ctx>->sd, XROOTD_SD_CAP_SENDFILE)) {
     send_fd = dup(xrootd_vfs_file_fd(fh));   // == xrootd_sd_fd(fh->obj)
     ... existing dup/cleanup/close/send_file_range ... (UNCHANGED)
 } else {
     ngx_chain_t *chain = NULL;
     rc = xrootd_vfs_read(fh, range_start, send_len, &chain, NULL);
     xrootd_vfs_close(fh, r->connection->log);
     if (rc == NGX_OK && chain) { rc = ngx_http_output_filter(r, chain); }
 }"
```

Compressed-send branch (near line 124-130) — `csend = dup(cfd)` feeds
`xrootd_http_send_file_compressed`. Same treatment: keep the dup path under
`CAP_SENDFILE`; for non-fd backends the compressor consumes an `xrootd_vfs_read()`
chain. (`xrootd_http_compress_negotiate` is unaffected.)

`pre_header_send` callback (near line 170) — it currently passes
`xrootd_vfs_file_fd(fh)` to the protocol's header hook (S3/WebDAV). Change the callback
signature to receive the `xrootd_vfs_file_t *fh` (or drop the fd argument where the hook
only needs `vst->size`/`mtime`). Both current hooks
(`webdav_get_add_xrdhttp_headers`, `s3_get_pre_header`) read metadata, not bytes, so
this is a clean signature narrowing.

The `xrootd_vfs_file_from_cache`/`xrootd_vfs_file_path` accessors here stay. For POSIX
every path keeps using sendfile; the only new code is the `else` arm, dead for POSIX.

`src/fs/README.md` (line 21) and `src/protocols/shared/README.md` (line 66) prose that names
`xrootd_vfs_file_fd()` as the raw-fd accessor should be updated to state that raw fds are
no longer exposed above the seam (capability-gated `xrootd_sd_fd` is private to the VFS).

---

### 17.17 `config` (top-level addon build script)

**Intent:** register the new `src/fs/backend/` sources and the `sd.h` header so
`./configure` compiles them. **A `./configure` re-run is required** (new source files,
per BUILD GOVERNANCE) — incremental `make` alone will not pick them up.

Add `sd.h` to the **stream** deps list (after line 290,
`$ngx_addon_dir/src/fs/vfs_internal.h \`):

```diff
                         $ngx_addon_dir/src/fs/vfs.h \
                         $ngx_addon_dir/src/fs/vfs_internal.h \
+                        $ngx_addon_dir/src/fs/backend/sd.h \
                         $ngx_addon_dir/src/frm/frm.h \
```

Add `sd.h` to the **webdav** deps list (after line 391,
`$ngx_addon_dir/src/fs/vfs.h \`):

```diff
                         $ngx_addon_dir/src/fs/vfs.h \
+                        $ngx_addon_dir/src/fs/backend/sd.h \
                         $ngx_addon_dir/src/fs/cache/open.h \
```

Add the new `.c` files to `NGX_ADDON_SRCS` (after line 510,
`$ngx_addon_dir/src/fs/vfs_staged.c \`, before `fd_cache.c`):

```diff
     $ngx_addon_dir/src/fs/vfs_copy.c \
     $ngx_addon_dir/src/fs/vfs_staged.c \
+    $ngx_addon_dir/src/fs/backend/sd_registry.c \
+    $ngx_addon_dir/src/fs/backend/sd_posix.c \
+    $ngx_addon_dir/src/fs/backend/sd_object.c \
+    $ngx_addon_dir/src/fs/backend/sd_object_s3.c \
+    $ngx_addon_dir/src/fs/backend/sd_block.c \
     $ngx_addon_dir/src/fs/fd_cache.c \
```

(`sd.h` is header-only and goes in the deps lists above, not `NGX_ADDON_SRCS`. Phase
ordering: 55.A adds `sd.h`+`sd_registry.c`+`sd_posix.c`; `sd_block.c`/`sd_object*.c`
land in 55.D/55.E but registering all five up front is harmless — each compiles to a
self-contained TU and is inert until its driver is selected. If you prefer minimal 55.A
churn, add only `sd_registry.c`+`sd_posix.c` now and the other three in their phase.)

There is a third deps occurrence at line 956 (`$ngx_addon_dir/src/fs/vfs.h`); if that
block compiles a unit that includes `vfs.h` (now pulling `backend/sd.h`), add the
`sd.h` line there too for dependency-tracking correctness.

---

### 17.18 `src/core/types/config.h` (srv-conf struct)

**Intent:** add the paired store-config objects and the built instance pointers to
`ngx_stream_xrootd_srv_conf_t` (§6.6). The struct lives in `src/core/types/config.h`, not
`src/core/config/config.h`; it ends at line 740 (`} ngx_stream_xrootd_srv_conf_t;`).

Add near the cache block (e.g. after the `cache_slice_size` region, near line 418),
before the struct close:

```c
    /* ---- Phase 55: pluggable storage backend (store binding) ---- */
    typedef_marker_for_review_only_below;   /* (remove; see real types below) */

    /* parsed config for the durable store and the staging store (§6.6) */
    ngx_str_t   backend_store;      /* [xrootd_storage_backend posix|block|s3] raw name */
    ngx_str_t   staging_store;      /* [xrootd_storage_staging posix|s3|same]  raw name; "same" default */
    void       *backend_store_conf; /* parsed backend-specific config (driver-owned)    */
    void       *staging_store_conf; /* parsed staging-specific config; NULL for "same"  */

    /* built at postconfig/worker init by sd_registry.c (§6.4) */
    xrootd_sd_instance_t *backend_instance;   /* durable store instance               */
    xrootd_sd_instance_t *staging_instance;   /* == backend_instance when staging=same */
```

(Drop the `typedef_marker_...` placeholder line — it is only here to flag that if you
adopt the richer `xrootd_storage_store_conf_t` from §6.6 instead of two bare `ngx_str_t`,
declare that struct in `backend/sd.h` and use it for `backend_store`/`staging_store`.
The minimal `ngx_str_t name + void *conf` shape above is sufficient for 55.A.)

`src/core/types/config.h` must `#include "../fs/backend/sd.h"` (or forward-declare
`struct xrootd_sd_instance_s;`) so the pointer fields type-check. A forward declaration
is the lighter touch:

```c
struct xrootd_sd_instance_s;
typedef struct xrootd_sd_instance_s xrootd_sd_instance_t;   /* near the top includes */
```

---

### 17.19 `src/protocols/root/stream/module_cache_proxy_directives.c` (or a new
`module_storage_directives.c`) + `src/core/config/server_conf.c` (merge)

**Intent:** add the `xrootd_storage_backend` and `xrootd_storage_staging`
`ngx_command_t` entries (mirroring the existing `xrootd_cache_root` string directive at
lines 33-38), and the merge logic in `server_conf.c` (mirroring the `cache_root` merge
at line 366), with defaults `posix` / `same`.

Directive entries — add two commands alongside the cache ones (near line 38):

```diff
     { ngx_string("xrootd_cache_root"),
       NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_STREAM_SRV_CONF_OFFSET,
       offsetof(ngx_stream_xrootd_srv_conf_t, cache_root),
       NULL },
+
+    /* Phase 55 §6.4: storage backend (durable store).  Default posix.
+     * In 55.A only "posix" is accepted by the registry; unknown name → nginx -t
+     * fails with a clear message. */
+    { ngx_string("xrootd_storage_backend"),
+      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
+      ngx_conf_set_str_slot,
+      NGX_STREAM_SRV_CONF_OFFSET,
+      offsetof(ngx_stream_xrootd_srv_conf_t, backend_store),
+      NULL },
+
+    /* Phase 55 §6.4: staging store.  Default "same" (alias for the backend
+     * instance → today's in-root temp+rename). */
+    { ngx_string("xrootd_storage_staging"),
+      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
+      ngx_conf_set_str_slot,
+      NGX_STREAM_SRV_CONF_OFFSET,
+      offsetof(ngx_stream_xrootd_srv_conf_t, staging_store),
+      NULL },
```

(`NGX_CONF_TAKE1` matches the §6.5 v1 shape where the backend *type* is one token;
backend-specific args like `xrootd_storage_s3_endpoint` are separate directives added in
55.E. If you want the `[args…]` form now, use `NGX_CONF_1MORE` and a custom set handler
that stashes the trailing args into `backend_store_conf`.)

Merge logic — in `src/core/config/server_conf.c`, alongside the `cache_root` merge (line 366):

```diff
     ngx_conf_merge_str_value(conf->cache_root,  prev->cache_root,      "");
+    /* Phase 55: storage store binding.  Defaults reproduce today's behaviour:
+     * posix backend + staging "same" (== backend instance) → in-root O_EXCL temp
+     * + atomic renameat2, byte-identical to the pre-phase tree. */
+    ngx_conf_merge_str_value(conf->backend_store, prev->backend_store, "posix");
+    ngx_conf_merge_str_value(conf->staging_store, prev->staging_store, "same");
```

Then (in `server_conf.c` merge tail, or in `postconfiguration.c`/worker-init where the
rootfd is prepared) the registry build:

```c
"After the string merges, resolve the names to instances via sd_registry.c:
   conf->backend_instance = xrootd_sd_registry_resolve(cf, &conf->backend_store,
                                                        conf /* for root_canon/rootfd */);
   if (conf->backend_instance == NULL) return 'unknown storage backend \"...\"';
   if (ngx_strcmp(conf->staging_store.data, 'same') == 0) {
       conf->staging_instance = conf->backend_instance;   // pointer identity → §3.6.1 fast path
   } else {
       conf->staging_instance = xrootd_sd_registry_resolve(cf, &conf->staging_store, conf);
       if (conf->staging_instance == NULL) return 'unknown staging store \"...\"';
       // §6.5: validate staging advertises RANDOM_WRITE|TRUNCATE for in-flight writes,
       // else fail nginx -t naming the missing capability.
   }"
```

Finally, the ctx-population sites that build an `xrootd_vfs_ctx_t` (the
`xrootd_vfs_ctx_init` helper in `vfs_open.c` and each protocol handler that fills a ctx)
must copy `conf->backend_instance` → `ctx->sd` and `conf->staging_instance` →
`ctx->sd_staging`. For the stream plane this is wherever `ctx->rootfd`/`ctx->root_canon`
are set; for HTTP it is `xrootd_vfs_ctx_init` plus the WebDAV/S3 ctx builders. Add the
two assignments next to the existing `vctx->rootfd = -1;` / `root_canon` lines so every
ctx carries its store binding. (In 55.A, with both resolving to the POSIX instance, the
fast-path identity `ctx->sd == ctx->sd_staging` holds and nothing changes on the wire.)


## 18. Sequence diagrams & state machines

These diagrams ground §3–§6 in the **real** Phase-54 lifecycle: every disk op is
`PREPARE` (event loop) → `EXECUTE` (`xrootd_vfs_io_execute()`, AIO worker thread) →
`COMPLETE` (`*_aio_done`, event loop), around a POD `xrootd_vfs_job_t`. Phase 55
generalizes the job from fd-centric to object-centric: `job->fd` /`job->rootfd`
become `job->obj` (`xrootd_sd_obj_t *`) and the executor dispatches the raw op
through `obj->driver->pread/pwrite/...` (§3.4) instead of bare `pread(2)`.

Thread legend used throughout:

```text
  [EL]  = nginx event-loop thread (single-threaded; pools, metrics, access log,
          cache, response framing, ngx_post_event all live here)
  [WK]  = AIO thread-pool worker (xrootd_*_aio_thread → xrootd_vfs_io_execute);
          POD job + caller buffers ONLY — no pool, no metric, no log, no cache
  [EL/IO] = inline fallback: the EXECUTE body runs on [EL] when no pool / queue full
            (still touches only the POD job — same worker-safe body)
```

The SD seam never moves the PREPARE/COMPLETE work off `[EL]`; it only changes
*what raw primitive* `[WK]` calls. Object backends differ from POSIX in exactly
two structural ways: (1) **more** ops must be `[WK]`-offloaded (namespace ops that
are inline POSIX syscalls today — `vfs_stat`, `vfs_dir` open, `vfs_mkdir`,
`vfs_rename`, `vfs_unlink` — gain an "offload when object" branch via
`xrootd_aio_post_task`, §5.5); (2) the EXECUTE body is a blocking network call,
not a syscall.

---

### 18.1 open — cache-first → SD open cascade → adopt object handle

`xrootd_vfs_open()` stays on `[EL]` for POSIX (open is a fast `openat2`); for an
object backend the HEAD/GET-stat is a network call and is `[WK]`-offloaded (§5.5).
The cache gets first refusal exactly as today (`vfs_open.c` step 1).

```text
 PROTOCOL HANDLER                VFS (src/fs/)                     SD INSTANCE (ctx->sd)
 (root/webdav/s3/cms)            [EL]                              driver = ctx->sd->driver
       │                          │                                       │
       │ build xrootd_vfs_ctx_t   │                                       │
       │ {resolved (confined),    │                                       │
       │  rootfd, root_canon,     │                                       │
       │  allow_write, is_tls,    │                                       │
       │  want_pgcrc, sd, sd_stg} │                                       │
       ├─────────────────────────►│ xrootd_vfs_open(ctx, flags)           │
       │                          │                                       │
       │              [EL] require_confined(resolved)  ── empty/!is_confined ──► EINVAL
       │              [EL] write open? require_write(allow_write) ───────────► EACCES
       │                          │                                       │
       │              [EL] xrootd_cache_open()  ── HIT ──► ready handle, cache-hit metric, RETURN
       │                          │  (MISS → record miss, fall through)   │
       │                          │                                       │
       │            ┌─────────────┴──── SD OPEN CASCADE (driver->open) ───┐
       │            │                                                     │
       │   POSIX driver (sd_posix):                  OBJECT driver (sd_object):
       │   [EL] caps & CAP_FD                          [WK] offload (network HEAD/stat)
       │   rootfd>=0 → xrootd_open_beneath()           [WK] map logical→key (prefix+path)
       │     (openat2 RESOLVE_BENEATH)                 [WK] reject ".."/escape after normalize
       │   else root_canon →                          [WK] HEAD key:
       │     xrootd_open_confined_canon()                   200→size/etag/mtime snapshot
       │   else raw open() (server abs path only)           404→ENOENT (kXR_NotFound/404)
       │   → obj wraps {fd}                                 403→EACCES (kXR_NotAuthorized/403)
       │   caps = ALL                                  → obj wraps {key,etag,size,
       │                                                   staging_fd=-1,upload_id=NULL}
       │                                                 caps = RANGE_READ|SERVER_COPY|XATTR
       │            │                                                     │
       │            └────────────► xrootd_sd_obj_t *obj (or NULL,*err_out)─┘
       │                          │                                       │
       │              [EL] adopt: fh->obj = obj;                          │
       │                   fstat snapshot via obj->driver->fstat →        │
       │                     xrootd_sd_stat_to_vfs() → fh->{size,mtime,    │
       │                     ctime,ino,mode}; stat_current=1 (phase-45)   │
       │              [EL] register pool cleanup → xrootd_vfs_close(fh)    │
       │              [EL] observe_ctx_op(OP_OPEN, latency, err_class)     │
       │◄─────────────────────────┤ return xrootd_vfs_file_t *fh          │
       │                          │                                       │
```

Key invariants visible here:
- The handle stores **`obj`, not `fd`** (§6.2). `xrootd_vfs_file_fd()` is retired
  (§6.1); any fd is reached only via the cap-gated `xrootd_sd_fd(obj)` which
  returns `NGX_INVALID_FILE` when `!CAP_FD`.
- For POSIX, the whole cascade is the unchanged `vfs_open.c` body, now behind
  `driver->open`. For object, the cascade body runs on `[WK]` because it blocks.
- Cache decision, confinement re-check, write-gate, metrics, and adopt-fstat all
  stay on `[EL]` — backend-agnostic.

---

### 18.2 read — PREPARE (cap-check + pool-alloc) → EXECUTE (`obj->driver->pread`) → COMPLETE (chain by CAP_SENDFILE)

This is the hot path. The CAP_SENDFILE / TLS branch is the §5.1 resolution: the
buffer-shape decision becomes `is_tls || want_pgcrc || !CAP_SENDFILE → memory`.

```text
 kXR_read / WebDAV GET / S3 GET                                     job: xrootd_vfs_job_t
 ──────────────────────────────────────────────────────────────────────────────────────
 PREPARE  [EL]  xrootd_vfs_read(ctx, fh, off, len)
   │  require_confined already held at open; cap length to (fh->size - off), set eof
   │  ── CAP_RANGE_READ check ── !RANGE_READ → ENOTSUP (kXR_Unsupported/501) + unsupp metric
   │  decide read buffer:
   │     memory path  ⟸  is_tls || want_pgcrc || !CAP_SENDFILE
   │     sendfile path ⟸  cleartext && CAP_SENDFILE
   │  ngx_pnalloc(pool, len)  (memory path) OR reserve scratch (aio reads)   ← POOL on [EL] only
   │  fill job: { op=READ, obj=fh->obj, offset, length, buf, buf_cap,
   │              want_pgcrc, streamid[2] copy }
   │  xrootd_task_bind(task,_thread,_done); xrootd_aio_post_task(...)
   │      └─ pool present → XRD_ST_AIO, events disarmed     │  no pool/full → [EL/IO] inline
   ▼                                                        ▼
 EXECUTE  [WK]  xrootd_*_aio_thread → xrootd_vfs_io_execute(job)
   │  switch(job->op) → xrootd_vfs_io_execute_read(job):
   │     validate (obj!=NULL, off>=0, buf_cap>=length)
   │     nio = obj->driver->pread(obj, buf, length, offset)   ← the ONLY storage primitive
   │        POSIX : xrootd_vfs_pread_full() (EINTR/short-read safe)  → same syscalls as today
   │        OBJECT: range GET key bytes=[off, off+len)  (blocking network call, correct on [WK])
   │     on success: job->nio = nread; job->out_size = nread;
   │                 if want_pgcrc: job->crc32c = xrootd_crc32c_value(buf,nread)
   │     on error:   job->nio = -1; job->io_errno = errno/ESTALE/ETIMEDOUT
   │  (touches ONLY job + buf — no pool/metric/log/cache)
   │  ngx_post_event(_done)  → back to [EL]
   ▼
 COMPLETE [EL]  xrootd_*_aio_done(ev)
   │  xrootd_aio_restore_request(); if ctx->destroyed → free detached buf, RETURN (UAF guard)
   │  job->nio < 0 → xrootd_send_error(map(io_errno)→kXR_*/HTTP); observe_op(error); resume
   │  success → build response chain by buffer shape decided in PREPARE:
   │     memory   : ngx_buf b->memory=1 (b->pos=buf, b->last=buf+nread)         [TLS & object]
   │     sendfile : b->in_file=1 from dup(xrootd_sd_fd(obj)) + ngx_pool_cleanup_file [POSIX cleartext]
   │  pgread special framing: ServerStatusResponse_pgRead hdr + [CRC32C(4)][page]×N (never chunked)
   │  update fh.bytes_read / session_bytes; cache record-access; access-log emit;
   │  observe_op(OP_READ, nread, latency, ok)
   │  xrootd_aio_resume() → arm write (XRD_ST_SENDING) else read event
```

Where the branches live, explicitly:
- **TLS vs cleartext** — decided on `[EL]` in PREPARE *and* re-honored in COMPLETE
  when picking memory vs sendfile builder. The two never mix (INVARIANT #2).
- **CAP_SENDFILE absent** — collapses cleartext into the memory builder; access
  log + metrics unchanged; emit `xrootd_sd_degraded_total{op=read,reason=sendfile}`
  once at open/first-read, not per-buffer.
- **Object** always lands on the memory builder (it has no `CAP_FD`, so
  `xrootd_sd_fd(obj)==NGX_INVALID_FILE` and the sendfile path is structurally
  unreachable — a correctness property, not a runtime check).

---

### 18.3 write (sequential) — POSIX pwrite vs object staged buffering

For POSIX with `staging==backend`, a `kXR_write` is a direct `pwrite` against the
open object's fd. For an object backend with `!CAP_RANDOM_WRITE`, the **write is
buffered into the staging store** (§3.6) and only sequential, contiguous bytes
ever reach the backend — at commit, as a multipart PUT (§18.5).

```text
 kXR_write @ offset  (handler validated handle, offset, allow_write)
 ──────────────────────────────────────────────────────────────────────────────────────
 PREPARE  [EL]  xrootd_vfs_write(ctx, fh, chain, dst_off)
   │  require_write(allow_write); detach payload (payload_to_free) for [WK]
   │  ── write policy gate (§5.3) ──
   │     CAP_RANDOM_WRITE present (POSIX, or POSIX staging)  → accept any offset
   │     !CAP_RANDOM_WRITE (object direct):
   │         offset==expected_next (monotonic, contiguous from 0) → accept (staged part)
   │         hole / rewrite existing offset / pgwrite / writev   → ENOTSUP/501 + unsupp metric
   │  route bytes:
   │     A) staging==backend POSIX:  job.obj = fh->obj (backend fd)
   │     B) POSIX staging + object backend: job.obj = staging handle's obj (sd_staging)
   │  fill job { op=WRITE, obj, offset=dst_off, buf=payload, length }
   │  post → [WK]   (no pool/full → [EL/IO] inline)
   ▼
 EXECUTE  [WK]  xrootd_vfs_io_execute_write(job):
   │     written = obj->driver->pwrite(obj, buf, length, offset)
   │        POSIX (A or B): xrootd_vfs_io_write_counted() — EINTR-safe, short-write = EIO fact
   │        (object backend NEVER sees this path for in-flight writes — it only sees
   │         the multipart parts produced at promote, §18.4/§18.5)
   │     short write → job->short_io=1, job->nio=written, io_errno=EIO/ENOSPC
   │     ngx_post_event(_done)
   ▼
 COMPLETE [EL]  xrootd_write_aio_done(ev):
   │  destroyed guard; short_io/error → kXR_IOError "short write (disk full?)"; observe(error)
   │  success → fh.size grows (cached); stat_current cleared (write-then-stat re-fstats);
   │            write-through dirty mark (cache); write-recovery journal; expected_next += written
   │  observe(OP_WRITE, written); resume
```

The crucial property: **the backend object store never receives a random
`pwrite`.** With a POSIX staging store, all out-of-order / checkpointed / hole
writes land on the staging file (which advertises `RANDOM_WRITE|TRUNCATE|APPEND`),
and the backend only ever sees the sequential bytes of a finished object at
promote time (§18.4). `staging==backend==posix` is the unchanged default and
supports everything (§5.3 last paragraph).

---

### 18.4 staged-commit / promote — the §3.6.1 decision

`xrootd_vfs_staged_commit()` becomes a VFS-orchestrated decision keyed on
`ctx->sd_staging == ctx->sd` (pointer compare, §19.3) and the backend's
`CAP_HARD_RENAME`. Two cases below: (a) the unchanged fast native rename, and
(b) the headline cross-store promote.

#### (a) staging == backend POSIX → native renameat2 (fast path, zero copy)

```text
 COMMIT  [EL]  xrootd_vfs_staged_commit(st, noreplace)
   │  identity check:  ctx->sd_staging == ctx->sd   → TRUE
   │  backend caps & CAP_HARD_RENAME → TRUE
   │  → backend driver->rename(inst, temp_path, final_path, noreplace)
   │       POSIX: renameat2(rootfd, temp, rootfd, final, noreplace?RENAME_NOREPLACE:0)
   │  (rename op itself is a fast syscall → stays [EL] for POSIX)
   │  observe(OP_WRITE commit); NO promote bytes recorded (identical to today)
   ▼
   atomic publish — single kernel rename; crash window = none (rename is atomic)
```

#### (b) POSIX staging → object backend → drive backend `staged_*` multipart, then unlink temp

```text
 COMMIT  [EL]  xrootd_vfs_staged_commit(st, noreplace)
   │  identity check: sd_staging != sd  → cross-store promote
   │  degraded metric: xrootd_sd_degraded_total{op=commit,reason=promote}
   │  open backend multipart lifecycle + stream staging bytes — ALL on [WK] (network):
   ▼
 PROMOTE  [WK]  (xrootd_aio_post_task with a promote job)
   │  s = backend->driver->staged_open(backend_inst, final_path, mode, &err)   ── Init MPU
   │  loop part p = 1..N:
   │     n = staging->driver->pread(staging_obj, partbuf, PART_SZ, off)        ── read scratch
   │     backend->driver->staged_write(s, partbuf, n, off)                     ── UploadPart p
   │     off += n
   │  ◄── CRASH WINDOW W1: worker dies mid-loop → MPU is open but not completed;
   │       no final object visible; staging temp still present (reclaimed by sweeper, §12.5/§9.3)
   │  rc = backend->driver->staged_commit(s, noreplace)                        ── CompleteMPU
   │       └─ ETag/generation mismatch → ESTALE; commit FAILS, no publish
   │  ◄── CRASH WINDOW W2: worker dies AFTER CompleteMPU success, BEFORE unlink staging:
   │       durable object IS present (correct & complete); at most a stale staging temp
   │       remains (sweeper reclaims). NEVER a missing object. (§9.3 promote-crash test)
   │  staging->driver->unlink(staging_inst, temp_path, /*is_dir=*/0)           ── drop scratch
   ▼
 COMPLETE [EL]
   │  rc != OK → backend->driver->staged_abort(s) (AbortMPU); leave staging temp for cleanup;
   │            final path stays ENOENT (never partially published); observe(error)
   │  rc == OK → record xrootd_sd_bytes_total against the BACKEND store (durable write);
   │            observe(OP_WRITE commit ok); resume
```

Atomicity statement: the **only** publish point is `staged_commit`
(CompleteMultipartUpload). Before it, `stat`/`list`/`read` of the final path
returns `ENOENT` exactly as today (§3.6.3). Order is mandatory:
`CompleteMPU` **then** `unlink staging` — so a crash between them strands a temp,
never an object. The reverse order would risk a missing object and is forbidden.

---

### 18.5 object multipart upload — state machine

The object driver's own `staged_*` lifecycle (§3.3 / §5.3). This is what
`staged_open/_write/_commit/_abort` drive on `[WK]`.

```text
                              staged_open(final_path)
                                      │  CreateMultipartUpload → upload_id
                                      ▼
                              ┌───────────────┐
                ┌────────────►│     INIT      │  (upload_id held on xrootd_sd_staged_t)
                │             └───────┬───────┘
                │   create err (EACCES/                │ staged_write(part) [part>=5MiB or final]
                │   ETIMEDOUT)→ FAIL  │                ▼
                │                     │        ┌───────────────┐  UploadPart N → etag[N]
                │  abort/cancel/      │        │  UPLOADING    │◄──────────┐
                │  teardown           │        │  (part 1..N)  │           │ more parts
                │                     │        └───┬───────┬───┘───────────┘
                │                     │ part err   │       │ last part buffered
                │                     │ (EIO/ENOSPC│       │ staged_commit
                │                     │  /ETIMEDOUT)▼       ▼
                │             ┌───────────────┐   ┌────────────────────┐
                └─────────────┤    ABORTING   │   │     COMPLETING     │
                              │ AbortMPU(     │   │ CompleteMPU(       │
                              │  upload_id)   │   │  upload_id,etags)  │
                              └───────┬───────┘   └─────┬──────────┬───┘
                                      │                 │ 200      │ ETag/gen mismatch
                                      ▼                 ▼          ▼  → ESTALE
                               ┌──────────────┐  ┌────────────┐  ┌──────────┐
                               │   ABORTED    │  │  COMMITTED │  │   FAIL   │
                               │ (no object;  │  │ (durable   │  │(no publish;
                               │  upload_id   │  │  object;   │  │ caller may
                               │  freed)      │  │  id freed) │  │  abort)  │
                               └──────────────┘  └────────────┘  └──────────┘

 Error transitions (all → ABORTING then ABORTED, upload_id always freed):
   UploadPart short/EIO/ENOSPC/ETIMEDOUT ──► ABORTING
   CompleteMPU ESTALE/conflict           ──► FAIL ──(caller)──► ABORTING
   cancel / client disconnect (destroyed)──► ABORTING
   worker/conf teardown (cleanup)        ──► ABORTING   (no upload_id may leak, §19.2-D)
```

Invariant: every exit path frees `upload_id` and either completes or aborts the
remote MPU — there is no terminal state that leaves a dangling server-side
upload. `staged_abort` is idempotent and safe to call from the `destroyed`/
teardown guard.

---

### 18.6 dirlist — POSIX fdopendir scan vs object ListObjectsV2 prefix iterator

POSIX dirlist is the existing `xrootd_vfs_io_execute_opendir()` body: dup the
PREPARE-confined `rootfd`, `fdopendir`, build the whole flat wire buffer on
`[WK]`. The object backend replaces the scan with a paginated `ListObjectsV2`
prefix iterator — same wire framing, different enumeration source.

```text
 kXR_dirlist / PROPFIND / S3 ListObjects
 ──────────────────────────────────────────────────────────────────────────────────────
 PREPARE  [EL]  resolve+confine path; fill job { op=OPENDIR, rootfd(dup-able) OR
                 obj/inst+prefix, buf, buf_cap, want_stat, want_cksum, cksum_algo,
                 path, streamid[2] }; post → [WK]
   ▼
 EXECUTE  [WK]  xrootd_vfs_io_execute_opendir(job):

   POSIX driver:                              OBJECT driver:
   ───────────────────────────────           ─────────────────────────────────────────
   scanfd = dup(job->rootfd)                  key_prefix = inst.prefix + job->path + "/"
   dp = fdopendir(scanfd)                     continuation_token = NULL
   for de in readdir(dp):                     do:
     skip "."/".."/".nginx-xrootd"/ctrl bytes    page = ListObjectsV2(bucket, prefix,
     (name_unsafe filter)                              delimiter="/", token, max-keys)
     want_stat → fstatat(dirfd,name,           for each Contents[k] in page:
       NOFOLLOW) → stat body                       name = strip(prefix); skip markers
     want_cksum → dirlist_checksum_token          want_stat → key.Size/LastModified → stat body
     need-new-chunk? flush kXR_oksofar            want_cksum → object tag/ETag → token
       (E2BIG if > buf_cap)                       for each CommonPrefixes[j]: synth subdir entry
     emit name[+stat][+cksum] into chunk          need-new-chunk? flush kXR_oksofar (E2BIG cap)
   closedir(dp)                                    emit entry into chunk
                                              while page.IsTruncated:
                                                  token = page.NextContinuationToken
   ── identical tail for both ──
   final entry NUL-terminate; xrootd_build_resp_hdr(streamid, kXR_ok, cdpos, ...)
   job->out_size = base + HDR + cdpos; job->nio = 0
   (network blocking calls correct on [WK]; touches only job + buf)
   ngx_post_event(_done)
   ▼
 COMPLETE [EL]  xrootd_dirlist_aio_done(ev): destroyed guard; queue framed response;
                observe(OP_DIRLIST); resume
```

Notes:
- POSIX uses `dup(rootfd)`+`fdopendir` precisely because the directory was
  `RESOLVE_BENEATH`-confined on `[EL]` in PREPARE — never re-resolve a path on a
  worker (`aio/README.md` invariant). The object iterator is confined by the
  `inst.prefix` bound applied on `[WK]`; a listing can never escape the prefix.
- Both emit the **same** `kXR_oksofar`×N + final `kXR_ok` framing and honor the
  `XROOTD_VFS_DIRLIST_CHUNK_CAP` / `buf_cap` E2BIG ceiling, so the wire bytes are
  capability-independent for the entries that exist.
- `!CAP_DIRS` synthesizes directories from `CommonPrefixes`; `mkdir`/`rmdir`
  become prefix-marker ops or no-ops (§3.1 cap table).

---

## 19. Concurrency, lifetime & memory-ordering proofs

Numbered invariants with short proofs (style of phase-44 §24). "Proof" = the
mechanism that makes the invariant hold, plus the failure it prevents.

### 19.1 Worker-safe invariant

**INV-19.1.** Every SD raw op invoked from the EXECUTE phase
(`obj->driver->pread/pwrite/ftruncate/fsync/fstat`, and the offloaded
`stat/opendir/readdir/server_copy/staged_*` for object backends) touches **only**
the POD `xrootd_vfs_job_t` and caller-owned buffers. It must not touch an nginx
pool, a metric, an access/error log, `c->log`, the cache, connection/request
state, or any shared mutable table.

*May touch:* `job->{obj,segs,buf,buf_cap,offset,length,want_pgcrc,do_sync,
rootfd,path,streamid,cksum_algo}` (IN), `job->{nio,out_size,crc32c,io_errno,
short_io,err_msg}` (OUT); the driver-private object state reachable through `obj`
(POSIX fd; object `{key,etag,size,staging_fd,upload_id}` + its own per-instance
transport handle); raw syscalls / network sockets the driver owns; the thread
pool's `log` argument (not `c->log`); driver-instance allocations from a
*non-request* pool or `ngx_alloc` (§3.2 rule 5).

*May NOT touch:* request `pool` / `ngx_palloc` (alloc is done on `[EL]` in
PREPARE — see `vfs_read` `ngx_pnalloc`), `ngx_post_event`/event arming, Prometheus
counters, `xrootd_access_log_emit`, `xrootd_send_error`/`XROOTD_OP_*`,
`xrootd_cache_*`, `ctx`/`c`/`r`/`fh` fields beyond the POD snapshot, any SHM
table.

*Proof.* This is structurally identical to the Phase-54 contract that
`xrootd_vfs_io_execute()` already enforces (`vfs_io_core.c` header: "mutates only
the job's OUT fields and caller-owned buffers; it never touches nginx pools,
connection state, metrics, access logs, or cache metadata") and to the
`aio/README.md` rule ("Worker threads touch nothing but the task struct"). Phase
55 only changes the *body* of the per-op executor from a bare syscall to
`obj->driver->...`; the vtable is **flat POD-pointer-only** (§3.3 note) precisely
so the object driver's blocking network body satisfies the same contract with
zero event-loop coupling. The POSIX driver bodies are *literally* today's
`xrootd_vfs_pread_full` / `xrootd_vfs_io_write_counted` / `fdopendir` scan, which
already provably obey it. Therefore the invariant is preserved by construction.
The failure it prevents: a worker calling `ngx_palloc` or a metric would race the
single-threaded `[EL]` allocator/registry → heap corruption or counter tearing
(cf. the `aio/README.md` scratch-buffer UAF postmortem). ∎

### 19.2 Object-handle lifetime / UAF guards

**INV-19.2-A (no free under in-flight AIO).** An `xrootd_sd_obj_t` is freed only
after every AIO job referencing it has reached COMPLETE on `[EL]`.

*Proof.* The handle lifetime is owned on `[EL]`: `xrootd_vfs_close()` (pool
cleanup, §18.1) runs on the event loop, and a job is in flight exactly while the
connection sits in `XRD_ST_AIO` with events disarmed. The `_done` callback runs
`xrootd_aio_restore_request()` and only then may the connection advance to a state
where close is reachable. Because `[EL]` is single-threaded, close and `_done`
cannot interleave; the job's `obj` pointer is therefore valid for the entire
EXECUTE window. The `ctx->destroyed` guard handles the disconnect-during-flight
case: `_done` frees the *detached payload* and returns **before** dereferencing
freed connection state, and the handle close itself is deferred to normal pool
teardown after the in-flight task drains. ∎

**INV-19.2-B (dup'd sendfile fd ownership).** A POSIX cleartext read emits an
`in_file` buf built from `dup(xrootd_sd_fd(obj))` with `ngx_pool_cleanup_file`;
the duplicate is closed by the request pool independently of the handle.

*Proof.* Unchanged from `fs/README.md` invariant #7 / `vfs_read.c`
`make_file_chain()` — the only change is the fd source (`xrootd_sd_fd(obj)`
instead of `fh->fd`), and it is reached **only** when `CAP_SENDFILE` (so the dup
is always a real fd). Closing the handle does not close the in-flight sendfile
duplicate; an object backend never reaches this path (`!CAP_FD` ⇒
`xrootd_sd_fd` is `NGX_INVALID_FILE` ⇒ memory builder), so there is no
"dup of an invalid fd" hazard. ∎

**INV-19.2-C (staging object outlives promote).** During a cross-store promote
(§18.4b) the staging object handle remains open and valid until **after**
`unlink staging`, which itself runs after backend `staged_commit` succeeds.

*Proof.* The promote loop on `[WK]` holds the staging `obj` (it `pread`s parts
from it) and the backend `staged_t` simultaneously; both are stack/job-scoped for
the duration of one promote job. `unlink` is issued only on the success edge
after `staged_commit` returns OK, and the staging temp has **no** logical-path
mapping in the backend namespace (§3.6.3), so no concurrent client op can race a
delete of it. On any failure edge, `staged_abort` aborts the backend MPU and the
staging temp is intentionally **left** for the abort/sweeper path — never unlinked
on the failure branch. ∎

**INV-19.2-D (multipart upload_id cleanup on abort/cancel/teardown).** No
server-side multipart upload is leaked across abort, client cancel, or
worker/conf teardown.

*Proof.* The §18.5 state machine has no terminal state that retains a live
`upload_id`: COMMITTED and ABORTED both free it, and FAIL transitions to ABORTING
(driver `cleanup`/`staged_abort` is invoked from the `destroyed` guard and from
the instance `cleanup` vtable entry). `staged_abort` is idempotent (§3.2 rule 2:
"close is idempotent"), so the teardown path may call it unconditionally. The
crash-only window (worker SIGKILL before AbortMPU) is reclaimed by the
staging-store sweeper / existing `compat/staged_file` cleanup extended to the
staging root (§12.5) — i.e. durability of cleanup does not depend on graceful
shutdown. ∎

### 19.3 Two-store identity

**INV-19.3.** `ctx->sd_staging == ctx->sd` is a **stable pointer comparison**
valid for the entire lifetime of the configuration, and is the sole switch
between the native-rename fast path and cross-store promote.

*Proof.* The registry (`sd_registry.c`) constructs instances at
postconfiguration/worker init and, when `xrootd_storage_staging` resolves to
`same`, **hands back the identical pointer** rather than a copy (§6.4, §6.6:
`staging_instance == backend_instance`). Instances are immutable for the conf's
lifetime (no per-request backend switching, principle §3 design rule). Therefore
`sd_staging == sd` is a constant-time, race-free pointer compare with no
dereference and no locking. Reload semantics: a config reload **rebuilds**
instances on the new workers (standard nginx drain — new connections get the new
instances; in-flight requests finish on the **old** workers against the old
instances, FAQ "Config reload"). Because each request reads a single immutable
`ctx->{sd,sd_staging}` snapshot for its whole lifetime, a reload can never flip
the identity mid-request. Cert/key/cred rotation on reload follows the same
old-worker-finishes rule. ∎

### 19.4 Confinement under concurrency (no TOCTOU across PREPARE/EXECUTE)

**INV-19.4.** Each store enforces its own physical confinement primitive, and the
path is resolved + confined on `[EL]` in PREPARE **before** the job is posted, so
there is no time-of-check/time-of-use gap across the worker boundary.

*Proof.* Two independent guards compose:
1. **VFS logical guard** (`xrootd_vfs_require_confined`) runs on `[EL]` at open and
   before every entry point — unchanged. The resolved `xrootd_path_result_t` is a
   value captured in the ctx; the worker receives a confined fd/object, never a
   client path to re-resolve (cf. `aio/README.md`: "Path confinement happens
   before posting, not on the worker"; the dirlist worker `dup`s the
   already-confined `rootfd`).
2. **SD physical guard** is per-driver and applied at the seam: POSIX via
   `openat2(RESOLVE_BENEATH)` (so the kernel re-checks each path component at open,
   defeating symlink-swap TOCTOU); object via "logical→`key_prefix+path`, reject
   `..`/escape after normalization" evaluated on `[WK]` from the immutable instance
   prefix. An `EXDEV`/prefix-escape is returned as a storage fact the VFS maps to
   `kXR_NotAuthorized`/403 (§3.3.2, §5.2) — identical to today.

Because the object passed to `[WK]` is *already* the confined target (an fd, or a
key derived from the confined logical path bound to an immutable instance prefix),
no untrusted string crosses the PREPARE→EXECUTE boundary. The two stores confine
independently (§3.6.3): a staging temp can never escape the staging root, a
promoted key can never escape the backend prefix — and since instances are
immutable (§19.3), concurrent requests on the same worker cannot perturb each
other's confinement state. ∎

### 19.5 No-new-deadlock argument

**INV-19.5.** Phase 55 introduces no new lock-ordering or lost-wakeup hazard with
respect to (a) the CLAUDE.md INVARIANT #10 shmtx spin+yield rule, and (b) the AIO
thread pool.

*Proof, part (a) — shmtx.* The SD seam adds **no** shared-memory mutex. The only
SHM table touched on the open hot path is the existing `xrootd_handle_mutex`
(fd-table), which is already created via `xrootd_shm_table_mutex_create()` →
spin+yield, **never** the POSIX-semaphore mode (INVARIANT #10 / the
postmortem-shmtx-semaphore-stall fix). Phase 55 does not add SHM tables, does not
take any SHM mutex inside an SD raw op (INV-19.1 forbids it), and does not hold any
SHM lock across a blocking SD call. Therefore the lost-wakeup class that froze
workers cannot be reached through the new seam: SD blocking happens on a worker
thread with **no** SHM lock held, and the µs-held fixed-slot `[EL]` critical
sections are unchanged. ∎

*Proof, part (b) — thread pool.* Object-store blocking network I/O runs **only**
on the AIO worker tier (`xrootd_aio_post_task`), which is exactly the tier built to
absorb tens-to-hundreds-of-ms stalls without freezing the `[EL]` loop
(`aio/README.md` overview; §5.5). Three properties prevent deadlock:
1. **No `[EL]` block.** No SD blocking call runs on `[EL]`; namespace ops that are
   inline POSIX syscalls today are *additionally offloaded* for object backends
   (§5.5), so the event loop never waits on a network round-trip. Running them on
   `[EL]` is exactly the failure mode the shmtx postmortem warns against, and is
   structurally excluded.
2. **No worker→worker dependency.** Each AIO job is independent; a worker never
   blocks waiting on another pool task (the promote loop drives both
   staging-`pread` and backend-`staged_write` **sequentially within one job**, not
   across jobs), so the pool cannot deadlock on its own queue. Queue saturation
   degrades to the inline `[EL/IO]` fallback (`xrootd_aio_post_task` returns to
   sync) for POSIX; for object backends the gate at config time requires a thread
   pool (§6.5), and back-pressure is shed via the Phase-31 `kXR_wait` budget
   (§12.6), not by blocking.
3. **No lock held across post.** PREPARE allocates and posts, then disarms events
   and returns to the loop; it holds no lock while the worker runs. COMPLETE
   re-acquires nothing the worker could be holding (the worker holds no `[EL]`
   lock at all, INV-19.1).

Hence the cascade io_uring→pool→inline is unchanged in shape; the object driver
merely populates the pool tier with network bodies that are, from the scheduler's
view, indistinguishable from slow disk reads the pool already tolerates. No new
wait edge is created between `[EL]` and `[WK]` beyond the existing
post/`ngx_post_event` handoff, which is wakeup-safe (eventfd→epoll bridge for
io_uring; `ngx_thread_pool` completion notification for the pool). ∎


## 20. Exhaustive error/status mapping (no-new-error-paths proof)

This appendix is the formal companion to §3.3.2 (error contract). It exists to
*prove* one claim that 55.A–55.C must hold: **the Storage Driver seam adds no new
client-visible error path for the POSIX backend.** A driver returns an `errno`-style
fact; the VFS observer (`xrootd_vfs_observe_ctx_op`, `vfs_internal.h`) classifies it
and the protocol layers map it to `kXR_*` / HTTP / S3. The seam moves *where* the
`errno` is produced (from an inline syscall to `obj->driver->op`), never *which*
`errno` is produced, and never the mapping above the seam.

The mapping pipeline is therefore unchanged in shape:

```
driver op  ──errno──►  VFS (xrootd_vfs_ns_status_errno / raw errno)
                          │  xrootd_vfs_observe_ctx_op: errno → xrootd_err_class_t
                          ▼
           XRootD: xrootd_send_error(kXR_*)        (stream front end)
           HTTP:   xrootd_http_errno_to_status()   (WebDAV front end)
           S3:     s3 XML <Code> + HTTP status      (S3 REST front end)
```

The VFS never invents a status; it forwards the driver's `errno` through the *same*
`xrootd_metric_err_from_errno` / `xrootd_http_errno_to_status` / S3-XML edges that
exist today.

### 20.1 Complete errno → VFS → kXR → HTTP → S3 table

`errno` column is the value the driver captures immediately on failure (`*err_out`,
or `errno` after a `NGX_ERROR`/`NULL`/short-count return). "VFS handling" is what the
VFS does *before* handing the fact to the protocol layer. For namespace ops the errno
is produced via `xrootd_vfs_ns_status_errno()` (`vfs_internal.h`) from the driver's
`xrootd_ns_status_t`; for byte I/O it is the raw syscall errno from `pread`/`pwrite`.

| errno | VFS handling | XRootD `kXR_*` | HTTP | S3 `<Code>` (HTTP) | NEW with object backend? |
|---|---|---|---|---|---|
| `ENOENT` | forward as-is; idempotent-missing ops (`xrootd_ns_delete` `idempotent_missing`) fold to OK | `kXR_NotFound` | 404 | `NoSuchKey` (404) | no — same fact; object HEAD 404 → `ENOENT` |
| `EACCES` | forward; produced by `require_write` (no `allow_write`), backend creds, or prefix/RESOLVE_BENEATH escape (§20.3) | `kXR_NotAuthorized` | 403 | `AccessDenied` (403) | no — object cred/ACL denial folds here |
| `EPERM` | treated identically to `EACCES` by the error class map | `kXR_NotAuthorized` | 403 | `AccessDenied` (403) | no |
| `EEXIST` | forward; conditional-create / `O_EXCL` / `noreplace` rename collisions; per-op semantics preserved | `kXR_ArgInvalid` (or op-specific, e.g. mkdir) | 409 / 412 | `PreconditionFailed` (412) for `If-None-Match:*`, else 409 | no — object conditional PUT (`If-None-Match`) folds here |
| `ENOTEMPTY` | forward; from `XROOTD_NS_NOT_EMPTY` (driver's own emptiness probe; `sys_errno==0`, so **must** route via `xrootd_vfs_ns_status_errno`) | `kXR_FSError` (rmdir non-empty) | 409 | `BucketNotEmpty`/409 (delete-prefix) | no — POSIX-identical; object prefix-non-empty maps here too |
| `ENOTDIR` | forward; from `XROOTD_NS_CONFLICT` (path component is not a dir) | `kXR_FSError`/`kXR_NotFound` per op | 409 / 404 | `NoSuchKey` (404) | no |
| `EISDIR` | forward; open-for-write / read of a directory target | `kXR_isDirectory` | 409 (or 400) | `NoSuchKey`/`InvalidRequest` (404/400) | no — object "key is a prefix" maps here |
| `EINVAL` | forward; bad args, unconfined ctx (`require_confined`), malformed offset/len | `kXR_ArgInvalid` | 400 | `InvalidArgument`/`InvalidRange` (400) | no |
| `ENOSPC` | forward; from `XROOTD_NS_NO_SPACE` or a short/failed write | `kXR_FSError` (no-space text preserved) | 507 | `EntityTooLarge`/`ServiceUnavailable` (413/503) | no — object 507/quota-full surfaces here or as `EDQUOT` |
| `EDQUOT` | forward; quota exceeded. Mapped through the error class like `ENOSPC` | `kXR_FSError` | 507 | `QuotaExceeded`/`ServiceUnavailable` (507/503) | **partly** — object/quota backends make this reachable on write/commit; folds into the existing no-space wire code |
| `EIO` | forward; the catch-all in `xrootd_vfs_ns_status_errno` (`default: EIO`) and short-write fallback | `kXR_IOError` | 500 | `InternalError` (500) | no — also the landing zone for new object faults (see `ESTALE`/`ETIMEDOUT`) |
| `ENOTSUP` / `EOPNOTSUPP` | forward; emitted by the VFS capability gate (`xrootd_sd_supports` failed) **or** a driver op that declines an advertised-absent feature | `kXR_Unsupported` | 501 | `NotImplemented` (501) | **YES** — only reachable when a backend lacks a `CAP_*` the request needs (§20.4); POSIX advertises every cap, so never reached on POSIX |
| `ESTALE` | VFS maps to `EIO` class unless the op has an explicit conflict mapping (optimistic-commit / ETag mismatch) | `kXR_IOError` (commit conflict: op-specific) | 500, or **409** for staged-commit conflict | `PreconditionFailed`/`InternalError` (412/500) | **YES (object-only)** — optimistic staged-commit / generation mismatch; folds into `kXR_IOError`/`InternalError` except the documented commit-conflict 409 |
| `ETIMEDOUT` | forward; backend name goes to **log detail**, never a metric label | `kXR_IOError` | 504 | `ServiceUnavailable`/`InternalError` (503/500) | **YES (object-only)** — blocking network op timed out; POSIX syscalls do not time out, so unreachable on POSIX |
| `ECONNREFUSED` | treated as a transport `EIO`-class fault; backend name in log detail | `kXR_IOError` | 502 / 503 | `ServiceUnavailable` (503) | **YES (object-only)** — endpoint unreachable; never produced by a local fd op |
| `EXDEV` | **normalized at the seam to escape → denial** (§20.3); never surfaces raw to a client | `kXR_NotAuthorized` | 403 | `AccessDenied` (403) | no — POSIX `RESOLVE_BENEATH`/cross-root already does this; object key-prefix escape reuses the same normalization |
| `ENAMETOOLONG` | forward; from `XROOTD_NS_TOO_LONG` | `kXR_ArgInvalid` | 414 (or 400) | `InvalidArgument`/`KeyTooLongError` (400) | no — object key-length limit also folds here |
| `EOVERFLOW` | forward; size/offset exceeds the type range on stat/read | `kXR_ArgInvalid` | 400 (or 416 on range) | `InvalidRange` (416) | no |
| `EBUSY` | forward; resource temporarily locked (rare on POSIX: e.g. busy mount on rename) | `kXR_FSError` | 409 / 503 | `ServiceUnavailable` (503) | no — object backends prefer `ETIMEDOUT`/`ESTALE`; `EBUSY` stays the rare POSIX case |
| `ECANCELED` | forward; client-cancelled / aborted transfer (multipart abort, staged_abort path) | (connection already torn down; no wire reply) | 499 (client-closed) or no reply | (no reply / aborted) | **partly** — object multipart abort uses `staged_abort`; on POSIX it is the existing cancellation path |

Notes on rows that look new but are not:
- **`EDQUOT`** is technically reachable on POSIX today (a quota'd export already
  returns it via a failed `pwrite`); it maps through the *same* no-space class. Object
  backends merely make it more common. It is **not** a new wire code.
- **`EBUSY`/`EOVERFLOW`/`ENAMETOOLONG`/`EISDIR`** are all pre-existing POSIX errnos
  with pre-existing mappings; listed for completeness, unchanged by the seam.

### 20.2 No-new-error-paths proof (POSIX backend)

**Claim.** For `xrootd_storage_backend posix; xrootd_storage_staging same;` (the
default, and any config that omits both directives), every client-visible status —
`kXR_*`, HTTP code, S3 `<Code>`, access-log error class, and `xrootd_metric_op_done`
error label — is byte-identical to pre-Phase-55.

**Proof by construction (three links of the chain are provably unchanged):**

1. **The driver returns the *same* errno the old code returned.** `sd_posix.c` is, per
   §4 ("behaviour-preserving wrapper"), the *current bodies moved verbatim*:
   - `pread`/`pwrite` are literally `xrootd_vfs_pread_full` / `xrootd_vfs_pwrite_full`
     (`vfs_internal.h`), which set `errno` exactly as `pread(2)`/`pwrite(2)` do today
     (EINTR-safe loop, 0-byte write → `EIO` — unchanged text).
   - `fstat`/`stat`/`open` are the `adopt_fd` / `xrootd_open_beneath` /
     `xrootd_lstat_beneath` bodies — same syscall, same errno.
   - `unlink`/`mkdir`/`rename`/`server_copy` forward to `xrootd_ns_delete` / `_mkdir`
     / `_rename` / `_local_copy`, whose `xrootd_ns_result_t.status` is collapsed to an
     errno by **the same** `xrootd_vfs_ns_status_errno()` switch the VFS uses today.
     That switch is the single source of truth (`XROOTD_NS_NOT_EMPTY → ENOTEMPTY`,
     `XROOTD_NS_CONFLICT → ENOTDIR`, `default → EIO`); Phase 55 does not edit it, so a
     non-empty rmdir still yields `ENOTEMPTY/409`, not `EIO/500`.

2. **The VFS classification is unchanged.** `xrootd_vfs_observe_ctx_op` /
   `xrootd_vfs_observe_file_op` still take the *same* `(rc, sys_errno)` and run the
   *same* `xrootd_metric_err_from_errno` to produce the `xrootd_err_class_t`, the
   *same* `xrootd_metric_op_done` (same proto label from `xrootd_vfs_metrics_proto`),
   and the *same* `xrootd_access_log_emit`. The observer signature does not change; the
   only difference upstream is that `sys_errno` arrives from `obj->driver->op` instead
   of an inline syscall — a value-identical substitution.

3. **The protocol mapping is unchanged.** No `kXR_*` table, no
   `xrootd_http_errno_to_status`, and no S3 `<Code>` emission is touched by 55.A–55.C
   (§1.1.2 "stays in VFS/protocol"). The driver "must never call `xrootd_send_error`,
   set `XROOTD_OP_*`, or emit protocol metrics" (§3.3.2).

**Therefore** the composition `errno → class → wire` is the identity of today's
composition for POSIX. **No existing test can observe a changed status**, which is
exactly why the ~5180-test suite is the correctness oracle for the refactor (§9.1):
any diff is a regression, not an intended new path. The single API change
(retiring `xrootd_vfs_file_fd()`, §6.1) is a buffer-shaping change, not a status
change — the bytes and the status are identical; only the `ngx_buf_t` backing (file vs
memory) can differ, and only on a `!CAP_SENDFILE` backend (never POSIX).

**Genuinely-new statuses (object backends only), and where each surfaces:**

| New status | First reachable in | Where it surfaces | Folds into existing wire code? |
|---|---|---|---|
| `ENOTSUP`/`EOPNOTSUPP` → `kXR_Unsupported`/501/`NotImplemented` | 55.D (block), 55.E (object) | VFS capability gate (`xrootd_sd_supports`) rejecting `kXR_read`/`kXR_write`/`writev`/`pgwrite`/truncate/checkpoint on a backend lacking the cap (§20.4) | new code `kXR_Unsupported`/501 was already defined; newly *reachable*, not new mapping |
| `ESTALE` → `kXR_IOError`/500 (commit-conflict: 409) | 55.E (object) | `staged_commit` optimistic-concurrency / ETag-or-generation mismatch (`vfs_staged_commit` body) | yes — `kXR_IOError`/`InternalError`, except the one documented staged-commit 409 |
| `ETIMEDOUT` → `kXR_IOError`/504 | 55.E (object) | AIO-offloaded object op (`pread`/`pwrite`/`server_copy`/`staged_*`/offloaded namespace) exceeding the backend deadline | yes — existing `kXR_IOError` |
| `ECONNREFUSED` → `kXR_IOError`/502–503 | 55.E (object) | object transport (`sd_object_s3.c`) connect failure | yes — existing `kXR_IOError`/`ServiceUnavailable` |
| `EDQUOT` (more common) → `kXR_FSError`/507 | 55.E (object/quota) | backend `pwrite`/`staged_commit` over quota | yes — existing no-space wire code |
| `xrootd_sd_degraded_total` (not an errno) | 55.F | sendfile→memory fallback, stream-through copy, weak rename, sidecar xattrs, cross-store promote (§20.4) | **no client status change** — the op still *succeeds*; only a metric + log-detail string is added |

Each new status reuses an existing wire code; none introduces a new `kXR_*` constant
or a new HTTP class beyond `kXR_Unsupported`/501 (already defined in `XProtocol`).

### 20.3 `EXDEV`-means-escape normalization

Both confinement primitives report a containment breach as `EXDEV` *internally*, and
the VFS normalizes both to the same denial — there is no escape-specific client status,
and the path that escaped is never echoed.

| Backend | Physical confinement primitive | Escape signal | Normalized to |
|---|---|---|---|
| POSIX (`sd_posix`) | `openat2(RESOLVE_BENEATH)` rooted at the per-instance `rootfd`; `xrootd_ns_*` strip to a within-root tail | a path that escapes `root_canon` → `xrootd_ns_result_t.status = XROOTD_NS_DENIED`, `sys_errno = EXDEV` (see `namespace_ops.h` `xrootd_ns_delete`/`_rename` doc) | `EACCES` → `kXR_NotAuthorized` / **403** |
| object (`sd_object`) | `logical path → key_prefix + path`, reject `..`/escape *after* normalization (§5.2, §3.3.3) | a key that would resolve outside the configured prefix → driver returns `EXDEV` (or `EACCES`) before any transport call | `EACCES` → `kXR_NotAuthorized` / **403** |

Normalization rules (single edge, both backends):
- The VFS treats `EXDEV` from any SD op on a *logical* path as **escape**, mapping it
  to `EACCES` and thence `kXR_NotAuthorized` / 403 / S3 `AccessDenied` — identical to
  today's POSIX behaviour (the existing `tests/test_attack_vectors.py` asserts this).
- The escape is detected **at the seam**, before the op has any effect; the VFS
  `require_confined` logical guard (`vfs_internal.h`) stays in front of it, so a
  malformed ctx is already `EINVAL` before the driver is consulted.
- The offending physical locator (POSIX path tail or object key) is **never** put in a
  metric label and only appears in the sanitized access/debug log
  (`xrootd_sanitize_log_string`). `EXDEV` itself never reaches a client.
- `server_copy`/`rename` enforce that **both** endpoints are confined; a cross-root
  POSIX rename and a cross-prefix object copy both yield `EXDEV` → 403, not a partial
  move.

### 20.4 Capability-absence mapping (which `CAP_*` → which status + which metric)

When the VFS asks `xrootd_sd_supports(inst, CAP_X)` and the answer is false, it picks
one of exactly two outcomes — **reject** (the op cannot be honoured) or **degrade**
(the op succeeds by a fallback) — and each outcome owns a distinct metric. Reject →
`xrootd_sd_unsupported_total`; degrade → `xrootd_sd_degraded_total`. The op label and
`backend` label are low-cardinality; **no path/key/bucket/etag/host/identity label**
(§3.5).

| Missing cap | Affected ops | Outcome | Client-visible status | Metric |
|---|---|---|---|---|
| `CAP_FD` | sendfile path, fd-cache, io_uring entry | **degrade** to memory-backed `pread` chain (`b->memory=1`) | unchanged — same bytes, same 200/`kXR_ok` | `xrootd_sd_degraded_total{op=read,reason=no_fd}` |
| `CAP_SENDFILE` | cleartext WebDAV/S3/root reads | **degrade** — memory chain even for cleartext (§5.1) | unchanged status; bytes identical | `xrootd_sd_degraded_total{op=read,reason=sendfile}` |
| `CAP_RANGE_READ` | `kXR_read`, WebDAV GET range, S3 GET, pgread | **reject** | `ENOTSUP` → `kXR_Unsupported` / 501 / `NotImplemented` | `xrootd_sd_unsupported_total{op=read}` |
| `CAP_RANDOM_WRITE` | non-sequential `kXR_write`, `writev`, `pgwrite`, partial PUT, checkpoint write | **reject** (direct-to-backend; the POSIX staging store is the supported route, §5.3) | `ENOTSUP` → `kXR_Unsupported` / 501 / `NotImplemented` | `xrootd_sd_unsupported_total{op=write}` |
| `CAP_TRUNCATE` | `ftruncate`, checkpoint rollback needing shrink/extend | **reject** | `ENOTSUP` → `kXR_Unsupported` / 501 | `xrootd_sd_unsupported_total{op=truncate}` |
| `CAP_SERVER_COPY` | WebDAV COPY, S3 CopyObject, `kXR_*` copy | **degrade** to stream-through pread→pwrite (`xrootd_copy_range`) when both sides r/w; else **reject** | success (degraded) **or** `ENOTSUP`/501 when not streamable | degrade: `xrootd_sd_degraded_total{op=copy,reason=stream_copy}`; reject: `xrootd_sd_unsupported_total{op=copy}` |
| `CAP_XATTR` | fattr, WebDAV dead-properties, lock DB | **degrade** to sidecar object if configured; else **reject** | success (degraded) **or** `ENOTSUP`/501 when sidecar off | degrade: `xrootd_sd_degraded_total{op=xattr,reason=sidecar}`; reject: `xrootd_sd_unsupported_total{op=xattr}` |
| `CAP_HARD_RENAME` | `rename`, staged-commit cross-store publish | **degrade** to copy+delete **only if** `weak_rename on`; else **reject** | success with non-atomic window (degraded) **or** `ENOTSUP`/501 | degrade: `xrootd_sd_degraded_total{op=rename,reason=weak_rename}`; reject: `xrootd_sd_unsupported_total{op=rename}` |
| `CAP_DIRS` | mkdir/rmdir, dirlist | **degrade** — synthesize from key prefixes; mkdir/rmdir become prefix-marker/no-ops | success (prefix-synthesized) | `xrootd_sd_degraded_total{op=mkdir|readdir,reason=prefix_dirs}` |
| `CAP_APPEND` | append-mode open | **reject** unless staged-append emulation enabled | `ENOTSUP` → `kXR_Unsupported` / 501 | `xrootd_sd_unsupported_total{op=open}` |
| `CAP_IOURING` | io_uring submit tier | **degrade** — thread-pool / inline fallback | unchanged status | (no degraded metric required; tier selection is internal — optionally `reason=no_iouring`) |

Decision rule the VFS encodes (policy-readable, per §3.3.1):
- If a fallback exists that produces the *same client-visible result* → **degrade**,
  count `xrootd_sd_degraded_total`, succeed, and leave an access-log detail naming the
  degraded op (`backend=s3 degraded=stream_copy`) — never a path label.
- If no honest fallback exists → **reject** with `ENOTSUP`, count
  `xrootd_sd_unsupported_total`, and let the protocol layer emit
  `kXR_Unsupported`/501/`NotImplemented`. Never silently emulate (§5.3, §8).
- The cross-store **promote** (§3.6) is a degrade-class event even though it succeeds:
  it records `xrootd_sd_degraded_total{op=commit,reason=promote}` and the durable bytes
  against the **backend** store's `xrootd_sd_bytes_total`. The intra-store fast rename
  (`staging==backend`, POSIX) records **no** promote bytes and **no** degrade — it is
  byte-for-byte today's `renameat2`.

---

## 21. Per-function interface & ABI contracts

One contract block per vtable slot and per helper. Conventions used below:

- **Thread context** is one of `event-loop` (nginx worker event loop only; may touch
  pools/metrics/log), `AIO-worker` (runs on the Phase-54 thread pool; **pool/metric/
  log-free**, no nginx allocation, errno-only signalling), or `either`.
- **Worker-safe** (the raw byte-I/O slots `pread`/`pwrite`/`ftruncate`/`fsync`/`fstat`
  and `staged_write`) means: **no nginx pool allocation, no metric increment, no log
  emission, no event-loop API** — exactly the Phase-54 EXECUTE contract (§3.3). The
  POSIX bodies are `xrootd_vfs_pread_full`/`xrootd_vfs_pwrite_full` and friends, which
  already obey this.
- **Errno on failure** is captured immediately (via `*err_out`, or `errno` after a
  `NGX_ERROR`/`NULL`/short-count return) and is the authoritative reason (§3.3.2).
- A driver **never** calls `xrootd_send_error`, sets `XROOTD_OP_*`, or emits a protocol
  metric (§3.3.2).

### 21.1 Instance lifecycle

```
Slot: init
Signature: ngx_int_t (*init)(xrootd_sd_instance_t *inst, ngx_log_t *log)
Thread context: event-loop (postconfig / worker init only)
Preconditions: inst allocated with parsed driver_conf; not yet usable; log valid.
Postconditions: on NGX_OK inst holds all per-export state (POSIX: persistent
  O_PATH rootfd; object: transport/cred handles, resolved bucket/prefix). On
  NGX_ERROR inst is left releasable by cleanup (no half-open transport leak).
Allocation: from the instance's own long-lived pool or ngx_alloc; NOT a request
  pool (instances outlive requests).
Errno on failure: set errno (EACCES bad root, ENOENT missing staging root,
  EINVAL bad config, ECONNREFUSED/ETIMEDOUT unreachable endpoint if validate on).
Returns NGX_DECLINED when: n/a.
Invariants/notes: must NOT make network calls during nginx -t unless a future
  validate_backend directive asks (§6.5). Idempotent per worker.
```

```
Slot: cleanup
Signature: void (*cleanup)(xrootd_sd_instance_t *inst)
Thread context: event-loop (worker exit / config teardown)
Preconditions: no in-flight op holds inst; all objects/dirs/staged from this
  inst already closed.
Postconditions: rootfd closed, transport torn down, credentials zeroized; inst
  inert. Idempotent (double-cleanup is a no-op).
Allocation: frees only what init allocated; allocates nothing.
Errno on failure: none (void; best-effort, log at most).
Returns NGX_DECLINED when: n/a.
Invariants/notes: must not commit/abort staged state — those are explicit.
```

### 21.2 Object lifecycle

```
Slot: open
Signature: xrootd_sd_obj_t *(*open)(xrootd_sd_instance_t *inst,
            const char *logical_path, int sd_flags, mode_t mode, int *err_out)
Thread context: event-loop for POSIX (fast openat2); AIO-worker when the driver
  blocks on the network (object HEAD) — VFS offloads per §5.5.
Preconditions: logical_path already VFS-confined (require_confined passed);
  err_out non-NULL.
Postconditions: returns a fully-initialized obj, OR NULL with *err_out set. No
  half-open object survives (driver cleans internally, §3.2). obj caches a stat
  snapshot (size/mtime/etag/generation).
Allocation: obj from inst pool or ngx_alloc; never a request pool (the handle can
  outlive the triggering request via the fd cache).
Errno on failure (*err_out): ENOENT, EACCES/EPERM, EISDIR, ENAMETOOLONG, EINVAL;
  object adds ETIMEDOUT/ECONNREFUSED/ESTALE; EXDEV (escape) normalized by VFS.
Returns NGX_DECLINED when: n/a (returns NULL, not a code).
Invariants/notes: applies the driver's OWN physical confinement (POSIX
  RESOLVE_BENEATH; object key-prefix). sd_flags are driver-neutral O_* semantics;
  append requires CAP_APPEND.
```

```
Slot: close
Signature: ngx_int_t (*close)(xrootd_sd_obj_t *obj)
Thread context: either (POSIX close(2) is cheap; object transport release may
  offload).
Preconditions: obj from this driver's open; may be called exactly once per live
  handle but is idempotent against double-close.
Postconditions: transport state and temp resources released. MUST NOT commit
  staged writes (commit is explicit, §3.2). Cached metadata is meaningless after.
Allocation: frees handle-private state; no pool/metric/log on the worker path.
Errno on failure: errno set (EIO on a deferred-flush failure); close still frees.
Returns NGX_DECLINED when: n/a.
Invariants/notes: idempotent. Releasing the fd is via the pool-cleanup ladder for
  POSIX sendfile handles (xrootd_vfs_register_fd_cleanup) — owned above the seam.
```

### 21.3 Raw byte I/O (WORKER-SAFE — pool/metric/log-free)

```
Slot: pread
Signature: ssize_t (*pread)(xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off)
Thread context: AIO-worker (EXECUTE phase). Worker-safe: NO pool/metric/log.
Preconditions: obj open and readable; buf>=len bytes; CAP_RANGE_READ for a true
  random offset (VFS gates first).
Postconditions: returns bytes read (0 at EOF), or -1 with errno. EINTR-safe,
  short-read-tolerant loop (POSIX body == xrootd_vfs_pread_full).
Allocation: none. buf is caller-owned (VFS-allocated before offload).
Errno on failure: EIO; object adds ETIMEDOUT/ECONNREFUSED/ESTALE.
Returns NGX_DECLINED when: n/a (byte count).
Invariants/notes: MUST be re-entrant across worker threads on distinct obj.
  Object driver issues a range GET; never the event loop.
```

```
Slot: pwrite
Signature: ssize_t (*pwrite)(xrootd_sd_obj_t *obj, const void *buf, size_t len, off_t off)
Thread context: AIO-worker. Worker-safe: NO pool/metric/log.
Preconditions: obj open writable; CAP_RANDOM_WRITE for a non-sequential off
  (VFS gates; object direct-write is reject-or-staging, §5.3).
Postconditions: returns bytes written, or -1 with errno; full-write loop, a
  0-byte write is reported EIO (POSIX body == xrootd_vfs_pwrite_full).
Allocation: none.
Errno on failure: ENOSPC, EDQUOT, EIO; object adds ETIMEDOUT/ECONNREFUSED.
Returns NGX_DECLINED when: n/a (byte count).
Invariants/notes: object driver only sees sequential bytes (staging store or
  multipart part); arbitrary-offset writes are gated out above the seam.
```

```
Slot: ftruncate
Signature: ngx_int_t (*ftruncate)(xrootd_sd_obj_t *obj, off_t len)
Thread context: AIO-worker. Worker-safe: NO pool/metric/log.
Preconditions: obj open writable; CAP_TRUNCATE (VFS gates).
Postconditions: object is exactly len bytes; cached size updated by the driver.
Allocation: none.
Errno on failure: ENOSPC, EIO; ENOTSUP if reached on a !TRUNCATE backend.
Returns NGX_DECLINED when: n/a.
Invariants/notes: object backend rejects (no in-place size change in v1).
```

```
Slot: fsync
Signature: ngx_int_t (*fsync)(xrootd_sd_obj_t *obj)
Thread context: AIO-worker. Worker-safe: NO pool/metric/log.
Preconditions: obj open.
Postconditions: durable on backends with per-write durability (POSIX). On object
  backends this is a documented NO-OP — durability is the commit point (§8).
Allocation: none.
Errno on failure: EIO.
Returns NGX_DECLINED when: n/a.
Invariants/notes: returning NGX_OK from a no-op object fsync is correct, not a lie
  — the durability contract is "committed", surfaced at staged_commit.
```

```
Slot: fstat
Signature: ngx_int_t (*fstat)(xrootd_sd_obj_t *obj, struct xrootd_sd_stat_s *out)
Thread context: AIO-worker (and event-loop for POSIX, which is fstat(2)).
  Worker-safe: NO pool/metric/log.
Preconditions: obj open; out non-NULL.
Postconditions: *out filled (size/mtime/ctime/mode/ino). Honours stat_current
  snapshot semantics — driver fills from its cached metadata when current,
  matching the phase-45 stat_current optimization (no extra round trip).
Allocation: none.
Errno on failure: EIO, ESTALE (object generation gone).
Returns NGX_DECLINED when: n/a.
Invariants/notes: VFS bridges to xrootd_vfs_stat_t via xrootd_sd_stat_to_vfs.
```

### 21.4 Namespace (logical paths; replaces the xrootd_ns_* tier)

```
Slot: stat
Signature: ngx_int_t (*stat)(xrootd_sd_instance_t *inst, const char *path,
            struct xrootd_sd_stat_s *out)
Thread context: event-loop for POSIX (lstat_beneath); AIO-worker for object
  (HEAD) — one of the namespace entry points that gains an offload branch (§5.5).
Preconditions: path VFS-confined; out non-NULL.
Postconditions: *out filled, or NGX_ERROR with errno. No path syscalls leak
  above the seam.
Allocation: none on the worker path; POSIX inline path allocates nothing
  (xrootd_lstat_beneath opens/closes its own rootfd).
Errno on failure: ENOENT, EACCES, ENOTDIR, ENAMETOOLONG; object adds
  ETIMEDOUT/ECONNREFUSED; EXDEV→escape (VFS-normalized).
Returns NGX_DECLINED when: n/a.
Invariants/notes: follows in-export symlinks like today's confined stat.
```

```
Slot: unlink
Signature: ngx_int_t (*unlink)(xrootd_sd_instance_t *inst, const char *path, int is_dir)
Thread context: event-loop (POSIX) / AIO-worker (object). 
Preconditions: path VFS-confined; write allowed (VFS require_write passed).
Postconditions: target removed; is_dir selects rmdir vs unlink semantics
  (POSIX body == xrootd_ns_delete with require_directory). ENOENT may fold to OK
  for idempotent callers (VFS decides).
Allocation: none.
Errno on failure: ENOENT, EACCES, ENOTEMPTY (non-empty dir), ENOTDIR (rmdir on a
  file), EIO; object adds transport errnos. Via xrootd_vfs_ns_status_errno.
Returns NGX_DECLINED when: n/a.
Invariants/notes: ENOTEMPTY comes from the driver's own emptiness probe
  (sys_errno==0 → must use xrootd_vfs_ns_status_errno, never blanket EIO).
```

```
Slot: mkdir
Signature: ngx_int_t (*mkdir)(xrootd_sd_instance_t *inst, const char *path, mode_t mode)
Thread context: event-loop (POSIX) / AIO-worker (object prefix-marker).
Preconditions: path VFS-confined; write allowed.
Postconditions: directory exists (POSIX body == xrootd_ns_mkdir). On a !DIRS
  object backend this is a prefix-marker no-op (degrade, §20.4).
Allocation: none.
Errno on failure: EEXIST, EACCES, ENOENT (missing parent, non-recursive),
  ENOSPC, ENAMETOOLONG.
Returns NGX_DECLINED when: a !DIRS driver MAY return NGX_DECLINED so the VFS
  treats mkdir as a synthesized no-op rather than an error.
Invariants/notes: mode subject to umask, as POSIX mkdir(2).
```

```
Slot: rename
Signature: ngx_int_t (*rename)(xrootd_sd_instance_t *inst, const char *src,
            const char *dst, int noreplace)
Thread context: event-loop (POSIX renameat2) / AIO-worker (object copy+delete).
Preconditions: src and dst BOTH VFS-confined under the SAME instance root/prefix;
  write allowed.
Postconditions: atomic move on CAP_HARD_RENAME (POSIX body == xrootd_ns_rename;
  noreplace → renameat2 RENAME_NOREPLACE). Without the cap: NGX_DECLINED (or weak
  copy+delete only when weak_rename on, §20.4).
Allocation: none.
Errno on failure: EEXIST (noreplace collision), EACCES, ENOENT (missing src),
  EXDEV (cross-root/cross-prefix → escape, VFS-normalized to 403), EIO.
Returns NGX_DECLINED when: !CAP_HARD_RENAME and weak rename not enabled — VFS
  then either falls back (if allowed) or maps to ENOTSUP/501.
Invariants/notes: confinement enforced inside the kernel rename (closes the
  realpath→rename TOCTOU); both endpoints checked.
```

```
Slot: server_copy
Signature: ngx_int_t (*server_copy)(xrootd_sd_instance_t *inst, const char *src,
            const char *dst, off_t *bytes_out)
Thread context: AIO-worker (POSIX copy_file_range can run inline but is offloaded
  for large copies; object CopyObject blocks → worker).
Preconditions: src/dst VFS-confined; write allowed; bytes_out non-NULL.
Postconditions: dst is a byte-exact copy of src; *bytes_out = bytes copied. POSIX
  body == xrootd_ns_local_copy (copy_file_range, falls back to xrootd_copy_range).
Allocation: none from request pools; may use a fixed scratch buffer.
Errno on failure: ENOENT, EACCES, ENOSPC, EXDEV (escape), EIO; object transport.
Returns NGX_DECLINED when: !CAP_SERVER_COPY (or cross-bucket object) — VFS falls
  back to its own pread→pwrite stream-through copy (§5.4).
Invariants/notes: directory sources rejected (ENOTDIR/CONFLICT); single-file only.
```

### 21.5 Directory iteration

```
Slot: opendir
Signature: xrootd_sd_dir_t *(*opendir)(xrootd_sd_instance_t *inst,
            const char *path, int *err_out)
Thread context: event-loop (POSIX fdopendir) / AIO-worker (object ListObjectsV2).
Preconditions: path VFS-confined; err_out non-NULL.
Postconditions: returns a dir cursor, or NULL with *err_out set. For object it
  holds pagination state (continuation token).
Allocation: dir cursor from inst pool / ngx_alloc; object may buffer one page.
Errno on failure (*err_out): ENOENT, ENOTDIR, EACCES; object ETIMEDOUT.
Returns NGX_DECLINED when: !CAP_DIRS may still opendir via prefix synthesis;
  a driver with no listing returns NULL/ENOTSUP.
Invariants/notes: carries root_canon for impersonation-routed per-child lstat
  (POSIX), mirroring struct xrootd_vfs_dir_s.
```

```
Slot: readdir
Signature: ngx_int_t (*readdir)(xrootd_sd_dir_t *d, struct xrootd_sd_dirent_s *out)
Thread context: matches the opendir context for that cursor (object: AIO-worker,
  may fetch the next page).
Preconditions: d from this driver's opendir; out non-NULL.
Postconditions: *out = next entry (name + optional stat); returns NGX_DONE at end
  of stream. Dot entries handling matches today (hidden by the dirlist layer).
Allocation: none beyond the cursor's page buffer (refilled internally for object).
Errno on failure: EIO; object ETIMEDOUT mid-pagination.
Returns NGX_DECLINED when: n/a (uses NGX_DONE for end).
Invariants/notes: object pagination must emit every key once — no dup/skip across
  page boundaries (§9.3).
```

```
Slot: closedir
Signature: ngx_int_t (*closedir)(xrootd_sd_dir_t *d)
Thread context: matches opendir context.
Preconditions: d from this driver's opendir; called once, idempotent.
Postconditions: cursor + page buffers freed; pagination state dropped.
Allocation: frees what opendir/readdir allocated.
Errno on failure: EIO (best-effort; still frees).
Returns NGX_DECLINED when: n/a.
Invariants/notes: idempotent against double-close.
```

### 21.6 xattr / object metadata

```
Slot: getxattr
Signature: ssize_t (*getxattr)(xrootd_sd_instance_t *inst, const char *path,
            const char *name, void *buf, size_t cap)
Thread context: event-loop (POSIX) / AIO-worker (object tag/sidecar fetch).
Preconditions: path VFS-confined; CAP_XATTR (or sidecar enabled).
Postconditions: returns value length copied into buf (≤cap), or -1 errno.
  POSIX body == the *xattr_confined_canon helper.
Allocation: none from request pools.
Errno on failure: ENODATA (absent), ERANGE (cap too small), EACCES; ENOTSUP if
  reached on !XATTR with sidecar off.
Returns NGX_DECLINED when: n/a (byte count).
Invariants/notes: object tag/size caps may force a sidecar object (degrade, §8).
```

```
Slot: listxattr
Signature: ssize_t (*listxattr)(xrootd_sd_instance_t *inst, const char *path,
            void *buf, size_t cap)
Thread context: event-loop (POSIX) / AIO-worker (object).
Preconditions: path VFS-confined; CAP_XATTR or sidecar.
Postconditions: returns total length of the NUL-separated name list (≤cap), or -1.
Allocation: none from request pools.
Errno on failure: ERANGE, EACCES; ENOTSUP if !XATTR + no sidecar.
Returns NGX_DECLINED when: n/a (byte count).
Invariants/notes: name set is the XRootD fattr-prefixed set, unchanged on POSIX.
```

```
Slot: setxattr
Signature: ngx_int_t (*setxattr)(xrootd_sd_instance_t *inst, const char *path,
            const char *name, const void *val, size_t len, int flags)
Thread context: event-loop (POSIX) / AIO-worker (object PUT tag / sidecar).
Preconditions: path VFS-confined; write allowed; CAP_XATTR or sidecar.
Postconditions: attribute set; flags carry XATTR_CREATE/REPLACE semantics.
Allocation: none from request pools.
Errno on failure: EEXIST (CREATE collision), ENODATA (REPLACE absent), ENOSPC
  (object tag-count/size cap), EACCES; ENOTSUP if !XATTR + sidecar off.
Returns NGX_DECLINED when: a !XATTR driver MAY decline so the VFS routes to a
  configured sidecar instead of erroring.
Invariants/notes: oversized sets → sidecar object or a clear reject (§8).
```

```
Slot: removexattr
Signature: ngx_int_t (*removexattr)(xrootd_sd_instance_t *inst, const char *path,
            const char *name)
Thread context: event-loop (POSIX) / AIO-worker (object).
Preconditions: path VFS-confined; write allowed; CAP_XATTR or sidecar.
Postconditions: attribute gone (idempotent-missing is the caller's choice).
Allocation: none from request pools.
Errno on failure: ENODATA (absent), EACCES; ENOTSUP if !XATTR + sidecar off.
Returns NGX_DECLINED when: !XATTR with sidecar routing (as setxattr).
Invariants/notes: object tag delete vs sidecar delete chosen by config.
```

### 21.7 Staged / atomic write (driver-own lifecycle; multipart for object)

```
Slot: staged_open
Signature: xrootd_sd_staged_t *(*staged_open)(xrootd_sd_instance_t *inst,
            const char *final_path, mode_t mode, int *err_out)
Thread context: event-loop (POSIX O_EXCL temp create) / AIO-worker (object
  CreateMultipartUpload).
Preconditions: final_path VFS-confined; write allowed; err_out non-NULL.
Postconditions: returns staged handle, or NULL with *err_out. POSIX body ==
  compat/staged_file (O_EXCL temp inside the export root). Object initiates
  multipart and records upload_id. The temp/upload is NEVER client-visible: stat/
  list/read of final_path before commit returns ENOENT (§3.6.3).
Allocation: staged handle from inst pool / ngx_alloc; object buffers a part.
Errno on failure (*err_out): EACCES, ENOSPC, ENOENT (missing parent), EEXIST;
  object ETIMEDOUT/ECONNREFUSED.
Returns NGX_DECLINED when: n/a (returns NULL).
Invariants/notes: this is the driver's OWN atomic-publish lifecycle, distinct
  from the VFS-level promote between a staging store and a backend store (§3.3,
  §3.6.2). A driver implements staged_* without knowing a staging store exists.
```

```
Slot: staged_write
Signature: ssize_t (*staged_write)(xrootd_sd_staged_t *st, const void *buf,
            size_t len, off_t off)
Thread context: AIO-worker. Worker-safe: NO pool/metric/log.
Preconditions: st from this driver's staged_open; for object, off must be
  sequential (VFS validates monotonicity, §5.3); POSIX staging allows any off.
Postconditions: returns bytes accepted, or -1 errno. POSIX pwrites the temp;
  object buffers/uploads a part when the part threshold is reached.
Allocation: none from request pools (a fixed part buffer is driver-private).
Errno on failure: ENOSPC, EDQUOT, EIO; object ETIMEDOUT/ECONNREFUSED.
Returns NGX_DECLINED when: n/a (byte count).
Invariants/notes: the universal write path (§5.3) — POSIX staging gives a
  !RANDOM_WRITE backend full random-write upload support via promote.
```

```
Slot: staged_commit
Signature: ngx_int_t (*staged_commit)(xrootd_sd_staged_t *st, int noreplace)
Thread context: event-loop (POSIX renameat2) / AIO-worker (object
  CompleteMultipartUpload).
Preconditions: all staged_write calls done; st valid.
Postconditions: final_path now holds the bytes, atomically. POSIX == atomic
  renameat2 (RENAME_NOREPLACE when noreplace). Object == the multipart-complete
  is the atomic publish point AND the durability point (§8). After NGX_OK the
  staged handle is consumed.
Allocation: none from request pools.
Errno on failure: EEXIST (noreplace collision), ENOSPC, EIO; object ESTALE
  (ETag/generation mismatch → optimistic-commit conflict, §20.1) / ETIMEDOUT.
Returns NGX_DECLINED when: n/a (the VFS owns the cross-store promote decision,
  §3.6.1; the slot itself just commits the driver's own staged state).
Invariants/notes: the VFS staged-commit body (xrootd_vfs_staged_commit) chooses
  native-rename vs cross-store promote keyed on staging==backend + CAP_HARD_RENAME;
  on identity it calls this slot on the single shared instance with zero extra copy.
```

```
Slot: staged_abort
Signature: void (*staged_abort)(xrootd_sd_staged_t *st)
Thread context: either (POSIX unlink temp; object AbortMultipartUpload may
  offload).
Preconditions: st valid; called instead of commit on failure/cancel.
Postconditions: temp/multipart discarded; final_path unchanged (still ENOENT if
  it never existed). Idempotent and best-effort.
Allocation: frees staged handle state; allocates nothing.
Errno on failure: none (void; a failed object abort is logged, leaving a temp the
  staging-store sweeper reclaims, §9.3 crash window).
Returns NGX_DECLINED when: n/a.
Invariants/notes: must leave NO visible final object (§7.1, 55.E acceptance).
```

### 21.8 Helper API (around the vtable; callers never touch driver->* directly)

```
Helper: xrootd_sd_caps
Signature: uint32_t xrootd_sd_caps(const xrootd_sd_obj_t *obj)
Thread context: either (pure read of a cached bitmap).
Preconditions: obj valid (or NULL).
Postconditions: returns the driver's xrootd_sd_cap_t bitmap; 0 if obj NULL.
Allocation: none. Errno on failure: none.
Returns NGX_DECLINED when: n/a.
Invariants/notes: const, side-effect-free; safe on the worker path.
```

```
Helper: xrootd_sd_fd
Signature: ngx_fd_t xrootd_sd_fd(const xrootd_sd_obj_t *obj)
Thread context: either.
Preconditions: obj valid.
Postconditions: returns the real kernel fd when CAP_FD, else
  NGX_INVALID_FILE (§3.2). The ONLY sanctioned fd accessor after
  xrootd_vfs_file_fd() is retired (§6.1).
Allocation: none. Errno on failure: none (returns NGX_INVALID_FILE).
Returns NGX_DECLINED when: n/a.
Invariants/notes: callers MUST check the result before sendfile/io_uring; a
  !CAP_FD backend always yields NGX_INVALID_FILE so no file-backed buf is built.
```

```
Helper: xrootd_sd_supports
Signature: ngx_int_t xrootd_sd_supports(const xrootd_sd_instance_t *inst,
            uint32_t required_caps)
Thread context: either.
Preconditions: inst valid.
Postconditions: NGX_OK iff (inst->caps & required_caps) == required_caps, else
  NGX_DECLINED. This is the policy-readable gate (§3.3.1) the VFS uses instead of
  scattered driver->caps & ... branches.
Allocation: none. Errno on failure: caller sets errno=ENOTSUP on the decline.
Returns NGX_DECLINED when: any required cap is absent.
Invariants/notes: pure; the single chokepoint that drives the §20.4 reject path.
```

```
Helper: xrootd_sd_stat_to_vfs
Signature: void xrootd_sd_stat_to_vfs(const xrootd_sd_stat_t *in,
            xrootd_vfs_stat_t *out)
Thread context: either (worker-safe: pure copy).
Preconditions: both pointers non-NULL.
Postconditions: zeroes *out, copies size/mtime/ctime/mode/ino, sets
  is_directory/is_regular from mode — the xrootd_vfs_fill_stat shape, sourced from
  the SD stat instead of struct stat.
Allocation: none. Errno on failure: none (silent no-op on NULL).
Returns NGX_DECLINED when: n/a.
Invariants/notes: the protocol-neutral bridge; keeps backend stat types private.
```

```
Helper: xrootd_sd_backend_name
Signature: const char *xrootd_sd_backend_name(const xrootd_sd_instance_t *inst)
Thread context: either.
Preconditions: inst valid.
Postconditions: returns the driver name ("posix"|"block"|"s3"); a stable literal.
Allocation: none. Errno on failure: none.
Returns NGX_DECLINED when: n/a.
Invariants/notes: safe as a low-cardinality `backend` metric label and a log
  detail token; NEVER use a path/key/bucket as a label (§3.5).
```


## 22. Capacity & sizing model

This section gives operators the formulas and worked numbers needed to size a
deployment running the **headline mode** — POSIX staging in front of a slow
object/S3 backend — without guessing. Everything here is downstream of the
§3.6 store binding and the Phase-31 transfer-heap memory budget
(`xfer_heap_in_use` / `budget_waits_total` / `xrootd_memory_budget`, see
`src/observability/metrics/metrics.h`). None of it changes the default `staging==backend`
POSIX deployment, which keeps today's sizing exactly.

The four capacity dimensions are independent and must each be sized:

1. **Staging-store disk** — bytes parked on the POSIX scratch mount while uploads
   complete and promotes drain (§22.1).
2. **Multipart part size** — the S3 chunking granularity, which bounds the
   maximum object size and feeds back into AIO buffer sizing (§22.2).
3. **Worker memory** — object range-GET is always memory-backed (no fd, no
   sendfile), so it draws on the Phase-31 windowed-read budget (§22.3).
4. **Transport pool** — per-worker HTTP(S) connections to the object endpoint
   vs worker count and AIO pool depth (§22.4).

---

### 22.1 Staging-store sizing

#### 22.1.1 The model

The staging store is a queue with arrivals (uploads landing bytes) and a service
process (promotes draining bytes into the backend). The high-water occupancy is a
Little's-law steady state plus a burst headroom term. Define:

| Symbol | Meaning | Typical |
|---|---|---|
| `C` | peak concurrent in-flight uploads (sessions writing to staging) | from connection limit / `xrootd_max_connections` |
| `S` | mean staged object size | workload-dependent |
| `T_up` | mean wall-clock to receive a full upload onto staging (client→staging) | `S / client_throughput` |
| `T_pr` | mean wall-clock to promote one staged object into the backend (staging read + multipart PUT) | `S / backend_throughput` |
| `R_pr` | sustained promote completion rate the backend can absorb | `P_pool / T_pr` (see below) |
| `P_pool` | promote concurrency = AIO pool threads available for promote work | `xrootd_aio_threads` budget |

**Residency time per object** on the staging mount is `T_up + T_queue + T_pr`,
where `T_queue` is the time a completed-but-not-yet-promoted object waits for a
free promote slot. An object's bytes occupy staging from the first `pwrite` until
the post-promote `unlink`.

**Steady-state staging occupancy** (bytes):

```
B_stage ≈ S × ( C_uploading  +  N_awaiting_promote  +  P_pool )
            └ receiving ┘      └ queued ┘             └ promoting ┘
```

When promote keeps up (`arrival_rate ≤ R_pr`), `N_awaiting_promote ≈ 0` and the
mount only holds objects that are actively being received or actively being
promoted:

```
B_stage_min ≈ S × (C + P_pool)
```

When promote is **backend-bound** (the object endpoint is slower than ingest,
the failure mode the staging store exists to absorb), the awaiting-promote queue
grows at `(arrival_rate − R_pr)` until admission control (§22.1.3) caps it. The
**high-water mark** you must provision for is therefore the queue cap, not the
steady state.

#### 22.1.2 Worked example

Workload: a CMS export, 1 GiB mean object, 64 concurrent uploads, a 10 GbE
client side and a 2 GbE-effective object endpoint, AIO pool of 8 promote slots.

| Quantity | Value |
|---|---|
| `S` | 1 GiB |
| `C` | 64 |
| client throughput / upload | ~250 MiB/s ⇒ `T_up ≈ 4 s` |
| backend throughput / promote | ~120 MiB/s ⇒ `T_pr ≈ 8.5 s` |
| `P_pool` | 8 |
| `R_pr` | `8 / 8.5 s ≈ 0.94 promotes/s` ⇒ ~0.94 GiB/s drained |
| ingest rate at `C=64`, `T_up=4 s` | `64 / 4 = 16 uploads/s` ⇒ ~16 GiB/s offered |

Ingest (16 GiB/s) hugely exceeds drain (0.94 GiB/s): the backend is the
bottleneck and the awaiting-promote queue would grow without bound. This is the
canonical case the staging store must bound. Sizing decision:

- **Floor (drain keeps up):** `B_stage_min = 1 GiB × (64 + 8) = 72 GiB`. This is
  the minimum you would ever need even if the backend were infinitely fast.
- **Headroom for a realistic burst:** set a high-water cap that lets, say, 256
  objects queue for promote before shedding: `256 × 1 GiB = 256 GiB`, plus the
  72 GiB working set ⇒ provision **~328 GiB** of staging, set **high-water at
  ~75 % (≈246 GiB)** and **low-water at ~50 % (≈164 GiB)**.

Rule of thumb for the cap: `B_highwater = S × (C + P_pool + Q_burst)` where
`Q_burst` is the number of completed uploads you are willing to hold while the
backend catches up. Provision the mount to `B_highwater / utilization_target`
(target ≤ 0.8 so the filesystem never runs at the wall).

#### 22.1.3 Shed via `kXR_wait` (soft) vs hard `ENOSPC`

Two thresholds, two mechanisms — and they are deliberately different layers:

| Trigger | Threshold | Mechanism | Client sees | Metric |
|---|---|---|---|---|
| Staging crosses **high-water** | configurable, e.g. 75 % of mount or an absolute byte cap | **admission control** — reuse the Phase-31 budget path: defer the *open*/first-write of a *new* upload with `kXR_wait` (root://) / `503 Retry-After` (WebDAV/S3) until occupancy drops below **low-water** | retriable wait, no error | `xrootd_sd_degraded_total{op=staged_open,reason=staging_backpressure}` + Phase-31 `budget_waits_total` |
| Staging hits the **filesystem wall** | actual `ENOSPC` from the staging driver | **hard fail** — the staged `pwrite` returns `ENOSPC`; abort the staged object, return `kXR_IOError`/507 | error, upload fails | `xrootd_sd_ops_total{backend=posix,op=staged_write,status=error}` |

Design intent: high-water/low-water **admission control** is the primary
back-pressure valve and should fire *long before* the mount fills, so the client
experiences a transient `kXR_wait` rather than a failed transfer. `ENSPC` is the
last-resort guard for when promote stalls completely (dead endpoint) and the cap
is mis-sized — it must never be the normal back-pressure path. Admission control
gates *new* uploads only; in-flight uploads that already have staging bytes are
allowed to finish (they are part of the working set you provisioned for), which
prevents a thrash where half-written objects are abandoned. This mirrors the
Phase-31 rule that the memory budget defers *reads* it has not yet started, never
ones mid-flight. The hysteresis band (high-water arm, low-water disarm) prevents
flapping between admit and shed on every promote completion.

Open question §12.6 is resolved by this section: **reuse the Phase-31
budget/`kXR_wait` mechanism for staging back-pressure**, keyed on a staging-store
occupancy gauge instead of `xfer_heap_in_use`; hard `ENOSPC` remains only as the
floor.

---

### 22.2 Multipart part sizing

#### 22.2.1 The hard constraints

S3 multipart upload imposes two fixed limits that together cap the maximum
promotable object size:

- **minimum part size = 5 MiB** (every part except the last);
- **maximum part count = 10 000.**

Therefore `max_object_size = part_size × 10 000`. The part size is the single
knob that trades small-object efficiency against large-object reach:

| `part_size` | max object | parts for a 1 GiB object | parts for a 1 TiB object |
|---|---|---|---|
| 5 MiB (min) | ~48.8 GiB | 205 | (exceeds 10 000 — rejected) |
| 16 MiB | ~156 GiB | 64 | 65 536 → exceeds, rejected |
| 64 MiB | ~625 GiB | 16 | 16 384 → exceeds, rejected |
| 128 MiB | ~1.22 TiB | 8 | 8 192 |
| 256 MiB | ~2.44 TiB | 4 | 4 096 |

The driver must **not** pick a too-small part size and then fail a large promote
at part 10 001 — that is a late, surprising failure. Instead it computes a part
size large enough that `ceil(staged_size / part_size) ≤ 10 000`, given the staged
object's *already-known* size at promote time (the staging file has a final size
before promote begins — a key advantage of staging first). Concretely:

```
effective_part = max( configured_part_size,
                      round_up_to_MiB( staged_size / 10000 ) )
```

So the configured value is a *floor/hint*; the promote escalates it when needed.
If even `staged_size / 10000` would exceed the S3 maximum part size (5 GiB), the
object is too large for a single multipart upload and the promote fails cleanly
with `EFBIG`→`kXR_IOError`/413, surfaced as
`xrootd_sd_ops_total{op=staged_commit,status=error}`.

#### 22.2.2 Interaction with the AIO buffer and Phase-31 windowed read

Promote is a `pread(staging) → staged_write(backend part)` loop running on an AIO
pool thread. The natural part buffer is one AIO scratch buffer; the part size
therefore directly sizes a transient allocation **per concurrent promote**:

```
promote_memory = P_pool × part_size
```

With the §22.1.2 example (`P_pool=8`) and a 128 MiB part: `8 × 128 MiB = 1 GiB`
of transient promote buffers across the worker. This memory is **part of the
Phase-31 transfer-heap budget** — promote buffers must be charged to
`xfer_heap_in_use` exactly like a windowed read, so that a flood of large-part
promotes is admission-controlled by the same budget and cannot OOM a worker. A
large part size improves S3 throughput (fewer round-trips, fewer
`CreateMultipartUpload`/`CompletePart` overheads) but linearly inflates this
buffer footprint, so the two must be tuned together with `P_pool`.

To keep part-buffer memory bounded independently of part size, the promote loop
may stream a part in **windowed sub-chunks** (e.g. 8 MiB) using S3 chunked
transfer-encoding within the part, reusing the Phase-31 windowed-read pattern:
~8 MiB resident per promote regardless of part size, at the cost of not being
able to retry a part without re-reading from staging (staging is durable, so
re-read is cheap). This is the recommended default for large parts.

#### 22.2.3 Recommended defaults + config knob

```nginx
xrootd_storage_s3_part_size 64m;   # default; floor/hint, auto-escalated per object
```

| Knob | Default | Rationale |
|---|---|---|
| `xrootd_storage_s3_part_size` | **64 MiB** | covers objects up to ~625 GiB at the floor; good throughput/round-trip balance; auto-escalates for larger objects so no operator math is required for the common case |
| (validated) min | 5 MiB | S3 floor; values below are rejected at `nginx -t` |
| (validated) max | 5 GiB | S3 ceiling; above is rejected |
| windowed sub-chunk | 8 MiB | matches Phase-31 ~2–8 MiB resident windowing; keeps part-buffer memory flat |

Validation at `nginx -t`: reject `< 5m` or `> 5g`; **warn** if `part_size` is so
small that common workload object sizes would approach the 10 000-part cap
(point the operator at a larger value). No network call is made to validate.

---

### 22.3 Memory budget

#### 22.3.1 Why object reads are always memory-backed

An object SD instance advertises `!CAP_FD` and `!CAP_SENDFILE` (§3.1). Per the
§5.1 capability-gated buffer rule, every read from an object backend is served as
a **memory chain** (`pread`-equivalent range-GET into `ngx_pnalloc`,
`b->memory=1`) — there is no fd to `dup`, no `in_file` buf, no sendfile, for
cleartext or TLS. This is exactly the existing TLS read path, so the data-plane
code is unchanged; only the *fraction* of traffic on the memory path goes to
100 % for an object export.

The consequence for capacity: an object export cannot lean on the kernel page
cache + sendfile to serve reads with near-zero application memory. Every in-flight
read byte is application-resident. This makes the **Phase-31 windowed read +
memory budget the load-bearing control** for object reads, not an optimization.

#### 22.3.2 Per-request and per-worker bounds

The Phase-31 windowed read already caps a single read response to a sliding
window (~2 MiB resident target, see the Phase-31 200 MB-TLS-at-~2 MB-resident
memo) rather than buffering the whole object: a 200 GiB range-GET streams through
a small window, charged to `xfer_heap_in_use`. For an object backend this is
mandatory and must be enforced regardless of TLS, because there is no sendfile
fallback for the cleartext case.

| Bound | Value | Enforced by |
|---|---|---|
| per-request resident read window | ~2 MiB target (windowed); never the full object | Phase-31 windowed read in `vfs_read.c` |
| per-request range-GET fetch unit | one window's worth per backend range-GET round-trip | object driver `pread` honoring the window length |
| per-worker total read residency | `xrootd_memory_budget` (the transfer-heap cap) | `xfer_heap_in_use` gauge + `kXR_wait` shed |
| per-worker promote-buffer residency | `P_pool × part_window` (§22.2.2), **also** charged to the budget | same budget |

The single invariant: **object read windows and promote part buffers share one
budget** (`xfer_heap_in_use`). When the sum approaches `xrootd_memory_budget`, new
reads are deferred with `kXR_wait` (incrementing `budget_waits_total`) exactly as
Phase-31 does today — the object backend gets memory back-pressure for free
because it routes through the same windowed-read accounting. Operators size
`xrootd_memory_budget` so that:

```
xrootd_memory_budget  ≥  (expected_concurrent_reads × read_window)
                       +  (P_pool × part_window)
                       +  Phase-31 baseline headroom
```

With 64 concurrent reads × 2 MiB + 8 promotes × 8 MiB ≈ 128 MiB + 64 MiB ≈
**~192 MiB** of data-plane residency for the §22.1.2 example — comfortably small
because nothing buffers a whole object. A misconfiguration that disables
windowing (full-object buffering) on an object export would multiply this by
object size and is rejected.

---

### 22.4 Connection / transport pooling

#### 22.4.1 The pool

Every object SD operation (HEAD, range-GET, PUT-part, CopyObject, DELETE,
ListObjectsV2) is a blocking HTTP(S) request executed on an **AIO pool thread**
(§5.5). Each such request needs a TCP+TLS connection to the object endpoint.
Establishing TLS per request is prohibitively expensive (handshake RTTs +
asymmetric crypto), so the object transport (`sd_object_s3.c`) keeps a
**per-worker pool of keep-alive connections** to the endpoint, reused across
operations.

Pool ownership is **per worker process**, not per SD instance and not global:
nginx workers do not share fds, and the connections are driven from AIO threads
that belong to the worker. The pool is keyed by `(endpoint host, port, scheme)`
so two exports pointing at the same endpoint share one pool within a worker.

#### 22.4.2 Sizing

The useful concurrency of object I/O is bounded by the **AIO pool thread count**,
because a blocking request occupies a thread for its whole duration. There is no
benefit to more keep-alive connections than threads that can drive them:

```
pool_max_conns_per_worker  ≈  ceil( aio_threads × endpoint_concurrency_factor )
```

| Parameter | Guidance |
|---|---|
| `aio_threads` (`xrootd_aio_threads`) | the real concurrency ceiling for object I/O; size to the endpoint's useful parallelism, not CPU count (these threads are I/O-bound on the network) |
| `pool_max_conns_per_worker` | start at `aio_threads` (1:1) so every busy thread has a warm connection; add ~25 % headroom for HEAD/stat bursts that interleave with long GET/PUT |
| `pool_idle_timeout` | trim idle connections after ~60 s so a quiet worker does not pin endpoint connection slots |
| total endpoint connections | `worker_processes × pool_max_conns_per_worker` — check this against the endpoint's per-client connection limit (S3 gateways and load balancers cap this) |

Worked: 16 workers × (`aio_threads=8` × 1.25 ≈ 10) = **160 endpoint connections**
at full load. If the endpoint or LB caps a single source IP at, say, 128, either
reduce `pool_max_conns_per_worker`, reduce `aio_threads`, or front the endpoint
with more source IPs. The pool must **fail closed**: when no connection is
available and the cap is reached, the op queues on the AIO pool (already its
natural back-pressure) rather than opening an unbounded number of sockets.

#### 22.4.3 Pool vs promote vs read contention

Promotes and reads draw from the **same** AIO pool and therefore the same
connection pool. A burst of promotes (each a long multipart PUT holding a thread
+ connection) will starve reads of threads/connections, manifesting as read
latency growth, not errors. Operators who need read-latency isolation from
promote bursts should provision a larger `aio_threads` and accept the extra
endpoint connections, or (future) split read and promote onto separate pools.
Either way the symptom is visible in `xrootd_sd_latency_seconds{op=read}` rising
in lockstep with `{op=staged_commit}` volume — see the runbook §24.3.

---

## 23. Failure-injection matrix

Storage-driver faults the POSIX backend cannot exercise, plus the staging/promote
faults the two-store binding introduces. Mirrors the phase-44 §28 layout. All
"Metric/log" entries obey CLAUDE.md invariant #8 — **no path/bucket/key/upload-id/
ETag/issuer label values** (those go to sanitized access/debug logs only); metric
labels are the low-cardinality `backend`/`op`/`status`/`reason`/`direction` enums
from §3.5. Test hooks reference `tests/test_storage_backend_matrix.py` (§9.1) and
`tests/test_storage_failures.py` (the §9.3 injection suite) using a mock S3
(`moto`/MinIO fault modes).

| # | Fault | Where injected | Expected behaviour | Client-visible result | Metric / log | Test hook |
|---|---|---|---|---|---|---|
| 1 | Object 404 after LIST showed key | object `open`/`stat` HEAD | map missing object to `ENOENT`; no retry storm | `kXR_NotFound` / 404 | `sd_ops_total{backend=s3,op=stat,status=error}`; debug log `enoent` | `test_storage_failures.py::test_head_404_after_list` (mock HEAD 404) |
| 2 | Multipart part N upload fails (5xx) | backend `staged_write` part PUT | bounded retry of the part; on exhaustion `staged_abort` (AbortMultipartUpload) | upload fails `kXR_IOError`/500; **no** visible final object | `sd_ops_total{op=staged_write,status=error}`; degraded `reason=part_retry` on retry | `::test_multipart_part_fail` (mock fails part 3) |
| 3 | CompleteMultipartUpload ETag/stale mismatch | backend `staged_commit` | commit fails, **no silent success**; abort upload; final path not published | `kXR_IOError` / 409 | `sd_ops_total{op=staged_commit,status=error}`; log `estale` | `::test_complete_etag_mismatch` |
| 4 | Weak rename: CopyObject ok, Delete fails | backend `rename` (weak) | destination exists, source remains; non-atomic window logged loudly | rename reports success of copy, warns leftover source | `sd_degraded_total{op=rename,reason=weak_rename}` + log `weak_rename delete_failed` | `::test_weak_rename_delete_fail` (requires `weak_rename on`) |
| 5 | Credential expires mid-transfer | transport auth on next request | refresh per `auth` policy; if unrefreshable, fail op | `kXR_NotAuthorized`/403 or `kXR_IOError`/504 per config | `sd_ops_total{op,*,status=error}`; log `cred_expired` (no issuer label) | `::test_cred_expiry_midtransfer` |
| 6 | ListObjectsV2 pagination gap/dupe | object `opendir`/`readdir` | continuation-token loop yields every key once, no skip/dupe | dirlist complete, stable order | `sd_ops_total{op=readdir,status=ok}`; existing S3 pagination metric | `::test_list_pagination_no_dupes` (mock truncated pages) |
| 7 | Staging `ENOSPC` mid-upload | staging `staged_write` (POSIX) | fail before any backend write; abort staged object; nothing in backend | `kXR_IOError` / 507 | `sd_ops_total{backend=posix,op=staged_write,status=error}` | `::test_staging_enospc` (small tmpfs staging root) |
| 8 | Promote crash window (worker killed between backend commit and staging unlink) | kill worker after `staged_commit` ok, before `unlink` | restart: durable object present; at most a stale staging temp; **never** a missing object | next read of final path succeeds | reclamation sweep logs `staging_temp_reaped`; `sd_degraded_total{op=commit,reason=promote}` recorded pre-crash | `::test_promote_crash_window` (SIGKILL hook) |
| 9 | Endpoint connection refused | transport connect | op fails fast (no event-loop block — runs on AIO thread); pool marks endpoint down briefly | `kXR_IOError` / 502 | `sd_ops_total{op,*,status=error}`; log `connect_refused` | `::test_endpoint_conn_refused` (closed port) |
| 10 | Endpoint timeout (slow/blackhole) | transport request deadline | op aborts at deadline; connection torn down not returned to pool | `kXR_IOError` / 504 | `sd_ops_total{status=error}`; `sd_latency_seconds{op}` tail; log `etimedout` | `::test_endpoint_timeout` (mock delay > deadline) |
| 11 | Partial range-GET short read | object `pread` (range-GET returns fewer bytes than requested) | treat as short read; retry remainder within window; if EOF-before-len, surface `EIO` | correct bytes or `kXR_IOError`/500 | `sd_ops_total{op=read,status=error}` on unrecoverable short read | `::test_range_short_read` |
| 12 | Concurrent commit to same final path | two `staged_commit` race on one key | last-writer-wins per backend; both clients get a definite result (one may `ESTALE`/409 if conditional) | one success, other success-or-409 | `sd_ops_total{op=staged_commit}` ok+error; log `commit_race` | `::test_concurrent_commit_same_path` |
| 13 | Staging temp orphan reclamation | leave temp older than reap age | sweeper (`compat/staged_file` extended) unlinks temps past `xrootd_storage_staging_reap_age`; never touches in-flight | none (background) | `sd_ops_total{backend=posix,op=staged_abort,status=ok}` for reaped; log `staging_temp_reaped` count | `::test_staging_orphan_reclaim` (pre-seed old temp) |
| 14 | Backend prefix-escape attempt (`../` after key map) | object driver key confinement | reject before any network call; key cannot leave `s3_prefix` | `kXR_NotAuthorized` / 403 | `sd_ops_total{op,*,status=error}`; log `prefix_escape` | `test_attack_vectors.py` vs s3 backend |
| 15 | Staging-root escape attempt (symlink/`..`) | staging `RESOLVE_BENEATH` | `openat2` refuses; `EXDEV`→escape normalized | `kXR_NotAuthorized` / 403 | `sd_ops_total{backend=posix,status=error}`; log `staging_escape` | `test_attack_vectors.py` vs staging root |
| 16 | Reload during in-flight promote | `nginx -t`/reload mid-promote | drain semantics: in-flight promote finishes on old worker; new conns get new binding; instances rotate on reload | transfer completes; no truncation | `xrootd_config_generation` bump; log `reload drain promote_inflight=N` | `::test_reload_during_promote` |
| 17 | AIO pool saturation (all threads busy) | flood promotes + reads | new ops queue on AIO pool (back-pressure), not unbounded sockets; read latency rises, no errors | slower, not failed | `sd_latency_seconds{op}` tail growth; no `status=error` | `::test_aio_saturation` |
| 18 | Random `kXR_write` hole direct to object backend (`!RANDOM_WRITE`, no staging) | VFS write policy gate | reject with `ENOTSUP`; no partial mutation | `kXR_Unsupported` / 501 | `sd_unsupported_total{backend=s3,op=write}` | `test_storage_backend_matrix.py` random-write row |
| 19 | Random/out-of-order upload **with** POSIX staging | staging accepts; promote sequential | upload succeeds; lands one sequential backend object | success; byte-exact + cksum | `sd_degraded_total{op=commit,reason=promote}`; backend `sd_bytes_total{direction=write}` | matrix "random upload via staging" row |
| 20 | `pgwrite`/`writev` direct to object backend | VFS write policy gate | reject; page-CRC fine, random page mutation not | `kXR_Unsupported` / 501 | `sd_unsupported_total{op=pgwrite\|writev}` | matrix pgwrite/writev rows |
| 21 | Truncate on `!CAP_TRUNCATE` backend | VFS truncate gate | reject; **no** size change | `kXR_Unsupported` / 501 | `sd_unsupported_total{op=truncate}` | matrix truncate row |
| 22 | `fsync` on object backend (no-op durability) | backend `fsync` | return `NGX_OK` (commit is the durability point); documented no-op | success | none (intentionally silent; documented §8) | `::test_object_fsync_noop` |
| 23 | xattr exceeds object tag limit | backend `setxattr` | fall back to sidecar object if enabled, else reject clearly | success (sidecar) or `kXR_error`/403 | `sd_degraded_total{op=setxattr,reason=sidecar}` or unsupported | `::test_xattr_overflow_sidecar` |
| 24 | CopyObject unsupported (cross-bucket) | backend `server_copy` returns `NGX_DECLINED` | VFS stream-through pread→pwrite fallback | success, byte-exact (slower) | `sd_degraded_total{op=copy,reason=stream_copy}` | matrix copy row, cross-bucket |
| 25 | Sendfile attempt on object read | VFS buffer-shape decision | force memory-backed chain (`!CAP_SENDFILE`); never build `in_file` buf | success; same bytes as TLS path | `sd_degraded_total{op=read,reason=sendfile_fallback}` | matrix cleartext-sendfile row |
| 26 | Backend `staged_abort` itself fails (orphan multipart) | abort path network error | log loudly; rely on backend lifecycle policy / reclamation; never block client | client already saw the original failure | `sd_ops_total{op=staged_abort,status=error}`; log `multipart_abort_failed` | `::test_abort_fails_orphan_mpu` |
| 27 | Promote read of staging temp fails (staging fault mid-promote) | staging `pread` during promote | abort backend multipart; leave staging temp for retry/reap; final not published | upload fails `kXR_IOError`/500 | `sd_ops_total{backend=posix,op=read,status=error}` + abort | `::test_promote_staging_read_fail` |
| 28 | Backend returns 503 SlowDown / throttle | transport on any op | honor `Retry-After`/backoff on AIO thread; surface `kXR_wait`-style retry where the op allows | retriable wait or eventual error | `sd_degraded_total{op,reason=throttle}` then ok/error | `::test_backend_slowdown_503` |
| 29 | Staging high-water back-pressure | staging occupancy ≥ high-water | defer new upload `open` with `kXR_wait`/503 until low-water | retriable wait, no error | `sd_degraded_total{op=staged_open,reason=staging_backpressure}` + `budget_waits_total` | `::test_staging_highwater_backpressure` |
| 30 | Object too large for multipart (>10k parts at max part size) | promote part-count check | fail cleanly before upload; do not start a doomed multipart | `kXR_IOError` / 413 | `sd_ops_total{op=staged_commit,status=error}`; log `object_too_large` | `::test_object_exceeds_multipart_cap` |
| 31 | Endpoint TLS cert invalid / hostname mismatch | transport TLS handshake | fail closed at connect; do not fall back to cleartext | `kXR_IOError` / 502 | `sd_ops_total{status=error}`; log `tls_verify_failed` | `::test_endpoint_tls_verify_fail` |

---

## 24. Observability & operational runbook

### 24.1 The full SD metric set

Reproduces and extends §3.5. These are **new** metric families that appear only
once a non-POSIX backend or capability degradation is selectable; the POSIX-only
phases (55.A–C) add nothing. All counter/histogram names are Prometheus-style and
live alongside the existing `xrootd_*` exporter output (`src/observability/metrics/`).

| Metric | Type | Labels | Notes |
|---|---|---|---|
| `xrootd_sd_ops_total` | counter | `backend`, `op`, `status` | every SD op; `status ∈ {ok, error, unsupported, degraded}` |
| `xrootd_sd_bytes_total` | counter | `backend`, `op`, `direction` | raw backend bytes; `direction ∈ {read, write}`; promote bytes counted against the **backend** store |
| `xrootd_sd_latency_seconds` | histogram | `backend`, `op` | blocking-op latency, primarily object-store calls; reuses the unified latency-bucket layout (`XROOTD_IO_LATENCY_BUCKETS`) |
| `xrootd_sd_degraded_total` | counter | `backend`, `op`, `reason` | a capability fallback fired; see reason enum below |
| `xrootd_sd_unsupported_total` | counter | `backend`, `op` | an op was refused because the capability is absent |

**Label value domains (all low-cardinality enums — fixed, bounded, no free-form
strings):**

| Label | Allowed values |
|---|---|
| `backend` | `posix`, `block`, `s3` (the driver `name`; bounded by registered drivers) |
| `op` | `open`, `close`, `read`, `write`, `pread`, `pwrite`, `stat`, `fstat`, `truncate`, `fsync`, `unlink`, `mkdir`, `rename`, `copy`, `readdir`, `getxattr`, `setxattr`, `staged_open`, `staged_write`, `staged_commit`, `staged_abort`, `commit` (the bounded vtable op set) |
| `status` | `ok`, `error`, `unsupported`, `degraded` |
| `direction` | `read`, `write` |
| `reason` | `sendfile_fallback`, `stream_copy`, `weak_rename`, `sidecar`, `promote`, `staging_backpressure`, `part_retry`, `throttle` (the fixed degradation-reason enum) |

**Cardinality rules (CLAUDE.md invariant #8 — non-negotiable):**

- **NEVER** add a label whose value is a path, bucket name, object key, upload id,
  ETag, generation, endpoint host:port, region, credential, token issuer, VO, DN,
  or user identity. Total series for the SD families is bounded by
  `|backend| × |op| × |status|` (≈ 3 × 23 × 4 ≈ 276 for `ops_total`) — a constant,
  not a function of traffic.
- Per-object/per-key/per-upload detail lives **only** in the sanitized JSON access
  log (`access_log.c`, which already `\uXXXX`-escapes) and debug logs — exactly
  where free-form identity safely lives today. The SD supplies a short reason
  string (e.g. `backend=s3 degraded=stream_copy`) for the access-log *detail
  field*, never as a metric label.
- Endpoint reachability, ETag mismatches, and credential issues go to logs with
  the backend **name** (low-cardinality, safe) but never the endpoint host or key.

### 24.2 `/healthz` + startup-log additions

Both must reflect the **store binding** (§3.6), not a single backend, and must
work at `nginx -t` **without any network call** to the endpoint.

`/healthz` JSON gains, per export/server block:

```json
"storage": {
  "backend": { "name": "s3",    "caps": "RANGE_READ|SERVER_COPY|XATTR",
               "endpoint_configured": true, "reachable": "unknown" },
  "staging": { "name": "posix", "caps": "FD|SENDFILE|RANDOM_WRITE|RANGE_READ|TRUNCATE|SERVER_COPY|XATTR|HARD_RENAME|DIRS|APPEND|IOURING",
               "root_configured": true },
  "promote": "cross_store"          // or "native_rename" when staging==backend
}
```

Rules:
- **both** store names + capability bitmaps are always present; `staging==backend`
  is reported as the same name and `promote: native_rename`;
- `reachable` is `"unknown"` until a live op or an explicit, opt-in
  `validate_backend on` probe runs — `nginx -t` and a fresh `/healthz` make **no**
  network call (consistent with §6.5: bucket/prefix/staging-root *syntax* is
  validated at config time, reachability is not);
- a background reachability probe (if enabled) updates `reachable` to
  `"ok"`/`"degraded"`/`"unreachable"` and is the only thing that ever talks to the
  endpoint outside the data path.

**Startup log** (one line per export, at worker init): both store names, both
capability bitmaps, the promote mode, the staging root, and the resolved
`part_size`/`memory_budget`/`aio_threads`. Example:

```
xrootd: export /store backend=s3(RANGE_READ|SERVER_COPY|XATTR) staging=posix(... full ...)
        promote=cross_store staging_root=/var/lib/xrootd/staging part_size=64m
        aio_threads=8 memory_budget=512m
```

The startup log is also where the §6.5 warnings fire: `staging==backend` with a
`!RANDOM_WRITE` backend logs a WARN naming the missing capability and pointing at
a POSIX staging store; `weak_rename on` logs a WARN about the non-atomic window.

### 24.3 Operator runbook entries

| Symptom | Likely cause | Diagnose | Fix |
|---|---|---|---|
| **Uploads failing with 501 (`kXR_Unsupported`)** | a client is doing a random/out-of-order/`pgwrite`/`writev`/checkpoint write **directly against the object backend** (no POSIX staging store) — see §5.3 policy table | `xrootd_sd_unsupported_total{backend=s3,op=write\|pgwrite\|writev}` rising; access log shows the op | **Add a POSIX staging store** (`xrootd_storage_staging posix; xrootd_storage_staging_root …`). With staging, random/checkpointed *uploads* land on POSIX and promote sequentially. 501 is correct only for re-mutating an *already-committed* object — that is a true limitation. |
| **Staging mount filling toward high-water** | promote lag: ingest faster than the backend drains (§22.1) | staging occupancy gauge near high-water; `sd_degraded_total{reason=staging_backpressure}` and `budget_waits_total` climbing; `sd_latency_seconds{op=staged_commit}` high | Back-pressure is working (clients see `kXR_wait`, not errors). To raise throughput: increase `aio_threads`/`P_pool`, grow the staging mount and the high-water cap (§22.1.2), or fix the slow endpoint. If it hits `ENOSPC`, the cap is mis-sized — raise the mount and lower high-water. |
| **Promote latency spike** | endpoint/network: slow S3, throttling (503 SlowDown), packet loss, or TLS renegotiation | `sd_latency_seconds{op=staged_commit\|staged_write}` p99 spike; `sd_degraded_total{reason=throttle}`; `sd_ops_total{status=error}` for `etimedout`; pool connection churn in logs | Check the endpoint/LB; raise transport deadline if it is genuine latency not a hang; verify keep-alive pool not being torn down each op (§22.4); confirm not exceeding endpoint per-IP connection cap. |
| **Orphaned staging temps accumulating** | crashes in the promote crash-window (§9.3) leaving temps after a successful backend commit, or aborted uploads | staging root temp count growing; `sd_ops_total{backend=posix,op=staged_abort}`/log `staging_temp_reaped` | Confirm the reclamation sweep runs (`xrootd_storage_staging_reap_age` set; extended `compat/staged_file` cleanup scanning the staging root). Temps past reap-age are unlinked automatically; a durable object is **never** lost — only the temp is stale. Tune reap-age down if accumulation is fast. |
| **Weak-rename non-atomic window warning** | `xrootd_storage_s3_weak_rename on`: rename = CopyObject + Delete with a window where both src and dst exist (or, on Delete failure, src leaks) | `sd_degraded_total{op=rename,reason=weak_rename}`; log `weak_rename delete_failed` | This is inherent to object stores without atomic rename. Prefer designs that don't rename committed objects. If Delete failed (#4), the leftover source must be cleaned manually or by a sweep; the log names it. Keep `weak_rename off` unless the operator accepts the non-atomic window. |
| **Reads slow whenever promotes spike** | reads and promotes share one AIO pool + connection pool (§22.4.3) | `sd_latency_seconds{op=read}` rising in lockstep with `{op=staged_commit}` volume; no `status=error` | Provision more `aio_threads` (accept more endpoint connections), or accept the coupling. Reads are degraded, not failing. |
| **`reachable: unreachable` in /healthz** | endpoint down/DNS/TLS-verify (#9, #31) — but only surfaces if `validate_backend on` or a live op ran | `sd_ops_total{status=error}` for connect/tls; healthz `reachable`; log `connect_refused`/`tls_verify_failed` | This never fails `nginx -t` by design. Fix the endpoint/credentials/CA; the data path fails closed (502/504), it does not fall back to cleartext. |

### 24.4 Grafana panels + alert suggestions

Panels (all derived from the §24.1 families — no high-cardinality joins):

| Panel | Query (PromQL sketch) | Why |
|---|---|---|
| **Degraded-path rate** | `sum by (reason) (rate(xrootd_sd_degraded_total[5m]))` | watch sendfile fallback, stream_copy, weak_rename, promote, backpressure, throttle volume |
| **Unsupported rate** | `sum by (op) (rate(xrootd_sd_unsupported_total[5m]))` | a spike means clients hitting object limitations — usually "needs a staging store" (runbook §24.3 row 1) |
| **Promote latency p99** | `histogram_quantile(0.99, sum by (le) (rate(xrootd_sd_latency_seconds_bucket{op="staged_commit"}[5m])))` | the leading indicator for staging back-pressure and endpoint health |
| **Read latency p99** | same with `op="read"` | object reads are memory-backed; latency tracks endpoint + budget pressure |
| **Staging utilization** | staging occupancy gauge / mount size (or `xfer`-style high-water gauge) | the capacity headline; alert before it fills |
| **SD error rate** | `sum by (backend,op) (rate(xrootd_sd_ops_total{status="error"}[5m]))` | endpoint faults, ETag mismatches, timeouts |
| **Budget waits** | `rate(budget_waits_total[5m])` (existing Phase-31 metric) | shows admission-control shedding (reads + staging back-pressure) |

Alerts:

| Alert | Condition | Severity | Meaning / action |
|---|---|---|---|
| `SDStagingHighWater` | staging utilization > 0.85 for 5m | warning | promote lag — scale `aio_threads`/mount or fix endpoint (§24.3) |
| `SDStagingNearFull` | staging utilization > 0.95 for 1m | critical | `ENOSPC` imminent; cap mis-sized or endpoint dead |
| `SDPromoteLatencyP99` | promote p99 > N×baseline for 10m | warning | endpoint/network degradation |
| `SDUnsupportedSpike` | `rate(xrootd_sd_unsupported_total[5m]) > 0` sustained | warning | clients hitting object limits — likely missing staging store |
| `SDDegradedWeakRename` | `rate(xrootd_sd_degraded_total{reason="weak_rename"}[5m]) > 0` | info | non-atomic rename in use — confirm intended |
| `SDErrorRate` | `rate(xrootd_sd_ops_total{status="error"}[5m]) > threshold` | warning | endpoint faults; check `/healthz` reachability + logs |
| `SDBackpressure` | `rate(xrootd_sd_degraded_total{reason="staging_backpressure"}[5m]) > 0` sustained | warning | sustained shed — backend cannot keep up with offered load |

All alert and panel queries aggregate over the bounded `backend`/`op`/`status`/
`reason` enums only; none reference a path, key, bucket, upload id, ETag, or
identity — preserving the metric-cardinality invariant end to end.


## 25. PR-by-PR rollout & review checklists

This section decomposes the §7 phasing (55.A–55.F) into small, bisectable PRs. The
hard rule from §7.2 is reproduced here and is non-negotiable: **never mix backend
config parsing with byte-I/O rewiring in the same change** — if it breaks, the failure
surface is too broad to bisect. Each PR carries the standard 3-tests rule
(success + error + security-negative, per §2.7 and `AGENTS.md`); PRs that touch the
hot path also carry the §10 perf gate, and PRs that move storage syscalls carry the
§9.2 static-syscall-scan.

Conventions used below:
- **Phase** = the 55.A–55.F phase the PR belongs to.
- **Depends-on** = PRs that must merge first (keeps the graph linear and revertible).
- **Risk** = Low / Medium / High, inherited from §7's phase risk and narrowed per PR.
- A review checklist item prefixed **[3-tests]**, **[perf]**, **[scan]**, or
  **[sec-neg]** is a gate that blocks merge.

---

### Milestone M1 — Inert scaffolding (Phase 55.A)

#### PR-01 — `sd.h`: vtable, capability bitmap, opaque types
- **Phase:** 55.A · **Risk:** Low
- **Scope:** Introduce the SD interface header only — the `xrootd_sd_driver_t` vtable
  (§3.3), `xrootd_sd_cap_t` bitmap (§3.1), opaque `xrootd_sd_obj_t`/`xrootd_sd_instance_t`/
  `xrootd_sd_dir_t`/`xrootd_sd_staged_t` forward decls, `xrootd_sd_stat_s`, and the
  helper-API prototypes (§3.3.1). No implementation, no callsite changes.
- **Files:** `src/fs/backend/sd.h` (new), `src/fs/backend/README.md` (new).
- **Depends-on:** —
- **Review checklist:**
  - Vtable is flat, POD-pointer-only (§3.3) so object ops can run in the AIO pool with zero event-loop coupling.
  - Capability enum matches §3.1 exactly (11 bits, names and values).
  - Helper prototypes (`xrootd_sd_caps`/`_fd`/`_supports`/`_stat_to_vfs`/`_backend_name`) present; no `driver->caps &` pattern leaks into the header doc examples.
  - No `goto`; section-level WHAT/WHY/HOW docblocks on every declared type.
  - **[3-tests]** N/A for a header-only PR — note in PR body that tests arrive with PR-03; header compiles standalone (`-fsyntax-only`).

#### PR-02 — `sd_registry.c`: name→driver lookup + per-export instance binding
- **Phase:** 55.A · **Risk:** Low
- **Scope:** Registry that resolves a backend/staging name to a `xrootd_sd_driver_t*`
  and constructs/owns per-export `xrootd_sd_instance_t`(s); collapses `staging=same` to
  a **shared instance pointer** (not a copy) so the §3.6.1 commit fast path is a pointer
  compare. Only `posix` registered (stub driver from PR-04 lands alongside or just after).
- **Files:** `src/fs/backend/sd_registry.c` (new), `src/fs/backend/sd.h` (registry API), `config` (`NGX_ADDON_SRCS`).
- **Depends-on:** PR-01
- **Risk note:** adds a new source → requires `./configure` (BUILD GOVERNANCE).
- **Review checklist:**
  - `staging=same` returns the identical pointer (`inst_a == inst_b`), verified by a unit assertion.
  - Unknown name returns a clear error, not a NULL deref.
  - Instance lifetime tied to postconfig/worker-init; cleanup symmetric with init.
  - **[3-tests]** success (posix resolves), error (unknown name → error), security-neg (name with embedded control bytes/`..` rejected, not used as a path).

#### PR-03 — `xrootd_storage_backend` + `xrootd_storage_staging` directives & config structs
- **Phase:** 55.A · **Risk:** Low
- **Scope:** Parse the two directives (§6.4/§6.5) and the paired config structs (§6.6:
  `xrootd_storage_store_conf_t`, `backend_store`/`staging_store`/`*_instance`). Defaults:
  backend `posix`, staging `same`. Validation gates from §6.5 (reject unknown name;
  reject non-POSIX without thread pool; staging-capability gate when `staging != backend`).
  **Config parsing only — zero byte-I/O rewiring** (§7.2).
- **Files:** `src/core/config/config.h`, `src/core/config/directives.c`, merge in `merge_*_conf()`.
- **Depends-on:** PR-02
- **Review checklist:**
  - Omitting both directives produces identical config to `posix`/`same` and `sd == sd_staging` (pointer identity).
  - `nginx -t` fails with a message **naming the missing capability** for an under-provisioned `staging != backend` (REQ-OPS-2).
  - Conf merge respects main→srv→loc and `NGX_CONF_UNSET`.
  - No network calls during `nginx -t` (§6.5).
  - **[3-tests]** parse success + inheritance; unknown backend/staging → `nginx -t` error; security-neg: a directive arg that smuggles a shell/path metachar is rejected at parse, not stored.

#### PR-04 — `sd_posix.c` stub + ctx wiring + `/healthz` exposure
- **Phase:** 55.A · **Risk:** Low
- **Scope:** Minimal `sd_posix` driver object advertising **all** caps (§3.1), wired into
  the registry; add `sd`/`sd_staging` pointers to `xrootd_vfs_ctx_t` (§6.3) and the
  per-srv `*_instance` pointers; expose **both** store names + capability bitmaps in debug
  logs and `/healthz`. Still **no VFS callsite rewired** — the ctx pointers are populated
  but unused on the data path.
- **Files:** `src/fs/backend/sd_posix.c` (new, stub), `src/fs/vfs.h`/`vfs_ctx`, `/healthz` writer, `config`.
- **Depends-on:** PR-03
- **Review checklist:**
  - `/healthz` lists `backend=posix staging=posix(same)` and the cap bitmaps.
  - No data-path behaviour change — diff against baseline access/error logs is empty.
  - `sd_staging == sd` for the default config, asserted in a test.
  - **[3-tests]** healthz shows correct pair; error (forced registry failure surfaces in healthz/startup); sec-neg: healthz never prints credentials/bucket/prefix (§3.5 label rules apply to healthz too).

---

### Milestone M2 — POSIX byte-I/O behind the seam (Phase 55.B)

#### PR-05 — POSIX `xrootd_sd_obj_t` (fd + stat snapshot) and `open`/`close`/`fstat`
- **Phase:** 55.B · **Risk:** Medium
- **Scope:** Define the POSIX object handle wrapping `{fd, stat snapshot}`; implement
  `open` (the `vfs_open.c` `xrootd_open_beneath`/`_confined_canon` cascade body),
  `close` (idempotent, §3.2), `fstat` (the `adopt_fd` body). `xrootd_sd_fd(obj)` returns
  the fd (POSIX has `CAP_FD`). **No job rewiring yet** — obj exists alongside `fh->fd`.
- **Files:** `src/fs/backend/sd_posix.c`, `src/fs/vfs_open.c`.
- **Depends-on:** PR-04
- **Review checklist:**
  - Object lifetime contract §3.2: open → fully initialized or NULL + `*err_out`; no half-open leak; close idempotent and does **not** commit staged writes.
  - The persistent per-worker `rootfd` (O_PATH) moves into the POSIX instance (§4).
  - Driver captures errno-style fact immediately; does not call `xrootd_send_error`/set `XROOTD_OP_*` (§3.3.2).
  - **[3-tests]** open existing (success), open missing → `ENOENT` (error), open escaping path → `EXDEV`/confinement refusal (sec-neg).

#### PR-06 — Route READ/PGREAD/READV execute arms through `obj->driver->pread`
- **Phase:** 55.B · **Risk:** Medium
- **Scope:** Change `xrootd_vfs_io_execute()` (`vfs_io_core.c`) to dispatch the read
  family through the SD vtable; `xrootd_vfs_job_t` carries `xrootd_sd_obj_t *obj` (+ the
  `{obj,off,len}` segment array for readv). POSIX `pread` body == today's
  `xrootd_vfs_pread_full`. Preserve page-CRC framing, EOF/short-read semantics.
- **Files:** `src/fs/vfs_io_core.c`, `src/fs/vfs_read.c`, `src/protocols/root/read/*` (job shape only).
- **Depends-on:** PR-05
- **Review checklist:**
  - io_uring tier still reads `xrootd_sd_fd(obj)`; capability-gated in `xrootd_aio_post_task` (§3.4) — non-fd backends never reach it (no live effect yet, but the gate is in place).
  - pgread per-page CRC32c framing byte-identical (INVARIANT 1).
  - Worker-safe: no nginx pool / metrics / log inside the driver `pread` (§3.3 contract).
  - **[scan]** §9.2 scan shows no new raw `pread`/`preadv` outside `sd_posix.c`.
  - **[perf]** §10 read throughput median + p99 within 1% of baseline.
  - **[3-tests]** read/readv/pgread success; range past EOF → short read (error path); OOB readv element → existing rejection preserved (sec-neg).

#### PR-07 — Route WRITE/WRITEV/PGWRITE/SYNC/TRUNCATE execute arms through SD
- **Phase:** 55.B · **Risk:** Medium
- **Scope:** Dispatch the write family + `fsync`/`ftruncate` through the vtable; POSIX
  bodies == today's `xrootd_vfs_pwrite_full`/`fsync`/`ftruncate`. Keep event-loop
  prepare/complete, cache, metrics, protocol counters and write-pipelining bounds unchanged.
- **Files:** `src/fs/vfs_io_core.c`, `src/fs/vfs_write.c`, `src/fs/vfs_sync.c`, `src/protocols/root/write/*` (job shape).
- **Depends-on:** PR-06
- **Review checklist:**
  - pgwrite CSE retransmit machine and per-page CRC unchanged (INVARIANT 1).
  - `fsync` is a real fsync for POSIX (durability semantics preserved; §8 object no-op is later).
  - **[scan]** §9.2 scan: no new raw `pwrite`/`fsync`/`ftruncate` outside `sd_posix.c`.
  - **[perf]** §10 write throughput median + p99 within 1% of baseline.
  - **[3-tests]** sequential + random write success; short-write/`ENOSPC` → `EIO`/`ENOSPC` text preserved (error); write past confinement / read-only export rejected (sec-neg).

---

### Milestone M3 — Namespace, copy, staged, xattr, fd-leak removal (Phase 55.C)

#### PR-08 — `stat`/`lstat` + directory iteration behind `sd_posix`
- **Phase:** 55.C · **Risk:** Medium
- **Scope:** Move `vfs_stat.c` (`xrootd_lstat_beneath`) and `vfs_dir.c` +
  `vfs_io_core.c` `fdopendir` scan behind `sd_posix` `stat`/`opendir`/`readdir`/
  `closedir`. `xrootd_sd_stat_to_vfs()` normalizes to `xrootd_vfs_stat_t`.
- **Files:** `src/fs/vfs_stat.c`, `src/fs/vfs_dir.c`, `src/fs/vfs_io_core.c`, `src/fs/backend/sd_posix.c`.
- **Depends-on:** PR-07
- **Review checklist:**
  - Dirlist dot-entry hiding + stat format stability preserved (§9.1 dirlist row).
  - Symlink-follow-in-export stat semantics preserved (no EXDEV regression).
  - **[scan]** no new raw `stat`/`lstat`/`opendir`/`readdir` outside SD.
  - **[3-tests]** stat/dirlist success; stat missing → `ENOENT`; symlink-escape / `..` stat refused (sec-neg via `test_attack_vectors.py`).

#### PR-09 — Namespace mutation (`unlink`/`mkdir`/`rename`) behind `sd_posix`; collapse `xrootd_ns_*`
- **Phase:** 55.C · **Risk:** Medium
- **Scope:** Move `xrootd_ns_delete/_mkdir/_rename` bodies behind the POSIX driver; the
  `xrootd_ns_*` entry points **stay** but become thin forwarders to `sd_posix` (one
  implementation) since worker-thread TPC/S3 assembly still call them (§4).
- **Files:** `src/fs/vfs_unlink.c`, `vfs_rename.c`, `vfs_mkdir.c`, `src/core/compat/namespace_ops.c`, `src/fs/backend/sd_posix.c`.
- **Depends-on:** PR-08
- **Review checklist:**
  - `renameat2` `RENAME_NOREPLACE` (`noreplace`) semantics preserved (atomic, `CAP_HARD_RENAME`).
  - `EXDEV`-means-escape contract preserved as a driver-returned fact mapped by VFS to `kXR_NotAuthorized`/403 (§5.2).
  - **[scan]** no new raw `rename`/`unlink`/`mkdir` outside SD/documented shim.
  - **[3-tests]** mkdir/rename/unlink success; rename onto existing with noreplace → `EEXIST` (error); cross-export / escaping rename refused (sec-neg).

#### PR-10 — Copy behind `server_copy` cap (POSIX `copy_file_range`) + stream-through fallback
- **Phase:** 55.C · **Risk:** Medium
- **Scope:** `vfs_copy.c` (WebDAV COPY, S3 CopyObject path) calls `server_copy`; POSIX =
  `copy_file_range`. When `!CAP_SERVER_COPY` or it returns `NGX_DECLINED`, fall back to
  the existing `xrootd_copy_range` pread→pwrite stream-through (§5.4). No live non-POSIX
  yet, but the fallback branch is wired and unit-tested by forcing `NGX_DECLINED`.
- **Files:** `src/fs/vfs_copy.c`, `src/fs/backend/sd_posix.c`.
- **Depends-on:** PR-09
- **Review checklist:**
  - Overwrite policy + byte-exactness identical to today (§9.1 copy row).
  - Forced-`NGX_DECLINED` test proves stream-through fallback is byte-exact.
  - **[3-tests]** copy success (native); forced-decline → stream copy success (error/fallback path); copy across confinement refused (sec-neg).

#### PR-11 — xattr/fattr behind `sd_posix`
- **Phase:** 55.C · **Risk:** Low
- **Scope:** Move `vfs_xattr.c` `*xattr_confined_canon` helpers behind
  `get/list/set/removexattr`. POSIX `CAP_XATTR` real user xattrs.
- **Files:** `src/fs/vfs_xattr.c`, `src/fs/backend/sd_posix.c`.
- **Depends-on:** PR-09
- **Review checklist:**
  - WebDAV dead-property + fattr wire names unchanged (no `U.` prefix regression).
  - **[scan]** no new raw `*xattr` outside SD.
  - **[3-tests]** set/get/list success; oversized/absent name → existing error; xattr op on escaping path refused (sec-neg).

#### PR-12 — Staged lifecycle + §3.6.1 commit decision (POSIX-same path only)
- **Phase:** 55.C · **Risk:** Medium
- **Scope:** Move `compat/staged_file` behind `staged_open`/`staged_write`/
  `staged_commit`/`staged_abort`; re-express `xrootd_vfs_staged_commit()` as the §3.6.1
  decision over `(staging, backend)` instances. Both still POSIX-same, so **only the
  native-rename fast path is exercised** (`staging.instance == backend.instance`).
- **Files:** `src/fs/vfs_staged.c`, `src/core/compat/staged_file.c`, `src/fs/backend/sd_posix.c`.
- **Depends-on:** PR-09
- **Review checklist:**
  - Identity fast path verified: `staging==backend` ⇒ atomic `renameat2`, **zero** promote bytes recorded (§9.1 fast-path row).
  - `O_EXCL` temp-in-export-root + atomic publish unchanged; data-loss-on-empty-`.part` guard preserved.
  - Staged temp never client-visible; pre-commit stat/list of final path → `ENOENT` (§3.6.3).
  - **[3-tests]** staged create+commit success (durable after reopen); abort leaves no final object (error); staged temp name not listable/readable (sec-neg).

#### PR-13 — Retire public `xrootd_vfs_file_fd()`; capability-aware read/serve helper
- **Phase:** 55.C · **Risk:** Medium
- **Scope:** The only genuine API change (§6.1). Replace the 3 external fd users
  (`webdav/get.c`, `s3/object.c`, `shared/file_serve.c`) with a VFS-owned
  capability-aware `xrootd_vfs_read()`-family call that returns the correct chain
  (memory or file-backed); internal `vfs_open.c` use becomes `xrootd_sd_fd(obj)`.
  `struct xrootd_vfs_file_s.fd` → `xrootd_sd_obj_t *obj` (§6.2).
- **Files:** `src/protocols/webdav/get.c`, `src/protocols/s3/object.c`, `src/protocols/shared/file_serve.c`, `src/fs/vfs_read.c`, `src/fs/vfs.h`, `src/fs/vfs_open.c`.
- **Depends-on:** PR-12
- **Review checklist:**
  - Cleartext WebDAV/S3/root reads **still use sendfile/file-backed buffers** on POSIX when `CAP_SENDFILE` (INVARIANT 2; §10 sendfile-preservation gate).
  - TLS path remains memory-backed; the two branches collapse into one VFS-owned decision (§5.1).
  - `xrootd_vfs_file_fd()` removed from `vfs.h`; no protocol/shared code builds its own sendfile buf from a raw fd.
  - **[perf]** sendfile preservation + TLS memory path both within §10 noise.
  - **[3-tests]** cleartext GET sendfile + TLS GET memory both byte-exact (success); GET of missing → 404 (error); range/path-escape GET refused (sec-neg).

#### PR-14 — §9.2 static-syscall-scan as a CI test
- **Phase:** 55.C · **Risk:** Low
- **Scope:** Add the §9.2 ripgrep allowlist check as a fast CI gate: raw storage syscalls
  in `src/fs`, `src/core/compat/namespace_ops.c`, `src/fs/path/beneath.c` must be **only** in
  `sd_posix.c` or a small, named, documented `allowed_compat_shim`. New sites fail CI.
- **Files:** `tests/test_static_syscall_scan.py` (or `tests/scan_syscalls.sh`), CI config.
- **Depends-on:** PR-13
- **Review checklist:**
  - Allowlist is small, named, documented; comments/docs do not trip the scan.
  - Scan runs in seconds and is **required** from 55.C onward.
  - A deliberately-planted raw `open(` outside SD makes the test fail (negative self-test).
  - **[3-tests]** clean tree passes; planted syscall fails; planted syscall inside an *undocumented* shim still fails (sec-neg of the allowlist itself).

---

### Milestone M4 — Block proof backend (Phase 55.D)

#### PR-15 — `sd_block.c`: extent-map / fixed-object-table block driver (off by default)
- **Phase:** 55.D · **Risk:** High
- **Scope:** Minimal second non-trivial backend proving the abstraction before S3:
  flat key namespace in a superblock, no dirs by default, explicit stat/read/write;
  `O_DIRECT` optional. Advertises only the caps it really has; everything else →
  `ENOTSUP` + metric. Inert unless `xrootd_storage_backend block`.
- **Files:** `src/fs/backend/sd_block.c` (new), `config`, `tests/test_storage_backend_matrix.py` (block params).
- **Depends-on:** PR-14
- **Review checklist:**
  - No protocol code gains a block-specific branch (REQ-CMPT-2).
  - Advertised-cap ops succeed; unadvertised ops return `ENOTSUP` and increment `xrootd_sd_unsupported_total`.
  - Driver bodies are worker-safe (no nginx pool/metrics/log).
  - **[3-tests]** advertised read/write success; unsupported op → `ENOTSUP`/501 + metric (error); flat-key escape refused (sec-neg).

#### PR-16 — Backend-parity matrix harness + degraded-path metrics scaffolding
- **Phase:** 55.D · **Risk:** Medium
- **Scope:** Build out `tests/test_storage_backend_matrix.py` (§9/§9.1): parametrize the
  same operation set across `posix`/`block`, asserting byte-identical reads, correct
  checksums, identical responses where the cap is present and the **correct error +
  metric** where absent. Add the §3.5 SD metrics
  (`xrootd_sd_ops_total`/`_bytes_total`/`_latency_seconds`/`_degraded_total`/
  `_unsupported_total`) — emitted only now that degradation is selectable.
- **Files:** `tests/test_storage_backend_matrix.py`, `src/observability/metrics/*` (SD metric enum/fields/export).
- **Depends-on:** PR-15
- **Review checklist:**
  - Metric labels are low-cardinality only — **no** path/bucket/key/upload-id/ETag/issuer (§3.5, INVARIANT 8).
  - Matrix asserts capability declaration + expected success/unsupported per row.
  - POSIX rows in the matrix still match baseline byte-for-byte (cross-check vs full suite).
  - **[3-tests]** matrix success rows pass; unsupported rows assert error + metric; sec-neg row (escape) per backend refused.

---

### Milestone M5 — Object/S3 backend + cross-store promote (Phase 55.E)

#### PR-17 — `sd_object.c` policy core: key mapping, capability model, metadata snapshot
- **Phase:** 55.E · **Risk:** High
- **Scope:** Object driver policy layer (no transport yet, or transport stubbed):
  reversible logical-path→key mapping with prefix (§3.3.3), capability declaration
  (`RANGE_READ | SERVER_COPY | XATTR`, **not** `FD|SENDFILE|RANDOM_WRITE|HARD_RENAME|DIRS|IOURING`),
  on-handle metadata model (`size`,`etag`,`generation`,`upload_id`), key-prefix confinement.
- **Files:** `src/fs/backend/sd_object.c` (new), `config`.
- **Depends-on:** PR-16
- **Review checklist:**
  - Key mapping is the single reversible function; **no** second normalization with string hacks in the SD (§3.3.3).
  - Key-prefix escape refused even when path normalization is bypassed in the test (§9 / REQ-SEC-2).
  - Physical locator (key) never leaks above `src/fs/backend/`.
  - **[3-tests]** key map round-trips (success); empty/illegal path → error; prefix escape (`../` post-decode, absolute key) refused (sec-neg).

#### PR-18 — `sd_object_s3.c` transport: HEAD/range-GET/PUT/multipart/DELETE/CopyObject/ListV2
- **Phase:** 55.E · **Risk:** High
- **Scope:** S3 transport for the object driver, reusing `src/protocols/s3` SigV4/transport.
  Implements `pread` (range GET), `stat` (HEAD), `unlink` (DELETE), `server_copy`
  (CopyObject), `opendir`/`readdir` (ListObjectsV2 prefix listing + pagination),
  `staged_*` (multipart init/part/complete/abort). Credential loading
  (`env|file|webidentity|static`), retry/timeout, sanitized error reporting.
- **Files:** `src/fs/backend/sd_object_s3.c` (new), `src/protocols/s3/*` (SigV4 reuse only), `config`.
- **Depends-on:** PR-17
- **Review checklist:**
  - All blocking calls run in the AIO thread pool — **never** on the event loop (§5.5; shmtx-stall lesson).
  - Error contract §3.3.2 honored: HEAD-miss→`ENOENT`, denied→`EACCES`/`EPERM`, stale-ETag→`ESTALE`, timeout→`ETIMEDOUT`; driver never emits wire codes/metrics.
  - Credentials/bucket/keys never appear in metric labels; sanitized in logs (§3.5, INVARIANT 8).
  - ListObjectsV2 pagination emits every entry with no duplicate/skipped key (§9.3).
  - **[3-tests]** range-GET/PUT-multipart/CopyObject success; multipart part-N failure → `staged_abort`, no visible final object (error); object-key escape refused (sec-neg).

#### PR-19 — AIO-offload currently-inline VFS namespace entry points for non-fd backends
- **Phase:** 55.E · **Risk:** High
- **Scope:** Add the "offload when `!CAP_DIRS`/object" branch to the small set of
  currently-inline namespace entries (`vfs_stat`, `vfs_dir` open, `vfs_mkdir`,
  `vfs_rename`, `vfs_unlink`) reusing `xrootd_aio_post_task` (§5.5). This is **the one
  place the upper VFS gains backend-aware code** — keep it minimal and capability-keyed.
- **Files:** `src/fs/vfs_stat.c`, `vfs_dir.c`, `vfs_mkdir.c`, `vfs_rename.c`, `vfs_unlink.c`.
- **Depends-on:** PR-18
- **Review checklist:**
  - POSIX path unchanged: `CAP_DIRS`+fast-syscall backends still run inline (no perf regression — §10).
  - Offload branch is purely capability-keyed; no per-protocol branching, no S3-specific names above the seam.
  - Event loop never blocks on an object namespace op (verified by latency/stall test).
  - **[3-tests]** object stat/list/mkdir/rename via offload succeed; backend timeout surfaces cleanly (error); offload path still re-checks confinement (sec-neg).

#### PR-20 — Cross-store promote: POSIX staging → object backend; `xrootd_storage_staging` goes live
- **Phase:** 55.E · **Risk:** High
- **Scope:** Wire the §3.6.1/§3.6.2 composed lifecycle: when `staging=posix, backend=s3`,
  `xrootd_vfs_staged_commit()` reads the POSIX staging object and drives the **backend's**
  `staged_open`/`staged_write`/`staged_commit` (multipart) as the byte source, then
  unlinks the staging temp. Makes the random/out-of-order/checkpointed upload path work
  end-to-end without RMW. `xrootd_storage_staging` directive becomes functional.
- **Files:** `src/fs/vfs_staged.c`, `src/fs/backend/sd_object.c`, `src/core/config/directives.c` (staging live).
- **Depends-on:** PR-19
- **Review checklist:**
  - Promote lands **one sequential object**, byte-exact + checksum-verified (REQ-FR-PROMOTE-1; §9.1 promote row).
  - Failed promote → backend `staged_abort` (multipart aborted), no visible final object; staging temp left for the abort/cleanup path (§3.6.3).
  - Crash window (§9.3): kill between backend `staged_commit` success and staging `unlink` → durable object present, at most a stale staging temp.
  - Promote bytes recorded against the **backend** store; `xrootd_sd_degraded_total{op=commit,reason=promote}` increments; intra-store rename records no promote bytes.
  - Each store enforces its **own** confinement (REQ-SEC-2): staging-root escape and key-prefix escape both refused.
  - **[3-tests]** random/checkpointed upload promotes byte-exact (success); mutate already-committed object → `ENOTSUP`/501 (error/limitation §8); staging-root + key-prefix escapes refused (sec-neg).

---

### Milestone M6 — Productization & parity gating (Phase 55.F)

#### PR-21 — Capability-degradation polish + per-degraded-path metrics & access-log details
- **Phase:** 55.F · **Risk:** Medium
- **Scope:** Complete the §3.1 degradation table: `!SENDFILE`→memory chain,
  `!SERVER_COPY`→stream-through, `!RANDOM_WRITE`→staged-only + reject in-place mutation,
  `!HARD_RENAME`→opt-in weak rename, `!XATTR`→sidecar-or-reject, `!CAP_DIRS`→prefix
  synthesis. Every degradation: correct client status + low-cardinality metric +
  access-log detail string naming the degraded op (no path as label).
- **Files:** `src/fs/vfs_read.c`, `vfs_copy.c`, `vfs_rename.c`, `vfs_xattr.c`, `vfs_dir.c`, `src/fs/backend/sd_object.c`, access-log writer.
- **Depends-on:** PR-20
- **Review checklist:**
  - Every degradation does all three things (§3.1 closing rule): status + metric + log detail.
  - `weak_rename on` logs the non-atomic window; off → `rename` rejected clearly (§8).
  - Sidecar xattr fallback works; disabled → clear error (§8 xattr row).
  - **[3-tests]** each degraded path success; unsupported-without-degradation → `ENOTSUP`+metric (error); weak-rename non-atomic-window cleanup-failure logged, not silent (sec-neg/observability).

#### PR-22 — Failure-injection suite (MinIO/moto) — §9.3
- **Phase:** 55.F · **Risk:** Medium
- **Scope:** `tests/test_storage_failure_injection.py` exercising the §9.3 object-only
  failures: HEAD-404-after-LIST, multipart part-N fail, Complete-ETag-mismatch,
  CopyObject-ok-but-Delete-fail (weak rename), credential-expiry-mid-transfer,
  ListV2 pagination, promote crash window, staging `ENOSPC`.
- **Files:** `tests/test_storage_failure_injection.py`, CI MinIO/moto service definition.
- **Depends-on:** PR-21
- **Review checklist:**
  - Every §9.3 scenario has an assertion on the **observable** outcome (no silent success).
  - Staging `ENOSPC` mid-upload fails **before** any backend write — no partial backend object.
  - Promote-crash restart leaves durable object present, never missing.
  - **[3-tests]** injected-failure handled (success=correct error surfaced); cleanup verified (error path); no orphaned visible object / no leaked credential in logs (sec-neg).

#### PR-23 — Full conformance + integrity matrix vs POSIX; perf report; docs
- **Phase:** 55.F · **Risk:** Medium
- **Scope:** Run `tests/test_integrity_matrix.py` and the conformance matrix with the
  object backend as the export across direct/proxy/cache topologies; produce the object
  baseline perf report (MinIO, report-only per §10); ship `src/fs/backend/README.md`,
  updated `src/fs/README.md`, `AGENTS.md` HELPERS/INVARIANTS, and
  `docs/10-reference/storage-backends.md` operator guide (§11).
- **Files:** docs (§11 list), CI conformance profile, example configs.
- **Depends-on:** PR-22
- **Review checklist:**
  - Documented limitation matrix (§8) matches **actual runtime** behaviour (verified, not asserted).
  - Full POSIX ~5180-suite still green (REQ-CMPT-1).
  - Object backend marked supported only after a representative backend matrix is green (REQ-NFR / §7.F acceptance).
  - **[3-tests]** integrity matrix byte-exact across topologies (success); documented-unsupported ops error as documented (error); attack-vector suite per backend green (sec-neg).
  - **[perf]** POSIX gates re-confirmed within §10 noise; object baseline reported (not compared).

---

### Milestone map

| Milestone | Phase | PRs | Theme | Tree state |
|---|---|---|---|---|
| **M1** | 55.A | PR-01…PR-04 | Inert scaffolding: vtable, registry, directives, ctx wiring | green, no data-path change |
| **M2** | 55.B | PR-05…PR-07 | POSIX byte-I/O behind the seam | green, byte-identical |
| **M3** | 55.C | PR-08…PR-14 | Namespace/copy/staged/xattr migration + fd-leak retirement + static scan | green, full POSIX parity; refactor complete |
| **M4** | 55.D | PR-15…PR-16 | Block proof backend + parity-matrix harness + SD metrics | green; block opt-in |
| **M5** | 55.E | PR-17…PR-20 | Object/S3 transport + AIO namespace offload + cross-store promote | green; object opt-in |
| **M6** | 55.F | PR-21…PR-23 | Degradation polish, failure injection, conformance + docs | green; object parity-gated → supported |

M1–M3 (PR-01…PR-14) are a **pure refactor** with the existing ~5180-test suite as the
oracle. M4–M6 (PR-15…PR-23) add capability behind `xrootd_storage_backend`/
`xrootd_storage_staging` and are each independently revertible (`git revert` the phase
commit, §13). The §9.2 static scan (PR-14) is the boundary marker: after it merges, no
new raw storage syscall may land outside the SD.

---

## 26. CI/CD jobs & gating

CI is organized so that the **POSIX-parity refactor (M1–M3) is gated by the existing
suite as an oracle**, and **non-POSIX backends (M4–M6) are gated by a parity matrix that
runs behind a flag/service** and never blocks a POSIX-only contributor who lacks an S3
endpoint. "Required" = blocks merge; "Informational" = reported, advisory.

### 26.1 Job catalog

#### J1 — `build-matrix` (build & `nginx -t`)
- **What:** `./configure --with-stream … --add-module=$REPO && make -j`, then
  `nginx -t` over the default config and an object-backend example config.
  Two axes: `{posix-only}` (default, no external service) and `{object}` (behind
  `CI_BACKEND=object`, brings up a MinIO service container).
- **Pass/fail:** build must succeed; `nginx -t` must pass for posix-only **and** must
  **fail with a capability-naming message** for the deliberately-misconfigured
  `staging != backend` fixture (REQ-OPS-2 negative).
- **Required?** posix-only axis **required every phase**; object axis required from 55.E,
  informational in 55.A–55.D.

#### J2 — `syscall-scan` (the §9.2 static gate)
- **What:** the §9.2 ripgrep allowlist check — raw storage syscalls in
  `src/fs`, `src/core/compat/namespace_ops.c`, `src/fs/path/beneath.c` only in
  `sd_posix.c` / named `allowed_compat_shim`.
- **Pass/fail:** **fail** if any matching syscall site appears outside the allowlist;
  fail if the allowlist grows without a documented, named shim. Runs in seconds.
- **Required?** Informational in 55.A–55.B (migration in flight); **required from 55.C
  onward** (PR-14).

#### J3 — `posix-parity-full` (the ~5180-test suite)
- **What:** the full suite via xdist, absolute paths, `--dist load`, two-lane split
  (per the full-suite recipe), POSIX backend only.
- **Pass/fail:** **zero diffs / zero new failures** vs the pre-phase baseline. This is the
  primary correctness oracle for the refactor (§9.1, §13).
- **Required?** **Required every phase.** A single new failure blocks merge.

#### J4 — `backend-parity-matrix` (`tests/test_storage_backend_matrix.py`)
- **What:** parametrizes the same op set across `posix`/`block`/`s3` (§9.1), asserting
  byte-identical reads + correct checksums where the cap is present, and the **correct
  `ENOTSUP`/501/`kXR_Unsupported` + metric** where absent. Object rows need the MinIO
  service; block rows are self-contained.
- **Pass/fail:** every row matches its declared expectation (success **or** documented
  unsupported); any divergence fails. Metric-label cardinality asserted (no path/bucket/key).
- **Required?** block rows **required from 55.D**; object rows **required from 55.E**;
  not run before 55.D.

#### J5 — `perf-gate` (§10)
- **What:** `tests/profile_load.sh` read profile + `run_load_test.sh` write profile +
  sendfile-preservation + TLS-memory checks, POSIX backend, vs stored baseline.
- **Pass/fail:** median **and** p99 within **1%** of baseline for read and write; sendfile
  still uses file-backed buffers when `CAP_SENDFILE`; AIO no queue-growth vs Phase 54.
  If POSIX indirection is measurable, the remedy is devirtualizing the hot byte-I/O path
  (§10) — not undoing the seam.
- **Required?** **Required for any PR touching the hot byte-I/O path** (PR-06, PR-07,
  PR-13, PR-19) and at the M2/M3/M6 milestone gates. Object baseline is **report-only**
  (network-bound, not compared to POSIX).

#### J6 — `security-negative` (`test_attack_vectors.py` per backend)
- **What:** the attack-vector suite (path `..`/absolute/symlink escape; object key-prefix
  escape; staging-root escape) run against **each enabled backend** (§9 #3).
- **Pass/fail:** every escape refused (`EXDEV`/`kXR_NotAuthorized`/403); object/staging
  prefix escapes refused even when path normalization is bypassed in the test.
- **Required?** POSIX axis **required every phase**; object/staging axes **required from
  55.E**.

#### J7 — `failure-injection` (MinIO/moto, §9.3)
- **What:** `tests/test_storage_failure_injection.py` — HEAD-404-after-LIST, multipart
  part-N fail, Complete-ETag-mismatch, CopyObject-ok+Delete-fail, credential expiry,
  ListV2 pagination, promote crash window, staging `ENOSPC`.
- **Pass/fail:** each scenario produces the documented observable outcome (no silent
  success; no orphaned visible object; no leaked credential in logs).
- **Required?** **Required from 55.E** (object lands); not applicable to posix-only PRs.

#### J8 — `integrity-conformance-matrix`
- **What:** `tests/test_integrity_matrix.py` + conformance matrix with the object backend
  as export across direct/proxy/cache topologies.
- **Pass/fail:** byte-exact + checksum r/w across topologies; documented-unsupported ops
  error as documented.
- **Required?** **Required from 55.F** (productization gate); informational in 55.E.

### 26.2 Required-vs-informational by phase

| Job | 55.A | 55.B | 55.C | 55.D | 55.E | 55.F |
|---|---|---|---|---|---|---|
| J1 build (posix-only) | req | req | req | req | req | req |
| J1 build (object/MinIO) | — | — | — | info | req | req |
| J2 syscall-scan | info | info | **req** | req | req | req |
| J3 posix-parity-full | req | req | req | req | req | req |
| J4 backend-parity-matrix | — | — | — | **req** | req | req |
| J5 perf-gate (POSIX) | gate | **req** | req | gate | req | req |
| J6 security-negative (posix) | req | req | req | req | req | req |
| J6 security-negative (object/staging) | — | — | — | — | **req** | req |
| J7 failure-injection | — | — | — | — | **req** | req |
| J8 integrity-conformance | — | — | — | — | info | **req** |

("gate" = run at the milestone boundary rather than per-PR; "req" = per-PR required;
"info" = informational; "—" = not applicable.)

### 26.3 Service & credential policy

- The object/MinIO axis runs **only** when `CI_BACKEND=object` (or on the 55.E+ branch
  protection), so the default contributor path needs no S3 credentials (§13.1).
- The selected CI profile must run **without external credentials by default** (§13.1):
  MinIO/moto is a local service container; real-S3 runs are a separate, manually-triggered,
  informational job.
- No job prints credentials, bucket names, full object keys, ETags, or token issuers
  (INVARIANT 8 / §3.5) — log redaction is itself asserted by J6.

---

## 27. Formal requirements & traceability matrix

Requirement IDs are grouped by category: **FR** functional, **NFR** perf/availability,
**SEC** confinement/credentials, **OPS** config/observability/fail-fast, **BLD**
build/registration, **CMPT** POSIX-parity/compatibility. Each requirement is testable and
traces to a design section, a phase/PR, and at least one test.

### 27.1 Functional (FR)

| ID | Requirement |
|---|---|
| REQ-FR-1 | The POSIX backend is byte-identical and response-identical to today's code: error codes, access-log detail, metrics, cache decisions, sendfile/TLS behaviour (§1.4.1). |
| REQ-FR-2 | All raw byte-I/O (`pread`/`pwrite`/`fsync`/`ftruncate`/`fstat`) dispatches through the SD vtable; the EXECUTE phase calls `obj->driver->*` (§3.4). |
| REQ-FR-3 | Namespace ops (`stat`/`unlink`/`mkdir`/`rename`/`server_copy`/dir iteration/xattr) dispatch through the vtable; `xrootd_ns_*` become single-implementation forwarders (§4). |
| REQ-FR-4 | `server_copy` absent (`NGX_DECLINED`/`!CAP_SERVER_COPY`) ⇒ VFS stream-through pread→pwrite fallback, byte-exact (§5.4). |
| REQ-FR-5 | The block backend supports its advertised caps and returns `ENOTSUP` for the rest (§7.D). |
| REQ-FR-6 | The object backend supports range-GET read, sequential/multipart create, HEAD-stat, DELETE, CopyObject, ListV2 prefix listing, tag/sidecar xattr (§7.E). |
| REQ-FR-7 | A driver lacking `FD`/`SENDFILE`/`RANDOM_WRITE`/`HARD_RENAME`/`DIRS` still passes the operations it advertises and returns clear unsupported errors for the rest (§1.4.3). |
| REQ-FR-PROMOTE-1 | A POSIX-staging→object-backend upload lands **byte-exact** as one sequential object; checksum verified; staging temp removed after commit (§3.6.2, §9.1). |
| REQ-FR-PROMOTE-2 | The `staging==backend` (POSIX-same) commit uses native atomic rename with **zero** extra copy and records **no** promote bytes (§3.6.1). |
| REQ-FR-PROMOTE-3 | Failed promote aborts the backend multipart (`staged_abort`), publishes no visible final object, and leaves the staging temp for the cleanup path (§3.6.3). |

### 27.2 Performance / availability (NFR)

| ID | Requirement |
|---|---|
| REQ-NFR-1 | POSIX read/write median **and** p99 stay within 1% of the pre-phase baseline (§10). |
| REQ-NFR-2 | Cleartext reads still use file-backed/sendfile buffers when `CAP_SENDFILE`; TLS stays memory-backed (§5.1, §10). |
| REQ-NFR-3 | Object/blocking ops run only in the AIO thread pool; the event loop never blocks on a backend call (§5.5). |
| REQ-NFR-4 | AIO shows no queue growth/regression vs Phase 54 under concurrent read/write (§10). |
| REQ-NFR-5 | Object-backend latency is measured separately (MinIO, report-only) and never compared to POSIX (§10). |

### 27.3 Security / confinement (SEC)

| ID | Requirement |
|---|---|
| REQ-SEC-1 | The VFS `require_confined`/`require_write` logical-path guards stay exactly where they are; the driver is handed an already-confined logical path (§2.4). |
| REQ-SEC-2 | Each store enforces its **own** physical confinement primitive independently: POSIX `RESOLVE_BENEATH`, object key-prefix bound, staging-root bound (§3.6.3, §5.2). |
| REQ-SEC-3 | Path/key escape (`..`, absolute, symlink, post-decode prefix escape) is refused even when path normalization is bypassed in tests (§9 #3). |
| REQ-SEC-4 | The driver never emits wire codes/metrics/`xrootd_send_error`; it returns errno-style storage facts only (§3.3.2). |
| REQ-SEC-5 | No credential, bucket name, full key, upload-id, ETag, token issuer, or user identity appears in any metric label; sanitized in logs only (§3.5). |
| REQ-SEC-6 | The physical locator (POSIX pathname, object key, extent address) never leaks above `src/fs/backend/` (§0). |

### 27.4 Operations / observability / fail-fast (OPS)

| ID | Requirement |
|---|---|
| REQ-OPS-1 | An unknown backend or staging name fails `nginx -t` with a clear message (§6.5). |
| REQ-OPS-2 | A `staging != backend` config missing a capability the enabled protocols need (`RANDOM_WRITE`/`TRUNCATE`) fails `nginx -t` naming the missing capability — not at upload time (§6.5). |
| REQ-OPS-3 | `staging == backend` with a backend lacking `RANDOM_WRITE` **warns** (not fails): whole-object sequential PUT only (§6.5). |
| REQ-OPS-4 | A non-POSIX backend/staging without a configured thread pool is rejected at config time (§6.5). |
| REQ-OPS-5 | Startup logs and `/healthz` include **both** store names and capability bitmaps (§6.5). |
| REQ-OPS-6 | Every capability degradation emits a low-cardinality metric and an access-log detail string naming the degraded op (§3.1 closing rule). |
| REQ-OPS-7 | `nginx -t` makes **no** network calls unless a future `validate_backend on` opts in (§6.5). |
| REQ-OPS-8 | Each phase is one atomic commit; rollback is `git revert <phase-commit>` (§13). |

### 27.5 Build / registration (BLD)

| ID | Requirement |
|---|---|
| REQ-BLD-1 | New SD source files are registered in the top-level `config` `NGX_ADDON_SRCS` and built via `./configure --add-module=$REPO` (§6.4, BUILD GOVERNANCE). |
| REQ-BLD-2 | The §9.2 static syscall scan is a CI gate from 55.C; the allowlist is small, named, documented (§9.2). |
| REQ-BLD-3 | The SD vtable is flat, POD-pointer-only, descriptor-driven, `goto`-free, functional/modular (§2.5, §3.3). |

### 27.6 Compatibility / POSIX-parity (CMPT)

| ID | Requirement |
|---|---|
| REQ-CMPT-1 | Omitting both directives == today's behaviour, and produces a **shared sd pointer** (`sd == sd_staging`) (§6.3, §7.A acceptance). |
| REQ-CMPT-2 | No protocol/cache/metrics/access-log code above the seam gains a backend-specific branch (the AIO namespace-offload in §5.5 is the sole, capability-keyed exception). |
| REQ-CMPT-3 | The full ~5180-test POSIX suite stays green with zero diffs throughout the refactor (§9.1, §13). |
| REQ-CMPT-4 | `xrootd_vfs_file_fd()` is retired from `vfs.h`; the 3 external callers move to a capability-aware VFS read/serve helper; no protocol code builds a sendfile buf from a raw fd (§6.1). |
| REQ-CMPT-5 | io_uring is preserved and orthogonal: `CAP_IOURING` gates the io_uring tier; non-fd backends never enter it; no io_uring code changes beyond the capability check (§3.4, §12.4). |
| REQ-CMPT-6 | Non-POSIX backends are inert until `xrootd_storage_backend` names them; they cannot regress any existing deployment (§13). |

### 27.7 Traceability matrix

| Req | Design section(s) | Phase / PR | Test(s) |
|---|---|---|---|
| REQ-FR-1 | §1.4.1, §4 | 55.A–C / PR-04…PR-14 | J3 posix-parity-full; baseline log/metric diff |
| REQ-FR-2 | §3.3, §3.4 | 55.B / PR-06, PR-07 | read/write/pgread/readv/writev/sync/truncate suite; J2 |
| REQ-FR-3 | §4, §5.4 | 55.C / PR-08…PR-11 | namespace + dirlist + xattr suite; J2 |
| REQ-FR-4 | §5.4 | 55.C / PR-10 | copy test (native + forced-decline stream-through) |
| REQ-FR-5 | §7.D | 55.D / PR-15 | `test_storage_backend_matrix.py` block rows (J4) |
| REQ-FR-6 | §7.E | 55.E / PR-17, PR-18 | J4 object rows; J8 |
| REQ-FR-7 | §1.4.3, §3.1 | 55.D–E / PR-15…PR-18 | J4 unsupported rows + metric |
| REQ-FR-PROMOTE-1 | §3.6.2, §9.1 | 55.E / PR-20 | matrix promote row; integrity-matrix (J8) |
| REQ-FR-PROMOTE-2 | §3.6.1 | 55.C/55.E / PR-12, PR-20 | staged fast-path test (no promote bytes) |
| REQ-FR-PROMOTE-3 | §3.6.3, §9.3 | 55.E / PR-20 | J7 multipart-part-N-fail; promote-crash-window |
| REQ-NFR-1 | §10 | 55.B/M2 / PR-06, PR-07 | J5 perf-gate (read+write median/p99) |
| REQ-NFR-2 | §5.1, §10 | 55.C / PR-13 | J5 sendfile-preservation + TLS-memory |
| REQ-NFR-3 | §5.5 | 55.E / PR-18, PR-19 | event-loop stall/latency test; J7 |
| REQ-NFR-4 | §10 | 55.B–F | J5 AIO-saturation |
| REQ-NFR-5 | §10 | 55.E–F / PR-18, PR-23 | object baseline (report-only) |
| REQ-SEC-1 | §2.4 | 55.A–C | J6 (posix); confinement re-check unit |
| REQ-SEC-2 | §3.6.3, §5.2 | 55.E / PR-17, PR-20 | J6 (object/staging escape) |
| REQ-SEC-3 | §9 #3 | 55.C/55.E / PR-14, PR-17 | `test_attack_vectors.py` per backend (J6) |
| REQ-SEC-4 | §3.3.2 | 55.B–E | error-contract unit; J4 |
| REQ-SEC-5 | §3.5 | 55.D–F / PR-16 | metric-label cardinality assertion (J4/J6) |
| REQ-SEC-6 | §0 | 55.E / PR-17 | key-leak unit (no key above seam) |
| REQ-OPS-1 | §6.5 | 55.A / PR-03 | `nginx -t` unknown-name test (J1) |
| REQ-OPS-2 | §6.5 | 55.A / PR-03 | `nginx -t` missing-capability test (J1 negative) |
| REQ-OPS-3 | §6.5 | 55.A / PR-03 | `nginx -t` warn-on-`same`-no-random-write test |
| REQ-OPS-4 | §6.5 | 55.A/55.E / PR-03, PR-18 | `nginx -t` no-thread-pool test |
| REQ-OPS-5 | §6.5 | 55.A / PR-04 | `/healthz` + startup-log test |
| REQ-OPS-6 | §3.1 | 55.F / PR-21 | degraded-path metric+log tests (J4) |
| REQ-OPS-7 | §6.5 | 55.A / PR-03 | `nginx -t` no-network assertion |
| REQ-OPS-8 | §13 | all | revert-restores-baseline smoke |
| REQ-BLD-1 | §6.4 | 55.A / PR-02, PR-04 | J1 build-matrix |
| REQ-BLD-2 | §9.2 | 55.C / PR-14 | J2 syscall-scan (+ planted-syscall self-test) |
| REQ-BLD-3 | §2.5, §3.3 | 55.A / PR-01 | coding-standards review; compile |
| REQ-CMPT-1 | §6.3, §7.A | 55.A / PR-03, PR-04 | shared-pointer identity test |
| REQ-CMPT-2 | §5.5 | 55.A–F | J3 + code review (no backend branch above seam) |
| REQ-CMPT-3 | §9.1, §13 | all | J3 posix-parity-full |
| REQ-CMPT-4 | §6.1 | 55.C / PR-13 | sendfile-preservation test; grep no `vfs_file_fd` |
| REQ-CMPT-5 | §3.4, §12.4 | 55.B/55.E / PR-06, PR-18 | io_uring tier capability-gate test |
| REQ-CMPT-6 | §13 | 55.D–F | default-config inertness smoke |

---

## 28. Architecture Decision Records (ADRs) & design FAQ

### ADR-01 — Runtime vtable, not compile-time backend selection
- **Context:** The POSIX/object/block split could be a compile-time `#ifdef` or a runtime
  vtable.
- **Decision:** A runtime `xrootd_sd_driver_t` vtable selected per export at config time (§3.3).
- **Consequences:** One binary serves any mix of exports; backends are revertible by config,
  not rebuild; one predicted indirect call per raw op (§10), devirtualized if measurable.
- **Alternatives rejected:** compile-time selection (can't mix exports, no operator
  reversibility); a plugin ABI / dlopen (over-engineered, no platform plugin story today).

### ADR-02 — Capability bitmap, not lowest-common-denominator interface
- **Context:** Either expose only the intersection of all backends' abilities, or let each
  backend declare what it can do.
- **Decision:** An 11-bit capability bitmap (§3.1); the VFS adapts per capability (§3.1 table).
- **Consequences:** POSIX keeps sendfile/random-write/atomic-rename at full speed; object
  backends are honest about absences; every degradation is metric+log-surfaced.
- **Alternatives rejected:** LCD interface (cripples POSIX to match S3); silent emulation
  (the slow, incorrect FUSE-over-S3 path the doc explicitly refuses, §1.3).

### ADR-03 — Two-store binding (backend + staging), not one
- **Context:** Bind an export to a single driver, or to a (backend, staging) pair.
- **Decision:** Each export binds a pair (§3.6); both default to the same POSIX instance.
- **Consequences:** The headline "fast POSIX staging in front of cheap object backend" is
  two one-line directives; no RMW, no POSIX-over-S3 pretence; subsumes part of the FRM/tape shape.
- **Alternatives rejected:** single store (forces RMW/emulation for object upload, the §5.3
  pain); per-request backend switching (§2.3 forbids it in v1).

### ADR-04 — `staging=same` collapses to a shared pointer
- **Context:** The default staging store equals the backend; representing that as a copy
  vs the identical pointer.
- **Decision:** The registry hands back the **identical** `xrootd_sd_instance_t*` for
  `staging=same` (§6.4); commit identity is a pointer compare.
- **Consequences:** The common POSIX deployment pays nothing — native rename, zero promote
  bytes (§3.6.1); the fast path is a one-instruction check.
- **Alternatives rejected:** duplicate instance (wastes the rootfd/credentials, breaks the
  identity fast path); a boolean "same" flag (less direct than pointer identity).

### ADR-05 — Promote (stage→commit), not in-place read-modify-write
- **Context:** Object backends can't `pwrite` at arbitrary offsets; either emulate with RMW
  or promote a finished object.
- **Decision:** Random/out-of-order/checkpointed writes land on POSIX staging; commit
  **promotes** a single sequential object to the backend (§3.6.2, §5.3).
- **Consequences:** Upload path is fully featured; the backend only ever sees sequential
  bytes; in-place mutation of an already-committed object is the only remaining `ENOTSUP` (§8).
- **Alternatives rejected:** RMW emulation (expensive, non-atomic, misleading under
  concurrent writers — §5.3); rejecting all non-sequential uploads (breaks real clients).

### ADR-06 — Drivers return errno facts; protocol layers emit wire codes
- **Context:** Where does `errno`→`kXR_*`/HTTP mapping live?
- **Decision:** The driver captures an errno-style fact immediately and returns it; the
  VFS/protocol layers map (§3.3.2). The driver never calls `xrootd_send_error`/sets `XROOTD_OP_*`.
- **Consequences:** One mapping table (§3.3.2) for all backends; drivers stay protocol-agnostic
  and worker-safe; metrics labels stay protocol-owned.
- **Alternatives rejected:** drivers emitting `kXR_*`/HTTP directly (couples storage to wire,
  duplicates mapping, breaks the §0 rule-of-thumb).

### ADR-07 — Retire `xrootd_vfs_file_fd()` as a public accessor
- **Context:** Three external callers build sendfile bufs from a raw VFS fd — the only real
  POSIX leak above the seam.
- **Decision:** Remove it from `vfs.h`; route callers through a capability-aware
  `xrootd_vfs_read()` family; internal use becomes `xrootd_sd_fd(obj)` (§6.1).
- **Consequences:** Sendfile vs memory becomes one VFS-owned, capability-gated decision;
  object backends serve memory chains correctly; the TLS and cleartext branches collapse.
- **Alternatives rejected:** keep the public fd accessor returning `NGX_INVALID_FILE` for
  non-fd backends (leaves three callers to each re-implement the fallback — fragile).

### ADR-08 — Capability-gated sendfile, not always-memory
- **Context:** Simplest correctness is "always memory-backed"; fastest cleartext POSIX is sendfile.
- **Decision:** File-backed/sendfile only when `CAP_SENDFILE`; otherwise memory-backed (§5.1).
- **Consequences:** POSIX cleartext keeps zero-copy sendfile (perf gate §10); object/TLS use
  memory chains; no protocol code chooses — the VFS does, from the capability.
- **Alternatives rejected:** always memory (regresses POSIX cleartext throughput); per-protocol
  sendfile choice (re-introduces the fd leak this phase removes).

### ADR-09 — AIO-offload namespace ops only for non-fd/object backends
- **Context:** POSIX `stat`/`mkdir`/`rename` are fast inline syscalls; object equivalents are
  blocking network calls that would stall the event loop.
- **Decision:** Add a capability-keyed "offload when `!CAP_DIRS`/object" branch to the small set
  of inline namespace entry points, reusing `xrootd_aio_post_task` (§5.5).
- **Consequences:** POSIX stays inline (no perf hit); object never blocks the loop; this is the
  **one** place the upper VFS gains backend-aware code.
- **Alternatives rejected:** offload everything always (penalizes POSIX); run object namespace
  inline (event-loop stall — the shmtx-postmortem failure mode).

### ADR-10 — One backend per export in v1; no tiering driver yet
- **Context:** A composing cache/tiering driver (`sd_cache.c`) is attractive but large.
- **Decision:** Exactly one backend + one staging store per export in v1 (§2.3); tiering deferred
  to 55.F as an open question (§12.1).
- **Consequences:** Bounded v1 scope; the cache stays VFS-owned hooks for now; the seam is
  designed so a recursive tiering driver is a clean later addition.
- **Alternatives rejected:** ship `sd_cache.c` composition in v1 (scope blow-up, couples Phase-26
  slice cache + Phase-35 tape tier into this phase).

### ADR-11 — Weak (non-atomic) rename is opt-in only
- **Context:** Object stores have no atomic rename; `rename` would be copy+delete with a window.
- **Decision:** `rename` on a `!CAP_HARD_RENAME` backend is rejected unless
  `xrootd_storage_s3_weak_rename on` is explicitly set; weak rename logs the non-atomic window (§6.5, §8).
- **Consequences:** Operators can't be silently surprised by non-atomic rename; the dangerous
  mode is explicit and observable.
- **Alternatives rejected:** silent copy+delete (violates the rename atomicity contract clients
  expect); always-reject (blocks legitimate object-store rename when the operator accepts the risk).

### ADR-12 — xattr via sidecar object, not only native tags
- **Context:** Object tag count/size is capped; WebDAV dead-properties / lock DB can exceed it.
- **Decision:** Map xattrs to native tags when they fit; fall back to a configured **sidecar
  object** (`xrootd_storage_s3_xattrs sidecar`), else reject clearly (§6.5, §8).
- **Consequences:** Full xattr fidelity where needed; bounded native-tag use; explicit error when
  sidecar is disabled — never silent truncation.
- **Alternatives rejected:** tags only (truncates large property sets); always sidecar (extra
  object per file even for small metadata).

### ADR-13 — Defer cache-as-tiering-driver to 55.F
- **Context:** The read-through/write-through cache (`src/fs/cache/`) is itself a POSIX store and
  could become a composing driver in front of the object backend.
- **Decision:** Keep the existing cache hooks VFS-owned for v1; evaluate `sd_cache.c` tiering in
  55.F (§12.1 recommendation).
- **Consequences:** Less churn now; the cache integration stays where the suite already proves it;
  a clean recursive tiering mechanism is a deliberate future step that subsumes Phase-26/35.
- **Alternatives rejected:** convert the cache to a driver inside this phase (entangles cache
  correctness with the storage-seam refactor — too broad to bisect).

### ADR-14 — Defer the object identity / impersonation model to before 55.E
- **Context:** Phase-40 impersonation opens POSIX fds with dropped privilege; object stores
  authenticate with a service credential.
- **Decision:** Define the object-driver identity model (per-user store credentials vs
  request-signing identity) as a gating open question resolved **before** 55.E (§12.3).
- **Consequences:** The object driver doesn't ship an ad-hoc identity story; impersonation
  semantics are decided deliberately, not implied by the transport code.
- **Alternatives rejected:** map every user to one service credential silently (loses per-user
  authorization the POSIX broker provides); block 55.E on a full impersonation rebuild (over-scoped).

### ADR-15 — io_uring stays orthogonal, gated by `CAP_IOURING`
- **Context:** Phase-44 io_uring submits on a kernel fd; object backends have none.
- **Decision:** `CAP_IOURING` gates the io_uring tier in `xrootd_aio_post_task`; non-fd backends
  never enter it; no io_uring code changes beyond the capability check (§3.4, §12.4).
- **Consequences:** io_uring keeps its POSIX speedup untouched; the object backend simply never
  reaches that tier; zero coupling between the two features.
- **Alternatives rejected:** teach io_uring about object backends (meaningless — no fd); disable
  io_uring when any object export exists (penalizes co-resident POSIX exports).

### ADR-16 — Two SD-staged lifecycles composed, not one merged path
- **Context:** Both the staging store (client byte writes) and the backend store (multipart) have
  a staged lifecycle; they could be merged or composed.
- **Decision:** Keep them distinct and **composed** by the VFS: promotion drives the backend's
  `staged_*` using the staging object as the byte source; neither driver knows about the other (§3.6.2).
- **Consequences:** Each driver implements only its own atomic-publish; the orchestration lives
  once in the VFS staged-commit body; clean recursion.
- **Alternatives rejected:** a merged cross-store staged op inside one driver (breaks driver
  independence, leaks the other store's existence into the driver).

### 28.1 Design FAQ

**Q1. Does the VFS public API change?**
No, except the deliberate retirement of `xrootd_vfs_file_fd()` (§6.1, ADR-07). Protocol
handlers keep building `xrootd_vfs_ctx_t` and calling `xrootd_vfs_*`.

**Q2. What does an unconfigured deployment get?**
Backend `posix`, staging `same` → the identical POSIX instance rooted at the export root,
`sd == sd_staging`, native rename on commit. Byte-for-byte today (REQ-CMPT-1).

**Q3. How is a random-offset `kXR_write` handled on an S3 backend?**
During an in-progress upload with a POSIX staging store: fully supported — it lands on the
staging file and the finished object is promoted. Against an already-committed backend object:
`ENOTSUP`/501 + `xrootd_sd_unsupported_total` (§5.3, §8). Never silent RMW.

**Q4. Where does confinement live now?**
The VFS keeps the logical-path `require_confined` guard (unchanged); each driver enforces its
own physical primitive — POSIX `RESOLVE_BENEATH`, object key-prefix, staging-root bound
(REQ-SEC-1/2, §5.2). Both stores confine independently.

**Q5. What stops the POSIX hot path from regressing?**
The §10 perf gate (1% median+p99) and, if the single indirect call shows up, devirtualizing
the hot byte-I/O path with a `CAP_FD`-keyed `static ngx_inline` fast-path before the vtable call.

**Q6. Why prove the abstraction with a block backend (55.D) before S3?**
A second non-trivial, non-POSIX backend forces the capability seam to be honest (no-dirs,
flat keys, `ENOTSUP` paths) before the high-value object work, catching seam leaks cheaply.

**Q7. Is sendfile lost for object backends?**
Yes, deliberately — object backends have no fd, so reads are memory-backed (already the TLS
path). POSIX cleartext keeps sendfile via `CAP_SENDFILE` (ADR-08, REQ-NFR-2).

**Q8. What happens on a crash mid-promote?**
Restart leaves the durable object present (commit is the atomic point) and at most a stale
staging temp, reclaimed by the staging-store sweeper — never a missing object (§9.3, §12.5).

**Q9. Can a single change introduce config parsing and rewire byte I/O?**
No — §7.2 forbids it; the PR plan (§25) separates them (PR-03 parsing vs PR-06/07 I/O) so a
break is bisectable.

**Q10. How does the object driver avoid stalling the event loop?**
Its raw I/O ops *are* the AIO thread-pool bodies (Phase-54 EXECUTE), and its namespace ops gain
the capability-keyed offload branch (ADR-09, §5.5). Nothing object-store blocks the loop.

**Q11. Do metrics gain object-specific high-cardinality labels?**
No. SD metrics use `backend`/`op`/`status`/`direction`/`reason` only — never path, bucket, key,
upload-id, ETag, issuer, or user (REQ-SEC-5, §3.5).

**Q12. How is the whole phase rolled back?**
Each phase is one atomic commit; `git revert <phase-commit>`. 55.D–55.F are inert unless a
non-POSIX backend is named, so they can't regress an existing deployment (§13, REQ-OPS-8/CMPT-6).

---

## 29. Glossary

| Term | Definition |
|---|---|
| **SD (Storage Driver)** | The new `src/fs/backend/` layer below the VFS owning raw storage primitives (open/read/write/stat/namespace/staged commit) behind a capability-typed vtable. |
| **SD instance (`xrootd_sd_instance_t`)** | One configured backend bound to one export root/location: driver config, root/key-prefix confinement state, credentials, transport handles. |
| **SD object (`xrootd_sd_obj_t`)** | The opaque open object a driver returns: an fd for POSIX, `{key, etag, size, staging_fd, upload_id}` for object, an extent cursor for block. |
| **SD driver (`xrootd_sd_driver_t`)** | The flat, POD-pointer-only vtable + capability bitmap that *is* the descriptor table for one backend type (`posix`/`block`/`s3`). |
| **Backend store** | The SD instance holding durable, client-visible data for an export — the canonical bytes a reopen/stat/list reflects. Default POSIX. |
| **Staging store** | The SD instance holding in-progress uploads before commit; scratch temp objects consumed by commit/promote, never client-visible by their temp names. Default POSIX (= the backend). |
| **Store binding** | The (backend store, staging store) pair bound to one export; both default to the same POSIX instance; either reselectable independently (§3.6). |
| **Promote** | The commit action moving a completed staged object from the staging store into the backend store: native rename when both are the same store, else stream/multipart copy-then-delete. |
| **Capability bitmap (`xrootd_sd_cap_t`)** | The 11-bit set of abilities a driver advertises (`FD`/`SENDFILE`/`RANDOM_WRITE`/`RANGE_READ`/`TRUNCATE`/`SERVER_COPY`/`XATTR`/`HARD_RENAME`/`DIRS`/`APPEND`/`IOURING`) that drives VFS adaptation. |
| **Logical path** | The canonical client/export path already normalized by `src/path/`, passed from VFS to SD; never trusted until the SD enforces its own confinement primitive. |
| **Physical locator** | The driver-private addressing of bytes: POSIX pathname, object key, block extent address; never leaks above `src/fs/backend/`. |
| **RESOLVE_BENEATH** | The `openat2(2)` flag that is the POSIX driver's physical confinement primitive — kernel-enforced "cannot escape this directory." |
| **Key prefix** | The object driver's confinement primitive: logical path → `key_prefix + path`, rejecting `..`/escape after normalization; the object analogue of `RESOLVE_BENEATH`. |
| **Multipart** | The S3 sequential whole-object upload protocol (init → upload parts → complete/abort) used as the object backend's `staged_*` lifecycle. |
| **CopyObject** | The S3 server-side object copy used to implement the SD `server_copy` op when both ends are object-store (else the VFS streams through). |
| **ETag** | The object store's content/version tag; used for optimistic commit checks (ETag mismatch → `ESTALE`); never a metric label. |
| **Generation** | The object's version snapshot cached on the handle alongside `size`/`mtime`/`etag`; updated only after a successful write/truncate/staged commit. |
| **Sidecar metadata** | A separate companion object holding xattrs/dead-properties that exceed native object tag limits (`xrootd_storage_s3_xattrs sidecar`). |
| **Tiering driver** | A deferred composing SD (e.g. `sd_cache.c`) that stacks a POSIX cache/disk tier in front of a slow object/tape backend — the recursive future for cache + FRM/tape (§12.1). |
| **PREPARE / EXECUTE / COMPLETE** | The Phase-54 three-phase split of every disk op around a POD `xrootd_vfs_job_t`; EXECUTE (`vfs_io_core.c`) is the worker-safe raw-I/O phase that calls the driver vtable. |
| **Worker-safe** | The contract for raw SD ops (`pread`/`pwrite`/`ftruncate`/`fsync`/`fstat`): no nginx pool, no metrics, no log, no event-loop coupling — runnable inside the AIO thread pool. |
| **Devirtualization** | The `static ngx_inline`, `CAP_FD`-keyed fast-path before the vtable call used only if the single predicted indirect call shows up in the §10 perf gate. |
| **Server copy (`server_copy`)** | The SD op for native copy (`copy_file_range` on POSIX, `CopyObject` on S3); returns `NGX_DECLINED` when `!CAP_SERVER_COPY` so the VFS falls back to stream-through. |
| **Staged lifecycle (`staged_*`)** | A driver's own atomic-publish sequence (`staged_open`/`_write`/`_commit`/`_abort`): POSIX temp+rename, object multipart — distinct from VFS-level cross-store promote. |
| **Weak rename** | Opt-in non-atomic `rename` = server-copy + delete on a `!CAP_HARD_RENAME` backend, enabled only by `weak_rename on`, with the non-atomic window logged. |
| **Cross-store promote** | The §3.6.2 composed flow where the VFS drives the backend's `staged_*` multipart lifecycle using a separate staging-store object as the byte source, then unlinks the staging temp. |
| **`xrootd_vfs_file_fd()`** | The retired (§6.1, ADR-07) public fd accessor — the only genuine POSIX leak above the seam; replaced by a capability-aware VFS read/serve helper. |
| **`xrootd_aio_post_task`** | The Phase-54 AIO thread-pool entry point; raw-I/O EXECUTE and the object namespace-offload branch both submit through it, gated by `CAP_IOURING` for the io_uring tier. |


