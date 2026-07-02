# Phase 15 — Unified POSIX Namespace Layer

**Target**: ensure all three protocols (XRootD stream, WebDAV, S3) route
namespace mutations through `compat/namespace_ops.c` as the single authoritative
implementation, eliminating per-handler reimplementations of delete/mkdir/rename
semantics.

**Net LoC reduction**: ~35–45 LoC  
**Risk**: low — mechanical migration; `namespace_ops.c` already handles every
case that the bypassing callers cover  
**Requires**: `make -j$(nproc)` only — no new source files, no `./configure`

---

## Existing architecture

The codebase has a four-layer namespace stack:

```
Layer 4: Protocol handlers
         webdav/namespace.c, webdav/move.c,       ← already use Layer 3
         write/mkdir.c, write/mv.c, write/op_table.c, s3/delete_objects.c
                                                   ← bypass to Layer 1

Layer 3: compat/namespace_ops.c
         xrootd_ns_delete(), xrootd_ns_mkdir(), xrootd_ns_rename(),
         xrootd_ns_local_copy()                   ← authoritative semantics

Layer 2: path/path.h  — resolve_path* wrappers (→ path/unified.h)
         path/unified.h — xrootd_path_resolve_cstr() canonical implementation

Layer 1: path/path.h  — confined primitives
         xrootd_open_confined_canon(), xrootd_unlink_confined_canon(),
         xrootd_mkdir_confined_canon(), xrootd_rename_confined_canon()
         (openat2 RESOLVE_BENEATH or O_NOFOLLOW fallback)
```

**WebDAV is already correct**: `webdav/namespace.c` (`DELETE`, `MKCOL`) uses
`xrootd_ns_delete()` and `xrootd_ns_mkdir()`.  `webdav/move.c` (`MOVE`) uses
`xrootd_ns_rename()`.

**Stream and S3 have gaps** — they call Layer 1 directly for the semantic
operations, duplicating errno-to-error-code mapping and edge-case handling that
`namespace_ops.c` already provides.

---

## What NOT to change

Several callers use Layer 1 confined primitives correctly and must remain
unchanged:

| File | Operation | Why fine-grained is correct |
|------|-----------|----------------------------|
| `webdav/tpc_thread.c` | `unlink_confined_canon`, `rename_confined_canon` | TPC staging: atomic tmp→final commit; error handling is operation-specific |
| `webdav/tpc_marker.c` | `unlink_confined_canon`, `rename_confined_canon` | Marker file lifecycle; not a user-facing namespace operation |
| `webdav/copy.c` | `mkdir_confined_canon`, `rename_confined_canon` | Staged copy commit; one atomic tmp→final rename |
| `webdav/fs/copy_engine.c` | `open_confined_canon`, `mkdir_confined_canon` | Recursive tree copy requiring direct fd control |
| `s3/multipart_*.c` | `open_confined_canon`, `unlink_confined_canon`, `rename_confined_canon` | Multi-step part assembly; each step has specific error recovery |
| `write/chkpoint.c` | `open_confined_canon`, `unlink_confined_canon` | Checkpoint file management, internal to stream session |
| `query/checksum_*.c` | `open_confined_canon` | Read-only file opens for checksum computation |
| All stream read handlers | `open_confined` | File opens are I/O operations, not namespace mutations |

The criterion: if the caller is implementing a user-facing semantic operation
(delete, mkdir, rename) it belongs in Layer 3.  If it is doing internal
staging, streaming I/O, or fine-grained file assembly, it stays at Layer 1.

---

## Change A — add `xrootd_kxr_map_ns_status()` to `compat/result_mapper.c/h`

The existing `result_mapper.h` has `xrootd_http_map_ns_status()` for HTTP
callers but no equivalent for stream protocol callers, which currently do
inline `errno → kXR_*` translation after confined primitive calls.

**Add to `compat/result_mapper.h`**:

```c
/*
 * xrootd_kxr_map_ns_status — map a namespace service status to a kXR error
 * code for stream protocol responses.  The sys_errno field of the result is
 * used only for XROOTD_NS_IO_ERROR (falls back to kXR_IOError).
 */
uint16_t xrootd_kxr_map_ns_status(xrootd_ns_status_t status, int sys_errno);
```

**Add to `compat/result_mapper.c`**:

```c
uint16_t
xrootd_kxr_map_ns_status(xrootd_ns_status_t status, int sys_errno)
{
    switch (status) {
    case XROOTD_NS_OK:        return kXR_ok;
    case XROOTD_NS_NOT_FOUND: return kXR_NotFound;
    case XROOTD_NS_DENIED:    return kXR_NotAuthorized;
    case XROOTD_NS_EXISTS:    return kXR_FSError;
    case XROOTD_NS_CONFLICT:  return kXR_FSError;
    case XROOTD_NS_NOT_EMPTY: return kXR_FSError;
    case XROOTD_NS_NO_SPACE:  return kXR_NoMemory;
    case XROOTD_NS_TOO_LONG:  return kXR_ArgTooLong;
    case XROOTD_NS_IO_ERROR:  return xrootd_kxr_from_errno(sys_errno);
    }
    return kXR_IOError;
}
```

**LoC**: +12 LoC (result_mapper.c) + 5 LoC (result_mapper.h)

---

## Change B — migrate `write/mkdir.c` to `xrootd_ns_mkdir()`

**Current** (lines 89–118, ~30 LoC after the auth gate):

```c
if (recursive) {
    if (xrootd_mkdir_recursive_confined(c->log, &conf->common.root,
                                        resolved, mode, conf->group_rules) != 0
        && errno != EEXIST)
    {
        XROOTD_RETURN_ERR(ctx, c, ..., kXR_IOError, strerror(errno));
    }
} else {
    if (xrootd_mkdir_confined(c->log, &conf->common.root, resolved, mode) != 0) {
        int err = errno;
        if (err == EEXIST) { /* not an error */ }
        else if (err == EACCES) { XROOTD_RETURN_ERR(..., kXR_NotAuthorized, "permission denied"); }
        else { XROOTD_RETURN_ERR(..., kXR_IOError, strerror(err)); }
    }
    if (conf->group_rules != NULL) {
        xrootd_apply_parent_group_policy_path(c->log, resolved, conf->group_rules);
    }
}
XROOTD_RETURN_OK(ctx, c, ...);
```

**After** (~12 LoC):

```c
{
    xrootd_ns_result_t res;
    const char *root_canon = xrootd_get_root_canon_str(conf);

    res = xrootd_ns_mkdir(c->log, root_canon, resolved, mode, recursive);

    if (res.status != XROOTD_NS_OK && res.status != XROOTD_NS_EXISTS) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
                          xrootd_kxr_map_ns_status(res.status, res.sys_errno),
                          res.status == XROOTD_NS_DENIED ? "permission denied"
                                                         : strerror(res.sys_errno));
    }
    /* Apply parent group policy after successful single-level mkdir. */
    if (!recursive && res.created && conf->group_rules != NULL) {
        xrootd_apply_parent_group_policy_path(c->log, resolved, conf->group_rules);
    }
}
XROOTD_RETURN_OK(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-", 0);
```

**LoC accounting**: 30 LoC → 14 LoC = **−16 LoC**

**Note**: `xrootd_ns_mkdir()` already handles both recursive
(`xrootd_mkdir_recursive_confined_canon`) and non-recursive
(`xrootd_mkdir_confined_canon`) and treats `EEXIST` as success internally.
Group policy is applied after the call only for the non-recursive path where
`res.created` is set, matching current behaviour.

**Requires**: the caller needs `conf->common.root_canon` (a `const char *`),
not the `ngx_str_t *root`.  Stream conf already has `root_canon` as a field
after the upstream bootstrap phase; verify its name via grep before editing.

---

## Change C — migrate `write/mv.c` to `xrootd_ns_rename()`

**Current** (lines 132–142, ~8 LoC after both auth gates):

```c
if (xrootd_rename_confined(c->log, &conf->common.root, src_resolved,
                           dst_resolved) != 0) {
    int err = errno;
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_resolved, "-",
                      xrootd_kxr_from_errno(err),
                      err == EACCES || err == EPERM ? "permission denied"
                                                    : strerror(err));
}
XROOTD_RETURN_OK(ctx, c, XROOTD_OP_MV, "MV", src_resolved, dst_resolved, 0);
```

**After** (~8 LoC):

```c
{
    xrootd_ns_result_t res;
    res = xrootd_ns_rename(c->log, root_canon, src_resolved, dst_resolved, 0);
    if (res.status != XROOTD_NS_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MV, "MV", src_resolved, "-",
                          xrootd_kxr_map_ns_status(res.status, res.sys_errno),
                          res.status == XROOTD_NS_DENIED ? "permission denied"
                                                         : strerror(res.sys_errno));
    }
}
XROOTD_RETURN_OK(ctx, c, XROOTD_OP_MV, "MV", src_resolved, dst_resolved, 0);
```

**LoC accounting**: essentially neutral (8 → 8 LoC); primary value is using the
shared error path rather than duplicating the `EACCES/EPERM` branch inline.

The `overwrite_dirs` flag is 0: kXR_mv does not do recursive destination
replacement — it is `rename(2)` semantics, same as before.

---

## Change D — migrate `exec_rmdir` in `write/op_table.c` to `xrootd_ns_delete()`

**Current** `exec_rmdir` (lines 61–77, 17 LoC):

```c
static ngx_int_t
exec_rmdir(const xrootd_op_exec_t *e, int *out_errno)
{
    if (xrootd_unlink_confined(e->c->log, &e->conf->common.root,
                               e->resolved, 1) == 0) {
        return NGX_OK;
    }
    *out_errno = errno;
    if (*out_errno == ENOENT) { return NGX_OK; }
    if (*out_errno == EEXIST) { *out_errno = ENOTEMPTY; }
    return NGX_ERROR;
}
```

**After** (~10 LoC):

```c
static ngx_int_t
exec_rmdir(const xrootd_op_exec_t *e, int *out_errno)
{
    xrootd_ns_delete_opts_t opts;
    xrootd_ns_result_t      res;

    ngx_memzero(&opts, sizeof(opts));
    opts.idempotent_missing = 1;   /* ENOENT treated as success, matching before */
    res = xrootd_ns_delete(e->c->log, e->conf->common.root_canon,
                           e->resolved, &opts);
    if (res.status == XROOTD_NS_OK) {
        return NGX_OK;
    }
    *out_errno = res.sys_errno ? res.sys_errno : ENOTEMPTY;
    return NGX_ERROR;
}
```

**LoC accounting**: 17 LoC → 12 LoC = **−5 LoC**

**Note**: `EEXIST → ENOTEMPTY` normalisation is handled inside `namespace_ops.c`
via `errno_to_ns_status()` which maps both to `XROOTD_NS_NOT_EMPTY`.  The
`idempotent_missing=1` flag preserves the current `ENOENT → NGX_OK` path.

---

## Change E — migrate `s3/delete_objects.c` to `xrootd_ns_delete()`

S3 `DeleteObjects` currently calls `xrootd_unlink_confined_canon()` twice per
object (once as file, once as directory fallback) with per-call errno handling.

**Current pattern** per object (lines ~375–385, ~12 LoC per object, ~2 objects
handled = ~24 LoC for the error path block):

```c
del_rc = xrootd_unlink_confined_canon(r->connection->log,
                                      cf->common.root_canon, path, 0);
if (del_rc != 0 && errno == EISDIR) {
    del_rc = xrootd_unlink_confined_canon(r->connection->log,
                                          cf->common.root_canon, path, 1);
}
if (del_rc != 0) {
    /* inline errno→S3 error mapping */
}
```

**After** (~8 LoC per object):

```c
{
    xrootd_ns_delete_opts_t opts;
    xrootd_ns_result_t      res;
    ngx_memzero(&opts, sizeof(opts));
    opts.idempotent_missing = 1;
    res = xrootd_ns_delete(r->connection->log, cf->common.root_canon, path, &opts);
    if (res.status != XROOTD_NS_OK) {
        /* map res.status → S3 error XML */
    }
}
```

`xrootd_ns_delete()` already tries the file path, then retries as a directory
if `was_dir` is set (see `namespace_ops.c` lines 113–128).

**LoC accounting**: depends on how many error-path paths exist; estimated **−10
to −15 LoC**.

---

## What the architecture looks like after

```
Layer 4: Protocol handlers
         webdav/namespace.c    → xrootd_ns_delete(), xrootd_ns_mkdir()
         webdav/move.c         → xrootd_ns_rename()
         write/mkdir.c         → xrootd_ns_mkdir()         [Change B]
         write/mv.c            → xrootd_ns_rename()        [Change C]
         write/op_table.c      → xrootd_ns_delete()        [Change D]
         s3/delete_objects.c   → xrootd_ns_delete()        [Change E]

Layer 3: compat/namespace_ops.c           ← single authoritative implementation

Layer 2: path/unified.c
Layer 1: path/resolve_confined_ops.c
Layer 0: openat2(RESOLVE_BENEATH)
```

Fine-grained file I/O code (TPC staging, copy engine, multipart assembly,
checksum) continues to call Layer 1 directly — this is correct.

---

## Architecture invariant to enforce going forward

Add to `compat/namespace_ops.h` (as a comment at the top):

```
 * INVARIANT: All protocol handlers implementing user-visible namespace
 * mutations (delete, mkdir, rename) MUST route through these functions.
 * Direct calls to xrootd_*_confined*() from protocol handler files
 * (src/protocols/root/write/, src/protocols/s3/, src/protocols/webdav/ dispatch paths) are a defect.
 * Internal staging code (TPC, multipart, copy engine, checksum) is exempt.
```

---

## Honest LoC accounting

```
Change A (xrootd_kxr_map_ns_status):   +17 LoC
Change B (write/mkdir.c):              −16 LoC
Change C (write/mv.c):                   0 LoC
Change D (write/op_table.c exec_rmdir): − 5 LoC
Change E (s3/delete_objects.c):        −12 LoC (estimated)
─────────────────────────────────────────────────
Net code reduction:                    −16 LoC
```

**Net LoC is modest** (~16 LoC). The value of this phase is not the line count:

1. **Security surface reduction**: A future bug in confined-rename semantics
   (TOCTOU, symlink escape) needs fixing in ONE place — `namespace_ops.c` —
   rather than hunting for every protocol handler that calls the primitive
   directly.

2. **Edge-case consistency**: `EEXIST-as-success` for mkdir, `EISDIR-fallback`
   for rm, `ENOTEMPTY` normalisation — these are currently implemented multiple
   times with slight variations. After this phase, one implementation governs
   all three protocols.

3. **`xrootd_ns_result_t` gives richer error context**: `sys_errno`, `existed`,
   `created`, `was_dir` flags are available to all callers for richer logging
   and response generation, replacing the current single-scalar `errno` check.

4. **Enforces the layering model**: `namespace_ops.c` was added with the
   explicit goal of being the shared layer; this phase closes the remaining gaps.

---

## Tests (minimum 3)

No new tests are needed — no logic changes. After the changes, run:

```bash
# Stream namespace operations
PYTHONPATH=tests pytest tests/test_conformance.py -v -k "mkdir or mv or rmdir or rm"
PYTHONPATH=tests pytest tests/test_aio.py -v

# WebDAV namespace (regression)
PYTHONPATH=tests pytest tests/ -k "webdav" -v

# S3 delete operations
PYTHONPATH=tests pytest tests/ -k "s3 and delete" -v

# Full suite for confidence
PYTHONPATH=tests pytest tests/ -v --tb=short
```

Additional manual check: run `PYTHONPATH=tests pytest tests/test_conformance.py -v` and confirm all kXR_mkdir, kXR_mv, kXR_rmdir, kXR_rm cases pass with the expected kXR status codes — specifically the error paths (ENOENT, EPERM, ENOTEMPTY) that are now routed through `xrootd_kxr_map_ns_status()`.

---

## Relationship to overall 10% target

This phase contributes **~16 LoC net** to the 10% reduction goal. Its primary
contribution is architectural: closing the gap between `namespace_ops.c`'s
intended role and the current state, so the layered security model is complete.

Combined contribution of Phases 12–15:
```
Phase 12 (shared HTTP file-serve):       − 80–110 LoC
Phase 13 (aio task dispatch macro):       −     10 LoC
Phase 14 (table-driven metrics):          −     83 LoC
Phase 15 (unified namespace layer):       −     16 LoC
────────────────────────────────────────────────────────
Subtotal:                                −189–219 LoC
```
