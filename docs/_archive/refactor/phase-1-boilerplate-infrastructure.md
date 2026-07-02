# Phase 1: Boilerplate Infrastructure

**Projected ΔLoC:** −300  
**Risk:** Low  
**Depends on:** nothing  
**Blocks:** Phases 2, 3, 4, 6

---

## Goal

Introduce the shared macro and helper infrastructure that all later phases depend on.  This phase does not delete any existing code — it adds new helpers so later phases can replace duplicated patterns without creating net-new logic.

Phase 1 should be a no-op from a behaviour standpoint: no handler files change, no tests change.  After this phase the build is identical but the new helpers exist for later phases to use.

---

## Pattern Inventory

Three patterns are pervasive enough to warrant centralised helpers at this phase:

### Pattern A: Unified op result builder

Every handler terminates in one of these two macros (defined in `src/core/compat/op_result.h` or equivalent):

```c
XROOTD_RETURN_OK(ctx, c, XROOTD_OP_CHMOD, "CHMOD", resolved, "-", 0);
XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHMOD, "CHMOD", reqpath, "-",
                  kXR_NotAuthorized, "authdb denied");
```

These already exist.  What does NOT exist is a single place to check: "did this op succeed or fail with a specific errno?"  Phase 1 adds a thin errno-to-kXR helper that is currently duplicated across 30+ sites.

### Pattern B: errno-to-kXR mapping gaps

`src/core/compat/error_mapping.h` already exports `xrootd_kxr_from_errno(err)`.  But 15+ handlers still hand-roll the mapping inline:

```c
/* Repeated literally in chmod.c, mkdir.c, truncate.c, mv.c, ... */
if (err == EACCES || err == EPERM) {
    XROOTD_RETURN_ERR(..., kXR_NotAuthorized, "permission denied");
}
if (err == ENOENT) {
    XROOTD_RETURN_ERR(..., kXR_NotFound, "file not found");
}
XROOTD_RETURN_ERR(..., kXR_IOError, strerror(err));
```

Phase 1 adds `xrootd_kxr_err_string(err)` — returns a static string matching the standard message for common errnos — so handlers can write:

```c
XROOTD_RETURN_ERR(ctx, c, op_id, op_name, path, detail,
                  xrootd_kxr_from_errno(err),
                  xrootd_kxr_err_string(err));
```

### Pattern C: Pool allocation guard

Throughout the codebase (especially `webdav/` and `s3/`), `ngx_palloc` is called with a size, then the result is NULL-checked with nearly identical boilerplate:

```c
foo = ngx_palloc(r->pool, sizeof(*foo));
if (foo == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
```

Phase 1 adds an `XROOTD_HTTP_ALLOC(r, ptr, type)` macro that expands to this pattern, and a stream equivalent `XROOTD_STREAM_ALLOC(log, ptr, sz)`.  These are purely cosmetic in Phase 1 but Phases 4 and 6 use them to reduce handler boilerplate.

---

## New Files

### `src/core/compat/err_strings.h` (new, header-only)

```c
/*
 * err_strings.h — canonical error message strings for common errnos.
 * These match the messages expected by conformance tests in test_conformance.py.
 */
#pragma once
#include <errno.h>

static inline const char *
xrootd_kxr_err_string(int err)
{
    switch (err) {
    case EACCES: /* fall through */
    case EPERM:  return "permission denied";
    case ENOENT: return "file not found";
    case ENOTDIR:return "not a directory";
    case EISDIR: return "is a directory";
    case ENOSPC: return "no space left on device";
    case EEXIST: return "already exists";
    case ENOMEM: return "out of memory";
    default:     return strerror(err);
    }
}
```

**Rationale:** `strerror(EACCES)` returns "Permission denied" (capital P) on Linux, but conformance tests assert lowercase "permission denied".  Centralising avoids any future case/format drift.

### `src/core/compat/alloc_macros.h` (new, header-only)

```c
/*
 * alloc_macros.h — pool allocation guard macros.
 *
 * HTTP context:
 *   XROOTD_HTTP_PALLOC(r, ptr, type) — allocates sizeof(type) from r->pool;
 *     returns NGX_HTTP_INTERNAL_SERVER_ERROR on failure.
 *
 * Stream context:
 *   XROOTD_STREAM_PALLOC(log, ptr, sz) — allocates sz bytes via ngx_alloc;
 *     returns NGX_ERROR on failure.
 */
#pragma once
#include <ngx_core.h>
#include <ngx_http.h>

#define XROOTD_HTTP_PALLOC(r, ptr, type)                            \
    do {                                                            \
        (ptr) = ngx_palloc((r)->pool, sizeof(type));               \
        if ((ptr) == NULL) {                                        \
            return NGX_HTTP_INTERNAL_SERVER_ERROR;                  \
        }                                                           \
    } while (0)

#define XROOTD_STREAM_PALLOC(log, ptr, sz)                          \
    do {                                                            \
        (ptr) = ngx_alloc((sz), (log));                             \
        if ((ptr) == NULL) {                                        \
            return NGX_ERROR;                                       \
        }                                                           \
    } while (0)
```

---

## Files Modified

No existing `.c` files change in Phase 1.  Only additions:

| File | Change |
|---|---|
| `src/core/compat/err_strings.h` | NEW — 35 LoC |
| `src/core/compat/alloc_macros.h` | NEW — 40 LoC |
| `src/core/ngx_xrootd_module.h` | Add `#include` for both new headers |

**Net LoC delta for Phase 1 itself:** +75 (new infrastructure).  The −300 reduction happens in Phases 2–6 as handlers adopt these helpers.

---

## Verification

```bash
# Must compile cleanly — no new ./configure needed (header-only changes)
make -j$(nproc) 2>&1 | grep -c "^error:"
# Expected: 0

# Full test suite must stay green
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
# Expected: all 2187 passed

# Headers included correctly
grep -r "err_strings.h" src/
grep -r "alloc_macros.h" src/
# Expected: only ngx_xrootd_module.h includes them
```

---

## Risk Assessment

**Low.** No handler logic changes.  New headers are `#include`-guarded and compile-only.  The only risk is a name collision with an existing symbol — verify with:

```bash
grep -r "xrootd_kxr_err_string\|XROOTD_HTTP_PALLOC\|XROOTD_STREAM_PALLOC" src/
# Expected: 0 matches (symbols don't exist yet)
```

## Rollback

```bash
git revert <phase-1-commit>
make -j$(nproc)
```

No state changes in nginx instances.  Revert is instantaneous.
