# Phase 3: Path Resolution Middleware

**Projected ΔLoC:** −200  
**Risk:** Medium  
**Depends on:** Phase 2 (auth_gate must be in place)  
**Blocks:** Phase 4

---

## Goal

Standardise path extraction and resolution across all namespace handlers.  Currently, 22 handlers do one of two things:

1. Call `xrootd_write_resolve_existing_path()` — a combined extractor+resolver+auth-checker wrapper (used by `chmod.c`, `rm.c`)
2. Inline the 3-step sequence: `xrootd_extract_path` → `xrootd_resolve_path*` → depth check (used by `rmdir.c`, `mkdir.c`, `truncate.c`, `stat.c`, `locate.c`, and others)

This phase introduces a unified resolver `xrootd_resolve_op_path()` that replaces both variants and eliminates the inconsistency.  The auth step that was baked into `xrootd_write_resolve_existing_path` is now handled by the Phase 2 `xrootd_auth_gate()` call, making each step independently composable.

---

## Inventory of Inline Resolution Sites

```
src/write/rmdir.c      lines 55-73   — extract + depth + resolve (two fallbacks)
src/write/mkdir.c      lines 66-107  — extract + depth + conditional resolve
src/write/truncate.c   lines 68-93   — extract + depth + write-fallback + read-fallback
src/read/stat.c        lines ~40-65  — extract + depth + resolve
src/read/locate.c      lines ~30-55  — extract + resolve
src/read/open_request.c lines ~35-70 — extract + depth + resolve_write
src/dirlist/handler.c  lines ~40-80  — extract + depth + resolve
src/query/prepare.c    lines ~25-50  — extract + resolve
src/query/prepare_cmd.c lines ~20-45 — extract + resolve
src/write/mv.c         lines ~30-70  — extract (x2, src + dst) + depth (x2) + resolve
```

That is roughly 30 lines per handler × 10 handlers = 300 lines of near-identical extraction+resolution code.

---

## Proposed Unified Resolver

### `src/path/op_path.h` (new)

```c
#pragma once
#include "ngx_xrootd_module.h"

typedef enum {
    XROOTD_PATH_EXISTING,     /* target must exist (read ops, chmod, rm) */
    XROOTD_PATH_WRITE,        /* parent must exist, target may not (write create) */
    XROOTD_PATH_NOEXIST,      /* full path may not exist (recursive mkdir) */
    XROOTD_PATH_EITHER,       /* try WRITE first, fall back to EXISTING (truncate) */
} xrootd_path_mode_t;

/*
 * xrootd_resolve_op_path — extract, clean, depth-check, and resolve a path
 * from the current request payload.
 *
 * On success: reqpath and resolved are filled; returns NGX_OK.
 * On failure: sends the appropriate kXR_error response and returns NGX_DONE;
 *             caller must return ctx->write_rc.
 *
 * Parameters:
 *   ctx      — connection context (payload + cur_dlen consumed here)
 *   c        — nginx connection (for logging + error sending)
 *   op_id    — XROOTD_OP_* for error framing
 *   op_name  — string label ("MKDIR", "CHMOD", etc.)
 *   conf     — server config (root, depth limit)
 *   mode     — path resolution strategy (see enum above)
 *   reqpath  — caller-provided buffer, XROOTD_MAX_PATH+1 bytes
 *   resolved — caller-provided buffer, PATH_MAX bytes
 */
ngx_int_t xrootd_resolve_op_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
                                  xrootd_op_t op_id, const char *op_name,
                                  ngx_stream_xrootd_srv_conf_t *conf,
                                  xrootd_path_mode_t mode,
                                  char *reqpath, size_t reqpath_sz,
                                  char *resolved, size_t resolved_sz);
```

### `src/path/op_path.c` (new, ~80 LoC)

```c
/*
 * op_path.c — unified path extractor + resolver for namespace operations.
 *
 * Centralises: extract_path → depth_check → resolve (mode-dependent) logic
 * that was previously copied into 10+ handler files.
 */
#include "ngx_xrootd_module.h"
#include "op_path.h"

ngx_int_t
xrootd_resolve_op_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
                       xrootd_op_t op_id, const char *op_name,
                       ngx_stream_xrootd_srv_conf_t *conf,
                       xrootd_path_mode_t mode,
                       char *reqpath, size_t reqpath_sz,
                       char *resolved, size_t resolved_sz)
{
    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        ctx->write_rc = xrootd_send_named_error(ctx, c, op_id, op_name,
                            "-", "-", kXR_ArgMissing, "no path given");
        return NGX_DONE;
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath, reqpath_sz, 1)) {
        ctx->write_rc = xrootd_send_named_error(ctx, c, op_id, op_name,
                            "-", "-", kXR_ArgInvalid, "invalid path payload");
        return NGX_DONE;
    }

    if (xrootd_count_path_depth(reqpath) != NGX_OK) {
        ctx->write_rc = xrootd_send_named_error(ctx, c, op_id, op_name,
                            reqpath, "-", kXR_ArgInvalid, "path exceeds maximum depth");
        return NGX_DONE;
    }

    int ok = 0;
    switch (mode) {
    case XROOTD_PATH_EXISTING:
        ok = xrootd_resolve_path(c->log, &conf->common.root,
                                 reqpath, resolved, resolved_sz);
        break;
    case XROOTD_PATH_WRITE:
        ok = xrootd_resolve_path_write(c->log, &conf->common.root,
                                       reqpath, resolved, resolved_sz);
        break;
    case XROOTD_PATH_NOEXIST:
        ok = xrootd_resolve_path_noexist(c->log, &conf->common.root,
                                          reqpath, resolved, resolved_sz);
        break;
    case XROOTD_PATH_EITHER:
        ok = xrootd_resolve_path_write(c->log, &conf->common.root,
                                        reqpath, resolved, resolved_sz);
        if (!ok) {
            ok = xrootd_resolve_path(c->log, &conf->common.root,
                                     reqpath, resolved, resolved_sz);
        }
        break;
    }

    if (!ok) {
        ctx->write_rc = xrootd_send_named_error(ctx, c, op_id, op_name,
                            reqpath, "-", kXR_NotFound, "invalid path");
        return NGX_DONE;
    }

    return NGX_OK;
}
```

---

## Concrete Before/After: `src/write/rmdir.c`

**Before** (lines 55–73, ~18 lines):

```c
if (ctx->payload == NULL || ctx->cur_dlen == 0) {
    return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
}

if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                         reqpath, sizeof(reqpath), 1)) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", "-", "-",
                      kXR_ArgInvalid, "invalid path payload");
}

exists = xrootd_resolve_path(c->log, &conf->common.root, reqpath,
                             resolved, sizeof(resolved));
if (!exists &&
    !xrootd_resolve_path_noexist(c->log, &conf->common.root, reqpath,
                                  resolved, sizeof(resolved))) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_RMDIR, "RMDIR", reqpath, "-",
                      kXR_NotFound, "invalid path");
}
```

**After** (3 lines):

```c
if (xrootd_resolve_op_path(ctx, c, XROOTD_OP_RMDIR, "RMDIR", conf,
                            XROOTD_PATH_EITHER,
                            reqpath, sizeof(reqpath),
                            resolved, sizeof(resolved)) != NGX_OK) {
    return ctx->write_rc;
}
```

Note: `XROOTD_PATH_EITHER` replaces the `XROOTD_PATH_NOEXIST` fallback pattern in rmdir.  The `exists` flag logic (idempotent success if path does not exist) is preserved in the handler after the resolve call — that is application logic, not resolution logic, and stays in the handler.

---

## Concrete Before/After: `src/write/truncate.c`

**Before** (lines 68–93, ~25 lines):

```c
if (ctx->payload == NULL) {
    return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
}
if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                         reqpath, sizeof(reqpath), 1)) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE", "-",
                      detail, kXR_ArgInvalid, "invalid path payload");
}
if (!xrootd_resolve_path_write(c->log, &conf->common.root,
                               reqpath, resolved, sizeof(resolved))) {
    if (!xrootd_resolve_path(c->log, &conf->common.root,
                             reqpath, resolved, sizeof(resolved))) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE",
                          reqpath, detail, kXR_NotFound, "file not found");
    }
}
```

**After** (3 lines):

```c
if (xrootd_resolve_op_path(ctx, c, XROOTD_OP_TRUNCATE, "TRUNCATE", conf,
                            XROOTD_PATH_EITHER,
                            reqpath, sizeof(reqpath),
                            resolved, sizeof(resolved)) != NGX_OK) {
    return ctx->write_rc;
}
```

---

## Handler Conversion Table

| Handler | Path Mode | Lines removed | New LoC |
|---|---|---|---|
| `src/write/rmdir.c` | EITHER | −18 | 79 |
| `src/write/mkdir.c` (recursive) | NOEXIST | −20 | 117 |
| `src/write/mkdir.c` (non-recur) | WRITE | folded into above | — |
| `src/write/truncate.c` (path) | EITHER | −25 | 113 |
| `src/read/stat.c` | EXISTING | −18 | 181 |
| `src/read/locate.c` | EXISTING | −15 | 198 |
| `src/read/open_request.c` | WRITE | −18 | ~150 |
| `src/dirlist/handler.c` | EXISTING | −20 | 654 |
| `src/query/prepare.c` | EXISTING | −15 | ~96 |
| `src/query/prepare_cmd.c` | EXISTING | −12 | ~79 |
| **New infrastructure** | | +80 | 80 |
| **Net** | | **−161** | |

Note: `mv.c` handles two paths (source + destination) and requires two calls to `xrootd_resolve_op_path`; this is handled in Phase 4.

---

## Files Added to `config.h`

```
$ngx_addon_dir/src/path/op_path.c
```

Requires `./configure` before `make`.

---

## Special Case: `src/write/mkdir.c` Recursive Flag

`mkdir.c` currently selects the resolver based on the `kXR_mkdirpath` flag:

```c
if (recursive) {
    /* NOEXIST resolver */
} else {
    /* WRITE resolver */
}
```

After Phase 3, this becomes:

```c
xrootd_path_mode_t mode = recursive ? XROOTD_PATH_NOEXIST : XROOTD_PATH_WRITE;
if (xrootd_resolve_op_path(ctx, c, XROOTD_OP_MKDIR, "MKDIR", conf,
                            mode, reqpath, sizeof(reqpath),
                            resolved, sizeof(resolved)) != NGX_OK) {
    return ctx->write_rc;
}
```

The conditional is preserved but expressed as data (the mode enum) rather than a branching code path.

---

## Verification

```bash
# Configure required (new .c file)
cd /tmp/nginx-1.28.3
./configure --with-stream --with-http_ssl_module --with-http_dav_module \
            --with-threads --add-module=$REPO
make -j$(nproc) 2>&1 | grep "^error:" | wc -l
# Expected: 0

# Path edge cases: depth limit, null payload, path escape
PYTHONPATH=tests pytest tests/test_conformance.py -k "path" -v
PYTHONPATH=tests pytest tests/test_a_robustness.py -v

# Namespace ops: mkdir, rmdir, stat, truncate, locate
PYTHONPATH=tests pytest tests/test_conformance.py -k "mkdir or rmdir or stat or truncate or locate" -v

# Full suite
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

---

## Risk Assessment

**Medium.**  The resolver has three variants with subtly different semantics (EXISTING vs WRITE vs NOEXIST vs EITHER).  If the wrong mode is chosen for a handler the operation will fail with kXR_NotFound on paths that should succeed (or succeed on paths that shouldn't resolve).

Mitigation strategy: convert one handler at a time.  After each conversion, run the targeted test for that operation before touching the next handler.  Conversion order: rmdir → mkdir → truncate → stat → locate → open_request → dirlist → prepare.

The `XROOTD_PATH_EITHER` mode (write fallback → read fallback) must exactly replicate the original two-call fallback pattern in truncate.c and rmdir.c.  Verify by testing truncate on an existing file AND a non-existent path:

```bash
PYTHONPATH=tests pytest tests/test_conformance.py::TestTruncate -v
```

## Rollback

```bash
git revert <phase-3-commit>
./configure ...
make -j$(nproc)
```
