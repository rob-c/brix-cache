# Phase 2: Auth Gate Unification

**Projected ΔLoC:** −250  
**Risk:** Low-Medium  
**Depends on:** Phase 1  
**Blocks:** Phases 3, 4

---

## Goal

Replace 35+ inline three-tier auth check sequences with a single `xrootd_auth_gate()` call.  Every write and read handler currently repeats the same three-call pattern; this phase centralises it once in `src/path/auth_gate.c` and `src/path/auth_gate.h`.

---

## The Repeated Pattern (35+ call sites)

This exact sequence appears in `mkdir.c`, `rmdir.c`, `truncate.c`, `chmod.c` (via the shared resolver), `dirlist/handler.c`, `read/stat.c`, `read/locate.c`, and many more:

```c
/* Tier 1: authdb ACL */
if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_UPDATE) != NGX_OK) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
                      kXR_NotAuthorized, "authdb denied");
}
/* Tier 2: VO ACL */
if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
                         ctx->identity) != NGX_OK) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
                      kXR_NotAuthorized, "VO not authorized");
}
/* Tier 3: Token scope */
if (xrootd_check_token_scope(ctx, reqpath, 1) != NGX_OK) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", reqpath, "-",
                      kXR_NotAuthorized, "token scope denied");
}
```

That is **9 lines per handler** (3 calls + 3 RETURN_ERR blocks, each 2-3 lines).  After Phase 2 it becomes:

```c
if (xrootd_auth_gate(ctx, c, XROOTD_OP_MKDIR, "MKDIR",
                     reqpath, resolved, conf,
                     XROOTD_AUTH_UPDATE, /*need_write=*/1) != NGX_OK) {
    return ctx->write_rc;
}
```

**2 lines per handler** — a reduction of 7 lines × 35 sites = 245 lines removed.

---

## New Infrastructure

### `src/path/auth_gate.h` (new)

```c
#pragma once
#include "ngx_xrootd_module.h"

/*
 * xrootd_auth_gate — execute all three auth tiers for a resolved path.
 *
 * Parameters:
 *   ctx        — connection context (carries identity, token, write_rc output)
 *   c          — nginx connection (for logging)
 *   op_id      — XROOTD_OP_* constant for metric tracking
 *   op_name    — string label used in access log ("MKDIR", "CHMOD", etc.)
 *   reqpath    — client-supplied path (used for token scope check)
 *   resolved   — canonical resolved path (used for authdb + VO checks)
 *   conf       — server config carrying vo_rules, authdb
 *   auth_level — XROOTD_AUTH_READ / XROOTD_AUTH_UPDATE / XROOTD_AUTH_DELETE /
 *                XROOTD_AUTH_MKDIR
 *   need_write — 1 if token write scope is required, 0 for read
 *
 * Returns:
 *   NGX_OK   — all tiers passed; caller may proceed with the operation
 *   NGX_DONE — one tier denied; the wire response has already been sent;
 *              caller must return ctx->write_rc immediately
 *
 * On NGX_DONE, ctx->write_rc holds the value that the handler must return
 * to nginx (typically NGX_OK after xrootd_send_error completes the response).
 */
ngx_int_t xrootd_auth_gate(xrootd_ctx_t *ctx, ngx_connection_t *c,
                            xrootd_op_t op_id, const char *op_name,
                            const char *reqpath, const char *resolved,
                            ngx_stream_xrootd_srv_conf_t *conf,
                            int auth_level, int need_write);
```

### `src/path/auth_gate.c` (new, ~60 LoC)

```c
/*
 * auth_gate.c — three-tier auth check for path-based operations.
 *
 * Called by every handler that performs a namespace operation on a
 * canonically-resolved path.  Checks authdb, VO ACL, and token scope in
 * order; sends the kXR_error response and returns NGX_DONE on first failure.
 */
#include "ngx_xrootd_module.h"
#include "auth_gate.h"

ngx_int_t
xrootd_auth_gate(xrootd_ctx_t *ctx, ngx_connection_t *c,
                 xrootd_op_t op_id, const char *op_name,
                 const char *reqpath, const char *resolved,
                 ngx_stream_xrootd_srv_conf_t *conf,
                 int auth_level, int need_write)
{
    if (xrootd_check_authdb(ctx, resolved, auth_level) != NGX_OK) {
        ctx->write_rc = xrootd_send_named_error(ctx, c, op_id, op_name,
                            resolved, "-", kXR_NotAuthorized, "authdb denied");
        return NGX_DONE;
    }

    if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
                                     ctx->identity) != NGX_OK) {
        ctx->write_rc = xrootd_send_named_error(ctx, c, op_id, op_name,
                            resolved, "-", kXR_NotAuthorized, "VO not authorized");
        return NGX_DONE;
    }

    if (need_write && xrootd_check_token_scope(ctx, reqpath, 1) != NGX_OK) {
        ctx->write_rc = xrootd_send_named_error(ctx, c, op_id, op_name,
                            reqpath, "-", kXR_NotAuthorized, "token scope denied");
        return NGX_DONE;
    }

    return NGX_OK;
}
```

**Note:** `xrootd_send_named_error` is a thin wrapper over the existing error sender that accepts `op_id` and `op_name` explicitly; this avoids the RETURN_ERR macro's implicit return and lets the gate function communicate results via `ctx->write_rc`.

---

## `ctx->write_rc` Field

`xrootd_ctx_t` needs one new field:

```c
/* In src/types/context.h, inside xrootd_ctx_t: */
ngx_int_t  write_rc;   /* populated by xrootd_auth_gate on NGX_DONE */
```

This is zero-initialised at context allocation and is only meaningful immediately after an `xrootd_auth_gate` call returns NGX_DONE.

---

## Files to Modify

### Handlers that do the inline auth triad (to be converted)

| File | LoC before | Lines removed | LoC after |
|---|---|---|---|
| `src/write/rmdir.c` | 115 | −18 | 97 |
| `src/write/mkdir.c` | 155 | −18 | 137 |
| `src/write/truncate.c` | 150 | −12 | 138 |
| `src/write/mv.c` | 163 | −15 | 148 |
| `src/read/stat.c` | 211 | −12 | 199 |
| `src/read/locate.c` | 225 | −12 | 213 |
| `src/dirlist/handler.c` | 692 | −18 | 674 |
| `src/read/open_request.c` | ~180 | −12 | ~168 |
| `src/query/prepare.c` | ~120 | −9 | ~111 |
| `src/query/prepare_cmd.c` | ~100 | −9 | ~91 |
| (others in read/ + session/) | ~150 | −30 | ~120 |
| **New infrastructure** | 0 | +120 | 120 |
| **Net** | | **−135** | |

Note: `src/write/chmod.c` and `src/write/rm.c` already use `xrootd_write_resolve_existing_path` which wraps auth internally; those are converted in Phase 3 instead.

### New files added to `src/config/config.h`

```
# In NGX_ADDON_SRCS, add:
$ngx_addon_dir/src/path/auth_gate.c
```

This requires a `./configure` run before `make`.

---

## Concrete Before/After: `src/write/mkdir.c`

**Before** (lines 109–123):

```c
if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_MKDIR) != NGX_OK) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
                      kXR_NotAuthorized, "authdb denied");
}

if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
                         ctx->identity) != NGX_OK) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", resolved, "-",
                      kXR_NotAuthorized, "VO not authorized");
}

if (xrootd_check_token_scope(ctx, reqpath, 1) != NGX_OK) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "MKDIR", reqpath, "-",
                      kXR_NotAuthorized, "token scope denied");
}
```

**After** (2 lines):

```c
if (xrootd_auth_gate(ctx, c, XROOTD_OP_MKDIR, "MKDIR",
                     reqpath, resolved, conf,
                     XROOTD_AUTH_MKDIR, 1) != NGX_OK) {
    return ctx->write_rc;
}
```

---

## Verification

```bash
# Configure required (new .c file)
cd /tmp/nginx-1.28.3
./configure --with-stream --with-http_ssl_module --with-http_dav_module \
            --with-threads --add-module=$REPO
make -j$(nproc) 2>&1 | grep "^error:" | wc -l
# Expected: 0

# Auth denial must still produce kXR_NotAuthorized (3010)
PYTHONPATH=tests pytest tests/test_conformance.py -k "auth" -v
PYTHONPATH=tests pytest tests/test_credential_translation.py -v
PYTHONPATH=tests pytest tests/test_a_robustness.py -v

# Full suite
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

---

## Risk Assessment

**Low-Medium.**  The auth logic itself does not change — only the call site structure.  The main risk is subtle argument ordering: `reqpath` and `resolved` must be passed in the correct positions for authdb vs token scope checks.  Mitigation: convert one file at a time and run targeted auth tests after each conversion before moving to the next file.

A secondary risk is the new `ctx->write_rc` field: it must be zero-initialised.  Verify by checking `ngx_pcalloc` usage at context allocation sites:

```bash
grep -n "ngx_pcalloc.*xrootd_ctx_t" src/
```

`ngx_pcalloc` zero-initialises, so the new field starts as 0 (NGX_OK) by default.

## Rollback

```bash
git revert <phase-2-commit>
./configure ...   # same flags
make -j$(nproc)
```

All handler files that were modified revert to their inline auth triads.  No nginx config changes required.
