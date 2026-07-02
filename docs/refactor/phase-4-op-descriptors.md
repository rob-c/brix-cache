# Phase 4: Simple Op Descriptor Tables

**Projected ΔLoC:** −450  
**Risk:** Medium  
**Depends on:** Phases 1, 2, 3  
**Blocks:** nothing (Phase 5 and 6 are independent)

---

## Goal

Replace the most uniform namespace-mutation handlers with a **descriptor table + interpreter** pattern.  After Phases 2 and 3, each simple handler is already a thin shell:

1. `xrootd_resolve_op_path()` → extract + resolve
2. `xrootd_auth_gate()` → three auth tiers
3. One syscall
4. `XROOTD_RETURN_OK` / `XROOTD_RETURN_ERR`

For handlers where step 3 is a single syscall with no special cases, the entire handler body can be expressed as a **descriptor entry** and a tiny `exec_*` function.  The interpreter loop handles steps 1, 2, and 4 exactly once.

---

## Descriptor Design

### `src/protocols/root/write/op_table.h` (new)

```c
#pragma once
#include "ngx_xrootd_module.h"
#include "../path/op_path.h"

/*
 * xrootd_op_exec_t — execution context passed to every op exec function.
 * Populated by the interpreter before calling exec().
 */
typedef struct {
    xrootd_ctx_t                  *ctx;
    ngx_connection_t              *c;
    ngx_stream_xrootd_srv_conf_t  *conf;
    const char                    *reqpath;   /* client-supplied, after extract */
    const char                    *resolved;  /* canonical, after resolve */
} xrootd_op_exec_t;

/*
 * xrootd_op_desc_t — declarative descriptor for a single namespace op.
 */
typedef struct {
    uint16_t            opcode;
    const char         *name;          /* "CHMOD", "RM", etc. */
    xrootd_op_t         op_id;         /* XROOTD_OP_* */
    int                 auth_level;    /* XROOTD_AUTH_* */
    int                 need_write;    /* token write scope required */
    xrootd_path_mode_t  path_mode;     /* EXISTING / WRITE / NOEXIST / EITHER */
    ngx_int_t         (*exec)(const xrootd_op_exec_t *exec,
                               int *out_errno);
} xrootd_op_desc_t;

/*
 * xrootd_dispatch_op — interpreter entry point.
 * Looks up the descriptor, resolves path, gates auth, calls exec.
 * Returns NGX_OK / NGX_ERROR as appropriate for nginx event loop.
 */
ngx_int_t xrootd_dispatch_op(xrootd_ctx_t *ctx, ngx_connection_t *c,
                              ngx_stream_xrootd_srv_conf_t *conf,
                              uint16_t opcode);
```

### `src/protocols/root/write/op_table.c` (new, ~120 LoC)

The interpreter:

```c
#include "ngx_xrootd_module.h"
#include "op_table.h"
#include "../compat/err_strings.h"   /* Phase 1 */

/* --- exec functions (one per op) ---------------------------------------- */

static ngx_int_t exec_chmod(const xrootd_op_exec_t *e, int *out_errno)
{
    ClientChmodRequest *req = (ClientChmodRequest *) e->ctx->hdr_buf;
    mode_t mode = ntohs(req->mode) & 0777;
    if (mode == 0) mode = 0644;
    if (chmod(e->resolved, mode) == 0) return NGX_OK;
    *out_errno = errno;
    return NGX_ERROR;
}

static ngx_int_t exec_rm(const xrootd_op_exec_t *e, int *out_errno)
{
    xrootd_ns_delete_opts_t opts = {0};
    xrootd_ns_result_t res = xrootd_ns_delete(e->c->log,
                                 e->conf->common.root_canon,
                                 e->resolved, &opts);
    if (res.status == XROOTD_NS_OK) return NGX_OK;
    /* Retry as directory if unlink hit EISDIR */
    if (res.was_dir) {
        opts.recursive = 1;
        res = xrootd_ns_delete(e->c->log, e->conf->common.root_canon,
                               e->resolved, &opts);
        if (res.status == XROOTD_NS_OK) return NGX_OK;
    }
    *out_errno = res.sys_errno;
    return NGX_ERROR;
}

static ngx_int_t exec_rmdir(const xrootd_op_exec_t *e, int *out_errno)
{
    if (xrootd_unlink_confined(e->c->log, &e->conf->common.root,
                               e->resolved, 1) == 0) {
        return NGX_OK;
    }
    *out_errno = errno;
    return NGX_ERROR;
}

/* --- descriptor table ---------------------------------------------------- */

static const xrootd_op_desc_t _ops[] = {
    { kXR_chmod,  "CHMOD",  XROOTD_OP_CHMOD,  XROOTD_AUTH_UPDATE, 1,
      XROOTD_PATH_EXISTING, exec_chmod },
    { kXR_rm,     "RM",     XROOTD_OP_RM,     XROOTD_AUTH_DELETE, 1,
      XROOTD_PATH_EXISTING, exec_rm    },
    { kXR_rmdir,  "RMDIR",  XROOTD_OP_RMDIR,  XROOTD_AUTH_DELETE, 1,
      XROOTD_PATH_EITHER,   exec_rmdir },
};
#define N_OPS (sizeof(_ops) / sizeof(_ops[0]))

/* --- interpreter --------------------------------------------------------- */

ngx_int_t
xrootd_dispatch_op(xrootd_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_xrootd_srv_conf_t *conf,
                   uint16_t opcode)
{
    char reqpath[XROOTD_MAX_PATH + 1];
    char resolved[PATH_MAX];
    const xrootd_op_desc_t *d = NULL;

    for (size_t i = 0; i < N_OPS; i++) {
        if (_ops[i].opcode == opcode) { d = &_ops[i]; break; }
    }
    if (d == NULL) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest, "unknown opcode");
    }

    if (xrootd_resolve_op_path(ctx, c, d->op_id, d->name, conf,
                               d->path_mode,
                               reqpath, sizeof(reqpath),
                               resolved, sizeof(resolved)) != NGX_OK) {
        return ctx->write_rc;
    }

    if (xrootd_auth_gate(ctx, c, d->op_id, d->name,
                         reqpath, resolved, conf,
                         d->auth_level, d->need_write) != NGX_OK) {
        return ctx->write_rc;
    }

    xrootd_op_exec_t exec = {
        .ctx = ctx, .c = c, .conf = conf,
        .reqpath = reqpath, .resolved = resolved,
    };
    int err = 0;
    if (d->exec(&exec, &err) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, d->op_id, d->name, resolved, "-",
                          xrootd_kxr_from_errno(err),
                          xrootd_kxr_err_string(err));
    }

    XROOTD_RETURN_OK(ctx, c, d->op_id, d->name, resolved, "-", 0);
}
```

---

## Handler Files That Collapse

After Phase 3, the following handlers become wrappers that can be reduced to a single dispatch call:

### `src/protocols/root/write/chmod.c` — 90 LoC → 12 LoC

**Before:** Full handler with path resolution, three-tier auth, chmod, errno mapping (90 lines).

**After:**

```c
/*
 * chmod.c — kXR_chmod: delegate to op descriptor table.
 */
#include "ngx_xrootd_module.h"
#include "op_table.h"

ngx_int_t
xrootd_handle_chmod(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    return xrootd_dispatch_op(ctx, c, conf, kXR_chmod);
}
```

12 lines.  **−78 LoC.**

### `src/protocols/root/write/rm.c` — 98 LoC → 12 LoC

```c
/*
 * rm.c — kXR_rm: delegate to op descriptor table.
 */
#include "ngx_xrootd_module.h"
#include "op_table.h"

ngx_int_t
xrootd_handle_rm(xrootd_ctx_t *ctx, ngx_connection_t *c,
                 ngx_stream_xrootd_srv_conf_t *conf)
{
    return xrootd_dispatch_op(ctx, c, conf, kXR_rm);
}
```

**−86 LoC.**

### `src/protocols/root/write/rmdir.c` — 97 LoC (post-Phase-3) → 12 LoC

**−85 LoC.**

---

## Handlers That Are NOT Good Descriptor Candidates

These handlers have non-trivial logic that cannot be cleanly expressed in a descriptor and should remain as explicit handlers:

| Handler | Reason to keep as-is |
|---|---|
| `src/protocols/root/write/sync.c` | TPC arm/flush dual semantics; TPC state machine in exec path |
| `src/protocols/root/write/truncate.c` | Two modes: handle-based (fd lookup) vs path-based; both in same handler |
| `src/protocols/root/write/mkdir.c` | Recursive vs non-recursive different syscall paths + group policy |
| `src/protocols/root/write/mv.c` | Two-path operation (src + dst resolution); atomic rename semantics |
| `src/protocols/root/write/pgwrite.c` | CRC32c per-page framing; async I/O path |
| `src/protocols/root/write/write.c` | Write-recovery journal; async I/O path; cache writethrough |
| `src/protocols/root/read/stat.c` | Complex stat response formatting (sbuf → kXR_StatRsp) |
| `src/protocols/root/read/locate.c` | Cluster/manager mode redirector; complex response body |
| `src/protocols/root/read/open_request.c` | Most complex handler: cache, TPC, compression, write-through |

These handlers benefit from Phases 2 and 3 (auth gate + path middleware) but do not reduce to simple descriptors.

---

## Phase 4 LoC Delta Summary

| File | Before | After | Delta |
|---|---|---|---|
| `src/protocols/root/write/chmod.c` | 90 | 12 | −78 |
| `src/protocols/root/write/rm.c` | 98 | 12 | −86 |
| `src/protocols/root/write/rmdir.c` | 97* | 12 | −85 |
| `src/protocols/root/write/op_table.c` (new) | 0 | 120 | +120 |
| `src/protocols/root/write/op_table.h` (new) | 0 | 50 | +50 |
| **Net** | | | **−179** |

*Post-Phase-3 size.

Additional LoC reductions in Phase 4 come from converting `stat.c` and `close.c` to use descriptor-style cleanup once they are standardised on Phase 2/3 infrastructure.  These are optional sub-tasks within Phase 4:

| Optional | File | Current | After | Delta |
|---|---|---|---|---|
| Optional | `src/protocols/root/read/close.c` | 206 | 80 | −126 |
| Optional | `src/protocols/root/read/stat.c` (partial) | 211 | 150 | −61 |
| Optional | `src/protocols/root/read/locate.c` (partial) | 213* | 175 | −38 |

With optional sub-tasks: total Phase 4 ΔLoC ≈ **−404**.

---

## Files Added to `config.h`

```
$ngx_addon_dir/src/protocols/root/write/op_table.c
```

Requires `./configure`.

---

## Dispatch Table Registration

The existing `handshake/dispatch_write.c` (or equivalent) already routes `kXR_chmod`, `kXR_rm`, `kXR_rmdir` opcodes to their handler functions.  After Phase 4, those handler functions simply call `xrootd_dispatch_op`.  No changes to the dispatch table registration itself are needed — handler function names remain the same.

---

## Verification

```bash
# Build
cd /tmp/nginx-1.28.3
./configure --with-stream --with-http_ssl_module --with-http_dav_module \
            --with-threads --add-module=$REPO
make -j$(nproc) 2>&1 | grep "^error:" | wc -l

# Unit-level: namespace mutation operations
PYTHONPATH=tests pytest tests/test_conformance.py -k "chmod or rm or rmdir" -v
PYTHONPATH=tests pytest tests/test_concurrent.py -k "rm or mkdir" -v

# Auth edge cases: ensure authdb/VO/token denial still returns kXR_NotAuthorized (3010)
PYTHONPATH=tests pytest tests/test_conformance.py -k "auth" -v

# Regression: full suite
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

---

## Risk Assessment

**Medium.**  The interpreter adds one level of indirection between opcode dispatch and the syscall.  The main risks are:

1. **Incorrect descriptor entry** — wrong `auth_level`, `need_write`, or `path_mode` for an opcode.  Mitigation: each entry has exactly one corresponding test in `test_conformance.py`; run targeted tests after adding each entry.

2. **exec function return value** — `exec_rm` has special-case retry logic (was_dir).  Verify `rm` on a directory-type target still works correctly.

3. **`out_errno` initialisation** — `err = 0` before `d->exec()` call; if exec returns NGX_ERROR without setting `*out_errno`, the error mapping receives `err == 0` and produces a confusing "Success" message.  Add assert in debug builds: `assert(err != 0)` after NGX_ERROR return.

## Rollback

```bash
git revert <phase-4-commit>
./configure ...
make -j$(nproc)
```

handler files revert; chmod.c, rm.c, rmdir.c return to their Phase-3 forms.
