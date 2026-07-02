# Phase 18 — Auth Gate Completion

**Target**: migrate the remaining 5 files that use inline `xrootd_check_authdb` /
`xrootd_check_vo_acl_identity` / `xrootd_check_token_scope` triads to
`xrootd_auth_gate()`, fixing missing access log entries for auth failures and
completing the Phase 2 goal.

**Net LoC reduction**: ~50–70 LoC  
**Correctness fix**: 2 files currently send kXR_NotAuthorized without writing
an access log entry — silently dropping auth failures from the audit trail  
**Risk**: very low — `xrootd_auth_gate()` is already deployed in `stat.c`,
`op_table.c`, `mv.c`, `open_request.c`, and `truncate.c`; this extends the
same pattern  
**Requires**: `make -j$(nproc)` only — no new source files, no `./configure`

---

## Context

`src/auth/authz/auth_gate.c` and `src/auth/authz/auth_gate.h` implement:

```c
ngx_int_t xrootd_auth_gate(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_uint_t op_id, const char *op_name,
    const char *reqpath, const char *resolved,
    ngx_stream_xrootd_srv_conf_t *conf,
    int auth_level, int need_write);
```

On denial: logs via `xrootd_log_access()`, increments `XROOTD_OP_ERR`, stores
the wire response in `ctx->write_rc`, returns `NGX_DONE`.  
On success: returns `NGX_OK`.

The canonical call pattern (already in place in 5 files):

```c
if (xrootd_auth_gate(ctx, c, XROOTD_OP_MKDIR, "MKDIR",
                     reqpath, resolved, conf,
                     XROOTD_AUTH_UPDATE, /*need_write=*/1) != NGX_OK) {
    return ctx->write_rc;
}
```

Five files have not been migrated.  Three of them are pure deduplication;
two additionally fix a **missing access log entry** for auth failures.

---

## Files and changes

### `src/fattr/dispatch.c` — 1 full triad, auth_level varies by subcode

**Current** (~18 LoC across two separate scope blocks):

```c
{
    int need_write = (subcode == kXR_fattrSet
                      || subcode == kXR_fattrDel) ? 1 : 0;
    uint32_t needed = need_write ? XROOTD_AUTH_UPDATE : XROOTD_AUTH_READ;
    if (xrootd_check_authdb(ctx, resolved, needed) != NGX_OK) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "fattr: not authorized");
    }
}
if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
                                 ctx->identity) != NGX_OK) {
    XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
    return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                             "fattr: VO not authorized");
}
{
    int need_write = (subcode == kXR_fattrSet
                      || subcode == kXR_fattrDel) ? 1 : 0;
    if (xrootd_check_token_scope(ctx, pathbuf, need_write) != NGX_OK) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "fattr: token scope denied");
    }
}
```

**After** (~5 LoC):

```c
int need_write = (subcode == kXR_fattrSet
                  || subcode == kXR_fattrDel) ? 1 : 0;
uint32_t auth_level = need_write ? XROOTD_AUTH_UPDATE : XROOTD_AUTH_READ;
if (xrootd_auth_gate(ctx, c, XROOTD_OP_FATTR, "FATTR",
                     pathbuf, resolved, conf, auth_level, need_write) != NGX_OK) {
    return ctx->write_rc;
}
```

**Saves ~13 LoC.  Also adds missing access log entry for auth failures.**

Note: `need_write` is computed once instead of twice (the two nested scopes
were a defensive workaround for the variable scope issue that the merger
eliminates).

### `src/query/metadata.c` — 2 partial triads (authdb + vo, no token)

There are two independent query handlers in this file, each with an
`xrootd_check_authdb` + `xrootd_check_vo_acl_identity` pair that omits both
`xrootd_log_access()` and `xrootd_check_token_scope()`.

**Current** (~8 LoC each × 2):

```c
if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_READ) != NGX_OK) {
    XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_XATTR);
    return xrootd_send_error(ctx, c, kXR_NotAuthorized, "not authorized");
}
if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
                                 ctx->identity) != NGX_OK) {
    XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_XATTR);
    return xrootd_send_error(ctx, c, kXR_NotAuthorized, "VO not authorized");
}
```

**After** (~3 LoC each):

```c
if (xrootd_auth_gate(ctx, c, XROOTD_OP_QUERY_XATTR, "QUERY",
                     pathbuf, resolved, conf, XROOTD_AUTH_READ, 0) != NGX_OK) {
    return ctx->write_rc;
}
```

**Saves ~10 LoC per instance × 2 = ~20 LoC.  Adds missing access log entries
for auth failures AND adds the missing token scope check.**

### `src/query/checksum_qcksum.c` — 1 partial triad (authdb + vo, no token)

Uses `XROOTD_RETURN_ERR` (which includes log_access) — so logging is correct.
Missing only the token scope check.

**Current** (~8 LoC):

```c
if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_READ) != NGX_OK) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY",
                      resolved, "cksum", kXR_NotAuthorized, "not authorized");
}
if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
                                 ctx->identity) != NGX_OK) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY",
                      resolved, "cksum", kXR_NotAuthorized, "VO not authorized");
}
```

**After** (~3 LoC):

```c
if (xrootd_auth_gate(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY",
                     pathbuf, resolved, conf, XROOTD_AUTH_READ, 0) != NGX_OK) {
    return ctx->write_rc;
}
```

**Saves ~5 LoC. Adds missing token scope check.**

### `src/query/checksum_ckscan_dispatch.c` — 1 full triad using XROOTD_RETURN_ERR

All three auth checks use `XROOTD_RETURN_ERR`, so logging is correct.
Migration to `xrootd_auth_gate()` is purely structural deduplication.

**Current** (~12 LoC):

```c
if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_READ) != NGX_OK) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                      resolved, "ckscan", kXR_NotAuthorized, "not authorized");
}
if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
                                 ctx->identity) != NGX_OK) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                      pathbuf, "ckscan", kXR_NotAuthorized, "VO not authorized");
}
if (xrootd_check_token_scope(ctx, pathbuf, 0) != NGX_OK) {
    XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                      pathbuf, "ckscan", kXR_NotAuthorized, "token scope denied");
}
```

**After** (~3 LoC):

```c
if (xrootd_auth_gate(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                     pathbuf, resolved, conf, XROOTD_AUTH_READ, 0) != NGX_OK) {
    return ctx->write_rc;
}
```

**Saves ~9 LoC.**

---

## What NOT to change

### `src/query/prepare.c` — auth triads via `xrootd_prepare_check_fail()`

`prepare.c` routes all errors through a local helper that already calls
`xrootd_log_access()`:

```c
static ngx_int_t
xrootd_prepare_send_fail(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *path, uint16_t errcode, const char *errmsg)
{
    xrootd_log_access(ctx, c, "PREPARE", path != NULL ? path : "-",
                      "-", 0, errcode, errmsg, 0);
    return xrootd_send_error(ctx, c, errcode, errmsg);
}
```

The auth triads use this correctly:
```c
if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_READ) != NGX_OK) {
    return xrootd_prepare_check_fail(ctx, c, resolved, kXR_NotAuthorized,
                                     "not authorized");
}
```

This pattern is semantically correct and uses a prepare-specific helper that
wraps NGX_DONE for multi-path semantics.  Migrating to `xrootd_auth_gate()`
would require making auth_gate configurable for per-call error sinks — not
worth the complexity.  Leave as-is.

### `src/query/prepare.c` — conjunction form at line ~514

```c
if (   xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_READ) == NGX_OK
    && xrootd_check_vo_acl_identity(...) == NGX_OK
    && xrootd_check_token_scope(ctx, pathbuf, 0) == NGX_OK)
{
    ...
}
```

This is a **predicate** (checking whether something IS authorized without
sending an error).  `xrootd_auth_gate()` sends an error response on failure;
it cannot be used as a predicate.  Leave as-is.

---

## Honest LoC accounting

```
fattr/dispatch.c    (18 → 5 lines):   −13 LoC
query/metadata.c    (2× 8 → 3 lines): −20 LoC (2 handlers)
query/checksum_qcksum.c (8 → 3):       −5 LoC
query/checksum_ckscan_dispatch.c (12→3): −9 LoC
──────────────────────────────────────────
Net:                                   −47 LoC (correctness fix: no new LoC cost)
```

Uncertainty ±10 LoC depending on blank lines and comment wrapping.

---

## Correctness summary

| File | Before | After |
|------|--------|-------|
| `fattr/dispatch.c` | auth failure: no log, no token check | logged, token checked |
| `query/metadata.c` (×2) | auth failure: no log, no token check | logged, token checked |
| `query/checksum_qcksum.c` | auth failure: logged; no token check | logged, token checked |
| `query/checksum_ckscan_dispatch.c` | logged, all checks present | no change in semantics |

The two `query/metadata.c` handlers and `fattr/dispatch.c` currently drop
`kXR_NotAuthorized` responses silently from the access log.  An operator
debugging an auth failure for a `kXR_fattr` or `kXR_query/xattr` call would
see the request arrive but no denial event in the log.  After this phase,
every auth denial is recorded.

---

## Implementation steps

1. **`fattr/dispatch.c`**: locate the two nested scope blocks (lines ~106–132),
   replace with `need_write` variable and `xrootd_auth_gate()` call.

2. **`query/metadata.c`**: locate two handler functions; each has a 2-tier
   `authdb` + `vo_acl` check — replace each with `xrootd_auth_gate()`.

3. **`query/checksum_qcksum.c`**: replace `authdb` + `vo_acl` pair with
   `xrootd_auth_gate()`.

4. **`query/checksum_ckscan_dispatch.c`**: replace all three individual checks
   with `xrootd_auth_gate()`.

5. **Build and test**:
   ```bash
   make -j$(nproc)
   /tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf
   ```

---

## Tests (minimum 3)

No logic changes for ckscan, qcksum, fattr (token check was missing but should
not have been rejecting previously-passing requests — `xrootd_check_token_scope`
returns OK when no token is configured).  For metadata.c auth failures, the
behaviour becomes stricter: auth failures that previously sent `kXR_NotAuthorized`
without logging now also log.

```bash
# fattr operations: get, set, delete, list
PYTHONPATH=tests pytest tests/ -k "fattr" -v

# kXR_query operations: xattr, cksum, ckscan
PYTHONPATH=tests pytest tests/ -k "query or cksum or ckscan" -v

# Auth failure coverage: confirm denial is now in access log
PYTHONPATH=tests pytest tests/ -k "auth or denied or unauthorized" -v
```

Manual check after auth-failure test: confirm `xrootd_access*.log` contains
`kXR_NotAuthorized` entries for the denied fattr/query requests that previously
had no log line.

---

## Relationship to the series

| Phase | Target area | Net ΔLoC |
|-------|-------------|----------|
| Phase 12 | Shared HTTP file-serve | −80–110 |
| Phase 13 | AIO task dispatch macro | −10 |
| Phase 14 | Table-driven Prometheus export | −83 |
| Phase 15 | Unified namespace layer | −16 |
| Phase 16 | Unified prop store | −277 |
| Phase 17 | Error-response macro collapse | −414 |
| **Phase 18** | Auth gate completion | −47 |
| **Subtotal** | | **−927–957 LoC** |

Phase 18 closes the last known gap in the stream protocol handler consistency:
every path-based auth check now goes through `xrootd_auth_gate()`.
