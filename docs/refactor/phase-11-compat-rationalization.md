# Phase 11: compat/ Rationalization — nginx + OpenSSL Audit

**Projected ΔLoC:** −200 (conservative) / −310 (optimistic)  
**Risk:** Low  
**Depends on:** nothing  
**Blocks:** nothing  
**Parallel-safe with:** all other phases

---

## Premise and honest assessment

`compat/` is 8,123 LoC across 65 files.  The framing "compat/ → nginx + OpenSSL"
implies that most of the layer is wrapping those two libraries and could be deleted.
Reading the code corrects this:

| Claim | Reality |
|---|---|
| OpenSSL provides CRC32c | `openssl list -digest-algorithms` returns no CRC entry — confirmed |
| nginx exposes range/conditional/sendfile APIs | These are nginx internals, not public module APIs |
| compat/ wraps nginx HTTP primitives | Most files implement domain logic (SSRF guards, XRootD protocol, RFC 7232/7233, filesystem ops) |
| EVP context allocations are expensive | `checksum.c` already uses static `EVP_sha256()`/`EVP_md5()` — no fetch per call |

**The real opportunities are different from the premise:**

1. **Double-wrapper elimination** — several compat/ files have exactly one external caller
   that is itself a thin wrapper, creating a two-hop indirection that adds no value.

2. **nginx direct-field access** — callers in `s3/` already bypass `http_query.c` and
   call `ngx_http_arg()` directly; `http_conditionals.c` already uses
   `r->headers_in.if_match` directly.  The pattern is inconsistent.  This phase
   audits and normalises the boundary.

3. **Permanent compat/ files** — 48 of 65 files are irreplaceable domain code.
   Documenting them as permanent prevents future phases from re-auditing them.

---

## What OpenSSL 3.x does NOT provide (confirmed)

```bash
$ openssl list -digest-algorithms | grep -i crc
# (no output)
```

- **CRC32c** — not in any OpenSSL provider.  `crc32c.c` (267 LoC) with SSE4.2 intrinsics
  stays.  It is not a candidate for replacement.
- **Adler-32 / CRC32** — already via zlib `adler32()` / `crc32()` (not OpenSSL).  Correct.
- **MD5, SHA1, SHA256** — already via OpenSSL `EVP_md5()` / `EVP_sha1()` / `EVP_sha256()`
  (static singletons, no per-call `EVP_MD_fetch`).  Already optimal.

---

## What nginx already provides (and where it IS used)

| nginx primitive | Already used directly in | compat/ wrapper |
|---|---|---|
| `ngx_http_arg(r, key, len, &val)` | `s3/auth_sigv4_parse.c:155,229`, `auth_sigv4_verify.c:99` | `http_query.c` |
| `r->headers_in.if_match` | `compat/http_conditionals.c:117` | — |
| `r->headers_in.if_none_match` | `compat/http_conditionals.c:118` | — |
| `ngx_parse_http_time()` | `compat/http_conditionals.c:174` | — |
| `ngx_http_read_client_request_body()` | `compat/http_body.c:277` | `xrootd_http_read_body()` |

Observation: `http_conditionals.c` already uses nginx fields directly — there is no
indirection to remove there.  `http_query.c` has a clear split: auth code (simple
lookups without decoding) already uses `ngx_http_arg()`; S3 list code (needs
percent-decoding, flags, continuation tokens) cannot — `http_query.c` is correct for
those callers.

---

## Change A: Dissolve the compat/cors.c + webdav/cors.c double-wrapper

### Current structure (two hops for one feature)

```
webdav/dispatch.c
    └── webdav/cors.c            (38 LoC — builds xrootd_cors_conf_t, calls compat)
            └── compat/cors.c    (152 LoC — actual header insertion logic)
                    └── compat/cors.h (72 LoC)
```

Total LoC for CORS: **262 LoC** across 3 files for a single
`xrootd_http_add_cors_headers()` function.

### After: single file in webdav/

Merge both layers into `webdav/cors.c`, keeping the `xrootd_cors_conf_t` type and the
`xrootd_http_add_cors_headers()` symbol (other WebDAV handlers may call it):

```c
/* webdav/cors.c — merged CORS implementation (~160 LoC) */
#include "cors.h"       /* kept: type definitions only */
#include "http_headers.h"

static ngx_int_t origin_allowed(...)  { ... }

ngx_int_t xrootd_http_add_cors_headers(ngx_http_request_t *r,
    const xrootd_cors_conf_t *cors)
{
    /* body of old compat/cors.c directly here */
}
```

Delete `compat/cors.c` and `compat/cors.h`.

**LoC delta:**
- Delete `compat/cors.c` (152) + `compat/cors.h` (72): **−224**
- `webdav/cors.c` grows from 38 → ~160 LoC: **+122**
- Net: **−102 LoC**

---

## Change B: Dissolve the compat/io.c + webdav/io.c double-wrapper

### Current structure

```
webdav/put.c  (and others)
    └── webdav/io.c           (38 LoC — 1-line wrapper)
            └── compat/io.c   (55 LoC — EINTR-retrying write loop)
```

`webdav/io.c` line 47:
```c
ngx_int_t webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len) {
    return xrootd_write_full(fd, buf, len);  /* literally this */
}
```

### After: inline `xrootd_write_full` into `webdav/io.c`, delete `compat/io.c`

```c
/* webdav/io.c — absorbs compat/io.c directly */
#include "io.h"
#include <errno.h>
#include <unistd.h>

ngx_int_t webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len)
{
    while (len > 0) {
        ssize_t nwritten = write(fd, buf, len);
        if (nwritten < 0) {
            if (errno == EINTR) continue;
            return NGX_ERROR;
        }
        if (nwritten == 0) { errno = EIO; return NGX_ERROR; }
        buf += (size_t) nwritten;
        len -= (size_t) nwritten;
    }
    return NGX_OK;
}
```

Delete `compat/io.c` and `compat/io.h`.

**LoC delta:**
- Delete `compat/io.c` (55) + `compat/io.h` (28): **−83**
- `webdav/io.c` grows 38 → ~60 LoC: **+22**
- Net: **−61 LoC**

---

## Change C: Move http_protocol_vars.c into webdav/module.c

`compat/http_protocol_vars.c` (59 LoC) has exactly one caller: `webdav/module.c`.
It registers the `$xrootd_protocol` nginx variable.  The function
`xrootd_http_add_protocol_variables()` directly includes `webdav/webdav.h` and
`s3/s3.h` — it already has webdav-specific knowledge, so the "protocol-agnostic"
placement in `compat/` is misleading.

### After: static function inside webdav/module.c

```c
/* webdav/module.c — absorbs http_protocol_vars.c */
static ngx_int_t xrootd_http_protocol_variable(...)  { /* 35 LoC */ }

static ngx_int_t
webdav_add_protocol_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var;
    ngx_str_t            name = ngx_string("xrootd_protocol");
    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) { return NGX_ERROR; }
    var->get_handler = xrootd_http_protocol_variable;
    return NGX_OK;
}
```

Delete `compat/http_protocol_vars.c` and `compat/http_protocol_vars.h`.

**LoC delta:**
- Delete `compat/http_protocol_vars.c` (59) + `http_protocol_vars.h` (10): **−69**
- `webdav/module.c` grows by ~50 LoC: **+50**
- Net: **−19 LoC**

---

## Change D: Inline compat/log.c into its three call sites

`compat/log.c` (18 LoC) provides `xrootd_log_safe_path()`:

```c
void xrootd_log_safe_path(ngx_log_t *log, ngx_uint_t level,
    ngx_err_t err, const char *fmt, const char *path)
{
    char safe_path[512];
    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));
    ngx_log_error(level, log, err, fmt, safe_path);
}
```

Three callers exist.  Each call site is one line; replacing with the two-line inline
is mechanical:

```c
/* Before */
xrootd_log_safe_path(log, NGX_LOG_ERR, errno, "stat failed: %s", path);

/* After — 2 lines, no function call overhead */
char _safe[512]; xrootd_sanitize_log_string(path, _safe, sizeof(_safe));
ngx_log_error(NGX_LOG_ERR, log, errno, "stat failed: %s", _safe);
```

Delete `compat/log.c` and `compat/log.h`.

**LoC delta:**
- Delete `compat/log.c` (18) + `log.h` (17): **−35**
- Three call sites each +1 line: **+3**
- Net: **−32 LoC**

---

## ngx_http_read_body: keep despite being a wrapper

`compat/http_body.c` contains:

```c
ngx_int_t xrootd_http_read_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt handler)
{
    ngx_int_t rc = ngx_http_read_client_request_body(r, handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) { return rc; }
    return NGX_DONE;
}
```

This is a 3-line wrapper around `ngx_http_read_client_request_body()`.  It has
12 callers.  Inlining would replace 1 call with 3 lines at each site, **adding** 24 LoC
net.  The `NGX_HTTP_SPECIAL_RESPONSE` sentinel check is an nginx detail that leaks if
inlined.  **Keep.**

---

## LoC delta table

| Change | Deleted from compat/ | Added to caller | Net |
|---|---|---|---|
| A: cors.c dissolution | −224 | +122 | **−102** |
| B: io.c dissolution | −83 | +22 | **−61** |
| C: http_protocol_vars.c move | −69 | +50 | **−19** |
| D: log.c inlining | −35 | +3 | **−32** |
| **Total** | **−411** | **+197** | **−214** |

Conservative: **−200 LoC** (accounting for doc comments added to merged code).  
Optimistic: **−310 LoC** (if `webdav/cors.c` can be further compacted with Phase 6
xml_builder patterns).

---

## Permanent compat/ inventory

Files confirmed as irreplaceable domain logic.  Do not audit again in future phases.

| File | LoC | Why kept |
|---|---|---|
| `crc32c.c/.h` | 325 | OpenSSL has no CRC32c; SSE4.2 intrinsics are optimal |
| `checksum.c/.h` | 555 | Already uses OpenSSL EVP static singletons correctly |
| `crypto.c/.h` | 106 | Phase 9 handles EVP_MAC singleton; otherwise correct |
| `http_body.c/.h` | 568 | Body chain writing, inflate, read-all — no nginx equivalent |
| `http_headers.c/.h` | 444 | Header find/set/extract_bearer — nginx only exposes known headers in fast path |
| `net_target.c/.h` | 454 | SSRF guard (ipv4/ipv6 range checks) + URL parser — domain logic |
| `namespace_ops.c/.h` | 381 | mkdir/rename/rm with confined-fd — domain logic |
| `http_file_response.c/.h` | 426 | nginx file-backed buffer chain + TLS/sendfile mode — no public nginx API |
| `http_query.c/.h` | 338 | Query parsing with percent-decode flags — `ngx_http_arg()` has no decode |
| `range_vector.c/.h` | 269 | RFC 7233 multi-range parsing — nginx exposes no public range API |
| `http_conditionals.c/.h` | 277 | RFC 7232 — already uses `r->headers_in.*` directly; ETag list parse is domain logic |
| `xml.c/.h` | 527 | XML element builder — libxml2 not a dependency |
| `http_xml.c/.h` | 306 | XML for S3/WebDAV responses — domain logic |
| `fs_walk.c/.h` | 421 | Directory traversal for dirlist/S3 list — POSIX opendir/readdir |
| `uri.c/.h` | 216 | Percent-encode/decode with flags — nginx `ngx_http_arg()` returns raw |
| `integrity_info.c/.h` | 317 | File integrity metadata extraction — domain logic |
| `staged_file.c/.h` | 212 | Atomic rename with `.part` staging — domain logic |
| `copy_range.c/.h` | 177 | `copy_file_range` with fallback read/write loop — POSIX |
| `error_mapping.c/.h` | 196 | errno→kXR→HTTP mapping table — domain logic |
| `range.c/.h` | 116 | Single-range RFC 7233 wrapper — domain logic |
| `hex.c/.h` | 102 | Lowercase hex encode — nginx `ngx_hex_dump()` is uppercase |
| `time.c/.h` | 69 | ISO8601 UTC formatting — nginx has no ISO8601 output |
| `etag.c/.h` | 72 | ETag from mtime+size — 6 callers, shared correctly |
| `fs_usage.c/.h` | 130 | `statvfs` disk usage — 4 callers |
| `path.c/.h` | 102 | Path strip/basename — 4 callers |
| `protocol_caps.c/.h` | 155 | Protocol capability flags — XRootD domain |
| `tmp_path.c/.h` | 75 | Temp path generation — 2 callers |
| `async_job.c/.h` | 119 | Thread pool job wrapper — 1 caller; Phase 7 may address |
| `shm_slots.h` | 49 | SHM slot type definitions — data definition only |
| `alloc_helpers.h` | 126 | Pool alloc helpers — Phase 1 may absorb |
| `alloc_macros.h` | 35 | Pool macro wrappers — Phase 1 covers |
| `err_strings.h` | 27 | Error string constants — Phase 1 covers |
| `result_mapper.h` | 20 | Result mapping types — Phase 2 covers |

---

## Files removed from config.h

Remove from `NGX_ADDON_SRCS` in `src/core/config/config.h`:

```
$ngx_addon_dir/src/core/compat/cors.c
$ngx_addon_dir/src/core/compat/io.c
$ngx_addon_dir/src/core/compat/http_protocol_vars.c
$ngx_addon_dir/src/core/compat/log.c
```

`./configure` required once after editing `config.h`.

---

## Migration order

1. **Change D** (`log.c`) — smallest, self-contained.  `make` must succeed.
2. **Change C** (`http_protocol_vars.c`) — move function body into `webdav/module.c`.
3. **Change B** (`io.c`) — inline into `webdav/io.c`.  Remove `compat/io.h` include from that file.
4. **Change A** (`cors.c`) — merge both cors files into `webdav/cors.c`.  Most mechanical risk is
   ensuring `xrootd_cors_conf_t` type is still accessible wherever it's referenced in config.

After all four changes: `./configure`, `make -j$(nproc)`, run full test suite.

---

## Verification

```bash
cd /tmp/nginx-1.28.3
./configure --with-stream --with-http_ssl_module --with-http_dav_module \
            --with-threads --add-module=$REPO
make -j$(nproc) 2>&1 | grep "^error:" | wc -l
# Expected: 0

tests/manage_test_servers.sh restart

# CORS preflight (verifies cors.c merge)
PYTHONPATH=tests pytest tests/test_a_webdav_clients.py -v -k "cors or options"

# S3 range + conditional requests (verifies no breakage)
PYTHONPATH=tests pytest tests/test_conformance.py -k "range or etag or conditional" -v

# Full suite
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

---

## Risk assessment

**Low.**  All four changes are mechanical moves — no logic changes.

The highest-risk change is A (`cors.c` dissolution) because the `xrootd_cors_conf_t`
type defined in `compat/cors.h` may be referenced by other webdav headers.  Audit with:

```bash
grep -rn "xrootd_cors_conf_t\|cors\.h" src/ --include="*.c" --include="*.h" \
     | grep -v "src/core/compat/"
```

Before deleting `cors.h`, move the type definition into `webdav/cors.h` and update
any non-webdav callers.

## Rollback

```bash
git revert <phase-11-commit>
./configure ...
make -j$(nproc)
```
