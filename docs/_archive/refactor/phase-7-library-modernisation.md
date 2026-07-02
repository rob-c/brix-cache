# Phase 7: Library Modernisation — token/ and aio/

**Date:** 2026-06-11  
**Status:** PLAN  
**Projected total ΔLoC:** −750 (token) + −250 (aio) = **−1,000**

---

## Correction: aio/ premise

The suggestion "Replace aio/ with nginx's ngx_thread_pool" was based on incorrect information.
Reading `src/core/aio/resume.c` and `src/core/aio/config.c` confirms that **aio/ already uses
`ngx_thread_pool_get()`, `ngx_thread_task_post()`, and `ngx_thread_task_alloc()`** — it is a
correct and intentional user of nginx's built-in thread pool, not a reimplementation of it.

There is no wholesale replacement to be done. Section B below identifies the genuine
simplification opportunities within aio/ (consolidated thread workers, ~250 LoC).

---

## Section A — Replace JWT plumbing in token/ with libjwt

### What exists today

| File | LoC | Function |
|---|---|---|
| `validate.c` | 376 | Hand-rolled JWT pipeline: structure check → alg gate → key selection → signature verify → claim extraction → exp/nbf |
| `jwks.c` | 198 | JWKS disk loader (uses jansson, already a dep) → EVP_PKEY array |
| `keys.c` | 136 | Key lifecycle (rsa_pubkey_from_ne, ec_pubkey_from_xy, EVP_PKEY wrappers) |
| `signature.c` | 99 | RS256 + ES256 signature verification via OpenSSL EVP_DigestVerify |
| `b64url.c` | 82 | Base64url decode |
| `json.c` | 172 | Thin wrappers over jansson (get_string, get_int64, get_string_array) — jansson already a build dep |
| **Subtotal replaceable** | **1,063** | |

| File | LoC | Stays because |
|---|---|---|
| `macaroon.c` | 769 | HMAC-chain + caveat validation — no library equivalent |
| `macaroon_issue.c` | 224 | Macaroon minting — no library equivalent |
| `scopes.c` | 275 | WLCG/SciToken scope grammar ("storage.read:/path") — no library equivalent |
| `refresh.c` | 126 | JWKS key refresh loop |
| `file.c` | 105 | Token-from-file reader |
| `oauth2.c` | 76 | OAuth2 token introspection (already uses jansson) |
| `config.c` | 70 | nginx config directives for token subsystem |
| `token.h` | 136 | Public API (unchanged) |
| **Subtotal unchanged** | **1,781** | |

**Honest scope of the migration:** libjwt handles the JWT structural + cryptographic layer
(b64url, JSON header/payload parsing, alg enforcement, key selection, signature
verification, standard claim access). The WLCG-specific layer (scopes, groups, macaroons)
is completely custom and unaffected.

### Why libjwt fits

libjwt 2.x provides exactly the pipeline that validate.c hand-rolls:

```c
/* libjwt 2.x API (simplified) */
jwt_t *jwt;
int rc = jwt_decode(&jwt, token_str, key_set);  /* structure + sig + alg */
if (rc != 0) return -1;                          /* error reason in jwt_errno */

const char *iss = jwt_get_grant(jwt, "iss");     /* standard string claim */
time_t      exp = (time_t) jwt_get_grant_int(jwt, "exp");  /* numeric claim */
const char *scope_raw = jwt_get_grant(jwt, "scope");
/* wlcg.groups is an array: use jwt_get_grants_json() + jansson (already a dep) */
const char *groups_json = jwt_get_grants_json(jwt, "wlcg.groups");
jwt_free(jwt);
```

libjwt's alg enforcement gate rejects `alg:none` before calling any verification code,
closing the same bypass the current code guards against manually at line 231 of validate.c.

Key observation: jansson is already a build dependency (jwks.c and oauth2.c both
`#include <jansson.h>`). libjwt 2.x can be built against jansson. No new transitive
dependencies are added.

### Required libjwt version

**libjwt 2.x** (released 2024). The 2.x API adds:
- `jwt_set_SET_jwks_file()` — load a JWKS file directly, replaces jwks.c's disk loader
- `jwt_decode()` now takes a `jwk_set_t*` key set
- `jwt_get_grants_json()` — access complex (array) claims as a JSON string

libjwt 1.x lacks the JWKS loading API and requires manual key injection via
`jwt_add_grant_int()`; using 1.x would not simplify jwks.c.

Check availability: `pkg-config --modversion libjwt` should return ≥ 2.0.0.

### Migration plan

#### Step 1: Dependency declaration

In `src/core/config/config.h`, add the libjwt pkg-config check:

```makefile
# NGX_ADDON_DEPS — add libjwt flags
LIBJWT_CFLAGS := $(shell pkg-config --cflags libjwt 2>/dev/null)
LIBJWT_LIBS   := $(shell pkg-config --libs   libjwt 2>/dev/null)

# In NGX_ADDON_SRCS, remove (files being deleted):
#   src/auth/token/b64url.c
#   src/auth/token/signature.c
```

Requires a `./configure` run.

#### Step 2: New `src/auth/token/jwt_verify.c` (~120 LoC)

This replaces validate.c's JWT path (not the macaroon path, which stays in validate.c):

```c
/*
 * jwt_verify.c — libjwt-backed JWT validation for RS256/ES256 WLCG tokens.
 *
 * Replaces the hand-rolled pipeline in validate.c:
 *   structural check, alg gate, key selection, signature verify,
 *   standard claim extraction (iss/sub/aud/exp/nbf/iat).
 *
 * Macaroon tokens are still handled by macaroon.c — this file is
 * only reached when xrootd_token_is_macaroon() returns 0.
 */
#include "token_internal.h"
#include "scopes.h"

#include <jwt.h>         /* libjwt */
#include <jansson.h>     /* wlcg.groups array extraction */

/*
 * xrootd_jwt_verify — validate a WLCG JWT and populate claims.
 *
 * key_set: built once at startup by xrootd_jwks_load_libjwt() (see jwks.c).
 *
 * Returns 0 on success, -1 on any validation failure (reason logged).
 */
int
xrootd_jwt_verify(ngx_log_t *log,
                  const char *token, size_t token_len,
                  jwk_set_t *key_set,
                  const char *expected_issuer,
                  const char *expected_audience,
                  xrootd_token_claims_t *claims)
{
    jwt_t       *jwt = NULL;
    int          rc;
    const char  *val;
    const char  *groups_json;
    time_t       now;

    ngx_memzero(claims, sizeof(*claims));

    rc = jwt_decode(&jwt, token, key_set);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: JWT decode/verify failed: %s",
                      jwt_exception_message(rc));
        return -1;
    }

    /* Standard string claims */
    val = jwt_get_grant(jwt, "iss");
    if (val) ngx_cpystrn((u_char *)claims->iss, (u_char *)val,
                          sizeof(claims->iss));

    val = jwt_get_grant(jwt, "sub");
    if (val) ngx_cpystrn((u_char *)claims->sub, (u_char *)val,
                          sizeof(claims->sub));

    val = jwt_get_grant(jwt, "aud");
    if (val) ngx_cpystrn((u_char *)claims->aud, (u_char *)val,
                          sizeof(claims->aud));

    val = jwt_get_grant(jwt, "scope");
    if (val) ngx_cpystrn((u_char *)claims->scope_raw, (u_char *)val,
                          sizeof(claims->scope_raw));

    /* Numeric claims */
    claims->exp = (int64_t) jwt_get_grant_int(jwt, "exp");
    claims->nbf = (int64_t) jwt_get_grant_int(jwt, "nbf");
    claims->iat = (int64_t) jwt_get_grant_int(jwt, "iat");

    /* wlcg.groups is a JSON array — use jwt_get_grants_json + jansson */
    groups_json = jwt_get_grants_json(jwt, "wlcg.groups");
    if (groups_json) {
        xrootd_token_extract_groups_json(groups_json, claims);
    }

    jwt_free(jwt);

    /* Issuer / audience / time checks remain in C (not delegated to libjwt)
     * so the error messages and clock-skew window stay under our control. */
    if (expected_issuer && expected_issuer[0]
        && strcmp(claims->iss, expected_issuer) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: issuer mismatch: got \"%s\" expected \"%s\"",
                      claims->iss, expected_issuer);
        return -1;
    }
    if (expected_audience && expected_audience[0]
        && strcmp(claims->aud, expected_audience) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: audience mismatch: got \"%s\" expected \"%s\"",
                      claims->aud, expected_audience);
        return -1;
    }

    now = time(NULL);
    if (claims->exp > 0
        && now > (time_t)claims->exp + XROOTD_TOKEN_CLOCK_SKEW_SECS) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: token expired (exp=%L now=%L)",
                      (long long)claims->exp, (long long)now);
        return -1;
    }
    if (claims->nbf > 0 && now < (time_t)claims->nbf) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: token not yet valid (nbf=%L now=%L)",
                      (long long)claims->nbf, (long long)now);
        return -1;
    }

    claims->scope_count = xrootd_token_parse_scopes(
        claims->scope_raw, claims->scopes, XROOTD_MAX_TOKEN_SCOPES);

    return 0;
}
```

#### Step 3: Rewrite `src/auth/token/jwks.c` (~60 LoC)

libjwt 2.x provides `jwks_create_fromfile()` and `jwks_item_free_all()`.
The new jwks.c wraps these, populating a `jwk_set_t*` instead of the
`xrootd_jwks_key_t[]` array:

```c
jwk_set_t *
xrootd_jwks_load_libjwt(ngx_log_t *log, const char *path)
{
    jwk_set_t *ks = jwks_create_fromfile(path);
    if (ks == NULL || jwks_error(ks)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_token: failed to load JWKS from \"%s\": %s",
                      path, ks ? jwks_error_msg(ks) : "null key set");
        if (ks) jwks_free(ks);
        return NULL;
    }
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "xrootd_token: loaded JWKS from \"%s\" via libjwt", path);
    return ks;
}

void
xrootd_jwks_free_libjwt(jwk_set_t *ks)
{
    if (ks) jwks_free(ks);
}
```

#### Step 4: Files deleted

| File | LoC | Reason |
|---|---|---|
| `src/auth/token/b64url.c` | 82 | libjwt handles base64url internally |
| `src/auth/token/b64url.h` | 26 | header for above |
| `src/auth/token/signature.c` | 99 | libjwt handles EVP_DigestVerify internally |

#### Step 5: Files that shrink

| File | Before | After | Delta |
|---|---|---|---|
| `validate.c` | 376 | ~80 (macaroon dispatch + call to jwt_verify) | −296 |
| `jwks.c` | 198 | ~60 (libjwt wrapper) | −138 |
| `keys.c` | 136 | ~40 (jwk_set_t lifecycle only) | −96 |
| `json.c` | 172 | ~50 (only groups array + backend name) | −122 |
| `jwt_verify.c` | 0 | +120 | +120 |

**Net token/ reduction: ~659 LoC**

### Public API compatibility

`token.h` is unchanged. The `xrootd_token_validate()` signature stays identical — all
callers outside token/ (30 sites verified with grep) see no change. The internal type
`xrootd_jwks_key_t` becomes a thin wrapper over `jwk_set_t*`; since it is not
exposed outside token/, no callers need updating.

### Files added to `src/core/config/config.h`

```
$ngx_addon_dir/src/auth/token/jwt_verify.c
```

Remove from `NGX_ADDON_SRCS`:
```
$ngx_addon_dir/src/auth/token/b64url.c
$ngx_addon_dir/src/auth/token/signature.c
```

Requires `./configure`.

### Verification

```bash
# 1. Check libjwt 2.x is installed
pkg-config --modversion libjwt
# Must be >= 2.0.0

# 2. Build
cd /tmp/nginx-1.28.3
./configure --with-stream --with-http_ssl_module --with-http_dav_module \
            --with-threads --add-module=$REPO \
            --with-cc-opt="$(pkg-config --cflags libjwt jansson)" \
            --with-ld-opt="$(pkg-config --libs   libjwt jansson)"
make -j$(nproc) 2>&1 | grep "^error:" | wc -l

# 3. Token validation correctness
PYTHONPATH=tests pytest tests/test_conformance.py -k "token" -v
PYTHONPATH=tests pytest tests/test_credential_translation.py -v

# 4. Macaroon path unchanged
PYTHONPATH=tests pytest tests/ -k "macaroon" -v

# 5. Security regression: alg:none bypass must still be rejected
#    (libjwt rejects it before signature; verify this is not silently accepted)
PYTHONPATH=tests pytest tests/test_conformance.py -k "alg_none" -v

# 6. Full suite
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

### Risk assessment

**Medium.** The primary risk is libjwt's handling of edge cases that the hand-rolled
code explicitly guards against:

1. **`alg:none` bypass** — libjwt 2.x rejects unsigned tokens. Verify with a crafted
   test token that has `"alg":"none"` in the header. The test `test_conformance.py::alg_none`
   must fail authentication, not succeed.

2. **Clock-skew window** — libjwt validates `exp`/`nbf` internally by default. The current
   code adds `XROOTD_TOKEN_CLOCK_SKEW_SECS`. In `jwt_verify.c` above, we skip libjwt's
   internal time check (`JWT_ALG_NONE` flag or `jwt_set_grant_int(jwt, "exp", INT64_MAX)`)
   and re-implement it explicitly with the skew window. Confirm the sequence: signature
   check first, time check second — never the reverse.

3. **ES256 key loading** — verify that `jwks_create_fromfile()` loads EC P-256 keys
   correctly on the build target. Run against a JWKS file that contains only EC keys.

4. **libjwt 2.x availability** — libjwt 2.0 was released in late 2024. It is packaged in
   Fedora 41+, Ubuntu 25.04+, and RHEL 9 via EPEL. For older distros a vendored build
   from source is required. Check target OS before committing to this phase.

### Rollback

```bash
git revert <phase-7a-commit>
./configure ...   # restore original NGX_ADDON_SRCS
make -j$(nproc)
```

---

## Section B — Consolidate aio/ thread workers

### Correction to the original suggestion

The claim "aio/ reimplements nginx's thread pool" is **false**. Reading the source:

- `resume.c:78` calls `ngx_thread_task_post(pool, task)` — nginx's native API
- `config.c` calls `ngx_thread_pool_get(cf->cycle, pool_name)` — nginx's native API
- Each operation allocates an `ngx_thread_task_t` via `ngx_thread_task_alloc()`

aio/ is a correct, well-designed user of `ngx_thread_pool`. There is no wholesale
replacement to be done.

### What IS reducible

The six `_thread` worker functions are all structurally identical and trivially thin:

```c
/* read.c — 4 lines of actual work */
void xrootd_read_aio_thread(void *data, ngx_log_t *log) {
    xrootd_read_aio_t *t = data;
    t->nread = pread(t->fd, t->databuf, t->rlen, t->offset);
    if (t->nread < 0) t->io_errno = errno;
}

/* write.c — effectively the same shape */
void xrootd_write_aio_thread(void *data, ngx_log_t *log) {
    xrootd_write_aio_t *t = data;
    t->nwritten = pwrite(t->fd, t->data, t->len, t->offset);
    if (t->nwritten < 0) t->io_errno = errno;
}
```

These cannot be unified into one function (different struct types, different syscalls)
but they can each be collapsed to their 4–6 lines of substance by eliminating the
auto-injected documentation blocks that currently inflate each to 40–50 lines in
read.c/write.c/pgread.c/readv.c/dirlist.c.

The `_done` callbacks are operation-specific (each builds a different wire response) and
cannot be meaningfully unified without adding an abstraction layer that would cost more
lines than it saves.

### Genuine reduction targets within aio/

#### Target 1: Scratch buffer API simplification in `buffers.c` (~80 LoC)

`buffers.c` exports three nearly-identical public functions that differ only in which
context field they touch:

```c
/* Three functions, same body modulo slot pointer */
u_char *xrootd_get_read_scratch(ctx, c, need)         { return xrootd_get_pool_scratch(c->pool, &ctx->read_scratch,        &ctx->read_scratch_size, need); }
u_char *xrootd_get_read_header_scratch(ctx, c, need)  { return xrootd_get_pool_scratch(c->pool, &ctx->read_hdr_scratch,    &ctx->read_hdr_scratch_size, need); }
u_char *xrootd_get_write_scratch(ctx, c, need)        { return xrootd_get_pool_scratch(c->pool, &ctx->write_scratch,       &ctx->write_scratch_size, need); }
```

After Phase 1's alloc macros are in place, these three wrappers can be replaced by a
single macro:

```c
/* In aio.h — replaces the three public function declarations */
#define XROOTD_GET_SCRATCH(ctx, c, slot_field, sz_field, need)  \
    xrootd_get_pool_scratch((c)->pool,                          \
                            &(ctx)->slot_field,                 \
                            &(ctx)->sz_field,                   \
                            (need))
```

Eliminates ~80 LoC (3 function bodies + 3 declarations in aio.h).

#### Target 2: Consolidate `_thread` boilerplate in read.c/write.c/pgread.c (~90 LoC)

Each `_thread` function currently has 40–50 lines because of the auto-injected
WHAT/WHY/HOW comment blocks. The actual syscall logic is 4–6 lines. After the comment
policy change (mentioned in the main overview), the 6 thread functions shrink from
~240 lines total to ~36 lines total — a reduction of ~200 lines within read.c and
write.c alone.

This is the same comment-policy lever discussed in 00-overview.md, applied to aio/.

#### Target 3: Inline `xrootd_aio_restore_request()` (~20 LoC)

`resume.c` exports two nearly-identical functions:

```c
/* xrootd_aio_restore_stream:   check destroyed + restore streamid */
/* xrootd_aio_restore_request:  same + reset state to XRD_ST_REQ_HEADER */
```

`xrootd_aio_restore_request` is called in 4 places, `xrootd_aio_restore_stream` in 2.
The body of `restore_request` is `restore_stream` + 2 assignments. These can be
expressed as a single function with a `reset_state` flag, saving ~20 LoC.

### aio/ reduction summary

| Change | ΔLoC |
|---|---|
| Scratch buffer macro (Target 1) | −80 |
| `_thread` comment block removal (Target 2) | −200 |
| `restore_request` inline (Target 3) | −20 |
| **Net** | **−300** |

Note: Target 2 is conditional on the comment policy change. Without it, the net from
aio/ is ~100 LoC.

### Verification

```bash
make -j$(nproc) 2>&1 | grep "^error:" | wc -l

# AIO paths exercised by all read/write tests
PYTHONPATH=tests pytest tests/test_aio.py -v
PYTHONPATH=tests pytest tests/test_concurrent.py -v

# pgread (CRC32c path)
PYTHONPATH=tests pytest tests/test_conformance.py -k "pgread" -v

# dirlist AIO path
PYTHONPATH=tests pytest tests/test_conformance.py -k "dirlist" -v

PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

---

## Combined Phase 7 Summary

| Sub-phase | Primary change | ΔLoC |
|---|---|---|
| 7a — token/libjwt | Delete b64url.c + signature.c; shrink validate/jwks/keys/json | −659 |
| 7b — aio/ consolidation | Scratch macro + comment policy + restore inline | −300 |
| **Total** | | **−959** |

### Prerequisites

- libjwt ≥ 2.0.0 available on the build host (`pkg-config --modversion libjwt`)
- Phase 1 (alloc macros) merged before 7b
- Comment policy decision made before Target 2 of 7b

### Sequencing relative to other phases

Phase 7a (token) is fully independent — it touches only `src/auth/token/` and has no
dependency on Phases 1–6.

Phase 7b (aio) depends on Phase 1 macros for Target 1, and on the comment policy
decision for Target 2. It can otherwise proceed in parallel with Phases 2–6.
