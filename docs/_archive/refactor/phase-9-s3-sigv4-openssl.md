# Phase 9: S3 SigV4 — OpenSSL Efficiency + Key Derivation Consolidation

**Projected ΔLoC:** −100 (conservative), −140 (optimistic)
**Risk:** Low–Medium (security-sensitive code; easy to verify with test vectors)
**Depends on:** nothing
**Blocks:** nothing
**Parallel-safe with:** all other phases

---

## Corrected Premise

The original suggestion ("S3 SigV4 → OpenSSL: −441 LoC") was based on the assumption
that the HMAC-SHA256 implementation was hand-rolled.  Reading the source showed it is
not.  `compat/crypto.c` already wraps `EVP_MAC` and `EVP_DigestInit_ex`:

```c
/* compat/crypto.c — already OpenSSL */
int
xrootd_hmac_sha256(const u_char *key, size_t keylen,
                   const u_char *data, size_t datalen,
                   u_char out[32])
{
    EVP_MAC     *mac;
    EVP_MAC_CTX *ctx;
    OSSL_PARAM   params[2];
    ...
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);   /* ← expensive per call */
    ...
}
```

`auth_sigv4_parse.c` (269 LoC) is string parsing — not crypto — and is already
as compact as it can be.  `auth_sigv4_canonical.c` (158 LoC) is query-string
sorting — cannot be replaced by a library.

**What this phase actually addresses:**

1. `EVP_MAC_fetch` called per HMAC invocation — a registry lookup that allocates
   memory.  SigV4 verification calls `xrootd_hmac_sha256` five times;
   `post_object.c` calls it another five times.  That is 10 fetch+free cycles for
   a single presigned POST.
2. The four-round signing-key derivation is **duplicated** between
   `auth_sigv4_verify.c:470–493` and `post_object.c:799–804` — identical code,
   two places.
3. `s3_days_from_civil` (15 LoC) + manual time arithmetic (10 LoC) in
   `auth_sigv4_verify.c` reimplements `timegm(3)`, a Linux glibc function
   guaranteed available on the project's Linux 5.6+ minimum platform.
4. `auth_sigv4_headers.c` (73 LoC) is a thin file whose sole function
   (`build_canonical_headers`) is only ever called from `auth_sigv4_verify.c`,
   and it carries a messy `extern get_header()` dependency on `auth_sigv4_parse.c`.

---

## Changes

### A. Fix `xrootd_hmac_sha256` — replace per-call `EVP_MAC_fetch` with a singleton

**Problem:** every call to `xrootd_hmac_sha256` does:

```c
mac = EVP_MAC_fetch(NULL, "HMAC", NULL);   /* provider registry search + alloc */
ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
/* ... use ... */
EVP_MAC_CTX_free(ctx);
EVP_MAC_free(mac);                         /* free again per call */
```

OpenSSL 3.x documents `EVP_MAC_fetch` as non-trivial: it locks the algorithm
table, searches by name, and may allocate.  Calling it 10 times per SigV4 POST
request is unnecessary.

**Fix:** fetch the `EVP_MAC *` once at nginx worker init, store it as a
`static EVP_MAC *s_hmac_mac` in `crypto.c`, and expose init/cleanup functions:

```c
/* compat/crypto.c — after */
static EVP_MAC *s_hmac_mac;

int
xrootd_crypto_init(void)
{
    s_hmac_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    return s_hmac_mac != NULL;
}

void
xrootd_crypto_cleanup(void)
{
    EVP_MAC_free(s_hmac_mac);
    s_hmac_mac = NULL;
}

int
xrootd_hmac_sha256(const u_char *key, size_t keylen,
                   const u_char *data, size_t datalen,
                   u_char out[32])
{
    EVP_MAC_CTX *ctx;
    OSSL_PARAM   params[2];
    size_t       outlen = 32;
    int          ok = 0;

    if (s_hmac_mac == NULL) { return 0; }

    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    ctx = EVP_MAC_CTX_new(s_hmac_mac);
    if (ctx
        && EVP_MAC_init(ctx, key, keylen, params) == 1
        && EVP_MAC_update(ctx, data, datalen) == 1
        && EVP_MAC_final(ctx, out, &outlen, 32) == 1)
    {
        ok = 1;
    }

    EVP_MAC_CTX_free(ctx);
    return ok;
}
```

`xrootd_sha256` gets the same treatment with a `static EVP_MD *s_sha256_md`.

**Call sites for init/cleanup:** `xrootd_crypto_init()` called in
`ngx_stream_xrootd_init_process()` (already exists); `xrootd_crypto_cleanup()`
in `ngx_stream_xrootd_exit_process()`.

**LoC delta in crypto.c:** 79 → 90 (net +11 for the init/cleanup pair, −6 inside
`xrootd_hmac_sha256`, −6 inside `xrootd_sha256`).  Apparent wash in lines but
10× fewer `EVP_MAC_fetch` calls per SigV4 request.

**`compat/crypto.h` additions:**

```c
int  xrootd_crypto_init(void);
void xrootd_crypto_cleanup(void);
```

---

### B. Extract `s3_sigv4_derive_signing_key()` — eliminate the duplication

The four-round key derivation appears verbatim in two places.  In
`auth_sigv4_verify.c`:

```c
/* lines 471–493 */
u_char prefix_key[128];
size_t pklen;

if (cf->secret_key.len + 4 > sizeof(prefix_key)) { ... error ... }
ngx_memcpy(prefix_key, "AWS4", 4);
ngx_memcpy(prefix_key + 4, cf->secret_key.data, cf->secret_key.len);
pklen = 4 + cf->secret_key.len;

if (!xrootd_hmac_sha256(prefix_key, pklen,
                 (u_char *) comp.date, strlen(comp.date), k1)
    || !xrootd_hmac_sha256(k1, 32,
                    (u_char *) comp.region, strlen(comp.region), k2)
    || !xrootd_hmac_sha256(k2, 32, (u_char *) "s3", 2, k3)
    || !xrootd_hmac_sha256(k3, 32,
                    (u_char *) "aws4_request", 12, k4))
{ ... error ... }
```

And in `post_object.c:799–804` — identical logic, different variable names.

**New helper** in `auth_sigv4_verify.c` (used by both files via the internal
header `s3_auth_internal.h`):

```c
/*
 * s3_sigv4_derive_signing_key — compute the four-round SigV4 signing key.
 *
 * signing_key = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), "s3"),
 *                    "aws4_request")
 *
 * Returns 1 on success, 0 on HMAC failure.
 */
int
s3_sigv4_derive_signing_key(const ngx_str_t *secret,
                             const char *date, const char *region,
                             u_char out[32])
{
    u_char prefix[128];
    u_char k1[32], k2[32], k3[32];

    if (secret->len + 4 > sizeof(prefix)) { return 0; }
    ngx_memcpy(prefix, "AWS4", 4);
    ngx_memcpy(prefix + 4, secret->data, secret->len);

    return xrootd_hmac_sha256(prefix, 4 + secret->len,
                               (u_char *) date, strlen(date), k1)
        && xrootd_hmac_sha256(k1, 32,
                               (u_char *) region, strlen(region), k2)
        && xrootd_hmac_sha256(k2, 32, (u_char *) "s3", 2, k3)
        && xrootd_hmac_sha256(k3, 32, (u_char *) "aws4_request", 12, out);
}
```

Declaration added to `s3_auth_internal.h`.

**Call site in `auth_sigv4_verify.c`** (the 25-line block collapses to):

```c
if (!s3_sigv4_derive_signing_key(&cf->secret_key, comp.date, comp.region, k4)) {
    s3_record_auth_result(XROOTD_S3_AUTH_INTERNAL_ERROR);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
```

**Call site in `post_object.c`** (lines 799–808 collapse similarly):

```c
if (!s3_sigv4_derive_signing_key(&cf->secret_key, date, region, k4)) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
```

**LoC delta:**
- New helper function: +20 LoC
- Removed from `auth_sigv4_verify.c`: −25 LoC
- Removed from `post_object.c`: −22 LoC
- Net: **−27 LoC**

---

### C. Add a per-worker signing-key cache

The signing key changes only when the date or region changes.  For a single-region
deployment, the key is stable for 24 hours (one calendar day in YYYYMMDD format).
Within one nginx worker (single-threaded), a two-field cache is safe:

```c
/* src/protocols/s3/auth_sigv4_verify.c — worker-level cache */
static struct {
    char   date[9];    /* "YYYYMMDD\0" */
    char   region[64];
    u_char key[32];
} s_signing_key_cache;

int
s3_sigv4_derive_signing_key_cached(const ngx_str_t *secret,
                                    const char *date, const char *region,
                                    u_char out[32])
{
    if (strcmp(s_signing_key_cache.date,   date)   == 0
        && strcmp(s_signing_key_cache.region, region) == 0)
    {
        ngx_memcpy(out, s_signing_key_cache.key, 32);
        return 1;
    }

    if (!s3_sigv4_derive_signing_key(secret, date, region, out)) {
        return 0;
    }

    ngx_cpystrn((u_char *) s_signing_key_cache.date,
                (u_char *) date, sizeof(s_signing_key_cache.date));
    ngx_cpystrn((u_char *) s_signing_key_cache.region,
                (u_char *) region, sizeof(s_signing_key_cache.region));
    ngx_memcpy(s_signing_key_cache.key, out, 32);
    return 1;
}
```

Replace the `s3_sigv4_derive_signing_key()` call in `auth_sigv4_verify.c` and
`post_object.c` with `s3_sigv4_derive_signing_key_cached()`.

**Security note:** the cache stores a HMAC key in worker memory.  This is no
different from how `cf->secret_key` is already stored in the location config.
The threat model for worker process memory compromise is already assumed by
storing the secret at all.

**LoC delta:** +22 LoC (the cache struct + function).  No LoC saving, but reduces
the hot path from 5 HMAC calls to 1 HMAC call on a cache hit (every request that
arrives on the same calendar day in the same region).

---

### D. Replace `s3_days_from_civil` + manual arithmetic with `timegm(3)`

`auth_sigv4_verify.c` implements its own Gregorian calendar algorithm to convert
`YYYYMMDDTHHMMSSZ` into a `time_t`, because `mktime()` is affected by the TZ
environment variable.

```c
/* Before — lines 145–187 (~50 LoC) */
static int64_t
s3_days_from_civil(int y, unsigned m, unsigned d)
{
    int64_t  era;
    unsigned yoe, doy, doe;
    int      mp;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned) (y - era * 400);
    mp  = (int) m + (m > 2 ? -3 : 9);
    doy = (153 * (unsigned) mp + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t) doe - 719468;
}

static ngx_int_t
s3_parse_amz_datetime(const char *s, time_t *out)
{
    /* ... parse digits ... */
    int64_t days = s3_days_from_civil(year, (unsigned) mon, (unsigned) day);
    *out = (time_t) (days * 86400 + hour * 3600 + min * 60 + sec);
    return NGX_OK;
}
```

`timegm(3)` is a GNU/BSD extension that converts a broken-down UTC time to
`time_t` without consulting the TZ variable.  It is available in glibc (Linux)
and guaranteed on the project's Linux 5.6+ minimum platform:

```c
/* After — same function, ~20 LoC */
#define _GNU_SOURCE
#include <time.h>

static ngx_int_t
s3_parse_amz_datetime(const char *s, time_t *out)
{
    int year, mon, day, hour, min, sec;

    if (strlen(s) != 16 || s[8] != 'T' || s[15] != 'Z') {
        return NGX_ERROR;
    }

    year = s3_parse_4digits(s);
    mon  = s3_parse_2digits(s + 4);
    day  = s3_parse_2digits(s + 6);
    hour = s3_parse_2digits(s + 9);
    min  = s3_parse_2digits(s + 11);
    sec  = s3_parse_2digits(s + 13);

    if (year < 1970 || mon < 1 || mon > 12 || day < 1 || day > 31
        || hour < 0 || hour > 23 || min < 0 || min > 59
        || sec < 0 || sec > 60)
    {
        return NGX_ERROR;
    }

    struct tm tm = {
        .tm_year = year - 1900, .tm_mon = mon - 1, .tm_mday = day,
        .tm_hour = hour,        .tm_min = min,      .tm_sec  = sec,
        .tm_isdst = 0,
    };
    *out = timegm(&tm);
    return (*out == (time_t) -1) ? NGX_ERROR : NGX_OK;
}
```

**LoC delta:** −28 LoC (`s3_days_from_civil` 15 LoC deleted, `s3_parse_amz_datetime`
reduced from 35 to 22 LoC).

---

### E. Merge `auth_sigv4_headers.c` into `auth_sigv4_verify.c`

`auth_sigv4_headers.c` (73 LoC) contains exactly one non-trivial function
(`build_canonical_headers`) that is called only from `auth_sigv4_verify.c`.
It also carries an `extern get_header()` declaration that points back into
`auth_sigv4_parse.c`, creating a circular extern dependency between the three
files.

Move `build_canonical_headers` into `auth_sigv4_verify.c`.  Remove the extern
declaration.  Delete `auth_sigv4_headers.c`.

**LoC delta:** −13 LoC (extern declarations removed, one file header dropped).
Remove `auth_sigv4_headers.c` from `config.h`; run `./configure`.

---

## LoC Delta Table

| File | Before | After | Delta | Notes |
|---|---|---|---|---|
| `compat/crypto.c` | 79 | 90 | +11 | init/cleanup added; fetch loop removed |
| `compat/crypto.h` | 27 | 30 | +3 | two new declarations |
| `src/protocols/s3/auth_sigv4_verify.c` | 534 | 472 | −62 | civil days deleted; key derivation → helper; headers merged in |
| `src/protocols/s3/auth_sigv4_headers.c` | 73 | 0 | −73 | merged into verify.c |
| `src/protocols/s3/post_object.c` | 1,112 | 1,090 | −22 | key derivation → helper |
| `src/protocols/s3/s3_auth_internal.h` | ~50 | ~55 | +5 | new declaration |
| **Signing key helper + cache (new)** | 0 | +65 | +65 | in verify.c |
| **Net** | | | **−73** | |

With optimistic deletions of dead helper boilerplate: **−100 to −140 LoC**.

---

## Performance Improvement (primary benefit)

| Metric | Before | After |
|---|---|---|
| `EVP_MAC_fetch` calls per SigV4 header request | 5 | 0 (cache hit) / 1 (miss) |
| `EVP_MAC_fetch` calls per presigned POST | 10 | 0 / 1 |
| HMAC round calls per request (cache hit) | 5 | 1 |
| HMAC round calls per request (cache miss, once/day) | 5 | 5 |

On a cache hit (>99% of requests in steady state), SigV4 verification reduces
from 5 `EVP_MAC_fetch` + 5 ctx create/destroy cycles to 1 HMAC call for the
final signature check.

---

## Files Modified

```
compat/crypto.c         — singleton HMAC/SHA256 fetch
compat/crypto.h         — xrootd_crypto_init / xrootd_crypto_cleanup
src/protocols/s3/auth_sigv4_verify.c  — absorb headers.c; key helper; cache; timegm
src/protocols/s3/auth_sigv4_headers.c — DELETED
src/protocols/s3/post_object.c        — use s3_sigv4_derive_signing_key_cached
src/protocols/s3/s3_auth_internal.h   — declare s3_sigv4_derive_signing_key[_cached]
src/net/upstream/bootstrap.c    — call xrootd_crypto_init in init_process hook
                               call xrootd_crypto_cleanup in exit_process hook
```

`config.h` change: remove `auth_sigv4_headers.c` entry, add nothing.
Requires `./configure` + full build.

---

## Execution Order

1. **`compat/crypto.c`** — add singleton + init/cleanup, wire up init/cleanup
   hooks.  Build + run full suite.  No behaviour change.

2. **Extract `s3_sigv4_derive_signing_key()`** — add to `auth_sigv4_verify.c`,
   add to `s3_auth_internal.h`, replace 25-line block in `auth_sigv4_verify.c`.
   Build + run `test_conformance.py -k s3`.

3. **Update `post_object.c`** — replace 22-line block with helper call.
   Build + run `test_conformance.py -k post_object`.

4. **Add signing key cache** — replace `s3_sigv4_derive_signing_key` calls with
   cached variant.  Verify: run the clock-skew tests (cache must not survive a
   date rollover; unit test the cache invalidation).

5. **`timegm()` replacement** — delete `s3_days_from_civil`, rewrite
   `s3_parse_amz_datetime`.  Add `_GNU_SOURCE` if not already defined at top of
   `auth_sigv4_verify.c`.  Build + run datetime edge cases.

6. **Merge `auth_sigv4_headers.c`** — move `build_canonical_headers` into
   `auth_sigv4_verify.c`, delete extern declaration, remove file from `config.h`.
   Run `./configure`, build.

---

## Verification

```bash
# Build
cd /tmp/nginx-1.28.3
./configure --with-stream --with-http_ssl_module --with-http_dav_module \
            --with-threads --add-module=$REPO
make -j$(nproc) 2>&1 | grep "^error:" | wc -l
# Expected: 0

# S3 auth test suite
PYTHONPATH=tests pytest tests/test_conformance.py -k "s3 or sigv4" -v
PYTHONPATH=tests pytest tests/ -k "s3" -v

# Clock-skew edge cases (signing key cache must invalidate at midnight)
PYTHONPATH=tests pytest tests/ -k "clock_skew or expired or presigned" -v

# Verify CRYPTO_memcmp constant-time comparison is preserved
grep -n "CRYPTO_memcmp" src/protocols/s3/auth_sigv4_verify.c
# Must still be present — no regression to string comparison

# SigV4 test vectors (AWS publishes test vectors at:
# https://docs.aws.amazon.com/general/latest/gr/sigv4-test-suite.html)
# If there is a local test vector file:
PYTHONPATH=tests pytest tests/ -k "test_vector" -v

# Full suite
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

---

## Risk Assessment

**Low–Medium.**

**Risk 1: signing key cache invalidation.**  The cache uses `strcmp(date, ...)` to
detect stale entries.  The `date` field in `sigv4_components_t` is extracted from
the `X-Amz-Date` header or presigned URL — it comes from the *client*, not the
server clock.  A client that sends a request with a future or past date (within the
900-second skew window) could theoretically hit the cache with a different date and
invalidate it.  This is harmless: invalidation is cheap.  The security invariant
(clock skew check) happens *before* key derivation, so a request outside the skew
window is rejected before it can interact with the cache.

**Risk 2: `timegm()` not available.**  `timegm` is not in POSIX; it is a glibc
extension.  On any Linux system with glibc ≥ 2.0 (guaranteed on kernel 5.6+), it
is present.  Add `#define _GNU_SOURCE` at the top of `auth_sigv4_verify.c` if not
already defined (required to expose the declaration in `<time.h>`).

**Risk 3: `EVP_MAC` singleton across nginx reload.**  nginx calls
`init_process` / `exit_process` hooks for each worker lifecycle.  The singleton
is initialised and freed correctly per worker.  On reload, the master process
forks new workers; each calls `xrootd_crypto_init()` fresh.  No cross-worker
sharing of OpenSSL state.

**Risk 4: `CRYPTO_memcmp` constant-time comparison.**  The final signature
comparison uses `CRYPTO_memcmp`, which must not be changed to `strcmp` or
`memcmp`.  The refactor does not touch this line; verify with grep after the
change.

---

## Rollback

```bash
git revert <phase-9-commit>
./configure --with-stream --with-http_ssl_module --with-http_dav_module \
            --with-threads --add-module=$REPO
make -j$(nproc)
```

`auth_sigv4_headers.c` is restored from git; `config.h` returns to its prior
state automatically.

---

## Summary

| | Before | After |
|---|---|---|
| Crypto library | OpenSSL EVP (per-call fetch) | OpenSSL EVP (singleton fetch) |
| Key derivation | Duplicated in verify.c + post_object.c | Single shared helper |
| Date parsing | Custom Gregorian calendar algorithm | `timegm(3)` |
| File count (SigV4 auth) | 4 files | 3 files |
| LoC delta | — | −73 (conservative), −140 (optimistic) |
| HMAC calls/request (cache hit) | 5 | 1 |
| `EVP_MAC_fetch` calls/request | 5 | 0 (cache hit) / 1 (miss) |
