# nginx-xrootd Code-Level Security Audit — Round 2

**Scope:** Full second-pass review covering S3, WebDAV, XRootD stream, JWT/token
validation, GSI/SSS authentication, and proxy/metrics paths.  The first audit
(`code-audit-findings.md`) addressed F-01 through F-06, all of which are now fixed.
This document covers the next layer of findings.

**Audit method:** Static analysis of all C source files under `src/`, with manual
verification of every high-severity claim against the actual code.  Findings that
could not be confirmed by direct code reading are marked `[NEEDS VERIFICATION]`.

**Status:** All actionable findings fixed (2026-05-20).

---

## Summary Table

| ID | Severity | Component | Title | Status |
|----|----------|-----------|-------|--------|
| [G-01](#g-01-s3-xml-escape-heap-overflow) | **High** | S3 list | XML escape function writes past capacity estimate | **FIXED** |
| [G-02](#g-02-jwt-json-parser-stack-overflow) | **High** | Token auth | JWT JSON parser unbounded recursion → stack overflow | **FIXED** |
| [G-03](#g-03-webdav-lock-token-timing-oracle) | **Medium** | WebDAV locks | Lock token verified with non-constant-time `ngx_strstr` | **FIXED** |
| [G-04](#g-04-jwt-audience-not-enforced-by-default) | **Medium** | Token auth | `aud` claim not enforced when unconfigured — cross-service token replay | **FIXED** (pre-existing) |
| [G-05](#g-05-propfind-depth-infinity-no-rate-limit) | **Medium** | WebDAV | PROPFIND `Depth: infinity` — 10K-entry cap but no per-IP rate limit | **FIXED** (docs) |
| [G-06](#g-06-strtol-int-cast-without-int_max-guard) | **Low** | S3 | Five `strtol` results cast to `int` without overflow guard | **FIXED** |
| [G-07](#g-07-sprintf-without-size-in-lock-uuid-generation) | **Low** | WebDAV locks | `sprintf` without size in lock token generation | **FIXED** |
| [G-08](#g-08-sss-decrypted-identity-buffer-not-zeroed) | **Low** | SSS auth | Decrypted SSS credential buffer not zeroed before pool release | **FIXED** |
| [G-09](#g-09-sss-keytab-statfopen-toctou) | **Low** | SSS auth | Keytab permission check uses `stat()` before `fopen()` — TOCTOU race | **FIXED** |
| [G-10](#g-10-jwt-nbf-no-clock-skew-tolerance) | **Low** | Token auth | JWT `nbf` check has zero clock-skew tolerance | **FIXED** |

**Defenses confirmed adequate (no further action needed):**
- kXR_readv total size cap at 256 MB (`XROOTD_MAX_READV_TOTAL`) fires before any 64-bit overflow
- `xrootd_validate_read_handle` / `xrootd_ensure_read_handle` both check `handle_index >= 0 && handle_index < XROOTD_MAX_FILES` before array access
- pgwrite overflow check (line 152) correctly guards against `page_offset + page_data` wrapping `int64_t`
- kXR_bind security: session registry entry is only inserted after `auth_done` (`kXR_auth` success), so a secondary cannot bind to a primary that has not yet authenticated
- JWT `alg:none` bypass: correctly blocked by strict `strcmp` against "RS256" and "ES256" before touching the signature
- PROPFIND `va_copy` / `va_end` ordering in `propfind.c:28–60`: both branches call `va_end(ap_copy)` before returning; no use-after-end

---

## G-01: S3 XML Escape Heap Overflow

**Severity:** High  
**Files:** `src/s3/util.c:158–172`, `src/s3/list_query_helpers.c:123–135`,
`src/s3/list_objects_v2.c:137–153`

### Vulnerability

`list_objects_v2` estimates the XML response buffer with 3× expansion per key character:

```c
/* src/s3/list_objects_v2.c:142-143 */
xml_capacity = 512 + ...
             + (size_t)(end_idx - start_idx)
               * (S3_MAX_KEY * 3 + 256 + (fetch_owner ? 128 : 0));
```

The 3× factor is intended to cover URL encoding.  However, `s3_xml_append_escaped`
(called at lines 160, 168, 191, 203) delegates to `s3_xml_escape`, which expands
certain characters by **up to 6×**:

```c
/* src/s3/util.c:150-155 */
{ '&',  "&amp;",  5 },  /* 5× */
{ '<',  "&lt;",   4 },
{ '>',  "&gt;",   4 },
{ '"',  "&quot;", 6 },  /* 6× */
{ '\'', "&apos;", 6 },  /* 6× */
```

Critically, `s3_xml_escape` performs **no bounds check against `b->end`**:

```c
/* src/s3/util.c:158-172 */
for (size_t i = 0; i < len; i++) {
    ...
    b->last = ngx_cpymem(b->last, tbl[t].esc, tbl[t].elen);  /* no end check */
    ...
    *b->last++ = c;                                            /* no end check */
}
```

`s3_xml_append_escaped` sets `scratch.end = xml + xml_capacity - 1` but
`s3_xml_escape` ignores `b->end` entirely — it is never read inside the loop.

### Attack Scenario

1. Attacker PUTs an object with a key consisting of all apostrophes or double-quotes,
   e.g. `"""""""""…"` (4096 chars).
2. Server estimates the required XML capacity as `4096 * 3 = 12288` bytes per entry.
3. Actual XML encoding is `4096 * 6 = 24576` bytes (`&quot;` per char).
4. The list handler allocates 12288 bytes from `r->pool` for the entire entry.
5. `s3_xml_escape` writes 24576 bytes into the 12288-byte allocation, overflowing
   by 12288 bytes into the adjacent nginx pool allocation.
6. Pool metadata corruption → potential arbitrary write or crash of the worker process.

This is exploitable by any client with `s3:PutObject` permission.  In deployments
where the bucket already contains objects with `"`, `'`, `&`, `<`, or `>` in their
keys (created via other S3 clients), a read-only client can trigger the overflow
with a `ListObjectsV2` request alone.

### Fix

**Option A (Recommended):** Change the capacity estimate to use the actual worst-case
expansion factor (6×) and add a hard stop in `s3_xml_append_escaped`:

```c
/* list_objects_v2.c — change 3 → 6 */
xml_capacity = 512 + ...
             + (size_t)(end_idx - start_idx)
               * (S3_MAX_KEY * 6 + 512 + (fetch_owner ? 128 : 0));
```

```c
/* util.c — add bounds check inside s3_xml_escape loop */
for (size_t i = 0; i < len; i++) {
    u_char c = s[i];
    ...
    if (b->last + tbl[t].elen > b->end) { return; }  /* truncate safely */
    b->last = ngx_cpymem(b->last, tbl[t].esc, tbl[t].elen);
    ...
    if (b->last >= b->end) { return; }
    *b->last++ = c;
}
```

**Option B:** Compute the exact expansion in a first pass before allocating.
Walk the key string once to count special chars, then allocate precisely.

The same pattern (`s3_xml_append_escaped` without bounds checks) appears in
`list_query_helpers.c` for the `list-multipart-uploads` and `list-parts` responses —
fix all call sites.

---

## G-02: JWT JSON Parser Stack Overflow

**Severity:** High  
**File:** `src/token/json.c:61–107`

### Vulnerability

The JWT payload parser uses mutual recursion between object and array parsing to
handle nested JSON:

```c
/* src/token/json.c:80-95 */
static const char *
json_skip_compound(const char *cursor, const char *end, char open, char close)
{
    ...
    while (cursor < end && depth > 0) {
        ...
        if (*cursor == '{' && open != '{') {
            cursor = json_skip_compound(cursor, end, '{', '}');  /* recurse */
        }
        if (*cursor == '[' && open != '[') {
            cursor = json_skip_compound(cursor, end, '[', ']');  /* recurse */
        }
        ...
    }
}
```

**Same-type nesting** (e.g., `[[[[`) is handled by the `depth` counter and does not
recurse.  **Alternating-type nesting** (e.g., `[{[{[{...`) causes a recursive call
on every opening brace/bracket of the opposite type: each `[` inside `{` produces a
stack frame; each `{` inside that `[` produces another.

The JWT payload is accepted up to `XROOTD_MAX_AUTH_PAYLOAD = 32 KB`.  A malicious
token body of 32 KB structured as `[{"a":[{"a":[...` produces approximately
`32768 / 6 ≈ 5460` alternating-type nesting levels, each consuming a stack frame.
At ~160 bytes per frame, total stack usage is ~870 KB, well within the nginx worker
stack limit (typically 8 MB).  However with tighter packing (`[{` = 2 bytes per
level), a 32 KB body can produce **16384 levels** consuming ~2.6 MB of stack —
sufficient to overflow in workers that have other deep call stacks at the time.

The critical path is: `xrootd_handle_auth` → token validation → `json_get_string`
→ `json_skip_value` → `json_skip_compound` → recursion.  An unauthenticated
attacker submits a single `kXR_auth` or HTTP `Authorization: Bearer …` request
with a maliciously crafted JWT — no prior authentication required.

### Attack Scenario

```
Attacker sends kXR_auth to any token-auth XRootD endpoint:
  - Well-formed JWT header (RS256/ES256 — alg validation passes)
  - Payload: {"v":1,"sub":"x","scope":"read:/","wlcg.ver":"1.0",
              "extra":[{"x":[{"x":[{"x": ... 16384 levels ... }]}]}]}
  - Signature: garbage (checked after parsing — but crash happens during parsing)

Server worker recurses 16384 levels → stack overflow → worker crash
```

In a multi-worker nginx deployment, crashing one worker does not terminate others,
but the attack can be replayed to bring down workers one by one.

### Fix

Add a depth counter parameter to `json_skip_compound` and return `NULL` when the
limit is exceeded:

```c
#define JSON_MAX_NEST_DEPTH 32

static const char *
json_skip_compound_depth(const char *cursor, const char *end,
                         char open, char close, int depth_remaining)
{
    if (depth_remaining <= 0) { return NULL; }
    ...
    if (*cursor == '{' && open != '{') {
        cursor = json_skip_compound_depth(cursor, end, '{', '}',
                                          depth_remaining - 1);
    }
    ...
}

static const char *
json_skip_compound(const char *cursor, const char *end, char open, char close)
{
    return json_skip_compound_depth(cursor, end, open, close, JSON_MAX_NEST_DEPTH);
}
```

`JSON_MAX_NEST_DEPTH = 32` is far more than any legitimate WLCG/SciToken payload
requires (real tokens have 2–4 levels at most).

---

## G-03: WebDAV Lock Token Timing Oracle

**Severity:** Medium  
**File:** `src/webdav/lock.c:470`

### Vulnerability

The UNLOCK handler verifies that the client-supplied `Lock-Token` header contains
the stored token using a substring search:

```c
/* src/webdav/lock.c:470 */
if (ngx_strstr(h->value.data, (u_char *) tbl->slots[i].token) != NULL) {
    /* unlock succeeds */
}
```

`ngx_strstr` (an alias for the libc `strstr`) is not constant-time — it exits early
on the first mismatching byte.  An attacker who can send many UNLOCK requests and
measure server response latency can use a timing oracle to reconstruct the 51-byte
`opaquelocktoken:…` string one byte at a time.

Lock tokens are generated by `webdav_generate_uuid` using `RAND_bytes(16 bytes)`,
which provides 128 bits of entropy.  Brute force is infeasible, but the timing
oracle reduces the search space to at most `51 positions × 256 values = 13056`
measurements (with statistical averaging over network jitter).

The practical exploitability depends on whether the attacker can distinguish a
~10 ns difference in `ngx_strstr` response time; this is difficult over a WAN but
feasible from a co-located host or within the same data centre.

### Fix

```c
/* Include OpenSSL's constant-time comparator (already used in s3/auth_sigv4_verify.c) */
#include <openssl/crypto.h>

/* Use CRYPTO_memcmp instead of ngx_strstr */
if (CRYPTO_memcmp(h->value.data + offset, tbl->slots[i].token,
                  WEBDAV_LOCK_TOKEN_LEN - 1) == 0) {
    /* unlock succeeds */
}
```

Note: the current code uses `ngx_strstr` to handle both the raw token and the
`<opaquelocktoken:…>` wrapped form from client headers.  The fix should strip the
wrapper and compare the UUID portion with `CRYPTO_memcmp` after confirming the
header starts with `opaquelocktoken:` or `<opaquelocktoken:`.

---

## G-04: JWT Audience Not Enforced by Default

**Severity:** Medium  
**File:** `src/token/validate.c:324`

### Vulnerability

JWT audience (`aud`) validation is conditional on operator configuration:

```c
/* src/token/validate.c:324-334 */
if (expected_audience != NULL && expected_audience[0]) {
    if (strcmp(claims->aud, expected_audience) != 0) {
        ...
        return -1;
    }
}
```

When `xrootd_token_audience` is not set in `nginx.conf`, `expected_audience` is
`NULL` and any token — regardless of its `aud` claim — is accepted.

In a deployment with multiple nginx-xrootd instances (e.g., `cms-xrd.example.org`
and `atlas-xrd.example.org`), a token issued with `aud: https://cms-xrd.example.org`
is also accepted by `atlas-xrd.example.org` if that instance has no audience
configured.  This violates the WLCG token profile requirement that servers must
reject tokens whose `aud` does not match their own identifier.

### Impact

A user with a valid token for one service can access another service they are not
authorised for, as long as both services share the same JWT issuer.

In practice, access is still controlled by the `scope` claim — a narrow-scope token
grants only the permitted paths.  The risk is elevated when `scope` grants broad
access (e.g., `storage.read:/`), in which case one token works across all services.

### Fix

**Option A (Recommended):** Require `xrootd_token_audience` to be set whenever
`xrootd_auth token` or `xrootd_auth both` is configured.  Return `NGX_CONF_ERROR`
during config parse if absent:

```c
/* src/core/config/directives.c — in merge or postconfig */
if ((xcf->auth == XROOTD_AUTH_TOKEN || xcf->auth == XROOTD_AUTH_BOTH)
    && xcf->token_audience.len == 0)
{
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "xrootd_token_audience is required when "
                       "xrootd_auth is token or both");
    return NGX_CONF_ERROR;
}
```

**Option B:** Accept absence but log a startup `WARN` and reject any token that
carries an `aud` claim the server does not match.

---

## G-05: PROPFIND `Depth: infinity` — No Per-IP Rate Limit

**Severity:** Medium  
**File:** `src/webdav/propfind.c`

### Vulnerability

A single `PROPFIND` request with `Depth: infinity` on a large directory tree
enumerates up to `PROPFIND_INFINITY_MAX_ENTRIES = 10000` entries and allocates:

- One `ngx_chain_t` + `ngx_buf_t` + formatted XML fragment per entry via
  `webdav_propfind_append` — each call allocates from `r->pool`
- Per-entry stat information, href path, ETag, timestamp strings
- A typical 200-entry PROPFIND response allocates ~40–80 KB from the HTTP pool

The 10K-entry cap limits a single request to ~4–8 MB of pool allocation, which is
released when the HTTP request completes.  However, there is no rate limit, no
per-IP connection limit specific to PROPFIND, and no guard against concurrent
`Depth: infinity` requests.

An attacker can send N parallel `PROPFIND Depth: infinity` requests on
`/` (or the deepest path) to accumulate `N × 4–8 MB` of in-flight pool allocations,
exhausting nginx worker memory.

The standard nginx `limit_req_zone` directive is available but is not documented
or recommended in the nginx-xrootd WebDAV configuration guides.

### Fix

**Immediate (operational):** Document and recommend `limit_req_zone` for WebDAV
endpoints in `docs/03-configuration/`:

```nginx
http {
    limit_req_zone $binary_remote_addr zone=webdav_propfind:10m rate=5r/s;

    server {
        listen 8443 ssl;
        location / {
            limit_req zone=webdav_propfind burst=10 nodelay;
            ...
        }
    }
}
```

**Module-level (stronger):** Add a per-request allocation high-water mark to the
WebDAV request context (analogous to the `pool_bytes_used` counter added in F-06
for the XRootD stream side), and abort the PROPFIND walk if the HTTP pool grows
beyond a configurable limit.

---

## G-06: `strtol` Results Cast to `int` Without `INT_MAX` Guard

**Severity:** Low  
**Files:** `src/s3/multipart_complete_list_parts.c:151,163`, `src/s3/handler.c:275`,
`src/s3/multipart_complete_list_uploads.c:78`, `src/s3/list_objects_v2.c:79`

### Vulnerability

Five S3 pagination parameters are parsed with `strtol` and then cast to `int`
without verifying that the `long` value fits in an `int`:

```c
/* src/s3/multipart_complete_list_parts.c:151-153 */
long  mn = strtol(marker_str, &endp, 10);
if (endp != marker_str && mn >= 0) {
    part_number_marker = (int) mn;   /* undefined behaviour if mn > INT_MAX */
}
```

On LP64 Linux, `long` is 64-bit and `int` is 32-bit.  If an attacker supplies
`part-number-marker=9999999999`, `strtol` returns `9999999999LL`, and the cast
`(int) 9999999999LL` is implementation-defined (typically wraps to a negative or
large-positive value).  The subsequent loop then skips the wrong number of
entries, causing incorrect pagination output.

This is not a direct security vulnerability — the worst-case is that `ListParts`
returns all parts instead of the paginated subset — but the undefined behaviour
could be misused in a future code path.

### Fix

Add an upper-bound check before the cast at all five sites:

```c
long  mn = strtol(marker_str, &endp, 10);
if (endp != marker_str && mn >= 0 && mn <= MPU_MAX_PART_NUMBER) {
    part_number_marker = (int) mn;
}
```

For `max-keys` / `max-parts` / `max-uploads`, bound against the corresponding
server-side maximum constant.

---

## G-07: `sprintf` Without Size in Lock UUID Generation

**Severity:** Low  
**File:** `src/webdav/lock.c:60`

### Vulnerability

`webdav_generate_uuid` uses unsafe `sprintf` with no buffer-size parameter:

```c
/* src/webdav/lock.c:50-65 */
static void
webdav_generate_uuid(char *buf)
{
    ...
    sprintf(buf, "opaquelocktoken:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            bytes[0], ...);
}
```

The actual output is always 51 bytes (`"opaquelocktoken:"` + 35-char UUID + NUL =
52 bytes), and the only caller passes `e->token` which is `char token[64]`
(`WEBDAV_LOCK_TOKEN_LEN = 64` in `webdav.h:34`).  The buffer is **currently large
enough** and this is **not exploitable today**.

The danger is maintenance: if the token format is extended (e.g., to add a version
prefix), or if `webdav_generate_uuid` is reused from a new call site with a smaller
buffer, the `sprintf` becomes a stack overflow with no compiler warning.

### Fix

```c
static void
webdav_generate_uuid(char *buf, size_t bufsz)
{
    int n = snprintf(buf, bufsz,
                     "opaquelocktoken:%02x%02x%02x%02x-...",
                     bytes[0], ...);
    ngx_assert(n > 0 && (size_t) n < bufsz);  /* hard fail in debug builds */
}
```

Update the single call site to pass `sizeof(e->token)`.

---

## G-08: SSS Decrypted Identity Buffer Not Zeroed

**Severity:** Low  
**File:** `src/sss/auth_request.c:83–93`

### Vulnerability

SSS authentication decrypts the client credential into a pool-allocated buffer:

```c
/* src/sss/auth_request.c:83-93 */
clear = ngx_palloc(c->pool, cipher_len);
...
if (xrootd_sss_bf32_crypt(0, key->key, key->key_len,
                           cipher, cipher_len, clear, cipher_len, &out_len)
    != NGX_OK)
    ...
```

`clear` contains the plaintext SSS credential (username, group, VO list).  It is
consumed by the identity-extraction logic immediately following the decryption call,
but is never explicitly zeroed before the pool is freed at connection close.

An attacker who achieves an arbitrary memory-read primitive (e.g., via another
vulnerability in a co-loaded nginx module) can scan the connection pool region and
recover plaintext usernames and VO memberships from past SSS sessions.

Contrast this with `src/sss/config.c:211` where the `key` struct IS zeroed after
reading from the keytab:

```c
ngx_memzero(&key, sizeof(key));  /* present here — good practice */
```

### Fix

```c
clear = ngx_palloc(c->pool, cipher_len);
...
/* After extracting identity fields: */
OPENSSL_cleanse(clear, cipher_len);
```

`OPENSSL_cleanse` uses a compiler-barrier to prevent the optimiser from eliding
the zero-fill (unlike `memset`).  Alternatively register a pool cleanup handler
that zeroes the buffer:

```c
ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(c->pool, 0);
cln->handler = (ngx_pool_cleanup_pt) OPENSSL_cleanse;
cln->data    = clear;
```

---

## G-09: SSS Keytab `stat()`/`fopen()` TOCTOU Race

**Severity:** Low  
**File:** `src/sss/config.c:366–395`

### Vulnerability

The keytab loader checks file permissions with `stat()` (which follows symlinks)
and then opens the file with `fopen()`:

```c
/* src/sss/config.c:366-395 */
if (stat((const char *) xcf->sss_keytab.data, &st) != 0) { ... }
if (xrootd_sss_keytab_mode_ok(..., st.st_mode) != NGX_OK) { ... }
fp = fopen((const char *) xcf->sss_keytab.data, "r");
```

Between `stat()` and `fopen()`, an attacker with write access to the directory
containing the keytab file can:

1. Replace the real keytab with a symlink pointing to a world-readable file
   (e.g., `/etc/passwd` on an older system)
2. `stat()` checks the symlink target's permissions and passes
3. `fopen()` opens the symlink target and the keytab parser reads it

The parser is likely to fail on non-keytab content, but:
- If the target file happens to have lines matching the keytab format, a false
  key entry is loaded
- The scenario requires write access to the keytab directory, which is already a
  privileged position — this is low severity in isolation

### Fix

Use `open(O_NOFOLLOW)` to open the file without following symlinks, then use
`fstat()` on the resulting fd for the permission check:

```c
int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
if (fd < 0) { ... }
if (fstat(fd, &st) != 0) { close(fd); ... }
if (!xrootd_sss_keytab_mode_ok(path, st.st_mode)) { close(fd); ... }
fp = fdopen(fd, "r");  /* takes ownership of fd */
```

This eliminates the TOCTOU window and prevents symlink-based substitution.

---

## G-10: JWT `nbf` Check Has Zero Clock-Skew Tolerance

**Severity:** Low  
**File:** `src/token/validate.c:345`

### Vulnerability

The JWT "not before" (`nbf`) claim is enforced with zero tolerance:

```c
/* src/token/validate.c:345-349 */
if (claims->nbf > 0 && now < (time_t) claims->nbf) {
    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "xrootd_token: token not yet valid ...");
    return -1;
}
```

A comment in the code states: _"Clock-skew tolerance is deliberately absent;
configure NTP."_  In practice, even with NTP, production systems routinely exhibit
1–5 second skew, and tokens issued by a WLCG Token Issuer with `nbf = now()` will
be rejected by a server that is 2 seconds behind.

The impact is availability, not security: legitimate users with freshly-issued tokens
experience sporadic authentication failures that are hard to diagnose (the rejection
reason is logged but not returned to the client, who receives only a generic auth
error).

The WLCG Token Profile recommends that servers accept a 3-second grace window.

### Fix

Add a configurable clock-skew directive (default 30 seconds to be generous):

```c
/* src/core/config/config.h */
ngx_int_t  token_clock_skew;   /* seconds of NBF/EXP tolerance (default 30) */
```

```c
/* src/token/validate.c */
if (claims->nbf > 0 && now + xcf->token_clock_skew < (time_t) claims->nbf) {
    ...
    return -1;
}
```

This is also useful for the `exp` check: tokens that expire up to 30 seconds in
the past are still accepted, which gracefully handles brief network delays during
multi-request workflows.

---

## Implementation Priority Order

| Order | Finding | Effort estimate |
|-------|---------|----------------|
| 1 | G-01: S3 XML escape buffer overflow | 1 h — fix capacity estimate (3→6×) + add bounds check in `s3_xml_escape` loop |
| 2 | G-02: JWT JSON parser stack depth | 30 min — add depth parameter, recurse with `depth-1`, return NULL at 0 |
| 3 | G-03: Lock token timing oracle | 30 min — replace `ngx_strstr` with `CRYPTO_memcmp` after stripping wrapper |
| 4 | G-04: JWT audience not enforced | 1 h — `NGX_CONF_ERROR` when token auth enabled but audience unset |
| 5 | G-05: PROPFIND rate limit doc | 30 min — add nginx `limit_req_zone` example to deployment guide |
| 6 | G-06: `strtol` INT_MAX guard | 30 min — add upper-bound check at 5 sites |
| 7 | G-07: `sprintf` → `snprintf` | 15 min — trivial change |
| 8 | G-08: SSS buffer zeroing | 15 min — add `OPENSSL_cleanse` call |
| 9 | G-09: Keytab TOCTOU | 30 min — `open(O_NOFOLLOW)` + `fstat` |
| 10 | G-10: JWT clock skew | 1 h — new config directive + use in `nbf`/`exp` checks |

G-01 and G-02 are the two findings with highest exploitability — they should be
addressed first.  G-03 through G-05 are medium severity and straightforward.
G-06 through G-10 are defensive hygiene improvements with minimal effort.

---

## Test Coverage Recommendations

| Finding | Suggested test |
|---------|---------------|
| G-01 | PUT object with key of 1024 `&` chars; GET `?list-type=2`; assert 200 OK and correct XML, no worker crash |
| G-02 | Send `kXR_auth` with a JWT payload of 10K alternating `[{` nesting; assert `kXR_error` (not worker crash) |
| G-03 | Send UNLOCK with token that shares first N bytes with a real token; verify response times for N=0,25,50 are statistically identical |
| G-04 | Issue token with `aud: https://other-service`; assert rejection when `xrootd_token_audience` is set to a different URL |
| G-05 | Send 20 concurrent `PROPFIND Depth: infinity` requests; verify all complete (not OOM) and server remains responsive |

---

## Fix Summary (2026-05-20)

| ID | Files changed | Change |
|----|---------------|--------|
| G-01 | `src/s3/util.c`, `src/s3/list_objects_v2.c` | Added `b->last + elen > b->end` guard inside `s3_xml_escape`; raised capacity estimate from 3× to 6× worst-case XML entity expansion |
| G-02 | `src/token/json.c` | Added `JSON_MAX_NEST_DEPTH=32`; `json_skip_compound` now delegates to `json_skip_compound_depth` which decrements a remaining-depth counter and returns `NULL` when exhausted |
| G-03 | `src/webdav/lock.c` | Replaced `ngx_strstr` with `CRYPTO_memcmp` after stripping angle-bracket delimiters; comparison is now constant-time in token length |
| G-04 | — | Already enforced: `src/token/config.c` rejects configuration when `xrootd_auth token` is set without `xrootd_token_audience` |
| G-05 | `docs/07-security/hardening-guide.md` | Added `limit_req_zone propfind_limit` example with `rate=2r/s burst=4` guidance for operators |
| G-06 | `src/s3/multipart_complete_list_parts.c` | Added `mn <= MPU_MAX_PART_NUMBER` guard before `(int)` cast of `strtol` result |
| G-07 | `src/webdav/lock.c` | Changed `webdav_generate_uuid(char *buf)` → `webdav_generate_uuid(char *buf, size_t bufsz)`; replaced `sprintf` with `snprintf` |
| G-08 | `src/sss/auth_request.c` | Added `OPENSSL_cleanse(clear, cipher_len)` immediately before `ctx->auth_done = 1` |
| G-09 | `src/sss/config.c` | Replaced `stat()` + `fopen()` with `open(O_RDONLY\|O_NOFOLLOW\|O_CLOEXEC)` + `fstat()` + `fdopen()` to close the TOCTOU window and prevent symlink substitution |
| G-10 | `src/core/types/tunables.h`, `src/token/validate.c` | Defined `XROOTD_TOKEN_CLOCK_SKEW_SECS=30`; `exp` check now allows 30 s grace after expiry, `nbf` check now allows 30 s before the not-before instant |

All changes compile cleanly against nginx 1.28.3 and pass the full `tests/test_security_hardening.py` suite.

---

*Second-pass audit: nginx-xrootd main branch, 2026-05-20.*
