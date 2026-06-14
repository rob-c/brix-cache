# Shared-Code Plan 3: Compat Consolidation (May 2026 Audit)

This plan documents the third audit pass over `src/` for duplicate or
near-duplicate logic that should live in `src/compat/`.  Plans 1 and 2 drove
the original compat layer into existence; this plan picks up what remains after
those phases landed.

The same governing principle applies: consolidation is only worthwhile when it
shrinks the security surface (fewer places where a confinement or sanitization
check can be missing) or removes a real maintenance burden (parallel changes
required in N files when one thing changes).

---

## Current state of `src/compat/`

| File | Purpose |
|---|---|
| `checksum.c/h` | Digest/hex encoding for XRootD and HTTP checksums |
| `copy_range.c/h` | `copy_file_range` with fallback, SSIZE_MAX cap, pwrite retry |
| `crc32c.c/h` | CRC32c computation for pgread/pgwrite |
| `etag.c/h` | `xrootd_http_etag_str()` — ETag from mtime+size |
| `fs_usage.c/h` | Filesystem quota/usage stats |
| `fs_walk.c/h` | Recursive directory traversal |
| `hex.c/h` | Shared hex nibble, parse, and lowercase byte-array encoding helpers |
| `http_body.c/h` | Request body → fd writer |
| `http_conditionals.c/h` | ETag precondition check + ETag list membership |
| `http_errno.c/h` | `xrootd_http_errno_to_status()` — errno → HTTP status |
| `http_file_response.c/h` | `xrootd_http_send_file_range()`, ETag/Content-Range headers |
| `http_headers.c/h` | Header lookup/set helpers plus `xrootd_http_extract_bearer()` |
| `http_query.c/h` | `xrootd_http_query_get()` — URL query parameter parsing |
| `http_xml.c/h` | `xrootd_http_chain_appendf()` — XML chain building |
| `io.c/h` | Low-level I/O abstraction |
| `kxr_errno.c/h` | `xrootd_kxr_from_errno()` — errno → kXR error code |
| `path.c/h` | Canonical path operations |
| `range.c/h` | `xrootd_http_parse_range()` — HTTP Range header |
| `shm_slots.h` | SHM slot helpers |
| `staged_file.c/h` | `xrootd_staged_open/commit/abort` — atomic temp-file staging |
| `time.c/h` | `xrootd_format_iso8601()` — UTC ISO-8601 timestamp formatting |
| `tmp_path.c/h` | `xrootd_make_tmp_path()` — random temp path generation |
| `uri.c/h` | `xrootd_http_urldecode()` — percent-decode |
| `xml.c/h` | `xrootd_xml_escape()`, `xrootd_xml_write_text_element()` |

---

## Opportunity catalogue

Entries are ordered by implementation priority (highest first).  Each entry
describes what is duplicated, exactly which files are affected, what the
concrete change is, and a risk/effort rating.

---

### 1 — `aio/dirlist.c` inline errno switch  ★★★ trivial, drop-in

**What:** `aio/dirlist.c` contains a hand-rolled errno → kXR mapping identical
to `xrootd_kxr_from_errno()` in `compat/kxr_errno.c`.

**Where:**

| Copy | File | Lines |
|---|---|---|
| Inline switch | `src/aio/dirlist.c` | ~315–332 |
| Canonical function | `src/compat/kxr_errno.c` | — |

The switch maps `ENOENT → kXR_NotFound`, `EACCES/EPERM → kXR_NotAuthorized`,
`ENOTDIR → kXR_NotFile`, default `→ kXR_IOError`.  All four cases are already
correct in `xrootd_kxr_from_errno()`.  Every other AIO handler (`read.c`,
`readv.c`, `pgread.c`, `write.c`) already calls the shared function.
`aio/dirlist.c` was simply missed when those were converted.

**Change:**

```c
/* Before */
switch (t->io_errno) {
case ENOENT:       xrd_err = kXR_NotFound;       break;
case EACCES:
case EPERM:        xrd_err = kXR_NotAuthorized;  break;
case ENOTDIR:      xrd_err = kXR_NotFile;         break;
default:           xrd_err = kXR_IOError;         break;
}

/* After */
uint16_t xrd_err = xrootd_kxr_from_errno(t->io_errno);
```

**Effort:** < 10 minutes.  **Risk:** None — it is a mechanical substitution.

---

### 2 — `fattr/helpers.c:fattr_errno_to_xrd()` duplicates `xrootd_kxr_from_errno()`  ★★★ trivial

**What:** `fattr/helpers.c` defines a private `fattr_errno_to_xrd()` with the
same core errno → kXR mapping as `xrootd_kxr_from_errno()` plus two
xattr-specific cases.

**Where:**

| | `fattr/helpers.c` | `compat/kxr_errno.c` |
|---|---|---|
| `ENOENT` | `kXR_NotFound` | `kXR_NotFound` ✓ |
| `ENOTDIR` | `kXR_NotFound` | `kXR_NotFound` ✓ |
| `EPERM/EACCES` | `kXR_NotAuthorized` | `kXR_NotAuthorized` ✓ |
| `EEXIST` | `kXR_ItExists` | `kXR_ItExists` ✓ |
| `ENOMEM` | `kXR_NoMemory` | `kXR_NoMemory` ✓ |
| `ENOSPC` | `kXR_NoSpace` | `kXR_NoSpace` ✓ |
| `ENODATA` | `kXR_AttrNotFound` | *(missing)* |
| `ERANGE` | `kXR_ArgTooLong` | *(missing)* |

**Change:** Handle the two xattr-specific cases first, delegate the rest:

```c
uint16_t
fattr_errno_to_xrd(int err)
{
    switch (err) {
    case ENODATA:  return kXR_AttrNotFound;
    case ERANGE:   return kXR_ArgTooLong;
    default:       return xrootd_kxr_from_errno(err);
    }
}
```

No change to callers.  The `ENODATA` and `ERANGE` cases from `compat/` are also
useful elsewhere, so a follow-on could add them to `xrootd_kxr_from_errno()`
with an extra comment explaining they are primarily xattr errno values.

**Effort:** 5 minutes.  **Risk:** None.

---

### 3 — S3 multipart path logging bypasses `xrootd_sanitize_log_string()`  ★★★ security consistency

**What:** `s3/multipart_initiate.c` and several sites in
`s3/multipart_complete_body.c` log filesystem path strings directly into
`ngx_log_error` without sanitization.  Every other S3 and WebDAV file that
logs a path applies `xrootd_sanitize_log_string()` first (enforced as an
invariant in `AGENTS.md`).

**Affected sites:**

| File | Approx. line | Variable logged unsanitized |
|---|---|---|
| `src/s3/multipart_initiate.c` | ~76 | `mpu_dir` |
| `src/s3/multipart_complete_body.c` | ~76, ~97, ~110, ~126, ~140, ~156 | various path strings |

The MPU directory path is server-generated (not directly client-controlled
byte-for-byte), so this is not an exploitable injection.  However, it
violates the established invariant and would need to be patched if the
path derivation ever changes.

**Change:** Wrap each affected `ngx_log_error` call with a local sanitized buffer:

```c
char safe_path[512];
xrootd_sanitize_log_string(mpu_dir, safe_path, sizeof(safe_path));
ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
              "s3 initiate_mpu: mkdir(\"%s\") failed", safe_path);
```

**Effort:** Low (10–15 sites, mechanical).  **Risk:** None — log output only.

---

### 4 — `webdav_propfind_append()` is an alias for `xrootd_http_chain_appendf()`  ★★ low effort

**Status (2026-05-21): Complete.**  The local PROPFIND append wrapper is gone.
`propfind.c`, `methods_basic.c`, and LOCK/UNLOCK XML helpers now call
`xrootd_http_chain_appendf()` directly.

**What:** `src/webdav/propfind.c` defines a local variadic function whose
entire body is a single call to `xrootd_http_chain_vappendf()` — the exact
internal form of `xrootd_http_chain_appendf()` from `compat/http_xml.c`.
The wrapper function adds no logic, no documentation value, and no type
safety.

**Callers:** `propfind.c` (~20 call sites) and `methods_basic.c`.

**Change:** Remove `webdav_propfind_append()` and replace every call site
with `xrootd_http_chain_appendf()`.  The signatures are identical (pool,
head, tail, fmt, ...).

**Effort:** ~30 minutes (mechanical sed + compile check).
**Risk:** Low — purely mechanical.

---

### 5 — `s3/list_query_helpers.c` base64url wrappers  ★★ low effort

**Status (2026-05-21): Complete.**  S3 ListObjectsV2 includes
`token/b64url.h` directly and performs continuation-token NUL termination at
the decode call site.  The stale base64url include/comment in
`list_query_helpers.c` was removed, and the shared-helper guard test now
prevents `s3_b64url_*` wrappers from returning.

**What:** `s3/list_query_helpers.c` defines `s3_b64url_encode()` and
`s3_b64url_decode()` solely to avoid `list_objects_v2.c` depending directly
on `token/b64url.h`.  The encode wrapper is a one-line passthrough.  The
decode wrapper adds only NUL termination (which can be done at the call site
with a `+1` buffer).

**Change:** Remove both wrappers.  Include `token/b64url.h` directly in the
two or three S3 files that need base64url.  Add `dst[decoded_len] = '\0'`
inline where needed.  The include of a `token/` header from `s3/` is already
done elsewhere (`token/validate.h` is included in `s3/auth.c`).

**Effort:** ~20 minutes.  **Risk:** None.

---

### 6 — Bearer token extraction duplicated in `webdav/tpc.c`  ★★ security-adjacent

**Status (2026-05-21): Complete.**  `xrootd_http_extract_bearer()` now lives in
`compat/http_headers.c/h`.  WebDAV token authentication and both HTTP-TPC
credential-delegation paths use it, giving all three call sites one
case-insensitive Bearer-scheme parser.  TPC copies the extracted slice into the
request pool before passing it to the token-exchange helper, so the C-string
contract is explicit.

**What:** The pattern of stripping the `Bearer ` prefix from an Authorization
header appears in at least three locations:

| File | Form |
|---|---|
| `src/webdav/auth_token.c` | `ngx_strncmp(auth_hdr.data, "Bearer ", 7)` then skip 7 |
| `src/webdav/tpc.c` | `strncasecmp(value, "Bearer ", prefix_len)` (push path) |
| `src/webdav/tpc.c` | Same pattern again (pull path, ~200 lines below) |

Each site has its own case-sensitivity choice and its own error path.  The
`tpc.c` sites use `strncasecmp` (case-insensitive); `auth_token.c` uses
`ngx_strncmp` (case-sensitive).  RFC 7235 requires case-insensitive scheme
matching, so the `auth_token.c` version has a latent correctness bug.

**Change:** Add to `src/compat/http_headers.c`:

```c
/*
 * xrootd_http_extract_bearer — extract the token value from an
 * Authorization header whose scheme is "Bearer" (case-insensitive).
 *
 * Sets *token_out to the token slice (no copy; points into auth_header).
 * Returns NGX_OK on success, NGX_DECLINED if scheme is absent/wrong,
 * NGX_ERROR if the header value is malformed.
 */
ngx_int_t
xrootd_http_extract_bearer(const ngx_str_t *auth_header,
                            ngx_str_t       *token_out);
```

All three sites become one-liners, and the case-sensitivity inconsistency is
fixed in one place.

**Effort:** ~1 hour (new compat function + update 3 call sites).
**Risk:** Low — only the `auth_token.c` site gets a behavioural change
(case-insensitive fix), which is a correctness improvement.

---

### 7 — ISO 8601 timestamp formatting in two places  ★★ medium effort

**Status (2026-05-21): Complete.**  `xrootd_format_iso8601()` now lives in
`compat/time.c/h`.  S3 ListObjectsV2, copy, list-parts, list-uploads, and
upload-part-copy responses call the shared helper directly, and WebDAV
PROPFIND creationdate uses the same UTC formatter.  The helper preserves the
existing S3 wire format with fixed zero milliseconds:
`YYYY-MM-DDTHH:MM:SS.000Z`.

**What:** `src/s3/util.c` defines `s3_iso8601(time_t t, char *buf, size_t bufsz)`
and calls it from five S3 files.  `src/webdav/propfind.c` formats a similar
UTC ISO-8601 creationdate inline with `gmtime_r` + `strftime`.

**Change:** Move `s3_iso8601` to `src/compat/time.c` as
`xrootd_format_iso8601(time_t t, char *buf, size_t bufsz)`.  Update the
five S3 call sites and the WebDAV propfind inline.  Remove the private copy
from `s3/util.c`.

**Effort:** ~45 minutes.  **Risk:** Low — pure I/O formatting, no logic.

---

### 8 — Four private hex nibble helpers should be one  ★★ medium effort

**Status (2026-05-21): Complete.**  `compat/hex.c/h` now exports
`xrootd_hex_nibble()`, `xrootd_hex_from_char()`, and `xrootd_hex_encode()`.
Path log sanitization, XML control escaping, Macaroon packet parsing, URI
percent decoding, checksum digest encoding, and S3 SigV4 signature encoding all
use the shared helpers.  The private S3 `hex_encode()` and local nibble parsers
were removed.

**What:** Four files each define their own version of the same
nibble ↔ ASCII hex character conversion:

| File | Function | Direction |
|---|---|---|
| `src/path/helpers.c` | `xrootd_hex_digit(u_char v)` | nibble → uppercase ASCII |
| `src/compat/xml.c` | `xrootd_xml_hex_digit(unsigned char v)` | nibble → uppercase ASCII |
| `src/token/macaroon.c` | `hex_to_int(char c)` | ASCII → nibble |
| `src/compat/uri.c` | `hex_val(unsigned char c, unsigned char *out)` | ASCII → nibble |

Additionally, `src/compat/checksum.c` has `xrootd_checksum_hex_encode(in, len, out)`
and `src/s3/auth_sigv4_canonical.c` has a private `hex_encode(in, len, out)` — both
performing byte-array → lowercase hex string conversion.

**Change:** Create `src/compat/hex.c` / `compat/hex.h` exporting:

```c
/* nibble (0-15) to ASCII uppercase hex character */
u_char xrootd_hex_nibble(u_char v);

/* ASCII hex character to nibble; returns -1 on invalid input */
int    xrootd_hex_from_char(unsigned char c);

/* byte array → lowercase hex string (SigV4 / checksum style) */
void   xrootd_hex_encode(const u_char *in, size_t len, char *out);
```

- `path/helpers.c:xrootd_hex_digit` → delegate to `xrootd_hex_nibble`
- `compat/xml.c:xrootd_xml_hex_digit` → delegate to `xrootd_hex_nibble`
- `token/macaroon.c:hex_to_int` → replace inline with `xrootd_hex_from_char`
- `compat/uri.c:hex_val` → replace inline with `xrootd_hex_from_char`
- `compat/checksum.c:xrootd_checksum_hex_encode` → delegate to `xrootd_hex_encode`
- `s3/auth_sigv4_canonical.c:hex_encode` → remove, call `xrootd_hex_encode`

The two uppercase-digit functions (`xrootd_hex_digit`, `xrootd_xml_hex_digit`)
can remain as thin `static inline` wrappers in their own headers if callers are
numerous and the include chain is heavy, but the implementation should be in one place.

**Effort:** ~2 hours (new file + 6 sites).
**Risk:** Low — all sites have test coverage.

---

### 9 — `s3/auth_sigv4_canonical.c:hmac_sha256()` belongs in `compat/crypto.c`  ★ medium effort

**What:** `s3/auth_sigv4_canonical.c` defines a private single-shot HMAC-SHA256
helper that allocates an `EVP_MAC`, computes one MAC, and frees it.  This is a
useful primitive that any future caller (WLCG discharge verification, new auth
schemes) would need to reimplement.

`src/handshake/sigver.c` caches the `EVP_MAC` handle across requests for
performance — it should **not** be unified with the S3 helper; the cached form
is architecturally different.

**Change:** Move the S3 `hmac_sha256()` and the adjacent `sha256()` helper to a
new `src/compat/crypto.c` / `compat/crypto.h` as:

```c
/* Single-shot HMAC-SHA256.  Returns 1 on success, 0 on failure. */
int xrootd_hmac_sha256(const u_char *key, size_t keylen,
                        const u_char *data, size_t datalen,
                        u_char out[32]);

/* Single-shot SHA-256.  Returns 1 on success, 0 on failure. */
int xrootd_sha256(const u_char *data, size_t len, u_char out[32]);
```

**Effort:** ~1.5 hours (new file, update S3 include, verify build).
**Risk:** Low — only the S3 auth path changes.

---

### 10 — URI percent-encode is missing from `compat/uri.c`  ★ medium effort

**What:** `compat/uri.c` provides `xrootd_http_urldecode()` (decode only).
Two S3-private functions fill the encoding gap:

| Function | File | Safe chars |
|---|---|---|
| `canonical_uri()` | `s3/auth_sigv4_canonical.c` | unreserved + `'/'` |
| `s3_url_encode_key()` | `s3/list_query_helpers.c` | unreserved only |

The implementations differ only in which characters are passed through
unchanged.

**Change:** Add to `compat/uri.c`:

```c
/*
 * xrootd_http_urlencode — RFC 3986 percent-encoder.
 *
 * Characters in [A-Za-z0-9._~-] plus any character present in safe_extra
 * are passed through unchanged.  All others are encoded as %XX (uppercase).
 *
 * Returns the number of bytes written to dst (not including NUL terminator),
 * or -1 if dst is too small.
 */
ssize_t xrootd_http_urlencode(const u_char *src, size_t srclen,
                               char *dst, size_t dstsz,
                               const char *safe_extra);
```

`canonical_uri()` becomes `xrootd_http_urlencode(path, pathlen, dst, dstsz, "/")`
and `s3_url_encode_key()` becomes `xrootd_http_urlencode(key, keylen, dst, dstsz, "")`.

**Effort:** ~2 hours (new function, unit test, update 2 call sites).
**Risk:** Low, but the SigV4 canonical URI encoding is security-critical
(a difference in encoding breaks auth).  The new function must pass the existing
SigV4 test vectors before landing.

---

## Implementation order

| Phase | Items | Dependency |
|---|---|---|
| **A** | 1, 2, 3 | None — each is independent and trivial |
| **B** | 4, 5, 6 | **Complete (2026-05-21)** |
| **C** | 7, 8 | **Complete (2026-05-21)** |
| **D** | 9, 10 | 10 must be verified against SigV4 test vectors before merging |

Phase A items can be submitted individually as single-commit PRs and reviewed
in minutes.  Phases C and D should each be a single PR with a `make` + full
test suite run before merge.

---

## Items deliberately excluded

| Candidate | Reason not included |
|---|---|
| `s3/list_query_helpers.c:s3_xml_append_escaped` → `xrootd_xml_escape` | Three-layer chain but each layer adds a caller-specific convenience; not a maintenance burden |
| `webdav/tpc_curl.c` retry logic | Curl-specific; no other protocol uses curl |
| `handshake/sigver.c` cached EVP_MAC | Performance-critical; different lifecycle from single-shot helpers |
| `write/common.c:xrootd_write_resolve_existing_path` | Already consolidated — no action needed |
| `webdav_metrics_finalize` / `s3_metrics_finalize` patterns | Per-protocol metric label sets differ; forced unification would require low-cardinality hacks |
