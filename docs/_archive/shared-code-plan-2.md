# Shared-Code Plan 2: Post-Phase-A/B Opportunities

This plan picks up where `shared-code-plan.md` left off.  Phases A (URL
decode) and B (errno mapping) have been implemented and are in `src/compat/`.
This document catalogues what remains from that plan and adds three new
opportunities found by cross-reading `src/webdav/` and `src/s3/` after those
changes landed.

---

## Current state of `src/compat/`

| File | Purpose | Status |
|---|---|---|
| `crc32c.c/h` | CRC32c for XRootD pgread/pgwrite | pre-existing |
| `xml.c/h` | XML escape, text elements, lockinfo parse | pre-existing |
| `uri.c/h` | Percent-decode (`xrootd_http_urldecode`) | **Phase A — done** |
| `http_errno.c/h` | errno → HTTP status (`xrootd_http_errno_to_status`) | **Phase B — done** |
| `path.c/h` | URI→filesystem path resolver | Phase C — pending |
| `range.c/h` | HTTP Range header parse | **new** |
| `etag.c/h` | ETag string generation | **new** |

---

## Carried-over items (from shared-code-plan.md)

### Phase C — shared path resolver  ★★★ highest security value

**What:** Translate a decoded path string into a canonicalised filesystem path
confined within `root_canon`.

**Where:**

| Copy | File | LOC | Key behaviour |
|---|---|---:|---|
| `ngx_http_xrootd_webdav_resolve_path` | `src/webdav/path.c` | ~120 | URL-decodes `r->uri`, `..` check, `realpath()`, ENOENT parent strategy, confinement verify. Returns `NGX_HTTP_*`. |
| `webdav_resolve_destination_path` | `src/webdav/path.c` | ~100 | Same logic for pre-decoded Destination header paths (COPY/MOVE). |
| `s3_resolve_key` | `src/s3/util.c` | ~45 | Concatenates root + key, `..` scan only. **No `realpath()` call.** Symlinks in the key path reach the kernel unverified at user-space level. |

**Security gap:** `s3_resolve_key` does not call `realpath()`.  Symlink
escapes are caught downstream by `xrootd_open_confined_canon`'s kernel-level
`RESOLVE_BENEATH` / `O_NOFOLLOW`, so there is no exploitable path escape.
However:

1. S3 multipart helpers call `lstat()` on staging-directory paths built from
   `fs_path` without going through `xrootd_open_confined_canon`.  A symlink at
   a staging-path component that points outside `root_canon` is **not** caught
   at the `lstat` layer.
2. S3 currently returns 500 on traversal attempts rather than 403, because
   `s3_resolve_key` returns `0` (generic failure) with no errno context.

**Proposed implementation:** `xrootd_http_resolve_path(root_canon,
decoded_path, out, outsz)` in `src/compat/path.c`.  Pure C, no nginx headers.
Returns 0 on success or an HTTP integer status code (403, 404, 414, 500) on
failure.  Implements the realpath + ENOENT-parent strategy from WebDAV.

Replace:
- `ngx_http_xrootd_webdav_resolve_path` → wrapper: URL-decode `r->uri` +
  strip trailing slash, then call shared function, map int → `NGX_HTTP_*`.
- `webdav_resolve_destination_path` → wrapper: call shared function directly.
- `s3_resolve_key` → wrapper: prepend `/` to key, call shared function, return
  `1`/`0`.

**LOC saved:** ~200 (net, after wrappers).
**Risk:** Medium.  Both protocols are in hot paths; test coverage is strong.
**Required tests:** `test_s3_path_traversal_dotdot_403`,
`test_s3_symlink_escape_403` (currently returns 500).

---

### Phase D — S3 response header helper  ★ low value

**What:** `s3_set_header(r, key, value)` — allocate and push a response header.

**Where:** Defined as a `static` function in `src/s3/object.c` (lines 14–30).
Used only within that file.

**Fix:** Move to `src/s3/util.c`, remove `static`, declare in `src3/s3.h`.
Allows other S3 files to call it without duplicating the pattern.

**LOC saved:** ~0 net (move, not deletion).  Value: prevents future copies.
**Risk:** Trivial.

---

## New opportunities

### Phase E — HTTP Range header parser  ★★ medium value

**What:** Parse a `Range: bytes=start-end` header into `(range_start,
range_end, has_range)` and clamp to file size.

**Where:**

| Copy | File | Range LOC |
|---|---|---:|
| `s3_handle_get` | `src/s3/object.c` | ~55 (lines 91–145) |
| `webdav_handle_get` | `src/webdav/get.c` | ~65 (lines 133–200) |

The two implementations are **structurally identical** — same three-case parse
(`bytes=S-E`, `bytes=-suffix`, `bytes=S-`), same clamping, same 416 path.
One minor divergence:

| Detail | WebDAV | S3 |
|---|---|---|
| `bytes=start-` with no end digit | `*(dash+1) != '\0'` guard before parsing | no guard (safe: `end` pointer bounds it) |
| 416 response for empty file + range | separate `st_size == 0` branch | combined into `range_start > range_end` check |

**Proposed implementation:**

```c
/* src/compat/range.h */
typedef struct {
    off_t  start;
    off_t  end;
    int    present;   /* 1 if Range header was found and parsed */
    int    satisfiable; /* 0 → caller should return 416 */
} xrootd_http_range_t;

void xrootd_http_parse_range(const unsigned char *hdr_val, size_t hdr_len,
    off_t file_size, xrootd_http_range_t *out);
```

Pure C, no nginx headers.  Callers read `r->headers_in.range->value` and pass
`.data`/`.len` to the function.  Handles all three `bytes=` forms.  Sets
`satisfiable=0` when `start > end` or `file_size == 0` with a range request.

**LOC saved:** ~100 (net, after wrappers).
**Risk:** Low.  Pure parsing; well-covered by existing range tests in both
test suites.  Divergence between the two implementations is cosmetic — the
unified version should use WebDAV's stricter guard.

**Required tests (3 per protocol):**

WebDAV: `test_get_range_partial_200`, `test_get_range_suffix_200`,
`test_get_range_unsatisfiable_416`.

S3: `test_s3_get_range_partial_206`, `test_s3_get_range_suffix_206`,
`test_s3_get_range_unsatisfiable_416`.

---

### Phase F — ETag string generation  ★ low-medium value

**What:** Format a synthetic ETag from `(mtime, size)`.

**Where:**

| Copy | File | Format | RFC status |
|---|---|---|---|
| `webdav_etag_str` | `src/webdav/headers.c` | `W/"%lx-%llx"` | Weak (RFC 7232 §2.1) |
| `s3_etag` | `src/s3/util.c` | `"%lx-%lx"` | Strong |

**Two divergences:**

1. **Weak vs strong:** WebDAV prefixes `W/` per RFC 7232; S3 omits it per AWS
   S3 convention.  Correct for each protocol — cannot be unified into a single
   format.
2. **Size type:** WebDAV casts `st_size` to `unsigned long long` (`%llx`); S3
   casts to `unsigned long` (`%lx`).  On 64-bit Linux `unsigned long` is also
   64-bit, so no truncation in practice, but `%llx` with `unsigned long long`
   is the portable correct form.

**Proposed implementation:**

```c
/* src/compat/etag.h */
#define XROOTD_ETAG_WEAK    0x01u

void xrootd_http_etag_str(char *buf, size_t bufsz,
    time_t mtime, off_t size, unsigned flags);
```

`webdav_etag_str` → one-line wrapper passing `XROOTD_ETAG_WEAK`.
`s3_etag` → one-line wrapper passing `0`, gains `%llx` fix for `st_size`.

**LOC saved:** ~20 (net).  **Bug fixed:** S3 `st_size` now uses `%llx`.
**Risk:** Low.

---

### Phase G — S3 log sanitization  ★★ security value (not LOC)

**What:** S3 `put.c` logs filesystem paths and temp-file names directly with
`ngx_log_error`:

```c
ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
              "s3: write to temp failed");          // safe (no path)
ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
              "s3: temp open(\"%s\") failed", tmp_path);   // UNSAFE
ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
              "s3: rename(\"%s\" -> \"%s\") failed",
              tmp_path, fs_path);                          // UNSAFE
```

`tmp_path` is derived from `fs_path` which comes from `s3_resolve_key` which
comes from the decoded S3 object key in the request URI.  An attacker can
include `\n`, `\r`, or escape sequences in the object key to forge log entries.

`xrootd_sanitize_log_string` is already declared in `src/path/path.h` (the
stream-layer header) and re-declared in `src/webdav/webdav.h`.  The function
is compiled into the stream module and available to all modules in the binary.

**Fix:** In `src/s3/put.c`, before each `ngx_log_error` call that includes a
user-derived path, pass it through `xrootd_sanitize_log_string`.  S3's `s3.h`
should include `src/path/path.h` (or a compat wrapper) to get the declaration.

Files to update: `src/s3/put.c` (~6 log sites), `src/s3/object.c` (~2 log
sites with `fs_path`).

**LOC added:** ~15 (sanitization buffers + calls).  Net: +15 LOC for a
security fix, not a reduction.  Worth doing regardless of LOC cost.
**Risk:** Low.  Pure logging change; no protocol behaviour affected.

---

## What cannot be shared (updated)

| Area | Reason |
|---|---|
| Auth (GSI / Bearer / SigV4) | Three incompatible wire formats. |
| Request dispatch / routing | Stream = binary XProtocol; HTTP = nginx parsed request. Incompatible layers. |
| PUT body async reading | Both use `ngx_http_read_client_request_body()` — already the shared nginx API. No further abstraction needed. |
| WebDAV CORS (cors.c) | S3 clients (XrdClS3, s3cmd, boto3) do not issue browser preflight requests; CORS would add latency for zero gain. |
| `root_canon` init (realpath at config time) | ~15 LOC each, in module init hooks that are called once. Not worth abstracting. |
| TPC credential/header parsing | WLCG-specific. XrdHttp reuses WebDAV symbols. S3 has no TPC. |
| High-level XML builders | PROPFIND MultiStatus ≠ ListBucketResult. Shared primitives already in `src/compat/xml.c`. |

---

## Phased implementation

### Phase C — path resolver (2–3 days, medium risk)

1. Add `src/compat/path.c` + `src/compat/path.h` with
   `xrootd_http_resolve_path`.
2. Add to stream module `ngx_module_srcs` in `config`.
3. Replace `ngx_http_xrootd_webdav_resolve_path` with wrapper.
   Full WebDAV test suite before touching S3.
4. Replace `webdav_resolve_destination_path` with wrapper.
5. Replace `s3_resolve_key` with wrapper.
6. Audit S3 multipart `lstat` sites — replace with
   `xrootd_open_confined_canon` + `fstat` where possible.
7. Build + run 3 tests per protocol including path-traversal negatives.

### Phase D — S3 header helper (0.5 day)

1. Move `s3_set_header` from `object.c` to `util.c`; remove `static`.
2. Declare in `s3.h`.
3. Build + test.

### Phase E — range parser (1 day, low risk)

1. Add `src/compat/range.c` + `src/compat/range.h` with
   `xrootd_http_parse_range`.
2. Add to stream module `ngx_module_srcs` in `config`.
3. Replace range-parse block in `webdav/get.c` with call.
4. Replace range-parse block in `s3/object.c` with call.
5. Build + 3 range tests per protocol.

### Phase F — ETag string (0.5 day, low risk)

1. Add `src/compat/etag.c` + `src/compat/etag.h` with
   `xrootd_http_etag_str`.
2. Add to stream module `ngx_module_srcs` in `config`.
3. Replace `webdav_etag_str` and `s3_etag` bodies with wrappers.
4. Build + test.

### Phase G — S3 log sanitization (0.5 day, security fix)

1. Include `src/path/path.h` in `src/s3/s3.h` for
   `xrootd_sanitize_log_string` declaration.
2. In `src/s3/put.c`: wrap each user-derived path in a `safe_path[512]` buffer
   via `xrootd_sanitize_log_string` before passing to `ngx_log_error`.
3. In `src/s3/object.c`: same treatment for any `fs_path` log sites.
4. Build + manual log-injection test: PUT key containing `\n` → verify log
   shows escaped `\n`, not a forged new log line.

---

## Metrics

| Phase | LOC removed | LOC added | Net | Primary benefit |
|---|---:|---:|---:|---|
| C — path resolver | ~265 | ~140 | −125 | Security: symlink confinement for S3 multipart |
| D — header helper | ~0 | 0 | 0 | Prevents future duplication |
| E — range parser | ~120 | ~70 | −50 | Eliminates exact duplicate |
| F — ETag str | ~20 | ~15 | −5 | Fixes S3 `%lx` size truncation (cosmetic on Linux) |
| G — log sanitize | 0 | ~15 | +15 | Security: blocks S3 log-injection attack |
| **Total** | **~405** | **~240** | **−165** | |

Phases C and G deliver the highest security value.  Phase E delivers the
largest LOC reduction for the risk involved.  All five fit in one week of
focused work.
