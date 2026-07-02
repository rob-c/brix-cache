# Shared-Code Plan 4: Cross-Protocol Audit (May 2026)

This plan is the fourth pass over `src/` for duplicate or near-duplicate logic
across the four protocol implementations — XRootD native stream (`src/session/`,
`src/read/`, `src/write/`, `src/core/aio/`), WebDAV HTTP (`src/webdav/`), S3 REST
(`src/s3/`), and the already-shared compat layer (`src/core/compat/`).

Plans 1–3 consolidated the compat layer itself.  This plan looks specifically at
cross-protocol patterns: things the S3 and WebDAV HTTP modules share with each
other, things the stream protocol shares with both, and a cluster of S3-internal
redundancies that reduce cohesion within that module.

The governing principle is unchanged: only consolidate when it shrinks the
security surface or removes a real maintenance burden.

---

## Already consolidated — for reference

The following are fully shared and need no action:

| What | Where |
|---|---|
| Percent-decode / percent-encode | `compat/uri.c/h` |
| Path confinement (`realpath` + openat2 fallback) | `compat/path.c/h` |
| ETag generation (`mtime-size` string) | `compat/etag.c/h` |
| Precondition checking (`If-Match`, `If-Modified-Since`) | `compat/http_conditionals.c/h` |
| Range header parsing | `compat/range.c/h` |
| Staged atomic file write (open temp → rename) | `compat/staged_file.c/h` |
| Request body → fd writer | `compat/http_body.c/h` |
| Query parameter parsing | `compat/http_query.c/h` |
| HTTP header get/set, bearer extraction | `compat/http_headers.c/h` |
| HMAC-SHA256, SHA-256 | `compat/crypto.c/h` |
| ISO 8601 timestamp formatting | `compat/time.c/h` |
| Hex nibble / byte-array → hex | `compat/hex.c/h` |
| XML escape + text-element write | `compat/xml.c/h` |
| XML chain building + buffer send | `compat/http_xml.c/h` |
| Recursive directory tree remove | `compat/fs_walk.c/h` (`xrootd_fs_remove_tree_confined`) |
| errno → kXR error code | `compat/kxr_errno.c/h` |
| errno → HTTP status | `compat/http_errno.c/h` |

---

## Opportunity catalogue

Entries are ordered by priority.  Each entry names the exact files, approximate
line numbers, and what the concrete change is.

---

### 1 — `XML_APPEND` / `XML_APPEND_ELEM` defined three times in `src/s3/`  ★★★ trivial

**What:** Three S3 response files each contain a `#define … #undef` block for
two identical macros, `XML_APPEND` and `XML_APPEND_ELEM`:

| File | Lines |
|---|---|
| `src/s3/list_objects_v2.c` | 158–166, undef 242–243 |
| `src/s3/multipart_complete_list_parts.c` | 199–217, undef 257–258 |
| `src/s3/multipart_complete_list_uploads.c` | 192–210, undef 250–251 |

All three definitions are byte-for-byte identical.  They reference three local
variables by fixed name (`xml`, `xml_len`, `xml_capacity`) and call
`s3_xml_append_text_element()` from `s3.h`.

**Change:** Move both macros to `src/s3/s3.h` as permanent definitions (no
`#undef` needed — names are short-lived by convention).  Remove the six
define/undef blocks from the three files.  The convention of using `xml`,
`xml_len`, and `xml_capacity` as the local variable names is already uniform
across all call sites; add a comment in `s3.h` documenting the required names.

**Effort:** 15 minutes.  **Risk:** None — purely mechanical.

---

### 2 — Six S3 XML responses bypass `xrootd_http_send_xml_buffer()`  ★★★ low effort

**What:** `xrootd_http_send_xml_buffer()` in `compat/http_xml.c` encapsulates the
10-line pattern of setting `content_type`, `content_length_n`, calling
`ngx_http_send_header()`, and returning `ngx_http_output_filter()`.  Six S3
response handlers inline this pattern instead of calling the shared function:

| File | What it sends | Note |
|---|---|---|
| `src/s3/multipart_initiate.c` | `<InitiateMultipartUploadResult>` | Also omits `content_type` — bug |
| `src/s3/copy.c` | `<CopyObjectResult>` | |
| `src/s3/multipart_complete_upload_part_copy.c` | `<CopyPartResult>` | |
| `src/s3/multipart_complete_list_parts.c` | `<ListPartsResult>` | |
| `src/s3/multipart_complete_list_uploads.c` | `<ListMultipartUploadsResult>` | |
| `src/s3/delete_objects.c` | `<DeleteResult>` | |

`multipart_initiate.c` is also missing the `content_type = "application/xml"`
assignment, so it sends the XML body with no Content-Type header.

**Change:** Replace each inline block with a call to `xrootd_http_send_xml_buffer()`.
For `multipart_initiate.c`, add the missing `content_type` at the same time.
Each site already has a filled `ngx_buf_t *b`, so the replacement is two lines.

```c
/* Before (multipart_initiate.c) */
r->headers_out.status           = NGX_HTTP_OK;
r->headers_out.content_length_n = (off_t) xml_len;
ngx_http_send_header(r);
return ngx_http_output_filter(r, &out);

/* After */
return xrootd_http_send_xml_buffer(r, NGX_HTTP_OK,
    (ngx_str_t) ngx_string("application/xml"), b);
```

Note: `delete_objects.c` wraps its `output_filter` call in
`s3_metrics_finalize_request_method()`; preserve that wrapper.

**Effort:** ~30 minutes.  **Risk:** None for five files; low for
`delete_objects.c` (preserve metrics wrapper).

---

### 3 — Stale `extern` declarations in `src/s3/list_objects_v2.c`  ★★★ trivial cleanup

**What:** Four hand-written `extern` declarations at the top of
`list_objects_v2.c` duplicate what should be in `s3.h`:

```c
/* src/s3/list_objects_v2.c lines 17–23 */
extern int entry_cmp(const void *a, const void *b);
extern int s3_walk(const char *root, ...);
extern int s3_get_arg(ngx_str_t args, ...);
extern void s3_xml_append_escaped(u_char *xml, ...);  /* never called */
```

`s3_get_arg()` is already declared in `s3.h:142`.  `entry_cmp` and `s3_walk`
are defined in `list_walk.c` but are not declared in any header — they should be
added to `s3.h` (or a new `list_walk_internal.h` shared between
`list_walk.c` and `list_objects_v2.c`).  `s3_xml_append_escaped` is declared
extern but never called — it is a dead declaration, a leftover from an older
version of the listing code.

**Change:**
1. Add `entry_cmp` and `s3_walk` declarations to `s3.h` (or a new
   `list_internal.h` included by both files).
2. Remove all four `extern` lines from `list_objects_v2.c`.
3. Remove the dead `s3_xml_append_escaped` declaration.

**Effort:** 10 minutes.  **Risk:** None.

---

### 4 — `s3_urldecode()` is a thin wrapper over `xrootd_http_urldecode()`  ★★ low effort

**What:** `src/s3/util.c` defines `s3_urldecode()` as a 10-line wrapper:

```c
ssize_t
s3_urldecode(const u_char *src, size_t slen, u_char *dst, size_t dsz)
{
    int rc = xrootd_http_urldecode(src, slen, (char *) dst, dsz,
                                    XROOTD_URLDECODE_PLUS_TO_SPACE |
                                    XROOTD_URLDECODE_REJECT_NUL);
    if (rc != XROOTD_URLDECODE_OK)
        return -1;
    return (ssize_t) strlen((char *) dst);
}
```

Three callers: `src/s3/handler.c:71`, `src/s3/auth_sigv4_canonical.c:106,122`,
`src/s3/auth_sigv4_parse.c:160`.  The only thing the wrapper adds is converting
the int return code to a `ssize_t` length.

This is a close parallel to `webdav_urldecode()` in
`src/webdav/util/uri.c`, which wraps the same compat function with a different
flag set (`REJECT_NUL` only, no `PLUS_TO_SPACE`) and maps return codes to
`NGX_HTTP_*` values.

**Change:** Replace `s3_urldecode()` with an inline call at each of the three
call sites, using the flags directly.  Remove the function and its declaration
from `s3.h`.  The three call sites are straightforward — each already checks the
`ssize_t` return for `< 0`.

**Consideration:** `webdav_urldecode()` cannot be unified with this because it
uses different flags and a different return convention (`NGX_HTTP_*` vs
`ssize_t`).  Both thin wrappers are legitimate protocol-specific adapters; the
question is whether the S3 wrapper adds enough value to justify a named function
(it does not — three call sites, zero added logic).

**Effort:** ~20 minutes.  **Risk:** None — mechanical substitution.

---

### 5 — `xrootd_log_safe_path()` should be in `compat/` — used by all three protocols  ★★ medium effort

**What:** All three protocols need to log filesystem paths safely — calling
`xrootd_sanitize_log_string()` before writing to `ngx_log_error`.

WebDAV centralised this in `src/webdav/util/logging.c`:

```c
void ngx_http_xrootd_webdav_log_safe_path(ngx_log_t *log, ngx_uint_t level,
    ngx_err_t err, const char *prefix, const char *path);
```

S3 inlines the two-step pattern at 11 call sites across
`src/s3/put.c`, `src/s3/copy.c`, `src/s3/multipart_initiate.c`, and
`src/s3/multipart_complete_body.c`.

The XRootD stream protocol inlines the pattern at 24 call sites across
`src/path/`, `src/read/`, `src/session/`, `src/dirlist/`, `src/auth/gsi/`, and
others.

The WebDAV helper itself uses a format string `"%s: \"%s\""` (prefix + quoted
path) that is suitable for error-log context.  The S3 and stream sites vary their
format strings, so a one-liner `ngx_log_error` with a sanitized variable is more
flexible than a fixed-format wrapper.

**Change:** Move the WebDAV helper to `src/core/compat/` as
`xrootd_log_safe_path()` with a more general signature:

```c
/* compat/log.c / log.h */
void xrootd_log_safe_path(ngx_log_t *log, ngx_uint_t level, ngx_err_t err,
    const char *fmt, const char *path);
```

The `fmt` parameter is a `printf`-style format containing exactly one `%s`
placeholder for the sanitized path (verified at compile time via a
`__attribute__((format(printf, 4, 0)))` annotation).

Update the 9 WebDAV call sites to use the renamed function.  Update the 11 S3
call sites where the pattern fits the `fmt + path` signature.  Stream sites where
the path appears mid-string (e.g. `"xrootd: kXR_open handle=%d path=%s mode=%s"`)
cannot use the single-path helper and must continue inlining.

**Effort:** ~1.5 hours.  **Risk:** Low — pure refactor, no logic change.

---

### 6 — Directory traversal: `list_walk.c` and `propfind.c` both open-code `opendir`/`readdir`  ★ medium effort, higher risk

**What:** `src/s3/list_walk.c` and `src/webdav/propfind.c` each contain their
own recursive `opendir`/`readdir` loops.  Neither uses `xrootd_fs_walk()` from
`compat/fs_walk.c`, though both include `fs_walk.h` for utility helpers.

| Location | Lines | Purpose |
|---|---|---|
| `src/s3/list_walk.c:70–170` | 100 lines | S3 ListObjectsV2 with prefix/delimiter filtering |
| `src/webdav/propfind.c:511–580` | 70 lines | PROPFIND Depth:1 enumeration |
| `src/webdav/propfind.c:643–680` | 40 lines | PROPFIND Depth:infinity recursive walk |

Both skip hidden/dot entries, build child paths via `snprintf`, call `stat()`, and
recurse into subdirectories.  `list_walk.c` uses `de->d_name[0] == '.'` for
dot-skip while `propfind.c` uses the shared `xrootd_fs_is_dot_entry()` — a minor
inconsistency that introduces a latent divergence.

`xrootd_fs_walk()` already handles the common structure (opendir, readdir, stat,
recurse, callback) but its callback signature (`xrootd_fs_walk_entry_t *entry,
void *data`) was designed for simple recursive removal; it does not carry the
S3-specific `key_prefix` / `filter_prefix` / `delimiter` state nor WebDAV's
`href` construction state.

**Change:** Extend `xrootd_fs_walk_entry_t` to carry a `rel_path` field (path
relative to the traversal root), which both callers need.  Convert `s3_walk()` to
use `xrootd_fs_walk()` with an S3-specific callback that performs
prefix/delimiter filtering and populates `s3_entry_t` entries.  Convert
`propfind_walk()` similarly with a WebDAV callback that builds `href` strings and
appends XML chain nodes.

Alternatively, keep the walkers as-is but fix the dot-skip inconsistency by
having `list_walk.c` call `xrootd_fs_is_dot_entry()` instead of the open-coded
character check.

**Effort:** 3–4 hours for full consolidation; 15 minutes for dot-skip fix only.
**Risk:** Medium — both walkers have specific filtering semantics.  Test coverage
(S3 list tests, WebDAV PROPFIND tests) must pass before merging.

The dot-skip consistency fix is safe and should be done regardless.

---

### 7 — `s3_xml_append_text_element()` duplicates the `xrootd_xml_write_text_element()` interface  ★ low effort

**What:** `src/s3/util.c` defines a 12-line wrapper:

```c
ngx_int_t
s3_xml_append_text_element(u_char *xml, size_t xml_capacity, size_t *xml_len,
    const char *name, const u_char *value, size_t value_len)
{
    size_t available = xml_capacity - *xml_len;
    xrootd_xml_write_text_element(name, value, value_len,
        XROOTD_XML_ESCAPE_APOS_ENTITY, xml + *xml_len, available, &written);
    *xml_len += written;
    return NGX_OK / NGX_ERROR;
}
```

This exists to adapt the compat function's `(out, available, &written)` calling
convention to the S3 flat-buffer convention `(xml, xml_capacity, &xml_len)`.

The three call sites are exclusively inside the `XML_APPEND_ELEM` macro (Item 1).
If Items 1 and 2 are implemented first (macro moved to `s3.h`, inline XML
responses replaced by `xrootd_http_send_xml_buffer`), this wrapper may be
replaceable by a macro that calls `xrootd_xml_write_text_element` directly.

**Change:** After Items 1 and 2 are complete, update `XML_APPEND_ELEM` in `s3.h`
to call `xrootd_xml_write_text_element` directly (adjusting the available/written
arithmetic inline in the macro).  Remove `s3_xml_append_text_element` and its
`s3.h` declaration.

**Effort:** ~30 minutes.  **Risk:** Low — completely covered by the XML response
test suite.  Dependency: Items 1 and 2 must land first.

---

## Items deliberately excluded

| Candidate | Reason |
|---|---|
| S3 SigV4 auth vs WebDAV JWT auth | Entirely different schemes; no shared logic |
| S3 XML error response vs WebDAV error response | S3 API requires XML errors; WebDAV uses HTTP status codes only — no protocol-appropriate unification |
| CORS headers (WebDAV only) | S3 has no CORS config; nothing to share |
| `s3_xml_escape()` wrapper | 5-line passthrough around `xrootd_xml_escape()`; callers inside the module are few and could call compat directly, but the wrapper adds a nil maintenance burden |
| `webdav_urldecode()` and `s3_urldecode()` unification | Different flag sets and return conventions; each is a correct protocol-specific adapter |
| S3 metrics `bytes_tx_total` not tracked in multipart files | Inconsistency, not shared-code issue; fix in a separate metrics audit |
| Multipart upload state → common struct | Parts list and upload list structs (`mpu_part_entry_t`, `mpu_upload_entry_t`) are not shared — different shapes, different callers |

---

## Implementation order

| Phase | Items | Dependency |
|---|---|---|
| **A** | 1, 2, 3 | None — each is independent; 3 is pure cleanup |
| **B** | 4, 5 | None — independent of A |
| **C** | 6 (dot-skip only) | None — 15-minute safety fix |
| **D** | 7 | Items 1 and 2 must land first |
| **E** | 6 (full walk consolidation) | Requires PROPFIND and S3 list test suites to pass |

Phase A items are single-commit and reviewable in minutes.  Phase B items each
warrant a PR with a `make` + full test suite run.  Phase E is optional — the
dot-skip fix in Phase C delivers the safety benefit at low risk; full walk
consolidation is worthwhile but not urgent.
