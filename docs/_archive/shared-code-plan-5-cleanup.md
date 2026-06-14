# Shared-Code Plan 5 — Cleanup Supplement (May 2026)

This document is a companion to `shared-code-plan-5.md`, which covers large
architectural opportunities (protocol-neutral result objects, shared object-response
builder, namespace scan engine, access/write admission policy, write pipeline,
identity/audit context).  That plan requires significant design work and staged
migration.

This supplement covers smaller, lower-risk items surfaced during the Plan 4 audit
cycle that are actionable immediately without touching cross-protocol architecture.
Each item stands alone.

---

## Context: what the prior plans already cover

| Plans 1–4 | Done |
|---|---|
| URL encode/decode | `compat/uri.c` |
| Path confinement | `compat/path.c` |
| ETag, Range, Conditionals | `compat/etag/range/http_conditionals.c` |
| Staged writes, body→fd | `compat/staged_file.c`, `compat/http_body.c` |
| XML escape/send, crypto, hex, ISO8601 | `compat/xml/http_xml/crypto/hex/time.c` |
| errno→HTTP/kXR, safe log, query parsing | `compat/http_errno/kxr_errno/log/http_query.c` |
| File-response headers + sendfile | `compat/http_file_response.c` |
| `XML_APPEND`/`XML_APPEND_ELEM` in `s3.h` | — |
| `s3_urldecode`, stale S3 externs, dot-skip | removed / fixed in Plans 3–4 |

---

## Item 1 — `s3_xml_escape()` and `s3_xml_append_escaped()` are dead code  ★★★ trivial

**Files:** `src/s3/util.c:109–123`, `src/s3/list_query_helpers.c:40–56`, `src/s3/s3.h:228`

**What:** Both functions were made obsolete when `XML_APPEND_ELEM` was added to `s3.h`.
Neither has any live callers:

```
s3_xml_append_escaped()  ← defined in list_query_helpers.c, no external declaration, no callers
s3_xml_escape()          ← declared in s3.h:228, only caller is s3_xml_append_escaped()
```

Confirmed with `grep -rn "s3_xml_escape\b" src/s3/` — the only appearances are the
declaration in `s3.h`, the definition in `util.c`, and the single call inside
`s3_xml_append_escaped()` itself.

**Change:**
1. Remove `s3_xml_escape()` body from `src/s3/util.c`.
2. Remove `void s3_xml_escape(...)` declaration from `src/s3/s3.h:228`.
3. Remove `s3_xml_append_escaped()` body from `src/s3/list_query_helpers.c`.

**Effort:** 10 min.  **Risk:** None.

---

## Item 2 — `webdav/headers.c` contains two 1-line delegates  ★★★ trivial

**Files:** `src/webdav/headers.c` (entire file, 66 lines), `src/webdav/webdav.h`

**What:** The file exports exactly two functions, each a single-line call to a compat
helper with fixed ETag-flag arguments:

```c
/* headers.c */
void webdav_etag_str(char *buf, size_t bufsz, time_t mtime, off_t size)
    { xrootd_http_etag_str(buf, bufsz, mtime, size, XROOTD_ETAG_WEAK); }

ngx_int_t webdav_add_etag(ngx_http_request_t *r, time_t mtime, off_t size)
    { return xrootd_http_add_etag_header(r, mtime, size, XROOTD_ETAG_WEAK, 1); }
```

Three call sites in total:
- `src/webdav/get.c:175` — `webdav_add_etag(r, sb.st_mtime, sb.st_size)`
- `src/webdav/methods_basic.c:104` — `webdav_add_etag(r, sb.st_mtime, sb.st_size)`
- `src/webdav/propfind.c:345` — `webdav_etag_str(etag_buf, sizeof(etag_buf), ...)`

**Change:**
1. Replace each call site with the direct compat call and explicit `XROOTD_ETAG_WEAK`:
   ```c
   /* get.c / methods_basic.c */
   xrootd_http_add_etag_header(r, sb.st_mtime, sb.st_size, XROOTD_ETAG_WEAK, 1);
   /* propfind.c */
   xrootd_http_etag_str(etag_buf, sizeof(etag_buf), sb->st_mtime, sb->st_size,
                        XROOTD_ETAG_WEAK);
   ```
2. Remove both declarations from `webdav.h`.
3. Delete `src/webdav/headers.c`; remove from `config`.

**Effort:** 20 min.  **Risk:** None.

---

## Item 3 — `s3_get_arg()` wrapper and an empty `list_query_helpers.c`  ★★ low effort

**Files:** `src/s3/list_query_helpers.c`, `src/s3/s3.h`, `src/s3/list_objects_v2.c:68–84`

**What:** After Item 1, `list_query_helpers.c` holds only `s3_get_arg()` — an 8-line
delegate over `xrootd_http_query_get()` with a specific four-flag combination:

```c
int s3_get_arg(ngx_str_t args, const char *name, u_char *buf, size_t bufsz)
{
    return xrootd_http_query_get(args, name, (char *) buf, bufsz,
                                 XROOTD_HTTP_QUERY_DECODE_VALUE
                                 | XROOTD_HTTP_QUERY_PLUS_TO_SPACE
                                 | XROOTD_HTTP_QUERY_REJECT_NUL
                                 | XROOTD_HTTP_QUERY_ALLOW_EMPTY) > 0;
}
```

Six call sites, all in `list_objects_v2.c`.  No other file calls it.

Note: `s3_get_query_param()` in `multipart_helpers.c` uses a *different* flag set
(`DECODE_VALUE | REJECT_NUL`, no `PLUS_TO_SPACE`, no `ALLOW_EMPTY`) — it is a distinct
correct adapter and stays.

**Change:**
1. Define the flag combination once at the top of `list_objects_v2.c`:
   ```c
   /* S3 list params: URL-decode, + → space, reject NUL, allow empty delimiter. */
   #define S3_LIST_QUERY_FLAGS \
       (XROOTD_HTTP_QUERY_DECODE_VALUE | XROOTD_HTTP_QUERY_PLUS_TO_SPACE \
        | XROOTD_HTTP_QUERY_REJECT_NUL | XROOTD_HTTP_QUERY_ALLOW_EMPTY)
   ```
2. Replace each `s3_get_arg(r->args, "…", buf, sz)` call with
   `xrootd_http_query_get(r->args, "…", (char *) buf, sz, S3_LIST_QUERY_FLAGS) > 0`.
3. Remove `s3_get_arg` declaration from `s3.h`.
4. Delete `src/s3/list_query_helpers.c`; remove from `config`.

**Effort:** 30 min.  **Risk:** None — mechanical substitution.

---

## Item 4 — "set response headers from stat" block duplicated in three handlers  ★★ medium effort

**Files:** `src/s3/object.c` (`s3_handle_get`, `s3_handle_head`), `src/webdav/get.c`

**What:** All three handlers execute the same five-header block after opening and
stat-ing a file:

```c
/* ── identical in all three (~15 lines each) ── */
r->headers_out.status             = has_range ? NGX_HTTP_PARTIAL_CONTENT : NGX_HTTP_OK;
r->headers_out.content_length_n   = send_len;
r->headers_out.last_modified_time = sb.st_mtime;
xrootd_http_set_header(r, "Content-Type", "application/octet-stream", NULL);
xrootd_http_add_etag_header(r, mtime, size, etag_flags, 0);
if (has_range)
    xrootd_http_add_content_range_header(r, start, end, size);
```

The only varying inputs: `etag_flags` (0 for S3, `XROOTD_ETAG_WEAK` for WebDAV),
`has_range`, `range_start`, `range_end`.

**Change:** Add to `src/compat/http_file_response.c/h`:

```c
/*
 * xrootd_http_set_file_headers — fill status, content-length, last-modified,
 * Content-Type, ETag, and optionally Content-Range from a file stat result.
 *
 * etag_flags: 0 (S3 strong) or XROOTD_ETAG_WEAK (WebDAV).
 * content_type: must be a string literal or pool-allocated value.
 * has_range/range_start/range_end: ignored when has_range == 0.
 */
ngx_int_t xrootd_http_set_file_headers(ngx_http_request_t *r,
    time_t mtime, off_t total_size, off_t send_len,
    const char *content_type, unsigned etag_flags,
    int has_range, off_t range_start, off_t range_end);
```

Replace the three duplicated blocks with one call each.

**Effort:** ~1 hr.  **Risk:** Low — encapsulates existing compat calls; all three paths
are exercised by the existing GET/HEAD test suite.

---

## Item 5 — S3 PUT blocks the nginx event loop on large uploads  ★★ correctness

**Files:** `src/s3/put.c`, reference: `src/webdav/put.c`

**What:** `src/s3/put.c` writes the uploaded body synchronously on the nginx worker
thread.  For large HEP objects (GiB range), this blocks the event loop and stalls all
other connections on that worker for the duration of the write syscall.

`src/webdav/put.c` solves this with a well-tested `#if (NGX_THREADS)` block that
dispatches to nginx's thread pool via `ngx_thread_task_alloc / ngx_thread_task_post`.

This is a **latency correctness** issue, not merely style: a single large S3 PUT from
XrdClS3 will freeze all concurrent WebDAV, S3, and stream connections on that worker.

**Change:** Port the thread-pool write path from `webdav/put.c` to `s3/put.c`:

```c
/* s3/put.c — mirror the webdav/put.c thread-pool pattern */
#if (NGX_THREADS)
typedef struct {
    ngx_http_request_t  *r;
    ngx_fd_t             fd;
    const u_char        *data;
    size_t               len;
    off_t                offset;
    ssize_t              nwritten;
    int                  io_errno;
    ngx_uint_t           method_slot;
    char                 path[PATH_MAX];
} s3_put_aio_t;

static void s3_put_aio_thread(void *data, ngx_log_t *log);
static void s3_put_aio_done(ngx_event_t *ev);
#endif
```

The `s3_put_aio_done` callback calls `s3_metrics_finalize_request_method()` instead of
`webdav_metrics_finalize_request()`.  The synchronous fallback (`#else` path) is left in
place for builds without `--with-threads`.

**Tests required:**
- Large PUT (> nginx worker buffer) completes correctly.
- PUT failure (disk full simulation) propagates 500 through the async callback.
- Concurrent GET request on same worker is not stalled during PUT write.

**Effort:** ~2 hr.  **Risk:** Medium — async fd lifecycle and error paths need coverage.

---

## Item 6 — S3 MPU staging `lstat()` bypasses confinement invariant  ★ documentation

**Files:** `src/s3/multipart_abort.c`, `multipart_complete_body.c`,
`multipart_complete_list_parts.c`, `multipart_complete_list_uploads.c`,
`multipart_complete_upload_part_copy.c`

**What:** Seven `lstat()`/`stat()` calls in the S3 multipart upload handlers operate on
server-generated paths directly, bypassing `xrootd_open_confined_canon()`.  There is
no security gap — the paths come from `s3_get_mpu_dir()` which formats
`<root>/.<key>.mpu-<upload_id>` from already-confined values — but the deviation from
the module-wide "all filesystem ops through confined helpers" invariant is confusing.

**Change (minimal):** Add a confinement comment above each group of bare
`lstat()`/`stat()` calls in the five affected files:

```c
/*
 * Confinement: mpu_dir is generated by s3_get_mpu_dir() from a validated
 * upload_id (mpu_validate_upload_id) and an fs_path confined by s3_resolve_key().
 * The staging dir is always a direct child of cf->root_canon; bare lstat is safe.
 */
```

**Optional:** Convert to `fstatat(dirfd, name, &sb, AT_SYMLINK_NOFOLLOW)` using a
parent dirfd opened via `xrootd_open_confined_canon()`, making confinement explicit at
the syscall boundary.

**Effort:** 20 min (comments only); ~2 hr (fstatat conversion with MPU path tests).

---

## nginx built-in feature audit

Full audit is in `shared-code-plan-5.md` §8 and is not repeated here.

The single actionable gap found in that audit is **Item 5** above (S3 PUT
thread pool).  Every other nginx feature is either correctly delegated, intentionally
bypassed with documented rationale, or not applicable to this workload.

---

## Deliberate non-items

| Candidate | Reason kept |
|---|---|
| `webdav_urldecode()` (`util/uri.c`) | Maps `XROOTD_URLDECODE_*` codes to `NGX_HTTP_*` — correct protocol-specific adapter |
| `webdav_escape_xml_text()` (`util/xml.c`) | Adds pool allocation to compat escape — genuine glue, not redundant |
| `s3_get_query_param()` (`multipart_helpers.c`) | Different flag set from `s3_get_arg`; each is correct for its call sites |
| `webdav_destination_extract_path()` (`util/uri.c`) | WebDAV COPY/MOVE–specific; no S3 equivalent |
| S3 `open_file_cache` | XrdClS3 access pattern is write-once; cache adds config complexity for negligible benefit |
| Full walker consolidation (Plan 4 Item 6) | Valid but deferred; requires extended `xrootd_fs_walk_entry_t` callback API |

---

## Implementation order

| Phase | Item | Dependency | Estimate |
|---|---|---|---|
| **A** | 1 — dead `s3_xml_escape` / `s3_xml_append_escaped` | None | 10 min |
| **B** | 2 — collapse `webdav/headers.c` | None | 20 min |
| **C** | 3 — remove `s3_get_arg`, delete `list_query_helpers.c` | Item 1 same file | 30 min |
| **D** | 6 — MPU unconfined lstat comments | None | 20 min |
| **E** | 4 — `xrootd_http_set_file_headers()` helper | None | ~1 hr |
| **F** | 5 — S3 PUT thread pool | None | ~2 hr |

Phases A–D are trivial, low-risk, and can ship together in a single commit.
Phase E and F each warrant their own commit with `make` + full test suite validation.

**Total:** Phases A–D ≈ 1.5 hours.  All phases ≈ 4–5 hours.

---

## Relationship to Plan 5

`shared-code-plan-5.md` targets higher-level consolidation (result objects, resource
metadata snapshot, shared object-response builder, access/write admission, write
pipeline, namespace scan engine, identity/audit context).  That work requires design
effort and careful staged migration.

This document covers the quick-win layer that should be done *before* or *in parallel
with* the larger plan, since it reduces the noise that would otherwise complicate
the bigger refactors.  Item 5 here (S3 PUT thread pool) directly enables Plan 5's
Opportunity 6 (Shared HTTP Write Pipeline) to start from a correct async baseline.
