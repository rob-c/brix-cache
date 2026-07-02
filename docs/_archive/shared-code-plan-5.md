# Shared-Code Plan 5: Protocol Surface Unification

Date: 2026-05-22

This plan looks for the next useful layer of sharing between the native
`root://` stream protocol, WebDAV, XrdHttp, and S3. It deliberately builds on
`shared-code-plan-4.md` instead of repeating it. Plan 4 focuses on mechanical
helper cleanup such as XML helpers, safe logging, and S3/WebDAV directory-walk
duplication. This plan focuses on higher-level behavior that still repeats
across protocol surfaces.

The main goal is not maximum line-count reduction. The real goal is one
security and policy decision per concept, then small protocol-specific adapters
for the wire format.

## Current Baseline

Already shared and not re-planned here:

| Area | Existing shared code |
|---|---|
| Path confinement | `src/core/compat/path.c`, `src/path/*` |
| Checksums and digests | `src/core/compat/checksum.c`, `src/core/compat/crc32c.c` |
| HTTP range/ETag/body/query/XML helpers | `src/core/compat/http_*.c`, `src/core/compat/etag.c`, `src/core/compat/xml.c` |
| Staged file lifecycle | `src/core/compat/staged_file.c` |
| POSIX errno mapping | `src/core/compat/http_errno.c`, `src/core/compat/kxr_errno.c` |
| Directory utility pieces | `src/core/compat/fs_walk.c` |
| Token parsing and scope checks | `src/auth/token/*` |
| Metrics storage and status classes | `src/observability/metrics/*` |

XrdHttp is implemented as an extension layer inside the WebDAV HTTP module
(`src/protocols/webdav/xrdhttp.c`), so this plan treats it as a protocol dialect sharing
the WebDAV dispatch path, not as a fourth independent nginx module.

## Do Not Unify

These areas should stay protocol-specific:

| Area | Reason |
|---|---|
| S3 SigV4 and WebDAV bearer/GSI auth | Different trust model, canonicalization, and error vocabulary |
| S3 XML errors and WebDAV status-only errors | Client APIs expect different response bodies |
| WebDAV locks | RFC 4918-specific behavior with no S3 or native XRootD equivalent |
| XrdHttp `X-Xrootd-*` headers | Compatibility dialect for XRootD-aware HTTP clients |
| Native XRootD frame emission | The binary stream framing is intentionally separate from HTTP chain output |

The right shape is usually: shared decision or metadata struct, then
protocol-specific response emission.

## Opportunity 1: Protocol-Neutral Result Object

### Problem

The codebase already has `errno -> HTTP` and `errno -> kXR` maps, but many
handlers still translate failures independently:

| Surface | Examples |
|---|---|
| Native stream | `xrootd_send_error()`, `XROOTD_RETURN_ERR(...)`, `xrootd_kxr_from_errno()` |
| WebDAV | direct `NGX_HTTP_*` returns plus XrdHttp `xrdhttp_http_to_xrd_status()` |
| S3 | `s3_send_xml_error()` with S3-specific error strings |
| XrdHttp | HTTP status is converted again to `X-Xrootd-Status` |

This creates several places where the same semantic failure can drift:
not found, denied, read-only, locked, conflict, invalid path, no space, and
unsupported operation.

### Plan

Add `src/core/compat/result.h` and `src/core/compat/result.c`:

```c
typedef enum {
    XROOTD_RESULT_OK = 0,
    XROOTD_RESULT_NOT_FOUND,
    XROOTD_RESULT_DENIED,
    XROOTD_RESULT_READ_ONLY,
    XROOTD_RESULT_LOCKED,
    XROOTD_RESULT_CONFLICT,
    XROOTD_RESULT_INVALID,
    XROOTD_RESULT_TOO_LONG,
    XROOTD_RESULT_NO_SPACE,
    XROOTD_RESULT_NO_MEMORY,
    XROOTD_RESULT_UNSUPPORTED,
    XROOTD_RESULT_IO_ERROR,
    XROOTD_RESULT_INTERNAL
} xrootd_result_code_t;

typedef struct {
    xrootd_result_code_t code;
    int                  sys_errno;
    ngx_uint_t           http_status;
    uint16_t             kxr_status;
    const char          *s3_code;
    const char          *message;
} xrootd_result_t;
```

Expose constructors:

```c
xrootd_result_t xrootd_result_from_errno(int err);
xrootd_result_t xrootd_result_make(xrootd_result_code_t code,
    const char *message);
```

Keep final emission protocol-specific:

| Protocol | Adapter |
|---|---|
| Native stream | `xrootd_send_result(ctx, c, result)` |
| WebDAV | `xrootd_http_return_result(r, result)` |
| XrdHttp | keep `X-Xrootd-Status`, but derive from result |
| S3 | `s3_send_result(r, result)` mapping to XML error code |

### First Migration Targets

1. `src/protocols/s3/object.c`: open/fstat/not-dir failures.
2. `src/protocols/webdav/get.c`: cached-open and range failure handling.
3. `src/protocols/webdav/xrdhttp.c`: replace its local HTTP-to-kXR switch with the shared result map.
4. `src/read/stat.c`: path-based stat failure mapping only.

### Tests

Add table-driven tests that assert:

| Case | Expected |
|---|---|
| `ENOENT` | HTTP 404, kXR `NotFound`, S3 `NoSuchKey` for object paths |
| `EACCES` | HTTP 403, kXR `NotAuthorized`, S3 `AccessDenied` |
| `ENOSPC` | HTTP 507, kXR `NoSpace`, S3 `InternalError` or explicit storage-full mapping |
| read-only write gate | HTTP 403, kXR `fsReadOnly`, S3 `AccessDenied` |

### Estimate

Adds about 150-220 lines initially. Removes about 250-450 lines after the first
four migration targets. Net reduction: 100-230 lines, plus a single error policy
surface.

## Opportunity 2: Shared HTTP Request/Metric Finalization

### Problem

`src/protocols/webdav/metrics.c` and `src/protocols/s3/metrics.c` both implement the same response
status extraction pattern:

1. Ignore `NGX_DONE`.
2. Convert `NGX_ERROR` to 500.
3. Use explicit `NGX_HTTP_*` return codes.
4. Fall back to `r->headers_out.status`.
5. Default to 200.
6. Bucket into a status class.

Only the method enum and counter arrays differ.

`src/protocols/webdav/xrdhttp.c` also has local `add_header_str()` and `add_header_num()`
helpers even though `src/core/compat/http_headers.c` already owns most response
header insertion.

### Plan

Extend shared HTTP helpers:

| New helper | Purpose |
|---|---|
| `xrootd_http_effective_status(r, rc)` | One canonical handler-return-code to HTTP-status conversion |
| `xrootd_http_set_header_num(r, key, long value)` | Remove XrdHttp numeric-header helper |
| `xrootd_http_method_name(r, out)` | Optional shared method string extraction for logs/tests |

Keep protocol-specific method slot classification in WebDAV and S3, because
their Prometheus label sets are intentionally different.

### First Migration Targets

1. Replace status extraction in `webdav_metrics_response()`.
2. Replace status extraction in `s3_metrics_response_method()`.
3. Replace XrdHttp `add_header_str()` with `xrootd_http_set_header()`.
4. Replace XrdHttp `add_header_num()` with `xrootd_http_set_header_num()`.

### Tests

Add or extend metrics tests:

| Case | Expected |
|---|---|
| handler returns `NGX_DONE` | response metric is not incremented |
| handler returns `NGX_ERROR` | 5xx bucket |
| handler sets `headers_out.status = 204` and returns `NGX_OK` | 2xx bucket |

### Estimate

Adds about 60-100 lines. Removes about 120-220 lines. Net reduction: 60-120
lines.

## Opportunity 3: Resource Metadata Snapshot

### Problem

The same `stat` tuple is repeatedly converted into protocol-specific metadata:

| Surface | Files |
|---|---|
| WebDAV HEAD/GET/PROPFIND | `src/protocols/webdav/resource.c`, `methods_basic.c`, `get.c`, `propfind.c` |
| S3 GET/HEAD/ListObjectsV2 | `src/protocols/s3/object.c`, `src/protocols/s3/list_walk.c`, `src/protocols/s3/util.c` |
| Native stat/statx/dirlist | `src/read/stat.c`, `src/read/statx.c`, `src/dirlist/handler.c` |
| XrdHttp Digest/headers | `src/protocols/webdav/xrdhttp.c`, `src/protocols/webdav/get.c` |

Each surface asks the same questions:

| Question | Current repeated logic |
|---|---|
| Is this a directory? | `S_ISDIR(st.st_mode)` |
| Is this a regular file? | `S_ISREG(st.st_mode)` |
| What size should HTTP expose? | files use `st_size`, dirs often zero |
| What mtime is exposed? | `st_mtime` |
| What ETag should HTTP/S3 expose? | `mtime-size`, weak for WebDAV |
| What XRootD stat body should be emitted? | `xrootd_make_stat_body()` |

### Plan

Add `src/core/compat/resource_info.h` and `src/core/compat/resource_info.c`:

```c
typedef struct {
    struct stat st;
    ngx_flag_t  exists;
    ngx_flag_t  is_dir;
    ngx_flag_t  is_reg;
    off_t       content_length;
    time_t      mtime;
} xrootd_resource_info_t;

void xrootd_resource_info_from_stat(const struct stat *st,
    xrootd_resource_info_t *info);

ngx_int_t xrootd_resource_info_stat(const char *path,
    xrootd_resource_info_t *info);

ngx_int_t xrootd_resource_info_fstat(ngx_fd_t fd,
    xrootd_resource_info_t *info);
```

Keep wire serialization separate:

| Serializer | Stays where |
|---|---|
| XRootD stat body | `src/path/stat_body.c` |
| WebDAV PROPFIND XML | `src/protocols/webdav/propfind.c` |
| S3 XML listing entry | `src/protocols/s3/list_objects_v2.c` |
| HTTP ETag header | `src/core/compat/http_file_response.c` |

The shared struct should stop repeated `stat` interpretation without hiding the
protocol differences.

### First Migration Targets

1. `src/protocols/s3/object.c`: GET/HEAD fstat handling.
2. `src/protocols/webdav/methods_basic.c`: HEAD handling.
3. `src/protocols/webdav/get.c`: metadata and range setup.
4. `src/read/statx.c`: convert host stat to info before formatting.

### Tests

| Case | Expected |
|---|---|
| regular file | size, mtime, `is_reg` true |
| directory | content length zero for HTTP adapter, `is_dir` true |
| missing path | result maps to not found |

### Estimate

Adds about 120-180 lines. Removes about 200-350 lines after migration. Net
reduction: 80-170 lines.

## Opportunity 4: HTTP Object Response Builder

### Problem

`src/core/compat/http_file_response.c` already shares file-backed sendfile output,
ETag, and Content-Range header construction. WebDAV GET, XrdHttp GET, and S3
GET still duplicate the orchestration around it:

1. Open or cached-open fd.
2. Reject directories.
3. Parse `Range`.
4. Map unsatisfied range.
5. Set `Content-Type`.
6. Set length, mtime, ETag.
7. Add optional XrdHttp `Digest`.
8. Emit file-backed buffer.
9. Account bytes.

### Plan

Add a higher-level helper above `xrootd_http_send_file_range()`:

```c
typedef struct {
    ngx_flag_t close_fd;
    ngx_flag_t weak_etag;
    ngx_flag_t register_etag;
    ngx_flag_t allow_range;
    ngx_flag_t add_digest;
    const char *content_type;
} xrootd_http_object_response_opts_t;

ngx_int_t xrootd_http_send_object_response(ngx_http_request_t *r,
    ngx_fd_t fd, const char *path, const xrootd_resource_info_t *info,
    const xrootd_http_object_response_opts_t *opts,
    off_t *bytes_sent);
```

Keep these as protocol callbacks or wrapper responsibilities:

| Item | Reason |
|---|---|
| WebDAV fd-cache ownership | WebDAV-specific cache integration |
| S3 XML error body on missing key | S3-specific API contract |
| XrdHttp `Digest` computation policy | XrdHttp compatibility behavior |
| Metrics increment | Protocol-specific metric arrays |

### First Migration Targets

1. Move the common range/header/send path from `src/protocols/s3/object.c`.
2. Move the common range/header/send path from `src/protocols/webdav/get.c`.
3. Let XrdHttp pass a digest callback or keep one wrapper around the shared send.

### Tests

| Case | Expected |
|---|---|
| full GET | 200, length, ETag, body bytes |
| single range | 206, Content-Range, partial bytes |
| unsatisfied range | 416 and no body |
| HEAD | headers only, no body bytes metric |
| XrdHttp checksum request | Digest header preserved |

### Estimate

Adds about 140-220 lines. Removes about 220-380 lines. Net reduction:
80-160 lines.

## Opportunity 5: Shared Access and Write Admission

### Problem

The same policy pattern appears in several shapes:

| Surface | Current shape |
|---|---|
| Native stream | `xrootd_dispatch_require_write()`, `xrootd_check_token_scope()`, authdb, VO ACL |
| WebDAV | `access.c` write-method gate, token write-scope gate, lock prechecks |
| S3 | `handler.c` repeats `allow_write` checks for POST/PUT/DELETE |
| XrdHttp | inherits WebDAV but injects TPC and response headers |

Some parts must remain protocol-specific, especially WebDAV locks and S3 SigV4.
But the common concepts can be named once:

| Concept | Common meaning |
|---|---|
| read lookup | metadata/list/read permitted |
| create | may create a new object |
| modify | may overwrite/truncate/chmod/write |
| delete | may remove an object |
| read-only endpoint | global write gate rejects mutation |

### Plan

Add `src/core/compat/access_policy.h` with protocol-neutral operation names:

```c
typedef enum {
    XROOTD_ACCESS_READ,
    XROOTD_ACCESS_LIST,
    XROOTD_ACCESS_CREATE,
    XROOTD_ACCESS_MODIFY,
    XROOTD_ACCESS_DELETE,
    XROOTD_ACCESS_STAGE
} xrootd_access_op_t;

ngx_flag_t xrootd_access_op_is_write(xrootd_access_op_t op);
ngx_flag_t xrootd_access_op_needs_existing_path(xrootd_access_op_t op);
ngx_flag_t xrootd_access_op_needs_write_scope(xrootd_access_op_t op);
```

Then add adapters:

| Adapter | Responsibility |
|---|---|
| `xrootd_stream_check_access(...)` | authdb, VO ACL, token scope, kXR result |
| `xrootd_webdav_check_access(...)` | allow-write, token scope, optional lock hook, HTTP result |
| `xrootd_s3_check_write_enabled(...)` | single write-disabled check and XML result |

Do not put WebDAV locks or S3 SigV4 inside the common helper. Instead, expose
hooks so the protocol handler can run its own extra checks after the shared
decision passes.

### First Migration Targets

1. Replace S3's four repeated `!cf->allow_write` blocks with one helper.
2. Replace WebDAV `webdav_is_write_method()` and `webdav_scope_method_name()`
   with `xrootd_access_op_t` mapping.
3. Replace native `xrootd_check_token_scope(ctx, path, 0/1)` calls gradually
   with an access-op wrapper.

### Tests

Every migrated operation needs:

| Test | Example |
|---|---|
| success | PUT/MKCOL/write succeeds when write is enabled and scope matches |
| error | read-only endpoint rejects write |
| security negative | token with read-only scope cannot mutate matching path |

### Estimate

Adds about 220-330 lines. Removes about 350-650 lines after broad migration.
Net reduction: 130-320 lines. The security benefit is larger than the line
count reduction.

## Opportunity 6: Shared HTTP Write Pipeline

### Problem

WebDAV PUT and S3 PUT both consume an nginx request body and write a filesystem
object, but their finalization differs:

| Surface | Current behavior |
|---|---|
| WebDAV PUT | opens final path with `O_TRUNC`, writes body, returns 201/204 |
| S3 PUT | writes staged temp file, commits rename, returns 200 and ETag |
| XrdHttp PUT | follows WebDAV path with XrdHttp request/response additions |

The shared body helper already exists: `xrootd_http_body_write_to_fd()`.
The staged file helper already exists: `xrootd_staged_open/commit/abort()`.
The orchestration is still duplicated and WebDAV's direct truncate path has a
larger partial-write failure surface than S3's staged path.

### Plan

Add `src/core/compat/http_object_write.h`:

```c
typedef struct {
    ngx_flag_t use_staging;
    ngx_flag_t create_parents;
    ngx_flag_t return_etag;
    ngx_uint_t created_status;
    ngx_uint_t replaced_status;
    mode_t     file_mode;
} xrootd_http_object_write_opts_t;

ngx_int_t xrootd_http_write_object_body(ngx_http_request_t *r,
    const char *root_canon, const char *path,
    const xrootd_http_object_write_opts_t *opts,
    xrootd_http_body_summary_t *summary,
    ngx_flag_t *created);
```

Protocol wrappers still decide:

| Decision | Owner |
|---|---|
| WebDAV conditional headers | WebDAV |
| S3 directory sentinels | S3 |
| S3 ETag response | S3 wrapper or option |
| Metrics and final status | Protocol wrapper |

### Migration Order

1. Move S3 normal PUT body write to the helper first. This should be mostly
   mechanical because it already uses staged files.
2. Add an opt-in WebDAV staged PUT mode behind the same helper.
3. After tests prove compatibility, make staged WebDAV PUT the default.

### Tests

| Test | Expected |
|---|---|
| S3 normal PUT | object exists, body matches, ETag present |
| S3 sentinel PUT | directory behavior unchanged |
| WebDAV PUT create | 201 and body persisted |
| WebDAV PUT replace | 204 and body replaced |
| failed body write | final path is not partially replaced when staging is enabled |

### Estimate

Adds about 160-260 lines. Removes about 200-360 lines. Net reduction:
40-100 lines initially, 100-220 after WebDAV staging migration. It also reduces
partial-write risk.

## Opportunity 7: Namespace Scan and Listing Engine

### Problem

Directory enumeration is still fragmented:

| Surface | Files |
|---|---|
| Native `kXR_dirlist` | `src/dirlist/handler.c` |
| Native `kXR_Qckscan` | `src/query/checksum_ckscan_common.c` |
| WebDAV PROPFIND | `src/protocols/webdav/propfind.c` |
| S3 ListObjectsV2 | `src/protocols/s3/list_walk.c`, `src/protocols/s3/list_objects_v2.c` |

`src/core/compat/fs_walk.c` provides a recursive callback walk, but it does not yet
carry all information needed by every serializer:

| Needed field | Why |
|---|---|
| relative path from scan root | S3 keys and Qckscan logical paths |
| parent fd or `dirfd` | safer `fstatat`/checksum open for dirlist |
| depth and entry count caps | PROPFIND infinity and Qckscan protection |
| hidden-entry policy | WebDAV and S3 skip hidden entries differently |
| unsafe-name policy | native dirlist cannot emit control characters |

### Plan

Add a higher-level scan engine rather than stretching `fs_walk.c` too far:

```c
typedef struct {
    const char *resolved_path;
    const char *relative_path;
    const char *name;
    const struct stat *st;
    int         parent_fd;
    ngx_uint_t  depth;
} xrootd_ns_scan_entry_t;

typedef struct {
    ngx_uint_t max_depth;
    ngx_uint_t max_entries;
    ngx_flag_t include_files;
    ngx_flag_t include_dirs;
    ngx_flag_t skip_hidden;
    ngx_flag_t reject_control_names;
    ngx_flag_t use_openat;
} xrootd_ns_scan_options_t;
```

Each protocol supplies a serializer callback:

| Protocol | Serializer callback |
|---|---|
| Native dirlist | append newline entry, optional stat/checksum |
| Qckscan | append `algo hex logical_path` |
| WebDAV PROPFIND | append one `<D:response>` chain |
| S3 ListObjectsV2 | collect object or common-prefix entry |

### Migration Order

1. Extend tests around current listing behavior before changing code.
2. Move Qckscan first because it already has a dedicated common helper.
3. Move S3 list next, preserving prefix/delimiter pagination semantics.
4. Move WebDAV PROPFIND depth 1.
5. Move native dirlist last because its chunked `kXR_oksofar` framing is the
   most wire-sensitive.

### Tests

| Test | Expected |
|---|---|
| dot entries | skipped everywhere |
| hidden entries | skipped only where currently skipped |
| depth cap | PROPFIND infinity and Qckscan stop at configured cap |
| S3 delimiter | common prefixes unchanged |
| dirlist unsafe names | control-byte filenames skipped |
| checksum scan | regular files included, dirs traversed |

### Estimate

Adds about 250-400 lines. Removes about 500-900 lines after all four
enumerators migrate. Net reduction: 250-500 lines. Risk is medium-high because
listing semantics are client-visible.

## Opportunity 8: Request Identity and Audit Context

### Problem

The codebase has several identity fragments:

| Surface | Identity state |
|---|---|
| Native stream | `ctx->dn`, `ctx->vo_list`, auth mode, access log |
| WebDAV | request context stores token/cert identity |
| S3 | SigV4 identity and optional bearer-token fallback |
| Metrics | VO and unique-user tracking in `src/observability/metrics/tracking.c` |

This makes it easy for a new handler to update one observability path but miss
another. The stream protocol has a structured access log in
`src/observability/accesslog/access_log.c`; HTTP protocols mostly rely on request metrics and
nginx logs.

### Plan

Add `src/core/compat/request_identity.h`:

```c
typedef enum {
    XROOTD_IDENTITY_ANON,
    XROOTD_IDENTITY_GSI,
    XROOTD_IDENTITY_SSS,
    XROOTD_IDENTITY_TOKEN,
    XROOTD_IDENTITY_SIGV4
} xrootd_identity_source_t;

typedef struct {
    xrootd_identity_source_t source;
    const char              *subject;
    const char              *issuer;
    const char              *vo_list;
    const char              *client_ip;
} xrootd_request_identity_t;
```

Add small fillers:

| Filler | Source |
|---|---|
| `xrootd_identity_from_stream(ctx, c, out)` | native stream session |
| `xrootd_identity_from_webdav(r, out)` | WebDAV/XrdHttp request context |
| `xrootd_identity_from_s3(r, out)` | S3 auth context |

Then add a shared audit formatter that all protocols can call without forcing
one log format onto every protocol:

```c
void xrootd_audit_event(ngx_log_t *log,
    const xrootd_request_identity_t *id,
    const char *protocol, const char *verb,
    const char *path, const xrootd_result_t *result,
    size_t bytes);
```

### Tests

| Case | Expected |
|---|---|
| token WebDAV request | source `token`, subject populated |
| native GSI request | source `gsi`, DN populated |
| anonymous request | source `anon`, subject `-` |
| malicious subject/path | audit output sanitized |

### Estimate

Adds about 100-180 lines. Removes about 150-280 lines of repeated identity and
safe-log setup over time. Net reduction: 50-100 lines, with better audit
coverage.

## Opportunity 9: Query and Header Classification Cleanup

### Problem

Several handlers still manually scan headers or query strings despite shared
helpers:

| File | Current pattern |
|---|---|
| `src/protocols/s3/handler.c` | manual scan for `list-type=2` |
| `src/protocols/webdav/xrdhttp.c` | local wrappers around `xrootd_http_query_get()` |
| `src/protocols/webdav/xrdhttp.c` | local request-header insertion |
| S3 copy/multipart paths | repeated request-header loops |

This is not large, but it is low-risk cleanup and reduces parser drift.

### Plan

1. Replace `s3_is_list_request()` manual scan with `xrootd_http_query_has()`
   or `xrootd_http_query_get()`.
2. Add `xrootd_http_request_header_add()` for injected headers, then use it in
   XrdHttp TPC header injection.
3. Replace S3 repeated header loops with `xrootd_http_find_header()` or a
   shared wrapper that preserves case-insensitive matching.

### Tests

| Case | Expected |
|---|---|
| `?list-type=2` | S3 list request still detected |
| encoded query edge cases | no false positives |
| XrdHttp TPC query params | `Source`/`Destination` headers injected |
| existing header present | injected header does not duplicate it |

### Estimate

Adds about 40-80 lines. Removes about 120-240 lines. Net reduction: 80-160
lines.

## Recommended Implementation Phases

### Phase 0: Guardrails and Golden Tests

Add tests before the larger refactors:

| Test type | Purpose |
|---|---|
| result mapping table | lock HTTP/kXR/S3 mappings before moving callers |
| listing golden tests | protect WebDAV/S3/dirlist/Qckscan output shape |
| source grep tests | flag new direct query/header/status helpers where shared APIs exist |

No production code should move in this phase except test-only fixture helpers.

### Phase 1: Low-Risk HTTP Helper Cleanup

Implement Opportunity 2 and Opportunity 9:

1. `xrootd_http_effective_status()`
2. numeric and injected header helpers
3. query detection cleanup
4. WebDAV/S3 metrics migration

Expected net reduction: 140-280 lines.

### Phase 2: Result Object

Implement Opportunity 1:

1. add result struct and mapping table
2. migrate XrdHttp status mapping
3. migrate S3/WebDAV/native stat-open error paths

Expected net reduction: 100-230 lines.

### Phase 3: Resource Metadata and HTTP Object Responses

Implement Opportunities 3 and 4:

1. add `xrootd_resource_info_t`
2. migrate S3 GET/HEAD
3. migrate WebDAV/XrdHttp GET
4. preserve existing range, ETag, Digest, and metrics behavior

Expected net reduction: 160-330 lines.

### Phase 4: Access and Write Admission

Implement Opportunity 5:

1. add `xrootd_access_op_t`
2. consolidate S3 write-disabled handling
3. map WebDAV methods to access ops
4. gradually replace native token-scope boolean calls with named access ops

Expected net reduction: 130-320 lines.

### Phase 5: HTTP Write Pipeline

Implement Opportunity 6:

1. migrate S3 PUT first
2. add WebDAV staged PUT behind an opt-in or internal flag
3. make staged WebDAV PUT default after compatibility tests pass

Expected net reduction: 40-220 lines, with a meaningful partial-write safety
improvement.

### Phase 6: Namespace Scan Engine

Implement Opportunity 7 last:

1. Qckscan
2. S3 ListObjectsV2
3. WebDAV PROPFIND
4. native dirlist

Expected net reduction: 250-500 lines. This phase has the highest behavior
risk and should not start until the listing golden tests are strong.

### Phase 7: Identity and Audit Context

Implement Opportunity 8:

1. add identity struct and per-protocol fillers
2. connect to existing VO/user tracking
3. add shared audit formatter
4. migrate stream access log internals only after HTTP identity fillers are
   stable

Expected net reduction: 50-100 lines.

## Overall Line-Count Estimate

These are approximate source-line estimates under `src/`, excluding inline
documentation comments. They assume all phases are fully migrated.

| Area | Lines added | Lines removed | Net reduction |
|---|---:|---:|---:|
| HTTP helper cleanup | 100-180 | 240-500 | 140-320 |
| Result object | 150-220 | 250-450 | 100-230 |
| Resource metadata and object response | 260-400 | 420-730 | 160-330 |
| Access/write admission | 220-330 | 350-650 | 130-320 |
| HTTP write pipeline | 160-260 | 200-480 | 40-220 |
| Namespace scan engine | 250-400 | 500-900 | 250-500 |
| Identity/audit context | 100-180 | 150-280 | 50-100 |
| Total | 1,240-1,970 | 2,110-3,990 | 870-2,020 |

Conservative expected net reduction: about 900-1,500 non-documentation source
lines. The upper end requires the directory scan phase to complete. Without
Phase 6, the likely net reduction is closer to 600-1,000 lines.

## Review Checklist Per Phase

Every phase should include at least:

1. Success test: representative operation still succeeds.
2. Error test: expected protocol-specific error is preserved.
3. Security-negative test: traversal, denied token scope, read-only write, or
   unauthorized path is rejected.
4. Cross-protocol regression check: a shared helper change must cover at least
   two protocol surfaces.
5. Metrics check when status paths move: response status class must remain
   unchanged.

## Suggested First PR

Start with Phase 1 because it is low risk and creates useful building blocks:

1. Add `xrootd_http_effective_status()` to `src/core/compat/http_headers.c/h` or a
   new `src/core/compat/http_status.c/h`.
2. Add `xrootd_http_set_header_num()`.
3. Add `xrootd_http_request_header_add()` for XrdHttp injected headers.
4. Migrate `src/protocols/webdav/metrics.c`, `src/protocols/s3/metrics.c`, and the local XrdHttp
   header helpers.
5. Replace `s3_is_list_request()` with `xrootd_http_query_has()`.

This first PR should remove duplicated code without changing any filesystem or
authorization behavior.
