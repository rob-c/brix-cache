# Shared-Code Plan 6: Deeper Cross-Protocol Service Layer

Date: 2026-05-22

This plan answers the next question after `shared-code-plan-5.md`: after the
obvious HTTP helpers, result mapping, resource metadata, object responses,
write admission, write pipelines, listing scans, and audit identity are shared,
is there still more common functionality that can safely move below the
protocol handlers?

Yes. The remaining opportunities are not small helper cleanup. They are
operation-level service layers that should sit between the protocol adapters and
the existing low-level helpers.

The target shape is:

1. Protocol handlers keep wire parsing, response emission, and protocol-specific
   semantics.
2. Shared services own common filesystem, range, external-target, integrity, and
   capability decisions.
3. Existing confinement, auth, metrics, framing, and path helpers remain the
   canonical primitives. Do not reimplement them.

## Relationship To Plan 5

Plan 5 should still be treated as the primary near-term refactor plan. This
plan deliberately avoids replanning these Plan 5 items:

| Already covered in Plan 5 | Do not duplicate here |
|---|---|
| Protocol-neutral result object | Use it as the error return shape for new service helpers |
| HTTP effective status and header cleanup | Reuse the helpers once present |
| Resource metadata snapshot | Use it as input to namespace and object helpers |
| HTTP object response builder | Leave GET/HEAD emission there |
| Shared access and write admission | Call it before namespace mutation helpers |
| Shared HTTP write pipeline | Let it own PUT body storage |
| Namespace scan/listing engine | Keep enumeration separate from mutation |
| Request identity and audit context | Let service helpers accept context, not format audit logs |
| Query/header cleanup | Keep parser cleanup out of this plan |

This plan is about the next layer down: mutation execution, range-vector
planning, external transfer targets, integrity metadata, capability tables,
export-root preparation, and async-job lifecycle.

## Do Not Unify

These boundaries should remain protocol-specific:

| Area | Reason |
|---|---|
| Native XRootD frame emission | Binary stream responses and `kXR_status` framing must stay in `src/response/` and handlers |
| S3 SigV4 canonical request logic | It is an S3 API contract, not a storage policy decision |
| WebDAV lock model | RFC 4918 lock discovery, `If`, and `Lock-Token` stay in `src/webdav/lock.c` |
| XrdHttp compatibility headers | `X-Xrootd-*` remains an HTTP dialect wrapper |
| S3 XML error bodies | S3 clients require S3 code/message vocabulary |
| Native TPC wire protocol | XRootD TPC rendezvous remains separate from WebDAV curl-based TPC |

The useful common layer is not one giant protocol abstraction. It is a set of
small service APIs where multiple protocols already make the same storage
decision in slightly different code.

## Opportunity 1: Shared Namespace Mutation Service

### Problem

Filesystem mutations are still implemented independently in the native stream,
WebDAV, XrdHttp-through-WebDAV, and S3 surfaces.

| Operation | Native root:// | WebDAV / XrdHttp | S3 |
|---|---|---|---|
| create directory | `src/write/mkdir.c` | `src/webdav/namespace.c` | directory sentinel paths in `src/s3/put.c`, MPU dirs |
| delete | `src/write/rm.c`, `rmdir.c` | `src/webdav/namespace.c` | `src/s3/object.c`, `delete_objects.c`, MPU abort |
| rename/move | `src/write/mv.c` | `src/webdav/move.c` | MPU complete temp-to-final rename |
| local copy | `src/read/clone.c`, `src/write/chkpoint*.c` | `src/webdav/copy.c`, `fs/copy_engine.c` | `src/s3/copy.c`, upload-part-copy |
| truncate/chmod | `src/write/truncate.c`, `chmod.c` | not generally exposed | not exposed |

The low-level confined helpers already exist and must remain canonical:

| Helper | Keep using |
|---|---|
| `xrootd_open_confined*` | confined fd open |
| `xrootd_unlink_confined*` | confined unlink/rmdir/remove-tree |
| `xrootd_mkdir_confined*` | confined directory creation |
| `xrootd_rename_confined*` | confined atomic rename |
| `xrootd_fs_remove_tree_confined()` | recursive confined delete |
| `xrootd_staged_open/commit/abort()` | temp-file staging |
| `xrootd_copy_range()` | file data copy |

The duplication is the orchestration around those helpers: missing-target
semantics, recursive-vs-empty directory behavior, overwrite handling, staged
copy commit, self-copy checks, xattr preservation, and errno mapping.

### Plan

Add `src/compat/namespace_ops.h` and `src/compat/namespace_ops.c`.

The helpers should operate on already-resolved, confined paths. They must not
parse wire paths, check tokens, check authdb, check VO ACLs, or check WebDAV
locks. Protocol handlers do those steps first.

```c
typedef enum {
    XROOTD_NS_OK = 0,
    XROOTD_NS_NOT_FOUND,
    XROOTD_NS_DENIED,
    XROOTD_NS_EXISTS,
    XROOTD_NS_CONFLICT,
    XROOTD_NS_NOT_EMPTY,
    XROOTD_NS_TOO_LONG,
    XROOTD_NS_NO_SPACE,
    XROOTD_NS_IO_ERROR
} xrootd_ns_status_t;

typedef struct {
    xrootd_ns_status_t status;
    int                sys_errno;
    ngx_flag_t         existed;
    ngx_flag_t         created;
    ngx_flag_t         was_dir;
} xrootd_ns_result_t;

typedef struct {
    ngx_flag_t recursive;
    ngx_flag_t idempotent_missing;
    ngx_flag_t require_empty_dir;
} xrootd_ns_delete_opts_t;

typedef struct {
    ngx_flag_t recursive;
    ngx_flag_t overwrite;
    ngx_flag_t overwrite_dirs;
    ngx_flag_t preserve_xattrs;
    ngx_flag_t staged_commit;
} xrootd_ns_copy_opts_t;
```

Initial APIs:

```c
xrootd_ns_result_t xrootd_ns_delete(ngx_log_t *log,
    const char *root_canon, const char *path,
    const xrootd_ns_delete_opts_t *opts);

xrootd_ns_result_t xrootd_ns_mkdir(ngx_log_t *log,
    const char *root_canon, const char *path, mode_t mode,
    ngx_flag_t recursive);

xrootd_ns_result_t xrootd_ns_rename(ngx_log_t *log,
    const char *root_canon, const char *src, const char *dst,
    ngx_flag_t overwrite_dirs);

xrootd_ns_result_t xrootd_ns_local_copy(ngx_log_t *log,
    const char *root_canon, const char *src, const char *dst,
    const xrootd_ns_copy_opts_t *opts);
```

Protocol adapters translate the neutral result:

| Protocol | Adapter responsibility |
|---|---|
| Native stream | convert to `kXR_*`, log via `XROOTD_RETURN_*` |
| WebDAV | convert to HTTP, preserve `Overwrite`, `Depth`, locks, conditionals |
| XrdHttp | reuse WebDAV path plus `X-Xrootd-Status` mapping |
| S3 | convert to XML errors, preserve idempotent DELETE and bucket-directory behavior |

### First Migration Targets

1. Move S3 `s3_handle_delete()` into `xrootd_ns_delete()` with
   `idempotent_missing=1`.
2. Move WebDAV `webdav_handle_delete()` into `xrootd_ns_delete()` with
   `require_empty_dir=1` unless recursive semantics are intentionally enabled.
3. Move native `xrootd_handle_rm()` directory retry behavior behind
   `xrootd_ns_delete()`.
4. Move WebDAV local COPY and S3 CopyObject file copy into
   `xrootd_ns_local_copy()` while keeping XML response emission protocol-specific.

### Tests

Each migrated operation needs the standard three tests:

| Test | Example |
|---|---|
| success | delete existing object, mkdir existing parent, copy file |
| error | missing parent, non-empty destination dir, no space or too-long path |
| security negative | traversal/symlink escape still rejected by existing confined helpers |

Also add cross-protocol assertions:

| Case | Expected |
|---|---|
| S3 DELETE missing | 204 and no file created |
| WebDAV DELETE missing | 404 |
| native `kXR_rm` directory not empty | `kXR_FSError` or mapped result preserved |
| WebDAV `Overwrite: F` | 412, destination unchanged |

### Estimate

Adds about 300-450 lines. Removes about 500-900 lines after broad migration.
Net reduction: 200-450 lines. The bigger win is one mutation execution policy
using the existing confined primitives.

## Opportunity 2: Shared Byte-Range Vector Planner

### Problem

The module now has three related range paths:

| Surface | File | Current behavior |
|---|---|---|
| HTTP single range | `src/compat/range.c` | parses one `Range: bytes=...` value |
| XrdHttp multi-range | `src/webdav/xrdhttp_multipart.c` | local parser for comma-separated ranges |
| Native readv | `src/read/readv.c` | validates wire segments and coalesces adjacent reads |

These are not identical wire formats, but they share several decisions:

1. Normalize byte intervals against file size.
2. Reject or drop unsatisfiable ranges.
3. Cap range count and total response bytes.
4. Detect integer overflow.
5. Coalesce adjacent ranges from the same fd when doing actual I/O.

The XrdHttp multi-range parser is currently local. Native `readv` has a useful
coalescing implementation that is not reusable by XrdHttp or future HTTP vector
read paths.

### Plan

Add `src/compat/range_vector.h` and `src/compat/range_vector.c`.

```c
typedef struct {
    off_t       start;
    off_t       end;       /* inclusive */
    int         fd;        /* optional for I/O planning */
    ngx_uint_t  handle;    /* optional for native readv */
} xrootd_byte_range_t;

typedef struct {
    ngx_uint_t max_ranges;
    off_t      max_total_bytes;
    ngx_flag_t allow_suffix;
    ngx_flag_t allow_open_ended;
    ngx_flag_t drop_unsatisfiable;
} xrootd_range_vector_opts_t;
```

Shared helpers:

```c
ngx_int_t xrootd_http_parse_range_vector(const u_char *data, size_t len,
    off_t file_size, const xrootd_range_vector_opts_t *opts,
    xrootd_byte_range_t *ranges, ngx_uint_t *nranges);

ngx_int_t xrootd_range_vector_validate_total(
    const xrootd_byte_range_t *ranges, ngx_uint_t nranges,
    off_t max_total_bytes, off_t *total_out);

ngx_uint_t xrootd_range_vector_next_coalesced_run(
    const xrootd_byte_range_t *ranges, ngx_uint_t nranges,
    ngx_uint_t start_index, ngx_uint_t max_iov);
```

Keep serialization protocol-specific:

| Protocol | Stays where |
|---|---|
| Native readv wire body | `src/read/readv.c` |
| XrdHttp multipart/byteranges chain | `src/webdav/xrdhttp_multipart.c` |
| WebDAV/S3 single-range response headers | `src/compat/http_file_response.c` |

### First Migration Targets

1. Replace `parse_multi_ranges()` in `src/webdav/xrdhttp_multipart.c`.
2. Let `src/compat/range.c` become a thin max-one wrapper around the vector
   parser.
3. Move the contiguous-run logic from `src/read/readv.c` into the coalescer
   while preserving native readv response layout.

### Tests

| Case | Expected |
|---|---|
| `bytes=0-9,20-29` | two ranges for XrdHttp |
| `bytes=-10` | suffix range normalized |
| `bytes=999-1000` on 100-byte file | unsatisfiable |
| malformed digits | rejected or dropped consistently by caller policy |
| adjacent native readv segments | one coalesced I/O run |
| too many ranges | capped and reported according to caller policy |

### Estimate

Adds about 180-260 lines. Removes about 200-320 lines. Net reduction is modest,
but it makes XrdHttp vector reads and native `readv` share the same overflow and
range-normalization logic.

## Opportunity 3: Shared External Transfer Target Policy

### Problem

Native root TPC has an SSRF guard in `src/tpc/connect.c`:

| Guard | Current owner |
|---|---|
| DNS resolution before transfer | native TPC |
| loopback/link-local rejection | native TPC |
| RFC1918 private rejection option | native TPC |
| IPv4-mapped IPv6 handling | native TPC |

WebDAV HTTP-TPC and XrdHttp TPC currently enforce a different minimum policy in
`src/webdav/tpc.c` and `src/webdav/xrdhttp.c`: URL must be `https://`, must not
contain control bytes, and must fit local buffers. That is necessary, but it is
not the same destination policy as native TPC.

S3 does not currently fetch remote URLs for CopyObject, but any future
remote-copy or presigned-fetch feature should not grow a third policy.

### Plan

Move the address classification and DNS preflight from `src/tpc/connect.c` into
`src/compat/net_target.h` and `src/compat/net_target.c`.

```c
typedef struct {
    ngx_str_t  raw_url;
    ngx_str_t  scheme;
    ngx_str_t  host;
    ngx_str_t  path;
    uint16_t   port;
    ngx_flag_t has_port;
} xrootd_net_target_t;

typedef struct {
    ngx_flag_t require_https;
    ngx_flag_t allow_root_scheme;
    ngx_flag_t allow_local;
    ngx_flag_t allow_private;
    uint16_t   default_https_port;
    uint16_t   default_root_port;
} xrootd_net_target_policy_t;
```

Shared helpers:

```c
ngx_int_t xrootd_net_target_parse(ngx_pool_t *pool,
    const ngx_str_t *url, xrootd_net_target_t *out,
    char *err, size_t errsz);

ngx_int_t xrootd_net_target_check_dns(
    const xrootd_net_target_t *target,
    const xrootd_net_target_policy_t *policy,
    char *err, size_t errsz);
```

Policy defaults:

| Surface | Default |
|---|---|
| Native root TPC | existing `xrootd_tpc_allow_local/private` behavior |
| WebDAV HTTP-TPC | require HTTPS, deny local by default, allow private by default |
| XrdHttp TPC query injection | parse and validate before synthesizing headers |
| S3 future remote target | must use this helper before opening network connections |

### First Migration Targets

1. Move `tpc_addr_is_prohibited()` and related IPv4/IPv6 helpers out of
   `src/tpc/connect.c`.
2. Keep `xrootd_tpc_check_src_policy()` as a native wrapper over the compat
   DNS checker.
3. Add `xrootd_webdav_tpc_allow_local` and
   `xrootd_webdav_tpc_allow_private` directives, or reuse a common HTTP-TPC
   config block, defaulting to the native policy.
4. Validate `Source` and `Destination` URLs in `src/webdav/tpc.c` before curl
   runs.
5. Validate `?tpc.src=` and `?tpc.dst=` in `src/webdav/xrdhttp.c` before header
   injection.

### Tests

Extend `tests/test_tpc_ssrf_policy.py` or add an HTTP companion:

| Case | Expected |
|---|---|
| native TPC to `127.0.0.1` default | rejected |
| WebDAV TPC `Source: https://127.0.0.1/...` default | rejected before curl |
| XrdHttp `?tpc.src=https://localhost/...` default | rejected before header injection |
| allow-local enabled | loopback accepted |
| private denied | RFC1918 target rejected |
| non-HTTPS WebDAV TPC | still rejected as 400 |

### Estimate

Adds about 220-320 lines. Removes about 80-140 lines from native TPC and avoids
future duplication. This is mainly a security consistency improvement, not a
line-count play.

## Opportunity 4: Shared Integrity Metadata Service

### Problem

Checksum computation is already shared in `src/compat/checksum.c`, but checksum
metadata policy is still split:

| Surface | Current behavior |
|---|---|
| native `kXR_Qcksum` | computes checksum by path or handle |
| native `kXR_Qckscan` | computes checksums while walking |
| native `kXR_dirlist` dcksm | has its own xattr cache in `src/dirlist/dcksm.c` |
| XrdHttp `Want-Digest` | computes and injects `Digest` in `src/webdav/xrdhttp.c` |
| fattr | exposes user metadata through POSIX xattrs |
| WebDAV PROPFIND | emits selected metadata and ETag |
| S3 | uses stat-derived ETag, not a general checksum |

The important duplication is not the checksum algorithm itself. It is:

1. Which xattr key stores a cached checksum.
2. When cached checksum data may be trusted.
3. How a checksum becomes an HTTP `Digest` value.
4. Which write paths should invalidate or refresh integrity metadata.

### Plan

Add `src/compat/integrity_info.h` and `src/compat/integrity_info.c`.

```c
typedef struct {
    xrootd_checksum_alg_t alg;
    char                  alg_name[16];
    char                  hex[129];
    ngx_flag_t            from_cache;
} xrootd_integrity_info_t;

typedef struct {
    ngx_flag_t allow_xattr_cache;
    ngx_flag_t update_xattr_cache;
    ngx_flag_t require_regular_file;
} xrootd_integrity_opts_t;
```

Shared helpers:

```c
ngx_int_t xrootd_integrity_get_fd(ngx_log_t *log, int fd,
    const char *path, const char *alg_name,
    const xrootd_integrity_opts_t *opts,
    xrootd_integrity_info_t *out);

ngx_int_t xrootd_integrity_format_http_digest(
    const xrootd_integrity_info_t *info,
    char *out, size_t outsz);

void xrootd_integrity_invalidate_fd(ngx_log_t *log, int fd);
void xrootd_integrity_invalidate_path(ngx_log_t *log, const char *path);
```

The service should use the existing checksum helper for computation and the
existing safe-log helper for errors. It should not invent new digest algorithms.

### First Migration Targets

1. Move the dcksm xattr cache helpers from `src/dirlist/dcksm.c` into
   `src/compat/integrity_info.c`.
2. Use `xrootd_integrity_get_fd()` in XrdHttp `xrdhttp_add_checksum_header()`.
3. Use the same helper in `kXR_Qcksum` handle mode.
4. Add invalidation hooks to native write/truncate/pgwrite/writev, WebDAV PUT,
   S3 PUT, S3 multipart complete, and local copy/rename paths as they migrate
   to shared namespace/write helpers.

### Tests

| Case | Expected |
|---|---|
| first checksum | computed and optionally cached |
| second checksum | returns same value from xattr cache |
| write then checksum | stale cache not reused |
| XrdHttp `Want-Digest: adler32` | `Digest` header preserved |
| unsupported algorithm | protocol-specific error preserved |

### Estimate

Adds about 180-260 lines. Removes about 120-220 lines initially. Net reduction
is small until invalidation is shared, but it prevents checksum drift across
native, WebDAV/XrdHttp, and S3 write paths.

## Opportunity 5: Protocol Capability And Operation Registry

### Problem

Each protocol repeats operation classification in several places.

WebDAV examples:

| Concern | Current file |
|---|---|
| dispatch routing | `src/webdav/dispatch.c` |
| write-method detection | `src/webdav/access.c` |
| token scope method name | `src/webdav/access.c` |
| OPTIONS `Allow` header | `src/webdav/methods_basic.c` |
| CORS methods | `src/webdav/cors.c` |
| metrics method slots | `src/webdav/metrics.c` |

S3 has a similar split between `src/s3/handler.c` and `src/s3/metrics.c`.
Native root has opcode dispatch, `kXR_Qconfig` capability reporting, and metric
slot mappings in separate places.

Plan 5's access-op enum is the right security abstraction. This plan adds the
read-only capability view that can drive user-visible method/capability lists.

### Plan

Add a small generic descriptor shape in `src/compat/protocol_caps.h`.

```c
typedef enum {
    XROOTD_PROTO_OP_READ      = 0x0001,
    XROOTD_PROTO_OP_WRITE     = 0x0002,
    XROOTD_PROTO_OP_LIST      = 0x0004,
    XROOTD_PROTO_OP_TPC       = 0x0008,
    XROOTD_PROTO_OP_LOCK      = 0x0010,
    XROOTD_PROTO_OP_ASYNC_BODY = 0x0020
} xrootd_proto_op_flags_t;

typedef struct {
    const char  *name;
    ngx_uint_t   http_method;
    ngx_uint_t   metric_slot;
    ngx_uint_t   access_op;
    ngx_uint_t   flags;
} xrootd_http_operation_t;
```

Protocol modules keep their own tables:

| Table | Owner |
|---|---|
| WebDAV methods | `src/webdav/operation_table.c` |
| S3 operations | `src/s3/operation_table.c` |
| Native root opcode capabilities | `src/protocol/operation_table.c` or stream-local table |

Shared helpers format and query those tables:

```c
const xrootd_http_operation_t *xrootd_http_operation_find(
    ngx_http_request_t *r, const xrootd_http_operation_t *ops,
    ngx_uint_t nops);

ngx_int_t xrootd_http_operation_allow_header(ngx_pool_t *pool,
    const xrootd_http_operation_t *ops, ngx_uint_t nops,
    ngx_uint_t enabled_flags, ngx_str_t *out);
```

### First Migration Targets

1. Replace WebDAV `Allow` and CORS method string construction with the WebDAV
   operation table.
2. Replace `webdav_is_write_method()` and `webdav_scope_method_name()` with
   table lookups feeding Plan 5's access-op wrapper.
3. Replace S3 method-slot classification with a table lookup while keeping
   ListObjectsV2 as a distinct operation.
4. Use the native operation table to generate stable `kXR_Qconfig` capability
   fragments for `chksum`, `tpc`, and future flags.

### Tests

| Case | Expected |
|---|---|
| WebDAV read-only OPTIONS | no mutating methods in `Allow` |
| WebDAV write-enabled OPTIONS | `PUT`, `DELETE`, `MKCOL`, `MOVE`, `COPY` present |
| WebDAV CORS methods | matches `Allow` for enabled methods |
| S3 ListObjectsV2 | still counted as list metric slot |
| unknown method/opcode | protocol-specific 405 or `kXR_Unsupported` |

### Estimate

Adds about 120-220 lines. Removes about 250-450 lines after WebDAV and S3
migrate. Net reduction: 130-230 lines, plus fewer "forgot to update the Allow
header" bugs.

## Opportunity 6: Shared Export-Root Preparation

### Problem

Export-root validation and canonicalization are done in at least three places:

| Surface | Current path |
|---|---|
| native stream | `src/config/runtime_server.c` and stream config |
| WebDAV/XrdHttp | `src/webdav/config.c` |
| S3 | `src/s3/module.c` |

The WebDAV path uses `xrootd_validate_path()` and then `realpath()`. The S3
path does its own length copy and `realpath()`. Native stream validates the
root during runtime preparation. These should converge because export-root
setup is part of the confinement boundary.

### Plan

Add `src/config/root_prepare.h` and `src/config/root_prepare.c`.

```c
typedef struct {
    const char *directive_name;
    ngx_flag_t allow_write;
    ngx_flag_t required;
    size_t     canon_size;
} xrootd_export_root_opts_t;

char *xrootd_prepare_export_root(ngx_conf_t *cf,
    const ngx_str_t *root, const xrootd_export_root_opts_t *opts,
    char *root_canon);
```

The helper should:

1. Reject empty roots when the protocol is enabled.
2. Copy `ngx_str_t` into a bounded NUL-terminated buffer.
3. Validate directory existence.
4. Validate `R_OK|X_OK` or `R_OK|W_OK|X_OK` based on write policy.
5. Run `realpath()`.
6. Normalize the canonical root string consistently.
7. Emit directive-specific `NGX_LOG_EMERG` messages.

### First Migration Targets

1. S3 `ngx_http_s3_merge_loc_conf()`.
2. WebDAV `ngx_http_xrootd_webdav_merge_loc_conf()`.
3. Native `xrootd_config_prepare_server()`.

### Tests

| Case | Expected |
|---|---|
| enabled protocol with missing root | `nginx -t` fails |
| read-only root without write permission | accepted |
| write-enabled root without write permission | `nginx -t` fails |
| root path too long | directive-specific error |
| symlink root | canonical root is real path |

### Estimate

Adds about 80-140 lines. Removes about 70-120 lines. The primary value is
consistent confinement preflight, not source reduction.

## Opportunity 7: Async Job Lifecycle Helpers

### Problem

Several features run work outside the main request path:

| Feature | Current owner |
|---|---|
| native read/write AIO | `src/aio/*`, `src/read/readv.c` |
| native TPC pull | `src/tpc/thread.c`, `done.c`, `source.c` |
| WebDAV HTTP-TPC curl thread | `src/webdav/tpc_thread.c`, `tpc_marker.c` |
| Qckscan checksum scan | `src/query/checksum_ckscan_async.c` |
| request body callbacks | WebDAV PUT, S3 PUT, S3 multipart complete |

These implementations cannot be collapsed into one generic job engine, but they
repeat lifecycle mechanics:

1. Allocate per-job state.
2. Register cleanup.
3. Preserve request/session pointers carefully.
4. Finalize metrics exactly once.
5. Abort staged temp files on failure.
6. Return `NGX_DONE` for async paths and finalize later.

### Plan

Add a deliberately small lifecycle helper, not a framework:

```c
typedef void (*xrootd_job_cleanup_pt)(void *data);

typedef struct {
    ngx_log_t              *log;
    void                   *owner;
    ngx_uint_t              finalized;
    xrootd_job_cleanup_pt   cleanup;
    void                   *cleanup_data;
} xrootd_async_job_t;

void xrootd_async_job_init(xrootd_async_job_t *job, ngx_log_t *log,
    void *owner);

void xrootd_async_job_set_cleanup(xrootd_async_job_t *job,
    xrootd_job_cleanup_pt cleanup, void *data);

void xrootd_async_job_cleanup_once(xrootd_async_job_t *job);
```

Then add protocol wrappers where useful:

| Wrapper | Use |
|---|---|
| HTTP request async finalizer | S3/WebDAV body callbacks and HTTP-TPC |
| Stream connection async finalizer | native AIO and native TPC |
| staged-file cleanup adapter | PUT/TPC/copy paths |

### Migration Order

1. Start with WebDAV/S3 staged temp cleanup, where request-pool lifetime is
   simple.
2. Move Qckscan async cleanup next.
3. Consider native TPC only after its existing skipped tests are stable.

### Tests

| Case | Expected |
|---|---|
| async success | finalizer runs once |
| async error | temp file removed |
| client disconnect | cleanup runs once |
| body read error | metric finalized once |
| native TPC skipped tests | no additional hangs introduced |

### Estimate

Adds about 120-220 lines. Removes about 80-180 lines initially. This is
medium-high risk because lifecycle code is easy to overgeneralize. It should be
last unless a concrete bug forces it earlier.

## Recommended Implementation Phases

### Phase 0: Guardrail Tests

Before moving production code, add tests that preserve current behavior:

| Guardrail | Scope |
|---|---|
| namespace mutation matrix | native/WebDAV/S3 delete, mkdir, copy, rename |
| multi-range golden tests | XrdHttp multipart output and native readv coalescing |
| external target SSRF matrix | native TPC plus WebDAV/XrdHttp TPC |
| checksum cache behavior | dcksm, Qcksum, XrdHttp Digest |
| capability consistency | WebDAV `Allow`, CORS, access method table |

### Phase 1: Export Roots And Capability Tables

Implement Opportunities 5 and 6 first. They are mostly configuration and table
plumbing and should not change filesystem data paths.

Expected net reduction: 180-350 lines.

### Phase 2: External Target Policy

Implement Opportunity 3 before touching more TPC behavior. This gives native
TPC, WebDAV TPC, and XrdHttp TPC one SSRF decision.

Expected source reduction is small, but security consistency improves.

### Phase 3: Range Vector Planner

Implement Opportunity 2. Start with XrdHttp multi-range parsing, then native
readv coalescing. Keep serialization unchanged.

Expected net reduction: 20-120 lines.

### Phase 4: Integrity Metadata

Implement Opportunity 4. Move the dcksm cache first, then XrdHttp Digest, then
Qcksum. Add invalidation hooks only after write paths are consolidated.

Expected net reduction: 0-100 lines initially, larger after invalidation moves.

### Phase 5: Namespace Mutation Service

Implement Opportunity 1 after Plan 5's result object and access-op wrappers are
available. This phase touches user-visible mutation semantics and should be
split by operation family.

Suggested order:

1. delete
2. mkdir
3. rename/move
4. local copy
5. truncate/chmod

Expected net reduction: 200-450 lines.

### Phase 6: Async Job Lifecycle

Implement Opportunity 7 last, and only with strong tests around failure paths.

Expected net reduction: 0-100 lines at first. The value is cleanup correctness.

## Overall Estimate

| Area | Lines added | Lines removed | Net reduction |
|---|---:|---:|---:|
| Namespace mutation service | 300-450 | 500-900 | 200-450 |
| Range vector planner | 180-260 | 200-320 | 20-120 |
| External target policy | 220-320 | 80-140 | -140 to -80 |
| Integrity metadata service | 180-260 | 120-220 | -60 to 40 |
| Capability registry | 120-220 | 250-450 | 130-230 |
| Export-root preparation | 80-140 | 70-120 | -20 to 40 |
| Async job lifecycle | 120-220 | 80-180 | -40 to 60 |
| Total | 1,200-1,870 | 1,300-2,330 | 100-460 |

The conservative line-count reduction is modest compared with Plan 5. That is
expected. These are service-layer refactors whose main payoff is stronger
security consistency and fewer protocol drift bugs.

## Review Checklist Per Phase

Every implementation PR should include:

1. A success test.
2. An error test.
3. A security-negative test.
4. A cross-protocol assertion when a helper is used by more than one surface.
5. A check that existing helpers remain the only path/auth/metrics/framing
   primitives.
6. No wire response changes unless the PR explicitly documents them.

## Suggested First PR

Start with export-root preparation because it is small, easy to validate with
`nginx -t`, and improves the confinement boundary before larger refactors:

1. Add `src/config/root_prepare.c/h`.
2. Migrate S3 root canonicalization.
3. Migrate WebDAV root canonicalization.
4. Migrate native stream root preparation.
5. Add three config tests: missing root, write permission failure, symlink root.

This first PR should not change request handling. It just makes every protocol
enter runtime with the same canonical export-root contract.
