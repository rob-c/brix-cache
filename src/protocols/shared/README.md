# shared — cross-protocol helper library (HTTP file serving + overflow-safe size math)

## Overview

`src/shared/` is a small, dependency-light library of helpers that more than one
protocol handler needs but that belong to none of them. It exists to stop the
same logic being copied into the WebDAV, S3, readv, and cache subsystems, where
divergent copies would drift apart and (for the security-sensitive math) silently
reintroduce bugs. The rule the suite enforces is "one canonical implementation,
many callers" — see `tests/test_cross_protocol_shared_helpers.py`, which fails
the build if a handler grows a private copy again instead of calling through here.

There are two concerns, deliberately kept separate:

1. **HTTP ranged file serving** (`file_serve.c` / `file_serve.h`). The shared
   "open file is already known → parse `Range:` → emit headers → send body →
   account bytes" pipeline used by both `davs://` WebDAV `GET` and the S3
   `GetObject` path. It sits at the *response* end of an HTTP read lifecycle:
   the caller has already authenticated, confined the path beneath the export
   root, and obtained an open, stat'd VFS handle; this module turns that handle
   into a correct HTTP `200`/`206`/`416` response. Protocol-specific concerns (S3
   error XML, WebDAV `XrdHttp` checksum headers, per-protocol metric labels) stay
   in the caller, exposed through an options struct and a pre-header hook.

2. **Overflow-checked size arithmetic** (`safe_size.h`, header-only). The
   primitives `brix_size_mul`/`brix_size_add` and the array allocators
   `brix_palloc_array`/`brix_pcalloc_array`/`brix_alloc_array` turn
   attacker-controlled `n * sizeof(elem)` allocations into a clean `NULL`/error
   instead of a wrapped, undersized buffer that the caller then overflows. They
   are used wherever a count or length comes off the wire — currently the readv
   segment array (`../read/readv.c`) and the cache eviction-candidate growth
   (`../cache/evict_candidates.c`).

Build registration: the serve pair is registered in the top-level nginx module
`config` (the header at `config:168`, the source at `config:247`) and compiled as
part of the normal build. `safe_size.h` is *not* in `config` — it is header-only
(`static ngx_inline`), so consumers pick it up purely by `#include`, with no new
translation unit and no `./configure` change.

## Files

| File | Responsibility |
|---|---|
| `file_serve.c` | Implements `brix_http_serve_file_ranged()` — the 5-phase shared HTTP body-send pipeline: (1) parse `Range:` via `brix_http_parse_range`, short-circuiting to `416` if unsatisfiable; (2) emit `Last-Modified`/`Content-Length`/`Content-Range`/ETag via `brix_http_set_file_headers` and fire the optional `pre_header_send` hook; (3) start dashboard transfer tracking via `brix_dashboard_http_start_identity`; (4) `dup()` the fd, release the VFS handle, send the range via `brix_http_send_file_range`; (5) post-send byte accounting (`brix_dashboard_http_add`) + cache-access recording (`brix_cache_record_access`) for cache-backed handles. |
| `file_serve.h` | Public interface: `brix_http_serve_file_ranged()` prototype, the `brix_http_serve_opts_t` input struct, the `brix_http_serve_result_t` output struct, the `brix_http_pre_header_fn` hook typedef, and the `BRIX_SERVE_RANGE_FULL/_PARTIAL/_UNSATISFIED` outcome constants. |
| `safe_size.h` | Header-only (all `static ngx_inline`, no new translation unit): `brix_size_mul`/`brix_size_add` (overflow-detecting via `__builtin_*_overflow`, with a portable fallback for other compilers) and `brix_palloc_array`/`brix_pcalloc_array` (request-pool) / `brix_alloc_array` (heap, for the long-lived stream path) array allocators that return `NULL` on overflow, on a zero-size request, or on OOM. Compiles standalone under `BRIX_SAFE_SIZE_STANDALONE` for the fuzz target. |

## Key types & data structures

- **`brix_http_serve_opts_t`** (`file_serve.h:22`) — caller-supplied options for a
  serve. Carries `xfer_proto` (`BRIX_XFER_PROTO_WEBDAV`/`_S3`) and `op_name`
  (`"GET"`/`"GetObject"`) for dashboard/metric labelling, the resolved
  `identity` display string, `etag_flags` (`BRIX_ETAG_WEAK` or 0), and the
  optional `pre_header_send`/`pre_header_ud` hook.
- **`brix_http_pre_header_fn`** (`file_serve.h:19`) —
  `void (*)(ngx_http_request_t*, ngx_fd_t fd, off_t file_size, void *userdata)`.
  Fires after the standard headers are set but **before** the body send begins;
  WebDAV uses it to inject `XrdHttp` checksum/status headers. `NULL` skips it.
- **`brix_http_serve_result_t`** (`file_serve.h:31`) — what the caller reads
  back to drive its own metrics: `range_result` (one of `BRIX_SERVE_RANGE_*`)
  and `bytes_sent` (0 on `header_only`, 416, or error). The shared code
  deliberately does **not** increment protocol metrics itself — labels are
  protocol-specific, so the caller does it from these fields.
- **`brix_vfs_file_t` / `brix_vfs_stat_t`** (from `../fs/vfs.h`) — the
  already-open handle and its stat snapshot that the caller hands in. Accessed
  here only through VFS accessors: `brix_vfs_file_fd`, `brix_vfs_file_path`,
  `brix_vfs_file_from_cache`, `brix_vfs_close`.
- **`safe_size.h`** defines no types — just inline functions over plain `size_t`.

## Control & data flow

**`file_serve.c` — entry and call-outs.** Execution enters only via
`brix_http_serve_file_ranged()`, called from two HTTP read handlers:

- WebDAV `GET` — `../webdav/get.c` (`#include "../shared/file_serve.h"`).
- S3 `GetObject` — `../s3/object.c` (`#include "../shared/file_serve.h"`).

Each caller has already run access-phase auth, confined the path under the export
root (see `../path/README.md`), and opened the file through the VFS (possibly
satisfied from cache). It builds an `brix_http_serve_opts_t`, calls in with the
open handle + stat, and reads back `brix_http_serve_result_t` to bump its own
range/bytes metrics.

Inside, the module calls out to:
- `../compat/range.h` — `brix_http_parse_range` (RFC 7233 `Range:` parsing).
- `../compat/http_file_response.h` — `brix_http_set_file_headers` and
  `brix_http_send_file_range` (the actual nginx header emission and
  sendfile/range body send).
- `../dashboard/dashboard_tracking.h` — `brix_dashboard_http_start_identity` /
  `_add` / `_error` / `_finish` for live transfer monitoring.
- `../cache/open.h` — `brix_cache_record_access` to update LRU access stats when
  the bytes came from a cache-backed handle (`brix_vfs_file_from_cache`).
- `../fs/vfs.h` — handle accessors and `brix_vfs_close`.

**Ownership contract:** the function **always closes the VFS handle** (on the
416 early-out, on the header-build failure, on dup failure, and before the body
send on the success path). Callers must **not** close `fh` afterward. The body is
sent over a `dup()`'d fd so nginx's chain/sendfile machinery owns its own
descriptor independent of the VFS handle's lifetime — the handle can be reused or
evicted by the cache/fd-cache layer while nginx is still streaming the duplicate.

**`safe_size.h` — usage flow.** Pure utility, no control flow of its own.
Wire-driven allocation sites compute the size with `brix_size_mul` (or allocate
directly with the `*_array` helpers) and bail on `NGX_ERROR`/`NULL`. Current
callers:
- `../read/readv.c` — the readv segment-descriptor array, guarded both by an
  explicit `brix_size_mul(segment_count, sizeof(*ranges), …)` pre-check
  (`readv.c:87`) and by allocation through `brix_alloc_array(c->log,
  segment_count, …)` (`readv.c:301`), because the count comes straight off the
  client's `kXR_readv` request.
- `../cache/evict_candidates.c` — the eviction-candidate list realloc growth, sized
  with `brix_size_mul(new_cap, sizeof(list->elts[0]), …)` (`evict_candidates.c:237`)
  before the buffer is grown.

The header also compiles standalone for the libFuzzer target
`tests/fuzz/fuzz_safe_size.c`, which defines `BRIX_SAFE_SIZE_STANDALONE` to skip
the nginx includes and supply its own `ngx_int_t`/`size_t`/alloc shims.

## Invariants, security & gotchas

- **The handle is closed for you — exactly once.** Every return path in
  `brix_http_serve_file_ranged` calls `brix_vfs_close(fh, …)` before
  returning (`file_serve.c:68`, `:88`, `:110`, `:115`). A caller that also closes
  `fh` will double-close. This is the most common integration mistake.
- **Body is sent over a `dup()`'d fd, not the handle's fd** (`file_serve.c:108`).
  The VFS handle is released immediately after the dup so the cache/fd-cache layer
  can reuse or evict it while nginx is still streaming the duplicate. A `dup()`
  failure is a `500` (after `brix_dashboard_http_error`/`_finish`), not a silent
  partial response.
- **416 short-circuits before any send** (`file_serve.c:67-74`): an unsatisfiable
  `Range:` returns `NGX_HTTP_RANGE_NOT_SATISFIABLE` with `content_length_n = 0`
  and `ngx_http_send_special(NGX_HTTP_LAST)` — no body, handle closed.
- **`header_only` (HEAD) returns after the header/dashboard phase**
  (`file_serve.c:126-129`) with `bytes_sent` left 0 — callers must not treat a HEAD
  as a transferred range when emitting metrics.
- **Metrics are the caller's job, by design.** This module returns
  `range_result`/`bytes_sent` and stops. Per the project invariant, metric labels
  must stay low-cardinality (no paths/buckets/UUIDs/DNs); keeping the increment in
  the protocol handler is what lets WebDAV and S3 apply their own correct label
  sets. Do not add `BRIX_*_METRIC_INC` calls here.
- **TLS vs cleartext is handled downstream, not here.** The actual buffer choice
  (TLS memory-backed vs cleartext file-backed + sendfile) lives in
  `brix_http_send_file_range` / `../compat/http_file_response.c`. Do not add a
  raw `b->memory`/sendfile branch in this file; route through the compat helper so
  the two body paths never get mixed.
- **`safe_size.h` is fail-NULL, not fail-truncate.** On overflow the math helpers
  return `NGX_ERROR` and leave `*out` unspecified — callers must check the return
  and not read `*out` (`safe_size.h:36-37`). The `*_array` allocators fold
  overflow, a zero-size request, and OOM into a single `NULL`, so one callsite
  check covers all three.
- **Pool vs heap allocator must match the buffer's lifetime.** Use
  `brix_palloc_array`/`brix_pcalloc_array` for request-pool memory (freed when
  the request pool is destroyed) and `brix_alloc_array` (free with `ngx_free`)
  only for the long-lived stream path where a connection/persistent buffer
  outlives any request pool — see the readv stream consumer above.
- **`safe_size.h` adds no `.c` and no `./configure` change.** All functions are
  `static ngx_inline`; adopting them is `#include "../shared/safe_size.h"` plus a
  call. The mandate (header comment, `safe_size.h:1-24`) is that *every*
  wire-driven `n * sizeof(...)` and `len + 1` size computation migrates to these —
  the readv segment array and the cache eviction realloc were the seed sites.

## Entry points / extending

**Adopt the shared serve path from a new HTTP read handler.** Open and stat the
file through the VFS, then:

```c
#include "../shared/file_serve.h"

brix_http_serve_opts_t   opts = {0};
brix_http_serve_result_t res;

opts.xfer_proto      = BRIX_XFER_PROTO_WEBDAV;   /* or _S3 */
opts.op_name         = "GET";                       /* or "GetObject" */
opts.identity        = resolved_identity;
opts.etag_flags      = BRIX_ETAG_WEAK;            /* or 0 */
opts.pre_header_send = my_checksum_header_hook;     /* or NULL */
opts.pre_header_ud   = my_ctx;

ngx_int_t rc = brix_http_serve_file_ranged(r, fh, &vst, fs_path, &opts, &res);
/* DO NOT close fh here — already closed. Bump your own metrics from
 * res.range_result / res.bytes_sent. */
```

`rc` is `NGX_OK`, `NGX_ERROR`, or an HTTP status code (`416`, `500`); feed it
straight back as the handler's return value.

**Add a wire-driven allocation safely.** Replace `ngx_palloc(pool, n * sizeof(*p))`
with `brix_palloc_array(pool, n, sizeof(*p))` (or `brix_pcalloc_array` for
zeroed, `brix_alloc_array(log, …)` for heap/stream-lifetime), and check for
`NULL`. For a bare size computation feeding something else, use
`brix_size_mul`/`brix_size_add` and check the `NGX_OK`/`NGX_ERROR` return
before reading `*out`.

**Where new shared helpers belong.** Put logic here only when ≥2 protocol
subsystems need it and it carries no protocol-specific policy. Anything with
auth, path, or metric-label semantics stays in the owning subsystem and is wired
to by these helpers, not absorbed into them. New shared `.c` files must be added
to `config` (`NGX_ADDON_SRCS`); header-only helpers need no registration.

## See also

- [`../README.md`](../README.md) — master subsystem index.
- [`../webdav/README.md`](../webdav/README.md) — WebDAV `GET` caller of `file_serve.c`.
- [`../s3/README.md`](../s3/README.md) — S3 `GetObject` caller of `file_serve.c`.
- [`../compat/README.md`](../compat/README.md) — `range.h` / `http_file_response.h` (range parse + header/body send).
- [`../fs/README.md`](../fs/README.md) — VFS handle/stat types and accessors.
- [`../cache/README.md`](../cache/README.md) — cache-backed handles + `evict_candidates.c` (safe_size consumer).
- [`../read/README.md`](../read/README.md) — `readv.c` segment array (safe_size consumer).
- [`../dashboard/README.md`](../dashboard/README.md) — live transfer tracking hooks.
- [`../path/README.md`](../path/README.md) — path confinement that precedes every serve.
