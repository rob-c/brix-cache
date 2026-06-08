# Phase 4: Cache Unification - Implementation Plan

**Status:** PLANNING  
**Phase:** 4 of 6 (Protocol Unification)  
**Depends On:** Phase 3 (VFS Operation Abstraction)  
**Estimated Effort:** 12-16 hours  
**Risk Level:** HIGH (cache correctness is critical for data integrity)  
**Target:** A single cache access path invoked transparently by `xrootd_vfs_open()` for all three protocols

---

## Executive Summary

After Phase 3, all protocols open files through `xrootd_vfs_open()`. This phase makes the cache layer fully transparent inside that call — no protocol handler needs to know whether a file comes from cache or origin. It also unifies the writethrough decision logic (currently duplicated between stream and WebDAV) and gives the eviction policy a single view of all cached content regardless of which protocol placed it there.

Currently:
- Stream reads go through `src/read/open_cache.c` → `src/cache/open_or_fill.c`
- WebDAV reads bypass the cache entirely unless TPC writethrough is involved
- S3 reads have no cache integration at all

The target is: **one cache, three entry points, zero protocol-specific cache code**.

---

## Current State Analysis

### Existing Cache Subsystem (`src/cache/`)

| File | Purpose |
|:---|:---|
| `open_or_fill.c` | Main entry: open cached file or fill from origin |
| `fetch.c` | Origin fetch (pulls data, writes to cache root) |
| `io.c` | Cached read — maps to `aio/read.c` on the cache root |
| `lock.c` | Per-file cache lock (prevents concurrent fill races) |
| `paths.c` | Translate a logical path to its cache root path |
| `evict_policy.c` | LRU / LFU eviction candidate selection |
| `evict_candidates.c` | Walk cache root, find eviction candidates |
| `thread.c` | Background eviction thread |
| `errors.c` | Cache-specific error codes |
| `writethrough_decision.c` | Decide if a write should be cached |
| `writethrough_flush.c` | Flush writethrough data to origin |
| `origin_connection.c` | Open connection to origin (XRootD upstream) |
| `origin_protocol.c` | Protocol for origin fetch |
| `origin_response.c` | Parse origin response, write to cache file |
| `cache_internal.h` | Internal types |

### Stream Cache Path (Current)

```
src/read/open_cache.c
  → xrootd_cache_open_or_fill()      -- in src/cache/open_or_fill.c
    → cache lock acquire             -- src/cache/lock.c
    → check cache path exists        -- src/cache/paths.c
    → if miss: origin fetch          -- src/cache/fetch.c
    → open cached fd                 -- src/cache/io.c
```

### WebDAV Cache Path (Current)

- **Reads:** No cache integration. `src/webdav/get.c` opens the origin path directly.
- **Writes (TPC only):** `src/webdav/tpc.c` calls `src/cache/writethrough_decision.c` to decide whether to write through, then `writethrough_flush.c`.

### S3 Cache Path (Current)

None. `src/s3/object.c` opens the origin path directly every time.

---

## Target Architecture

### Cache as a VFS-Layer Concern

After Phase 3, `xrootd_vfs_open()` calls a new internal function:

```c
// Inside src/fs/vfs_open.c (Phase 3):
static ngx_int_t
vfs_open_with_cache(xrootd_vfs_ctx_t *ctx, ngx_uint_t flags,
                    xrootd_vfs_file_t *fh)
{
    if (flags & XROOTD_VFS_O_NOCACHE) {
        return vfs_open_origin(ctx, flags, fh);
    }

    // Phase 4: unified cache lookup
    return xrootd_cache_open(ctx, flags, fh);
}
```

The `xrootd_cache_open()` function in `src/cache/open.c` (new file) replaces the stream-specific `src/read/open_cache.c`.

### New and Modified Cache Files

```
src/cache/
  open.c              — NEW: xrootd_cache_open() (replaces open_cache.c in stream)
  open.h              — NEW: public header
  writethrough.h      — NEW: unified writethrough decision header
  ... (existing files unchanged internally)
```

### `src/cache/open.c` — Unified Entry Point

```c
/*
 * xrootd_cache_open()
 *
 * WHAT: Protocol-agnostic cache open. Checks for a valid cached copy;
 *       fills from origin if missing; returns a ready-to-read fd.
 * WHY:  Centralizes all cache hit/miss logic. Every protocol benefits from
 *       the cache without protocol-specific code.
 * HOW:
 *   1. Map logical path → cache path (src/cache/paths.c)
 *   2. Acquire per-file lock (src/cache/lock.c)
 *   3. If cache file exists and is valid → open it, set fh->from_cache=1
 *   4. If miss → origin fetch (src/cache/fetch.c), then re-open
 *   5. Release lock, return NGX_OK
 */
ngx_int_t xrootd_cache_open(xrootd_vfs_ctx_t *ctx,
                             ngx_uint_t flags,
                             xrootd_vfs_file_t *fh);
```

### Writethrough Unification

Currently `src/cache/writethrough_decision.c` is only reachable from the WebDAV TPC path. After Phase 4 it is called by `xrootd_vfs_write()` for **all** write operations:

```c
// Inside src/fs/vfs_write.c (extended in Phase 4):
if (xrootd_cache_should_writethrough(ctx, offset, length)) {
    rc = xrootd_cache_writethrough(fh, offset, in);
    if (rc != NGX_OK) { /* log, fall through to origin write */ }
}
rc = vfs_write_origin(fh, offset, in, result);
```

`xrootd_cache_should_writethrough()` is a thin wrapper over `writethrough_decision.c`, now exposed via `src/cache/writethrough.h`.

---

## Cache Validity Model

The cache currently validates entries by checking file existence and comparing size/mtime against origin metadata. This model must be extended for HTTP and S3 semantics:

| Protocol | Cache Freshness Signal |
|:---|:---|
| XRootD Stream | mtime comparison via `kXR_stat` to origin |
| WebDAV | HTTP `ETag` / `Last-Modified` from origin (add to cache metadata) |
| S3 | `ETag` (MD5 of content) from origin HEAD response |

### New Cache Metadata Sidecar: `<hash>.meta`

Alongside each cached file `<hash>` store a small sidecar `<hash>.meta`:

```
# Binary format (fixed 64-byte header + variable ETag)
uint64_t  mtime;         // POSIX mtime at fill time
uint64_t  size;          // File size at fill time
uint8_t   etag_len;      // ETag string length (0 if not present)
char      etag[55];      // ETag (truncated to 55 bytes)
```

`src/cache/paths.c` gains `xrootd_cache_meta_path()`. `open.c` reads the sidecar to validate freshness before opening the cached data file.

---

## Eviction Policy Integration

The existing eviction policy (`src/cache/evict_policy.c`) tracks access via a background thread. After Phase 4 it is the single source of eviction signals — receiving access events from all three protocols:

```c
// Called inside xrootd_vfs_read() after a cache hit (Phase 3 hook):
xrootd_cache_record_access(ctx->resolved.resolved.data,
                            result.length,
                            ctx->log);
```

Previously only stream reads contributed to eviction accounting. WebDAV and S3 reads will now extend TTL of cached objects they serve.

---

## Origin Protocol Abstraction

`src/cache/origin_protocol.c` currently speaks the XRootD protocol to fetch missing content from a redirector or storage node. For WebDAV and S3 protocols, the origin may also speak HTTP or S3. This requires a thin dispatch:

```c
// src/cache/origin_protocol.c (extended):
typedef enum {
    XROOTD_CACHE_ORIGIN_XROOTD = 0,
    XROOTD_CACHE_ORIGIN_HTTP,
    XROOTD_CACHE_ORIGIN_S3
} xrootd_cache_origin_proto_t;

ngx_int_t xrootd_cache_fetch(xrootd_vfs_ctx_t *ctx,
                              xrootd_cache_origin_proto_t proto,
                              const ngx_str_t *cache_path);
```

The origin protocol is determined by the nginx config directive `xrootd_cache_origin_protocol [xrootd|http|s3]` (new directive, registered in `src/config/config.h`).

---

## File Inventory

### New files
| File | Purpose |
|:---|:---|
| `src/cache/open.c` | Unified cache open — replaces `src/read/open_cache.c` |
| `src/cache/open.h` | Public header for `xrootd_cache_open()` |
| `src/cache/writethrough.h` | Public header exposing writethrough decision |
| `src/cache/meta.c` | Read/write `.meta` sidecar files |
| `src/cache/meta.h` | Public header for cache metadata |

### Modified files
| File | Change |
|:---|:---|
| `src/cache/open_or_fill.c` | Rename/refactor into `open.c`; remove stream-specific context |
| `src/cache/paths.c` | Add `xrootd_cache_meta_path()` |
| `src/cache/evict_policy.c` | Accept access events from all protocols |
| `src/cache/origin_protocol.c` | Add HTTP and S3 origin fetch dispatch |
| `src/cache/writethrough_decision.c` | Accept `xrootd_vfs_ctx_t *` (was stream-specific) |
| `src/fs/vfs_open.c` | Call `xrootd_cache_open()` (Phase 4 hook) |
| `src/fs/vfs_write.c` | Call `xrootd_cache_should_writethrough()` |
| `src/fs/vfs_read.c` | Call `xrootd_cache_record_access()` on cache hit |
| `src/read/open_cache.c` | **Removed** — replaced by `src/cache/open.c` |
| `src/config/config.h` | Add `src/cache/open.c`, `src/cache/meta.c` to `NGX_ADDON_SRCS`; new `xrootd_cache_origin_protocol` directive |

---

## Testing Strategy

### Unit Tests (extend `tests/test_cache.py`)

1. **Cache miss → fill → hit**: First read fills cache; second read is served from cache (`result.from_cache=1`).
2. **Stale entry**: Modify origin file; cache entry must be invalidated on next access.
3. **Concurrent fill race**: Two simultaneous cache misses for same file — only one fill should occur (lock test).
4. **Eviction**: Fill cache to capacity; oldest entry evicted automatically.
5. **Meta sidecar**: Verify `.meta` written on fill; verify ETag stored and checked on re-access.
6. **Writethrough**: Write via VFS; verify origin file updated.

### Cross-Protocol Cache Tests

- File placed in cache via stream `kXR_read` → served from cache on WebDAV GET (`from_cache=1` in access log).
- File placed in cache via WebDAV GET → served from cache on S3 GetObject.
- Cache eviction triggered by one protocol correctly evicts files cached by another.

### Data Integrity Tests

- Read 1 GB file via all three protocols from cache; SHA-256 checksums must match origin.
- pgread over cached file: CRC32c per page must match CRC32c computed directly from origin.

---

## Risk Assessment

| Risk | Mitigation |
|:---|:---|
| Cache lock contention under high concurrency | Existing lock implementation uses per-inode locks; verify scalability with load test |
| ETag mismatch causes spurious cache invalidation | Only invalidate if mtime AND size both mismatch; ETag is advisory |
| S3/HTTP origin fetch not yet implemented | Gate behind feature flag `xrootd_cache_origin_protocol`; default=xrootd (existing behavior) |
| Writethrough double-write on error | Writethrough is best-effort; origin write is authoritative; cache failure is logged, not fatal |
| `.meta` sidecar corruption | Treat any unreadable meta as a cache miss; re-fill |

---

## Completion Criteria

- [ ] `src/cache/open.c` exists; `src/read/open_cache.c` removed
- [ ] `xrootd_vfs_open()` calls `xrootd_cache_open()` for all protocols (no `XROOTD_VFS_O_NOCACHE`)
- [ ] WebDAV GET served from cache for files previously fetched by stream — `from_cache=1` in log
- [ ] S3 GetObject served from cache — `from_cache=1` in log
- [ ] Cache eviction access events received from all three protocols
- [ ] `.meta` sidecar written and validated on every cache fill
- [ ] Writethrough triggered by VFS write for all protocols (not just WebDAV TPC)
- [ ] Data integrity test: 1 GB file, all three protocols, SHA-256 match
- [ ] `make -j$(nproc)` clean with no warnings
