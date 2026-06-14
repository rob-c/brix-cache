# Phase 26 — Sub-request Slicing & Slice-Granular Caching

**Status:** Draft — 2026-06-11  
**Effort:** Large (≈ 1,800 LoC new, ≈ 350 LoC integration changes)  
**Depends on:** existing cache layer (`src/cache/`), Phase 3 (path resolution)  
**Optional:** Phase 20 (SHM KV store) for in-progress slice-fill tracking across workers

---

## Motivation

The existing cache layer fetches **whole files** from the XRootD origin before serving the
first byte to the client.  For multi-GiB ROOT files this creates three problems:

1. **Time-to-first-byte**: a 10 GiB file must fully download before any byte is served.
2. **Partial reads are wasteful**: a HEP analysis job reading only the TKey index
   (typically the first ~32 MiB of a ROOT file) triggers a 10 GiB origin transfer.
3. **Failure blast radius**: any transient error during a multi-GiB fetch invalidates
   everything; the next client restarts from byte 0.

The fix is to cache files in fixed-size **slices** (e.g. 128 MiB) independently under their
own paths.  A kXR_read or HTTP GET for bytes 0–200 MiB requires only slices 0 and 1 to be
present.  Slices 2–79 can be filling in the background (or never fetched at all).

**Shared abstraction:** the slice enumeration and path-generation logic is shared between
the HTTP/WebDAV plane (WebDAV GET handler) and the XRootD stream plane (kXR_read handler).
No separate implementation per protocol.

---

## Architecture Overview

```
                 ┌──────────────────────────────────────────────────┐
                 │               src/cache/slice.h / slice.c         │
                 │  xrootd_slice_t, xrootd_slice_enumerate(),        │
                 │  xrootd_slice_path(), xrootd_slice_meta_*()       │
                 └────────────┬──────────────────┬───────────────────┘
                              │                  │
              ┌───────────────▼──┐       ┌───────▼─────────────────┐
              │ src/webdav/get.c  │       │  src/read/read.c        │
              │ HTTP GET handler  │       │  kXR_read handler       │
              │ (slice-aware)     │       │  (slice-aware)          │
              └───────────────┬──┘       └───────┬─────────────────┘
                              │                  │
              ┌───────────────▼──────────────────▼─────────────────┐
              │             src/cache/slice_fill.c                  │
              │  xrootd_slice_fill_schedule()                        │
              │  (thread pool, reuses origin_protocol.c primitives) │
              └─────────────────────────────────────────────────────┘
                              │
              ┌───────────────▼──────────────────────────────────────┐
              │  Origin XRootD: kXR_open → kXR_read(offset,rlen) → kXR_close  │
              └──────────────────────────────────────────────────────┘
```

### Slice file naming convention

```
<cache_root>/<path>.__xrds_<SLICE_KiB>k_<IDX>
```

Examples with `xrootd_cache_slice 128m` (131072 KiB) for `/store/atlas/run3.root`:

| Slice index | Byte range | Cache path |
|---|---|---|
| 0 | 0 – 134217727 | `.../store/atlas/run3.root.__xrds_131072k_0` |
| 1 | 134217728 – 268435455 | `.../store/atlas/run3.root.__xrds_131072k_1` |
| N | N·size – (N+1)·size−1 | `.../store/atlas/run3.root.__xrds_131072k_N` |

The slice size is encoded in the filename.  Changing `xrootd_cache_slice` automatically
invalidates all existing slices (they have different names and will not be found by
`xrootd_cache_file_ready()`).

A **file-level meta file** (reusing `xrootd_cache_meta_t` format) tracks the origin file's
etag, mtime, and size to detect file changes between slice fills:

```
<cache_root>/<path>.__xrds_meta
```

In-progress and lock files for each slice follow the existing patterns:

```
<cache_path>.__xrds_131072k_N.ngx-xrootd-part   ← in-progress fill
<cache_path>.__xrds_131072k_N.ngx-xrootd-lock   ← O_EXCL fill serialisation lock
```

---

## Step A — Shared Slice Library

**New files:** `src/cache/slice.h`, `src/cache/slice.c`

### `src/cache/slice.h`

```c
#ifndef XROOTD_CACHE_SLICE_H
#define XROOTD_CACHE_SLICE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "../cache/meta.h"

/*
 * xrootd_slice_t — one slice covering part of a requested byte range.
 *
 * file_start / file_end: byte positions in the origin file (file_end exclusive).
 * req_start  / req_end:  intersection with the client's requested range (exclusive).
 * path:                  absolute path to the slice cache file.
 * ready:                 1 = file exists and is complete (xrootd_cache_file_ready).
 */
typedef struct {
    off_t  file_start;
    off_t  file_end;
    off_t  req_start;
    off_t  req_end;
    char   path[PATH_MAX];
    int    ready;
} xrootd_slice_t;

/*
 * xrootd_slice_path — build the absolute path for one slice.
 *
 * cache_root:   the xrootd_cache_root value (e.g. /data/cache)
 * cache_path:   the resolved cache path for the whole file
 *               (from xrootd_cache_path_for_resolved)
 * slice_size:   slice size in bytes
 * slice_idx:    0-based slice index
 * out / outsz:  caller-supplied buffer for the result path
 *
 * Returns NGX_OK or NGX_ERROR (path too long).
 */
ngx_int_t xrootd_slice_path(const char *cache_path, size_t slice_size,
    ngx_uint_t slice_idx, char *out, size_t outsz);

/*
 * xrootd_slice_enumerate — find all slices covering [req_start, req_end).
 *
 * On return, out[0..nout-1] are the covering slices in ascending order;
 * each has .ready set to xrootd_cache_file_ready() result.
 *
 * Returns NGX_OK if at least one slice was found; NGX_ERROR on bad args.
 */
ngx_int_t xrootd_slice_enumerate(const char *cache_path, off_t file_size,
    size_t slice_size, off_t req_start, off_t req_end,
    xrootd_slice_t *out, ngx_uint_t max_out, ngx_uint_t *nout);

/*
 * xrootd_slice_meta_path — path for the file-level meta file.
 * out = cache_path + ".__xrds_meta"
 */
ngx_int_t xrootd_slice_meta_path(const char *cache_path,
    char *out, size_t outsz);

/*
 * xrootd_slice_meta_validate — check that a cached meta matches origin.
 *
 * Reads the meta file and compares etag (if non-empty) and size.
 * Returns:
 *   NGX_OK       — meta matches (or no meta yet — caller treats as unknown)
 *   NGX_DECLINED — mismatch: file changed at origin; all slices are stale
 *   NGX_ERROR    — I/O error reading meta file
 */
ngx_int_t xrootd_slice_meta_validate(const char *cache_path,
    off_t origin_size, const char *origin_etag, ngx_log_t *log);

/*
 * xrootd_slice_meta_write — persist file-level meta after first slice fill.
 */
ngx_int_t xrootd_slice_meta_write(const char *cache_path,
    off_t origin_size, const char *origin_etag, uint64_t mtime,
    ngx_log_t *log);

#endif /* XROOTD_CACHE_SLICE_H */
```

### `src/cache/slice.c` — key implementation

```c
ngx_int_t
xrootd_slice_path(const char *cache_path, size_t slice_size,
    ngx_uint_t slice_idx, char *out, size_t outsz)
{
    int n = snprintf(out, outsz, "%s.__xrds_%zuk_%u",
                     cache_path, slice_size / 1024, (unsigned) slice_idx);
    if (n < 0 || (size_t) n >= outsz) return NGX_ERROR;
    return NGX_OK;
}

ngx_int_t
xrootd_slice_enumerate(const char *cache_path, off_t file_size,
    size_t slice_size, off_t req_start, off_t req_end,
    xrootd_slice_t *out, ngx_uint_t max_out, ngx_uint_t *nout)
{
    ngx_uint_t  first_idx, last_idx, i, n;
    off_t        fs_start, fs_end;

    if (req_start < 0 || req_end <= req_start || slice_size == 0) {
        return NGX_ERROR;
    }

    /* Clamp to file size if known. */
    if (file_size > 0 && req_end > file_size) {
        req_end = file_size;
    }

    first_idx = (ngx_uint_t) (req_start / (off_t) slice_size);
    last_idx  = (ngx_uint_t) ((req_end - 1) / (off_t) slice_size);

    n = 0;
    for (i = first_idx; i <= last_idx && n < max_out; i++) {

        fs_start = (off_t) i * (off_t) slice_size;
        fs_end   = fs_start + (off_t) slice_size;
        if (file_size > 0 && fs_end > file_size) {
            fs_end = file_size;
        }

        out[n].file_start = fs_start;
        out[n].file_end   = fs_end;
        out[n].req_start  = (req_start > fs_start) ? req_start : fs_start;
        out[n].req_end    = (req_end   < fs_end)   ? req_end   : fs_end;

        if (xrootd_slice_path(cache_path, slice_size, i,
                              out[n].path, sizeof(out[n].path)) != NGX_OK) {
            return NGX_ERROR;
        }

        out[n].ready = xrootd_cache_file_ready(out[n].path);
        n++;
    }

    *nout = n;
    return (n > 0) ? NGX_OK : NGX_ERROR;
}
```

---

## Step B — Slice Fill from Origin

**New file:** `src/cache/slice_fill.c`  
**New header additions in:** `src/cache/cache_internal.h`

The existing `xrootd_cache_fill_t` fetches an entire file.  The slice fill context adds
`slice_start` and `slice_size` to constrain origin reads to the slice window:

```c
/* Add to cache_internal.h alongside xrootd_cache_fill_t */
typedef struct {
    /* Shares the same thread-pool infrastructure as xrootd_cache_fill_t. */
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;    /* NULL for HTTP-triggered fills */
    ngx_stream_xrootd_srv_conf_t  *conf;
    u_char   streamid[2];
    char     clean_path[PATH_MAX];
    char     cache_path[PATH_MAX];    /* whole-file cache path (for meta) */
    char     slice_path[PATH_MAX];    /* this slice's cache file path */
    char     slice_part[PATH_MAX];    /* slice_path + PART_SUFFIX */
    char     slice_lock[PATH_MAX];    /* slice_path + LOCK_SUFFIX */
    off_t    slice_start;             /* byte offset in origin file */
    off_t    slice_size;              /* byte count to fetch */
    int      result;
    int      xrd_error;
    int      sys_errno;
    char     err_msg[256];
} xrootd_slice_fill_t;
```

### `xrootd_slice_fill_schedule()`

```c
/*
 * Schedule an async slice fill.  Called from the main nginx event loop.
 *
 * for_stream:  1 = called from kXR_read dispatch (stream ctx available)
 *              0 = called from WebDAV GET handler (HTTP request pool)
 *
 * On success returns NGX_OK; the fill runs in the thread pool.
 * The completion callback posts a notification back to the event loop,
 * which then wakes the suspended connection (kXR_waitresp / subrequest resume).
 */
ngx_int_t xrootd_slice_fill_schedule(
    ngx_pool_t *pool, ngx_log_t *log,
    ngx_thread_pool_t *tp,
    const char *clean_path, const char *cache_path, const char *slice_path,
    off_t slice_start, off_t slice_size,
    ngx_event_handler_pt on_complete, void *on_complete_data);
```

### Thread worker — `xrootd_slice_fill_worker()`

```c
static void
xrootd_slice_fill_worker(void *data, ngx_log_t *log)
{
    xrootd_slice_fill_t       *t = data;
    xrootd_cache_origin_conn_t conn;
    u_char fhandle[4];
    off_t  origin_size;
    char   etag[XROOTD_CACHE_META_ETAG_MAX];
    int    lock_owned = 0;
    int    fd = -1;
    off_t  pos, remaining, chunk;
    char   buf[XROOTD_CACHE_FETCH_CHUNK];  /* 1 MiB stack buffer */

    ngx_memzero(&conn, sizeof(conn));

    /* Claim the O_EXCL lock for this slice, or wait for another worker. */
    if (xrootd_cache_lock_or_wait(t->slice_lock, t->slice_path, log,
                                  &lock_owned) != 0)
    {
        t->result   = 1;
        t->xrd_error = kXR_FileLocked;
        return;
    }

    if (!lock_owned) {
        /* Another worker filled this slice while we waited — success. */
        t->result = 0;
        return;
    }

    /* Bootstrap XRootD connection and open the file. */
    if (xrootd_cache_origin_bootstrap(&conn, t->conf, log) != 0) {
        goto fail;
    }

    etag[0] = '\0';
    if (xrootd_cache_origin_open(&conn, t->clean_path, fhandle,
                                  &origin_size, etag, sizeof(etag), log) != 0)
    {
        goto fail;
    }

    /* Validate consistency with existing file-level meta (if any). */
    if (xrootd_slice_meta_validate(t->cache_path, origin_size, etag, log)
        == NGX_DECLINED)
    {
        /* File changed at origin — invalidate all sibling slices. */
        xrootd_slice_evict_all(t->cache_path, log);
        xrootd_slice_meta_write(t->cache_path, origin_size, etag, 0, log);
    }

    /* Open the part file for writing. */
    fd = open(t->slice_part, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        goto fail;
    }

    /* Read exactly [slice_start, slice_start + slice_size) from origin.
     * Stop at EOF (origin_size) — the last slice may be shorter. */
    pos       = t->slice_start;
    remaining = ngx_min(t->slice_size, origin_size - t->slice_start);

    while (remaining > 0) {
        chunk = ngx_min((off_t) sizeof(buf), remaining);

        /* kXR_read(fhandle, offset=pos, rlen=chunk) → buf */
        if (xrootd_cache_origin_read_chunk(&conn, fhandle, pos,
                                           (uint32_t) chunk, buf, log) != 0)
        {
            goto fail;
        }

        if (write(fd, buf, (size_t) chunk) != (ssize_t) chunk) {
            goto fail;
        }

        pos       += chunk;
        remaining -= chunk;
    }

    close(fd);  fd = -1;

    /* Atomic promotion: part → final slice path. */
    if (rename(t->slice_part, t->slice_path) != 0) {
        goto fail;
    }

    xrootd_cache_origin_close_file(&conn, fhandle, log);

    /* Write file-level meta if not yet present. */
    xrootd_slice_meta_write(t->cache_path, origin_size, etag, 0, log);

    unlink(t->slice_lock);
    t->result = 0;
    return;

fail:
    if (fd >= 0) close(fd);
    unlink(t->slice_part);
    unlink(t->slice_lock);
    t->result    = 1;
    t->xrd_error = kXR_IOError;
}
```

**Key reuse:** `xrootd_cache_origin_bootstrap`, `xrootd_cache_origin_open`, and
`xrootd_cache_origin_close_file` are called unchanged from `origin_protocol.c`.
The only new primitive is `xrootd_cache_origin_read_chunk(conn, fhandle, offset, rlen, buf, log)`
— a thin wrapper around the existing kXR_read wire call that already handles
big-endian encoding and response parsing.  The existing whole-file fill loop in
`origin_protocol.c` uses this same call internally.

---

## Step C — WebDAV GET Slice Serving

**Modified file:** `src/webdav/get.c`

When `conf->cache_slice_size > 0` and the cache is enabled, replace the existing
single-file `xrootd_cache_file_ready()` check with the slice-aware path:

```c
/* In webdav_handle_get(), after resolve_path and stat: */
if (conf->cache_root_canon[0] != '\0' && conf->cache_slice_size > 0) {
    return webdav_get_slice(r, conf, path, &sb, wctx);
}
/* else: existing whole-file cache path (unchanged) */
```

### `webdav_get_slice()` — new function in `get.c`

```c
static ngx_int_t
webdav_get_slice(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    const char *path, struct stat *sb,
    ngx_http_xrootd_webdav_req_ctx_t *wctx)
{
    char            cache_path[PATH_MAX];
    off_t           req_start, req_end, file_size;
    xrootd_slice_t  slices[XROOTD_SLICE_MAX_PER_REQUEST];
    ngx_uint_t      nslices, i;
    ngx_chain_t    *head, **tail, *cl;
    ngx_buf_t      *b;
    ngx_fd_t        fd;

    file_size = sb->st_size;

    /* Derive the whole-file cache path; slice paths are built from it. */
    if (xrootd_cache_path_for_resolved(conf->cache_root_canon,
                                       conf->common.root_canon, path,
                                       cache_path, sizeof(cache_path)) != NGX_OK)
    {
        goto fallthrough;  /* fall back to whole-file path */
    }

    /* Parse client Range header; default to full file. */
    req_start = 0;
    req_end   = file_size;
    webdav_parse_range(r, file_size, &req_start, &req_end);

    if (xrootd_slice_enumerate(cache_path, file_size,
                               conf->cache_slice_size,
                               req_start, req_end,
                               slices, XROOTD_SLICE_MAX_PER_REQUEST,
                               &nslices) != NGX_OK)
    {
        goto fallthrough;
    }

    /* Check for any missing slices — schedule fills for them. */
    for (i = 0; i < nslices; i++) {
        if (!slices[i].ready) {
            return webdav_get_slice_with_fill(r, conf, path, cache_path,
                                              slices, nslices, i, wctx);
        }
    }

    /* All slices cached — stitch response chain from cache files. */
    head = NULL;
    tail = &head;

    for (i = 0; i < nslices; i++) {
        fd = open(slices[i].path, O_RDONLY);
        if (fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          "slice cache open failed: %s", slices[i].path);
            goto fallthrough;
        }

        /*
         * Position within the slice file: req_start is relative to the
         * origin file; subtract slice's file_start to get the fd offset.
         */
        off_t slice_fd_start = slices[i].req_start - slices[i].file_start;
        off_t slice_len      = slices[i].req_end - slices[i].req_start;

        b = ngx_pcalloc(r->pool, sizeof(*b));
        if (b == NULL) { close(fd); return NGX_ERROR; }

        ngx_file_t *f = ngx_pcalloc(r->pool, sizeof(*f));
        if (f == NULL) { close(fd); return NGX_ERROR; }

        f->fd     = fd;
        f->offset = slice_fd_start;
        f->log    = r->connection->log;

        b->file        = f;
        b->file_pos    = slice_fd_start;
        b->file_last   = slice_fd_start + slice_len;
        b->in_file     = 1;
        b->last_in_chain = (i == nslices - 1) ? 1 : 0;
        b->last_buf      = (i == nslices - 1) ? 1 : 0;

        /* TLS connections must use memory-backed buffers (INVARIANT 2). */
        if (r->connection->ssl) {
            u_char *mem = ngx_palloc(r->pool, (size_t) slice_len);
            if (mem == NULL) { close(fd); return NGX_ERROR; }
            if (pread(fd, mem, (size_t) slice_len, slice_fd_start)
                != (ssize_t) slice_len)
            {
                close(fd); goto fallthrough;
            }
            close(fd);
            b->pos    = b->start = mem;
            b->last   = b->end   = mem + slice_len;
            b->memory = 1;
            b->in_file = 0;
        } else {
            webdav_register_send_fd_cleanup(r, fd, slices[i].path);
        }

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) return NGX_ERROR;
        cl->buf  = b;
        cl->next = NULL;
        *tail    = cl;
        tail     = &cl->next;
    }

    r->headers_out.status            = (req_start > 0 || req_end < file_size)
                                       ? NGX_HTTP_PARTIAL_CONTENT
                                       : NGX_HTTP_OK;
    r->headers_out.content_length_n  = req_end - req_start;
    xrootd_rl_charge_bytes(zone, rule, wctx->rl_key_str,
                           (size_t)(req_end - req_start));

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || r->header_only) return rc;
    return ngx_http_output_filter(r, head);

fallthrough:
    /* Fall back to whole-file path (downloads full file to cache). */
    return webdav_handle_get_whole_file(r, conf, path, sb, wctx);
}
```

### Missing slice handling — suspend and fill

When one or more required slices are missing, we cannot serve the request synchronously
(the fill must run in the thread pool).  The pattern mirrors the existing
`xrootd_cache_open_or_fill()` approach:

```c
static ngx_int_t
webdav_get_slice_with_fill(ngx_http_request_t *r, ...,
    ngx_uint_t first_missing_idx)
{
    /*
     * Schedule fills for all missing slices in the thread pool.
     * Each fill is independent — slices may arrive out of order.
     * The first missing slice suspends this request; completion
     * callback resumes it via r->main->blocked / ngx_http_run_posted_requests.
     */
    for (i = first_missing_idx; i < nslices; i++) {
        if (slices[i].ready) continue;

        xrootd_slice_fill_schedule(
            r->pool, r->connection->log,
            conf->common.thread_pool,
            path, cache_path, slices[i].path,
            slices[i].file_start,
            slices[i].file_end - slices[i].file_start,
            webdav_slice_fill_done, r);
    }

    r->main->blocked++;  /* suspend: don't finalise the request */
    return NGX_DONE;
}

/* Completion callback — runs on main event loop thread. */
static void
webdav_slice_fill_done(void *data)
{
    ngx_http_request_t *r = data;
    r->main->blocked--;
    /* Re-enter the GET handler — slices will now be ready. */
    ngx_http_run_posted_requests(r->connection);
}
```

### Slice prefetch

When serving slice N from cache, proactively schedule fills for slices N+1 … N+P
(where P = `xrootd_cache_slice_prefetch` directive value, default 1).  Prefetch fills
use the same `xrootd_slice_fill_schedule()` but with a NULL `on_complete` callback —
they fire and forget:

```c
/* After the slice-hit response is built, before sending headers: */
for (p = 1; p <= conf->cache_slice_prefetch; p++) {
    next_idx = last_served_idx + p;
    if (xrootd_slice_path(cache_path, conf->cache_slice_size,
                          next_idx, prefetch_path, sizeof(prefetch_path)) != NGX_OK)
        break;
    if (!xrootd_cache_file_ready(prefetch_path)) {
        xrootd_slice_fill_schedule(r->pool, r->connection->log,
            conf->common.thread_pool,
            path, cache_path, prefetch_path,
            next_idx * conf->cache_slice_size,
            conf->cache_slice_size,
            NULL, NULL);  /* fire-and-forget */
    }
}
```

---

## Step D — XRootD Stream (kXR_read) Slice Serving

**Modified file:** `src/read/read.c`

The stream handler has `ctx->files[idx]` (an open fd from `kXR_open`) and `offset` + `rlen`
from the wire request.  When slice caching is enabled, kXR_read is intercepted:

```c
/* In xrootd_handle_read(), after parsing offset/rlen: */
if (conf->common.cache_root_canon[0] != '\0'
    && conf->common.cache_slice_size > 0
    && ctx->files[idx].cache_path[0] != '\0')
{
    return xrootd_read_from_slices(ctx, c, conf, idx, offset, rlen);
}
/* else: existing direct pread path (unchanged) */
```

### `xrootd_read_from_slices()` — new function in `read.c`

```c
static ngx_int_t
xrootd_read_from_slices(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf,
    int idx, off_t offset, size_t rlen)
{
    xrootd_file_t  *file = &ctx->files[idx];
    xrootd_slice_t  slices[XROOTD_SLICE_MAX_PER_REQUEST];
    ngx_uint_t      nslices, i;

    if (xrootd_slice_enumerate(file->cache_path, file->size,
                               conf->common.cache_slice_size,
                               offset, offset + rlen,
                               slices, XROOTD_SLICE_MAX_PER_REQUEST,
                               &nslices) != NGX_OK)
    {
        /* Fall through to direct pread. */
        return xrootd_read_direct(ctx, c, conf, idx, offset, rlen);
    }

    /* If any required slice is missing, send kXR_wait and schedule fill. */
    for (i = 0; i < nslices; i++) {
        if (!slices[i].ready) {
            xrootd_slice_fill_schedule(
                c->pool, c->log,
                conf->common.thread_pool,
                file->clean_path, file->cache_path, slices[i].path,
                slices[i].file_start,
                slices[i].file_end - slices[i].file_start,
                NULL, NULL);  /* fill proceeds; client retries after wait */

            /* Estimate fill time: 1 second per 100 MiB at typical origin speed. */
            uint32_t wait_sec = (uint32_t) ngx_max(1,
                (slices[i].file_end - slices[i].file_start)
                / (100 * 1024 * 1024));

            XROOTD_OP_METRIC_INC(XROOTD_OP_CACHE_MISS);
            return xrootd_send_wait(ctx, c, wait_sec);
        }
    }

    /* All slices ready — stitch pread results into one response. */
    size_t total = (size_t) (offset + rlen > file->size
                             ? file->size - offset : rlen);
    u_char *buf = ngx_alloc(total, c->log);
    if (buf == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "slice read alloc");
    }

    u_char *ptr = buf;
    for (i = 0; i < nslices; i++) {
        int    sfd  = open(slices[i].path, O_RDONLY);
        off_t  soff = slices[i].req_start - slices[i].file_start;
        size_t slen = (size_t) (slices[i].req_end - slices[i].req_start);

        if (sfd < 0 || pread(sfd, ptr, slen, soff) != (ssize_t) slen) {
            if (sfd >= 0) close(sfd);
            ngx_free(buf);
            return xrootd_send_error(ctx, c, kXR_IOError, "slice pread");
        }
        close(sfd);
        ptr += slen;
    }

    ngx_int_t rc = xrootd_send_ok(ctx, c, buf, (uint32_t) total);
    ngx_free(buf);

    /* Schedule prefetch for subsequent slices. */
    xrootd_stream_slice_prefetch(ctx, c, conf, file, slices, nslices);

    return rc;
}
```

**Memory note:** The `ngx_alloc(total, c->log)` above allocates from the heap (not pool)
because the total can be multi-MiB (e.g. a 256 MiB kXR_read spanning two 128 MiB slices).
`ngx_free(buf)` is called immediately after `xrootd_send_ok` copies the data into the send
buffer chain.  This is the same pattern used by the existing pgread handler for large
checksummed reads.

---

## Step E — ETag / File-Change Consistency

The file-level meta file (`.__xrds_meta`) is written by the first successful slice fill.
Subsequent fills validate against it before writing data.  This catches the common HEP
failure mode where a file is repacked at the origin mid-transfer.

### What happens when the origin file changes

1. Fill worker calls `xrootd_slice_meta_validate()`.
2. If etag or size differs: `xrootd_slice_evict_all()` deletes all slice files for this
   path (glob `path.__xrds_*`) and writes the new meta.
3. Fills continue with the new version's data.
4. In-flight clients that already received partial data from old slices will get a
   corrupted assembly.  This is detected at the application layer (ROOT file checksum
   or CMS data integrity check).  The gateway cannot guarantee consistency once a file
   changes at the origin mid-transfer — the same behaviour as a standard HTTP cache
   that receives a 304 race between two requests.

**Mitigation:** emit an nginx error log entry at `NGX_LOG_WARN` whenever
`xrootd_slice_evict_all()` is called, including the path and old/new etag.  The
`cache_slice_etag_mismatch_total` metric increments.  Operators can alert on this.

---

## Step F — Configuration Directives

**Added to `src/config/config.h`** (both HTTP loc conf and stream srv conf):

```c
size_t     cache_slice_size;      /* NGX_CONF_UNSET_SIZE; 0 = disabled */
ngx_uint_t cache_slice_prefetch;  /* NGX_CONF_UNSET_UINT; default 1   */
ngx_msec_t cache_slice_fill_timeout_ms;  /* default 30000              */
```

**New directives in `src/config/directives.c`:**

```nginx
# Slice size — must be a multiple of XROOTD_CACHE_FETCH_CHUNK (1 MiB).
# 0 (default) = whole-file mode (current behaviour).
xrootd_cache_slice 128m;

# Number of future slices to prefetch speculatively when serving a slice hit.
# 0 = no prefetch.
xrootd_cache_slice_prefetch 1;

# Maximum time to wait for a slice fill before returning an error.
# Applies to the HTTP suspended-request path only; stream uses kXR_wait instead.
xrootd_cache_slice_fill_timeout 30s;
```

**Validation in `ngx_conf_check_cmd_type`:**
- `cache_slice_size` must be 0 or ≥ `XROOTD_CACHE_FETCH_CHUNK` (1 MiB) and a multiple of it.
- `cache_slice_prefetch` must be 0–8.

### Full nginx.conf example

```nginx
http {
    server {
        listen 8443 ssl;
        location / {
            xrootd_webdav on;
            xrootd_cache_root /data/cache;
            xrootd_cache_slice 128m;          # 128 MiB slices
            xrootd_cache_slice_prefetch 2;    # fetch N+1, N+2 ahead
            xrootd_cache_slice_fill_timeout 30s;
        }
    }
}

stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_cache_root /data/cache;
        xrootd_cache_slice 128m;
        xrootd_cache_slice_prefetch 1;
    }
}
```

---

## Step G — Metrics

**New Prometheus counters** in `src/metrics/metrics.h`:

```c
ngx_atomic_t  cache_slice_hit_total;          /* slices served from cache      */
ngx_atomic_t  cache_slice_miss_total;         /* slices that required fill     */
ngx_atomic_t  cache_slice_fill_active;        /* fills in-progress (gauge)     */
ngx_atomic_t  cache_slice_etag_mismatch_total; /* origin file changed mid-fill  */
```

Exported in `src/metrics/cache.c`:

```
# HELP xrootd_cache_slice_hit_total Slice reads served entirely from local cache
# TYPE xrootd_cache_slice_hit_total counter
xrootd_cache_slice_hit_total 18247

# HELP xrootd_cache_slice_miss_total Slice reads that triggered an origin fetch
# TYPE xrootd_cache_slice_miss_total counter
xrootd_cache_slice_miss_total 341

# HELP xrootd_cache_slice_fill_active Concurrent slice fills in progress
# TYPE xrootd_cache_slice_fill_active gauge
xrootd_cache_slice_fill_active 3

# HELP xrootd_cache_slice_etag_mismatch_total Files that changed at origin mid-fill
# TYPE xrootd_cache_slice_etag_mismatch_total counter
xrootd_cache_slice_etag_mismatch_total 0
```

---

## Step H — Eviction Integration

`src/cache/evict_candidates.c` currently enumerates files under `cache_root` and returns
those that exceed their TTL.  It must be updated to treat slice files and the meta file
as a unit:

- When evicting slice 2 of a file, add the remaining slices (0, 1, 3, …) and the
  `.__xrds_meta` file to a "paired eviction" list.
- Eviction of any one slice file triggers eviction of the whole slice set for that file
  to prevent serving a partial slice set after the eviction run.
- The existing `XROOTD_CACHE_EVICT_LOCK_NAME` directory lock prevents concurrent evictions.

The `xrootd_slice_evict_all()` function (introduced in Step B) is reused here.

---

## Step I — Interaction with nginx's Native `ngx_http_slice_module`

nginx's built-in `slice` directive + `proxy_cache` is a common deployment pattern for
content-addressed storage.  For completeness, this is how the two approaches relate:

| | This plan (`xrootd_cache_slice`) | nginx `slice` + `proxy_cache` |
|---|---|---|
| Cache location | Local filesystem under `xrootd_cache_root` | nginx's native proxy cache (shared memory + files) |
| Cache key | Path + slice index (deterministic filename) | `$uri$slice_range` (nginx variable) |
| Origin protocol | XRootD wire protocol (kXR_read) | HTTP proxy |
| ETag validation | File-level `.__xrds_meta` file | nginx `proxy_cache_valid` + If-None-Match |
| XRootD stream | Shared via `xrootd_slice_enumerate()` | Not applicable |
| Subrequests | No (in-handler stitching) | Yes (`NGX_HTTP_SUBREQUEST_CLONE`) |

Using both at the same time is not supported.  If `xrootd_cache_slice > 0`, the module
bypasses the whole-file cache check before nginx's proxy layer can intercept.

---

## New Source Files

| File | LoC | Purpose |
|---|---|---|
| `src/cache/slice.h` | 80 | Public API and `xrootd_slice_t` struct |
| `src/cache/slice.c` | 160 | `xrootd_slice_path`, `xrootd_slice_enumerate`, meta helpers |
| `src/cache/slice_fill.c` | 220 | Thread-pool fill worker + `xrootd_slice_fill_schedule` |

All 3 files must be added to `NGX_ADDON_SRCS` in `src/config/config.h`.

**Modified files:**

| File | Change |
|---|---|
| `src/webdav/get.c` | Add `webdav_get_slice()` and `webdav_get_slice_with_fill()` |
| `src/read/read.c` | Add `xrootd_read_from_slices()` and dispatch guard |
| `src/cache/cache_internal.h` | Add `xrootd_slice_fill_t` struct |
| `src/cache/evict_candidates.c` | Add paired-eviction logic for slice file sets |
| `src/cache/paths.c` | Add `xrootd_slice_evict_all()` (glob + unlink) |
| `src/config/config.h` | Add `cache_slice_size`, `cache_slice_prefetch`, `cache_slice_fill_timeout_ms` |
| `src/config/directives.c` | Parse new directives; validate slice_size is a multiple of 1 MiB |
| `src/metrics/metrics.h` | Add 4 new counters |
| `src/metrics/cache.c` | Export new Prometheus metrics |

---

## Invariants

1. **`XROOTD_SLICE_MAX_PER_REQUEST`** — cap at 16 slices per request (2 GiB max at 128 MiB
   slices).  Requests spanning more slices than this limit receive a 416 Range Not Satisfiable
   error.  HEP clients never request multi-GiB ranges in a single kXR_read or HTTP GET.

2. **Slice size must be a multiple of `XROOTD_CACHE_FETCH_CHUNK`** (1 MiB).  Enforced at
   config parse time.  Prevents the fill worker from reading a partial chunk at a slice
   boundary.

3. **Stream `kXR_wait` value is an estimate, not a guarantee.** The client may retry before
   the fill completes — it will receive another `kXR_wait`.  This converges because each
   retry re-checks `xrootd_cache_file_ready()` before computing a new wait.

4. **Prefetch fills are fire-and-forget.** If the prefetch thread pool queue is full,
   `xrootd_slice_fill_schedule` returns `NGX_AGAIN` and prefetch is skipped silently.
   This prevents prefetch from starving demand fills.

5. **TLS path must use memory-backed buffers** (INVARIANT 2 from CLAUDE.md).  The slice
   stitching loop in `webdav_get_slice()` reads slice data into heap memory for TLS
   connections; the `b->memory = 1` path is taken whenever `r->connection->ssl != NULL`.

6. **`xrootd_slice_evict_all()` uses a glob pattern**, not a directory scan, to avoid
   accidentally deleting files from adjacent directories.  Pattern:
   `<cache_path>.__xrds_*`.  Uses `glob(3)` (POSIX, available on Linux).

---

## Testing Requirements

**Per CLAUDE.md: 3 tests per change: success + error + security-neg**

```
tests/test_slice_cache.py::TestWebDAV::test_slice_cache_hit
    # seed slice 0; GET bytes 0-50MiB; verify 206 served from cache (no origin call)

tests/test_slice_cache.py::TestWebDAV::test_slice_cache_miss_then_fill
    # cold cache; GET bytes 0-50MiB on 128MiB slice; verify fill triggered, response correct

tests/test_slice_cache.py::TestWebDAV::test_slice_cache_prefetch
    # GET slice 0; verify slice 1 fill is scheduled (check cache dir for .__xrds_*_1 file)

tests/test_slice_cache.py::TestWebDAV::test_slice_etag_mismatch_invalidates
    # cache slice 0; modify file at origin (different etag); GET again;
    # verify old slices evicted, fresh data served

tests/test_slice_cache.py::TestWebDAV::test_slice_range_spanning_two_slices
    # GET Range: bytes=100m-300m on 128MiB slice file; verify data stitched correctly

tests/test_slice_cache.py::TestStream::test_kxr_read_slice_cache_hit
    # open file; kXR_read with offset in cached slice; verify pread from cache, no wait

tests/test_slice_cache.py::TestStream::test_kxr_read_slice_cache_miss_wait
    # cold cache; kXR_read; verify kXR_wait response with seconds > 0

tests/test_slice_cache.py::TestStream::test_kxr_read_resumes_after_fill
    # cold cache; kXR_read → kXR_wait; wait for fill; retry; verify data correct

tests/test_slice_cache.py::TestEviction::test_evict_removes_whole_slice_set
    # cache multiple slices; trigger eviction; verify all .__xrds_* files removed

tests/test_slice_cache.py::TestSecurity::test_slice_path_cannot_escape_cache_root
    # attempt path traversal in slice path; verify confined to cache_root
```

---

## Implementation Order

1. **Step A** — `slice.c` / `slice.h` (no dependencies; unit-testable standalone)
2. **Step B** — `slice_fill.c` + `xrootd_cache_origin_read_chunk` addition to `origin_protocol.c`
3. **Step F** — Config directives wired to new fields (enables integration testing)
4. **Step C** — WebDAV GET slice path (depends on A + B + F)
5. **Step D** — Stream kXR_read slice path (depends on A + B + F)
6. **Step E** — ETag validation + `xrootd_slice_evict_all` (depends on A + B)
7. **Step H** — Eviction integration (depends on A + E)
8. **Step G** — Metrics (no blockers; add after each step completes its callsites)
