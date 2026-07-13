/*
 * file_serve.c — shared HTTP file-body serving pipeline (WebDAV + S3).
 *
 * WHAT: Implements brix_http_serve_file_ranged(), the single code path that
 *       turns an already-open, already-stat'd VFS file handle into an HTTP
 *       response body. It parses the Range request header, emits the matching
 *       full-body / 206-partial / 416-unsatisfied response headers, fires the
 *       optional pre-header hook, opens a dashboard transfer record, dups the
 *       fd and streams the requested byte range, then records bytes-sent and
 *       cache-access accounting.
 *
 * WHY:  WebDAV GET (src/webdav/get.c) and S3 GetObject (src/s3/object.c) need
 *       byte-for-byte identical range handling, ETag/Last-Modified header
 *       emission, dashboard transfer tracking, and cache hit accounting. This
 *       file is the one authoritative implementation so both protocols stay
 *       consistent and bugfixes land once. Callers supply only protocol-specific
 *       knobs (op_name, xfer_proto, identity, ETag flags, pre-header hook) via
 *       brix_http_serve_opts_t and read back metric inputs via
 *       brix_http_serve_result_t.
 *
 * HOW:  Sequential phases over the supplied fh, orchestrated by
 *       brix_http_serve_file_ranged() and implemented in static helpers so the
 *       orchestrator reads as a flat sequence:
 *         1. range parse  — brix_http_parse_range() against vst->size; an
 *            unsatisfiable range short-circuits to a 416
 *            (serve_range_unsatisfiable, fh closed first).
 *         2. compress     — serve_try_compressed(): opt-in whole-object codec path
 *            that bypasses sendfile; returns SERVE_DONE when it handled the
 *            request, SERVE_CONTINUE otherwise.
 *         3. headers      — brix_http_set_file_headers() sets status,
 *            content-length, Content-Range, ETag/Last-Modified.
 *         4. dashboard    — brix_dashboard_http_start_identity() opens a READ
 *            transfer record for live monitoring.
 *         5. send         — serve_send_sendfile() dup()'s the sendfile-gated fd so
 *            the send owns its own descriptor, or serve_send_memory_backed() drives
 *            driver reads when the backend exposes no single sendfile fd; the VFS
 *            handle is closed immediately after the dup / at the boundary so the
 *            cache/handle slot is released before the (possibly slow) body streams.
 *         6. accounting   — on success serve_record_body_accounting() reports
 *            bytes_sent and, for cache-backed files, updates LRU/hit stats.
 *            header_only (HEAD) requests skip accounting.
 *       INVARIANT: fh is always closed inside this function (success or error);
 *       callers must never close it afterwards.
 *       INVARIANT 2 (TLS memory-backed vs cleartext file-backed/sendfile): the
 *       sendfile path (serve_send_sendfile) is zero-copy; the object/block
 *       backend path (serve_send_memory_backed) is memory-backed. The two never
 *       mix — the backend's sendfile-fd availability picks exactly one.
 */
#include "file_serve.h"
#include "core/http/http_file_response.h"
#include "core/http/http_compress.h"
#include "core/compat/range.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "observability/metrics/unified.h"    /* brix_metric_backend_bytes */
#include "fs/cache/open.h"
#include "protocols/webdav/webdav.h"          /* brix_tcp_congestion (webdav-owned directive) */
#include "protocols/root/connection/netopt.h"      /* brix_apply_tcp_congestion */

#include <unistd.h>

/* Outcome of the compression fast-path probe. SERVE_CONTINUE => fall through to
 * the uncompressed sendfile / memory-backed pipeline; SERVE_DONE => the request
 * was fully handled (headers + body emitted) and the orchestrator must return the
 * captured rc. */
typedef enum {
    SERVE_CONTINUE = 0,
    SERVE_DONE
} serve_disposition_t;

/*
 * serve_ctx_t — file-local bundle of the immutable serve inputs plus the
 * per-request byte range and cache attribution.
 *
 * WHAT: Threads the request, the vfs handle, the caller's opts/result, the
 *       stat, the backend attribution label, and (once resolved) the byte range
 *       and cache-origin flags through the static send helpers as one pointer.
 * WHY:  The send/accounting phases share the same six-plus inputs; passing them
 *       as a single const context keeps each helper's parameter list small
 *       (§8 explicit-data-flow: pass state, no new globals) instead of a long
 *       positional argument list.
 * HOW:  `r`, `fh`, `vst`, `fs_path`, `opts`, `result`, `backend_name` are set
 *       up-front by the orchestrator; `range_start`, `send_len`, `from_cache`,
 *       `cache_path` are filled once the range and backend fd are resolved.
 */
typedef struct {
    ngx_http_request_t           *r;
    brix_vfs_file_t              *fh;
    const brix_vfs_stat_t        *vst;
    const char                   *fs_path;
    const brix_http_serve_opts_t *opts;
    brix_http_serve_result_t     *result;
    const char                   *backend_name;
    off_t                         range_start;
    off_t                         send_len;
    ngx_uint_t                    from_cache;
    const char                   *cache_path;
} serve_ctx_t;

/* brix_serve_memory_backed — stream [start, start+len) of `fh` to the client by
 * reading through the storage driver into pool buffers and pushing them through
 * nginx's output filter. Used when the backend exposes no single sendfile fd —
 * an object/block backend (e.g. pblock) whose bytes span multiple block files,
 * which brix_http_send_file_range (a single in_file buffer) cannot serve. The
 * bytes still flow proto -> VFS -> driver, just memory-backed instead of
 * zero-copy. The driver preads run on the event loop; a thread-pool/AIO streaming
 * variant for very large objects is a follow-up. Returns the output-filter rc or
 * NGX_ERROR. The caller still owns closing `fh`. */
#define BRIX_SERVE_MEM_CHUNK  (256 * 1024)

static ngx_int_t
brix_serve_memory_backed(ngx_http_request_t *r, brix_vfs_file_t *fh,
    off_t start, off_t len)
{
    off_t     done = 0;
    ngx_int_t hrc;

    /* The response headers were set (set_file_headers) but not yet sent — the
     * sendfile path sends them inside send_file_range; do the same here. */
    hrc = ngx_http_send_header(r);
    if (hrc == NGX_ERROR || hrc > NGX_OK) {
        return hrc;
    }

    if (r->header_only || len <= 0) {
        ngx_buf_t   *b = ngx_calloc_buf(r->pool);
        ngx_chain_t  out;

        if (b == NULL) {
            return NGX_ERROR;
        }
        b->last_buf = 1;
        out.buf  = b;
        out.next = NULL;
        return ngx_http_output_filter(r, &out);
    }

    while (done < len) {
        size_t       want = (size_t) (len - done);
        u_char      *buf;
        ssize_t      n;
        ngx_buf_t   *b;
        ngx_chain_t  out;
        ngx_int_t    rc;

        if (want > BRIX_SERVE_MEM_CHUNK) {
            want = BRIX_SERVE_MEM_CHUNK;
        }
        buf = ngx_palloc(r->pool, want);
        if (buf == NULL) {
            return NGX_ERROR;
        }
        n = brix_vfs_file_pread(fh, buf, want, start + done);
        if (n <= 0) {
            return n < 0 ? NGX_ERROR : NGX_OK;   /* error / unexpected EOF */
        }

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
        b->pos      = buf;
        b->last     = buf + n;
        b->memory   = 1;
        b->flush    = 1;
        b->last_buf = (done + n >= len) ? 1 : 0;
        out.buf  = b;
        out.next = NULL;

        rc = ngx_http_output_filter(r, &out);
        if (rc == NGX_ERROR || rc > NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        done += n;
    }

    return NGX_OK;
}

/*
 * serve_apply_tcp_congestion — select the configured TCP congestion control on
 * this connection before the body is streamed.
 *
 * WHAT: Reads the webdav-owned brix_tcp_congestion directive from the location
 *       conf and, when set, applies it to the connection socket.
 * WHY:  This single site covers BOTH WebDAV GET and S3 GetObject (both delegate
 *       the body send here), so one apply governs every HTTP download regardless
 *       of which protocol handler opened the file. The directive is owned by the
 *       always-present webdav http module; reading its per-location conf applies
 *       the same sender-side policy (e.g. "bbr") uniformly.
 * HOW:  Empty value => kernel default (no syscall). r->connection is known
 *       non-NULL here (the orchestrator's contract guard ran first) but the fd
 *       may still be invalid, so both are re-checked before the setsockopt.
 */
static void
serve_apply_tcp_congestion(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *wconf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    if (wconf != NULL && wconf->tcp_congestion.len > 0
        && r->connection != NULL
        && r->connection->fd != (ngx_socket_t) -1)
    {
        brix_apply_tcp_congestion(r->connection->fd, wconf->tcp_congestion);
    }
}

/*
 * serve_range_unsatisfiable — emit a 416 Range Not Satisfiable and release fh.
 *
 * WHAT: Closes the vfs handle, records the UNSATISFIED range result, and sends a
 *       zero-length 416 response.
 * WHY:  An unsatisfiable Range short-circuits the whole pipeline: no dashboard
 *       record, no send, no accounting. Factoring it out keeps the orchestrator's
 *       success path flat.
 * HOW:  Mirrors the original inline block byte-for-byte — same status, same
 *       content_length_n=0, same send_header + send_special(NGX_HTTP_LAST).
 */
static ngx_int_t
serve_range_unsatisfiable(ngx_http_request_t *r, brix_vfs_file_t *fh,
    brix_http_serve_result_t *result)
{
    brix_vfs_close(fh, r->connection->log);
    result->range_result            = BRIX_SERVE_RANGE_UNSATISFIED;
    r->headers_out.status           = NGX_HTTP_RANGE_NOT_SATISFIABLE;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/*
 * serve_record_body_accounting — post-send bytes/metric/cache accounting.
 *
 * WHAT: Reports bytes_sent back to the caller, increments the per-backend read
 *       bytes metric, adds to the live dashboard transfer, and (for cache-backed
 *       files) records a cache access for LRU/hit stats.
 * WHY:  The sendfile, memory-backed and compressed send paths perform identical
 *       body accounting; one helper keeps them in lockstep so a change lands once.
 * HOW:  HEAD (header_only) requests never reach this — accounting is body-only.
 *       from_cache/cache_path are captured by the caller before the vfs handle is
 *       released, since every send path closes fh before the bytes are counted.
 */
static void
serve_record_body_accounting(const serve_ctx_t *sc, off_t bytes,
    ngx_uint_t from_cache, const char *cache_path)
{
    sc->result->bytes_sent = bytes;
    brix_metric_backend_bytes(sc->backend_name, BRIX_METRIC_OP_READ,
                                (size_t) bytes);
    brix_dashboard_http_add(sc->r, (ngx_atomic_int_t) bytes);

    if (from_cache && bytes > 0) {
        (void) brix_cache_record_access(cache_path, (size_t) bytes,
                                          sc->r->connection->log);
    }
}

/*
 * serve_try_compressed — opt-in whole-object outbound compression fast-path.
 *
 * WHAT: When compression is enabled for this location and Accept-Encoding names a
 *       codec we have for a whole-object non-HEAD GET of a compressible type,
 *       resolves the content-type, negotiates the codec, and (on a hit) streams
 *       the object read -> codec -> chunked output filter, closing fh and doing
 *       body accounting. On a codec miss it leaves everything untouched.
 * WHY:  This path bypasses sendfile, so isolating it keeps the uncompressed fast
 *       path (headers + sendfile / memory-backed) untouched for every other
 *       request and cuts the orchestrator's branch count.
 * HOW:  Returns SERVE_DONE with *rc set (request fully handled) when it took the
 *       compressed path — including the negotiate-time content-type resolution
 *       that primes the incompressible-MIME deny list — else SERVE_CONTINUE.
 */
static serve_disposition_t
serve_try_compressed(const serve_ctx_t *sc, ngx_uint_t range_present,
    ngx_int_t *rc)
{
    ngx_http_request_t           *r    = sc->r;
    brix_vfs_file_t              *fh   = sc->fh;
    const brix_vfs_stat_t        *vst  = sc->vst;
    const brix_http_serve_opts_t *opts = sc->opts;
    brix_codec_id_t  enc;
    ngx_fd_t         cfd, csend;
    off_t            bytes_out = 0;
    ngx_uint_t       from_cache;
    const char      *cache_path;

    if (!opts->compress) {
        return SERVE_CONTINUE;
    }

    /* Resolve the response content-type from the URI extension BEFORE
     * negotiating: the negotiator's incompressible-MIME deny list reads
     * r->headers_out.content_type, which nginx does NOT populate on request
     * entry (it is otherwise set later, inside set_file_headers). Without this,
     * content_type is empty at negotiate time and the deny list is dead code, so
     * already-compressed types (image, video, .gz, ...) get wastefully
     * re-compressed. Idempotent: set_file_headers' later call early-returns once
     * it is set. */
    (void) ngx_http_set_content_type(r);
    enc = brix_http_compress_negotiate(r, vst->size, range_present);
    if (enc == BRIX_CODEC_IDENTITY) {
        return SERVE_CONTINUE;
    }

    cfd        = brix_vfs_file_fd(fh);
    from_cache = brix_vfs_file_from_cache(fh);
    cache_path = brix_vfs_file_path(fh);
    csend = dup(cfd);
    if (csend == NGX_INVALID_FILE) {
        brix_vfs_close(fh, r->connection->log);
        *rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return SERVE_DONE;
    }
    (void) brix_dashboard_http_start_identity(r, sc->fs_path,
        opts->identity, "", opts->xfer_proto, BRIX_XFER_DIR_READ,
        opts->op_name, (int64_t) vst->size);
    brix_vfs_close(fh, r->connection->log);

    *rc = brix_http_send_file_compressed(r, csend, sc->fs_path, vst->size,
                                           enc, vst->mtime,
                                           opts->etag_flags, &bytes_out);
    if (*rc == NGX_ERROR || *rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        brix_dashboard_http_error(r, "serve_file_ranged: compress send failed");
        brix_dashboard_http_finish(r);
        return SERVE_DONE;
    }
    sc->result->range_result = BRIX_SERVE_RANGE_FULL;
    /* compressed bytes on wire */
    serve_record_body_accounting(sc, bytes_out, from_cache, cache_path);
    return SERVE_DONE;
}

/*
 * serve_send_memory_backed — memory-backed send path for backends with no single
 * sendfile fd (INVARIANT 2: memory-backed, never mixed with the sendfile path).
 *
 * WHAT: Streams [range_start, range_start+send_len) via driver reads (through
 *       brix_serve_memory_backed), closes fh, and on success does body accounting.
 * WHY:  An object/block backend whose bytes span multiple block files cannot be
 *       served by the single-in_file sendfile buffer; this path drives the driver
 *       preads instead. Splitting it keeps the orchestrator flat.
 * HOW:  sc->from_cache/cache_path are captured by the orchestrator before fh is
 *       released. Returns the send rc; HEAD requests skip accounting.
 */
static ngx_int_t
serve_send_memory_backed(const serve_ctx_t *sc)
{
    ngx_http_request_t *r  = sc->r;
    brix_vfs_file_t    *fh = sc->fh;
    ngx_int_t           rc;

    rc = brix_serve_memory_backed(r, fh, sc->range_start, sc->send_len);
    brix_vfs_close(fh, r->connection->log);
    if (rc == NGX_ERROR) {
        brix_dashboard_http_error(r,
            "serve_file_ranged: memory-backed send failed");
        brix_dashboard_http_finish(r);
        return rc;
    }
    if (!r->header_only) {
        serve_record_body_accounting(sc, sc->send_len, sc->from_cache,
                                     sc->cache_path);
    }
    brix_dashboard_http_finish(r);
    return rc;
}

/*
 * serve_send_sendfile — zero-copy sendfile send path (INVARIANT 2: cleartext
 * file-backed/sendfile, never mixed with the memory-backed path).
 *
 * WHAT: dup()'s the sendfile-gated fd so the send owns its own descriptor,
 *       releases the vfs handle, streams the byte range via
 *       brix_http_send_file_range, and on success does body accounting.
 * WHY:  The serve path is zero-copy; the send must own a private descriptor while
 *       the vfs handle (and its cache/handle slot) is released immediately so a
 *       slow client cannot pin it. Splitting it keeps the orchestrator flat.
 * HOW:  fd is the orchestrator's already-fetched sendfile fd (known !=
 *       NGX_INVALID_FILE). sc->from_cache/cache_path are captured before fh is
 *       released. Returns the send rc; HEAD requests skip accounting.
 */
static ngx_int_t
serve_send_sendfile(const serve_ctx_t *sc, ngx_fd_t fd)
{
    ngx_http_request_t *r  = sc->r;
    brix_vfs_file_t    *fh = sc->fh;
    ngx_fd_t            send_fd;
    ngx_int_t           rc;

    send_fd = dup(fd);
    if (send_fd == NGX_INVALID_FILE) {
        brix_vfs_close(fh, r->connection->log);
        brix_dashboard_http_error(r, "serve_file_ranged: dup failed");
        brix_dashboard_http_finish(r);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    brix_vfs_close(fh, r->connection->log);

    rc = brix_http_send_file_range(r, send_fd, sc->fs_path,
                                     sc->range_start, sc->send_len, 1);

    if (rc == NGX_ERROR) {
        brix_dashboard_http_error(r, "serve_file_ranged: send failed");
        brix_dashboard_http_finish(r);
        return rc;
    }

    if (r->header_only) {
        brix_dashboard_http_finish(r);
        return rc;
    }

    serve_record_body_accounting(sc, sc->send_len, sc->from_cache,
                                 sc->cache_path);
    return rc;
}

ngx_int_t
brix_http_serve_file_ranged(ngx_http_request_t *r,
    brix_vfs_file_t *fh, const brix_vfs_stat_t *vst,
    const char *fs_path, const brix_http_serve_opts_t *opts,
    brix_http_serve_result_t *result)
{
    brix_http_range_t  rng;
    off_t                range_end;
    ngx_fd_t             fd;
    ngx_int_t            rc;
    serve_ctx_t          sc;

    ngx_memzero(result, sizeof(*result));
    ngx_memzero(&sc, sizeof(sc));
    sc.r       = r;
    sc.fh      = fh;
    sc.vst     = vst;
    sc.fs_path = fs_path;
    sc.opts    = opts;
    sc.result  = result;

    /* The tcp-congestion apply below treats r->connection as possibly NULL,
     * making that nullability part of this function's contract — so every later
     * r->connection->log / ->fd use must sit behind one provable guard. A request
     * with no connection cannot be served; release the handle (NULL log =>
     * brix_vfs_close falls back to fh->log) and bail. */
    if (r->connection == NULL) {
        (void) brix_vfs_close(fh, NULL);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Backend attribution label — captured now because every send path below
     * releases the vfs handle before the bytes are counted. */
    sc.backend_name = brix_vfs_file_backend_name(fh);

    serve_apply_tcp_congestion(r);

    /* Phase 1: range parse */
    brix_http_parse_range(
        r->headers_in.range ? r->headers_in.range->value.data : NULL,
        r->headers_in.range ? r->headers_in.range->value.len  : 0,
        vst->size, &rng);

    if (rng.present && !rng.satisfiable) {
        return serve_range_unsatisfiable(r, fh, result);
    }

    sc.range_start       = rng.start;
    range_end            = rng.end;
    sc.send_len          = (vst->size > 0) ? (range_end - sc.range_start + 1) : 0;
    result->range_result = rng.present ? BRIX_SERVE_RANGE_PARTIAL
                                       : BRIX_SERVE_RANGE_FULL;

    /* Phase 1b (phase-42): outbound compression. Opt-in per location; only a
     * whole-object, non-HEAD GET of a compressible type whose Accept-Encoding
     * names a codec we have takes this path. It bypasses sendfile (read ->
     * codec -> chunked output filter), so the uncompressed fast path below is
     * untouched for every other request. */
    if (serve_try_compressed(&sc, rng.present, &rc) == SERVE_DONE) {
        return rc;
    }

    /* Phase 2: response headers */
    if (brix_http_set_file_headers(r, vst->mtime, vst->size, sc.send_len,
                                     NULL, opts->etag_flags,
                                     rng.present, sc.range_start, range_end)
        != NGX_OK)
    {
        brix_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (opts->pre_header_send != NULL) {
        opts->pre_header_send(r, brix_vfs_file_fd(fh), vst->size,
                              opts->pre_header_ud);
    }

    /* Phase 3: dashboard */
    (void) brix_dashboard_http_start_identity(r, fs_path,
        opts->identity, "",
        opts->xfer_proto, BRIX_XFER_DIR_READ, opts->op_name,
        (int64_t) sc.send_len);

    /* Phase 4: dup fd, release vfs handle, send. Use the sendfile-gated fd: the
     * serve path is zero-copy (sendfile for cleartext), so it requires a backend
     * that can back it. A non-sendfile backend returns NGX_INVALID_FILE here and
     * fails closed rather than dup'ing a bogus descriptor. */
    fd            = brix_vfs_file_sendfile_fd(fh);
    sc.from_cache = brix_vfs_file_from_cache(fh);
    sc.cache_path = brix_vfs_file_path(fh);

    /* A backend with no single sendfile fd (an object/block backend whose bytes
     * span multiple block files) is served memory-backed via driver reads. */
    if (fd == NGX_INVALID_FILE) {
        return serve_send_memory_backed(&sc);
    }

    /* Phase 5: post-send accounting is done inside the send helper. */
    return serve_send_sendfile(&sc, fd);
}
