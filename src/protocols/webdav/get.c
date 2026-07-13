/*
 * get.c - WebDAV GET with Range support, sendfile, and fd-cache fast path.
 */

#include "webdav.h"
#include "xrdhttp.h"
#include "core/compat/error_mapping.h"
#include "core/http/etag.h"
#include "core/http/http_conditionals.h"
#include "fs/cache/open.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "fs/vfs/vfs.h"
#include "protocols/shared/file_serve.h"
#include "protocols/shared/http_cache_fill.h"     /* phase-64 SP2: off-loop cache fill */
#include "protocols/shared/http_serve_offload.h"  /* phase-64 SP3: off-loop remote serve */
#include "protocols/root/zip/zip_http.h"   /* phase-57 W2: shared HTTP ZIP member serving */

/* GET range/bytes metrics — shared by the inline serve and the off-loop serve
 * completion (brix_http_serve_offload), so both report identically. */
static void
webdav_serve_metrics(ngx_http_request_t *r,
    const brix_http_serve_result_t *result)
{
    if (result->range_result == BRIX_SERVE_RANGE_UNSATISFIED) {
        BRIX_WEBDAV_METRIC_INC(range_total[BRIX_WEBDAV_RANGE_UNSATISFIED]);
    } else if (result->range_result == BRIX_SERVE_RANGE_PARTIAL) {
        BRIX_WEBDAV_METRIC_INC(range_total[BRIX_WEBDAV_RANGE_PARTIAL]);
    } else {
        BRIX_WEBDAV_METRIC_INC(range_total[BRIX_WEBDAV_RANGE_FULL]);
    }
    if (result->bytes_sent > 0) {
        BRIX_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) result->bytes_sent);
        if (r->connection && r->connection->sockaddr) {
            if (r->connection->sockaddr->sa_family == AF_INET6) {
                BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total,
                                         (size_t) result->bytes_sent);
            } else {
                BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total,
                                         (size_t) result->bytes_sent);
            }
        }
    }
}

/* Re-entry trampoline for the off-event-loop cache fill: after the fill lands the
 * completion event re-runs the GET handler, which now finds a cache HIT and serves
 * it zero-copy. The fill helper carries no per-handler state (the request re-
 * resolves from r), so `data` is unused. */
static ngx_int_t
webdav_get_reenter(ngx_http_request_t *r, void *data)
{
    (void) data;
    return webdav_handle_get(r);
}

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static ngx_int_t
webdav_register_send_fd_cleanup(ngx_http_request_t *r, ngx_fd_t fd,
    const char *path)
{
    ngx_pool_cleanup_t      *cln;
    ngx_pool_cleanup_file_t *clnf;
    size_t                   path_len;
    u_char                  *name;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    path_len = ngx_strlen(path);
    name = ngx_pnalloc(r->pool, path_len + 1);
    if (name == NULL) {
        return NGX_ERROR;
    }
    ngx_cpystrn(name, (u_char *) path, path_len + 1);

    cln->handler = ngx_pool_cleanup_file;
    clnf = cln->data;
    clnf->fd = fd;
    clnf->name = name;
    clnf->log = r->pool->log;

    return NGX_OK;
}

static void
webdav_get_add_xrdhttp_headers(ngx_http_request_t *r, ngx_fd_t fd,
    off_t file_size, void *ud)
{
    struct stat *sb = ud;
    webdav_fadvise_willneed(r->connection->log, fd, 0, (size_t) file_size);
    xrdhttp_add_checksum_header(r, fd, sb);
    xrdhttp_add_response_headers(r, r->headers_out.status);
}

/*
 * get_serve_state_t — the serve-ready handle + derived metadata produced by
 * the resolve/open phase and consumed by the serving phases.  It bundles the
 * open VFS handle with the POSIX-shaped stat (`sb`, used by the multipart and
 * pre-header paths), the VFS stat (`vst`, used by the ranged serve), and the
 * fd-cache bookkeeping (`from_cache`/`cache_path`) so the phase helpers take a
 * single explicit state object instead of a long parameter list.  It is filled
 * only when the resolve phase returns NGX_OK.
 */
typedef struct {
    brix_vfs_file_t *fh;           /* open handle (owned by the caller flow) */
    struct stat      sb;           /* POSIX stat for multipart/pre-header use */
    brix_vfs_stat_t  vst;          /* VFS stat for the ranged serve           */
    ngx_uint_t       from_cache;   /* fd came from the read-through cache tier */
    const char      *cache_path;   /* cache path for access accounting         */
} get_serve_state_t;

/*
 * get_zip_member_serve — Phase-57 W2 ZIP member access over HTTP GET.
 *
 * WHAT: when the location is a ZIP-archive export, serve the requested member
 *   of the archive at `path` rather than the whole archive file.
 * WHY: archive auth already ran in the access phase; a GET on a zip export
 *   selects one member by argument, and this must short-circuit the normal
 *   file-serving pipeline.
 * HOW: parse the member argument; a negative result is a malformed request
 *   (400), a positive result serves the member and yields a terminal status,
 *   and zero means "no member requested" — signalled by NGX_DECLINED so the
 *   caller falls through to the normal whole-file path.
 */
static ngx_int_t
get_zip_member_serve(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path)
{
    char member[WEBDAV_MAX_PATH];
    int  zr;

    if (!conf->zip_access) {
        return NGX_DECLINED;
    }

    zr = brix_zip_http_member_arg(r, member, sizeof(member));
    if (zr < 0) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (zr > 0) {
        return brix_zip_http_serve(r, conf->common.root_canon,
                                     conf->zip_cd_max_bytes, path, member);
    }
    return NGX_DECLINED;
}

/*
 * get_init_vfs_ctx — build the VFS context for the GET.
 *
 * WHAT: initialise `vctx` for a WebDAV read of `path`, bind the per-user
 *   backend credential / opt-in mint / delegation, and select the export's
 *   storage backend instance.
 * WHY: every downstream open/offload/fill step reaches storage through this
 *   context; assembling it in one place keeps the credential-binding order
 *   (cred → mint → deleg) explicit and identical to the historical flow.
 * HOW: detect TLS, init the context, then apply the three credential binders
 *   and the backend instance in sequence.  Pure setup, no I/O.
 */
static void
get_init_vfs_ctx(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_req_ctx_t *wctx, const char *path,
    brix_vfs_ctx_t *vctx)
{
    int is_tls = 0;
#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    brix_vfs_ctx_init(vctx, r->pool, r->connection->log,
        BRIX_PROTO_WEBDAV, conf->common.root_canon,
        conf->cache_root_canon, conf->common.allow_write, is_tls,
        (wctx != NULL) ? wctx->identity : NULL, path);
    brix_vfs_ctx_bind_backend_cred(vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    /* Phase-2 T9: opt-in minting for GSI/token identities that have no
     * pre-provisioned proxy. No-op unless a mint CA is configured. */
    brix_vfs_ctx_bind_backend_mint(vctx,
        &conf->common.storage_credential_mint_ca_cert,
        &conf->common.storage_credential_mint_ca_key,
        conf->common.storage_credential_mint_ttl);
    webdav_vfs_bind_deleg(r, conf, vctx);

    /* Route through the export's selected storage backend (NULL ⇒ default POSIX). */
    vctx->sd = brix_webdav_backend_instance(conf, r->connection->log);
}

/*
 * get_offload_or_fill — run the off-loop serve/fill fast paths.
 *
 * WHAT: give the socket-wire serve offload (SP3) and the remote cache-fill
 *   offload (SP2) a chance to handle the request off the event loop.
 * WHY: a root://-backed or remote-store export cannot open/read on the worker
 *   loop, and a remote cache MISS fill would stall it; both are pushed to the
 *   thread pool and completed (or re-entered) asynchronously.
 * HOW: returns NGX_DONE when a path took over (async in flight), a terminal
 *   HTTP status on error, or NGX_DECLINED when neither applies and the caller
 *   should open inline.  EACCES/EPERM from the offload is the per-user backend
 *   credential gate → 403; any other offload error → 500.
 */
static ngx_int_t
get_offload_or_fill(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_req_ctx_t *wctx, const char *path,
    brix_vfs_ctx_t *vctx)
{
    const char             *identity =
        (wctx != NULL && wctx->dn[0] != '\0') ? wctx->dn : "anonymous";
    brix_http_serve_opts_t  sopts;
    ngx_int_t               sr;
    ngx_int_t               fr;

    ngx_memzero(&sopts, sizeof(sopts));
    sopts.xfer_proto = BRIX_XFER_PROTO_WEBDAV;
    sopts.op_name    = "GET";
    sopts.identity   = identity;
    sopts.etag_flags = BRIX_ETAG_WEAK;
    sopts.compress   = conf->common.compress;

    sr = brix_http_serve_offload_remote(r, vctx->sd,
        brix_vfs_export_relative(vctx, path), path, &sopts,
        &conf->common, vctx, webdav_serve_metrics);
    if (sr == NGX_DONE) {
        return NGX_DONE;
    }
    if (sr == NGX_ERROR) {
        return (errno == EACCES || errno == EPERM)
               ? NGX_HTTP_FORBIDDEN : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    fr = brix_http_cache_fill_if_needed(r, vctx->sd,
        brix_vfs_export_relative(vctx, path), &conf->common,
        webdav_get_reenter, NULL);
    if (fr == NGX_DONE) {
        return NGX_DONE;
    }
    if (fr == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return NGX_DECLINED;
}

/*
 * get_open_map_error — map a failed VFS open to its terminal HTTP status.
 *
 * WHAT: translate `vfs_err` from a NULL `brix_vfs_open` into the exact response
 *   the historical inline code produced.
 * WHY: the open error mapping carries security-load-bearing decisions
 *   (confinement rejections are 403, never 500) and a special-cased 202 tape
 *   recall — keeping it in one helper preserves those byte-for-byte.
 * HOW: early-return per errno class: ENOENT/ENOTDIR/ENAMETOOLONG → 404 (with
 *   xrdhttp headers), confinement/permission (EACCES/EPERM/EXDEV/ELOOP) → 403,
 *   EAGAIN → 202 + Retry-After, otherwise log and route through the shared
 *   errno→status table.
 */
static ngx_int_t
get_open_map_error(ngx_http_request_t *r, int vfs_err, const char *path)
{
    ngx_table_elt_t *ra;

    if (vfs_err == ENOENT || vfs_err == ENOTDIR
        || vfs_err == ENAMETOOLONG)
    {
        xrdhttp_add_response_headers(r, NGX_HTTP_NOT_FOUND);
        return NGX_HTTP_NOT_FOUND;
    }

    /* EXDEV (".." escape) / ELOOP (escaping or magic symlink) are the
     * kernel RESOLVE_BENEATH confinement rejections — forbidden, never a
     * 500.  EACCES/EPERM map the same way.  Route the whole errno set
     * through the shared table so the codes stay consistent with S3. */
    if (vfs_err == EACCES || vfs_err == EPERM
        || vfs_err == EXDEV || vfs_err == ELOOP)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    /* EAGAIN ⇒ a nearline (tape) recall is in flight (sd_frm/sd_cache, §9.2).
     * Answer 202 "staging" with a Retry-After so the client polls until the
     * object is recalled into the cache tier and served — never block the
     * worker for a minutes-to-hours MSS recall. */
    if (vfs_err == EAGAIN) {
        ra = ngx_list_push(&r->headers_out.headers);
        if (ra != NULL) {
            ra->hash = 1;
            ngx_str_set(&ra->key, "Retry-After");
            ngx_str_set(&ra->value, "10");
        }
        r->headers_out.status           = NGX_HTTP_ACCEPTED;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, vfs_err,
                  ngx_open_file_n " \"%s\" failed", path);
    return (ngx_int_t) brix_http_errno_to_status(vfs_err);
}

/*
 * get_resolve_and_stat — open the target and produce serve-ready state.
 *
 * WHAT: open `path` through the VFS, stat it, reject directories, and populate
 *   `st` (open handle + POSIX stat + VFS stat + fd-cache bookkeeping).
 * WHY: the serving phases need an open, statted, non-directory regular-file
 *   handle plus the derived metadata; concentrating open+stat+validation here
 *   keeps the orchestrator flat and each error path owning its own close.
 * HOW: open (mapping any failure via get_open_map_error), stat (500 on
 *   failure), directory guard (403), then fill `st.sb` from the VFS stat and
 *   capture the sendfile fd cache bookkeeping.  Returns NGX_OK with `st`
 *   populated and the handle open, or a terminal status with nothing to close.
 */
static ngx_int_t
get_resolve_and_stat(ngx_http_request_t *r, brix_vfs_ctx_t *vctx,
    const char *path, get_serve_state_t *st)
{
    int vfs_err = 0;

    st->fh = brix_vfs_open(vctx, BRIX_VFS_O_READ, &vfs_err);
    if (st->fh == NULL) {
        return get_open_map_error(r, vfs_err, path);
    }

    if (brix_vfs_file_stat(st->fh, &st->vst) != NGX_OK) {
        brix_vfs_close(st->fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (st->vst.is_directory) {
        brix_vfs_close(st->fh, r->connection->log);
        return NGX_HTTP_FORBIDDEN;
    }

    ngx_memzero(&st->sb, sizeof(st->sb));
    st->sb.st_size  = st->vst.size;
    st->sb.st_mtime = st->vst.mtime;
    st->sb.st_ctime = st->vst.ctime;
    st->sb.st_mode  = (mode_t) st->vst.mode;
    st->sb.st_ino   = st->vst.ino;

    /* Zero-copy (sendfile) serve fd, gated on the backend's CAP_SENDFILE; a
     * non-sendfile backend returns NGX_INVALID_FILE and the dup in the
     * multirange path fails closed instead of serving a bogus descriptor. */
    st->from_cache = brix_vfs_file_from_cache(st->fh);
    st->cache_path = brix_vfs_file_path(st->fh);
    return NGX_OK;
}

/*
 * get_serve_range — serve a multi-range (multipart/byteranges) GET.
 *
 * WHAT: handle the XrdHttp multi-range vector read by duplicating the sendfile
 *   fd, registering its cleanup, and delegating to the multipart handler.
 * WHY: multi-range is the kXR_readv-over-HTTP path; the TLS-memory vs
 *   cleartext-sendfile split lives inside xrdhttp_handle_multipart_get and is
 *   FROZEN — this helper only owns the dup + cleanup + cache accounting around
 *   it.  The dup lets the multipart handler own an independent fd while the VFS
 *   handle is closed here.
 * HOW: dup the sendfile fd (500 on failure), register a pool cleanup that owns
 *   the dup, close the VFS handle, run the multipart serve, and record cache
 *   access on a successful full body.
 */
static ngx_int_t
get_serve_range(ngx_http_request_t *r, get_serve_state_t *st, const char *path)
{
    ngx_fd_t  fd;
    ngx_fd_t  send_fd;
    ngx_int_t rc;

    fd = brix_vfs_file_sendfile_fd(st->fh);

    send_fd = dup(fd);
    if (send_fd == NGX_INVALID_FILE) {
        brix_vfs_close(st->fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (webdav_register_send_fd_cleanup(r, send_fd, path) != NGX_OK) {
        ngx_close_file(send_fd);
        brix_vfs_close(st->fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    brix_vfs_close(st->fh, r->connection->log);

    rc = xrdhttp_handle_multipart_get(r, send_fd, &st->sb, 1);
    if (st->from_cache && rc == NGX_OK && !r->header_only) {
        (void) brix_cache_record_access(st->cache_path,
                    (size_t) st->sb.st_size, r->connection->log);
    }
    return rc;
}

/*
 * get_eval_conditionals — apply the If-Modified-Since precondition.
 *
 * WHAT: evaluate the conditional GET via the shared eval and, on a 304, emit
 *   the not-modified response.
 * WHY: a matching precondition must short-circuit the serve with an empty 304
 *   body; the check owns closing the VFS handle on every terminal outcome.
 * HOW: NGX_HTTP_NOT_MODIFIED → close, send 304 headers + special last; any
 *   other non-OK → close and propagate; NGX_OK → return NGX_OK (handle stays
 *   open for the serve phase).
 */
static ngx_int_t
get_eval_conditionals(ngx_http_request_t *r, get_serve_state_t *st)
{
    ngx_int_t rc = brix_http_check_if_modified_since(r, st->sb.st_mtime);

    if (rc == NGX_HTTP_NOT_MODIFIED) {
        brix_vfs_close(st->fh, r->connection->log);
        r->headers_out.status           = NGX_HTTP_NOT_MODIFIED;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }
    if (rc != NGX_OK) {
        brix_vfs_close(st->fh, r->connection->log);
        return rc;
    }
    return NGX_OK;
}

/*
 * get_serve_full — serve the file with single-range (206) / full (200) body.
 *
 * WHAT: run the shared ranged file serve and report the range/bytes metrics.
 * WHY: this is the common whole-file / single-range path; the TLS-memory vs
 *   cleartext-sendfile split is FROZEN inside brix_http_serve_file_ranged.
 * HOW: enable byte ranges, build the serve opts (weak ETag, compress flag,
 *   xrdhttp pre-header hook carrying `sb`), serve, then feed the result to the
 *   shared metrics reporter.
 */
static ngx_int_t
get_serve_full(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_req_ctx_t *wctx, get_serve_state_t *st,
    const char *path)
{
    const char              *identity =
        (wctx != NULL && wctx->dn[0] != '\0') ? wctx->dn : "anonymous";
    brix_http_serve_opts_t   opts;
    brix_http_serve_result_t result;
    ngx_int_t                rc;

    r->allow_ranges = 1;

    ngx_memzero(&opts, sizeof(opts));
    opts.xfer_proto      = BRIX_XFER_PROTO_WEBDAV;
    opts.op_name         = "GET";
    opts.identity        = identity;
    opts.etag_flags      = BRIX_ETAG_WEAK;
    opts.compress        = conf->common.compress;
    opts.pre_header_send = webdav_get_add_xrdhttp_headers;
    opts.pre_header_ud   = &st->sb;

    rc = brix_http_serve_file_ranged(r, st->fh, &st->vst, path, &opts, &result);
    webdav_serve_metrics(r, &result);
    return rc;
}

/*
 * webdav_handle_get — serve a file via HTTP GET with Range support.
 *
 * Fast path: if the fd-cache already holds an open fd for the requested URI
 * hash, the stat and open system calls are skipped entirely.  The cached fd
 * remains owned by the fd-cache; the cleanup handler registered below uses
 * NGX_INVALID_FILE so it does not close it a second time.
 *
 * Range handling: a single "bytes=start-end" or "bytes=-suffix" range is
 * parsed and served as 206 Partial Content.  Multi-range requests and
 * overlapping ranges are not supported; clients that send them receive the
 * full file (200 OK).
 *
 * ngx_http_send_header + r->header_only: after calling ngx_http_send_header(),
 * always check r->header_only.  If true, the client sent HEAD — return
 * immediately without sending a body.  The check inside the serve phases
 * handles this.
 *
 * Pool allocation: ngx_pcalloc(r->pool, ...) for ngx_buf_t and ngx_file_t —
 *   both are freed when the request pool is destroyed after the response
 *   is sent.
 *
 * Ownership of fd:
 *   - If fd came from the fd-cache (fd_from_table=1), the cleanup handler
 *     stores NGX_INVALID_FILE so the fd-cache retains ownership.
 *   - If fd was opened here (fd_from_table=0), the cleanup handler closes it.
 *
 * Flow: resolve path → (zip member?) → build VFS ctx → off-loop serve/fill →
 * open+stat (get_resolve_and_stat) → multi-range (get_serve_range) or
 * conditional (get_eval_conditionals) + full/single-range (get_serve_full).
 */
ngx_int_t
webdav_handle_get(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char                             path[WEBDAV_MAX_PATH];
    ngx_int_t                        rc;
    ngx_http_brix_webdav_req_ctx_t  *wctx;
    brix_vfs_ctx_t                   vctx;
    get_serve_state_t                st = {0};

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon, path,
                                             sizeof(path));
    if (rc != NGX_OK) {
        return rc;
    }

    /* Phase-57 W2: ZIP member access over HTTP GET.  Auth on the archive ran in
     * the access phase; serve the requested member instead of the whole file. */
    rc = get_zip_member_serve(r, conf, path);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    get_init_vfs_ctx(r, conf, wctx, path, &vctx);

    /* phase-64 SP3/SP2: socket-wire serve offload and remote cache-fill offload
     * (both off the event loop).  NGX_DONE ⇒ async took over; a terminal HTTP
     * status ⇒ error; NGX_DECLINED ⇒ open inline below. */
    rc = get_offload_or_fill(r, conf, wctx, path, &vctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = get_resolve_and_stat(r, &vctx, path, &st);
    if (rc != NGX_OK) {
        return rc;
    }

    /* XrdHttp: multi-range vector read (kXR_readv equivalent over HTTP).
     * A comma in the Range: value indicates multiple byte ranges — delegate
     * to the multipart/byteranges handler rather than the single-range path. */
    if (xrdhttp_request_is_multirange(r)) {
        return get_serve_range(r, &st, path);
    }

    rc = get_eval_conditionals(r, &st);
    if (rc != NGX_OK) {
        return rc;
    }

    return get_serve_full(r, conf, wctx, &st, path);
}
