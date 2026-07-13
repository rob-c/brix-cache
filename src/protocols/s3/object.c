#include "s3.h"
#include "usermeta.h"
#include "fs/cache/open.h"
#include "core/http/http_file_response.h"
#include "core/http/http_headers.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "fs/vfs/vfs.h"
#include "protocols/shared/file_serve.h"
#include "protocols/shared/http_cache_fill.h"     /* phase-64 SP2: off-loop cache fill */
#include "protocols/shared/http_serve_offload.h"  /* phase-64 SP3: off-loop remote serve */
#include "protocols/root/zip/zip_http.h"   /* phase-57 W2: ZIP member access over S3 GET */

/* GetObject range/bytes metrics — shared by the inline serve and the off-loop
 * serve completion (brix_http_serve_offload), so both report identically. */
static void
s3_serve_metrics(ngx_http_request_t *r,
    const brix_http_serve_result_t *result)
{
    if (result->range_result == BRIX_SERVE_RANGE_UNSATISFIED) {
        BRIX_S3_METRIC_INC(range_total[BRIX_S3_RANGE_UNSATISFIED]);
    } else if (result->range_result == BRIX_SERVE_RANGE_PARTIAL) {
        BRIX_S3_METRIC_INC(range_total[BRIX_S3_RANGE_PARTIAL]);
    } else {
        BRIX_S3_METRIC_INC(range_total[BRIX_S3_RANGE_FULL]);
    }
    if (result->bytes_sent > 0) {
        BRIX_S3_METRIC_ADD(bytes_tx_total, (size_t) result->bytes_sent);
        if (r->connection && r->connection->sockaddr
            && r->connection->sockaddr->sa_family == AF_INET6) {
            BRIX_S3_METRIC_ADD(bytes_tx_ipv6_total, (size_t) result->bytes_sent);
        } else {
            BRIX_S3_METRIC_ADD(bytes_tx_ipv4_total, (size_t) result->bytes_sent);
        }
    }
}

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * GET /bucket/key - file download with Range support
 * */

static void
s3_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, brix_vfs_ctx_t *vctx)
{
    ngx_http_s3_req_ctx_t *s3ctx;
    int                    is_tls = 0;

    s3ctx = ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(vctx, r->pool, r->connection->log, BRIX_PROTO_S3,
        cf->common.root_canon, cf->cache_root_canon, cf->common.allow_write,
        is_tls, (s3ctx != NULL) ? s3ctx->identity : NULL, fs_path);
    /* Data-plane GET: bind the export's per-user backend credential policy
     * (+ opt-in mint), mirroring s3_build_vfs_ctx (util.c, the PUT/POST-object
     * path) — without this, both the inline brix_vfs_open below AND the
     * off-loop brix_http_serve_offload_remote gate (which reads this bound
     * ctx) would silently use the shared service credential for every user
     * on a remote-backed export. */
    brix_vfs_ctx_bind_backend_cred(vctx,
        &cf->common.storage_credential_dir,
        cf->common.storage_credential_fallback);
    brix_vfs_ctx_bind_backend_mint(vctx,
        &cf->common.storage_credential_mint_ca_cert,
        &cf->common.storage_credential_mint_ca_key,
        cf->common.storage_credential_mint_ttl);
    s3_vfs_bind_deleg(r, cf, vctx);
}

/* Re-entry state for the off-event-loop cache fill: GetObject needs its absolute
 * fs_path + loc_conf to re-serve, so unlike WebDAV (which re-resolves from r) the
 * trampoline carries them. Both are copied onto r->pool so they outlive the
 * worker-thread fill. */
typedef struct {
    const char             *fs_path;
    ngx_http_s3_loc_conf_t *cf;
} s3_get_reenter_t;

static ngx_int_t
s3_get_reenter(ngx_http_request_t *r, void *data)
{
    s3_get_reenter_t *d = data;
    return s3_handle_get(r, d->fs_path, d->cf);
}

/*
 * WHAT: Serve a ZIP archive member when the export is configured for ZIP member
 *   access (xrdcl.unzip) — reads the requested member name from the request and
 *   streams that member out of the archive object.
 * WHY:  Phase-57 W2 folds ZIP member access into the S3 GET path; keeping it in a
 *   dedicated helper keeps the GET orchestrator flat. Auth/key resolution already
 *   happened in the dispatcher, so this only serves the member.
 * HOW:  Returns NGX_DECLINED when ZIP access is off or no member was requested so
 *   the caller falls through to the normal object serve. Otherwise it returns the
 *   terminal serve status (mapping a missing member to NoSuchKey 404) — the caller
 *   must return it verbatim.
 */
static ngx_int_t
s3_get_serve_zip_member(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf)
{
    char member[PATH_MAX];
    int  zr;

    if (!cf->zip_access) {
        return NGX_DECLINED;
    }

    zr = brix_zip_http_member_arg(r, member, sizeof(member));
    if (zr < 0) {
        return s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                                 "invalid xrdcl.unzip member");
    }
    if (zr == 0) {
        return NGX_DECLINED;
    }

    {
        ngx_int_t zs = brix_zip_http_serve(r, cf->common.root_canon,
                                             cf->zip_cd_max_bytes,
                                             fs_path, member);
        if (zs == NGX_HTTP_NOT_FOUND) {
            return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                           "The specified key does not exist.",
                           BRIX_S3_EVENT_NO_SUCH_KEY);
        }
        return zs;
    }
}

/*
 * WHAT: Reject a GET of a tape-resident (nearline/offline) object before any
 *   open/fill is attempted.
 * WHY:  S3/Glacier semantics require an explicit restore (the WLCG Tape REST API)
 *   before a nearline object can be read; faulting a recall on a plain GET is
 *   wrong. An export with no nearline tier reports ONLINE, so a plain disk/object
 *   export is unaffected.
 * HOW:  Returns NGX_DECLINED when the object is online (or residency is unknown);
 *   returns a terminal 403 InvalidObjectState the caller must return verbatim when
 *   the object is nearline/offline.
 */
static ngx_int_t
s3_get_check_residency(ngx_http_request_t *r, brix_vfs_ctx_t *vctx)
{
    brix_sd_residency_t res = BRIX_SD_RES_ONLINE;

    if (brix_vfs_residency(vctx, &res, NULL) == NGX_OK
        && (res == BRIX_SD_RES_NEARLINE || res == BRIX_SD_RES_OFFLINE))
    {
        return s3_fail(r, NGX_HTTP_FORBIDDEN, "InvalidObjectState",
            "The operation is not valid for the object's storage class.",
            BRIX_S3_EVENT_ACCESS_DENIED);
    }
    return NGX_DECLINED;
}

/*
 * WHAT: Run the off-event-loop remote serve for a socket-wire backend (a root://
 *   primary backend, or a cache_store/stage_store served from one).
 * WHY:  Such a backend cannot open/read on the event loop; the whole open+read
 *   must run off-loop, materialise, then sendfile (mirrors webdav/get.c).
 * HOW:  Returns NGX_DECLINED when this is not a socket serve (the caller opens
 *   inline). Returns NGX_DONE when the off-loop serve took ownership. Maps a
 *   credential-gate denial (EACCES/EPERM) to 403 AccessDenied and any other
 *   offload setup failure to 500 — both terminal statuses the caller returns.
 */
static ngx_int_t
s3_get_serve_offload(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, brix_vfs_ctx_t *vctx)
{
    brix_http_serve_opts_t sopts;
    ngx_int_t                sr;

    ngx_memzero(&sopts, sizeof(sopts));
    sopts.xfer_proto = BRIX_XFER_PROTO_S3;
    sopts.op_name    = "GetObject";
    sopts.identity   = "";
    sopts.etag_flags = 0;
    sopts.compress   = cf->common.compress;

    sr = brix_http_serve_offload_remote(r, vctx->sd,
        brix_vfs_export_relative(vctx, fs_path), fs_path, &sopts,
        &cf->common, vctx, s3_serve_metrics);
    if (sr == NGX_DONE) {
        return NGX_DONE;
    }
    if (sr == NGX_ERROR) {
        /* EACCES/EPERM ⇒ the per-user backend credential gate denied
         * before any origin open was attempted (phase-2 follow-up);
         * everything else is a genuine offload setup failure. */
        if (errno == EACCES || errno == EPERM) {
            return s3_fail(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                "Access to the requested object is denied.",
                BRIX_S3_EVENT_ACCESS_DENIED);
        }
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return NGX_DECLINED;
}

/*
 * WHAT: Offload a remote cache-MISS fill to the thread pool, re-entering
 *   s3_handle_get on completion.
 * WHY:  An inline fill inside brix_vfs_open would otherwise stall the worker
 *   (mirrors webdav/get.c). The re-entry state carries the absolute fs_path + cf
 *   copied onto r->pool so they outlive the worker-thread fill.
 * HOW:  Returns NGX_DECLINED when no fill is needed (the caller opens inline).
 *   Returns NGX_DONE when a fill was scheduled. Allocation failure or a fill
 *   setup error maps to a terminal 500 the caller returns.
 */
static ngx_int_t
s3_get_cache_fill(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, brix_vfs_ctx_t *vctx)
{
    s3_get_reenter_t *rd;
    char             *fp;
    size_t            fplen;
    ngx_int_t         fr;

    rd = ngx_palloc(r->pool, sizeof(*rd));
    if (rd == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    fplen = ngx_strlen(fs_path);
    fp = (char *) ngx_pnalloc(r->pool, fplen + 1);
    if (fp == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(fp, fs_path, fplen + 1);
    rd->fs_path = fp;
    rd->cf      = cf;

    fr = brix_http_cache_fill_if_needed(r, vctx->sd,
        brix_vfs_export_relative(vctx, fs_path), &cf->common,
        s3_get_reenter, rd);
    if (fr == NGX_DONE) {
        return NGX_DONE;
    }
    if (fr == NGX_ERROR) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return NGX_DECLINED;
}

/*
 * WHAT: Open the object inline through the VFS and stat it, rejecting a missing
 *   key or a directory target as NoSuchKey.
 * WHY:  S3 keys are objects, not directories; a GET must resolve to a regular
 *   file. This bundles the open/stat/type checks so the orchestrator reads as one
 *   resolve step, and returns the open handle + populated stat on success.
 * HOW:  On success sets *out_fh + *out_vst and returns NGX_DECLINED (fall through
 *   to serve). On any failure it closes any handle it opened, increments the right
 *   metric, and returns the terminal status the caller returns; *out_fh is left
 *   NULL in that case.
 */
static ngx_int_t
s3_get_resolve(ngx_http_request_t *r, brix_vfs_ctx_t *vctx,
    brix_vfs_file_t **out_fh, brix_vfs_stat_t *out_vst)
{
    brix_vfs_file_t *fh;
    int              vfs_err = 0;

    *out_fh = NULL;

    fh = brix_vfs_open(vctx, BRIX_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        if (vfs_err == ENOENT || vfs_err == ENOTDIR) {
            return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                           "The specified key does not exist.",
                           BRIX_S3_EVENT_NO_SUCH_KEY);
        }
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return (ngx_int_t) brix_http_errno_to_status(vfs_err);
    }

    if (brix_vfs_file_stat(fh, out_vst) != NGX_OK) {
        brix_vfs_close(fh, r->connection->log);
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (out_vst->is_directory) {
        brix_vfs_close(fh, r->connection->log);
        return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                       "The specified key does not exist.",
                       BRIX_S3_EVENT_NO_SUCH_KEY);
    }

    *out_fh = fh;
    return NGX_DECLINED;
}

/*
 * WHAT: Resolve the display identity for the S3 access log / serve opts.
 * WHY:  The response pipeline records who fetched the object; S3 prefers the token
 *   subject, then the configured access key, then "anonymous".
 * HOW:  Pure formatter — writes a NUL-terminated identity into the caller-supplied
 *   buffer (size cap). No I/O; reads only the request module ctx + loc conf.
 */
static void
s3_get_resolve_identity(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    char *identity, size_t identity_size)
{
    ngx_http_s3_req_ctx_t *s3ctx;
    const char            *subject;

    s3ctx = ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    subject = s3ctx != NULL ? brix_identity_subject_cstr(s3ctx->identity)
                            : "";
    if (subject[0] != '\0') {
        ngx_cpystrn((u_char *) identity, (u_char *) subject, identity_size);
    } else if (cf->access_key.len > 0 && cf->access_key.data != NULL) {
        size_t n = cf->access_key.len < identity_size - 1
                   ? cf->access_key.len
                   : identity_size - 1;
        ngx_memcpy(identity, cf->access_key.data, n);
        identity[n] = '\0';
    } else {
        ngx_cpystrn((u_char *) identity, (u_char *) "anonymous", identity_size);
    }
}

/*
 * WHAT: Emit the AWS full-object checksum echo (x-amz-checksum-crc64nvme) and the
 *   stored user metadata (x-amz-meta-*) headers before the response headers go out.
 * WHY:  Both must be set while the open handle is still valid (serve closes it) and
 *   before serve sends the headers. Checksum echo is cache-only — emitted only when
 *   the value was stored at upload, so the read path never pays a full-file recompute.
 * HOW:  Reads the object fd from the open handle; skips the checksum header when the
 *   fd is invalid. Side-effecting header emission only — no return value.
 */
static void
s3_get_echo_headers(ngx_http_request_t *r, brix_vfs_file_t *fh,
    const char *fs_path)
{
    ngx_fd_t cfd = brix_vfs_file_fd(fh);

    if (cfd != NGX_INVALID_FILE) {
        s3_echo_object_checksums(r, cfd, fs_path);
    }
    s3_echo_user_metadata(r, fs_path);
}

/* Immutable inputs to the terminal S3 GET serve step, bundled so the serve
 * helper stays within the parameter budget. All borrowed for the call only. */
typedef struct {
    brix_vfs_file_t       *fh;        /* open handle; serve takes ownership */
    const brix_vfs_stat_t *vst;       /* object stat (size/mtime) */
    const char            *fs_path;   /* absolute export path */
    const char            *identity;  /* resolved display identity */
    ngx_flag_t             compress;  /* cf->common.compress */
} s3_get_serve_t;

/*
 * WHAT: Serve the resolved object bytes (full or byte-range, RFC 7233) and record
 *   the S3 range/bytes metrics.
 * WHY:  Isolates the terminal serve step so the orchestrator stays flat; the
 *   range-parse/header/send pipeline (incl. the TLS/cleartext split) is owned by
 *   the shared brix_http_serve_file_ranged() and stays frozen here.
 * HOW:  Delegates to brix_http_serve_file_ranged() (which takes ownership of the
 *   vfs handle), maps a 500 to the internal_error metric, then feeds the result to
 *   s3_serve_metrics. Returns the serve status the caller returns.
 */
static ngx_int_t
s3_get_serve(ngx_http_request_t *r, const s3_get_serve_t *sv)
{
    brix_http_serve_opts_t   opts;
    brix_http_serve_result_t result;
    ngx_int_t                rc;

    ngx_memzero(&opts, sizeof(opts));
    ngx_memzero(&result, sizeof(result));
    opts.xfer_proto = BRIX_XFER_PROTO_S3;
    opts.op_name    = "GetObject";
    opts.identity   = sv->identity;
    opts.etag_flags = 0;
    opts.compress   = sv->compress;
    /* phase-43 W3: apply response-* query overrides just before send. */
    opts.pre_header_send = s3_get_pre_header;

    rc = brix_http_serve_file_ranged(r, sv->fh, sv->vst, sv->fs_path, &opts,
                                       &result);

    if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
    }
    s3_serve_metrics(r, &result);
    return rc;
}

/* WHY: GET is the primary S3 data path — clients download object bytes via HTTP GET or byte-range requests. Range support (RFC 7233) enables resumable downloads and parallel chunked transfers, critical for large objects in HEP workflows where files often exceed gigabytes. The range-parse → headers → body-send pipeline is shared with WebDAV GET via brix_http_serve_file_ranged() (src/shared/file_serve.c); this handler keeps only the S3-specific concerns: NoSuchKey XML errors, identity resolution, and S3 range/bytes metrics. */

/* HOW: Phase 1 — open the object through the VFS layer (brix_vfs_open, read-only, cache-aware). If the open fails: ENOENT/ENOTDIR → NoSuchKey 404 XML; other errno → brix_http_errno_to_status() with internal_error metric. Phase 2 — brix_vfs_file_stat(); a directory target → NoSuchKey 404 (S3 keys are objects, not directories). Phase 3 — resolve the display identity (token subject, else access key, else "anonymous"). Phase 4 — fill brix_http_serve_opts_t (xfer_proto=S3, op_name="GetObject", etag_flags=0) and delegate the entire range-parse/header/send pipeline to brix_http_serve_file_ranged(), which also takes ownership of the vfs handle. Phase 5 — from the returned result, increment the S3 range_total[FULL/PARTIAL/UNSATISFIED] counter and, on a non-zero body, bytes_tx_total plus the IPv4/IPv6 split. */
/*
 * s3_handle_get - serve a file as an S3 GetObject response.
 *
 * Supports byte-range requests (RFC 7233).  After sending headers, checks
 * r->header_only so that HEAD requests (dispatched through s3_handle_head)
 * do not accidentally trigger a body send.
 *
 * Ownership: fd is opened here and closed either immediately on error or
 *   via an ngx_pool_cleanup_file registered on r->pool.
 *
 * Pool allocation: r->pool lifetime (request scope).
 */
ngx_int_t
s3_handle_get(ngx_http_request_t *r,
              const char *fs_path,
              ngx_http_s3_loc_conf_t *cf)
{
    brix_vfs_ctx_t    vctx;
    brix_vfs_file_t  *fh;
    brix_vfs_stat_t   vst;
    ngx_int_t           rc;
    char                identity[128];

    /* Phase-57 W2: ZIP member access. NGX_DECLINED ⇒ serve the object normally. */
    rc = s3_get_serve_zip_member(r, fs_path, cf);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    s3_vfs_ctx(r, fs_path, cf, &vctx);

    /* Tape residency (phase-64 VFS seam): reject a GET of a nearline/offline
     * object before any open/fill. NGX_DECLINED ⇒ online; fall through. */
    rc = s3_get_check_residency(r, &vctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* phase-64 SP3: socket-wire backend serve off the event loop. NGX_DONE ⇒
     * served; a terminal error status ⇒ return it; NGX_DECLINED ⇒ open inline. */
    rc = s3_get_serve_offload(r, fs_path, cf, &vctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* phase-64 SP2: offload a remote cache MISS fill to the thread pool and
     * re-enter on completion. NGX_DECLINED ⇒ open inline below. */
    rc = s3_get_cache_fill(r, fs_path, cf, &vctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* Resolve: open + stat inline, rejecting a missing key / directory target.
     * On success fh is an open handle owned by the serve step below. */
    rc = s3_get_resolve(r, &vctx, &fh, &vst);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /*
     * Conditional GET (If-Match / If-None-Match / If-(Un)Modified-Since).  On a
     * 304/412 short-circuit we must release the handle we opened above; on
     * NGX_DECLINED we fall through to serve the object.
     */
    {
        /* phase78-fp: s3_get_resolve (above, NGX_DECLINED path) populated vst via brix_vfs_file_stat before returning */
        ngx_int_t crc = s3_handle_conditional(r, vst.mtime, vst.size); /* NOLINT(clang-analyzer-core.CallAndMessage) */
        if (crc != NGX_DECLINED) {
            brix_vfs_close(fh, r->connection->log);
            return crc;
        }
    }

    s3_get_resolve_identity(r, cf, identity, sizeof(identity));

    /* Emit checksum + user-metadata headers before serve sends the response
     * headers (the handle stays open until serve sends them). */
    s3_get_echo_headers(r, fh, fs_path);

    {
        s3_get_serve_t sv;
        ngx_memzero(&sv, sizeof(sv));
        sv.fh       = fh;
        sv.vst      = &vst;
        sv.fs_path  = fs_path;
        sv.identity = identity;
        sv.compress = cf->common.compress;
        return s3_get_serve(r, &sv);
    }
}

/*
 * HEAD /bucket/key - metadata only
 * */

ngx_int_t
s3_handle_head(ngx_http_request_t *r,
               const char *fs_path,
               ngx_http_s3_loc_conf_t *cf)
{
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;

    s3_vfs_ctx(r, fs_path, cf, &vctx);
    if (brix_vfs_stat(&vctx, &vst) != NGX_OK) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                           "The specified key does not exist.",
                           BRIX_S3_EVENT_NO_SUCH_KEY);
        }
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return (ngx_int_t) brix_http_errno_to_status(errno);
    }

    if (vst.is_directory) {
        return s3_fail(r, NGX_HTTP_NOT_FOUND, "NoSuchKey",
                       "The specified key does not exist.",
                       BRIX_S3_EVENT_NO_SUCH_KEY);
    }

    /*
     * Tape residency (phase-64 VFS seam): advertise the GLACIER storage class for a
     * nearline object so clients learn a restore is required before a GET. HEAD
     * still returns 200 (metadata only); x-amz-restore reports no active restore
     * (the restore flow is the WLCG Tape REST API, not S3 GET).
     */
    {
        brix_sd_residency_t res;
        if (brix_vfs_residency(&vctx, &res, NULL) == NGX_OK
            && (res == BRIX_SD_RES_NEARLINE || res == BRIX_SD_RES_OFFLINE))
        {
            (void) brix_http_set_header(r, "x-amz-storage-class",
                                          "GLACIER", NULL);
            (void) brix_http_set_header(r, "x-amz-restore",
                                          "ongoing-request=\"false\"", NULL);
        }
    }

    /* Conditional HEAD (If-Match / If-None-Match / If-(Un)Modified-Since). */
    {
        ngx_int_t crc = s3_handle_conditional(r, vst.mtime, vst.size);
        if (crc != NGX_DECLINED) {
            return crc;
        }
    }

    /*
     * AWS full-object checksum echo (x-amz-checksum-crc64nvme). Cache-only: a
     * cheap confined open + getxattr (no full-file read) emits the value stored
     * at upload time; absent ⇒ no header, exactly as AWS behaves when no checksum
     * was set at upload.
     */
    {
        brix_vfs_ctx_t   vctx;
        brix_vfs_file_t *fh;

        s3_vfs_ctx(r, fs_path, cf, &vctx);
        fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, NULL);
        if (fh != NULL) {
            s3_echo_object_checksums(r, brix_vfs_file_fd(fh), fs_path);
            brix_vfs_close(fh, r->connection->log);
        }
    }

    /* User metadata (x-amz-meta-*): echo the stored set on HEAD. */
    s3_echo_user_metadata(r, fs_path);

    if (brix_http_set_file_headers(r, vst.mtime, vst.size, vst.size,
                                     NULL, 0,
                                     0, 0, 0) != NGX_OK)
    {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}
/*
 * WHY: HEAD requests return object metadata without body — required by S3 spec for existence checks and pre-upload validation. Clients use HEAD to verify an object exists, check size/ETag before deciding whether to upload or download.
 *
 * HOW: Mirrors s3_handle_get's opening/fstat path but skips range parsing entirely. Sets status=200, content-length from st_size, last-modified from st_mtime, Content-Type and ETag headers. Sends header only via ngx_http_send_header() + ngx_http_send_special(r, NGX_HTTP_LAST), closes the fd immediately after (no body transfer). Does NOT register pool cleanup since the fd is closed synchronously.
 */

/*
 * HEAD /bucket  -> HeadBucket
 * */

/*
 * s3_handle_head_bucket — answer a HEAD on the bucket root.
 *
 * WHAT: AWS SDKs (boto3, rclone, s5cmd, mc) issue HEAD /<bucket> at session
 *   start to confirm the bucket exists and learn its region before any object
 *   operation.  Returns 200 + x-amz-bucket-region when the configured export
 *   root is a directory, else 404 NoSuchBucket.
 * WHY:  Without this the empty-key guard answered 400 InvalidURI and an
 *   unmodified SDK client aborted the whole session.
 * HOW:  stat() the already-canonical, confinement-anchored export root (it is
 *   the bucket); no key is involved, so no per-request path resolution is
 *   needed.  Header-only response.
 */
ngx_int_t
s3_handle_head_bucket(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf)
{
    struct stat st;

    if (cf->common.root_canon[0] == '\0'
        || stat(cf->common.root_canon, &st) != 0  /* vfs-seam-allow: HeadBucket stats the export root itself (the confinement anchor), not a path beneath it */
        || !S_ISDIR(st.st_mode))
    {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INVALID_URI]);
        r->headers_out.status           = NGX_HTTP_NOT_FOUND;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    if (cf->region.len > 0) {
        char   region[64];
        size_t n = cf->region.len < sizeof(region) - 1
                   ? cf->region.len : sizeof(region) - 1;
        ngx_memcpy(region, cf->region.data, n);
        region[n] = '\0';
        (void) s3_set_header(r, "x-amz-bucket-region", region);
    }

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/*
 * GET /bucket?location  -> GetBucketLocation
 * */

/*
 * s3_handle_get_bucket_location — answer GET /<bucket>?location.
 *
 * WHAT: Region-discovery probe.  Many SDKs call this to decide which endpoint
 *   to sign against; a failure aborts the client.  Emits the LocationConstraint
 *   document carrying the configured region (empty element for "us-east-1",
 *   matching AWS, since us-east-1 has no explicit constraint).
 * WHY:  Cheap probe-satisfier; pairs with HeadBucket so unmodified SDK clients
 *   complete their pre-flight.
 * HOW:  The region is config-supplied (trusted, no XML metacharacters), so it
 *   is appended directly into the element body.
 */
ngx_int_t
s3_handle_get_bucket_location(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf)
{
    u_char    *xml;
    size_t     xml_len = 0;
    size_t     xml_capacity = 256 + cf->region.len;
    ngx_buf_t *response_buf;
    int        is_default;

    is_default = (cf->region.len == 0
                  || (cf->region.len == sizeof("us-east-1") - 1
                      && ngx_strncmp(cf->region.data,
                                     (u_char *) "us-east-1",
                                     cf->region.len) == 0));

    xml = ngx_palloc(r->pool, xml_capacity);
    if (xml == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    if (is_default) {
        XML_APPEND("<LocationConstraint "
                   "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>");
    } else {
        XML_APPEND("<LocationConstraint "
                   "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">%.*s"
                   "</LocationConstraint>",
                   (int) cf->region.len, (const char *) cf->region.data);
    }

    response_buf = ngx_create_temp_buf(r->pool, xml_len + 4);
    if (response_buf == NULL) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    response_buf->last = ngx_cpymem(response_buf->last, xml, xml_len);
    response_buf->last_buf = 1;

    BRIX_S3_METRIC_ADD(bytes_tx_total, xml_len);
    return brix_http_send_xml_buffer(r, NGX_HTTP_OK,
        (ngx_str_t) ngx_string("application/xml"), response_buf);
}

/*
 * DELETE /bucket/key
 * */

ngx_int_t
s3_handle_delete(ngx_http_request_t *r,
                 const char *fs_path,
                 ngx_http_s3_loc_conf_t *cf)
{
    brix_vfs_ctx_t vctx;
    ngx_int_t        rc;

    /* Route DELETE through the metered VFS unlink. brix_vfs_unlink unlinks a
     * file and rmdirs an (empty) directory — a non-empty dir surfaces as
     * ENOTEMPTY (S3 BucketNotEmpty), exactly as the old require_empty_dir path.
     * S3 DELETE is idempotent: a missing key (ENOENT) is still 204, and counts
     * as DELETE_MISSING. errno is read only on the NGX_ERROR branch. */
    s3_vfs_ctx(r, fs_path, cf, &vctx);
    rc = brix_vfs_unlink(&vctx);

    if (rc == NGX_OK || errno == ENOENT) {
        if (rc != NGX_OK) {   /* ENOENT: the object did not exist */
            BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_DELETE_MISSING]);
        }
        r->headers_out.status           = NGX_HTTP_NO_CONTENT;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    if (errno == ENOTEMPTY) {
        return s3_send_xml_error(r, NGX_HTTP_CONFLICT,
                                 "BucketNotEmpty",
                                 "The directory is not empty.");
    }

    BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
/*
 * WHY: S3 DELETE is idempotent — deleting a non-existent key returns 204 No Content (not 404), matching AWS behavior. This allows clients to safely retry delete operations without checking existence first.
 *
 * HOW: Routes the delete through the metered VFS surface (brix_vfs_unlink, which
 * unlinks a file and rmdirs an empty directory under root confinement). On success
 * sends a 204 No Content header-only response via ngx_http_send_special(); a missing
 * key (ENOENT) is still 204 (AWS-style idempotency) and increments DELETE_MISSING; a
 * non-empty directory (ENOTEMPTY) → 409 BucketNotEmpty; any other errno → internal_error
 * metric + 500.
 */
