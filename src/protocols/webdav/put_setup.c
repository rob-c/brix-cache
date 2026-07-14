/*
 * put_setup.c - WebDAV PUT precondition/setup phase (split from put.c).
 *
 * Everything that must pass before (and around) the staged-write body phase:
 * the staged-write VFS ctx construction, the resumable Content-Range branch,
 * the precheck gate (path resolve + existence probe + ETag preconditions), the
 * staged-temp open (with errno→status mapping), and dashboard-tracking start.
 */

#include "webdav.h"
#include "core/http/etag.h"
#include "core/http/http_body.h"
#include "core/compat/integrity_info.h"
#include "core/http/http_conditionals.h"
#include "core/compat/range.h"
#include "core/compat/staged_file.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "fs/vfs/vfs.h"
#include "auth/impersonate/lifecycle.h"
#include "fs/path/path.h"
#include "core/compat/cstr.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "put_internal.h"

/*
 * Build a transient VFS ctx for the staged-write lifecycle on the final `path`
 * (mirrors the canonical construction in get.c).  PUT is allow_write-gated at
 * the access phase, so brix_vfs_staged_open's write-gate never fires here.
 */
static void
webdav_put_vfs_ctx_init(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    brix_vfs_ctx_t *vctx)
{
    ngx_http_brix_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
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
    /* Phase-70: bind captured bearer/proxy for backend PASSTHROUGH (no-op on SELECT). */
    webdav_vfs_bind_deleg(r, conf, vctx);
    /* Route through the export's selected storage backend (NULL ⇒ default POSIX). */
    vctx->sd = brix_webdav_backend_instance(conf, r->connection->log);
}

/* Add an "X-Upload-Offset: <off>" response header (the resumable-PUT progress
 * marker the client reads to know where to continue).  Best-effort. */
static void
webdav_set_upload_offset(ngx_http_request_t *r, off_t off)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "X-Upload-Offset");
    h->value.data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
    if (h->value.data == NULL) {
        h->hash = 0;
        return;
    }
    h->value.len = ngx_sprintf(h->value.data, "%O", off) - h->value.data;
}

/*
 * Resumable Content-Range PUT (brix_webdav_upload_resume on).  Writes this
 * chunk to a persistent, identity-keyed partial at its absolute offset and
 * commits (atomic rename) only when the upload is complete.  Across separate PUT
 * requests — and across an nginx restart — the partial survives, so the client
 * resumes from X-Upload-Offset.  Append-only: the chunk must start exactly at the
 * current partial size, else 409 + X-Upload-Offset tells the client the truth.
 */
static void
webdav_put_ranged_resume(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    const brix_http_content_range_t *cr)
{
    brix_staged_file_t        staged;
    off_t                       cur = 0;
    brix_http_body_summary_t  bs;
    ngx_http_brix_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    const char *principal = (wctx != NULL && wctx->dn[0] != '\0')
                            ? wctx->dn : NULL;
    const char *stage_dir = conf->upload_stage_dir_canon[0]
                            ? conf->upload_stage_dir_canon : NULL;

    {
    brix_staged_open_req_t staged_req = {
        .root_canon = conf->common.root_canon,
        .final_path = path,
        .mode       = NGX_FILE_DEFAULT_ACCESS,
        .principal  = principal,
        .stage_dir  = stage_dir,
    };
    if (brix_staged_open_resume(r->connection->log, &staged_req, &staged, &cur)
        != NGX_OK)
    {
        ngx_int_t st = brix_http_map_errno(ngx_errno);
        webdav_metrics_finalize_request(r,
            st >= 500 ? NGX_HTTP_INTERNAL_SERVER_ERROR : st);
        return;
    }

    /* Append-only contiguity: the chunk must begin at the current partial size.
     * If it doesn't, report the real resume offset and let the client re-issue —
     * keep the partial (close without unlink). */
    if (cr->start != cur) {
        brix_staged_abort(r->connection->log, conf->common.root_canon,
                            &staged, 0 /* keep */);
        webdav_set_upload_offset(r, cur);
        webdav_send_status_only(r, NGX_HTTP_CONFLICT);
        return;
    }

    if (r->request_body != NULL) {
        if (brix_http_body_write_to_fd_at(r, staged.fd, path, &bs, cr->start)
            != NGX_OK)
        {
            /* keep the partial; the client can re-send this chunk */
            brix_staged_abort(r->connection->log, conf->common.root_canon,
                                &staged, 0 /* keep */);
            webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        BRIX_WEBDAV_METRIC_ADD(bytes_rx_total, bs.bytes);
        cur = cr->end + 1;
        /* Flush so the reported resume offset is durable across a restart. */
        (void) fsync(staged.fd);
    }

    /* Final chunk (last byte of the declared total) → commit; else keep partial
     * and report the next expected offset. */
    if (cr->total >= 0 && cr->end + 1 >= cr->total) {
        /* Commit the staged partial onto the destination — atomic rename on the
         * same filesystem, or copy-then-rename when staging on a different device
         * (brix_webdav_stage_dir).  brix_commit_staged owns neither close nor
         * the active flag, so finalize the staged struct ourselves.  On a stage
         * device, record a durable pending-commit marker first so an interrupted
         * cross-device move is finished by the reaper across a restart. */
        ngx_flag_t stage_tracked = (stage_dir != NULL);
        ngx_int_t  crc;
        if (stage_tracked) {
            (void) brix_stage_mark_pending(staged.tmp_path, path,
                                             r->connection->log);
        }
        crc = brix_commit_staged(staged.fd, staged.tmp_path, path,
                                   staged.final_mode, r->connection->log);
        if (staged.fd != NGX_INVALID_FILE) {
            ngx_close_file(staged.fd);
            staged.fd = NGX_INVALID_FILE;
        }
        staged.active = 0;
        if (crc != NGX_OK) {
            /* Keep the marker + partial — the reaper / a client retry completes it. */
            webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        if (stage_tracked) {
            brix_stage_unmark_pending(staged.tmp_path);
        }
        webdav_put_persist_checksums(r, (const char *) path);   /* §8.3 */
        webdav_send_status_only(r, NGX_HTTP_CREATED);
        return;
    }

    brix_staged_abort(r->connection->log, conf->common.root_canon,
                        &staged, 0 /* keep partial for the next chunk */);
    webdav_set_upload_offset(r, cur);
    webdav_send_status_only(r, NGX_HTTP_OK);
    }
}

/*
 * webdav_put_precheck — resolve the target and run pre-write gating.
 *
 * WHAT: Resolves the request path into `path`, dispatches a resumable
 *   Content-Range PUT (which fully handles its own response), probes the target
 *   for existence, and evaluates the ETag preconditions.  Returns
 *   WEBDAV_PUT_CONTINUE to proceed to the staged-write path with `*created`
 *   set, or WEBDAV_PUT_DONE when the request has already been answered (path
 *   error → 409/4xx, resumable handled, or an ETag precondition failed).
 *
 * WHY: Consolidates every gate that must pass before a staged temp is opened,
 *   keeping the orchestrator a flat sequence and the "never open before we know
 *   we should" invariant in one place.  Behavior is byte-identical to the prior
 *   inline block (same status codes, same order of checks).
 *
 * HOW:
 *   1. Resolve the path; a missing intermediate collection is RFC 4918 §9.7.1
 *      409 Conflict, any other resolve error propagates its status.
 *   2. If resumable uploads are on and a Content-Range header is present, parse
 *      it (malformed → 400) and hand off to webdav_put_ranged_resume; DONE.
 *   3. Probe the target through the metered VFS to populate a local stat for the
 *      ETag check and decide `*created` (0 = exists, 1 = new).
 *   4. Run the weak-ETag precondition check; a failure sends its status. DONE.
 */
webdav_put_step_t
webdav_put_precheck(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, char *path, int *created)
{
    struct stat sb;
    ngx_int_t   rc;

    *created = 0;
    ngx_memzero(&sb, sizeof(sb));

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon, path,
                                             WEBDAV_MAX_PATH);
    if (rc != NGX_OK) {
        /* RFC 4918 §9.7.1: missing intermediate collection → 409 Conflict */
        if (rc == NGX_HTTP_NOT_FOUND) {
            webdav_metrics_finalize_request(r, NGX_HTTP_CONFLICT);
            return WEBDAV_PUT_DONE;
        }
        webdav_metrics_finalize_request(r, rc);
        return WEBDAV_PUT_DONE;
    }

    /*
     * Resumable upload: a Content-Range PUT places its chunk at an absolute
     * offset on a persistent identity-keyed partial and commits only when the
     * upload completes (brix_webdav_upload_resume on).  Handled before the
     * whole-body staged-write path below.  A malformed Content-Range is 400.
     */
    if (conf->upload_resume) {
        ngx_table_elt_t *crh = brix_http_find_header(
            r, "Content-Range", sizeof("Content-Range") - 1);
        if (crh != NULL && crh->value.len > 0) {
            brix_http_content_range_t cr;
            brix_http_parse_content_range(crh->value.data, crh->value.len, &cr);
            if (!cr.present) {
                webdav_metrics_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                return WEBDAV_PUT_DONE;
            }
            webdav_put_ranged_resume(r, conf, path, &cr);
            return WEBDAV_PUT_DONE;
        }
    }

    {
        ngx_http_brix_webdav_req_ctx_t *rx =
            ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
        brix_vfs_ctx_t  pctx;
        brix_vfs_stat_t pst;
        int               is_tls = 0;

#if (NGX_HTTP_SSL)
        is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
        brix_vfs_ctx_init(&pctx, r->pool, r->connection->log,
            BRIX_PROTO_WEBDAV, conf->common.root_canon, conf->cache_root_canon,
            conf->common.allow_write, is_tls,
            (rx != NULL) ? rx->identity : NULL, path);
        brix_vfs_ctx_bind_backend_cred(&pctx,
            &conf->common.storage_credential_dir,
            conf->common.storage_credential_fallback);
        webdav_vfs_bind_deleg(r, conf, &pctx);
        if (brix_vfs_probe(&pctx, 0 /* follow */, &pst) == NGX_OK) {
            *created = 0;   /* target exists — sb populated for the ETag check */
            sb.st_mtime = pst.mtime;
            sb.st_size  = pst.size;
            sb.st_mode  = (mode_t) pst.mode;
        } else {
            *created = 1;   /* new file — sb unused (etag check sees !exists) */
        }
    }

    rc = brix_http_check_etag_preconditions(
        r, !*created, &sb, BRIX_ETAG_WEAK, BRIX_HTTP_COND_WEAK_EQUIV);
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return WEBDAV_PUT_DONE;
    }

    return WEBDAV_PUT_CONTINUE;
}

/*
 * webdav_put_open_target — open the staged temp for the final path.
 *
 * WHAT: Builds the staged-write VFS ctx and opens a staged temp file
 *   (O_EXCL, unique name, up to 16 attempts) through the metered VFS surface.
 *   On success returns WEBDAV_PUT_CONTINUE with `*out_staged` set; on failure
 *   maps the captured errno to a clean 4xx (or 500 for no-4xx-contract errnos),
 *   sends it, and returns WEBDAV_PUT_DONE.
 *
 * WHY: Keeps the "body is written to a staged temp and atomically renamed only
 *   on success" invariant (WS8/HTTP-4) and its errno→status mapping in one
 *   place, matching S3 PUT's s3_put_finalize_fs_error.  Status codes unchanged.
 *
 * HOW:
 *   1. Init the staged-write ctx via webdav_put_vfs_ctx_init.
 *   2. brix_vfs_staged_open; a non-NULL result is the success path.
 *   3. ENOENT/ENOTDIR (missing parent collection) → 409 (RFC 4918 §9.7.1).
 *   4. Otherwise map errno via brix_http_map_errno, log the path, and finalize
 *      with the mapped 4xx or 500.
 */
webdav_put_step_t
webdav_put_open_target(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    brix_vfs_ctx_t *vctx, brix_vfs_staged_t **out_staged)
{
    brix_vfs_staged_t *staged;
    int                staged_err = 0;
    ngx_int_t          status;

    *out_staged = NULL;

    /*
     * Open a staged temp file beside the final path (O_EXCL, unique name, up to
     * 16 attempts) through the metered VFS staged surface.  The body is written
     * here and atomically renamed onto the final path only on success — never
     * exposing a partial object.
     */
    webdav_put_vfs_ctx_init(r, conf, path, vctx);

    staged = brix_vfs_staged_open(vctx, NGX_FILE_DEFAULT_ACCESS, 16,
                                    &staged_err);
    if (staged != NULL) {
        *out_staged = staged;
        return WEBDAV_PUT_CONTINUE;
    }

    /* Use the errno the VFS open captured (logging may clobber errno). */
    {
        int open_errno = staged_err;

        if (open_errno == NGX_ENOENT || open_errno == NGX_ENOTDIR) {
            /* RFC 4918 §9.7.1 — PUT to non-existent parent collection is 409 */
            webdav_metrics_finalize_request(r, NGX_HTTP_CONFLICT);
            return WEBDAV_PUT_DONE;
        }
        /*
         * A DAC-denied staged-temp create (e.g. the accessor lacks write on the
         * parent collection → EACCES/EPERM, EXDEV/ELOOP on a confinement-blocked
         * traversal) is a forbidden, bounded request — surface it as a clean 4xx
         * via the shared errno map (EACCES/EPERM → 403, ENOSPC → 507, …), not a
         * blanket 500.  Only an errno with no clean 4xx contract (e.g. EIO) keeps
         * the internal-error path.  This mirrors S3 PUT's s3_put_finalize_fs_error.
         */
        status = brix_http_map_errno(open_errno);
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR,
                             (ngx_uint_t) open_errno,
                             "brix_webdav: staged open for write failed for: "
                             "\"%s\"", path);
        webdav_metrics_finalize_request(
            r, status >= 500 ? NGX_HTTP_INTERNAL_SERVER_ERROR : status);
        return WEBDAV_PUT_DONE;
    }
}

/*
 * webdav_put_start_dashboard — begin dashboard/metric tracking for this PUT.
 *
 * WHAT: Resolves the request identity (DN or "anonymous") and opens a
 *   dashboard transfer record for the write of `bytes` to `path`.  No return
 *   value — best-effort tracking start.
 *
 * WHY: The dashboard-start call is issued identically from both the body and
 *   the empty-PUT branch; factoring it removes the duplicated identity lookup
 *   and keeps the two callsites in lockstep.
 *
 * HOW:
 *   1. Look up the WebDAV request ctx; use wctx->dn if non-empty else
 *      "anonymous".
 *   2. Call brix_dashboard_http_start_identity with the WRITE direction and the
 *      declared byte count.
 */
void
webdav_put_start_dashboard(ngx_http_request_t *r, const char *path,
    int64_t bytes)
{
    ngx_http_brix_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    const char *identity = (wctx != NULL && wctx->dn[0] != '\0')
                           ? wctx->dn : "anonymous";

    (void) brix_dashboard_http_start_identity(r, path, identity, "",
        BRIX_XFER_PROTO_WEBDAV, BRIX_XFER_DIR_WRITE, "PUT", bytes);
}
