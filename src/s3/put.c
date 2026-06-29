/*
 * put.c - (kept) routing + shared helpers
 * Phase-38 split of put.c; behavior-identical.
 */
#include "s3_put_internal.h"

const char *
s3_dashboard_put_op(ngx_http_request_t *r)
{
    char upload_id[128];
    char part_num[16];

    if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))
        && s3_get_query_param(r, "partNumber", part_num, sizeof(part_num)))
    {
        return "UploadPart";
    }

    return "PutObject";
}


void
s3_dashboard_identity(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
                      char *out, size_t outsz)
{
    ngx_http_s3_req_ctx_t *s3ctx;
    const char            *subject;

    if (out == NULL || outsz == 0) {
        return;
    }

    s3ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
    subject = s3ctx != NULL
              ? xrootd_identity_subject_cstr(s3ctx->identity) : "";
    if (subject[0] != '\0') {
        ngx_cpystrn((u_char *) out, (u_char *) subject, outsz);
        return;
    }

    if (cf->access_key.len > 0 && cf->access_key.data != NULL) {
        size_t n = cf->access_key.len < outsz - 1
                   ? cf->access_key.len
                   : outsz - 1;
        ngx_memcpy(out, cf->access_key.data, n);
        out[n] = '\0';
        return;
    }

    ngx_cpystrn((u_char *) out, (u_char *) "anonymous", outsz);
}

/*
 * s3_put_body_mode — classify the body into one of four modes.
 *
 * WHY this classification:
 *   Prometheus metrics track put operations by body mode so we can see
 *   how much traffic is in-memory vs spooled. The enum values are used
 *   as indices into XROOTD_S3_METRIC_INC(put_body_total[...]).
 */

ngx_uint_t
s3_put_body_mode(const xrootd_http_body_summary_t *summary)
{
    if (summary->has_spooled && summary->has_memory) {
        return XROOTD_S3_PUT_MIXED;
    }
    if (summary->has_spooled) {
        return XROOTD_S3_PUT_SPOOLED;
    }
    if (summary->has_memory) {
        return XROOTD_S3_PUT_MEMORY;
    }
    return XROOTD_S3_PUT_EMPTY;
}


/*
 * s3_put_streaming — decode an aws-chunked PUT/UploadPart body and finalize.
 *
 * Reads x-amz-decoded-content-length, then either offloads the chunk decode to
 * the thread pool (so the blocking pread/pwrite state machine does not stall the
 * event loop) or, when no pool is configured, decodes synchronously.  Either way
 * the commit/ETag/checksum/tagging/200 run on the event loop (s3_chunk_finalize).
 */
void
s3_put_streaming(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    xrootd_staged_file_t *staged, const char *fs_path, ngx_uint_t body_mode)
{
    const char        *root_canon = cf->common.root_canon;
    ngx_table_elt_t   *dcl;
    uint64_t           expected = 0;
    ngx_thread_pool_t *pool;
    size_t             i;

    dcl = xrootd_http_find_header(r, "x-amz-decoded-content-length",
                                  sizeof("x-amz-decoded-content-length") - 1);
    if (dcl == NULL || dcl->value.len == 0) {
        xrootd_staged_abort(r->connection->log, root_canon, staged, 1);
        s3_put_finalize_client_error(r, NGX_HTTP_BAD_REQUEST,
            "MissingContentLength",
            "Streaming upload is missing x-amz-decoded-content-length.");
        return;
    }
    for (i = 0; i < dcl->value.len; i++) {
        u_char d = dcl->value.data[i];
        if (d < '0' || d > '9') {
            xrootd_staged_abort(r->connection->log, root_canon, staged, 1);
            s3_put_finalize_client_error(r, NGX_HTTP_BAD_REQUEST,
                "InvalidArgument",
                "x-amz-decoded-content-length is not a valid length.");
            return;
        }
        expected = expected * 10 + (uint64_t) (d - '0');
    }

    pool = s3_thread_pool(cf);
    if (pool != NULL) {
        ngx_thread_task_t *task =
            ngx_thread_task_alloc(r->pool, sizeof(s3_chunk_aio_t));
        s3_chunk_aio_t    *t;

        if (task == NULL) {
            xrootd_staged_abort(r->connection->log, root_canon, staged, 1);
            s3_put_finalize_error(r);
            return;
        }
        t = task->ctx;                  /* ngx_thread_task_alloc zeroes ctx */
        t->r         = r;
        t->staged    = *staged;
        t->expected  = expected;
        t->body_mode = body_mode;
        s3_build_chunk_verify(r, cf, &t->verify);   /* W6a */
        ngx_cpystrn((u_char *) t->fs_path, (u_char *) fs_path,
                    sizeof(t->fs_path));
        ngx_cpystrn((u_char *) t->root_canon, (u_char *) root_canon,
                    sizeof(t->root_canon));
        xrootd_task_bind(task, s3_chunk_aio_thread, s3_chunk_aio_done);

        if (ngx_thread_task_post(pool, task) != NGX_OK) {
            xrootd_staged_abort(r->connection->log, root_canon, staged, 1);
            s3_put_finalize_error(r);
            return;
        }
        r->main->count++;
        return;
    }

    /* Synchronous fallback (no thread pool): decode inline, then finalize. */
    {
        s3_chunk_trailer_t trailer;
        s3_chunk_verify_t  verify;
        int                status = NGX_HTTP_INTERNAL_SERVER_ERROR;

        s3_build_chunk_verify(r, cf, &verify);   /* W6a */
        if (s3_aws_chunked_decode_to_fd(r, staged->fd, fs_path, expected,
                                        &trailer, &status, NULL, &verify)
            != NGX_OK)
        {
            s3_chunk_decode_failed(r, root_canon, staged, status);
            return;
        }
        s3_chunk_finalize(r, root_canon, fs_path, staged, &trailer, expected,
                          body_mode);
    }
}


/*
 * Phase 40: the S3 PUT body is read asynchronously (after inline SigV4 auth has
 * already populated s3ctx->identity), so this callback re-establishes the
 * impersonation principal for the duration of the object write.  The staged
 * create then routes to the broker and the new object is owned by the mapped
 * user.  No-op unless map mode is active.
 */
void
s3_put_body_handler(ngx_http_request_t *r)
{
    ngx_http_s3_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);

    xrootd_imp_request_begin(rx != NULL ? rx->identity : NULL);
    s3_put_body_inner(r);
    xrootd_imp_request_end();
}


/* Directory-sentinel fast path: if fs_path names an S3 directory sentinel
 * (S3_DIR_SENTINEL), create the parent directory plus the zero-byte sentinel,
 * finalize the request, and return 1 (the caller must return).  Returns 0 when
 * fs_path is a normal object, so the caller proceeds with the body write. */
static int
s3_put_try_sentinel(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const u_char *fs_path)
{
    size_t  plen = ngx_strlen(fs_path);
    size_t  slen = sizeof(S3_DIR_SENTINEL) - 1;
    char    parent[PATH_MAX];
    char   *slash;
    int     fd;
    char    identity[128];

    if (!(plen >= slen
          && ngx_strncmp(fs_path + plen - slen,
                         (u_char *) S3_DIR_SENTINEL, slen) == 0))
    {
        return 0;
    }

    /* Create the directory that the sentinel lives in. */
    if (plen >= sizeof(parent)) {
        s3_put_finalize_error(r);
        return 1;
    }
    memcpy(parent, fs_path, plen + 1);
    slash = strrchr(parent, '/');
    if (slash != NULL) {
        *slash = '\0';
    }
    {
        xrootd_vfs_ctx_t pctx;

        s3_build_vfs_ctx(r, parent, cf, &pctx);
        if (xrootd_vfs_mkdir(&pctx, 0755, 0 /* no parents */) != NGX_OK
            && errno != EEXIST)
        {
            int mk_errno = errno;  /* capture before logging clobbers it */
            xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, mk_errno,
                                 "s3: mkdir(\"%s\") failed", parent);
            s3_put_finalize_fs_error(r, mk_errno);
            return 1;
        }
    }

    /* Write the zero-byte sentinel (confined create via the VFS seam). */
    fd = xrootd_vfs_open_fd(r->connection->log, cf->common.root_canon,
                            (const char *) fs_path,
                            O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        int open_errno = errno;  /* capture before logging clobbers it */
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, open_errno,
                             "s3: open(\"%s\") for sentinel failed",
                             (const char *) fs_path);
        s3_put_finalize_fs_error(r, open_errno);
        return 1;
    }
    close(fd);

    s3_dashboard_identity(r, cf, identity, sizeof(identity));
    (void) xrootd_dashboard_http_start_identity(r, (const char *) fs_path,
        identity, "", XROOTD_XFER_PROTO_S3, XROOTD_XFER_DIR_WRITE,
        "PutObjectSentinel", 0);
    XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_DIR_SENTINEL]);
    XROOTD_S3_METRIC_INC(put_body_total[XROOTD_S3_PUT_EMPTY]);
    s3_put_finalize_empty_ok(r);
    return 1;
}


void
s3_put_body_inner(ngx_http_request_t *r)
{
    u_char              *fs_path;
    ngx_http_s3_loc_conf_t *cf;
    ngx_http_s3_req_ctx_t  *s3ctx;
    xrootd_codec_id_t    put_codec = XROOTD_CODEC_IDENTITY;
    size_t               body_bytes = 0;
    ngx_uint_t           body_mode = XROOTD_S3_PUT_EMPTY;
    xrootd_staged_file_t staged;
    xrootd_http_body_summary_t body_summary;
    char                 identity[128];

    cf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
    s3ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
    fs_path = s3ctx != NULL ? (u_char *) s3ctx->fs_path : NULL;

    if (fs_path == NULL) {
        s3_put_finalize_error(r);
        return;
    }

    /* Directory-sentinel objects take a separate create-dir-and-return path. */
    if (s3_put_try_sentinel(r, cf, fs_path)) {
        return;
    }

    /* Create parent directories if needed using the shared confined mkdir helper. */
    {
        char   parent[PATH_MAX];
        char  *last_slash;
        size_t flen = strlen((const char *) fs_path);

        if (flen < sizeof(parent)) {
            memcpy(parent, fs_path, flen + 1);
            last_slash = strrchr(parent, '/');
            if (last_slash && last_slash != parent) {
                xrootd_vfs_ctx_t  pctx;
                xrootd_vfs_stat_t pst;

                *last_slash = '\0';

                /*
                 * phase-46 W2a: fast-path the common "many objects into one
                 * prefix" pattern.  A single confined probe that finds an
                 * existing directory replaces the per-path-component
                 * mkdirat(EEXIST) storm of the recursive mkdir. A symlink or a
                 * miss falls through to the confined vfs_mkdir, which re-enforces
                 * confinement.
                 */
                s3_build_vfs_ctx(r, parent, cf, &pctx);
                if (xrootd_vfs_probe(&pctx, 1 /* no-follow */, &pst) == NGX_OK
                    && pst.is_directory)
                {
                    /* parent prefix already exists — nothing to create */
                } else {
                    xrootd_vfs_ctx_t pvctx;

                    s3_build_vfs_ctx(r, parent, cf, &pvctx);
                    if (xrootd_vfs_mkdir(&pvctx, 0755, 1 /* parents */) != NGX_OK
                        && errno != EEXIST) {
                        int mk_errno = errno;  /* capture before logging clobbers it */
                        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR,
                                             mk_errno,
                                             "s3: mkdirs_for(\"%s\") failed",
                                             (const char *) fs_path);
                        /* DAC-denied create of a parent dir → 403, not 500. */
                        s3_put_finalize_fs_error(r, mk_errno);
                        return;
                    }
                }
            }
        }
    }

    if (xrootd_staged_open(r->connection->log, cf->common.root_canon,
                           (const char *) fs_path, O_WRONLY, 0600, 16,
                           &staged) != NGX_OK)
    {
        int open_errno = errno;   /* capture before logging clobbers errno */
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, open_errno,
                             "s3: staged open for \"%s\" failed",
                             (const char *) fs_path);
        /* A DAC-denied / confinement-blocked create is a 403, not a 500. */
        s3_put_finalize_fs_error(r, open_errno);
        return;
    }

    if (xrootd_http_body_summary(r, &body_summary) != NGX_OK) {
        xrootd_staged_abort(r->connection->log, cf->common.root_canon, &staged, 1);
        s3_put_finalize_error(r);
        return;
    }

    body_bytes = body_summary.bytes;
    body_mode = s3_put_body_mode(&body_summary);
    s3_dashboard_identity(r, cf, identity, sizeof(identity));
    (void) xrootd_dashboard_http_start_identity(r, (const char *) fs_path,
        identity, "", XROOTD_XFER_PROTO_S3, XROOTD_XFER_DIR_WRITE,
        s3_dashboard_put_op(r), (int64_t) body_bytes);

    /*
     * AWS streaming upload (aws-chunked): the body carries chunk framing that
     * must be decoded to the object bytes — storing it verbatim corrupts every
     * object from a default modern SDK/CLI client.  Routed through its own
     * decode → commit → checksum → finalize path.
     */
    if (s3_body_is_aws_chunked(r)) {
        /* A combined Content-Encoding such as "aws-chunked,gzip" means the body
         * was compressed THEN chunk-framed.  The streaming de-chunker strips only
         * the chunk envelope, so the inner-compressed payload would be stored
         * still compressed (silent object corruption).  Reject rather than store
         * undecoded bytes — the same invariant the non-chunked path enforces with
         * 400 below.  Plain aws-chunked (no inner coding) continues normally. */
        if (s3_aws_chunked_has_inner_coding(r)) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon,
                                &staged, 1);
            s3_put_finalize_codec_error(r, NGX_HTTP_BAD_REQUEST);
            return;
        }
        s3_put_streaming(r, cf, &staged, (const char *) fs_path, body_mode);
        return;
    }

    {
        ngx_table_elt_t  *ce = xrootd_http_find_header(
            r, "Content-Encoding", sizeof("Content-Encoding") - 1);
        if (ce != NULL && ce->value.len > 0) {
            const xrootd_codec_desc_t *d = xrootd_codec_by_http_token(
                (const char *) ce->value.data, ce->value.len);
            if (d == NULL || !d->available) {
                /* Unknown / not-compiled-in Content-Encoding: never store the
                 * undecoded bytes — reject as a client error (400), not 500. */
                xrootd_staged_abort(r->connection->log, cf->common.root_canon,
                                    &staged, 1);
                s3_put_finalize_codec_error(r, NGX_HTTP_BAD_REQUEST);
                return;
            }
            put_codec = d->id;
        }
    }

    /*
     * phase-46 W1a: offload the body write to the thread pool for ALL plain
     * (identity-encoded) bodies — including spooled and mixed ones, not just
     * in-memory.  The worker fn (s3_put_aio_thread) already streams every buf,
     * memory and file-backed, via xrootd_http_body_write_to_fd (kernel
     * copy_file_range for the spooled nginx temp file), so large uploads — the
     * ones nginx spools to disk — stop blocking the event loop.  Content-Encoding
     * decode (put_codec != IDENTITY) and aws-chunked (handled above) still run
     * synchronously.
     */
    if (body_summary.bytes > 0
        && put_codec == XROOTD_CODEC_IDENTITY && s3_thread_pool(cf) != NULL)
    {
        ngx_thread_task_t *task;
        s3_put_aio_t      *t;

        task = ngx_thread_task_alloc(r->pool, sizeof(s3_put_aio_t));
        if (task == NULL) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon, &staged, 1);
            s3_put_finalize_error(r);
            return;
        }

        t = task->ctx;
        t->r         = r;
        t->staged    = staged;
        t->len       = body_summary.bytes;
        t->body_mode = body_mode;
        t->body_bytes = body_bytes;
        ngx_cpystrn((u_char *) t->final_path, fs_path, sizeof(t->final_path));
        ngx_cpystrn((u_char *) t->root_canon,
                    (u_char *) cf->common.root_canon, sizeof(t->root_canon));

        /*
         * Phase 31 W2: no full-body collection — the thread streams the
         * in-memory body bufs straight to the staged fd (s3_put_aio_thread).
         */

        xrootd_task_bind(task, s3_put_aio_thread, s3_put_aio_done);

        if (ngx_thread_task_post(cf->common.thread_pool, task) != NGX_OK) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon, &staged, 1);
            s3_put_finalize_error(r);
            return;
        }

        r->main->count++;
        return;
    }

    {
        ngx_int_t  wrc;
        ngx_int_t  decode_status = 0;

        if (put_codec != XROOTD_CODEC_IDENTITY) {
            wrc = xrootd_http_body_decode_to_fd(r, staged.fd,
                                                (const char *) fs_path,
                                                put_codec,
                                                XROOTD_DECODE_MAX_OUTPUT,
                                                &body_summary,
                                                &decode_status);
        } else {
            wrc = xrootd_http_body_write_to_fd(r, staged.fd,
                                                (const char *) fs_path,
                                                &body_summary);
        }
        if (wrc != NGX_OK) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon,
                                &staged, 1);
            /* Map a decode failure to a clean S3 client error (413 bomb / 400
             * malformed); a genuine I/O failure (decode_status 0 or 5xx) stays
             * a 500. */
            if (decode_status == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE
                || decode_status == NGX_HTTP_BAD_REQUEST
                || decode_status == NGX_HTTP_UNSUPPORTED_MEDIA_TYPE)
            {
                s3_put_finalize_codec_error(r, decode_status
                    == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE
                    ? NGX_HTTP_REQUEST_ENTITY_TOO_LARGE
                    : NGX_HTTP_BAD_REQUEST);
            } else {
                s3_put_finalize_error(r);
            }
            return;
        }
    }

    if (s3_commit_put(r, r->connection->log, cf->common.root_canon, &staged,
                      (const char *) fs_path) != NGX_OK)
    {
        if (s3_put_commit_conflict(r)) {
            return;
        }
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "s3: staged commit to \"%s\" failed",
                             (const char *) fs_path);
        s3_put_finalize_error(r);
        return;
    }

    /* S3 API requires ETag on PutObject 200 response */
    {
        xrootd_vfs_ctx_t  fctx;
        xrootd_vfs_stat_t fst;
        char              etag_buf[48];

        s3_build_vfs_ctx(r, (const char *) fs_path, cf, &fctx);
        if (xrootd_vfs_probe(&fctx, 1 /* no-follow */, &fst) == NGX_OK) {
            struct stat final_sb;

            ngx_memzero(&final_sb, sizeof(final_sb));
            final_sb.st_mtime = fst.mtime;
            final_sb.st_size  = fst.size;
            s3_etag(&final_sb, etag_buf, sizeof(etag_buf));
            (void) s3_set_header(r, "ETag", etag_buf);
        }
    }

    /* Full-object checksum verify (client-supplied) + echo; failures remove the
     * object and send the matching 400. */
    if (s3_put_checksum_failed(r, (const char *) fs_path,
                               cf->common.root_canon))
    {
        return;
    }

    (void) s3_apply_put_tagging_header(r, (const char *) fs_path,
                                       cf->common.root_canon);
    (void) s3_apply_put_user_metadata(r, (const char *) fs_path,
                                      cf->common.root_canon);
    s3_put_finalize_ok(r, body_bytes, body_mode);
}
