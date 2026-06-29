/*
 * put_chunk.c - extracted concern
 * Phase-38 split of put.c; behavior-identical.
 */
#include "s3_put_internal.h"


/*
 * s3_chunk_finalize — post-decode steps that must run on the event loop:
 * commit the staged object, set the ETag, verify the (trailer or default)
 * checksum, store tags, and send 200.  Shared by the synchronous fallback and
 * the offload completion; `staged` has been written but not yet committed.
 */
void
s3_chunk_finalize(ngx_http_request_t *r, const char *root_canon,
    const char *fs_path, xrootd_staged_file_t *staged,
    const s3_chunk_trailer_t *trailer, uint64_t expected, ngx_uint_t body_mode)
{
    if (s3_commit_put(r, r->connection->log, root_canon, staged,
                      fs_path) != NGX_OK)
    {
        if (s3_put_commit_conflict(r)) {
            return;
        }
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "s3: staged commit to \"%s\" failed", fs_path);
        s3_put_finalize_error(r);
        return;
    }

    {
        xrootd_vfs_ctx_t  fctx;
        xrootd_vfs_stat_t fst;
        char              etag_buf[48];

        xrootd_vfs_ctx_init(&fctx, r->pool, r->connection->log, XROOTD_PROTO_S3,
            root_canon, NULL, 0 /* allow_write */, 0 /* is_tls */, NULL, fs_path);
        if (xrootd_vfs_probe(&fctx, 1 /* no-follow */, &fst) == NGX_OK) {
            struct stat sb;

            ngx_memzero(&sb, sizeof(sb));
            sb.st_mtime = fst.mtime;
            sb.st_size  = fst.size;
            s3_etag(&sb, etag_buf, sizeof(etag_buf));
            (void) s3_set_header(r, "ETag", etag_buf);
        }
    }

    if (trailer->algo_token[0] != '\0') {
        switch (s3_put_trailer_checksum_apply(r, fs_path, root_canon,
                                              trailer->algo_token,
                                              trailer->value))
        {
        case S3_CKSUM_MISMATCH:
            s3_put_finalize_bad_digest(r);
            return;
        case S3_CKSUM_CONFLICT:
            s3_put_finalize_invalid_request(r);
            return;
        default:
            break;
        }
    } else if (s3_put_checksum_failed(r, fs_path, root_canon)) {
        return;
    }

    (void) s3_apply_put_tagging_header(r, fs_path, root_canon);
    (void) s3_apply_put_user_metadata(r, fs_path, root_canon);
    s3_put_finalize_ok(r, expected, body_mode);
}


/* Decode-failure path: abort the staged temp and send the mapped S3 error. */
void
s3_chunk_decode_failed(ngx_http_request_t *r, const char *root_canon,
    xrootd_staged_file_t *staged, int http_status)
{
    xrootd_staged_abort(r->connection->log, root_canon, staged, 1);
    if (http_status >= 500) {
        s3_put_finalize_error(r);
    } else if (http_status == NGX_HTTP_FORBIDDEN) {
        /* W6a: a per-chunk signature mismatch — surface as SignatureDoesNotMatch. */
        s3_put_finalize_client_error(r, NGX_HTTP_FORBIDDEN,
            "SignatureDoesNotMatch",
            "The chunk signature does not match the calculated signature.");
    } else {
        s3_put_finalize_client_error(r, NGX_HTTP_BAD_REQUEST, "InvalidRequest",
            "The aws-chunked request body could not be decoded.");
    }
}


/*
 * phase-46 W1b: aws-chunked decode offload.  The decode is a blocking
 * pread/pwrite state machine over the (often spooled) body, so it runs on the
 * thread pool; the completion commits/checksums/finalizes on the event loop.
 * The worker uses the task's own `window` scratch — it never touches r->pool.
 */

void
s3_chunk_aio_thread(void *data, ngx_log_t *log)
{
    s3_chunk_aio_t *t = data;

    (void) log;
    t->http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    t->rc = s3_aws_chunked_decode_to_fd(t->r, t->staged.fd, t->fs_path,
                                        t->expected, &t->trailer,
                                        &t->http_status, t->window,
                                        &t->verify);
}


/*
 * s3_build_chunk_verify — W6a: assemble the per-chunk verification context from
 * the location flag + the SigV4 material auth retained on the request ctx.  Left
 * disabled (zeroed) unless verification is configured AND a signed request was
 * authenticated (an anonymous endpoint has no secret to verify against).
 */
void
s3_build_chunk_verify(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    s3_chunk_verify_t *v)
{
    ngx_http_s3_req_ctx_t *rx;

    ngx_memzero(v, sizeof(*v));
    if (!cf->verify_chunk_signatures) {
        return;
    }
    rx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
    if (rx == NULL || !rx->have_sigv4) {
        return;
    }
    v->enabled = 1;
    ngx_memcpy(v->signing_key, rx->sigv4_signing_key, 32);
    ngx_cpystrn((u_char *) v->seed_signature,
                (u_char *) rx->sigv4_seed_signature, sizeof(v->seed_signature));
    ngx_cpystrn((u_char *) v->amz_date,
                (u_char *) rx->sigv4_amz_date, sizeof(v->amz_date));
    ngx_cpystrn((u_char *) v->scope,
                (u_char *) rx->sigv4_scope, sizeof(v->scope));
}


void
s3_chunk_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    s3_chunk_aio_t     *t = task->ctx;
    ngx_http_request_t *r = t->r;

    if (t->rc != NGX_OK) {
        s3_chunk_decode_failed(r, t->root_canon, &t->staged, t->http_status);
        return;
    }
    s3_chunk_finalize(r, t->root_canon, t->fs_path, &t->staged, &t->trailer,
                      t->expected, t->body_mode);
}
