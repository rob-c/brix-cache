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

    s3ctx = ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    subject = s3ctx != NULL
              ? brix_identity_subject_cstr(s3ctx->identity) : "";
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
 *   as indices into BRIX_S3_METRIC_INC(put_body_total[...]).
 */

ngx_uint_t
s3_put_body_mode(const brix_http_body_summary_t *summary)
{
    if (summary->has_spooled && summary->has_memory) {
        return BRIX_S3_PUT_MIXED;
    }
    if (summary->has_spooled) {
        return BRIX_S3_PUT_SPOOLED;
    }
    if (summary->has_memory) {
        return BRIX_S3_PUT_MEMORY;
    }
    return BRIX_S3_PUT_EMPTY;
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
    brix_vfs_writer_t *writer, const char *fs_path, ngx_uint_t body_mode)
{
    const char        *root_canon = cf->common.root_canon;
    ngx_table_elt_t   *dcl;
    uint64_t           expected = 0;
    ngx_thread_pool_t *pool;
    size_t             i;

    dcl = brix_http_find_header(r, "x-amz-decoded-content-length",
                                  sizeof("x-amz-decoded-content-length") - 1);
    if (dcl == NULL || dcl->value.len == 0) {
        brix_vfs_writer_abort(writer);
        s3_put_finalize_client_error(r, NGX_HTTP_BAD_REQUEST,
            "MissingContentLength",
            "Streaming upload is missing x-amz-decoded-content-length.");
        return;
    }
    for (i = 0; i < dcl->value.len; i++) {
        u_char d = dcl->value.data[i];
        if (d < '0' || d > '9') {
            brix_vfs_writer_abort(writer);
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
            brix_vfs_writer_abort(writer);
            s3_put_finalize_error(r);
            return;
        }
        t = task->ctx;                  /* ngx_thread_task_alloc zeroes ctx */
        t->r         = r;
        t->writer    = writer;
        t->expected  = expected;
        t->body_mode = body_mode;
        s3_build_chunk_verify(r, cf, &t->verify);   /* W6a */
        ngx_cpystrn((u_char *) t->fs_path, (u_char *) fs_path,
                    sizeof(t->fs_path));
        ngx_cpystrn((u_char *) t->root_canon, (u_char *) root_canon,
                    sizeof(t->root_canon));
        brix_task_bind(task, s3_chunk_aio_thread, s3_chunk_aio_done);

        if (ngx_thread_task_post(pool, task) != NGX_OK) {
            brix_vfs_writer_abort(writer);
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
        if (s3_aws_chunked_decode_to_fd(r, brix_vfs_writer_fd(writer), fs_path, expected,
                                        &trailer, &status, NULL, &verify)
            != NGX_OK)
        {
            s3_chunk_decode_failed(r, root_canon, writer, status);
            return;
        }
        s3_chunk_finalize(r, root_canon, fs_path, writer, &trailer, expected,
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
        ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    s3_put_body_inner(r);
    brix_imp_request_end();
}
