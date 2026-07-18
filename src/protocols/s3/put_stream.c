/*
 * put_stream.c - (split from put.c) the s3_put_body_inner stream + commit
 * phases; behavior-identical.
 */
#include "s3_put_internal.h"

/*
 * s3put_stream_aws_chunked — decode and finalize an aws-chunked body.
 *
 * WHAT: routes an aws-chunked PUT/UploadPart body through the streaming
 *   de-chunker, rejecting a combined inner content-coding first.
 * WHY: aws-chunked bodies carry chunk framing that must be stripped; a combined
 *   "aws-chunked,gzip" would be stored still-compressed (silent corruption), so
 *   it is rejected with the same 400 the non-chunked codec path uses.
 * HOW: always terminal — either aborts the write session and finalizes a codec
 *   error, or hands off to s3_put_streaming (which finalizes asynchronously).
 */
static void
s3put_stream_aws_chunked(s3put_state_t *st)
{
    /* A combined Content-Encoding such as "aws-chunked,gzip" means the body
     * was compressed THEN chunk-framed.  The streaming de-chunker strips only
     * the chunk envelope, so the inner-compressed payload would be stored
     * still compressed (silent object corruption).  Reject rather than store
     * undecoded bytes — the same invariant the non-chunked path enforces with
     * 400 below.  Plain aws-chunked (no inner coding) continues normally. */
    if (s3_aws_chunked_has_inner_coding(st->r)) {
        brix_vfs_writer_abort(st->writer);
        s3_put_finalize_codec_error(st->r, NGX_HTTP_BAD_REQUEST);
        return;
    }
    s3_put_streaming(st->r, st->cf, st->writer, (const char *) st->fs_path,
                     st->body_mode);
}


/*
 * s3put_select_codec — resolve any Content-Encoding into st->put_codec.
 *
 * WHAT: parses the request Content-Encoding header to a codec id used by the
 *   body-write phase.
 * WHY: an unknown / not-compiled-in encoding must never be stored undecoded —
 *   it is a 400 client error, decided once here.
 * HOW: returns NGX_OK (st->put_codec set, defaulting to IDENTITY); returns
 *   NGX_DONE after aborting the write session and finalizing a 400.
 */
static ngx_int_t
s3put_select_codec(s3put_state_t *st)
{
    ngx_table_elt_t *ce = brix_http_find_header(
        st->r, "Content-Encoding", sizeof("Content-Encoding") - 1);

    if (ce != NULL && ce->value.len > 0) {
        const brix_codec_desc_t *d = brix_codec_by_http_token(
            (const char *) ce->value.data, ce->value.len);
        if (d == NULL || !d->available) {
            /* Unknown / not-compiled-in Content-Encoding: never store the
             * undecoded bytes — reject as a client error (400), not 500. */
            brix_vfs_writer_abort(st->writer);
            s3_put_finalize_codec_error(st->r, NGX_HTTP_BAD_REQUEST);
            return NGX_DONE;
        }
        st->put_codec = d->id;
    }

    return NGX_OK;
}


/*
 * s3put_stream_offload — try to hand the plain body write to the thread pool.
 *
 * WHAT: for identity-encoded non-empty bodies with a thread pool configured,
 *   posts the write to the pool (phase-46 W1a) so large/spooled uploads do not
 *   block the event loop.
 * WHY: keeps the async-offload task setup and its several failure finalizations
 *   out of the top-level flow, while preserving the exact eligibility condition.
 * HOW: returns NGX_DONE when the offload path took ownership (posted, or already
 *   finalized on error); returns NGX_AGAIN when not eligible so the caller runs
 *   the synchronous write.
 */
static ngx_int_t
s3put_stream_offload(s3put_state_t *st)
{
    ngx_thread_task_t *task;
    s3_put_aio_t      *t;

    /*
     * phase-46 W1a: offload the body write to the thread pool for ALL plain
     * (identity-encoded) bodies — including spooled and mixed ones, not just
     * in-memory.  The worker fn (s3_put_aio_thread) already streams every buf,
     * memory and file-backed, via brix_http_body_write_to_fd (kernel
     * copy_file_range for the spooled nginx temp file), so large uploads — the
     * ones nginx spools to disk — stop blocking the event loop.  Content-Encoding
     * decode (put_codec != IDENTITY) and aws-chunked (handled above) still run
     * synchronously.
     */
    if (!(st->body_summary.bytes > 0
          && st->put_codec == BRIX_CODEC_IDENTITY
          && s3_thread_pool(st->cf) != NULL))
    {
        return NGX_AGAIN;
    }

    task = ngx_thread_task_alloc(st->r->pool, sizeof(s3_put_aio_t));
    if (task == NULL) {
        brix_vfs_writer_abort(st->writer);
        s3_put_finalize_error(st->r);
        return NGX_DONE;
    }

    t = task->ctx;
    t->r          = st->r;
    t->writer     = st->writer;
    t->len        = st->body_summary.bytes;
    t->body_mode  = st->body_mode;
    t->body_bytes = st->body_bytes;
    ngx_cpystrn((u_char *) t->final_path, (u_char *) st->fs_path,
                sizeof(t->final_path));
    ngx_cpystrn((u_char *) t->root_canon,
                (u_char *) st->cf->common.root_canon, sizeof(t->root_canon));

    /*
     * Phase 31 W2: no full-body collection — the thread streams the
     * in-memory body bufs straight to the staged fd (s3_put_aio_thread).
     */

    brix_task_bind(task, s3_put_aio_thread, s3_put_aio_done);

    if (ngx_thread_task_post(st->cf->common.thread_pool, task) != NGX_OK) {
        brix_vfs_writer_abort(st->writer);
        s3_put_finalize_error(st->r);
        return NGX_DONE;
    }

    st->r->main->count++;
    return NGX_DONE;
}


/*
 * s3put_stream_sync — write the body to the staged fd synchronously.
 *
 * WHAT: the inline body-write path — decodes a Content-Encoding body or streams
 *   an identity body straight to the staged fd.
 * WHY: reached only when the async offload declined (encoded body, empty body,
 *   or no thread pool); maps a decode failure to the right S3 client error.
 * HOW: returns NGX_OK on a successful write; returns NGX_DONE after aborting the
 *   write session and finalizing the mapped error (413/400 codec, else 500).
 */
static ngx_int_t
s3put_stream_sync(s3put_state_t *st)
{
    ngx_int_t wrc;
    ngx_int_t decode_status = 0;

    if (st->put_codec != BRIX_CODEC_IDENTITY) {
        ngx_fd_t wfd = brix_vfs_writer_fd(st->writer);

        /* Codec decode writes through a raw fd; a driver-backed object session
         * has none (NGX_INVALID_FILE) — reject with 501 rather than corrupt. */
        if (wfd == NGX_INVALID_FILE) {
            errno = ENOSYS;
            wrc = NGX_ERROR;
            decode_status = NGX_HTTP_NOT_IMPLEMENTED;
        } else {
            wrc = brix_http_body_decode_to_fd(st->r, wfd,
                                                (const char *) st->fs_path,
                                                st->put_codec,
                                                BRIX_DECODE_MAX_OUTPUT,
                                                &st->body_summary,
                                                &decode_status);
        }
    } else {
        wrc = brix_http_body_write_to_writer(st->r, st->writer);
    }

    if (wrc == NGX_OK) {
        return NGX_OK;
    }

    brix_vfs_writer_abort(st->writer);
    /* Map a decode failure to a clean S3 client error (413 bomb / 400
     * malformed); a genuine I/O failure (decode_status 0 or 5xx) stays
     * a 500. */
    if (decode_status == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE
        || decode_status == NGX_HTTP_BAD_REQUEST
        || decode_status == NGX_HTTP_UNSUPPORTED_MEDIA_TYPE)
    {
        s3_put_finalize_codec_error(st->r, decode_status
            == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE
            ? NGX_HTTP_REQUEST_ENTITY_TOO_LARGE
            : NGX_HTTP_BAD_REQUEST);
    } else {
        s3_put_finalize_error(st->r);
    }
    return NGX_DONE;
}


/*
 * s3put_stream_body — summarize the body, emit the dashboard start, and write.
 *
 * WHAT: classifies the request body, records the dashboard/xfer start, then
 *   routes to the aws-chunked, async-offload, or synchronous write path.
 * WHY: consolidates every body-handling branch behind one phase entry so the
 *   top-level flow reads as precondition → open → stream → commit.
 * HOW: returns NGX_OK when the body was written synchronously and the caller
 *   should commit; returns NGX_DONE when a terminal path (chunked, offload, or
 *   an error) already finalized or will asynchronously finalize the request.
 */
ngx_int_t
s3put_stream_body(s3put_state_t *st)
{
    char      identity[128];
    ngx_int_t rc;

    if (brix_http_body_summary(st->r, &st->body_summary) != NGX_OK) {
        brix_vfs_writer_abort(st->writer);
        s3_put_finalize_error(st->r);
        return NGX_DONE;
    }

    st->body_bytes = st->body_summary.bytes;
    st->body_mode = s3_put_body_mode(&st->body_summary);
    s3_dashboard_identity(st->r, st->cf, identity, sizeof(identity));
    (void) brix_dashboard_http_start_identity(st->r, (const char *) st->fs_path,
        identity, "", BRIX_XFER_PROTO_S3, BRIX_XFER_DIR_WRITE,
        s3_dashboard_put_op(st->r), (int64_t) st->body_bytes);

    /*
     * AWS streaming upload (aws-chunked): the body carries chunk framing that
     * must be decoded to the object bytes — storing it verbatim corrupts every
     * object from a default modern SDK/CLI client.  Routed through its own
     * decode → commit → checksum → finalize path.
     */
    if (s3_body_is_aws_chunked(st->r)) {
        s3put_stream_aws_chunked(st);
        return NGX_DONE;
    }

    if (s3put_select_codec(st) == NGX_DONE) {
        return NGX_DONE;
    }

    rc = s3put_stream_offload(st);
    if (rc == NGX_DONE) {
        return NGX_DONE;
    }

    /* Not eligible for offload — write synchronously (encoded / empty / no pool). */
    return s3put_stream_sync(st);
}


/*
 * s3put_emit_etag — set the ETag header the S3 API requires on PutObject 200.
 *
 * WHAT: probes the freshly committed object and emits an ETag derived from its
 *   final size and mtime.
 * WHY: S3 clients rely on the ETag to confirm the stored object; a probe miss
 *   silently skips it (the object still committed).
 * HOW: pure side-effecting emit — no return value; called after a successful
 *   commit.
 */
static void
s3put_emit_etag(s3put_state_t *st)
{
    brix_vfs_ctx_t  fctx;
    brix_vfs_stat_t fst;
    char            etag_buf[48];

    s3_build_vfs_ctx(st->r, (const char *) st->fs_path, st->cf, &fctx);
    if (brix_vfs_probe(&fctx, 1 /* no-follow */, &fst) == NGX_OK) {
        struct stat final_sb;

        ngx_memzero(&final_sb, sizeof(final_sb));
        final_sb.st_mtime = fst.mtime;
        final_sb.st_size  = fst.size;
        s3_etag(&final_sb, etag_buf, sizeof(etag_buf));
        (void) s3_set_header(st->r, "ETag", etag_buf);
    }
}


/*
 * s3put_commit_and_headers — atomically commit the object, then emit headers.
 *
 * WHAT: promotes the staged file to the final object, verifies the client
 *   checksum, applies tagging/user-metadata, and finalizes the 200.
 * WHY: the post-write phase — every step here runs only after the body reached
 *   the staged fd, and each has its own finalize-and-return path.
 * HOW: always terminal — returns nothing; finalizes the request on the commit
 *   error, checksum-mismatch, or success path.
 */
void
s3put_commit_and_headers(s3put_state_t *st)
{
    if (s3_commit_put(st->r, st->r->connection->log,
                      st->cf->common.root_canon, st->writer,
                      (const char *) st->fs_path) != NGX_OK)
    {
        if (s3_put_commit_conflict(st->r)) {
            return;
        }
        brix_log_safe_path(st->r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "s3: staged commit to \"%s\" failed",
                             (const char *) st->fs_path);
        s3_put_finalize_error(st->r);
        return;
    }

    /* S3 API requires ETag on PutObject 200 response */
    s3put_emit_etag(st);

    /* Full-object checksum verify (client-supplied) + echo; failures remove the
     * object and send the matching 400. */
    if (s3_put_checksum_failed(st->r, (const char *) st->fs_path,
                               st->cf->common.root_canon))
    {
        return;
    }

    (void) s3_apply_put_tagging_header(st->r, (const char *) st->fs_path,
                                       st->cf->common.root_canon);
    (void) s3_apply_put_user_metadata(st->r, (const char *) st->fs_path,
                                      st->cf->common.root_canon);
    s3_put_finalize_ok(st->r, st->body_bytes, st->body_mode);
}
