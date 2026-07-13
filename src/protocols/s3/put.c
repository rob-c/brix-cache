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
    brix_vfs_staged_t *staged, const char *fs_path, ngx_uint_t body_mode)
{
    const char        *root_canon = cf->common.root_canon;
    ngx_table_elt_t   *dcl;
    uint64_t           expected = 0;
    ngx_thread_pool_t *pool;
    size_t             i;

    dcl = brix_http_find_header(r, "x-amz-decoded-content-length",
                                  sizeof("x-amz-decoded-content-length") - 1);
    if (dcl == NULL || dcl->value.len == 0) {
        brix_vfs_staged_abort(staged, 1);
        s3_put_finalize_client_error(r, NGX_HTTP_BAD_REQUEST,
            "MissingContentLength",
            "Streaming upload is missing x-amz-decoded-content-length.");
        return;
    }
    for (i = 0; i < dcl->value.len; i++) {
        u_char d = dcl->value.data[i];
        if (d < '0' || d > '9') {
            brix_vfs_staged_abort(staged, 1);
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
            brix_vfs_staged_abort(staged, 1);
            s3_put_finalize_error(r);
            return;
        }
        t = task->ctx;                  /* ngx_thread_task_alloc zeroes ctx */
        t->r         = r;
        t->staged    = staged;
        t->expected  = expected;
        t->body_mode = body_mode;
        s3_build_chunk_verify(r, cf, &t->verify);   /* W6a */
        ngx_cpystrn((u_char *) t->fs_path, (u_char *) fs_path,
                    sizeof(t->fs_path));
        ngx_cpystrn((u_char *) t->root_canon, (u_char *) root_canon,
                    sizeof(t->root_canon));
        brix_task_bind(task, s3_chunk_aio_thread, s3_chunk_aio_done);

        if (ngx_thread_task_post(pool, task) != NGX_OK) {
            brix_vfs_staged_abort(staged, 1);
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
        if (s3_aws_chunked_decode_to_fd(r, brix_vfs_staged_fd(staged), fs_path, expected,
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
        ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    s3_put_body_inner(r);
    brix_imp_request_end();
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
        brix_vfs_ctx_t pctx;

        s3_build_vfs_ctx(r, parent, cf, &pctx);
        if (brix_vfs_mkdir(&pctx, 0755, 0 /* no parents */) != NGX_OK
            && errno != EEXIST)
        {
            int mk_errno = errno;  /* capture before logging clobbers it */
            brix_log_safe_path(r->connection->log, NGX_LOG_ERR, mk_errno,
                                 "s3: mkdir(\"%s\") failed", parent);
            s3_put_finalize_fs_error(r, mk_errno);
            return 1;
        }
    }

    /* Write the zero-byte sentinel (confined create via the VFS seam). */
    fd = brix_vfs_open_fd(r->connection->log, cf->common.root_canon,
                            (const char *) fs_path,
                            O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        int open_errno = errno;  /* capture before logging clobbers it */
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR, open_errno,
                             "s3: open(\"%s\") for sentinel failed",
                             (const char *) fs_path);
        s3_put_finalize_fs_error(r, open_errno);
        return 1;
    }
    close(fd);

    s3_dashboard_identity(r, cf, identity, sizeof(identity));
    (void) brix_dashboard_http_start_identity(r, (const char *) fs_path,
        identity, "", BRIX_XFER_PROTO_S3, BRIX_XFER_DIR_WRITE,
        "PutObjectSentinel", 0);
    BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_DIR_SENTINEL]);
    BRIX_S3_METRIC_INC(put_body_total[BRIX_S3_PUT_EMPTY]);
    s3_put_finalize_empty_ok(r);
    return 1;
}


/*
 * s3put_state_t — file-local scratch threaded across the s3_put_body_inner
 * phase helpers.
 *
 * WHAT: carries the per-request PUT state (config, ctx, resolved path, staged
 *   handle, body classification) that the precondition / open / stream / commit
 *   phases each read and refine, instead of a single 197-NLOC procedure holding
 *   it all as locals.
 * WHY: the four phases have a strict data dependency (path → staged → body_mode
 *   → committed object) but each has several early-return finalize paths; a
 *   shared struct lets every phase signal "done, caller must return" without a
 *   goto and without re-deriving state.  No new globals — one stack instance per
 *   request, passed by pointer.
 * HOW: s3_put_body_inner zero-inits one instance, runs the phases in order, and
 *   returns as soon as any phase reports it already finalized the request.
 */
typedef struct {
    ngx_http_request_t       *r;
    ngx_http_s3_loc_conf_t   *cf;
    const u_char             *fs_path;
    brix_vfs_staged_t        *staged;
    brix_codec_id_t           put_codec;
    size_t                    body_bytes;
    ngx_uint_t                body_mode;
    brix_http_body_summary_t  body_summary;
} s3put_state_t;


/*
 * s3put_ensure_parent_dirs — create the object's parent prefix if absent.
 *
 * WHAT: derives the parent directory of fs_path and ensures it exists via the
 *   confined VFS mkdir (with a probe fast-path for the hot "many objects into
 *   one prefix" case).
 * WHY: keeps the phase-46 W2a probe-then-mkdir optimization and its DAC-denied
 *   → 403 mapping in one focused helper, out of the top-level flow.
 * HOW: returns NGX_OK to continue; returns NGX_DONE after finalizing the
 *   request with an fs error (caller must return).
 */
static ngx_int_t
s3put_ensure_parent_dirs(s3put_state_t *st)
{
    char   parent[PATH_MAX];
    char  *last_slash;
    size_t flen = strlen((const char *) st->fs_path);

    if (flen >= sizeof(parent)) {
        return NGX_OK;
    }

    memcpy(parent, st->fs_path, flen + 1);
    last_slash = strrchr(parent, '/');
    if (last_slash == NULL || last_slash == parent) {
        return NGX_OK;
    }

    *last_slash = '\0';

    {
        brix_vfs_ctx_t  pctx;
        brix_vfs_stat_t pst;

        /*
         * phase-46 W2a: fast-path the common "many objects into one prefix"
         * pattern.  A single confined probe that finds an existing directory
         * replaces the per-path-component mkdirat(EEXIST) storm of the recursive
         * mkdir. A symlink or a miss falls through to the confined vfs_mkdir,
         * which re-enforces confinement.
         */
        s3_build_vfs_ctx(st->r, parent, st->cf, &pctx);
        if (brix_vfs_probe(&pctx, 1 /* no-follow */, &pst) == NGX_OK
            && pst.is_directory)
        {
            /* parent prefix already exists — nothing to create */
            return NGX_OK;
        }
    }

    {
        brix_vfs_ctx_t pvctx;

        s3_build_vfs_ctx(st->r, parent, st->cf, &pvctx);
        if (brix_vfs_mkdir(&pvctx, 0755, 1 /* parents */) != NGX_OK
            && errno != EEXIST)
        {
            int mk_errno = errno;  /* capture before logging clobbers it */
            brix_log_safe_path(st->r->connection->log, NGX_LOG_ERR, mk_errno,
                                 "s3: mkdirs_for(\"%s\") failed",
                                 (const char *) st->fs_path);
            /* DAC-denied create of a parent dir → 403, not 500. */
            s3_put_finalize_fs_error(st->r, mk_errno);
            return NGX_DONE;
        }
    }

    return NGX_OK;
}


/*
 * s3put_precondition — resolve the object, run the sentinel fast-path, and
 * ensure parent directories.
 *
 * WHAT: the pre-write phase — validates fs_path, handles the directory-sentinel
 *   create-and-return path, then creates any missing parent prefix.
 * WHY: groups the checks that must pass before we open a staged file, each with
 *   its own finalize-and-return path, into one place.
 * HOW: returns NGX_OK to continue to the open phase; returns NGX_DONE when the
 *   request has already been finalized (missing path, sentinel handled, or a
 *   parent-dir error).
 */
static ngx_int_t
s3put_precondition(s3put_state_t *st)
{
    if (st->fs_path == NULL) {
        s3_put_finalize_error(st->r);
        return NGX_DONE;
    }

    /* Directory-sentinel objects take a separate create-dir-and-return path. */
    if (s3_put_try_sentinel(st->r, st->cf, st->fs_path)) {
        return NGX_DONE;
    }

    /* Create parent directories if needed using the shared confined mkdir helper. */
    return s3put_ensure_parent_dirs(st);
}


/*
 * s3put_open_target — open the staged (exclusive-create) file for the object.
 *
 * WHAT: opens a staged VFS handle into which the body is written before the
 *   atomic commit.
 * WHY: the phase-74 exclusive-create semantics are frozen here — this helper is
 *   the single place that opens the target, so the staged mode/perms live in
 *   exactly one spot.
 * HOW: on success stores the handle in st->staged and returns NGX_OK; on failure
 *   finalizes with the confinement-aware fs error (403 not 500) and returns
 *   NGX_DONE.
 */
static ngx_int_t
s3put_open_target(s3put_state_t *st)
{
    brix_vfs_ctx_t svctx;
    int            staged_err = 0;

    /* A transient stack ctx is fine: brix_vfs_staged_open deep-copies the ctx
     * (and the strings it points at) onto r->pool, so the handle survives the async
     * body-write completion (put_aio/put_chunk commit after this function returns). */
    s3_build_vfs_ctx(st->r, (const char *) st->fs_path, st->cf, &svctx);
    st->staged = brix_vfs_staged_open(&svctx, 0600, 16, &staged_err);
    if (st->staged == NULL) {
        int open_errno = staged_err;   /* the VFS open captured errno */
        brix_log_safe_path(st->r->connection->log, NGX_LOG_ERR, open_errno,
                             "s3: staged open for \"%s\" failed",
                             (const char *) st->fs_path);
        /* A DAC-denied / confinement-blocked create is a 403, not a 500. */
        s3_put_finalize_fs_error(st->r, open_errno);
        return NGX_DONE;
    }

    return NGX_OK;
}


/*
 * s3put_stream_aws_chunked — decode and finalize an aws-chunked body.
 *
 * WHAT: routes an aws-chunked PUT/UploadPart body through the streaming
 *   de-chunker, rejecting a combined inner content-coding first.
 * WHY: aws-chunked bodies carry chunk framing that must be stripped; a combined
 *   "aws-chunked,gzip" would be stored still-compressed (silent corruption), so
 *   it is rejected with the same 400 the non-chunked codec path uses.
 * HOW: always terminal — either aborts the staged file and finalizes a codec
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
        brix_vfs_staged_abort(st->staged, 1);
        s3_put_finalize_codec_error(st->r, NGX_HTTP_BAD_REQUEST);
        return;
    }
    s3_put_streaming(st->r, st->cf, st->staged, (const char *) st->fs_path,
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
 *   NGX_DONE after aborting the staged file and finalizing a 400.
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
            brix_vfs_staged_abort(st->staged, 1);
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
        brix_vfs_staged_abort(st->staged, 1);
        s3_put_finalize_error(st->r);
        return NGX_DONE;
    }

    t = task->ctx;
    t->r          = st->r;
    t->staged     = st->staged;
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
        brix_vfs_staged_abort(st->staged, 1);
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
 *   staged file and finalizing the mapped error (413/400 codec, else 500).
 */
static ngx_int_t
s3put_stream_sync(s3put_state_t *st)
{
    ngx_int_t wrc;
    ngx_int_t decode_status = 0;

    if (st->put_codec != BRIX_CODEC_IDENTITY) {
        wrc = brix_http_body_decode_to_fd(st->r, brix_vfs_staged_fd(st->staged),
                                            (const char *) st->fs_path,
                                            st->put_codec,
                                            BRIX_DECODE_MAX_OUTPUT,
                                            &st->body_summary,
                                            &decode_status);
    } else {
        wrc = brix_http_body_write_to_fd(st->r, brix_vfs_staged_fd(st->staged),
                                            (const char *) st->fs_path,
                                            &st->body_summary);
    }

    if (wrc == NGX_OK) {
        return NGX_OK;
    }

    brix_vfs_staged_abort(st->staged, 1);
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
static ngx_int_t
s3put_stream_body(s3put_state_t *st)
{
    char      identity[128];
    ngx_int_t rc;

    if (brix_http_body_summary(st->r, &st->body_summary) != NGX_OK) {
        brix_vfs_staged_abort(st->staged, 1);
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
static void
s3put_commit_and_headers(s3put_state_t *st)
{
    if (s3_commit_put(st->r, st->r->connection->log,
                      st->cf->common.root_canon, st->staged,
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


void
s3_put_body_inner(ngx_http_request_t *r)
{
    ngx_http_s3_req_ctx_t *s3ctx;
    s3put_state_t          st;

    ngx_memzero(&st, sizeof(st));
    st.r         = r;
    st.cf        = ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    s3ctx        = ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    st.fs_path   = s3ctx != NULL ? (const u_char *) s3ctx->fs_path : NULL;
    st.put_codec = BRIX_CODEC_IDENTITY;
    st.body_mode = BRIX_S3_PUT_EMPTY;

    if (s3put_precondition(&st) == NGX_DONE) {
        return;
    }

    if (s3put_open_target(&st) == NGX_DONE) {
        return;
    }

    if (s3put_stream_body(&st) == NGX_DONE) {
        return;
    }

    s3put_commit_and_headers(&st);
}
