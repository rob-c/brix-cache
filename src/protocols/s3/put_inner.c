/*
 * put_inner.c - (split from put.c) the s3_put_body_inner driver plus its
 * precondition / open phases; behavior-identical.
 */
#include "s3_put_internal.h"
#include "fs/vfs/vfs_backend_registry.h"  /* per-export storage-driver resolution */
#include "fs/vfs/vfs_internal.h"          /* brix_vfs_ns_leaf */
#include "fs/backend/sd.h"                /* BRIX_SD_CAP_DIRS_WRITE */

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
        /* Object-store leaf (phase-71 caps / P80.2): a namespace without
         * CAP_DIRS_WRITE has no physical catalog to mutate — parent prefixes
         * are virtual, so there is nothing to create here (and the VFS mkdir
         * caps gate would reject with EPERM, turning every first PUT into a
         * 403). Capability-driven, never scheme-driven. */
        brix_sd_instance_t *leaf = brix_vfs_ns_leaf(
            brix_vfs_backend_resolve(st->cf->common.root_canon,
                                     st->r->connection->log));

        if (leaf != NULL && !(leaf->driver->caps & BRIX_SD_CAP_DIRS_WRITE)) {
            return NGX_OK;
        }
    }

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
