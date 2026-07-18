/*
 * post_object.c - (kept) routing + shared helpers
 * Phase-38 split of post_object.c; behavior-identical.
 */
#include "s3_post_internal.h"

ngx_int_t
s3_post_error(ngx_http_request_t *r, ngx_uint_t status, const char *code,
    const char *message)
{
    return s3_send_xml_error(r, status, code, message);
}



/*
 * WHAT: Copy `len` raw form bytes into a fixed C-string buffer `dst`.
 * WHY:  Form values are attacker-controlled; we reject embedded NUL bytes so a
 *       value cannot be truncated when later treated as a C string (smuggling a
 *       different key/policy past length-based checks). HOW: bounds-check, scan
 *       for NUL, then copy and terminate.
 * Returns NGX_OK, or NGX_ERROR if it would overflow or contains a NUL.
 */
ngx_int_t
s3_post_copy_text(const u_char *data, size_t len, char *dst, size_t dstsz)
{
    size_t i;

    if (len >= dstsz) {
        return NGX_ERROR;
    }

    /* Reject embedded NUL so dst is an unambiguous C string downstream. */
    for (i = 0; i < len; i++) {
        if (data[i] == '\0') {
            return NGX_ERROR;
        }
    }

    ngx_memcpy(dst, data, len);
    dst[len] = '\0';
    return NGX_OK;
}


/*
 * WHAT: Find the first occurrence of `needle` within the binary buffer `hay`.
 * WHY:  The multipart body is binary (file bytes may contain NUL), so libc
 *       strstr() cannot be used to locate boundary/CRLF markers. HOW: naive
 *       O(n*m) byte scan, which is adequate for the small needles used here.
 * Returns a pointer into `hay`, or NULL if not found.
 */
u_char *
s3_memmem(u_char *hay, size_t hay_len, const u_char *needle,
    size_t needle_len)
{
    size_t i;

    if (needle_len == 0 || hay_len < needle_len) {
        return NULL;
    }

    for (i = 0; i <= hay_len - needle_len; i++) {
        if (hay[i] == needle[0]
            && ngx_memcmp(hay + i, needle, needle_len) == 0)
        {
            return hay + i;
        }
    }

    return NULL;
}


/*
 * WHAT: Reduce a client-supplied filename to its basename, in place.
 * WHY:  Browsers may send a full path (e.g. "C:\\Users\\x\\f.txt" or
 *       "/home/x/f.txt") in the multipart filename; only the final component is
 *       meaningful and stripping leading path segments removes a directory-
 *       traversal vector before the name is used in ${filename} expansion. HOW:
 *       take whichever of the last '/' or last '\\' appears later, then shift
 *       the tail (incl. its NUL) down to the front of the buffer.
 */
void
s3_post_basename(char *s)
{
    char *slash;
    char *bslash;
    char *base;

    slash = strrchr(s, '/');
    bslash = strrchr(s, '\\');
    base = slash > bslash ? slash : bslash;     /* later separator wins */

    if (base != NULL) {
        ngx_memmove(s, base + 1, strlen(base + 1) + 1);
    }
}


/*
 * WHAT: Commit the uploaded file bytes to `fs_path` and compute its ETag.
 * WHY:  Uses the VFS staged-write lifecycle (write to a temp, atomically rename
 *       on success) so a partial/failed upload never leaves a corrupt object
 *       visible — the same durability contract as PUT. The VFS layer keeps every
 *       op confined to root_canon and meters the publish (OP_WRITE) + access log.
 * HOW:  ensure the parent directory exists (brix_vfs_mkdir, parents=1), open a
 *       staged handle (brix_vfs_staged_open), pwrite the whole buffer to its
 *       fd, commit (atomic rename), then stat the result for the ETag.
 * Cleanup: any write error calls brix_vfs_staged_abort (discard temp) before
 *       returning NGX_ERROR, so no orphan temp file is left behind.
 * Returns NGX_OK (object committed, etag set) or NGX_ERROR.
 */
ngx_int_t
s3_post_write_object(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, const char *fs_path, char *etag,
    size_t etag_sz)
{
    brix_vfs_ctx_t     vctx;
    brix_vfs_writer_t   *w;
    int                  vfs_err;
    struct stat          sb;

    /* Create the key's parent directories (S3 keys may embed '/') through the
     * VFS mkdir (parents=1).  EEXIST is benign; any other mkdir failure aborts
     * the write. */
    {
        char   parent[PATH_MAX];
        char  *last_slash;
        size_t flen = strlen(fs_path);

        if (flen < sizeof(parent)) {
            ngx_memcpy(parent, fs_path, flen + 1);
            last_slash = strrchr(parent, '/');
            /* Skip if the slash is the root itself (last_slash == parent). */
            if (last_slash && last_slash != parent) {
                brix_vfs_ctx_t pctx;

                *last_slash = '\0';
                s3_build_vfs_ctx(r, parent, cf, &pctx);
                if (brix_vfs_mkdir(&pctx, 0755, 1 /* parents */) != NGX_OK
                    && errno != EEXIST)
                {
                    return NGX_ERROR;
                }
            }
        }
    }

    s3_build_vfs_ctx(r, fs_path, cf, &vctx);
    w = brix_vfs_writer_open(&vctx, BRIX_VFS_O_ATOMIC, cf->common.verify_write,
                             &vfs_err);
    if (w == NULL) {
        errno = vfs_err;
        return NGX_ERROR;
    }

    /* Write the full in-memory file part through the unified write session — it
     * routes to the backend's driver (in-place fd or staged object upload), so a
     * non-POSIX backend is no longer bypassed by a raw fd-keyed pwrite. */
    if (brix_vfs_writer_write(w, form->file_data, form->file_len, 0) != NGX_OK) {
        brix_vfs_writer_abort(w);
        return NGX_ERROR;
    }

    /* Atomically publish the staged temp as the final object (folds the
     * verify-on-write read-back when the export opts in). */
    if (brix_vfs_writer_commit(w) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Best-effort ETag: a stat failure here is non-fatal (empty ETag). The VFS
     * probe is confined + no-follow (so a symlink at the final name is not
     * followed) and non-metered (the PostObject op already accounts for this
     * upload; a per-upload OP_STAT would inflate the stat counter). */
    {
        brix_vfs_stat_t vst;

        if (brix_vfs_probe(&vctx, 1 /* no-follow */, &vst) == NGX_OK) {
            ngx_memzero(&sb, sizeof(sb));
            sb.st_mtime = vst.mtime;
            sb.st_size  = vst.size;
            s3_etag(&sb, etag, etag_sz);
            (void) s3_set_header(r, "ETag", etag);
        } else {
            etag[0] = '\0';
        }
    }

    return NGX_OK;
}


/*
 * WHAT: Request-body callback for S3 browser POST Object uploads.
 * WHY:  nginx invokes this once the full request body is buffered (registered as
 *       the body handler), so the multipart payload is available in memory here.
 *       This drives the whole pipeline; on any failure it sends the appropriate
 *       S3 error and finalizes per-method metrics — there is no return value
 *       because nginx owns the request lifecycle from a body handler.
 * HOW (ordered pipeline, each step finalizes metrics on failure):
 *   parse boundary -> read body -> parse multipart -> require key+file ->
 *   expand ${filename} and resolve the confined fs path -> verify the signed
 *   policy -> write the object -> send the success response.
 * NOTE: verifying the SIGNATURE before resolving/writing is intentional — but
 *       path resolution happens before the (potentially expensive) crypto since
 *       a bad key is a cheap reject; the object is only written post-verify.
 */

/*
 * Phase 40: the POST (form-upload) body is read asynchronously, so the dispatch
 * wrapper already cleared the impersonation principal.  Re-establish it (mirrors
 * s3_put_body_handler) so the written object is owned by the mapped user via the
 * broker rather than the unprivileged worker.  No-op unless map mode.
 */
void
s3_post_object_body_handler(ngx_http_request_t *r)
{
    ngx_http_s3_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    s3_post_object_body_handler_inner(r);
    brix_imp_request_end();
}


void
s3_post_object_body_handler_inner(ngx_http_request_t *r)
{
    ngx_http_s3_loc_conf_t *cf;
    u_char                 *body;
    size_t                  body_len;
    char                    boundary[256];
    s3_post_form_t          form;
    char                    fs_path[PATH_MAX];
    char                    etag[48];
    ngx_int_t               rc;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    ngx_memzero(&form, sizeof(form));

    if (s3_post_boundary(r, boundary, sizeof(boundary)) != NGX_OK) {
        s3_metrics_finalize_request_method(
            r, BRIX_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_BAD_REQUEST, "MalformedPOSTRequest",
                          "POST Object requires multipart/form-data."));
        return;
    }

    rc = brix_http_body_read_all(r, S3_POST_MAX_BODY, &body, &body_len);
    if (rc == NGX_DECLINED) {
        s3_metrics_finalize_request_method(
            r, BRIX_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE,
                          "EntityTooLarge", "POST body is too large."));
        return;
    }
    if (rc != NGX_OK) {
        s3_metrics_finalize_request_method(r, BRIX_S3_METHOD_POST,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (s3_post_parse_form(r, body, body_len, boundary, &form) != NGX_OK) {
        s3_metrics_finalize_request_method(
            r, BRIX_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_BAD_REQUEST, "MalformedPOSTRequest",
                          "The multipart form-data body is invalid."));
        return;
    }

    if (!form.have_file || form.key[0] == '\0') {
        s3_metrics_finalize_request_method(
            r, BRIX_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                          "POST Object requires key and file fields."));
        return;
    }

    if (s3_post_expand_filename(r, &form) != NGX_OK
        || !s3_resolve_key(cf->common.root_canon, form.key,
                           fs_path, sizeof(fs_path),
                           cf->common.cache_store_endpoint))
    {
        s3_metrics_finalize_request_method(
            r, BRIX_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                          "Access Denied."));
        return;
    }

    rc = s3_post_verify_policy(r, cf, &form);
    if (rc != NGX_OK) {
        s3_metrics_finalize_request_method(r, BRIX_S3_METHOD_POST, rc);
        return;
    }

    if (s3_post_write_object(r, cf, &form, fs_path, etag, sizeof(etag))
        != NGX_OK)
    {
        /*
         * A confined create that fails with EACCES/EPERM/EXDEV is a forbidden
         * write, not a server fault, and must surface as 403 AccessDenied (the
         * same contract the shared errno table gives every other handler).
         * Under impersonation (`brix_impersonation map`) the create is brokered
         * as the mapped user, so a missing/unmappable principal or a DAC-denied
         * target dir lands here — a clean 403, never a 500.  Genuine I/O faults
         * (EIO/ENOSPC/...) keep their 5xx mapping.  The staged-file pattern
         * leaves no orphan object behind on any of these paths.
         */
        int werrno = errno;

        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
        if (brix_http_map_errno(werrno) == NGX_HTTP_FORBIDDEN) {
            s3_metrics_finalize_request_method(
                r, BRIX_S3_METHOD_POST,
                s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                              "Access Denied."));
        } else {
            s3_metrics_finalize_request_method(
                r, BRIX_S3_METHOD_POST,
                (ngx_int_t) brix_http_map_errno(werrno));
        }
        return;
    }

    BRIX_S3_METRIC_ADD(bytes_rx_total, form.file_len);

    s3_metrics_finalize_request_method(
        r, BRIX_S3_METHOD_POST,
        s3_post_send_success(r, cf, &form, etag));
}
