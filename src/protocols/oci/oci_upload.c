/*
 * oci_upload.c — the blob upload-session state machine (§D4.2, App. J.7).
 *
 * WHAT: POST/PATCH/PUT/GET/DELETE routing on `/v2/<name>/blobs/uploads[/<id>]`,
 *       plus the idle-session reaper. The bytes themselves land next door, in
 *       oci_upload_seal.c.
 * WHY:  this is the whole of `podman push`'s data plane, and its contract is
 *       resumability: a client that loses a connection halfway through a
 *       600 MiB layer must be able to ask "how much did you get?" and carry
 *       on. That is why the session's state is the STAGED FILE ITSELF rather
 *       than a record beside it — the bytes on disk are the only answer that
 *       cannot disagree with reality, and a crashed worker leaves a session
 *       that is still exactly as resumable as it was a moment before.
 *       The J.7 states follow from that directly: OPEN is a zero-length part
 *       file, ACTIVE is a non-empty one, and SEALED / ABORTED / REAPED are
 *       all "the directory is gone" — which is why every one of them answers
 *       404 and none of them needs a flag to say so.
 * HOW:  each body-carrying method records what it decided in ctx->reg and
 *       hands off to the shared async body reader; the callback finds the
 *       decision waiting for it.
 *
 * The raw namespace calls carry per-line vfs-seam-allow markers for the
 * reason oci_store.c documents at its head: this is the registry's own
 * staging area, not a VFS export.
 */

#include "oci_upload_internal.h"

#include "core/http/http_body.h"
#include "core/http/http_headers.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OCI_UPLOAD_SESSION_MODE  0700


/* "<hex><hex>" from the worker pid and the request's own randomness. The id
 * is ours to choose, opaque to the client, and only has to be unguessable
 * enough that two concurrent pushes never draw the same one. */
static void
oci_session_id(char *out, size_t outsz)
{
    (void) snprintf(out, outsz, "stg_%08lx%08lx%08lx",
                    (unsigned long) ngx_pid,
                    (unsigned long) ngx_random(),
                    (unsigned long) ngx_time());
}


static oci_upload_ctx_t *
oci_upload_ctx(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx)
{
    oci_upload_ctx_t *u = ctx->reg;

    if (u == NULL) {
        u = ngx_pcalloc(r->pool, sizeof(*u));
        ctx->reg = u;
    }
    return u;
}


/* Current staged length of a session, or -1 when the session does not exist.
 * This IS the J.7 state: -1 is SEALED/ABORTED/REAPED, 0 is OPEN, >0 ACTIVE. */
static off_t
oci_session_size(const brix_oci_store_t *st, const char *session,
    size_t session_len)
{
    char   path[PATH_MAX];
    off_t  size = 0;

    if (brix_oci_store_upload_path(st, session, session_len, "part",
                                   path, sizeof(path)) != 0)
    {
        return -1;
    }
    return brix_oci_store_exists(path, &size) ? size : -1;
}


ngx_int_t
brix_oci_upload_headers(ngx_http_request_t *r, const brix_oci_req_t *req,
    const char *session, off_t end)
{
    char  loc[BRIX_OCI_KEY_MAX];
    char  range[64];

    if ((size_t) snprintf(loc, sizeof(loc), "/v2/%.*s/blobs/uploads/%s",
                          (int) req->name_len, req->name, session)
        >= sizeof(loc))
    {
        return NGX_ERROR;
    }
    (void) snprintf(range, sizeof(range), "0-%lld",
                    (end > 0) ? (long long) (end - 1) : 0LL);

    if (brix_http_set_header(r, "Location", loc, NULL) != NGX_OK
        || brix_http_set_header(r, "Range", range, NULL) != NGX_OK
        || brix_http_set_header(r, "Docker-Upload-UUID", session, NULL)
           != NGX_OK)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* Does this PATCH continue where the staged file ends? A request with no
 * Content-Range is "append here" by definition and always continues; one that
 * carries a range only continues when its first byte is our next byte.
 * Returns NGX_OK to append, NGX_DECLINED to answer 416.
 *
 * Real clients send layer PATCHes chunked with NO Content-Range at all
 * (App. Y-2), so this is the resume path, not the common path. */
static ngx_int_t
oci_check_range(ngx_http_request_t *r, off_t have)
{
    ngx_table_elt_t  *h = r->headers_in.content_range;
    const u_char     *p, *end;
    off_t             first = 0;

    if (h == NULL || h->value.len == 0) {
        return NGX_OK;
    }
    p   = h->value.data;
    end = p + h->value.len;

    /* Accept both the bare "start-end" the registry spec uses and the full
     * "bytes start-end/total" of RFC 7233 — clients send both. */
    if ((size_t) (end - p) > 6 && ngx_strncasecmp((u_char *) p,
                                                  (u_char *) "bytes ", 6) == 0)
    {
        p += 6;
    }
    while (p < end && *p == ' ') { p++; }

    if (p >= end || *p < '0' || *p > '9') {
        return NGX_DECLINED;
    }
    while (p < end && *p >= '0' && *p <= '9') {
        first = first * 10 + (*p++ - '0');
    }
    return (first == have) ? NGX_OK : NGX_DECLINED;
}


ngx_int_t
brix_oci_upload_created(ngx_http_request_t *r, const brix_oci_req_t *req,
    const brix_oci_digest_t *d)
{
    char  loc[BRIX_OCI_KEY_MAX];
    char  dg[BRIX_OCI_DIGEST_STRLEN];

    if (brix_oci_digest_format(d, dg, sizeof(dg)) < 0
        || (size_t) snprintf(loc, sizeof(loc), "/v2/%.*s/blobs/%s",
                             (int) req->name_len, req->name, dg) >= sizeof(loc))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (brix_http_set_header(r, "Location", loc, NULL) != NGX_OK
        || brix_http_set_header(r, "Docker-Content-Digest", dg, NULL) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return brix_oci_send_body(r, NGX_HTTP_CREATED, "application/json",
                              (const u_char *) "", 0);
}


ngx_int_t
brix_oci_reply_empty(ngx_http_request_t *r, ngx_uint_t status)
{
    if (brix_oci_api_version_header(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->headers_out.status           = status;
    r->headers_out.content_length_n = 0;
    r->header_only                  = 1;

    return ngx_http_send_header(r);
}


/* `?digest=` arrives percent-encoded from real clients (App. Y-1:
 * `sha256%3A…`), so decode before the grammar sees it — comparing the raw
 * form is how every push fails its seal. */
static ngx_int_t
oci_arg_digest(ngx_http_request_t *r, const char *name, size_t name_len,
    brix_oci_digest_t *out)
{
    ngx_str_t  v;
    size_t     n;

    if (brix_http_arg(r, name, name_len, &v) != NGX_OK) {
        return NGX_DECLINED;
    }
    n = brix_urldecode_inplace((char *) v.data);

    return (brix_oci_digest_parse((const char *) v.data, n, out) == 0)
           ? NGX_OK : NGX_ERROR;
}


/* Append the request body onto the part-file at `base`, under the session's
 * advisory lock. Returns the new length, or -1 with *status set. */
/* ---- POST /v2/<name>/blobs/uploads/ ------------------------------------- */

/* `?mount=<digest>&from=<repo>`: the blob is already in the global CAS, so
 * "uploading" it again would move gigabytes to reach a byte-identical file.
 * A mark and a 201 is the whole operation. */
static ngx_int_t
oci_upload_try_mount(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    const brix_oci_store_t *st)
{
    brix_oci_digest_t  d;
    char               blob[PATH_MAX];

    if (oci_arg_digest(r, "mount", 5, &d) != NGX_OK) {
        return NGX_DECLINED;
    }
    if (brix_oci_store_blob_path(st, &d, blob, sizeof(blob)) != 0
        || !brix_oci_store_exists(blob, NULL))
    {
        return NGX_DECLINED;               /* fall back to a real upload */
    }
    if (brix_oci_store_mark_layer(st, ctx->req.name, ctx->req.name_len, &d,
                                  r->connection->log) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return brix_oci_upload_created(r, &ctx->req, &d);
}


static ngx_int_t
oci_upload_create(ngx_http_request_t *r, const brix_oci_store_t *st,
    oci_upload_ctx_t *u)
{
    char  dir[PATH_MAX];
    char  part[PATH_MAX];

    oci_session_id(u->session, sizeof(u->session));
    u->session_len = ngx_strlen(u->session);
    u->st          = *st;
    u->base        = 0;

    if (brix_oci_store_upload_path(st, u->session, u->session_len, NULL,
                                   dir, sizeof(dir)) != 0
        || brix_oci_store_upload_path(st, u->session, u->session_len, "part",
                                      part, sizeof(part)) != 0)
    {
        return NGX_ERROR;
    }
    if (brix_oci_store_mkparent(part, r->connection->log) != NGX_OK) {
        return NGX_ERROR;
    }
    (void) chmod(dir, OCI_UPLOAD_SESSION_MODE);   /* vfs-seam-allow: registry staging area, private to the worker until seal */

    /* The empty part-file IS the session: creating it is what makes the
     * session exist, and its absence is what makes every later request on a
     * finished id answer 404 without a lookup table to consult. */
    return brix_oci_store_put_text(part, "", 0, r->connection->log);
}


ngx_int_t
brix_oci_upload_start(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx,
    brix_oci_store_t *st)
{
    oci_upload_ctx_t  *u;
    ngx_int_t          rc;

    if (r->method != NGX_HTTP_POST) {
        return brix_oci_error(r, NGX_HTTP_NOT_ALLOWED,
                              BRIX_OCI_ERR_UNSUPPORTED,
                              "start an upload with POST");
    }

    /* Reaping here rather than on a timer keeps the sweep proportional to the
     * traffic that creates sessions: an idle registry has nothing to reap and
     * pays nothing to discover that. */
    (void) brix_oci_upload_reap(st, lcf->upload_grace, r->connection->log);

    rc = oci_upload_try_mount(r, ctx, st);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    u = oci_upload_ctx(r, ctx);
    if (u == NULL || oci_upload_create(r, st, u) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = oci_arg_digest(r, "digest", 6, &u->want);
    if (rc == NGX_ERROR) {
        return brix_oci_error(r, NGX_HTTP_BAD_REQUEST,
                              BRIX_OCI_ERR_DIGEST_INVALID, NULL);
    }
    if (rc == NGX_OK) {
        /* The monolithic shortcut: body, hash and seal in one request. */
        u->act = OCI_UP_MONOLITHIC;
        return brix_http_read_body(r, brix_oci_upload_body_handler);
    }

    if (brix_oci_upload_headers(r, &ctx->req, u->session, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return brix_oci_reply_empty(r, NGX_HTTP_ACCEPTED);
}


/* ---- the /<session> methods --------------------------------------------- */

ngx_int_t
brix_oci_upload_session(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx,
    brix_oci_store_t *st)
{
    oci_upload_ctx_t  *u;
    char               dir[PATH_MAX];
    off_t              size;
    ngx_int_t          rc;

    size = oci_session_size(st, ctx->req.session, ctx->req.session_len);
    if (size < 0) {
        /* SEALED, ABORTED or REAPED — indistinguishable to a client, and
         * deliberately so: all three mean "this id is finished". */
        return brix_oci_error(r, NGX_HTTP_NOT_FOUND,
                              BRIX_OCI_ERR_BLOB_UPLOAD_UNKNOWN, NULL);
    }

    u = oci_upload_ctx(r, ctx);
    if (u == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    u->st          = *st;
    u->base        = size;
    u->session_len = ctx->req.session_len;
    ngx_memcpy(u->session, ctx->req.session, ctx->req.session_len);
    u->session[ctx->req.session_len] = '\0';

    if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) {
        if (brix_oci_upload_headers(r, &ctx->req, u->session, size) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return brix_oci_reply_empty(r, NGX_HTTP_NO_CONTENT);
    }

    if (r->method == NGX_HTTP_DELETE) {
        if (brix_oci_store_upload_path(st, u->session, u->session_len, NULL,
                                       dir, sizeof(dir)) != 0)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        brix_oci_store_drop_dir(dir, r->connection->log);
        return brix_oci_reply_empty(r, NGX_HTTP_NO_CONTENT);
    }

    if (r->method == NGX_HTTP_PUT) {
        rc = oci_arg_digest(r, "digest", 6, &u->want);
        if (rc != NGX_OK) {
            return brix_oci_error(r, NGX_HTTP_BAD_REQUEST,
                                  BRIX_OCI_ERR_DIGEST_INVALID,
                                  "a seal must name the digest it claims");
        }
        u->act = OCI_UP_SEAL;
        return brix_http_read_body(r, brix_oci_upload_body_handler);
    }

    if (r->method != NGX_HTTP_PATCH) {
        return brix_oci_error(r, NGX_HTTP_NOT_ALLOWED,
                              BRIX_OCI_ERR_UNSUPPORTED, NULL);
    }

    /* A Content-Range that does not continue where we are is the resume case,
     * and the spec's answer is to state the truth and let the client seek:
     * accepting it at the wrong offset would produce a blob that hashes to
     * nothing anybody asked for. */
    rc = oci_check_range(r, size);
    if (rc != NGX_OK) {
        if (brix_oci_upload_headers(r, &ctx->req, u->session, size) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return brix_oci_error(r, NGX_HTTP_RANGE_NOT_SATISFIABLE,
                              BRIX_OCI_ERR_BLOB_UPLOAD_INVALID,
                              "resume from the offset in the Range header");
    }

    u->act = OCI_UP_PATCH;
    return brix_http_read_body(r, brix_oci_upload_body_handler);
}


/* ---- the reaper ---------------------------------------------------------- */

ngx_uint_t
brix_oci_upload_reap(const brix_oci_store_t *st, time_t grace, ngx_log_t *log)
{
    char            root[PATH_MAX];
    char            part[PATH_MAX];
    char            dir[PATH_MAX];
    struct dirent  *ent;
    struct stat     sb;
    time_t          now = ngx_time();
    ngx_uint_t      reaped = 0;
    DIR            *dh;

    if (grace <= 0
        || (size_t) snprintf(root, sizeof(root), "%s/_uploads",
                             st->root) >= sizeof(root))
    {
        return 0;
    }
    dh = opendir(root);                    /* vfs-seam-allow: registry staging area sweep, not a VFS export listing */
    if (dh == NULL) {
        return 0;
    }

    while ((ent = readdir(dh)) != NULL) {  /* vfs-seam-allow: registry staging area sweep, not a VFS export listing */
        if (ent->d_name[0] == '.') {
            continue;
        }
        if ((size_t) snprintf(part, sizeof(part), "%s/%s/part",
                              root, ent->d_name) >= sizeof(part))
        {
            continue;
        }
        /* The part-file's mtime is the last time the client sent anything —
         * which is exactly the idleness the grace window is about. */
        if (stat(part, &sb) != 0                 /* vfs-seam-allow: staging idleness probe */
            || now - sb.st_mtime <= grace)
        {
            continue;
        }
        if ((size_t) snprintf(dir, sizeof(dir), "%s/%s",
                              root, ent->d_name) < sizeof(dir))
        {
            brix_oci_store_drop_dir(dir, log);
            reaped++;
        }
    }
    (void) closedir(dh);

    return reaped;
}
