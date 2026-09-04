/*
 * oci_upload_seal.c — where the pushed bytes actually land (§D4.2, App. J.7).
 *
 * WHAT: the body half of the upload machine: append the request body to the
 *       staged part-file, and — on a seal — hash it, compare it against the
 *       digest the client claimed, and publish it into the content store.
 * WHY:  a registry that stores what it was TOLD it received rather than what
 *       it verifiably did receive is a corruption pump: every later pull of
 *       that layer hands a client bytes that hash to something else, and the
 *       client is the one that looks broken. The seal is therefore the single
 *       point where bytes become an object, and it is the only place in this
 *       module allowed to say so.
 * HOW:  the routing half (oci_upload.c) leaves a decision in ctx->reg; nginx
 *       re-enters here once the body is on hand. Appends go in at the
 *       part-file's current length under an advisory lock, so two writers on
 *       one session id collide loudly rather than interleaving.
 *
 * The raw namespace calls carry per-line vfs-seam-allow markers for the
 * reason oci_store.c documents at its head: this is the registry's own
 * staging area, not a VFS export.
 */

#include "oci_upload_internal.h"

#include "core/http/http_body.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

/* Append the request body onto the part-file at `u->base`, under the
 * session's advisory lock. Returns the new length, or -1 with *status set. */
static off_t
oci_append_body(ngx_http_request_t *r, const oci_upload_ctx_t *u,
    size_t max_blob, ngx_uint_t *status)
{
    brix_http_body_summary_t  sum;
    char                      path[PATH_MAX];
    off_t                     end;
    int                       fd;

    *status = NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (brix_oci_store_upload_path(&u->st, u->session, u->session_len, "part",
                                   path, sizeof(path)) != 0)
    {
        return -1;
    }
    fd = open(path, O_WRONLY | O_CLOEXEC);   /* vfs-seam-allow: DOMAIN_REGISTRY — registry staging area; the received bytes are not an object until the seal */
    if (fd < 0) {
        *status = NGX_HTTP_NOT_FOUND;
        return -1;
    }

    /* One writer per session. A second concurrent PATCH is a client bug (the
     * id is issued to exactly one client), and interleaving its bytes would
     * corrupt the layer silently — so it is refused, loudly. */
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        (void) close(fd);
        *status = NGX_HTTP_CONFLICT;
        return -1;
    }

    if (brix_http_body_write_to_fd_at(r, fd, path, &sum, u->base) != NGX_OK) {
        (void) close(fd);
        return -1;
    }
    (void) close(fd);

    end = u->base + (off_t) sum.bytes;

    /* The cap is enforced against the RUNNING COUNT, never a header: real
     * layer PATCHes arrive chunked with no Content-Length at all (App. Y-2),
     * so a header-based cap would be no cap. */
    if (max_blob > 0 && (size_t) end > max_blob) {
        *status = NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        return -1;
    }
    return end;
}


/* Move the sealed part-file into the CAS and record the repo's reference. */
static ngx_int_t
oci_seal_commit(ngx_http_request_t *r, const oci_upload_ctx_t *u,
    const brix_oci_req_t *req, const brix_oci_digest_t *d)
{
    char       part[PATH_MAX];
    char       blob[PATH_MAX];
    char       dir[PATH_MAX];
    ngx_log_t *log = r->connection->log;

    if (brix_oci_store_upload_path(&u->st, u->session, u->session_len, "part",
                                   part, sizeof(part)) != 0
        || brix_oci_store_upload_path(&u->st, u->session, u->session_len, NULL,
                                      dir, sizeof(dir)) != 0
        || brix_oci_store_blob_path(&u->st, d, blob, sizeof(blob)) != 0)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Content addressing makes a re-upload a no-op rather than a conflict: the
     * bytes already in the store hash to the same digest by definition, so the
     * winner of a race is irrelevant. The exclusive publish makes that atomic —
     * EEXIST is the "already have these bytes" answer, not a failure — and
     * closes the exists()-then-publish window the previous two-step left open. */
    if (brix_oci_store_publish_staged(&u->st, part, blob, log) != NGX_OK
        && errno != EEXIST)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (brix_oci_store_mark_layer(&u->st, req->name, req->name_len, d,
                                  log) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    brix_oci_store_drop_dir(dir, log);

    return brix_oci_upload_created(r, req, d);
}


/* ---- the re-entered body handler ---------------------------------------- */

static ngx_int_t
oci_body_monolithic(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    oci_upload_ctx_t *u, size_t max_blob)
{
    ngx_uint_t  status;
    ngx_int_t   rc;
    char        part[PATH_MAX];

    if (oci_append_body(r, u, max_blob, &status) < 0) {
        return brix_oci_error(r, status,
                              (status == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE)
                              ? BRIX_OCI_ERR_SIZE_INVALID
                              : BRIX_OCI_ERR_BLOB_UPLOAD_INVALID, NULL);
    }
    if (brix_oci_store_upload_path(&u->st, u->session, u->session_len, "part",
                                   part, sizeof(part)) != 0)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = brix_oci_store_verify(part, &u->want, r->connection->log);
    if (rc != NGX_OK) {
        char dir[PATH_MAX];

        if (brix_oci_store_upload_path(&u->st, u->session, u->session_len,
                                       NULL, dir, sizeof(dir)) == 0)
        {
            brix_oci_store_drop_dir(dir, r->connection->log);
        }
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        return brix_oci_error(r, NGX_HTTP_BAD_REQUEST,
                              BRIX_OCI_ERR_DIGEST_INVALID,
                              "the uploaded bytes do not hash to the "
                              "digest the request named");
    }
    return oci_seal_commit(r, u, &ctx->req, &u->want);
}


static ngx_int_t
oci_body_seal(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    oci_upload_ctx_t *u, size_t max_blob)
{
    char       part[PATH_MAX];
    ngx_int_t  rc;

    /* A PUT may carry a final chunk. Appending it before the hash is what
     * makes the two-request push (POST, then PUT-with-everything) work. */
    if (r->request_body != NULL && r->request_body->bufs != NULL) {
        ngx_uint_t  status;

        if (oci_append_body(r, u, max_blob, &status) < 0) {
            return brix_oci_error(r, status,
                                  (status == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE)
                                  ? BRIX_OCI_ERR_SIZE_INVALID
                                  : BRIX_OCI_ERR_BLOB_UPLOAD_INVALID, NULL);
        }
    }
    if (brix_oci_store_upload_path(&u->st, u->session, u->session_len, "part",
                                   part, sizeof(part)) != 0)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = brix_oci_store_verify(part, &u->want, r->connection->log);
    if (rc == NGX_ERROR) {
        return brix_oci_error(r, NGX_HTTP_NOT_FOUND,
                              BRIX_OCI_ERR_BLOB_UPLOAD_UNKNOWN, NULL);
    }
    if (rc == NGX_DECLINED) {
        /* J.7: the session STAYS ACTIVE. The client may have mis-stated the
         * digest, or lost a chunk it can still re-send; destroying its work
         * would turn a recoverable mistake into a full re-upload. */
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        return brix_oci_error(r, NGX_HTTP_BAD_REQUEST,
                              BRIX_OCI_ERR_DIGEST_INVALID,
                              "the staged bytes do not hash to the digest "
                              "the seal named");
    }
    return oci_seal_commit(r, u, &ctx->req, &u->want);
}


void
brix_oci_upload_body_handler(ngx_http_request_t *r)
{
    ngx_http_brix_oci_loc_conf_t *lcf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_oci_module);
    ngx_http_brix_oci_ctx_t      *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_oci_module);
    oci_upload_ctx_t             *u   = (ctx != NULL) ? ctx->reg : NULL;
    ngx_uint_t                    status;
    off_t                         end;
    ngx_int_t                     rc;

    if (u == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    switch (u->act) {

    case OCI_UP_MONOLITHIC:
        rc = oci_body_monolithic(r, ctx, u, lcf->max_blob);
        break;

    case OCI_UP_SEAL:
        rc = oci_body_seal(r, ctx, u, lcf->max_blob);
        break;

    default:
        end = oci_append_body(r, u, lcf->max_blob, &status);
        if (end < 0) {
            rc = brix_oci_error(r, status,
                                (status == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE)
                                ? BRIX_OCI_ERR_SIZE_INVALID
                                : BRIX_OCI_ERR_BLOB_UPLOAD_UNKNOWN, NULL);
            break;
        }
        rc = (brix_oci_upload_headers(r, &ctx->req, u->session, end) == NGX_OK)
             ? brix_oci_reply_empty(r, NGX_HTTP_ACCEPTED)
             : NGX_HTTP_INTERNAL_SERVER_ERROR;
        break;
    }

    ngx_http_finalize_request(r, rc);
}


