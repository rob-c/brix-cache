/*
 * oci_registry.c — the local registry surface's router (§D4.1).
 *
 * WHAT: the entry point for a `brix_oci_registry on` location: gate →
 *       authorize → dispatch to the read path (serve from the local store) or
 *       to one of the write engines (upload sessions, manifest PUT, DELETE).
 * WHY:  the mirror and the registry share a URL grammar and an error
 *       envelope, but nothing else: one caches somebody else's objects and
 *       may refetch anything it drops, the other IS the source of truth and
 *       may drop nothing. Keeping the two routers apart is what stops that
 *       distinction from being one `if (lcf->mirror)` away from being lost —
 *       most visibly on the read path, where a registry that "filled" a miss
 *       from an upstream would silently launder unpushed content into a
 *       repository somebody trusts.
 * HOW:  reads go through the same serving pipeline as every other protocol in
 *       the tree (brix_vfs_open → brix_http_serve_file_ranged), so ranges,
 *       conditionals and the TLS/sendfile split (INVARIANT #2) are handled
 *       once, correctly, elsewhere. This file opens nothing itself.
 */

#include "oci_referrers.h"

#include "core/http/http_headers.h"
#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_backend_registry.h"
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"
#include "protocols/shared/file_serve.h"

#include <stdio.h>
#include <string.h>

/* A tag list of this size covers any repository a human maintains; past it
 * the answer is truncated rather than grown, because an unbounded listing on
 * the read path is a memory amplifier a single request could pull. */
#define OCI_TAGS_MAX  (64 * 1024)


/* Resolve what the request names to a path in the store. Manifests reached by
 * tag are resolved through the tag pointer first — that indirection is the
 * whole reason tags are mutable and digests are not. */
static ngx_int_t
oci_registry_resolve(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    brix_oci_store_t *st, char *path, size_t path_size)
{
    brix_oci_digest_t  d;
    char               tagfile[PATH_MAX];
    char               line[BRIX_OCI_DIGEST_STRLEN];
    ssize_t            n;

    if (ctx->req.cls == BRIX_OCI_REQ_BLOB) {
        if (brix_oci_store_blob_path(st, &ctx->req.digest, path, path_size)
            != 0)
        {
            return NGX_ERROR;
        }
        /* The CAS is global, but a repository only serves what it has been
         * told it holds: without the reference mark, one tenant could read
         * another tenant's private layer by guessing nothing more than its
         * digest — which a leaked manifest hands over for free. */
        if (brix_oci_store_layer_path(st, ctx->req.name, ctx->req.name_len,
                                      &ctx->req.digest, tagfile,
                                      sizeof(tagfile)) != 0
            || !brix_oci_store_exists(tagfile, NULL))
        {
            return NGX_DECLINED;
        }
        return NGX_OK;
    }

    if (ctx->req.ref_is_digest) {
        return brix_oci_store_manifest_path(st, ctx->req.name,
                   ctx->req.name_len, &ctx->req.digest, NULL,
                   path, path_size) == 0 ? NGX_OK : NGX_ERROR;
    }

    if (brix_oci_store_tag_path(st, &ctx->req, tagfile, sizeof(tagfile)) != 0) {
        return NGX_ERROR;
    }
    n = brix_oci_store_get_text(tagfile, line, sizeof(line));
    if (n <= 0) {
        return NGX_DECLINED;
    }
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
        line[--n] = '\0';
    }
    if (brix_oci_digest_parse(line, (size_t) n, &d) != 0) {
        return NGX_ERROR;                  /* a corrupt tag file is our bug */
    }
    return brix_oci_store_manifest_path(st, ctx->req.name, ctx->req.name_len,
               &d, NULL, path, path_size) == 0 ? NGX_OK : NGX_ERROR;
}


/* Serve one stored object. No fill, no upstream, no coalescing: on this
 * surface a miss is a miss, and inventing bytes for it is precisely the
 * failure mode the surface exists to prevent. */
static ngx_int_t
oci_registry_serve(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx, brix_oci_store_t *st)
{
    brix_http_serve_opts_t    opts;
    brix_http_serve_result_t  result;
    brix_oci_present_t       *pres;
    brix_vfs_ctx_t            vctx;
    brix_vfs_file_t          *fh;
    brix_vfs_stat_t           vst;
    char                      path[PATH_MAX];
    int                       is_tls = 0;
    int                       vfs_err = 0;
    ngx_int_t                 rc;

    rc = oci_registry_resolve(r, ctx, st, path, sizeof(path));
    if (rc == NGX_ERROR) {
        return brix_oci_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                              BRIX_OCI_ERR_UNAVAILABLE, NULL);
    }
    if (rc == NGX_DECLINED) {
        ctx->disp = BRIX_OCI_OUT_ERROR;
        return brix_oci_error(r, NGX_HTTP_NOT_FOUND,
                              (ctx->req.cls == BRIX_OCI_REQ_BLOB)
                              ? BRIX_OCI_ERR_BLOB_UNKNOWN
                              : BRIX_OCI_ERR_MANIFEST_UNKNOWN, NULL);
    }

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_OCI,
                      st->root, "", /* allow_write */ 0, is_tls, NULL, path);
    vctx.sd = brix_vfs_backend_resolve(st->root, r->connection->log);

    fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        ctx->disp = BRIX_OCI_OUT_ERROR;
        return brix_oci_error(r, brix_oci_errno_status(r, vfs_err),
                              (ctx->req.cls == BRIX_OCI_REQ_BLOB)
                              ? BRIX_OCI_ERR_BLOB_UNKNOWN
                              : BRIX_OCI_ERR_MANIFEST_UNKNOWN, NULL);
    }
    if (brix_vfs_file_stat(fh, &vst) != NGX_OK || vst.is_directory) {
        brix_vfs_close(fh, r->connection->log);
        return brix_oci_error(r, NGX_HTTP_NOT_FOUND,
                              BRIX_OCI_ERR_MANIFEST_UNKNOWN, NULL);
    }

    pres = ngx_pcalloc(r->pool, sizeof(*pres));
    if (pres == NULL
        || brix_oci_present_prepare(r, lcf, ctx, fh, &vst, path, pres)
           != NGX_OK)
    {
        brix_vfs_close(fh, r->connection->log);
        return brix_oci_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                              BRIX_OCI_ERR_UNAVAILABLE, NULL);
    }

    ctx->disp       = BRIX_OCI_OUT_LOCAL;
    r->allow_ranges = 1;

    brix_oci_present_serve_opts(&opts, pres);
    return brix_http_serve_file_ranged(r, fh, &vst, path, &opts, &result);
}


ngx_int_t
brix_oci_registry_tags(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    brix_oci_store_t *st)
{
    u_char  *body;
    char    *tags;
    size_t   used;
    char    *p;
    int      count;

    tags = ngx_palloc(r->pool, OCI_TAGS_MAX);
    body = ngx_palloc(r->pool, OCI_TAGS_MAX + BRIX_OCI_KEY_MAX);
    if (tags == NULL || body == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    count = brix_oci_store_tag_list(st, ctx->req.name, ctx->req.name_len,
                                    tags, OCI_TAGS_MAX);
    if (count < 0) {
        return brix_oci_error(r, NGX_HTTP_NOT_FOUND,
                              BRIX_OCI_ERR_NAME_UNKNOWN, NULL);
    }

    used = (size_t) snprintf((char *) body, OCI_TAGS_MAX + BRIX_OCI_KEY_MAX,
                             "{\"name\":\"%.*s\",\"tags\":[",
                             (int) ctx->req.name_len, ctx->req.name);

    /* The store hands back newline-separated names; the wire wants a JSON
     * array. Every name here has already passed the tag grammar, so it needs
     * no escaping — the grammar excludes quote and backslash by construction
     * (§0.7.2), which is why this can be a straight copy. */
    for (p = tags; *p != '\0'; ) {
        char *nl = strchr(p, '\n');
        size_t len = (nl != NULL) ? (size_t) (nl - p) : ngx_strlen(p);

        if (used + len + 4 >= OCI_TAGS_MAX + BRIX_OCI_KEY_MAX) {
            break;
        }
        if (p != tags) {
            body[used++] = ',';
        }
        body[used++] = '"';
        ngx_memcpy(body + used, p, len);
        used += len;
        body[used++] = '"';

        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }
    body[used++] = ']';
    body[used++] = '}';

    ctx->disp = BRIX_OCI_OUT_LOCAL;
    return brix_oci_send_body(r, NGX_HTTP_OK, "application/json", body, used);
}


/* Route → engine. The read/write split is explicit rather than derived from
 * the method alone, because "GET on an upload session" and "GET on a blob"
 * are different surfaces that happen to share a verb. */
static ngx_int_t
oci_registry_dispatch(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx,
    brix_oci_store_t *st)
{
    int  is_read = (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) != 0;

    switch (ctx->req.cls) {

    case BRIX_OCI_REQ_UPLOAD_START:
        return brix_oci_upload_start(r, lcf, ctx, st);

    case BRIX_OCI_REQ_UPLOAD_SESSION:
        return brix_oci_upload_session(r, lcf, ctx, st);

    case BRIX_OCI_REQ_TAGS_LIST:
        if (!is_read) {
            break;
        }
        return brix_oci_registry_tags(r, ctx, st);

    case BRIX_OCI_REQ_REFERRERS:
        if (!is_read) {
            break;
        }
        return brix_oci_referrers_get(r, ctx, st);

    case BRIX_OCI_REQ_MANIFEST:
        if (is_read) {
            return oci_registry_serve(r, lcf, ctx, st);
        }
        if (r->method == NGX_HTTP_PUT) {
            return brix_oci_manifest_put(r, lcf, ctx, st);
        }
        if (r->method == NGX_HTTP_DELETE) {
            return brix_oci_registry_delete(r, ctx, st);
        }
        break;

    case BRIX_OCI_REQ_BLOB:
        if (is_read) {
            return oci_registry_serve(r, lcf, ctx, st);
        }
        if (r->method == NGX_HTTP_DELETE) {
            return brix_oci_registry_delete(r, ctx, st);
        }
        break;

    default:
        break;
    }

    ctx->disp = BRIX_OCI_OUT_REFUSED;
    return brix_oci_error(r, NGX_HTTP_NOT_ALLOWED, BRIX_OCI_ERR_UNSUPPORTED,
                          "that method is not defined for this endpoint");
}


ngx_int_t
brix_oci_registry_handle(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx)
{
    brix_oci_store_t  st;
    char              principal[256];
    char             *uri;
    ngx_int_t         rc;

    /* The classified request holds SPANS into this buffer, and a body-reading
     * method (PATCH, PUT) is re-entered by nginx long after this frame has
     * returned — so the URI copy lives in the request pool, never on the
     * stack. A stack buffer here reads back as garbage in the Location the
     * second PATCH of a chunked layer emits. */
    uri = ngx_pnalloc(r->pool, BRIX_OCI_KEY_MAX);
    if (uri == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (brix_oci_store_init(&st, lcf) != NGX_OK) {
        return brix_oci_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                              BRIX_OCI_ERR_UNAVAILABLE,
                              "this location has no usable registry root");
    }

    rc = brix_oci_registry_gate(r, ctx, uri, BRIX_OCI_KEY_MAX);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* Authorization runs AFTER classification and BEFORE any store access, so
     * the scope check has a validated repository name to test against and no
     * unauthorized request has yet learned whether an object exists. */
    rc = brix_oci_registry_authz(r, lcf, ctx, principal, sizeof(principal));
    if (rc == NGX_DONE) {
        return NGX_OK;                  /* refused; the envelope is written */
    }
    if (rc != NGX_OK) {
        return rc;
    }

    return oci_registry_dispatch(r, lcf, ctx, &st);
}
