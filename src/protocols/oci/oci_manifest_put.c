/*
 * oci_manifest_put.c — manifest PUT and the DELETE surface (§D4.3, §D4.4).
 *
 * WHAT: PUT /v2/<name>/manifests/<ref> — validate the document, prove every
 *       blob it names is already in the store, then commit it and (for a tag)
 *       swap the tag pointer atomically. Plus DELETE of a manifest by digest.
 * WHY:  the manifest is the only object in a registry that REFERS to others,
 *       which makes it the only place a push can leave the store incoherent:
 *       accept a manifest whose layers were never uploaded and every later
 *       pull of that tag 404s halfway through, after the client has already
 *       committed to the image. The spec's answer — MANIFEST_BLOB_UNKNOWN at
 *       PUT time — is therefore not a nicety, it is the invariant that makes
 *       "the tag resolves" mean "the image is complete".
 * HOW:  jansson parses the document (never json_min: this is attacker-supplied
 *       nesting on the write path, and the bounded scanner cannot answer
 *       structural questions about it), the body is size-capped BEFORE it is
 *       read, and the commit order is blob-check → CAS write → sidecar → tag
 *       swap, so a failure at any step leaves the previous tag intact.
 */

#include "oci_referrers.h"

#include "core/http/http_body.h"
#include "core/http/http_headers.h"

#include <jansson.h>

#include <stdio.h>
#include <string.h>

/* The media types v1 accepts on the write path. An index is accepted so a
 * multi-arch push works; its children are manifests, which the referenced-blob
 * walk below treats exactly like any other referenced object. */
static const char *oci_manifest_types[] = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    NULL
};

typedef struct {
    brix_oci_store_t  st;
    char              ctype[128];
} oci_manifest_ctx_t;


static int
oci_type_known(const char *ctype)
{
    size_t  i;

    for (i = 0; oci_manifest_types[i] != NULL; i++) {
        if (ngx_strcmp(ctype, oci_manifest_types[i]) == 0) {
            return 1;
        }
    }
    return 0;
}


/* Is `d` present in the store, either as a blob or as a manifest? An index
 * names manifests, a manifest names blobs, and both live in the same CAS —
 * so one existence question covers both, and neither has to know which kind
 * of child it is holding. */
static int
oci_ref_present(const brix_oci_store_t *st, const char *name, size_t name_len,
    const brix_oci_digest_t *d)
{
    char  path[PATH_MAX];

    if (brix_oci_store_blob_path(st, d, path, sizeof(path)) == 0
        && brix_oci_store_exists(path, NULL))
    {
        return 1;
    }
    return brix_oci_store_manifest_path(st, name, name_len, d, NULL,
                                        path, sizeof(path)) == 0
           && brix_oci_store_exists(path, NULL);
}


/* Walk one descriptor array ("layers", "manifests", or the lone "config"
 * object) and stop at the first digest the store cannot produce. Returns 0,
 * or -1 with the offending digest string copied into `missing`. */
static int
oci_walk_refs(const brix_oci_store_t *st, const brix_oci_req_t *req,
    json_t *node, char *missing, size_t missing_len)
{
    brix_oci_digest_t  d;
    const char        *dg;
    json_t            *elem;
    size_t             i;

    if (json_is_object(node)) {
        dg = json_string_value(json_object_get(node, "digest"));
        if (dg == NULL
            || brix_oci_digest_parse(dg, ngx_strlen(dg), &d) != 0)
        {
            (void) snprintf(missing, missing_len, "%s",
                            (dg != NULL) ? dg : "(no digest)");
            return -1;
        }
        if (!oci_ref_present(st, req->name, req->name_len, &d)) {
            (void) snprintf(missing, missing_len, "%s", dg);
            return -1;
        }
        return 0;
    }

    if (!json_is_array(node)) {
        return 0;                          /* absent member: nothing to prove */
    }

    json_array_foreach(node, i, elem) {
        if (oci_walk_refs(st, req, elem, missing, missing_len) != 0) {
            return -1;
        }
        if (i + 1 >= BRIX_OCI_MAX_REFS) {
            (void) snprintf(missing, missing_len, "(too many references)");
            return -1;
        }
    }
    return 0;
}


/* Every object the document names is already here. NGX_OK = commit it;
 * NGX_DONE = refused, envelope written (never NGX_OK — a refusal that reads
 * as success is a manifest committed over its own 400).
 *
 * The `subject` descriptor is SHAPE-checked but deliberately not walked: a
 * referrer may be pushed before, or entirely without, the thing it describes
 * — that is what lets a signature exist for an image this registry never
 * held — but a subject we cannot read at all is a refusal, because storing it
 * would publish an artifact whose edge nothing can follow. */
static ngx_int_t
oci_manifest_validate(ngx_http_request_t *r, const oci_manifest_ctx_t *m,
    const brix_oci_req_t *req, json_t *doc)
{
    char         missing[BRIX_OCI_DIGEST_STRLEN + 32];
    const char  *why = NULL;
    int          bad;

    if (brix_oci_referrers_subject_ok(doc, &why) != 0) {
        return brix_oci_refuse(r, NGX_HTTP_BAD_REQUEST,
                               BRIX_OCI_ERR_MANIFEST_INVALID, why);
    }

    missing[0] = '\0';
    bad = oci_walk_refs(&m->st, req, json_object_get(doc, "config"),
                        missing, sizeof(missing))
          || oci_walk_refs(&m->st, req, json_object_get(doc, "layers"),
                           missing, sizeof(missing))
          || oci_walk_refs(&m->st, req, json_object_get(doc, "manifests"),
                           missing, sizeof(missing));

    if (bad) {
        return brix_oci_refuse(r, NGX_HTTP_BAD_REQUEST,
                               BRIX_OCI_ERR_MANIFEST_BLOB_UNKNOWN, missing);
    }
    return NGX_OK;
}


/* Write the manifest into the CAS, describe it in the sidecar, and — when the
 * push named a tag rather than a digest — point that tag at it. The tag swap
 * is last and atomic: until it lands, a reader sees the previous image, and
 * after it lands, a reader sees a complete one. There is no moment in between
 * where the tag names something half-written. */
static ngx_int_t
oci_manifest_commit(ngx_http_request_t *r, const oci_manifest_ctx_t *m,
    const brix_oci_req_t *req, json_t *doc, const u_char *body, size_t len,
    const brix_oci_digest_t *d)
{
    brix_oci_meta_t  meta;
    char             path[PATH_MAX];
    char             dg[BRIX_OCI_DIGEST_STRLEN];
    char             subj[BRIX_OCI_DIGEST_STRLEN];
    char             loc[BRIX_OCI_KEY_MAX];
    ngx_log_t       *log = r->connection->log;

    if (brix_oci_digest_format(d, dg, sizeof(dg)) < 0
        || brix_oci_store_manifest_path(&m->st, req->name, req->name_len,
                                        d, NULL, path, sizeof(path)) != 0)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (brix_oci_store_publish_bytes(&m->st, path, body, len,
                                     BRIX_VFS_DOMAIN_REGISTRY, log) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&meta, sizeof(meta));
    (void) snprintf(meta.content_type, sizeof(meta.content_type), "%s",
                    m->ctype);
    (void) snprintf(meta.digest, sizeof(meta.digest), "%s", dg);
    meta.fetched_at = ngx_time();
    meta.verified   = 1;

    /* mtime 0: the manifest is CAS-addressed, so its path already pins its
     * bytes and the size is all the coherence a memo beside it can need. */
    if (brix_oci_meta_store(path, (off_t) len, 0, &meta, log) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* The referrers edge is recorded BEFORE the tag swap, for the same reason
     * the blob walk runs before either: once a name resolves to this
     * manifest, everything the spec says about it must already be true. */
    if (brix_oci_referrers_index(&m->st, req, doc, d, m->ctype, (off_t) len,
                                 subj, sizeof(subj), log) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!req->ref_is_digest
        && brix_oci_store_tag_set(&m->st, req, dg, log) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* OCI-Subject is how the client learns the registry UNDERSTOOD the
     * subject field. Its absence tells a signing tool to fall back to the
     * tag-schema workaround, so emitting it is not cosmetic — it is the
     * handshake that turns the referrers API on for that client. */
    if (subj[0] != '\0'
        && brix_http_set_header(r, "OCI-Subject", subj, NULL) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if ((size_t) snprintf(loc, sizeof(loc), "/v2/%.*s/manifests/%s",
                          (int) req->name_len, req->name, dg) >= sizeof(loc)
        || brix_http_set_header(r, "Location", loc, NULL) != NGX_OK
        || brix_http_set_header(r, "Docker-Content-Digest", dg, NULL) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return brix_oci_send_body(r, NGX_HTTP_CREATED, "application/json",
                              (const u_char *) "", 0);
}


/* Parse once, then validate and commit against the same document. The parse
 * lives here rather than inside each stage because the referrers index needs
 * the `subject` descriptor at commit time, and re-parsing a 4 MiB body to
 * read one field would be a second chance for the two readings to disagree
 * about what was pushed. */
static ngx_int_t
oci_manifest_stages(ngx_http_request_t *r, oci_manifest_ctx_t *m,
    ngx_http_brix_oci_ctx_t *ctx, u_char *body, size_t len,
    const brix_oci_digest_t *d)
{
    json_error_t  jerr;
    json_t       *doc;
    ngx_int_t     rc;

    doc = json_loadb((const char *) body, len, 0, &jerr);
    if (doc == NULL) {
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        return brix_oci_error(r, NGX_HTTP_BAD_REQUEST,
                              BRIX_OCI_ERR_MANIFEST_INVALID, jerr.text);
    }
    if (!json_is_object(doc)) {
        json_decref(doc);
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        return brix_oci_error(r, NGX_HTTP_BAD_REQUEST,
                              BRIX_OCI_ERR_MANIFEST_INVALID,
                              "a manifest is a JSON object");
    }

    rc = oci_manifest_validate(r, m, &ctx->req, doc);
    if (rc != NGX_OK) {
        json_decref(doc);
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        return (rc == NGX_DONE) ? NGX_OK : rc;
    }

    rc = oci_manifest_commit(r, m, &ctx->req, doc, body, len, d);
    json_decref(doc);

    return rc;
}


static void
oci_manifest_body_handler(ngx_http_request_t *r)
{
    ngx_http_brix_oci_ctx_t  *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_oci_module);
    oci_manifest_ctx_t       *m   = (ctx != NULL) ? ctx->reg : NULL;
    brix_oci_digest_t         d;
    u_char                   *body;
    size_t                    len;

    if (m == NULL
        || brix_http_body_read_all(r, BRIX_OCI_MANIFEST_MAX, &body, &len)
           != NGX_OK)
    {
        ngx_http_finalize_request(r, brix_oci_error(r,
            NGX_HTTP_REQUEST_ENTITY_TOO_LARGE, BRIX_OCI_ERR_SIZE_INVALID,
            "the manifest exceeds brix's 4 MiB document cap"));
        return;
    }

    /* A push BY DIGEST is checked under the algorithm the client named —
     * anything else compares two different functions' output and rejects an
     * honest sha512 push. A push by tag has nothing to be checked against,
     * so it is filed under the algorithm we produce, and the tag therefore
     * always resolves to a sha256-addressed manifest. */
    if (brix_oci_digest_hash(ctx->req.ref_is_digest
                                 ? ctx->req.digest.alg
                                 : BRIX_OCI_ALG_SHA256,
                             body, len, &d) != 0)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Pushed by digest? Then the bytes must be the bytes that digest names.
     * Skipping this is how a registry ends up serving one document under
     * another document's immutable, infinitely-cacheable name. */
    if (ctx->req.ref_is_digest
        && !brix_oci_digest_eq(&d, &ctx->req.digest))
    {
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        ngx_http_finalize_request(r, brix_oci_error(r, NGX_HTTP_BAD_REQUEST,
            BRIX_OCI_ERR_DIGEST_INVALID,
            "the manifest does not hash to the digest it was pushed under"));
        return;
    }

    ngx_http_finalize_request(r,
        oci_manifest_stages(r, m, ctx, body, len, &d));
}


ngx_int_t
brix_oci_manifest_put(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx,
    brix_oci_store_t *st)
{
    oci_manifest_ctx_t  *m;

    (void) lcf;

    /* The cap is checked against the declared length here and enforced again
     * against the delivered bytes in the callback: a client may lie in the
     * header, but it cannot lie about how much it sent. */
    if (r->headers_in.content_length_n > (off_t) BRIX_OCI_MANIFEST_MAX) {
        return brix_oci_error(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE,
                              BRIX_OCI_ERR_SIZE_INVALID,
                              "the manifest exceeds brix's 4 MiB document cap");
    }

    m = ngx_pcalloc(r->pool, sizeof(*m));
    if (m == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    m->st = *st;

    if (r->headers_in.content_type != NULL) {
        (void) snprintf(m->ctype, sizeof(m->ctype), "%.*s",
                        (int) r->headers_in.content_type->value.len,
                        r->headers_in.content_type->value.data);
    }
    if (!oci_type_known(m->ctype)) {
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        return brix_oci_error(r, NGX_HTTP_BAD_REQUEST,
                              BRIX_OCI_ERR_MANIFEST_INVALID,
                              "unsupported manifest media type");
    }

    ctx->reg = m;
    return brix_http_read_body(r, oci_manifest_body_handler);
}


/* ---- DELETE (§D4.4) ------------------------------------------------------ */

ngx_int_t
brix_oci_registry_delete(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    brix_oci_store_t *st)
{
    char        path[PATH_MAX];
    char        meta[PATH_MAX];
    ngx_log_t  *log = r->connection->log;

    /* Deletion is by digest only. A tag is a NAME, and deleting the object a
     * name happens to point at is how two clients racing a re-tag destroy an
     * image neither of them meant to touch — so a tag DELETE removes the
     * pointer and nothing else. */
    if (ctx->req.cls == BRIX_OCI_REQ_MANIFEST && !ctx->req.ref_is_digest) {
        if (brix_oci_store_tag_path(st, &ctx->req, path, sizeof(path)) != 0) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (!brix_oci_store_exists(path, NULL)) {
            return brix_oci_error(r, NGX_HTTP_NOT_FOUND,
                                  BRIX_OCI_ERR_MANIFEST_UNKNOWN, NULL);
        }
        if (brix_oci_store_remove(path, log) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return brix_oci_reply_empty(r, NGX_HTTP_ACCEPTED);
    }

    if (ctx->req.cls == BRIX_OCI_REQ_MANIFEST) {
        if (brix_oci_store_manifest_path(st, ctx->req.name, ctx->req.name_len,
                                         &ctx->req.digest, NULL,
                                         path, sizeof(path)) != 0
            || brix_oci_store_manifest_path(st, ctx->req.name,
                                            ctx->req.name_len,
                                            &ctx->req.digest, ".meta",
                                            meta, sizeof(meta)) != 0)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (!brix_oci_store_exists(path, NULL)) {
            return brix_oci_error(r, NGX_HTTP_NOT_FOUND,
                                  BRIX_OCI_ERR_MANIFEST_UNKNOWN, NULL);
        }
        brix_oci_referrers_forget(st, ctx->req.name, ctx->req.name_len,
                                  &ctx->req.digest, log);
        (void) brix_oci_store_remove(meta, log);
        if (brix_oci_store_remove(path, log) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return brix_oci_reply_empty(r, NGX_HTTP_ACCEPTED);
    }

    /* A blob DELETE drops this repository's reference mark. The CAS object
     * itself stays: another repository may hold the same layer, and content
     * addressing means it is byte-identical, not merely similar. Reclaiming
     * unreferenced blobs is a GC pass (`brixoci rm`), not a request handler. */
    if (brix_oci_store_layer_path(st, ctx->req.name, ctx->req.name_len,
                                  &ctx->req.digest, path,
                                  sizeof(path)) != 0)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!brix_oci_store_exists(path, NULL)) {
        return brix_oci_error(r, NGX_HTTP_NOT_FOUND,
                              BRIX_OCI_ERR_BLOB_UNKNOWN, NULL);
    }
    if (brix_oci_store_remove(path, log) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return brix_oci_reply_empty(r, NGX_HTTP_ACCEPTED);
}
