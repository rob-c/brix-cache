/*
 * oci_key.c — the canonical cache key (§D2.3).
 *
 * WHAT: turn a classified route into the one string that is simultaneously
 *       the cache key, the export-relative store path, and the upstream URL
 *       suffix: "/v2/" [namespace "/"] name "/" terminal "/" reference.
 * WHY:  three consumers must agree on it byte for byte, and two of them
 *       RE-CLASSIFY it. brix_cache_verify_oci_digest() reads the reference
 *       back off the key to know which digest a fill must hash to, and
 *       sd_cache_is_manifest_key() reads it to know whether the object is a
 *       mutable tag manifest (TTL) or immutable content (forever). A key in
 *       any other shape — a hash, a flattened name, an Accept-qualified
 *       variant — silently disables both: the verify becomes a no-op and the
 *       tag manifest becomes permanent. So the key IS the route, and the one
 *       normalization applied (the DockerHub `library/` expansion) is applied
 *       HERE, before anyone reads it, rather than at each consumer.
 * HOW:  a single bounded append into ctx->key. No allocation: the classifier
 *       already validated every component, so this is concatenation, not
 *       parsing — the only failure is the cap.
 */

#include "oci.h"

/* Whether `name` needs the operator's upstream namespace prefixed. A
 * single-component name is the DockerHub shorthand ("alpine"), which every
 * client resolves against an implicit namespace ("library/alpine") before it
 * hits the wire; a multi-component name is already fully qualified and must
 * be passed through untouched or it would name a different repository. */
static int
oci_needs_namespace(const ngx_http_brix_oci_loc_conf_t *lcf,
    const brix_oci_req_t *req)
{
    return lcf->upstream_ns.len > 0 && req->name_components == 1;
}

ngx_int_t
brix_oci_build_key(ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx)
{
    const brix_oci_req_t *req = &ctx->req;
    const char           *terminal;
    char                  digest[BRIX_OCI_DIGEST_STRLEN];
    const char           *ref;
    size_t                ref_len;
    size_t                need, off;

    terminal = (req->cls == BRIX_OCI_REQ_MANIFEST) ? "manifests" : "blobs";

    /* A blob route is named ONLY by its digest, and the classifier already
     * parsed it — rebuild the canonical spelling from the parsed form rather
     * than echoing the wire span, so a legal-but-unusual encoding cannot
     * produce two keys for one object. A manifest reference is a tag or a
     * digest and rides verbatim: it is the client's chosen name for the
     * object, and the TTL classifier keys off exactly that distinction. */
    if (req->cls == BRIX_OCI_REQ_BLOB) {
        if (brix_oci_digest_format(&req->digest, digest, sizeof(digest)) < 0) {
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }
        ref     = digest;
        ref_len = ngx_strlen(digest);

    } else {
        ref     = req->ref;
        ref_len = req->ref_len;
    }

    need = sizeof("/v2/") - 1 + req->name_len + 1 + ngx_strlen(terminal) + 1
           + ref_len;
    if (oci_needs_namespace(lcf, req)) {
        need += lcf->upstream_ns.len + 1;
    }
    if (need >= sizeof(ctx->key)) {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    off = 0;
    ngx_memcpy(ctx->key + off, "/v2/", sizeof("/v2/") - 1);
    off += sizeof("/v2/") - 1;

    if (oci_needs_namespace(lcf, req)) {
        ngx_memcpy(ctx->key + off, lcf->upstream_ns.data, lcf->upstream_ns.len);
        off += lcf->upstream_ns.len;
        ctx->key[off++] = '/';
    }

    ngx_memcpy(ctx->key + off, req->name, req->name_len);
    off += req->name_len;
    ctx->key[off++] = '/';

    ngx_memcpy(ctx->key + off, terminal, ngx_strlen(terminal));
    off += ngx_strlen(terminal);
    ctx->key[off++] = '/';

    ngx_memcpy(ctx->key + off, ref, ref_len);
    off += ref_len;
    ctx->key[off] = '\0';

    ctx->key_len = off;
    return NGX_OK;
}
