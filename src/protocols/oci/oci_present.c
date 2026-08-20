/*
 * oci_present.c — the two headers a registry client actually reads (App. B.1).
 *
 * WHAT: decide the `Content-Type` and `Docker-Content-Digest` for a cached
 *       object and attach them to the outgoing response.
 * WHY:  the bytes alone are not a valid registry answer. Podman and docker
 *       branch on the manifest media type — an OCI image index and a Docker
 *       manifest list are different objects with the same JSON shape, and the
 *       wrong `Content-Type` sends the client down the wrong unpack path — and
 *       both read `Docker-Content-Digest` to pin what they pulled, which is
 *       what makes a subsequent `podman image inspect` agree with the registry.
 *       A cache stores bytes; a mirror must also answer these two questions.
 * HOW:  both are pure functions of the object, so they are DERIVED and then
 *       memoized in the `.ocimeta` sidecar rather than trusted from anywhere:
 *         - a blob or digest-addressed manifest already names its digest in the
 *           key, and needs no I/O at all;
 *         - a TAG-addressed manifest is hashed once (bounded read through the
 *           VFS seam), its `mediaType` lifted from the JSON, and the pair
 *           written beside the body.
 *       A missing, unreadable or stale sidecar therefore costs one derivation,
 *       never a wrong answer — which is the whole reason the sidecar is a memo
 *       and not a source of truth.
 */

#include "oci.h"
#include "oci_module_internal.h"

#include "core/compat/json_min.h"
#include "core/http/etag.h"
#include "core/http/http_headers.h"
#include "observability/dashboard/dashboard.h"
#include "observability/metrics/unified.h"
#include "protocols/shared/file_serve.h"
#include "fs/vfs/vfs.h"
#include "oci/digest.h"

#include <string.h>
#include <time.h>

/* The spec caps a manifest at 4 MiB; anything larger is not a manifest we can
 * describe, and hashing it on the event loop would be a stall besides. */
#define OCI_MANIFEST_MAX      (4 * 1024 * 1024)

/* The default when a manifest carries no `mediaType` member — Docker schema-2
 * manifests written before the field was mandatory. Serving them as the OCI
 * type would make a docker client reject its own manifest. */
#define OCI_CT_DOCKER_MANIFEST \
    "application/vnd.docker.distribution.manifest.v2+json"
#define OCI_CT_BLOB           "application/octet-stream"

/* Lift the digest out of the canonical key: for a blob it is the whole
 * reference, for a manifest only when the reference is digest-shaped. */
static int
oci_digest_from_key(const ngx_http_brix_oci_ctx_t *ctx, char *out, size_t outsz)
{
    if (ctx->req.cls != BRIX_OCI_REQ_BLOB && !ctx->req.ref_is_digest) {
        return -1;
    }
    return (brix_oci_digest_format(&ctx->req.digest, out, outsz) < 0) ? -1 : 0;
}

/* Hash a tag-addressed manifest and read its media type. sha256 is right here
 * and not a shortcut: a tag is only ever bound by a push that arrived by tag,
 * and such a push is filed under the algorithm we produce, so the digest this
 * reports is the digest the store is keyed by. The read goes through
 * brix_vfs_file_pread (invariant #12): the handle may be backed by a cache
 * decorator over a remote store, and this is the one seam that knows how to
 * read either. */
static ngx_int_t
oci_derive_manifest(ngx_http_request_t *r, brix_vfs_file_t *fh,
    const brix_vfs_stat_t *vst, brix_oci_meta_t *meta)
{
    u_char             *buf;
    ssize_t             n;
    brix_oci_digest_t   d;

    if (vst->size <= 0 || vst->size > OCI_MANIFEST_MAX) {
        return NGX_DECLINED;
    }

    buf = ngx_palloc(r->pool, (size_t) vst->size);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    n = brix_vfs_file_pread(fh, buf, (size_t) vst->size, 0);
    if (n != (ssize_t) vst->size) {
        return NGX_DECLINED;
    }

    if (brix_oci_sha256(buf, (size_t) n, &d) != 0
        || brix_oci_digest_format(&d, meta->digest, sizeof(meta->digest)) < 0)
    {
        return NGX_DECLINED;
    }

    if (!brix_json_get_str((const char *) buf, (size_t) n, "mediaType",
                           meta->content_type, sizeof(meta->content_type))
        || meta->content_type[0] == '\0')
    {
        (void) ngx_cpystrn((u_char *) meta->content_type,
                           (u_char *) OCI_CT_DOCKER_MANIFEST,
                           sizeof(meta->content_type));
    }
    return NGX_OK;
}

/* A media type is echoed straight into a response header, so it is validated
 * before it is trusted: the sidecar and the manifest JSON are both attacker-
 * reachable in the sense that matters (an upstream we mirror chose them). */
static int
oci_ctype_sane(const char *ct)
{
    size_t i;

    if (ct[0] == '\0') {
        return 0;
    }
    for (i = 0; ct[i] != '\0'; i++) {
        unsigned char c = (unsigned char) ct[i];

        if (c <= 0x20 || c >= 0x7f || c == ',' || c == ';' || c == '"') {
            return 0;
        }
    }
    return 1;
}

/* The validator a registry client revalidates with. A manifest's digest IS
 * its strong ETag (what a Docker Registry v2 emits), and it is the only
 * validator that survives a refill of identical bytes: the serve pipeline's
 * mtime+size ETag changes the moment the mirror re-fetches an unchanged tag
 * past its TTL, turning every revalidation into a full body transfer. */
int
brix_oci_present_etag(const brix_oci_present_t *pres, char *buf, size_t buflen)
{
    int n;

    if (pres == NULL || pres->meta.digest[0] == '\0') {
        return 0;
    }
    n = snprintf(buf, buflen, "\"%s\"", pres->meta.digest);

    return (n > 0 && (size_t) n < buflen);
}


/* Replace the validator the serve pipeline already registered rather than
 * adding one: two ETag headers leave the client to pick, and a client that
 * picks the mtime one is back to transferring bodies it holds. */
static void
oci_set_etag(ngx_http_request_t *r, const char *etag)
{
    ngx_str_t  v;

    v.len  = ngx_strlen(etag);
    v.data = ngx_pnalloc(r->pool, v.len);
    if (v.data == NULL) {
        return;                       /* the mtime validator stands */
    }
    ngx_memcpy(v.data, etag, v.len);

    if (r->headers_out.etag != NULL) {
        r->headers_out.etag->value = v;
        return;
    }
    (void) brix_http_set_header_str(r, "ETag", &v, 0, &r->headers_out.etag);
}


ngx_int_t
brix_oci_present_prepare(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx,
    brix_vfs_file_t *fh, const brix_vfs_stat_t *vst, const char *meta_base,
    brix_oci_present_t *pres)
{
    ngx_log_t  *log = r->connection->log;
    ngx_int_t   rc;

    ngx_memzero(pres, sizeof(*pres));

    /* A blob's digest IS its name: no sidecar, no read, no hash. Doing this
     * before the sidecar load keeps the hot path (blobs are ~99% of an image
     * pull by both count and bytes) free of any extra I/O. */
    if (ctx->req.cls == BRIX_OCI_REQ_BLOB) {
        if (oci_digest_from_key(ctx, pres->meta.digest,
                                sizeof(pres->meta.digest)) != 0)
        {
            return NGX_ERROR;              /* classifier guarantees otherwise */
        }
        (void) ngx_cpystrn((u_char *) pres->meta.content_type,
                           (u_char *) OCI_CT_BLOB,
                           sizeof(pres->meta.content_type));
        return NGX_OK;
    }

    rc = (meta_base != NULL)
         ? brix_oci_meta_load(meta_base, vst->size, vst->mtime, &pres->meta,
                              log)
         : NGX_DECLINED;
    if (rc == NGX_OK && oci_ctype_sane(pres->meta.content_type)
        && pres->meta.digest[0] != '\0')
    {
        /* A tag manifest served past its TTL is stale-if-error output from the
         * cache tier (sd_cache_stale_serve_ok). The mirror cannot see that
         * decision directly, but it wrote fetched_at itself, so the age of its
         * own record is an exact and local answer. */
        if (!ctx->req.ref_is_digest && lcf->manifest_ttl > 0
            && pres->meta.fetched_at > 0
            && ngx_time() - pres->meta.fetched_at > lcf->manifest_ttl)
        {
            pres->stale = 1;
            ctx->stale  = 1;
        }
        return NGX_OK;
    }

    /* No usable memo: derive from the bytes and (best-effort) leave one behind
     * for the next hit. */
    if (oci_derive_manifest(r, fh, vst, &pres->meta) != NGX_OK) {
        /* Undescribable object: still serve it, but say nothing we cannot
         * stand behind rather than guessing a digest. */
        (void) ngx_cpystrn((u_char *) pres->meta.content_type,
                           (u_char *) OCI_CT_DOCKER_MANIFEST,
                           sizeof(pres->meta.content_type));
        pres->meta.digest[0] = '\0';
        return NGX_OK;
    }

    pres->meta.fetched_at = ngx_time();
    /* D2.5: what "verified" may honestly claim. A digest-addressed object got
     * here through the oci-digest verify — its key named the hash its bytes
     * had to have, and a mismatch never became cache-visible. A TAG-addressed
     * manifest has no such check available: the client supplied no digest, and
     * the upstream's own Docker-Content-Digest is the upstream's word about
     * the upstream's bytes. That is trust-on-first-fetch, and the record says
     * so rather than laundering a derivation into a verification. */
    pres->meta.verified   = ctx->req.ref_is_digest ? 1 : 0;
    if (meta_base != NULL) {
        (void) brix_oci_meta_store(meta_base, vst->size, vst->mtime,
                                   &pres->meta, log);
    }

    return NGX_OK;
}

void
brix_oci_present_headers(ngx_http_request_t *r, ngx_fd_t fd, off_t file_size,
    void *userdata)
{
    brix_oci_present_t *pres = userdata;

    (void) fd;
    (void) file_size;

    if (pres == NULL) {
        return;
    }

    /* Overrides whatever the shared serve pipeline guessed: the key has no
     * extension, so its guess is always the location's default type. The
     * buffer is the request-pool-allocated presentation record, so it outlives
     * the header filter. */
    if (oci_ctype_sane(pres->meta.content_type)) {
        r->headers_out.content_type.data = (u_char *) pres->meta.content_type;
        r->headers_out.content_type.len  =
            ngx_strlen(pres->meta.content_type);
        r->headers_out.content_type_len  = r->headers_out.content_type.len;
        r->headers_out.content_type_lowcase = NULL;
    }

    if (pres->meta.digest[0] != '\0') {
        char  etag[BRIX_OCI_DIGEST_STRLEN + 3];

        (void) brix_http_set_header(r, "Docker-Content-Digest",
                                    pres->meta.digest, NULL);
        if (brix_oci_present_etag(pres, etag, sizeof(etag))) {
            oci_set_etag(r, etag);
        }
    }

    (void) brix_oci_api_version_header(r);

    /* RFC 9111 §5.5.1 — the response is knowingly past its freshness lifetime
     * because the upstream could not be reached. A client that honours it can
     * tell "the mirror is degraded" from "the tag genuinely still points here",
     * which is exactly the distinction a CI pipeline needs. */
    if (pres->stale) {
        (void) brix_http_set_header(r, "Warning",
            "110 - \"Response is Stale\"", NULL);
    }
}


void
brix_oci_present_serve_opts(brix_http_serve_opts_t *opts,
    brix_oci_present_t *pres)
{
    ngx_memzero(opts, sizeof(*opts));
    opts->xfer_proto      = BRIX_XFER_PROTO_OCI;
    opts->op_name         = "GET";
    opts->identity        = "anonymous";
    opts->etag_flags      = BRIX_ETAG_WEAK;
    /* Never transcode: a client verifies the body against the digest we just
     * advertised in Docker-Content-Digest, so any outbound codec — however
     * reversible — turns every pull into a checksum failure. */
    opts->compress        = 0;
    opts->pre_header_send = (pres != NULL) ? brix_oci_present_headers : NULL;
    opts->pre_header_ud   = pres;
}
