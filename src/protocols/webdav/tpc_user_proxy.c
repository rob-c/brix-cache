/*
 * tpc_user_proxy.c — resolve the requesting user's delegated x509 proxy for the
 * HTTP-TPC pull leg so the SOURCE authenticates the END USER, not the
 * destination's static service cert (phase-70 credential-forwarding closure).
 *
 * See tpc_user_proxy.h for the WHAT/WHY/HOW contract.  This file reuses the
 * existing Phase-70 delegation plumbing end-to-end:
 *   - the live full-proxy passthrough bag captured on the request
 *     (rctx->deleg_proxy_pem, from X-Brix-Delegate-Proxy) — same field the VFS
 *     PASSTHROUGH seam reads;
 *   - the per-user delegation store written by delegation.c
 *     (<storage_credential_dir>/<key>.pem, keyed by DN) — resolved via the same
 *     brix_sd_ucred_select() the davs/S3 origin legs use;
 *   - the same 0600 temp materialiser + unlink/zero cleanup pattern the VFS
 *     PASSTHROUGH seam uses (brix_proxy_gsi_write_pem_temp).
 */

#include "tpc_user_proxy.h"

#include "fs/backend/ucred.h"          /* brix_sd_ucred_select / brix_sd_ucred_t */
#include "net/proxy/gsi_upstream.h"    /* brix_proxy_gsi_write_pem_temp          */

#include <string.h>
#include <unistd.h>

/*
 * Cleanup payload for a materialised passthrough proxy temp: the pool-allocated
 * 0600 temp path.  Mirrors vfs_deleg.c's brix_deleg_temp_t — on request-pool
 * teardown the file is unlinked and its path string zeroed so the private key
 * never lingers in freed-but-reused pool memory.
 */
typedef struct {
    char *path;   /* NUL-terminated temp path, owned by the request pool */
} webdav_tpc_user_proxy_temp_t;

/*
 * webdav_tpc_user_proxy_temp_cleanup — request-pool cleanup handler: unlink the
 * materialised proxy temp and zero its path string.
 *
 * WHAT: unlink() the temp (ignoring ENOENT) then scrub the path bytes.
 * WHY:  secret hygiene — the delegated proxy's private key lives only in the
 *       0600 temp for the transfer's duration and must vanish the moment the
 *       request pool is torn down, success or failure.
 * HOW:  data is a webdav_tpc_user_proxy_temp_t*; a NULL/consumed entry is a
 *       no-op.
 */
static void
webdav_tpc_user_proxy_temp_cleanup(void *data)
{
    webdav_tpc_user_proxy_temp_t *t = data;

    if (t == NULL || t->path == NULL) {
        return;
    }
    (void) unlink(t->path);   /* vfs-seam-allow: config-domain delegated proxy credential temp (not export storage) */
    ngx_memzero(t->path, ngx_strlen(t->path));
    t->path = NULL;
}

/*
 * webdav_tpc_user_proxy_materialise — write PEM bytes to an owner-only temp and
 * register the unlink+zero cleanup, pointing *out at the temp path.
 *
 * WHAT: 0600 temp via brix_proxy_gsi_write_pem_temp(), pool-copied path,
 *       cleanup registered, out->cert_path == out->key_path == temp path.
 * WHY:  curl reads the client cert/key from a FILE path; a live passthrough
 *       proxy arrives as in-memory PEM (chain + key), so it must be staged to a
 *       0600 file the same way the VFS PASSTHROUGH seam stages it.  cert and key
 *       share one combined PEM, so both curl options point at the same file.
 * HOW:  NGX_OK with out filled on success; NGX_ERROR (out left have=0) on
 *       materialise / alloc / cleanup-registration failure — the temp is
 *       unlinked before returning so no key is left on disk.
 */
static ngx_int_t
webdav_tpc_user_proxy_materialise(ngx_http_request_t *r,
    const u_char *pem, size_t pem_len, webdav_tpc_user_proxy_t *out)
{
    char                            tmp[NGX_MAX_PATH];
    char                           *path;
    size_t                          path_len;
    ngx_pool_cleanup_t             *cln;
    webdav_tpc_user_proxy_temp_t   *payload;

    if (brix_proxy_gsi_write_pem_temp(pem, pem_len, tmp, sizeof(tmp)) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "brix_webdav: TPC pull could not materialise delegated"
                      " proxy temp");
        return NGX_ERROR;
    }

    path_len = ngx_strlen(tmp);
    path = ngx_pnalloc(r->pool, path_len + 1);
    if (path == NULL) {
        (void) unlink(tmp);   /* vfs-seam-allow: config-domain delegated proxy credential temp (not export storage) */
        return NGX_ERROR;
    }
    ngx_memcpy(path, tmp, path_len);
    path[path_len] = '\0';

    cln = ngx_pool_cleanup_add(r->pool, sizeof(*payload));
    if (cln == NULL) {
        (void) unlink(path);  /* vfs-seam-allow: config-domain delegated proxy credential temp (not export storage) */
        ngx_memzero(path, path_len);
        return NGX_ERROR;
    }
    payload = cln->data;
    payload->path = path;
    cln->handler = webdav_tpc_user_proxy_temp_cleanup;

    out->have      = 1;
    out->cert_path = path;
    out->key_path  = path;   /* stored PEM carries cert + key in one file */
    return NGX_OK;
}

/*
 * webdav_tpc_user_proxy_from_passthrough — resolution step 1: the live full
 * proxy the front door captured on this request.
 *
 * WHAT: if rctx carries a non-empty deleg_proxy_pem, materialise it and mark
 *       out->have=1.
 * WHY:  a user who explicitly delegated a full proxy over the wire
 *       (X-Brix-Delegate-Proxy) must have THAT proxy presented to the source —
 *       it is the most specific, request-scoped credential and takes precedence
 *       over any pre-provisioned store entry.
 * HOW:  returns 1 when the step produced a decision (materialise succeeded, or
 *       failed and was logged — either way the passthrough was the intended
 *       credential and we do not silently fall through to the service cert),
 *       0 when no passthrough proxy is present so the next step should run.
 */
static int
webdav_tpc_user_proxy_from_passthrough(ngx_http_request_t *r,
    const ngx_http_brix_webdav_req_ctx_t *rctx, webdav_tpc_user_proxy_t *out)
{
    if (rctx == NULL || rctx->deleg_proxy_pem.len == 0
        || rctx->deleg_proxy_pem.data == NULL)
    {
        return 0;
    }

    if (webdav_tpc_user_proxy_materialise(r, rctx->deleg_proxy_pem.data,
            rctx->deleg_proxy_pem.len, out) != NGX_OK)
    {
        /* Deny-consistent: the user delegated a proxy but we could not stage
         * it — do NOT quietly present the service identity in its place. Flag
         * deny so the caller aborts rather than falling back. */
        out->have = 0;
        out->deny = 1;
        return 1;
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "brix_webdav: TPC pull presenting delegated proxy"
                  " (passthrough) to source");
    return 1;
}

/*
 * webdav_tpc_user_proxy_from_store — resolution step 2: the per-user delegation
 * store keyed by the authenticated identity.
 *
 * WHAT: brix_sd_ucred_select() over common.storage_credential_dir; on an x509
 *       .pem hit point cert_path/key_path at the stored file.
 * WHY:  a proxy uploaded to <cred_dir>/<key>.pem via the GridSite delegation
 *       endpoint (delegation.c) is exactly the user's credential — the same
 *       store the davs/S3 origin legs select from — and must be presented to
 *       the source when no live passthrough proxy is present.
 * HOW:  no credential dir configured, or select returned non-x509 (bearer/s3/
 *       ceph) or DECLINED (absent / expired .pem) → leave have=0 so the caller
 *       falls back to the service cert.  A stored .pem holds cert + key in one
 *       file, so cert_path == key_path (the store path itself; no temp).
 */
static void
webdav_tpc_user_proxy_from_store(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const brix_identity_t *id,
    webdav_tpc_user_proxy_t *out)
{
    const ngx_str_t  *dir = &conf->common.storage_credential_dir;
    char              dirz[BRIX_UCRED_PATH_MAX];
    brix_sd_ucred_t   cred;
    char             *path;
    size_t            path_len;

    if (dir->len == 0 || id == NULL || dir->len >= sizeof(dirz)) {
        return;
    }
    ngx_memcpy(dirz, dir->data, dir->len);
    dirz[dir->len] = '\0';

    if (brix_sd_ucred_select(dirz, id, &cred) != NGX_OK) {
        /* Absent, or an expired .pem (cred.expired) — no usable per-user proxy;
         * fall back to the service cert. */
        return;
    }
    if (cred.is_bearer || cred.is_s3 || cred.is_ceph) {
        /* A non-x509 stored credential is not a curl client cert for the pull
         * leg (the bearer path is applied as an Authorization header, s3/ceph
         * are backend-only). Fall back to the service cert. */
        return;
    }

    path_len = ngx_strlen(cred.path);
    path = ngx_pnalloc(r->pool, path_len + 1);
    if (path == NULL) {
        return;
    }
    ngx_memcpy(path, cred.path, path_len);
    path[path_len] = '\0';

    out->have      = 1;
    out->cert_path = path;
    out->key_path  = path;   /* stored .pem carries cert + key in one file */
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "brix_webdav: TPC pull presenting delegated proxy"
                  " (store) to source");
}

void
webdav_tpc_user_proxy_resolve(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, webdav_tpc_user_proxy_t *out)
{
    ngx_http_brix_webdav_req_ctx_t *rctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    out->have      = 0;
    out->deny      = 0;
    out->cert_path = NULL;
    out->key_path  = NULL;

    /* Step 1: the live full-proxy passthrough the front door captured. */
    if (webdav_tpc_user_proxy_from_passthrough(r, rctx, out)) {
        return;
    }

    /* Step 2: the per-user delegation store keyed by the authenticated DN. */
    webdav_tpc_user_proxy_from_store(r, conf,
        (rctx != NULL) ? rctx->identity : NULL, out);

    /* Step 3 (implicit): out->have stays 0 → caller falls back to
     * conf->tpc_cert, preserving current behaviour for non-delegated setups. */
}
