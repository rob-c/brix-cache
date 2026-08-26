/*
 * access_vfs.c — WebDAV's confined-VFS-ctx constructors and the delegation
 * binder they compose.
 *
 * WHAT: webdav_vfs_bind_deleg (bearer/proxy forwarding onto a cred-bound ctx)
 *       and the webdav_vfs_ctx_build family (bare / _ns / _data), the single
 *       construction path every WebDAV method file uses to reach storage.
 * WHY:  Split out of access.c to hold that translation unit under the 600-line
 *       file-size cap; the access phase and the ctx constructors are separate
 *       concerns that only shared a file for historical reasons.
 * HOW:  Verbatim move — see each function's own contract comment.
 */

#include "webdav.h"
#include "protocols/shared/deleg_wire.h"    /* §5.2 aud gate + §5.4 exchange */
#include "fs/backend/sd.h"  /* enum brix_cred_mode / BRIX_CRED_SELECT */
#include "core/http/http_headers.h"         /* brix_http_request_is_tls */

/* ---- webdav_vfs_bind_deleg -------------------------------------------------
 *
 * WHAT: Bind the request's captured forwardable credential (bearer JWT and/or
 *       user-supplied full x509 proxy PEM) onto a cred-bound VFS ctx, using the
 *       export's resolved delegation mode. See webdav_auth.h for the contract.
 *
 * WHY:  Called at every WebDAV brix_vfs_ctx_bind_backend_cred site so a delegated
 *       export authenticates the backend leg AS the inbound user rather than the
 *       shared service credential. The bytes were captured once at the auth gate
 *       (bearer in webdav_verify_bearer_token, proxy in the access-phase header
 *       capture) and stashed on the req ctx; here they are handed to the VFS.
 *
 * HOW:  Reads conf->common.backend_delegation as the mode and the req ctx's
 *       bearer_token / deleg_proxy_pem as the bytes; brix_vfs_deleg_bind is a
 *       no-op for SELECT mode or when nothing was captured. A captured bearer
 *       that would be forwarded VERBATIM (any mode except EXCHANGE-with-endpoint,
 *       which re-audiences it) must first pass the backend audience gate
 *       (`brix_backend_token_audience_ok`, phase-70 §5.2 / P90-70.9) — on
 *       refusal the bearer is simply not bound (SELECT/service-cred policy then
 *       applies). EXCHANGE conf + the per-conf minted-token cache slot are
 *       stamped after the bind. */
void
webdav_vfs_bind_deleg(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, brix_vfs_ctx_t *vctx)
{
    ngx_http_brix_webdav_req_ctx_t *rctx;
    const ngx_str_t                *bearer;

    if (conf->common.backend_delegation == BRIX_CRED_SELECT) {
        return;
    }

    rctx   = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    bearer = brix_proto_deleg_gate_bearer(
        (rctx != NULL) ? &rctx->bearer_token : NULL,
        &conf->common, r->connection->log);

    (void) brix_vfs_deleg_bind(r->pool, vctx,
        (enum brix_cred_mode) conf->common.backend_delegation,
        bearer,
        (rctx != NULL) ? &rctx->deleg_proxy_pem : NULL);

    brix_proto_deleg_stamp_conf(vctx, &conf->common);

    /* P90-70.4: stamp the export's trust store so the VFS deleg gate re-runs
     * the RFC-3820 chain-trust check before materialising the proxy (no-op
     * when nothing was bound or no CA store is configured). */
    brix_vfs_deleg_set_ca_store(vctx, conf->ca_store, conf->common.verify_depth);
}


/*
 * WHAT: Canonical confined-VFS-ctx constructors for WebDAV storage ops.
 *
 * WHY: Every method file used to hand-roll the same init + credential-binding
 * sequence; one constructor family keeps the binding order (cred → mint →
 * deleg) in a single place next to the deleg binder it composes.
 *
 * HOW: webdav_vfs_ctx_build initialises the bare confined ctx (identity from
 * the req ctx, TLS from the connection). The _ns/_data variants add the
 * export's per-user backend credential policy on top; only the data plane
 * binds the opt-in mint CA — a namespace op that needs a credential the user
 * doesn't have falls back per storage_credential_fallback (see prop_xattr.c).
 * Callers that route through the export's storage driver assign vctx->sd
 * themselves (brix_webdav_backend_instance).
 */
void
webdav_vfs_ctx_build(ngx_http_request_t *r, const char *path,
    brix_vfs_ctx_t *vctx)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    brix_vfs_ctx_init(vctx, r->pool, r->connection->log,
        BRIX_PROTO_WEBDAV, conf->common.root_canon,
        conf->common.cache_root_canon, conf->common.allow_write,
        brix_http_request_is_tls(r),
        (wctx != NULL) ? wctx->identity : NULL, path);
}

static void
webdav_vfs_ctx_build_bound(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    unsigned bind_mint, brix_vfs_ctx_t *vctx)
{
    webdav_vfs_ctx_build(r, path, vctx);
    brix_vfs_ctx_bind_backend_cred(vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    if (bind_mint) {
        /* Phase-2 T9: opt-in minting for GSI/token identities that have no
         * pre-provisioned proxy. No-op unless a mint CA is configured. */
        brix_vfs_ctx_bind_backend_mint(vctx,
            &conf->common.storage_credential_mint_ca_cert,
            &conf->common.storage_credential_mint_ca_key,
            conf->common.storage_credential_mint_ttl);
    }
    webdav_vfs_bind_deleg(r, conf, vctx);
}

void
webdav_vfs_ctx_build_ns(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    brix_vfs_ctx_t *vctx)
{
    webdav_vfs_ctx_build_bound(r, conf, path, 0, vctx);
}

void
webdav_vfs_ctx_build_data(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    brix_vfs_ctx_t *vctx)
{
    webdav_vfs_ctx_build_bound(r, conf, path, 1, vctx);
}
