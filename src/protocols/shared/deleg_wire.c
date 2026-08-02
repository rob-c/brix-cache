/*
 * deleg_wire.c — shared conf→VFS delegation wiring (see deleg_wire.h).
 */
#include "deleg_wire.h"
#include "auth/token/aud_match.h"
#include "auth/s3/sts.h"                 /* brix_s3_sts_conf_t (§5.5 stamp) */

/* Arm S3 STS EXCHANGE (phase-70 §5.5) when the export configured a full STS
 * service triple (endpoint + service ak + service sk). An S3 SigV4 secret is
 * never on the wire, so this is the only way to authenticate the S3 origin leg
 * AS the caller: the node exchanges its own service credential for temporary
 * creds scoped to the caller's identity. The conf is built on the request pool
 * (its ngx_str_t fields borrow conf-owned bytes) and handed to set_sts, which
 * allocates the live-cred bag when no forwardable bytes were captured — the STS
 * case, exactly like SSS injection. A missing ak/sk (or endpoint) leaves STS
 * disarmed; region defaults inside the STS client, ttl inside the conf merge. */
static void
deleg_wire_stamp_sts(brix_vfs_ctx_t *vctx, ngx_http_brix_shared_conf_t *cc)
{
    brix_s3_sts_conf_t *cf;

    if (cc->backend_sts_endpoint.len == 0
        || cc->backend_sts_access_key.len == 0
        || cc->backend_sts_secret_key.len == 0)
    {
        return;
    }

    cf = ngx_pcalloc(vctx->pool, sizeof(*cf));
    if (cf == NULL) {
        return;                 /* degrade to SELECT — deny is the gate's call */
    }
    cf->endpoint = cc->backend_sts_endpoint;
    cf->region   = cc->backend_sts_region;
    cf->role_arn = cc->backend_sts_role;
    cf->svc_ak   = cc->backend_sts_access_key;
    cf->svc_sk   = cc->backend_sts_secret_key;
    cf->ttl_secs = (cc->backend_sts_ttl != NGX_CONF_UNSET)
                   ? (int) cc->backend_sts_ttl : 3600;
    cf->flavor   = (cc->backend_sts_flavor != NGX_CONF_UNSET_UINT)
                   ? (int) cc->backend_sts_flavor : BRIX_STS_FLAVOR_AWS;

    brix_vfs_deleg_set_sts(vctx,
        (enum brix_cred_mode) cc->backend_delegation, cf);
}

/* EXCHANGE-with-endpoint is the one mode that does NOT forward the client
 * bearer verbatim: the exchange mints a backend-audienced replacement. */
static int
deleg_wire_exchanges(const ngx_http_brix_shared_conf_t *cc)
{
    return cc->backend_delegation == BRIX_CRED_EXCHANGE
           && cc->backend_tx_endpoint.len > 0;
}

const ngx_str_t *
brix_proto_deleg_gate_bearer(const ngx_str_t *bearer,
    const ngx_http_brix_shared_conf_t *cc, ngx_log_t *log)
{
    if (bearer == NULL || bearer->len == 0 || deleg_wire_exchanges(cc)) {
        return bearer;
    }
    if (!brix_token_backend_aud_ok(bearer, cc->backend_token_aud, log)) {
        return NULL;   /* wrong audience — never forwarded verbatim */
    }
    return bearer;
}

void
brix_proto_deleg_stamp_conf(brix_vfs_ctx_t *vctx,
    ngx_http_brix_shared_conf_t *cc)
{
    const ngx_str_t *aud = NULL;

    /* SSS injection first: it allocates the bag when no bytes were captured
     * (§5.6); the exchange stamp below is a piggyback-only setter. */
    brix_vfs_deleg_set_sss(vctx,
        (enum brix_cred_mode) cc->backend_delegation,
        &cc->backend_sss_keytab);

    /* S3 STS EXCHANGE (§5.5): like SSS, arms on the no-captured-bytes path and
     * allocates the bag if needed. Independent of the bearer token-exchange
     * below (that is the OAuth RFC-8693 leg; this is the S3 SigV4 leg). */
    deleg_wire_stamp_sts(vctx, cc);

    if (!deleg_wire_exchanges(cc)) {
        return;
    }
    if (cc->backend_token_aud != NULL && cc->backend_token_aud->nelts > 0) {
        aud = &((ngx_str_t *) cc->backend_token_aud->elts)[0];
    }
    brix_vfs_deleg_set_exchange(vctx, &cc->backend_tx_endpoint,
        &cc->backend_tx_client_id, &cc->backend_tx_client_secret,
        aud, &cc->backend_tx_cache);
}
