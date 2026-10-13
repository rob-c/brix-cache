/*
 * dispatch_tls.c - WebDAV access-phase TLS capability policy.
 *
 * WHAT: Classifies the session/data/login capabilities exercised by a request
 *       and refuses cleartext use when brix_tls_require demands TLS.
 * WHY: Credential-bearing query forms must be gated before parsing or
 *      authentication and must never appear in nginx error-log context.
 * HOW: Build the capability mask, call the shared VFS security gate, scrub
 *      credential queries before logging, and return the metrics-counted 403.
 */

#include "core/compat/log_event.h"
#include "webdav.h"
#include "fs/vfs/vfs_secgate.h"

/* ---- Enforce WebDAV TLS capability requirements ----
 *
 * WHAT: Return NGX_DECLINED when the request may proceed, or a completed 403
 *       response when any exercised capability requires TLS.
 * WHY: Session, data, and login policies must agree with the root protocol and
 *      protect both header and query credential transports.
 * HOW: 1. Classify method and credential capabilities. 2. Ask the shared gate.
 *      3. On refusal scrub query tokens, log the capability, and count the 403.
 */
ngx_int_t
webdav_tls_require_gate(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_uint_t caps;
    ngx_uint_t refused;

    if (conf->common.tls_require == 0) {
        return NGX_DECLINED;
    }

    caps = BRIX_TLSREQ_SESSION;
    if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_PUT) {
        caps |= BRIX_TLSREQ_DATA;
    }
    if (r->headers_in.authorization != NULL
        || brix_http_query_has_decoded_name(r->args, "authz",
                                            BRIX_HTTP_QUERY_CASE_INSENSITIVE)
        || brix_http_query_has_decoded_name(r->args, "access_token",
                                            BRIX_HTTP_QUERY_CASE_INSENSITIVE))
    {
        caps |= BRIX_TLSREQ_LOGIN;
    }

    refused = brix_tls_gate_refused(conf->common.tls_require, caps,
                                    r->connection->ssl != NULL);
    if (refused == 0) {
        return NGX_DECLINED;
    }

    brix_http_redact_request_query_tokens(r);
    BRIX_LOG(NGX_LOG_WARN, r->connection->log, 0,
        "brix: cleartext request refused by brix_tls_require %s (method=%V)",
        brix_tls_cap_name(refused), &r->method_name);
    return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
}
