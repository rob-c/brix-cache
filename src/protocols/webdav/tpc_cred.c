/*
 * tpc_cred.c — HTTP-TPC credential delegation implementation
 *
 * Acquires OAuth2/OIDC access tokens for third-party-copy pull transfers.
 * Two delegation modes:
 *
 *   oidc-agent     — UNIX-socket JSON IPC to a local oidc-agent daemon
 *   token-exchange — RFC 8693 token-exchange request to an external OAuth2
 *                    token endpoint
 *
 * Both paths are non-blocking from the nginx-worker perspective: external
 * processes are fork/exec'd and their output is read synchronously in a
 * small helper that exits once the token is returned.
 *
 * Per-mode fetch implementations live in siblings tpc_cred_oidc.c (oidc-agent)
 * and tpc_cred_exchange.c (RFC 8693); this file keeps the credential parse/
 * validate, mode dispatch, and metric machinery.
 */

#include "tpc_cred_internal.h"
#include "tpc_config.h"
#include "webdav.h"
#include "core/compat/log_diag.h"
#include "tpc/common/credential.h"
#include "core/compat/subprocess.h"   /* shared SIGCHLD-safe fork/exec capture */

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>


ngx_int_t
webdav_tpc_cred_metric_increment(ngx_http_request_t *r,
                                 brix_tpc_cred_metrics_e idx)
{
    BRIX_WEBDAV_METRIC_INC(tpc_cred_total[idx]);
    (void) r;
    return NGX_OK;
}

static ngx_int_t
webdav_tpc_cred_validate_token(ngx_http_request_t *r, ngx_str_t *token)
{
    brix_tpc_credential_t cred;

    if (token == NULL || token->data == NULL || token->len == 0) {
        return NGX_ERROR;
    }

    if (brix_tpc_credential_parse(token, BRIX_TPC_CREDENTIAL_TOKEN,
                                    &cred, r->pool, r->connection->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return brix_tpc_credential_validate(&cred, r->connection->log);
}


brix_tpc_cred_mode_e
webdav_tpc_cred_parse_mode(const char *value, size_t len)
{
    if (len == 4 && ngx_strncmp((u_char *) value,
                                (u_char *) "none", 4) == 0)
        return BRIX_TPC_CRED_NONE;

    if (len == 10 && ngx_strncmp((u_char *) value,
                                 (u_char *) "oidc-agent", 10) == 0)
        return BRIX_TPC_CRED_OIDC_AGENT;

    if (len == 14 && ngx_strncmp((u_char *) value,
                                 (u_char *) "token-exchange", 14) == 0)
        return BRIX_TPC_CRED_TOKEN_EXCHANGE;

    return BRIX_TPC_CRED_UNKNOWN;
}

/*
 * WHAT: Immutable bundle of the inputs a single credential-obtain attempt needs.
 * WHY:  It threads the request/URL/subject-token/scope plus the resolved output
 *       slot through the per-mode helpers without re-plumbing the frozen
 *       6-parameter public entry point's argument list at each step.
 * HOW:  Populated once in webdav_tpc_cred_obtain_token and passed by const
 *       pointer; token_out is the caller-owned result slot (mutated in place).
 */
typedef struct {
    ngx_http_request_t *r;
    const char         *source_url;
    const char         *subject_token;
    const char         *scope;
    ngx_str_t          *token_out;
} tpc_cred_request_t;


/*
 * WHAT: Record the success/error metric for a completed obtain attempt.
 * WHY:  Both mode paths share the same "validate on OK, then count" tail, so it
 *       lives once to keep the metric labels identical across modes.
 * HOW:  On NGX_OK re-validate the fetched token, then bump NSUCCESS/NERROR by
 *       the (possibly downgraded) result and return it.
 */
static ngx_int_t
tpc_cred_finish(ngx_http_request_t *r, ngx_str_t *token_out, ngx_int_t rc)
{
    if (rc == NGX_OK) {
        rc = webdav_tpc_cred_validate_token(r, token_out);
    }
    if (rc == NGX_OK) {
        webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NSUCCESS);
    } else {
        webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NERROR);
    }
    return rc;
}


/*
 * WHAT: Run the oidc-agent delegation mode for one request.
 * WHY:  Isolates the OIDC branch so the public dispatcher stays a flat switch.
 * HOW:  Fetch via the oidc-agent pipeline, then fold into the shared
 *       validate-and-count tail.
 */
static ngx_int_t
tpc_cred_run_oidc_agent(const tpc_cred_request_t *req)
{
    ngx_int_t rc = tpc_cred_oidc_agent_fetch(req->r, req->source_url,
                                             req->scope, req->token_out);
    return tpc_cred_finish(req->r, req->token_out, rc);
}


/*
 * WHAT: Run the RFC 8693 token-exchange delegation mode for one request.
 * WHY:  Isolates the exchange branch — config presence, subject-token presence,
 *       then the curl exchange — from the dispatcher.
 * HOW:  Fail-closed (NERROR + diagnostic) when the token endpoint or subject
 *       token is missing; otherwise exchange and fold into the shared tail.
 */
static ngx_int_t
tpc_cred_run_token_exchange(const tpc_cred_request_t *req,
                            ngx_http_brix_webdav_loc_conf_t *wconf)
{
    ngx_http_request_t *r = req->r;
    ngx_int_t rc;

    if (wconf->tpc_cred.token_endpoint.len == 0
        || wconf->tpc_cred.token_endpoint.data == NULL) {
        BRIX_DIAG_ERR(r->connection->log, 0,
            "tpc_cred: token-exchange is selected but no token endpoint "
            "is configured",
            "third-party-copy credential mode is token-exchange, but "
            "brix_webdav_tpc_token_endpoint is unset",
            "set the OAuth token endpoint for your IdP, or switch the TPC "
            "credential mode away from token-exchange");
        webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NERROR);
        return NGX_ERROR;
    }
    if (req->subject_token == NULL || *req->subject_token == '\0') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred: no subject token for token-exchange");
        webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NERROR);
        return NGX_ERROR;
    }

    rc = tpc_cred_rfc8693_exchange(
        r, req->subject_token, req->source_url, req->scope,
        (const char *) wconf->tpc_cred.token_endpoint.data,
        wconf->tpc_cred.token_client_id.len > 0 ?
            (const char *) wconf->tpc_cred.token_client_id.data : NULL,
        wconf->tpc_cred.token_client_secret.len > 0 ?
            (const char *) wconf->tpc_cred.token_client_secret.data : NULL,
        req->token_out);

    return tpc_cred_finish(r, req->token_out, rc);
}


ngx_int_t
webdav_tpc_cred_obtain_token(ngx_http_request_t *r,
                             brix_tpc_cred_mode_e mode,
                             const char *source_url,
                             const char *subject_token,
                             const char *scope,
                             ngx_str_t *token_out)
{
    ngx_http_brix_webdav_loc_conf_t *wconf;
    tpc_cred_request_t req = {
        r, source_url, subject_token, scope, token_out
    };

    wconf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (wconf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred: no WebDAV location config");
        return NGX_ERROR;
    }

    /* Increment started counter. */
    (void) webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NSTARTED);

    switch (mode) {
    case BRIX_TPC_CRED_OIDC_AGENT:
        return tpc_cred_run_oidc_agent(&req);

    case BRIX_TPC_CRED_TOKEN_EXCHANGE:
        return tpc_cred_run_token_exchange(&req, wconf);

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred: unknown delegation mode %d", (int) mode);
        webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NUNKNOWN_MODE);
        return NGX_ERROR;
    }
}

const char *
webdav_tpc_cred_metric_name(brix_tpc_cred_metrics_e idx)
{
    switch (idx) {
    case BRIX_TPC_CRED_NSTARTED:    return "tpc_cred_started";
    case BRIX_TPC_CRED_NSUCCESS:    return "tpc_cred_success";
    case BRIX_TPC_CRED_NERROR:      return "tpc_cred_error";
    case BRIX_TPC_CRED_NUNKNOWN_MODE: return "tpc_cred_unknown_mode";
    case BRIX_TPC_CRED_NPARSE_ERROR: return "tpc_cred_parse_error";
    default:                          return "tpc_cred_unknown";
    }
}
