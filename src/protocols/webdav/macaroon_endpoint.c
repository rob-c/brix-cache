/*
 * macaroon_endpoint.c — POST /.oauth2/token and GET /.well-known/oauth-authorization-server.
 *
 * WHAT: REST endpoints that implement WLCG macaroon token issuance for third-party
 *       delegation.  An authenticated client POSTs a scope and expiry request and
 *       receives a signed macaroon that can be delegated to a TPC agent.
 *
 * WHY: WLCG HTTP-TPC pull operations require the TPC destination to authenticate to
 *      the source server.  The client obtains a scoped macaroon from the source via
 *      POST /.oauth2/token and passes it in the Credential: header of the COPY request.
 *      The destination then uses that macaroon to pull the file.
 *
 * HOW: Discovery handler returns a static JSON document pointing at the token endpoint.
 *      Issuance handler:
 *        1. Verifies macaroon_secret is configured and client is authenticated.
 *        2. Reads and URL-decodes the request body (application/x-www-form-urlencoded).
 *        3. Parses grant_type / scope / expire_in fields.
 *        4. Maps WLCG storage.* scope items to activity + path caveats.
 *        5. Calls brix_macaroon_issue() to build the signed token.
 *        6. Returns JSON {token, expires_in, token_type} per XrdMacaroons convention.
 *
 * NOTE: this file holds the discovery handler and the shared front-gate/response
 *       helpers (mac_respond, mac_gate_and_read_body, mac_authorize,
 *       mac_make_identifier, mac_build_location).  The OAuth2 token handler lives
 *       in macaroon_endpoint_oauth2.c and the dCache macaroon-request handler in
 *       macaroon_endpoint_request.c; both reach these helpers through
 *       macaroon_endpoint_internal.h.
 */

#include "webdav.h"
#include "auth/token/macaroon.h"
#include "auth/token/macaroon_issue.h"
#include "core/compat/log_diag.h"
#include "core/http/http_body.h"
#include "core/compat/json_min.h"

#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "macaroon_endpoint_internal.h"

/* Helper: send a JSON body */
static ngx_int_t
send_json(ngx_http_request_t *r, ngx_int_t status,
          const char *json, size_t json_len)
{
    ngx_buf_t        *b;
    ngx_chain_t       out;
    u_char           *buf;
    ngx_table_elt_t  *cc;
    ngx_int_t         rc;

    buf = ngx_pnalloc(r->pool, json_len);
    if (buf == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_memcpy(buf, json, json_len);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    b->pos      = buf;
    b->last     = buf + json_len;
    b->memory   = 1;
    b->last_buf = 1;

    out.buf  = b;
    out.next = NULL;

    r->headers_out.status            = status;
    r->headers_out.content_length_n  = (off_t) json_len;
    r->headers_out.content_type.data = (u_char *) "application/json";
    r->headers_out.content_type.len  = sizeof("application/json") - 1;
    r->headers_out.content_type_len  = r->headers_out.content_type.len;

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc != NULL) {
        cc->hash = 1;
        ngx_str_set(&cc->key, "Cache-Control");
        ngx_str_set(&cc->value, "no-store");
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    return ngx_http_output_filter(r, &out);
}

/*
 * mac_respond — emit a JSON body and finalize request metrics.
 * WHY: every response path in both issuance handlers ends the same way;
 * folding the pair into one call keeps the handlers early-return flat.
 */
void
mac_respond(ngx_http_request_t *r, ngx_int_t status,
            const char *json, size_t json_len)
{
    ngx_int_t rc = send_json(r, status, json, json_len);

    webdav_metrics_finalize_request(r, rc);
}

/*
 * mac_gate_and_read_body — shared front gate for both issuance endpoints:
 * (1) a macaroon secret must be configured (else 404 not_configured),
 * (2) the caller must be authenticated (else 401 unauthorized),
 * (3) the request body must read into a contiguous buffer (else 400).
 * Sends the rejection itself; returns NGX_OK only when the handler may
 * proceed.  SECURITY: the check order is load-bearing — do not reorder.
 */
ngx_int_t
mac_gate_and_read_body(ngx_http_request_t *r,
                       ngx_http_brix_webdav_loc_conf_t *conf,
                       size_t max_body, u_char **body, size_t *body_len)
{
    ngx_http_brix_webdav_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    /* Require configured macaroon secret */
    if (conf->token_macaroon_secret.len == 0) {
        mac_respond(r, NGX_HTTP_NOT_FOUND,
                    J_NOT_CONFIGURED, sizeof(J_NOT_CONFIGURED) - 1);
        return NGX_ERROR;
    }

    /* Require authentication — anonymous requests cannot obtain tokens */
    if (ctx == NULL || !ctx->verified) {
        mac_respond(r, NGX_HTTP_UNAUTHORIZED,
                    J_UNAUTHORIZED, sizeof(J_UNAUTHORIZED) - 1);
        return NGX_ERROR;
    }

    /* Read body into a contiguous buffer (token POST bodies are small) */
    if (brix_http_body_read_all(r, max_body, body, body_len) != NGX_OK
        || *body == NULL || *body_len == 0)
    {
        mac_respond(r, NGX_HTTP_BAD_REQUEST,
                    J_INVALID_REQUEST, sizeof(J_INVALID_REQUEST) - 1);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * mac_authorize — authority bound: a bearer-token caller cannot obtain a
 * macaroon that exceeds their own scope.  GSI-cert callers (token_auth == 0)
 * carry full identity-level authority and are not bounded here.
 *
 * Conservative rule: if ANY write activity (UPLOAD/MANAGE/DELETE) is
 * requested, require write scope on the target path; otherwise require
 * read scope.  This prevents a zero- or read-only-scope token from
 * delegating write rights it does not hold.  Sends the 403 itself;
 * returns NGX_OK only when issuance is authorized.
 */
ngx_int_t
mac_authorize(ngx_http_request_t *r, const char *activities, const char *path)
{
    ngx_http_brix_webdav_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    int wants_write;
    int scope_ok;

    if (!ctx->token_auth) {
        return NGX_OK;
    }

    wants_write = (strstr(activities, "UPLOAD")  != NULL
                   || strstr(activities, "MANAGE") != NULL
                   || strstr(activities, "DELETE") != NULL);

    if (ctx->identity != NULL) {
        scope_ok = (brix_identity_check_token_scope(ctx->identity,
                                                     path, wants_write)
                    == NGX_OK);
    } else {
        scope_ok = wants_write
            ? brix_token_check_write(ctx->token_scopes,
                                      ctx->token_scope_count, path)
            : brix_token_check_read(ctx->token_scopes,
                                     ctx->token_scope_count, path);
    }

    if (scope_ok) {
        return NGX_OK;
    }
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "macaroon_endpoint: token scope insufficient for"
                  " activities \"%s\" on \"%s\" — issue denied",
                  activities, path);
    mac_respond(r, NGX_HTTP_FORBIDDEN,
                J_UNAUTHORIZED, sizeof(J_UNAUTHORIZED) - 1);
    return NGX_ERROR;
}

/*
 * mac_make_identifier — build the unique macaroon identifier
 * "v=1;t=<unix>;n=<16-hex-random>".  Falls back to a time/pointer-seeded
 * LCG when RAND_bytes fails (identifier uniqueness, not secrecy, is the
 * goal — the signature carries the security).
 */
void
mac_make_identifier(ngx_http_request_t *r, char *identifier, size_t idsz)
{
    u_char rand_bytes[8];
    time_t now = (time_t) ngx_time();

    if (RAND_bytes(rand_bytes, (int) sizeof(rand_bytes)) != 1) {
        /* Fallback: mix time and request pointer for pseudo-random */
        ngx_uint_t seed = (ngx_uint_t) now ^ (ngx_uint_t)(uintptr_t) r;
        size_t i;
        for (i = 0; i < sizeof(rand_bytes); i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            rand_bytes[i] = (u_char)(seed >> 56);
        }
    }
    snprintf(identifier, idsz - 1,
             "v=1;t=%ld;n=%02x%02x%02x%02x%02x%02x%02x%02x",
             (long) now,
             (unsigned) rand_bytes[0], (unsigned) rand_bytes[1],
             (unsigned) rand_bytes[2], (unsigned) rand_bytes[3],
             (unsigned) rand_bytes[4], (unsigned) rand_bytes[5],
             (unsigned) rand_bytes[6], (unsigned) rand_bytes[7]);
    identifier[idsz - 1] = '\0';
}

/*
 * mac_build_location — build the macaroon "location".  When an issuer is
 * configured (brix_webdav_token_issuer), stamp THAT as the location:
 * validation pins a macaroon's location to the configured issuer
 * (issuer-pinning, fail-closed — src/token/validate.c), so a Host-derived
 * location would make our own issued macaroon fail re-validation on this
 * very server.  The dCache endpoint additionally honours the configured
 * macaroon_location (allow_conf_location != 0).  Fall back to the request
 * scheme + Host header only when neither is pinned.
 */
void
mac_build_location(ngx_http_request_t *r,
                   ngx_http_brix_webdav_loc_conf_t *conf,
                   ngx_uint_t allow_conf_location,
                   char *location, size_t locsz)
{
    const char *scheme;
    u_char     *p;

    if (conf->token_issuer.len > 0 && conf->token_issuer.len < locsz) {
        ngx_memcpy(location, conf->token_issuer.data, conf->token_issuer.len);
        location[conf->token_issuer.len] = '\0';
        return;
    }
    if (allow_conf_location
        && conf->macaroon_location.len > 0
        && conf->macaroon_location.len < locsz)
    {
        ngx_memcpy(location, conf->macaroon_location.data,
                   conf->macaroon_location.len);
        location[conf->macaroon_location.len] = '\0';
        return;
    }

    scheme = (r->connection->ssl != NULL) ? "https" : "http";
    if (r->headers_in.host != NULL) {
        p = ngx_snprintf((u_char *) location, locsz - 1,
                         "%s://%V", scheme, &r->headers_in.host->value);
    } else {
        p = ngx_snprintf((u_char *) location, locsz - 1,
                         "%s://localhost", scheme);
    }
    *p = '\0';
}

/* Discovery handler */
ngx_int_t
webdav_handle_macaroon_discovery(ngx_http_request_t *r)
{
    u_char      json[512];
    u_char     *p;
    size_t      jlen;
    const char *scheme;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    scheme = (r->connection->ssl != NULL) ? "https" : "http";

    if (r->headers_in.host != NULL) {
        p = ngx_snprintf(json, sizeof(json) - 1,
            "{\"token_endpoint\":\"%s://%V/.oauth2/token\","
            "\"grant_types_supported\":[\"client_credentials\"],"
            "\"token_endpoint_auth_methods_supported\":[\"none\"]}",
            scheme, &r->headers_in.host->value);
    } else {
        p = ngx_snprintf(json, sizeof(json) - 1,
            "{\"token_endpoint\":\"%s://localhost/.oauth2/token\","
            "\"grant_types_supported\":[\"client_credentials\"],"
            "\"token_endpoint_auth_methods_supported\":[\"none\"]}",
            scheme);
    }
    *p   = '\0';
    jlen = (size_t)(p - json);

    return send_json(r, NGX_HTTP_OK, (const char *) json, jlen);
}
