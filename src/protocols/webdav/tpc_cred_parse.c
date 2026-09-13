/*
 * WHAT: Parse OAuth2/OIDC token response JSON to extract access_token.
 *
 *   - Delegates JSON parsing to shared Jansson-backed token helper
 *   - Copies parsed token into ngx_str_t buffer allocated in r->pool
 *
 * WHY: HTTP-TPC requires OAuth2/OIDC credentials for source server auth.
 *   - access_token obtained from OIDC provider's token endpoint via curl
 *   - Passed as Credential header to source WebDAV server
 *   - TPC_CRED_MAX_TOKEN_LEN prevents OOM on malformed responses
 *   - Defensive bounds checking against crafted long access_token values
 *
 * HOW: Call brix_oauth2_parse_access_token() into bounded stack buffer.
 *   - Allocate exact ngx_str_t payload from r->pool
 *   - Copy and NUL-terminate token
 *   - Log errors with parser's diagnostic string
 */

#include "tpc_cred_internal.h"
#include "auth/token/oauth2.h"

#include <string.h>

/*
 * Extract the raw token string from a JSON response.
 *
 * The JSON must contain a "access_token": "<token>" field.
 * Returns NGX_OK and fills `token_out` (allocated in r->pool) on success.
 */
ngx_int_t
tpc_cred_parse_token_response(ngx_http_request_t *r,
                              const char *json,
                              ngx_str_t *token_out)
{
    char token[TPC_CRED_MAX_TOKEN_LEN + 1];
    char err[256];
    size_t tok_len;

    if (brix_oauth2_parse_access_token(json, token, sizeof(token),
                                         err, sizeof(err)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred: %s", err);
        return NGX_ERROR;
    }

    tok_len = strlen(token);
    token_out->len = tok_len;
    token_out->data = ngx_pnalloc(r->pool, tok_len + 1);
    if (token_out->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred: pnalloc failed for token");
        return NGX_ERROR;
    }
    memcpy(token_out->data, token, tok_len);
    token_out->data[tok_len] = '\0';

    return NGX_OK;
}
