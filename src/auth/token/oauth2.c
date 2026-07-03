/*
 * oauth2.c - shared OAuth2/OIDC token response helpers.
 *
 * WHAT: Parses JSON-encoded OAuth2/OIDC access_token responses into a
 *       caller-provided buffer. Validates JSON structure, extracts the
 *       "access_token" string field, checks length against output capacity,
 *       and copies the token value with NUL-termination.
 *
 * WHY: OIDC token endpoints return JSON bodies containing access tokens.
 *      This helper provides a single entry point for extracting the token
 *      from the response without requiring callers to embed jansson parsing
 *      logic. Error messages are written into err buffer when provided,
 *      enabling upstream handlers (token/validate.c, s3/auth.c) to report
 *      specific parse failures.
 *
 * HOW: Validates out/out_sz non-empty and zeroes output first. Loads JSON
 *      via json_loads() with JSON_REJECT_DUPLICATES — rejects malformed JSON
 *      with error message from jerr.text. Retrieves "access_token" key via
 *      json_object_get() — verifies it is a string type, not null/object/number.
 *      Checks strlen(token) < out_sz to prevent overflow. Copies token via
 *      ngx_memcpy including NUL terminator. Decrements JSON root refcount.
 *      Returns NGX_OK on success, NGX_ERROR on any failure with err buffer populated.
 */

#include "oauth2.h"

#include <jansson.h>
#include <stdio.h>
#include <string.h>

ngx_int_t
brix_oauth2_parse_access_token(const char *json, char *out, size_t out_sz,
    char *err, size_t err_sz)
{
    json_error_t  jerr;
    json_t       *root;
    json_t       *tok;
    const char   *token;
    size_t        len;

    if (out == NULL || out_sz == 0) {
        return NGX_ERROR;
    }
    out[0] = '\0';

    root = json_loads(json ? json : "", JSON_REJECT_DUPLICATES, &jerr);
    if (root == NULL) {
        if (err != NULL && err_sz > 0) {
            snprintf(err, err_sz, "invalid token JSON: %s", jerr.text);
        }
        return NGX_ERROR;
    }

    tok = json_object_get(root, "access_token");
    if (!json_is_string(tok)) {
        if (err != NULL && err_sz > 0) {
            snprintf(err, err_sz, "no string \"access_token\" in token response");
        }
        json_decref(root);
        return NGX_ERROR;
    }

    token = json_string_value(tok);
    len = strlen(token);
    if (len >= out_sz) {
        if (err != NULL && err_sz > 0) {
            snprintf(err, err_sz, "access_token too long for output buffer");
        }
        json_decref(root);
        return NGX_ERROR;
    }

    ngx_memcpy(out, token, len + 1);
    json_decref(root);
    return NGX_OK;
}
