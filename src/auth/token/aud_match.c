/*
 * aud_match.c — backend audience gate for bearer passthrough (see aud_match.h).
 *
 * WHAT: brix_token_backend_aud_ok() — does the client token's `aud` claim
 *       accept the backend, per the `brix_backend_token_audience_ok` list?
 *
 * WHY:  Phase-70 §5.2: the PASSTHROUGH zero-provisioning path forwards the
 *       client's own JWT to the origin, which is only correct when the token
 *       was actually audienced for that origin (or carries the WLCG
 *       any-endpoint wildcard). Without this gate the directive was parsed but
 *       never enforced — a silent fail-open (P90-70.9).
 *
 * HOW:  Split the compact JWS with xrdjwt_split(), b64url-decode the payload
 *       into a bounded stack buffer, then test membership with
 *       json_string_or_array_contains() so both the string and array `aud`
 *       forms are honoured exactly (same helper the front-door aud pin uses).
 *       No signature work — the front door validated the token before capture.
 *       Fail-closed on any decode failure once a gate is configured.
 */
#include "aud_match.h"
#include "b64url.h"
#include "json.h"

/* WLCG Common JWT Profile rules 104/105: a token audienced
 * 'https://wlcg.cern.ch/jwt/v1/any' is valid at ANY WLCG endpoint, so it is
 * forwardable regardless of the operator's backend allow-list. Mirrors the
 * front-door pin in validate.c. */
#define BRIX_WLCG_ANY_AUD  "https://wlcg.cern.ch/jwt/v1/any"

/* A JWT payload larger than this cannot be audience-checked and is treated as
 * not forwardable (fail-closed). Generous: real WLCG/OIDC payloads are <2k. */
#define BRIX_AUD_PAYLOAD_MAX  8192

int
brix_token_backend_aud_ok(const ngx_str_t *bearer,
    const ngx_array_t *ok_list, ngx_log_t *log)
{
    xrdjwt_seg        seg[3];
    u_char            payload[BRIX_AUD_PAYLOAD_MAX];
    ssize_t           plen;
    ngx_uint_t        i;
    const ngx_str_t  *ent;

    if (ok_list == NULL || ok_list->nelts == 0) {
        return 1;   /* no gate configured — passthrough unrestricted */
    }

    if (bearer == NULL || bearer->len == 0 || bearer->data == NULL) {
        return 0;
    }

    if (xrdjwt_split((const char *) bearer->data, bearer->len, seg) != 0) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
            "brix: backend audience gate: bearer is not a compact JWS - "
            "not forwarding");
        return 0;
    }

    plen = b64url_decode(seg[1].p, seg[1].n, payload, sizeof(payload));
    if (plen <= 0) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
            "brix: backend audience gate: token payload undecodable - "
            "not forwarding");
        return 0;
    }

    if (json_string_or_array_contains((const char *) payload, (size_t) plen,
            "aud", BRIX_WLCG_ANY_AUD)) {
        return 1;
    }

    ent = ok_list->elts;
    for (i = 0; i < ok_list->nelts; i++) {
        if (ent[i].len == 0 || ent[i].data == NULL) {
            continue;
        }
        if (json_string_or_array_contains((const char *) payload,
                (size_t) plen, "aud", (const char *) ent[i].data)) {
            return 1;
        }
    }

    /* Configured gate, no match (or no aud claim at all): fail closed. The
     * claim values are not logged — they can carry user-identifying URLs. */
    ngx_log_error(NGX_LOG_INFO, log, 0,
        "brix: backend audience gate: token aud does not accept this "
        "backend - not forwarding");
    return 0;
}
