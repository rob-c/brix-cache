#ifndef BRIX_AUTH_TOKEN_AUD_MATCH_H
#define BRIX_AUTH_TOKEN_AUD_MATCH_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * Backend audience gate for phase-70 bearer passthrough (§5.2 / P90-70.9).
 *
 * Decide whether a client bearer token's `aud` claim accepts the backend the
 * gateway is about to present it to, per the operator's
 * `brix_backend_token_audience_ok` allow-list. A token minted for THIS gateway
 * must not be replayed verbatim to an origin whose audience it does not name —
 * the origin would (rightly) reject it, and forwarding it at all widens the
 * token's blast radius.
 *
 * Returns 1 (forwardable) when:
 *   - `ok_list` is NULL or empty — no gate configured (back-compat: verbatim
 *     passthrough remains unrestricted until the operator opts in), or
 *   - the token's `aud` (string or RFC 7519 §4.1.3 array form) contains the
 *     WLCG any-endpoint wildcard `https://wlcg.cern.ch/jwt/v1/any`, or
 *   - the token's `aud` contains any entry of `ok_list`.
 *
 * Returns 0 (do not forward) otherwise — including a malformed/undecodable
 * token or a token with no `aud` claim when a gate IS configured (fail-closed).
 *
 * The check is purely syntactic: signature/expiry validation happened at the
 * front door before the bytes were captured. `bearer` is the raw compact JWS
 * text; it is never logged. Entries of `ok_list` are conf-owned ngx_str_t
 * (NUL-terminated).
 */
int brix_token_backend_aud_ok(const ngx_str_t *bearer,
    const ngx_array_t *ok_list, ngx_log_t *log);

#endif /* BRIX_AUTH_TOKEN_AUD_MATCH_H */
