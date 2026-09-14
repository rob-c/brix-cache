/*
 * token_peek.c — the UNVERIFIED claim readers.
 *
 * WHAT: brix_token_peek_iss() and brix_token_peek_exp() read one claim each out
 * of a compact JWS payload WITHOUT checking the signature.
 *
 * WHY: both are needed before, or entirely outside, verification. peek_iss runs
 * first by necessity — the registry has to pick an issuer, and thus a key set,
 * before anything about the token can be trusted; the claim is re-derived from
 * verified claims afterwards. peek_exp runs where a signature check would be
 * meaningless: the exchange cache reads the lifetime a token it just minted
 * declares about ITSELF so an entry never outlives its credential, and the TPC
 * outbound renewal leg reads the same claim to decide when to mint another.
 * Neither authorises anything.
 *
 * They live in their own translation unit because they are the only token
 * functions whose entire dependency set is xrdjwt_split + b64url_decode +
 * json_get_*. Keeping them here means a caller that wants nothing but the
 * declared lifetime -- exchange_cache.c, and its C unit test -- links three
 * small objects instead of dragging in the issuer registry, the signature
 * pipeline, the scope parser and the subject mapfile. Before this split the
 * exchange_cache unit could not be linked at all.
 *
 * HOW: split the compact JWS, base64url-decode segment 1, read the one claim.
 * Every failure -- not a compact JWS, an undecodable payload, a missing or
 * non-positive claim -- returns -1 with the out parameter already cleared, so a
 * caller that ignores the return value still cannot read a stale value.
 */

#include "core/types/tunables.h"
#include <ngx_config.h>
#include <ngx_core.h>

#include "token.h"
#include "b64url.h"
#include "json.h"

/* brix_token_peek_iss — read the "iss" claim WITHOUT trusting the signature
 * (xrdjwt_split + b64url_decode + json_get_string): the registry must pick an
 * issuer, and thus its verification keys, before it can trust anything, so this
 * read is explicitly untrusted and re-derived from verified claims afterwards. */
int
brix_token_peek_iss(const char *token, size_t token_len,
    char *out, size_t outsz)
{
    xrdjwt_seg  seg[3];
    u_char      pay[BRIX_BEARER_TOKEN_MAX];
    ssize_t     n;

    out[0] = '\0';

    if (xrdjwt_split(token, token_len, seg) != 0) {
        return -1;                              /* not a compact JWS */
    }
    n = b64url_decode(seg[1].p, seg[1].n, pay, sizeof(pay) - 1);
    if (n < 0) {
        return -1;
    }
    pay[n] = '\0';
    if (json_get_string((char *) pay, (size_t) n, "iss", out, outsz) < 0) {
        return -1;
    }
    return 0;
}

/* brix_token_peek_exp — read the "exp" claim WITHOUT trusting the signature.
 * Promoted out of exchange_cache.c (where it was tx_cache_minted_exp) when TPC
 * outbound renewal became a second caller: both need the lifetime a token
 * declares about ITSELF, and neither authorises anything on it — the cache uses
 * it to avoid outliving the credential, the renewal leg to decide when to mint
 * another. A signature check would be meaningless here: for the cache the token
 * was just minted by the issuer we asked, and for renewal it is a credential
 * this server already presented and the source already validated. */
int
brix_token_peek_exp(const char *token, size_t token_len, time_t *out)
{
    xrdjwt_seg  seg[3];
    u_char      payload[BRIX_B64_DECODE_MAX];
    ssize_t     plen;
    int64_t     exp = 0;

    *out = 0;

    if (xrdjwt_split(token, token_len, seg) != 0) {
        return -1;                              /* not a compact JWS */
    }
    plen = b64url_decode(seg[1].p, seg[1].n, payload, sizeof(payload));
    if (plen <= 0) {
        return -1;
    }
    if (json_get_int64((const char *) payload, (size_t) plen, "exp", &exp) != 0
        || exp <= 0)
    {
        return -1;
    }

    *out = (time_t) exp;
    return 0;
}
