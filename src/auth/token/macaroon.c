/* Macaroon bundle validation — public entry points and third-party discharge orchestration.
 *
 * WHAT: Validates WLCG macaroon tokens (base64url-encoded binary bundles). brix_macaroon_validate_bundle() space-
 * tokenizes a bundle (root + discharges), base64url-decodes the root, drives the HMAC chain parse
 * (macaroon_parse_core, macaroon_parse.c) to extract claims and capture third-party caveats, then for each caveat
 * locates the matching discharge, decrypts its vid (macaroon_decrypt_vid, macaroon_crypto.c), validates the
 * discharge, and intersects its expiry/paths into the root claims. brix_token_is_macaroon() and
 * brix_macaroon_secret_parse() are the routing/key-material helpers.
 *
 * WHY: WLCG uses macaroon tokens for delegated, caveatable authorization; third-party caveats enable cross-service
 * delegation where a discharge macaroon proves the third party authorized access. This file owns the bundle-level
 * orchestration; the HMAC chain (macaroon_parse.c), caveat interpretation (macaroon_caveats.c), and vid crypto
 * (macaroon_crypto.c) were split out under the phase-79 file-size guard, sharing macaroon_internal.h.
 *
 * HOW: brix_token_is_macaroon() — no dots ⇒ macaroon. brix_macaroon_secret_parse() — hex→binary via nibble pairing.
 * brix_macaroon_validate_bundle() — tokenize; decode+parse root with tp_arr capture; for each tp: find discharge by
 * cid==identifier (macaroon_candidate_matches_cid uses brix_macaroon_packet_len), decrypt vid, parse discharge with
 * recovered key, intersect claims. brix_macaroon_validate() is the single-root wrapper. */

#include "core/compat/log_event.h"
#include "core/types/tunables.h"
#include "token_internal.h"
#include "macaroon.h"
#include "macaroon_internal.h"
#include "b64url.h"
#include "scopes.h"
#include "core/compat/hex.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>   /* OPENSSL_cleanse — wipe recovered discharge key */
#include <string.h>
#include <time.h>

/* Use global constant for base64 decode max size */
#define MACAROON_MAX_BIN  BRIX_B64_DECODE_MAX

/* Max number of discharge Macaroons accepted in a single bundle */
#define BRIX_MACAROON_MAX_DISCHARGES   8
/* Max third-party caveats tracked in one Macaroon (cid+vid pairs) */
#define BRIX_MACAROON_MAX_TP_CAVEATS   8

int
brix_token_is_macaroon(const char *token, size_t token_len)
/* WHAT: Quick heuristic to distinguish macaroon tokens from JWT tokens.
 * WHY: The token layer needs to route authentication logic — JWTs use signature/algorithm verification while
 * macaroons use HMAC chain reconstruction. This check avoids expensive parsing of non-macaroon tokens.
 * HOW: Reject tokens shorter than 4 characters (both JWT and macaroon require minimum length); if memchr finds a '.' character,
 * classify as JWT (return 0); otherwise classify as macaroon (return 1). Note: this is heuristic only — base64url-encoded content could theoretically contain dots. */
{
    /* JWTs always have dots. Macaroons in base64url do not. */
    if (token_len < 4) return 0;
    if (memchr(token, '.', token_len) == NULL) return 1;
    return 0;
}

ssize_t
brix_macaroon_secret_parse(const char *hex, size_t hex_len,
    u_char *bin, size_t bin_max)
/* WHAT: Convert a hex-encoded macaroon root secret string into binary bytes for HMAC computation.
 * WHY: Macaroon secrets are stored as hex strings (e.g., in config files or environment variables); the HMAC chain
 * requires raw binary key material. This helper performs safe hex-to-binary conversion with bounds checking.
 * HOW: Validate hex_len is even and hex_len/2 ≤ bin_max; iterate each nibble pair calling brix_hex_from_char() on positions i*2 and i*2+1,
 * reject if any nibble invalid (<0); combine nibbles via (v1<<4)|v2 into bin[i]; return hex_len/2 or -1 on failure. */
{
    size_t i;
    int    v1, v2;

    if (hex_len % 2 != 0 || hex_len / 2 > bin_max) return -1;

    for (i = 0; i < hex_len / 2; i++) {
        v1 = brix_hex_from_char((unsigned char) hex[i * 2]);
        v2 = brix_hex_from_char((unsigned char) hex[i * 2 + 1]);
        if (v1 < 0 || v2 < 0) return -1;
        bin[i] = (u_char) ((v1 << 4) | v2);
    }

    return (ssize_t) (hex_len / 2);
}

static int
macaroon_bundle_tokenize(const char *token, size_t token_len,
                         const char **tokens, size_t *token_lens,
                         int *n_tokens)
{
    const char *cursor = token;
    const char *end = token + token_len;
    const char *token_start = cursor;

    *n_tokens = 0;
    for (;;) {
        if (cursor >= end || *cursor == ' ') {
            if (cursor > token_start) {
                if (*n_tokens > BRIX_MACAROON_MAX_DISCHARGES) {
                    return -1;
                }
                tokens[*n_tokens] = token_start;
                token_lens[*n_tokens] = (size_t)(cursor - token_start);
                (*n_tokens)++;
            }
            if (cursor >= end) {
                break;
            }
            token_start = cursor + 1;
        }
        cursor++;
    }
    return (*n_tokens > 0) ? 0 : -1;
}

/* WHAT: Test whether a decoded candidate's first identifier equals one cid.
 * WHY: Bundle validation must select the intended discharge before decrypting
 * its key, while the strict parser later validates the candidate completely.
 * HOW: Walk bounded packets and compare the first identifier byte-for-byte. */
static int
macaroon_candidate_matches_cid(const u_char *candidate, ssize_t candidate_len,
                               brix_macaroon_tp_t *tp)
{
    const u_char *packet = candidate;
    const u_char *end = candidate + candidate_len;

    while (packet + 4 <= end) {
        int packet_len = brix_macaroon_packet_len(packet);
        u_char *data;
        size_t data_len;

        if (packet_len < 4 || packet + packet_len > end) {
            break;
        }
        data = (u_char *)(packet + 4);
        data_len = (size_t)(packet_len - 4);
        if (data_len > 0 && data[data_len - 1] == '\n') {
            data_len--;
        }

        if (data_len >= 11 && memcmp(data, "identifier ", 11) == 0) {
            const u_char *identifier = data + 11;
            size_t identifier_len = data_len - 11;
            return (identifier_len == tp->cid_len
                    && memcmp(identifier, tp->cid, identifier_len) == 0);
        }
        packet += packet_len;
    }
    return 0;
}

/*
 * WHAT: A parsed space-separated macaroon bundle — parallel arrays of token
 *       pointers/lengths (tokens[0] = root, tokens[1..] = discharges) and the
 *       count.
 * WHY:  macaroon_find_discharge, macaroon_validate_one_discharge, and
 *       macaroon_validate_discharges all threaded tokens/token_lens/n_tokens as
 *       three separate parameters (6/7/7 total). Grouping them into one
 *       file-local descriptor keeps each helper ≤5 params; the discharge search
 *       walks the identical token set in the identical order, so which
 *       discharge matches which cid is unchanged.
 * HOW:  tokens[i]/token_lens[i] describe the i-th base64url token; index 0 is
 *       the root macaroon, indices 1..n_tokens-1 are candidate discharges;
 *       used_mask ensures each supplied discharge satisfies exactly one caveat.
 */
typedef struct {
    const char  **tokens;
    size_t       *token_lens;
    int           n_tokens;
    unsigned int  used_mask;
} macaroon_bundle_t;

/* WHAT: Decode the next unused discharge whose identifier matches one cid.
 * WHY: Duplicate identifiers require trying each cryptographic candidate;
 * selecting or consuming the first textual match makes bundle order decisive.
 * HOW: Resume at `token_index`, skip used/invalid/nonmatching entries, copy the
 * next exact candidate, and return its index without changing `used_mask`. */
static ssize_t
macaroon_find_discharge(macaroon_bundle_t *bundle,
                        brix_macaroon_tp_t *tp, u_char *discharge_bin,
                        size_t discharge_cap, int *token_index)
{
    int candidate_index;

    for (candidate_index = *token_index;
         candidate_index < bundle->n_tokens; candidate_index++) {
        ssize_t candidate_len;

        if ((bundle->used_mask & (1U << candidate_index)) != 0) {
            continue;
        }
        candidate_len = b64url_decode(bundle->tokens[candidate_index],
                                      bundle->token_lens[candidate_index],
                                      discharge_bin, discharge_cap);
        if (candidate_len < 4) {
            continue;
        }
        if (macaroon_candidate_matches_cid(discharge_bin, candidate_len, tp)) {
            *token_index = candidate_index;
            return candidate_len;
        }
    }
    return -1;
}

/* WHAT: Attenuate root expiry, permissions, and paths with one discharge.
 * WHY: A discharge proves an additional restriction and may never widen the
 * parent authority or turn an empty activity intersection into no restriction.
 * HOW: Take the earliest expiry, intersect explicit activity scopes, otherwise
 * apply every validated path restriction cumulatively. */
static int
macaroon_intersect_discharge_claims(ngx_log_t *log,
                                    brix_token_claims_t *claims,
                                    brix_token_claims_t *d_claims,
                                    brix_macaroon_parse_meta_t *d_meta)
{
    if (d_meta->before_seen
        && (claims->exp == 0 || d_claims->exp < claims->exp)) {
        claims->exp = d_claims->exp;
    }

    if (d_meta->activity_seen) {
        return macaroon_intersect_claim_scopes(log, claims, d_claims) == NGX_OK
               ? 0 : -1;
    }
    if (d_meta->n_path_caveats > 0
        && macaroon_apply_path_caveats(log, claims, d_meta->path_caveats,
                                       d_meta->n_path_caveats) != NGX_OK) {
        return -1;
    }
    return 0;
}

typedef struct {
    brix_token_claims_t       claims;
    brix_macaroon_parse_meta_t meta;
} macaroon_discharge_result_t;

/* WHAT: Authenticate one decoded discharge with its recovered caveat key.
 * WHY: Candidate selection may only consume a same-cid token after its HMAC
 *      chain and every signed restriction have passed strict parsing.
 * HOW: Clear isolated outputs, parse without nested capture, and return zero
 *      only for a completely valid candidate.
 */
static int
macaroon_parse_discharge_candidate(ngx_log_t *log, const u_char *binary,
    size_t binary_len, const u_char key[32],
    macaroon_discharge_result_t *result)
{
    macaroon_parse_input_t input;

    ngx_memzero(result, sizeof(*result));
    ngx_memzero(&input, sizeof(input));
    input.log = log;
    input.key = key;
    input.key_len = 32;
    input.claims = &result->claims;
    input.meta = &result->meta;
    return macaroon_parse_core(&input, binary, binary_len);
}

/* WHAT: Locate, decrypt, strictly validate, and apply one discharge macaroon.
 * WHY: Every captured third-party caveat must have one independently valid,
 * single-use discharge before its restrictions can affect root claims.
 * HOW: Recover the exact key, try every unused same-cid candidate, consume only
 * the first fully authenticated one, cleanse the key, and intersect claims. */
static int
macaroon_validate_one_discharge(ngx_log_t *log,
                                macaroon_bundle_t *bundle,
                                brix_macaroon_tp_t *tp,
                                brix_token_claims_t *claims, int caveat_index)
{
    u_char d_bin[MACAROON_MAX_BIN];
    ssize_t d_bin_len;
    u_char d_key[32];
    macaroon_discharge_result_t result;
    int token_index = 1;

    if (macaroon_decrypt_vid(tp->vid, tp->vid_len, tp->sig_before, d_key)
        != 0) {
        BRIX_LOG(NGX_LOG_WARN, log, 0,
            "brix_macaroon: cannot decrypt vid for caveat #%d "
            "(unsupported vid format?)", caveat_index);
        OPENSSL_cleanse(d_key, sizeof(d_key));
        return -1;
    }

    while ((d_bin_len = macaroon_find_discharge(bundle, tp, d_bin,
             sizeof(d_bin), &token_index)) >= 0) {
        if (macaroon_parse_discharge_candidate(log, d_bin,
                (size_t)d_bin_len, d_key, &result) == 0) {
            bundle->used_mask |= 1U << token_index;
            OPENSSL_cleanse(d_key, sizeof(d_key));
            BRIX_LOG(NGX_LOG_DEBUG, log, 0,
                "brix_macaroon: discharge #%d valid sub=\"%s\" scope=\"%s\"",
                caveat_index, result.claims.sub, result.claims.scope_raw);
            return macaroon_intersect_discharge_claims(log, claims,
                &result.claims, &result.meta);
        }
        token_index++;
    }
    OPENSSL_cleanse(d_key, sizeof(d_key));
    BRIX_LOG(NGX_LOG_WARN, log, 0,
        "brix_macaroon: no valid discharge Macaroon provided for "
        "third-party caveat #%d", caveat_index);
    return -1;
}

/* WHAT: Validate a one-to-one set of discharges for all root caveats.
 * WHY: Missing, extra, nested, or reused discharge requirements must fail
 * closed rather than leaving any signed condition unenforced.
 * HOW: Require equal counts and consume exactly one unused token per caveat. */
static int
macaroon_validate_discharges(ngx_log_t *log, macaroon_bundle_t *bundle,
                             brix_macaroon_tp_t *tp_arr, int n_tp,
                             brix_token_claims_t *claims)
{
    int caveat_index;

    if (bundle->n_tokens != n_tp + 1) {
        BRIX_LOG(NGX_LOG_WARN, log, 0,
            "brix_macaroon: root has %d third-party caveat(s), "
            "bundle carries %d discharge Macaroon(s)", n_tp,
            bundle->n_tokens - 1);
        return -1;
    }
    if (n_tp == 0) {
        return 0;
    }

    for (caveat_index = 0; caveat_index < n_tp; caveat_index++) {
        if (macaroon_validate_one_discharge(log, bundle,
                                            &tp_arr[caveat_index], claims,
                                            caveat_index) != 0) {
            return -1;
        }
    }
    return 0;
}

/*
 * brix_macaroon_validate_bundle — validate a space-separated Macaroon bundle.
 *
 * Accepts: "<root_macaroon_b64url> [<discharge_b64url> ...]"
 *
 * For each third-party caveat (cid+vid pair) in the root Macaroon:
 *   1. Find the discharge Macaroon whose identifier == cid.
 *   2. Decrypt the vid with AES-256-CBC(key=sig_before_cid, IV=vid[0..15])
 *      to recover the 32-byte discharge Macaroon root key.
 *   3. Validate the discharge Macaroon with that key.
 *   4. Intersect discharge claims (path restrictions, expiry) with root claims.
 *
 * Returns 0 on success, -1 on any validation failure.
 */
int
brix_macaroon_validate_bundle(ngx_log_t *log,
    const char *token, size_t token_len,
    const u_char *root_key, size_t root_key_len,
    brix_token_claims_t *claims)
/* WHAT: Validate a space-separated macaroon bundle containing one root macaroon and zero or more discharge macaroons.
 * WHY: WLCG third-party caveats require the client to present corresponding discharge macaroons — each discharge proves
 * that the third party authorized access for this specific request. Bundle validation ensures all discharges are valid,
 * decryptable, and their scope/expiry constraints intersect correctly with root claims.
 * HOW: Space-tokenize bundle into tokens[]/tlens[], base64url-decode root token → root_bin; zero-initialize claims and tp_arr;
 * call macaroon_parse_core(log,root_bin,root_key,claims,tp_arr,&n_tp,max_tp) to reconstruct HMAC chain, extract caveats, record third-party (cid+vid);
 * if n_tp>0: for each tp entry search discharge tokens[1..] for identifier matching tp->cid; b64url-decode matched discharge → d_bin;
 * macaroon_decrypt_vid(tp->vid,tp->vid_len,tp->sig_before,d_key) to recover 32-byte discharge root key via AES-256-CBC;
 * macaroon_parse_core(log,d_bin,d_key,32,&d_claims,NULL,NULL,0) to validate discharge (depth=1, no nested discharges); OPENSSL_cleanse d_key;
 * intersect discharge expiry (earliest wins) and scope paths as additional path: caveats via macaroon_apply_path_caveats; return 0 success or -1 failure. */
{
    const char          *tokens[BRIX_MACAROON_MAX_DISCHARGES + 1];
    size_t               tlens[BRIX_MACAROON_MAX_DISCHARGES + 1];
    int                  n_tokens    = 0;
    u_char               root_bin[MACAROON_MAX_BIN];
    ssize_t              root_bin_len;
    brix_macaroon_tp_t tp_arr[BRIX_MACAROON_MAX_TP_CAVEATS];
    int                  n_tp = 0;
    macaroon_parse_input_t root_in;
    macaroon_bundle_t      bundle;

    ngx_memzero(claims, sizeof(*claims));
    ngx_memzero(tp_arr, sizeof(tp_arr));

    if (macaroon_bundle_tokenize(token, token_len, tokens, tlens, &n_tokens)
        != 0) {
        BRIX_LOG(NGX_LOG_WARN, log, 0,
                      "brix_macaroon: empty token bundle");
        return -1;
    }

    /* Decode and validate the root Macaroon, collecting third-party caveats */
    root_bin_len = b64url_decode(tokens[0], tlens[0],
                                 root_bin, sizeof(root_bin));
    if (root_bin_len < 0) {
        BRIX_LOG(NGX_LOG_WARN, log, 0,
                      "brix_macaroon: root token base64url decode failed");
        return -1;
    }

    ngx_memzero(&root_in, sizeof(root_in));
    root_in.log     = log;
    root_in.key     = root_key;
    root_in.key_len = root_key_len;
    root_in.claims  = claims;
    root_in.tp_arr  = tp_arr;
    root_in.n_tp    = &n_tp;
    root_in.max_tp  = BRIX_MACAROON_MAX_TP_CAVEATS;

    if (macaroon_parse_core(&root_in, root_bin, (size_t)root_bin_len) != 0) {
        return -1;
    }

    bundle.tokens     = tokens;
    bundle.token_lens = tlens;
    bundle.n_tokens   = n_tokens;
    bundle.used_mask  = 0;

    if (macaroon_validate_discharges(log, &bundle, tp_arr, n_tp, claims) != 0) {
        return -1;
        }

    BRIX_LOG(NGX_LOG_INFO, log, 0,
                  "brix_macaroon: valid Macaroon bundle sub=\"%s\" "
                  "iss=\"%s\" scope=\"%s\" exp=%L "
                  "(third-party: %d, discharges: %d)",
                  claims->sub, claims->iss, claims->scope_raw,
                  (long long)claims->exp, n_tp, n_tokens - 1);

    return 0;
}

int
brix_macaroon_validate(ngx_log_t *log,
    const char *token, size_t token_len,
    const u_char *root_key, size_t root_key_len,
    brix_token_claims_t *claims)
/* WHAT: Thin wrapper — validate a single-root macaroon (no discharges required).
 * WHY: Provides the simple-entry-point for callers who only have a root macaroon without third-party caveats.
 * Internally delegates to validate_bundle which handles both single-root and multi-discharge cases uniformly.
 * HOW: Pass all arguments directly to brix_macaroon_validate_bundle() — identical behavior, no local logic. */
{
    return brix_macaroon_validate_bundle(log, token, token_len,
                                           root_key, root_key_len, claims);
}
