/* Macaroon HMAC-SHA256 signature chain — packet framing, per-type chain updates, third-party caveat capture, and final signature verification.
 *
 * WHAT: Parses one macaroon binary as a sequence of length-prefixed packets, reconstructing the HMAC-SHA256 chain
 * (sig = HMAC(sig_prev, packet_data)) across identifier/location/cid/vid/signature packets, capturing third-party
 * caveats (cid+vid+sig_before) into the caller's tp_arr, verifying the final signature in constant time, enforcing
 * fail-closed expiry, and finalizing the extracted scopes into claims.
 *
 * WHY: Split out of macaroon.c (phase-79 file-size split). The HMAC chain is the integrity core of the macaroon
 * security model — any tampered or reordered caveat yields a mismatched final signature. Keeping the exact HMAC
 * ordering (identifier seeds the chain; cid/vid each fold in before capture; signature compared with CRYPTO_memcmp)
 * in one file makes that guarantee auditable, separate from caveat interpretation (macaroon_caveats.c) and vid
 * crypto (macaroon_crypto.c).
 *
 * HOW: brix_macaroon_packet_len() reads the 4-char hex length. macaroon_parse_core() loops packets, dispatching each
 * via macaroon_dispatch_packet() to the per-type handlers: identifier seeds sig=HMAC(key,id); cid saves sig_before_cid
 * then folds the caveat and hands first-party caveats to macaroon_parse_first_party_caveat(); vid folds and records the
 * third-party triple; signature compares. After the loop it checks found_sig/expiry and finalizes scopes. */

#include "token_internal.h"
#include "macaroon.h"
#include "macaroon_internal.h"
#include "macaroon_frame.h"   /* brix_macaroon_packet_len — carved pure framing (C-1) */
#include "b64url.h"
#include "scopes.h"
#include "core/compat/hex.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>   /* CRYPTO_memcmp — constant-time MAC compare */
#include <string.h>
#include <time.h>

/* brix_macaroon_packet_len — the 4-hex-char packet length decoder — now lives in
 * macaroon_frame.c so it can be fuzzed standalone (C-1 target 4); see
 * macaroon_frame.h. macaroon_internal.h still declares it (u_char signature),
 * call-compatible with the ngx-free unsigned char definition. */

static ngx_int_t
macaroon_packet_identifier(brix_macaroon_parse_state_t *state,
                           const u_char *data, size_t data_len)
{
    const u_char *identifier = data + 11;
    size_t identifier_len = data_len - 11;

    HMAC(EVP_sha256(), state->key, state->key_len, identifier,
         identifier_len, state->sig, &state->sig_out_len);
    ngx_memcpy(state->claims->sub, identifier,
               identifier_len < sizeof(state->claims->sub)
                   ? identifier_len : sizeof(state->claims->sub) - 1);
    state->found_id = 1;
    state->have_last_cid = 0;
    return NGX_OK;
}

static void
macaroon_packet_location(brix_macaroon_parse_state_t *state,
                         const u_char *data, size_t data_len)
{
    const u_char *location = data + 9;
    size_t location_len = data_len - 9;

    ngx_memcpy(state->claims->iss, location,
               location_len < sizeof(state->claims->iss)
                   ? location_len : sizeof(state->claims->iss) - 1);
}

static ngx_int_t
macaroon_packet_cid(brix_macaroon_parse_state_t *state,
                    const u_char *data, size_t data_len)
{
    const u_char *caveat = data + 4;
    size_t caveat_len = data_len - 4;
    u_char next_sig[32];

    if (!state->found_id) {
        ngx_log_error(NGX_LOG_WARN, state->log, 0,
                      "brix_macaroon: caveat before identifier");
        return NGX_ERROR;
    }

    ngx_memcpy(state->sig_before_cid, state->sig, 32);
    HMAC(EVP_sha256(), state->sig, 32, caveat, caveat_len, next_sig,
         &state->sig_out_len);
    ngx_memcpy(state->sig, next_sig, 32);

    state->last_cid_len = caveat_len < sizeof(state->last_cid)
                          ? caveat_len : sizeof(state->last_cid) - 1;
    ngx_memcpy(state->last_cid, caveat, state->last_cid_len);
    state->have_last_cid = 1;
    macaroon_parse_first_party_caveat(state, caveat, caveat_len);
    return NGX_OK;
}

static void
macaroon_record_third_party_caveat(brix_macaroon_parse_state_t *state,
                                   const u_char *vid_data, size_t vid_len)
{
    brix_macaroon_tp_t *tp;

    if (!state->have_last_cid || state->tp_arr == NULL || state->n_tp == NULL
        || *state->n_tp >= state->max_tp) {
        return;
    }

    tp = &state->tp_arr[(*state->n_tp)++];
    ngx_memcpy(tp->cid, state->last_cid, state->last_cid_len);
    tp->cid_len = state->last_cid_len;
    tp->vid_len = vid_len < sizeof(tp->vid) ? vid_len : sizeof(tp->vid) - 1;
    ngx_memcpy(tp->vid, vid_data, tp->vid_len);
    ngx_memcpy(tp->sig_before, state->sig_before_cid, 32);
}

static ngx_int_t
macaroon_packet_vid(brix_macaroon_parse_state_t *state,
                    const u_char *data, size_t data_len)
{
    const u_char *vid_data = data + 4;
    size_t vid_len = data_len - 4;
    u_char next_sig[32];

    HMAC(EVP_sha256(), state->sig, 32, vid_data, vid_len, next_sig,
         &state->sig_out_len);
    ngx_memcpy(state->sig, next_sig, 32);
    macaroon_record_third_party_caveat(state, vid_data, vid_len);
    state->have_last_cid = 0;
    return NGX_OK;
}

static ngx_int_t
macaroon_packet_signature(brix_macaroon_parse_state_t *state,
                          const u_char *data, size_t data_len)
{
    const u_char *provided_sig = data + 10;

    if (data_len < 10 + 32
        || CRYPTO_memcmp(state->sig, provided_sig, 32) != 0) {
        ngx_log_error(NGX_LOG_WARN, state->log, 0,
                      "brix_macaroon: signature mismatch");
        return NGX_ERROR;
    }
    state->found_sig = 1;
    return NGX_OK;
}

static ngx_int_t
macaroon_dispatch_packet(brix_macaroon_parse_state_t *state,
                         const u_char *data, size_t data_len)
{
    if (data_len >= 11 && memcmp(data, "identifier ", 11) == 0) {
        return macaroon_packet_identifier(state, data, data_len);
    }
    if (data_len >= 9 && memcmp(data, "location ", 9) == 0) {
        macaroon_packet_location(state, data, data_len);
        return NGX_OK;
    }
    if (data_len >= 4 && memcmp(data, "cid ", 4) == 0) {
        return macaroon_packet_cid(state, data, data_len);
    }
    if (data_len >= 4 && memcmp(data, "vid ", 4) == 0) {
        return macaroon_packet_vid(state, data, data_len);
    }
    if (data_len >= 10 && memcmp(data, "signature ", 10) == 0) {
        return macaroon_packet_signature(state, data, data_len);
    }
    return NGX_OK;
}

static ngx_int_t
macaroon_check_expiry(brix_macaroon_parse_state_t *state)
{
    time_t now = time(NULL);

    if (state->tp_arr != NULL && state->claims->exp <= 0) {
        ngx_log_error(NGX_LOG_WARN, state->log, 0,
                      "brix_macaroon: rejected — no before: (expiry) caveat; "
                      "non-expiring macaroons are not accepted");
        return NGX_ERROR;
    }
    if (state->claims->exp > 0 && now > (time_t)state->claims->exp) {
        ngx_log_error(NGX_LOG_WARN, state->log, 0,
                      "brix_macaroon: token expired at %L (now=%L)",
                      (long long)state->claims->exp, (long long)now);
        return NGX_ERROR;
    }
    return NGX_OK;
}

static void
macaroon_finalize_scopes(brix_macaroon_parse_state_t *state)
{
    ngx_memcpy(state->claims->scope_raw, state->scope_buf, state->scope_off);
    state->claims->scope_raw[state->scope_off] = '\0';
    state->claims->scope_count = brix_token_parse_scopes(
        state->claims->scope_raw, state->claims->scopes,
        BRIX_MAX_TOKEN_SCOPES);

    if (state->n_path_caveats > 0) {
        macaroon_apply_path_caveats(state->log, state->claims,
                                    state->path_caveats,
                                    state->n_path_caveats);
    }
}

static void
macaroon_parse_state_init(brix_macaroon_parse_state_t *state,
    const macaroon_parse_input_t *in)
{
    ngx_memzero(state, sizeof(*state));
    state->log = in->log;
    state->key = in->key;
    state->key_len = in->key_len;
    state->claims = in->claims;
    state->tp_arr = in->tp_arr;
    state->n_tp = in->n_tp;
    state->max_tp = in->max_tp;
}

/* WHAT: Parse one macaroon binary, reconstruct HMAC-SHA256 signature chain across all packets, verify final signature, and extract WLCG caveats into claims.
 * WHY: The macaroon security model requires each caveat to deterministically modify the HMAC chain — sig = HMAC(sig_prev, caveat_data). This ensures any tampered or reordered caveat produces a mismatched final signature. Extracting activity:/path:/before: caveats converts raw binary authorization into structured claims for access control decisions.
 * HOW: Initialize sig=HMAC(key, identifier), scope_buf="", path_caveats[], last_cid/sig_before_cid state; loop packets (p+4≤end): brix_macaroon_packet_len(p)→plen; data=p+4,dlen=plen-4; strip trailing newline if present; process packet types: "identifier " → HMAC(EVP_sha256,key,identifier)→sig, copy to claims->sub; "location " → copy to claims->iss; "cid " → save sig_before_cid, HMAC(sig,cid)→next_sig→sig, track last_cid for vid pairing; parse first-party caveats within cid data (activity:→scope mapping, before:→parse_iso8601→claims->exp min, path:→path_caveats array); "vid " → HMAC(sig,vid_data)→sig, record (cid+vid+sig_before) triple into tp_arr if available; "signature " → compare provided 32-byte sig against computed sig, reject mismatch; after loop: check found_sig and found_id, validate expiry (now>claims->exp), finalize scopes from scope_buf via brix_token_parse_scopes(), apply path caveats via macaroon_apply_path_caveats(); return 0 success or -1 failure. */
int
macaroon_parse_core(const macaroon_parse_input_t *in,
    const u_char *bin, size_t bin_len)
{
    brix_macaroon_parse_state_t state;
    ngx_log_t                  *log = in->log;
    const u_char *p, *end;

    macaroon_parse_state_init(&state, in);
    p   = bin;
    end = bin + bin_len;

    while (p + 4 <= end) {
        int     plen = brix_macaroon_packet_len(p);
        u_char *data;
        size_t  dlen;

        if (plen < 4 || p + plen > end) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_macaroon: malformed packet length: %d", plen);
            return -1;
        }

        data = (u_char *)(p + 4);
        dlen = (size_t)(plen - 4);

        /* Strip trailing newline if present */
        if (dlen > 0 && data[dlen - 1] == '\n') {
            dlen--;
        }

        if (macaroon_dispatch_packet(&state, data, dlen) != NGX_OK) {
            return -1;
        }

        p += plen;
    }

    if (!state.found_sig) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_macaroon: no valid signature found");
        return -1;
    }

    /*
     * Expiry handling (fail-closed).  A macaroon is a bearer credential: a root
     * with no before: caveat leaves claims->exp == 0 and would otherwise be valid
     * forever, so a single leak would never lapse.  We therefore REQUIRE an
     * expiry on the root/standalone macaroon (tp_arr != NULL identifies that
     * context; discharges are validated with tp_arr == NULL).  dCache/WLCG
     * macaroons always carry a before: caveat on the root, so this rejects only
     * malformed or deliberately-unbounded tokens.  Discharge macaroons may
     * legitimately omit before: — their lifetime is governed by the root and
     * intersected by the caller — so we only enforce "not already expired" for
     * them.  claims->exp is the earliest before: caveat seen in the packet loop
     * above (macaroons only narrow, never widen).
     */
    if (macaroon_check_expiry(&state) != NGX_OK) {
        return -1;
    }

    macaroon_finalize_scopes(&state);
    return 0;
}
