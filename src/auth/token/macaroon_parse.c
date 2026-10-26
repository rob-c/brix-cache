/*
 * Macaroon HMAC-SHA256 signature chain.
 * Packet framing, per-type chain updates, third-party caveat capture,
 * final signature verification.
 *
 * WHAT: Parses one macaroon binary as sequence of length-prefixed packets.
 *       Reconstructs HMAC-SHA256 chain (sig = HMAC(sig_prev, packet_data)) across:
 *         - identifier packets
 *         - location packets
 *         - cid (caveat identifier) packets
 *         - vid (verification identifier) packets
 *         - cl (optional third-party caveat location) packets
 *         - signature packets
 *       Captures third-party caveats (cid+vid+sig_before) into caller's tp_arr.
 *       Verifies final signature in constant time.
 *       Enforces fail-closed expiry.
 *       Finalizes extracted scopes into claims.
 *
 * WHY: Split out of macaroon.c (phase-79 file-size split).
 *      HMAC chain is integrity core of macaroon security model —
 *      any tampered or reordered caveat yields mismatched final signature.
 *      Keeping exact HMAC ordering in one file makes guarantee auditable:
 *        - identifier seeds the chain
 *        - cid/vid each fold in before capture
 *        - signature compared with CRYPTO_memcmp (constant-time)
 *      Separate from caveat interpretation (macaroon_caveats.c)
 *      and vid crypto (macaroon_crypto.c).
 *
 * HOW: Two-stage process:
 *        1. brix_macaroon_packet_len() reads 4-char hex length prefix
 *        2. macaroon_parse_core() loops packets under a strict grammar:
 *           - identifier: seeds sig = HMAC(key, id)
 *           - cid: folds and remains pending until the next packet determines
 *                  whether it is first-party or paired with an exact vid
 *           - vid: folds and records the third-party triple
 *           - signature: finalizes a pending first-party cid and compares
 *        3. Reject residue after the terminal signature, then check expiry and
 *           finalize intersected scopes
 */

#include "core/compat/log_event.h"
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

/* ---- Validate a text packet value before copying or interpreting it ----
 *
 * WHAT: Return NGX_OK for nonempty control-free bytes, else NGX_ERROR.
 * WHY: Embedded NUL/newline bytes make signed identifiers differ from their
 *      C-string claims and can hide packet-like content in diagnostics.
 * HOW: Scan the bounded value and reject C0 controls and DEL.
 */
static ngx_int_t
macaroon_text_value_valid(const u_char *value, size_t value_len)
{
    size_t index;

    if (value_len == 0) {
        return NGX_ERROR;
    }
    for (index = 0; index < value_len; index++) {
        if (value[index] < 0x20 || value[index] == 0x7f) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/* ---- Seed the chain from the one required identifier packet ----
 *
 * WHAT: Validate and record a unique nonempty identifier; return NGX_OK or
 *       NGX_ERROR without truncation.
 * WHY: Reseeding the chain with a duplicate identifier discards all earlier
 *      caveat integrity and lets later claims replace the authenticated subject.
 * HOW: Enforce grammar/bounds, compute HMAC(root key, identifier), and copy the
 *      exact identifier into the zero-terminated subject claim.
 */
static ngx_int_t
macaroon_packet_identifier(brix_macaroon_parse_state_t *state,
                           const u_char *data, size_t data_len)
{
    const u_char *identifier = data + 11;
    size_t identifier_len = data_len - 11;

    if (state->found_id || state->have_last_cid
        || identifier_len >= sizeof(state->claims->sub)
        || macaroon_text_value_valid(identifier, identifier_len) != NGX_OK) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
            "brix_macaroon: invalid or duplicate identifier packet");
        return NGX_ERROR;
    }
    if (HMAC(EVP_sha256(), state->key, state->key_len, identifier,
             identifier_len, state->sig, &state->sig_out_len) == NULL
        || state->sig_out_len != sizeof(state->sig)) {
        return NGX_ERROR;
    }
    ngx_memcpy(state->claims->sub, identifier, identifier_len);
    state->claims->sub[identifier_len] = '\0';
    state->found_id = 1;
    return NGX_OK;
}

/* ---- Capture the optional pre-identifier location packet ----
 *
 * WHAT: Record one bounded nonempty location and return NGX_OK, else error.
 * WHY: Duplicate or post-identifier metadata creates ambiguous issuer claims.
 * HOW: Require the pre-identifier grammar position, validate bytes, and copy
 *      exactly into the zero-terminated issuer claim.
 */
static ngx_int_t
macaroon_packet_location(brix_macaroon_parse_state_t *state,
                         const u_char *data, size_t data_len)
{
    const u_char *location = data + 9;
    size_t location_len = data_len - 9;

    if (state->found_location || state->found_id
        || location_len >= sizeof(state->claims->iss)
        || macaroon_text_value_valid(location, location_len) != NGX_OK) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
            "brix_macaroon: invalid or misplaced location packet");
        return NGX_ERROR;
    }
    ngx_memcpy(state->claims->iss, location, location_len);
    state->claims->iss[location_len] = '\0';
    state->found_location = 1;
    return NGX_OK;
}

/* ---- Commit a pending cid as a first-party caveat ----
 *
 * WHAT: Parse the pending cid when no vid followed it; return NGX_OK or error.
 * WHY: cid is ambiguous until the next packet: cid+vid is third-party, while a
 *      lone cid is first-party and must be enforced rather than pre-applied.
 * HOW: If pending, clear the marker and invoke the strict caveat classifier.
 */
static ngx_int_t
macaroon_finalize_pending_cid(brix_macaroon_parse_state_t *state)
{
    if (!state->have_last_cid) {
        return NGX_OK;
    }
    state->have_last_cid = 0;
    return macaroon_parse_first_party_caveat(state, state->last_cid,
                                              state->last_cid_len);
}

/* ---- Begin one pending caveat and extend the HMAC chain ----
 * WHAT: Validate one cid, finalize any prior first-party cid, and retain this
 *       cid for first/third-party classification; return NGX_OK or error.
 * WHY: Duplicate/truncated identifiers and reordered chain updates are unsafe.
 * HOW: Check grammar/bounds, HMAC the exact bytes, and save exact pending data.
 */
static ngx_int_t
macaroon_packet_cid(brix_macaroon_parse_state_t *state,
                    const u_char *data, size_t data_len)
{
    const u_char *caveat = data + 4;
    size_t caveat_len = data_len - 4;
    u_char next_sig[32];

    if (!state->found_id) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
                      "brix_macaroon: caveat before identifier");
        return NGX_ERROR;
    }
    if (caveat_len >= sizeof(state->last_cid)
        || macaroon_text_value_valid(caveat, caveat_len) != NGX_OK) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
            "brix_macaroon: invalid or oversized caveat identifier");
        return NGX_ERROR;
    }
    if (macaroon_finalize_pending_cid(state) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memcpy(state->sig_before_cid, state->sig, 32);
    if (HMAC(EVP_sha256(), state->sig, 32, caveat, caveat_len, next_sig,
             &state->sig_out_len) == NULL
        || state->sig_out_len != sizeof(next_sig)) {
        OPENSSL_cleanse(next_sig, sizeof(next_sig));
        return NGX_ERROR;
    }
    ngx_memcpy(state->sig, next_sig, 32);
    OPENSSL_cleanse(next_sig, sizeof(next_sig));

    state->last_cid_len = caveat_len;
    ngx_memcpy(state->last_cid, caveat, state->last_cid_len);
    state->last_cid[state->last_cid_len] = '\0';
    state->have_last_cid = 1;
    return NGX_OK;
}

/* ---- Capture one exact third-party caveat without truncation ----
 *
 * WHAT: Store pending cid, 48-byte vid, and pre-cid signature; return NGX_OK
 *       or NGX_ERROR for nested, excess, or misconfigured capture.
 * WHY: Dropping an excess discharge requirement or truncating encrypted key
 *      material can turn an unsatisfied condition into accepted authority.
 * HOW: Validate root capture state/capacity, reserve one slot, and copy exact
 *      bounded fields.
 */
static ngx_int_t
macaroon_record_third_party_caveat(brix_macaroon_parse_state_t *state,
                                   const u_char *vid_data, size_t vid_len)
{
    brix_macaroon_tp_t *tp;

    if (!state->have_last_cid || state->tp_arr == NULL || state->n_tp == NULL
        || state->max_tp <= 0 || *state->n_tp < 0
        || *state->n_tp >= state->max_tp
        || vid_len != BRIX_MACAROON_VID_LEN) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
            "brix_macaroon: nested, excess, or malformed third-party caveat");
        return NGX_ERROR;
    }

    tp = &state->tp_arr[(*state->n_tp)++];
    ngx_memcpy(tp->cid, state->last_cid, state->last_cid_len);
    tp->cid_len = state->last_cid_len;
    tp->vid_len = vid_len;
    ngx_memcpy(tp->vid, vid_data, tp->vid_len);
    ngx_memcpy(tp->sig_before, state->sig_before_cid, 32);
    return NGX_OK;
}

/* ---- Pair one verification identifier with its pending cid ----
 * WHAT: Fold and capture an exact 48-byte vid; return NGX_OK or error.
 * WHY: Orphan, nested, excess, and oversized vid records must fail closed.
 * HOW: Validate pending/root capacity, extend HMAC, capture, and clear pending.
 */
static ngx_int_t
macaroon_packet_vid(brix_macaroon_parse_state_t *state,
                    const u_char *data, size_t data_len)
{
    const u_char *vid_data = data + 4;
    size_t vid_len = data_len - 4;
    u_char next_sig[32];

    if (!state->have_last_cid || vid_len != BRIX_MACAROON_VID_LEN) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
            "brix_macaroon: orphan or malformed verification identifier");
        return NGX_ERROR;
    }
    if (state->tp_arr == NULL || state->n_tp == NULL
        || state->max_tp <= 0 || *state->n_tp < 0
        || *state->n_tp >= state->max_tp) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
            "brix_macaroon: nested or excess third-party caveat");
        return NGX_ERROR;
    }
    if (HMAC(EVP_sha256(), state->sig, 32, vid_data, vid_len, next_sig,
             &state->sig_out_len) == NULL
        || state->sig_out_len != sizeof(next_sig)) {
        OPENSSL_cleanse(next_sig, sizeof(next_sig));
        return NGX_ERROR;
    }
    ngx_memcpy(state->sig, next_sig, 32);
    OPENSSL_cleanse(next_sig, sizeof(next_sig));
    if (macaroon_record_third_party_caveat(state, vid_data, vid_len)
        != NGX_OK) {
        return NGX_ERROR;
    }
    state->have_last_cid = 0;
    state->caveat_location_allowed = 1;
    return NGX_OK;
}

/* ---- Validate the optional location attached to one third-party caveat ----
 * WHAT: Accept one bounded text `cl` packet immediately after its `vid`.
 * WHY: Version-one macaroons may carry informational caveat locations, but a
 *      free-standing or delayed packet would make its ownership ambiguous.
 * HOW: Require the one-packet grammar window, validate text and size, then
 *      consume the window without folding informational bytes into the HMAC.
 */
static ngx_int_t
macaroon_packet_caveat_location(brix_macaroon_parse_state_t *state,
                                const u_char *data, size_t data_len)
{
    const u_char *location = data + 3;
    size_t location_len = data_len - 3;

    if (!state->caveat_location_allowed
        || location_len >= BRIX_MACAROON_MAX_CL_LEN
        || macaroon_text_value_valid(location, location_len) != NGX_OK) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
            "brix_macaroon: invalid or misplaced caveat location packet");
        return NGX_ERROR;
    }
    state->caveat_location_allowed = 0;
    return NGX_OK;
}

/* ---- Verify the one exact terminal signature packet ----
 * WHAT: Verify a 32-byte HMAC in constant time; return NGX_OK or error.
 * WHY: Short, duplicate, or pre-identifier signatures cannot authenticate.
 * HOW: Finalize pending first-party cid, check exact size, and compare bytes.
 */
static ngx_int_t
macaroon_packet_signature(brix_macaroon_parse_state_t *state,
                          const u_char *data, size_t data_len)
{
    const u_char *provided_sig = data + 10;

    if (!state->found_id || state->found_sig || data_len != 10 + 32) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
            "brix_macaroon: malformed or duplicate signature packet");
        return NGX_ERROR;
    }
    if (macaroon_finalize_pending_cid(state) != NGX_OK) {
        return NGX_ERROR;
    }
    if (CRYPTO_memcmp(state->sig, provided_sig, 32) != 0) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
                      "brix_macaroon: signature mismatch");
        return NGX_ERROR;
    }
    state->found_sig = 1;
    return NGX_OK;
}

/* ---- Dispatch one recognized packet under the strict grammar ----
 * WHAT: Route a packet to its typed handler; reject unknown/post-signature data.
 * WHY: Ignored signed or unsigned packet types create semantic ambiguity.
 * HOW: Match exact field prefixes in grammar order and fail closed otherwise.
 */
static ngx_int_t
macaroon_dispatch_packet(brix_macaroon_parse_state_t *state,
                         const u_char *data, size_t data_len)
{
    if (state->found_sig) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
            "brix_macaroon: packet follows terminal signature");
        return NGX_ERROR;
    }
    if (data_len >= 3 && memcmp(data, "cl ", 3) == 0) {
        return macaroon_packet_caveat_location(state, data, data_len);
    }
    state->caveat_location_allowed = 0;
    if (data_len >= 11 && memcmp(data, "identifier ", 11) == 0) {
        return macaroon_packet_identifier(state, data, data_len);
    }
    if (data_len >= 9 && memcmp(data, "location ", 9) == 0) {
        return macaroon_packet_location(state, data, data_len);
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
    BRIX_LOG(NGX_LOG_WARN, state->log, 0,
        "brix_macaroon: unknown packet type");
    return NGX_ERROR;
}

/* ---- Enforce fail-closed root expiry and elapsed deadlines ----
 * WHAT: Return NGX_OK for a live credential, otherwise NGX_ERROR.
 * WHY: Root bearer credentials without a deadline remain useful forever.
 * HOW: Require explicit root expiry and reject every seen deadline at or before
 *      wall time, including epoch-zero and pre-epoch values.
 */
static ngx_int_t
macaroon_check_expiry(brix_macaroon_parse_state_t *state)
{
    time_t now = time(NULL);

    if (state->tp_arr != NULL && !state->before_seen) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
                      "brix_macaroon: rejected — no before: (expiry) caveat; "
                      "non-expiring macaroons are not accepted");
        return NGX_ERROR;
    }
    if (state->before_seen
        && (now == (time_t)-1 || state->claims->exp <= (int64_t)now)) {
        BRIX_LOG(NGX_LOG_WARN, state->log, 0,
                      "brix_macaroon: token expired at %L (now=%L)",
                      (long long)state->claims->exp, (long long)now);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- Finalize effective scopes and optional parse metadata ----
 *
 * WHAT: Materialize activity scopes, apply path restrictions, and copy
 *       caveat-presence metadata; return NGX_OK or NGX_ERROR on overflow.
 * WHY: Authorization consumers need one coherent, fully narrowed claims view,
 *      while discharge orchestration must distinguish no restriction from an
 *      activity intersection that intentionally grants nothing.
 * HOW: Parse the bounded scope string, apply every path caveat, then copy the
 *      validated metadata only after all narrowing succeeds.
 */
static ngx_int_t
macaroon_finalize_scopes(brix_macaroon_parse_state_t *state,
    brix_macaroon_parse_meta_t *meta)
{
    ngx_memcpy(state->claims->scope_raw, state->scope_buf, state->scope_off);
    state->claims->scope_raw[state->scope_off] = '\0';
    state->claims->scope_count = brix_token_parse_scopes(
        state->claims->scope_raw, state->claims->scopes,
        BRIX_MAX_TOKEN_SCOPES);

    if (state->n_path_caveats > 0) {
        if (macaroon_apply_path_caveats(state->log, state->claims,
                                        state->path_caveats,
                                        state->n_path_caveats) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    if (meta != NULL) {
        ngx_memzero(meta, sizeof(*meta));
        meta->activity_seen = state->activity_seen;
        meta->before_seen = state->before_seen;
        meta->n_path_caveats = state->n_path_caveats;
        if (state->n_path_caveats > 0) {
            ngx_memcpy(meta->path_caveats, state->path_caveats,
                (size_t)state->n_path_caveats
                * sizeof(state->path_caveats[0]));
        }
    }
    return NGX_OK;
}

/* ---- Initialize one isolated parse state from immutable inputs ----
 * WHAT: Zero working state and copy input references; no output is produced.
 * WHY: Zero signatures/flags must never survive from a prior parse.
 * HOW: Clear the structure then assign the explicitly carried dependencies.
 */
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

/*
 * WHAT: Return the packet content length after its optional text delimiter.
 * WHY: Signature packets contain raw HMAC bytes with no delimiter; a final
 *      0x0a is part of the signature and must reach constant-time verification.
 * HOW: 1. Preserve signature content. 2. Strip one newline from other packets.
 */
static ngx_int_t
macaroon_packet_content_len(const u_char *data, size_t data_len,
    size_t *content_len)
{
    if (data_len >= 10 && memcmp(data, "signature ", 10) == 0) {
        *content_len = data_len;
        return NGX_OK;
    }
    if (data_len == 0 || data[data_len - 1] != '\n') {
        return NGX_ERROR;
    }
    *content_len = data_len - 1;
    return NGX_OK;
}

/* WHAT: Validate required parse pointers and lengths. WHY: Grammar handlers
 * dereference every input. HOW: Reject any absent dependency or empty input. */
static ngx_int_t
macaroon_parse_input_valid(const macaroon_parse_input_t *in,
    const u_char *bin, size_t bin_len)
{
    if (in == NULL || bin == NULL || bin_len == 0 || in->log == NULL
        || in->key == NULL || in->key_len == 0 || in->claims == NULL) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* WHAT: Dispatch every complete packet and require a terminal signature.
 * WHY: Unknown, malformed, or trailing packets make authorization ambiguous.
 * HOW: Decode bounded frames, preserve raw signature bytes, and stop on error. */
static ngx_int_t
macaroon_parse_packets(brix_macaroon_parse_state_t *state,
    const u_char *bin, size_t bin_len)
{
    const u_char *p = bin;
    const u_char *end = bin + bin_len;

    while (p < end) {
        size_t remaining = (size_t)(end - p);
        int plen;
        const u_char *data;
        size_t raw_len, data_len;

        if (remaining < 4) {
            BRIX_LOG(NGX_LOG_WARN, state->log, 0,
                "brix_macaroon: trailing bytes after final packet");
            return NGX_ERROR;
        }
        plen = brix_macaroon_packet_len(p);
        if (plen < 4 || (size_t)plen > remaining) {
            BRIX_LOG(NGX_LOG_WARN, state->log, 0,
                "brix_macaroon: malformed packet length: %d", plen);
            return NGX_ERROR;
        }

        data = p + 4;
        raw_len = (size_t)(plen - 4);
        if (macaroon_packet_content_len(data, raw_len, &data_len) != NGX_OK) {
            BRIX_LOG(NGX_LOG_WARN, state->log, 0,
                "brix_macaroon: malformed packet delimiter");
            return NGX_ERROR;
        }
        if (macaroon_dispatch_packet(state, data, data_len) != NGX_OK) {
            return NGX_ERROR;
        }
        if (state->found_sig && (size_t)plen != remaining) {
            BRIX_LOG(NGX_LOG_WARN, state->log, 0,
                "brix_macaroon: signature packet is not terminal");
            return NGX_ERROR;
        }
        p += plen;
    }
    return NGX_OK;
}

/* WHAT: Strictly parse and authenticate one macaroon into claims.
 * WHY: Every signed condition and framing byte must be enforced without
 * truncation or reinterpretation. HOW: Parse packets, require identifier plus
 * terminal signature, enforce expiry, then publish intersected scopes. */
int
macaroon_parse_core(const macaroon_parse_input_t *in,
    const u_char *bin, size_t bin_len)
{
    brix_macaroon_parse_state_t state;

    if (macaroon_parse_input_valid(in, bin, bin_len) != NGX_OK) {
        return -1;
    }
    if (in->meta != NULL) {
        ngx_memzero(in->meta, sizeof(*in->meta));
    }
    macaroon_parse_state_init(&state, in);
    if (macaroon_parse_packets(&state, bin, bin_len) != NGX_OK) {
        return -1;
    }

    if (!state.found_id || !state.found_sig) {
        BRIX_LOG(NGX_LOG_WARN, state.log, 0,
            "brix_macaroon: identifier or terminal signature missing");
        return -1;
    }

    if (macaroon_check_expiry(&state) != NGX_OK) {
        return -1;
    }

    if (macaroon_finalize_scopes(&state, in->meta) != NGX_OK) {
        return -1;
    }
    return 0;
}
