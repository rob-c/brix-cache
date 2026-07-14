#pragma once

/* Internal descriptors and cross-file entry points shared by the macaroon
 * validation split (macaroon.c / macaroon_parse.c / macaroon_caveats.c /
 * macaroon_crypto.c).
 *
 * WHAT: Declares the file-local structs threaded through one macaroon parse
 * (the third-party-caveat capture record, the parse working state, and the
 * invariant parse inputs) plus the five functions that cross a translation-unit
 * boundary after the phase-79 file-size split: the packet-length helper, the
 * HMAC chain parser, the path-caveat intersection, the first-party caveat
 * classifier, and the AES-256-CBC vid decrypt.
 *
 * WHY: macaroon.c exceeded the ~500-line file-size guard, so it was carved into
 * four cohesive units. The HMAC/packet machinery (macaroon_parse.c), the
 * caveat/scope narrowing (macaroon_caveats.c), and the vid crypto
 * (macaroon_crypto.c) each call — or are called by — the others. Grouping the
 * shared structs and the crossing entry points here keeps every definition in
 * exactly one place while preserving the identical bytes, HMAC ordering, and
 * caveat semantics of the original single-file implementation.
 *
 * HOW: Requires token_internal.h (brix_token_claims_t / brix_token_scope_t,
 * ngx types, u_char) and scopes.h (BRIX_SCOPE_PATH_MAX, brix_token_parse_scopes)
 * before inclusion. brix_macaroon_tp_t records one third-party caveat captured
 * during the root parse; brix_macaroon_parse_state_t is the per-parse working
 * set; macaroon_parse_input_t bundles the invariant parse inputs (tp_arr != NULL
 * marks the root/standalone parse). */

#include "token_internal.h"
#include "scopes.h"

/* Discharge Macaroon support (Feature 8b) — per-caveat identifier/vid bounds.
 * These size the fixed capture buffers in both brix_macaroon_tp_t and
 * brix_macaroon_parse_state_t, so they live with the struct definitions. */
#define BRIX_MACAROON_MAX_CID_LEN      512
#define BRIX_MACAROON_MAX_VID_LEN      256

/*
 * A third-party caveat (cid + vid pair) captured during root Macaroon parsing.
 *
 * sig_before is the HMAC sig value immediately before HMAC(sig, cid) was
 * computed.  At Macaroon creation time the discharge key was encrypted as:
 *   vid = [16-byte IV] || AES-256-CBC-encrypt(key=sig_before, IV, discharge_key)
 * so sig_before is the AES decryption key needed to recover the discharge key.
 */
typedef struct {
    u_char  cid[BRIX_MACAROON_MAX_CID_LEN];
    size_t  cid_len;
    u_char  vid[BRIX_MACAROON_MAX_VID_LEN];  /* raw binary — NOT base64 */
    size_t  vid_len;
    u_char  sig_before[32]; /* HMAC sig before the cid update — AES-256 key */
} brix_macaroon_tp_t;

typedef struct {
    ngx_log_t            *log;
    const u_char         *key;
    size_t                key_len;
    brix_token_claims_t  *claims;
    brix_macaroon_tp_t   *tp_arr;
    int                  *n_tp;
    int                   max_tp;
    u_char                sig[32];
    unsigned int          sig_out_len;
    int                   found_sig;
    int                   found_id;
    char                  scope_buf[1024];
    size_t                scope_off;
    char                  path_caveats[8][BRIX_SCOPE_PATH_MAX];
    int                   n_path_caveats;
    u_char                last_cid[BRIX_MACAROON_MAX_CID_LEN];
    size_t                last_cid_len;
    u_char                sig_before_cid[32];
    int                   have_last_cid;
} brix_macaroon_parse_state_t;

/*
 * WHAT: The invariant inputs to one macaroon parse — logging sink, HMAC root
 *       key, destination claims, and the optional third-party-caveat capture
 *       array (tp_arr/n_tp/max_tp) that identifies a root/standalone parse.
 * WHY:  macaroon_parse_core and macaroon_parse_state_init both threaded these
 *       same seven scalars individually (9 and 8 params). Grouping them into
 *       one file-local descriptor keeps both helpers ≤5 params while passing
 *       byte-identical values on to the HMAC/claims/capture logic — the parse
 *       decisions (expiry-required iff tp_arr != NULL, capture iff room) are
 *       unchanged because the same fields drive them.
 * HOW:  tp_arr == NULL marks a discharge parse (no expiry requirement, no
 *       capture); tp_arr != NULL marks the root parse. n_tp counts captured
 *       third-party caveats up to max_tp.
 */
typedef struct {
    ngx_log_t            *log;
    const u_char         *key;
    size_t                key_len;
    brix_token_claims_t  *claims;
    brix_macaroon_tp_t   *tp_arr;
    int                  *n_tp;
    int                   max_tp;
} macaroon_parse_input_t;

/* ---- Cross-translation-unit entry points (defined once, called across the split) ---- */

/* Defined in macaroon_parse.c — parse a 4-char hex packet length (macaroon.c's
 * discharge scanner and the parse loop both consume it). Returns the uint32
 * length or -1 on an invalid hex nibble. */
int brix_macaroon_packet_len(const u_char *p);

/* Defined in macaroon_parse.c — reconstruct the HMAC-SHA256 chain over one
 * macaroon binary, verify the final signature, and extract caveats into
 * in->claims. Returns 0 on success, -1 on any failure. */
int macaroon_parse_core(const macaroon_parse_input_t *in,
    const u_char *bin, size_t bin_len);

/* Defined in macaroon_caveats.c — narrow claim scope paths by each path: caveat
 * (intersection). Called from the parse finalizer and from discharge-claim
 * intersection in macaroon.c. */
void macaroon_apply_path_caveats(ngx_log_t *log,
    brix_token_claims_t *claims,
    char path_caveats[][BRIX_SCOPE_PATH_MAX], int n_path_caveats);

/* Defined in macaroon_caveats.c — classify and apply one first-party caveat
 * (activity:/before:/path:) into the parse state. Called from the cid packet
 * handler in macaroon_parse.c. */
void macaroon_parse_first_party_caveat(brix_macaroon_parse_state_t *state,
    const u_char *caveat, size_t caveat_len);

/* Defined in macaroon_crypto.c — recover a discharge macaroon's 32-byte root
 * key from a third-party caveat's vid via AES-256-CBC(key=aes_key, IV=vid[0..15]).
 * Returns 0 on success, -1 on failure. Called from discharge validation in
 * macaroon.c. */
int macaroon_decrypt_vid(const u_char *vid, size_t vid_len,
    const u_char *aes_key, u_char *discharge_key);
