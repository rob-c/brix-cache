/* Macaroon token validation — HMAC-SHA256 signature chaining, WLCG caveat parsing, and third-party discharge verification.
 *
 * WHAT: Validates WLCG macaroon tokens (base64url-encoded binary bundles) by reconstructing the HMAC chain across
 * packets (identifier, location, cid/vid caveats, signature), extracting scope/activity/path/expiry caveats into
 * claims structure, and optionally validating discharge macaroons for each third-party caveat via AES-256-CBC vid decryption.
 * Supports both single-root validation and space-separated multi-token bundles with up to 8 discharges per root.
 *
 * WHY: WLCG (Worldwide LHC Computing Grid) uses macaroon tokens for delegated, caveatable authorization. The HMAC chain
 * ensures each caveat modifies the signature deterministically — any tampered caveat produces a mismatched final signature.
 * Third-party caveats enable cross-service delegation where a discharge macaroon proves the third party authorized access.
 *
 * HOW: brix_token_is_macaroon() — check token has no dots (JWTs have 3 dot-separated parts, macaroons don't).
 * brix_macaroon_secret_parse() — hex string to binary via nibble pairing. brix_macaroon_validate_bundle() — space-tokenize bundle,
 * base64url-decode root, parse_core with tp_arr for third-party tracking, iterate discharges matching cid identifiers, decrypt vid via AES-256-CBC,
 * validate each discharge, intersect expiry/paths into root claims. Static helpers: parse_packet_len (hex→uint32), parse_iso8601 (before: caveat time),
 * macaroon_decrypt_vid (AES-256-CBC vid decryption), macaroon_rebuild_scope_raw (scope string reconstruction from parsed scopes),
 * macaroon_apply_path_caveats (intersection logic for path caveats vs scope paths), macaroon_parse_core (HMAC chain reconstruction + caveat extraction). */

#include "token_internal.h"
#include "macaroon.h"
#include "b64url.h"
#include "scopes.h"
#include "core/compat/hex.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>   /* CRYPTO_memcmp — constant-time MAC compare */
#include <string.h>
#include <time.h>

#define MACAROON_MAX_BIN 8192

static int
parse_packet_len(const u_char *p)
/* WHAT: Parse a 4-character hex-encoded packet length from macaroon binary data.
 * WHY: Macaroon packets are prefixed with a hex-encoded 32-bit length field (8 hex chars → uint32). This helper converts the first 4 hex characters into an integer for bounds checking before reading packet data.
 * HOW: Call brix_hex_from_char() on each of p[0..3], reject if any nibble invalid (<0); combine via bit shifts (v0<<12)|(v1<<8)|(v2<<4)|v3 to form uint32; return value or -1 on invalid nibble. */
{
    int v0, v1, v2, v3;
    v0 = brix_hex_from_char(p[0]);
    v1 = brix_hex_from_char(p[1]);
    v2 = brix_hex_from_char(p[2]);
    v3 = brix_hex_from_char(p[3]);
    if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) return -1;
    return (v0 << 12) | (v1 << 8) | (v2 << 4) | v3;
}

/* WHAT: Parse ISO8601 timestamp "YYYY-MM-DDTHH:MM:SSZ" into time_t for before: caveat expiry checking.
 * WHY: Macaroon "before:" caveats specify absolute expiry times in a restricted ISO8601 format (no timezone offsets, no fractional seconds). This helper converts the string to epoch seconds for comparison with current time.
 * HOW: Validate len≥20 and len<32; copy into buf[32] null-terminated; memset tm struct; sscanf(buf,"%d-%d-%dT%d:%d:%dZ") extracting year/month/day/hour/min/sec (expect 6 matches); adjust tm_year-=1900, tm_mon-=1, tm_isdst=-1; return timegm(&tm) or -1 on parse failure. */
static time_t
parse_iso8601(const char *s, size_t len)
{
    struct tm tm;
    char      buf[32];

    if (len < 20 || len >= sizeof(buf)) return (time_t) -1;
    memcpy(buf, s, len);
    buf[len] = '\0';

    memset(&tm, 0, sizeof(tm));
    /* %Y-%m-%dT%H:%M:%SZ */
    if (sscanf(buf, "%d-%d-%dT%d:%d:%dZ",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
    {
        return (time_t) -1;
    }

    tm.tm_year -= 1900;
    tm.tm_mon  -= 1;
    tm.tm_isdst = -1;

    return timegm(&tm);
}

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

/* Discharge Macaroon support (Feature 8b) */
/* Max number of discharge Macaroons accepted in a single bundle */
#define BRIX_MACAROON_MAX_DISCHARGES   8
/* Max third-party caveats tracked in one Macaroon (cid+vid pairs) */
#define BRIX_MACAROON_MAX_TP_CAVEATS   8
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

/* WHAT: Decrypt a third-party caveat vid blob to recover the discharge macaroon's 32-byte root key via AES-256-CBC.
 * WHY: At macaroon creation time, the discharge key was encrypted as vid = [16-byte IV] || AES-256-CBC(sig_before_cid, discharge_key).
 * sig_before_cid (the HMAC signature before cid update) serves as the AES decryption key. This function reverses that encryption so we can validate the discharge macaroon with its recovered root key.
 * HOW: Validate vid_len≥32 (16-byte IV + minimum 16-byte ciphertext); EVP_CIPHER_CTX_new(); set_padding=0 to disable PKCS7 (discharge key is always 32 bytes = two AES blocks); EVP_DecryptInit_ex(ctx,EVP_aes_256_cbc,NULL,aes_key,vid) using vid[0..15] as IV; EVP_DecryptUpdate(plain,&olen,vid+16,vid_len-16); EVP_DecryptFinal_ex(plain+olen,&flen); verify olen+flen≥32; ngx_memcpy(discharge_key,plain,32); OPENSSL_cleanse plain; EVP_CIPHER_CTX_free(ctx); return 0 success or -1 failure. */
/*
 * WHAT: One AES-256-CBC vid-decrypt request — the inputs and the output buffer
 *       for recovering a discharge macaroon's 32-byte root key from a
 *       third-party caveat's vid blob.
 * WHY:  macaroon_decrypt_vid_inner previously took vid/vid_len/aes_key/
 *       discharge_key as four separate parameters (6 total with ctx+plain).
 *       Bundling the crypto operands into one file-local descriptor keeps the
 *       helper's parameter count ≤5 without changing any value threaded into
 *       the OpenSSL calls — every field carries the identical bytes.
 * HOW:  vid = [16-byte IV || ciphertext]; aes_key = 32-byte HMAC sig used as the
 *       AES-256 key; discharge_key receives the recovered 32-byte key on success.
 */
typedef struct {
    const u_char  *vid;
    size_t         vid_len;
    const u_char  *aes_key;
    u_char        *discharge_key;
} macaroon_vid_t;

/*
 * Inner AES-256-CBC decrypt over an already-created ctx, writing the plaintext
 * into the caller's `plain` scratch and, on success, copying the recovered
 * 32-byte discharge key out. Returns 0 on success, -1 on any OpenSSL failure or
 * a plaintext shorter than 32 bytes. The caller owns ctx and the cleanse/free of
 * plain — keeping that cleanup at the edge lets this use flat early returns.
 */
static int
macaroon_decrypt_vid_inner(EVP_CIPHER_CTX *ctx, u_char *plain,
    const macaroon_vid_t *v)
{
    int olen = 0, flen = 0;

    /*
     * Disable PKCS7 padding: the discharge key is always 32 bytes (two AES
     * blocks), so the ciphertext is always a multiple of the block size.
     * This avoids ambiguity regardless of whether the issuer used padding.
     */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* vid[0..15] = IV; vid[16..] = ciphertext; aes_key = 32-byte HMAC sig */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, v->aes_key, v->vid)
        != 1) {
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plain, &olen,
                          v->vid + 16, (int)(v->vid_len - 16)) != 1) {
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, plain + olen, &flen) != 1) {
        return -1;
    }

    if (olen + flen < 32) {
        return -1;
    }

    ngx_memcpy(v->discharge_key, plain, 32);
    return 0;
}

static int
macaroon_decrypt_vid(const u_char *vid, size_t vid_len,
    const u_char *aes_key, u_char *discharge_key)
{
    EVP_CIPHER_CTX *ctx;
    u_char          plain[64];
    int             rc;
    macaroon_vid_t  v;

    /* Need at least 16-byte IV + 16-byte ciphertext (one AES block) */
    if (vid_len < 32) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    ngx_memzero(&v, sizeof(v));
    v.vid           = vid;
    v.vid_len       = vid_len;
    v.aes_key       = aes_key;
    v.discharge_key = discharge_key;

    rc = macaroon_decrypt_vid_inner(ctx, plain, &v);

    OPENSSL_cleanse(plain, sizeof(plain));
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* WHAT: Reconstruct scope_raw from individual scope entries and re-parse to refresh claims->scopes[].
 * WHY: After path narrowing (macaroon_apply_path_caveats) modifies individual scope paths, the raw scope string becomes stale — it still contains old paths. This function rebuilds the canonical scope_raw string from the updated scopes[] array so downstream access checks use the correct narrowed paths.
 * HOW: Iterate each scope entry's permission bits (read/write/create/modify); for each enabled bit append "perm_name:path" to scope_raw with space separator between entries; check bounds against sizeof(claims->scope_raw) — break if overflow; re-parse the rebuilt string via brix_token_parse_scopes() to refresh claims->scopes[]. */
/* HOW: Clear scope_raw buffer. Iterate each scope entry's permission bits (read/write/create/modify).
 *       For each enabled bit, append "perm_name:path" to scope_raw with space separator between entries.
 *       Check bounds against sizeof(claims->scope_raw) — break if overflow.
 *       Re-parse the rebuilt string via brix_token_parse_scopes() to refresh claims->scopes[]. */
static void
macaroon_rebuild_scope_raw(brix_token_claims_t *claims)
{
    static const char *perm_names[] = {
        "storage.read", "storage.write",
        "storage.create", "storage.modify"
    };
    size_t off = 0;
    int    si;

    claims->scope_raw[0] = '\0';
    for (si = 0; si < claims->scope_count; si++) {
        brix_token_scope_t *sc = &claims->scopes[si];
        unsigned int bits[4] = {
            sc->read, sc->write, sc->create, sc->modify
        };
        int bi;
        for (bi = 0; bi < 4; bi++) {
            size_t plen, pathlen;
            if (!bits[bi]) {
                continue;
            }
            plen    = strlen(perm_names[bi]);
            pathlen = strlen(sc->path);
            if (off + plen + 1 + pathlen + 2 > sizeof(claims->scope_raw)) {
                break;
            }
            if (off > 0) {
                claims->scope_raw[off++] = ' ';
            }
            memcpy(claims->scope_raw + off, perm_names[bi], plen);
            off += plen;
            claims->scope_raw[off++] = ':';
            memcpy(claims->scope_raw + off, sc->path, pathlen);
            off += pathlen;
            claims->scope_raw[off] = '\0';
        }
    }

    claims->scope_count = brix_token_parse_scopes(
        claims->scope_raw, claims->scopes, BRIX_MAX_TOKEN_SCOPES);
}
/*
 * HOW: Clear scope_raw buffer. Iterate each scope entry's permission bits (read/write/create/modify).
 *       For each enabled bit, append "perm_name:path" to scope_raw with space separator between entries.
 *       Check bounds against sizeof(claims->scope_raw) — break if overflow.
 *       Re-parse the rebuilt string via brix_token_parse_scopes() to refresh claims->scopes[].
 */

/* WHAT: Apply path: caveats to restrict scope paths via intersection logic — each caveat narrows allowed paths further.
 * WHY: WLCG macaroon "path:" caveats enforce hierarchical path restrictions on top of already-granted scope permissions. The intersection ensures the final effective path is the most restrictive among all caveats and scopes, preventing over-authorization.
 * HOW: For each caveat path cp: strip trailing slash from scope paths for comparison; case 1 (cp equal/deeper than sc->path): narrow scope to cp if different; case 2 (sc->path deeper than cp): keep sc->path already more restrictive; case 3 (disjoint paths): revoke all permissions (read/write/create/modify=0) on this scope entry; track narrowed flag; after processing all caveats, call macaroon_rebuild_scope_raw() if any narrowing occurred. */
static int
macaroon_apply_path_to_scope(ngx_log_t *log, brix_token_scope_t *scope,
                             const char *caveat_path, size_t caveat_path_len)
{
    size_t scope_len = strlen(scope->path);
    size_t scope_cmp_len = scope_len;

    if (scope_cmp_len > 1 && scope->path[scope_cmp_len - 1] == '/') {
        scope_cmp_len--;
    }

    if (strncmp(caveat_path, scope->path, scope_cmp_len) == 0
        && (caveat_path[scope_cmp_len] == '/'
            || caveat_path[scope_cmp_len] == '\0')) {
        if (strcmp(scope->path, caveat_path) == 0) {
            return 0;
        }
        ngx_log_error(NGX_LOG_INFO, log, 0,
            "brix_macaroon: path: caveat \"%s\" narrows "
            "scope path \"%s\" → \"%s\"", caveat_path, scope->path,
            caveat_path);
        memcpy(scope->path, caveat_path, caveat_path_len + 1);
        return 1;
    }

    if (strncmp(scope->path, caveat_path, caveat_path_len) == 0
        && (scope->path[caveat_path_len] == '/'
            || scope->path[caveat_path_len] == '\0')) {
        return 0;
    }

    if (scope->read || scope->write || scope->create || scope->modify) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
            "brix_macaroon: path: caveat \"%s\" revokes "
            "scope path \"%s\" (disjoint)", caveat_path, scope->path);
    }
    scope->read = scope->write = scope->create = scope->modify = 0;
    return 1;
}

static void
macaroon_apply_path_caveats(ngx_log_t *log,
    brix_token_claims_t *claims,
    char path_caveats[][BRIX_SCOPE_PATH_MAX], int n_path_caveats)
{
    int ci, si;
    int narrowed = 0;

    for (ci = 0; ci < n_path_caveats; ci++) {
        const char *cp    = path_caveats[ci];
        size_t      cplen = strlen(cp);

        for (si = 0; si < claims->scope_count; si++) {
            narrowed |= macaroon_apply_path_to_scope(log, &claims->scopes[si],
                                                     cp, cplen);
        }
    }

    if (narrowed) {
        macaroon_rebuild_scope_raw(claims);
    }
}

static const char *
macaroon_scope_for_activity(const char *activity, size_t activity_len)
{
    if (activity_len == 8 && memcmp(activity, "DOWNLOAD", 8) == 0) {
        return "storage.read";
    }
    if (activity_len == 4 && memcmp(activity, "LIST", 4) == 0) {
        return "storage.read";
    }
    if (activity_len == 5 && memcmp(activity, "STAGE", 5) == 0) {
        return "storage.stage";
    }
    if (activity_len == 6 && memcmp(activity, "UPLOAD", 6) == 0) {
        return "storage.write";
    }
    if (activity_len == 6 && memcmp(activity, "DELETE", 6) == 0) {
        return "storage.write";
    }
    if (activity_len == 6 && memcmp(activity, "MANAGE", 6) == 0) {
        return "storage.modify";
    }
    return NULL;
}

static void
macaroon_append_activity_scope(brix_macaroon_parse_state_t *state,
                               const char *scope)
{
    size_t scope_len = strlen(scope);

    /*
     * Overflow-proof capacity check: reject first if scope_off is already
     * at/past the buffer end, then compare against the REMAINING space by
     * subtraction. The additive form (scope_off + scope_len + 4 >= sizeof)
     * can wrap size_t for a corrupt/hostile scope_off and admit an
     * out-of-bounds append; this form cannot. Semantics for all in-range
     * offsets are identical: proceed iff scope_off + scope_len + 4 < sizeof.
     */
    if (state->scope_off >= sizeof(state->scope_buf)
        || scope_len + 4 >= sizeof(state->scope_buf) - state->scope_off) {
        return;
    }
    if (state->scope_off > 0) {
        state->scope_buf[state->scope_off++] = ' ';
    }
    memcpy(state->scope_buf + state->scope_off, scope, scope_len);
    state->scope_off += scope_len;
    state->scope_buf[state->scope_off++] = ':';
    state->scope_buf[state->scope_off++] = '/';
    state->scope_buf[state->scope_off] = '\0';
}

static void
macaroon_parse_activity_caveat(brix_macaroon_parse_state_t *state,
                               const u_char *caveat, size_t caveat_len)
{
    const char *activity = (const char *)(caveat + 9);
    size_t remaining = caveat_len - 9;

    while (remaining > 0) {
        const char *comma = memchr(activity, ',', remaining);
        size_t activity_len = (comma != NULL)
                              ? (size_t)(comma - activity) : remaining;
        const char *scope = macaroon_scope_for_activity(activity,
                                                        activity_len);

        if (scope != NULL) {
            macaroon_append_activity_scope(state, scope);
        }

        activity += activity_len + (comma != NULL ? 1 : 0);
        remaining -= activity_len + (comma != NULL ? 1 : 0);
    }
}

static void
macaroon_parse_before_caveat(brix_macaroon_parse_state_t *state,
                             const u_char *caveat, size_t caveat_len)
{
    time_t exp = parse_iso8601((const char *)(caveat + 7), caveat_len - 7);

    if (exp != (time_t)-1
        && (state->claims->exp == 0 || exp < state->claims->exp)) {
        state->claims->exp = exp;
    }
}

static void
macaroon_parse_path_caveat(brix_macaroon_parse_state_t *state,
                           const u_char *caveat, size_t caveat_len)
{
    const char *path = (const char *)(caveat + 5);
    size_t path_len = caveat_len - 5;

    if (state->n_path_caveats >= 8 || path_len == 0
        || path_len >= BRIX_SCOPE_PATH_MAX) {
        return;
    }

    memcpy(state->path_caveats[state->n_path_caveats], path, path_len);
    state->path_caveats[state->n_path_caveats][path_len] = '\0';
    state->n_path_caveats++;
}

static void
macaroon_parse_first_party_caveat(brix_macaroon_parse_state_t *state,
                                  const u_char *caveat, size_t caveat_len)
{
    if (caveat_len >= 9 && memcmp(caveat, "activity:", 9) == 0) {
        macaroon_parse_activity_caveat(state, caveat, caveat_len);
        return;
    }
    if (caveat_len >= 7 && memcmp(caveat, "before:", 7) == 0) {
        macaroon_parse_before_caveat(state, caveat, caveat_len);
        return;
    }
    if (caveat_len >= 5 && memcmp(caveat, "path:", 5) == 0) {
        macaroon_parse_path_caveat(state, caveat, caveat_len);
    }
}

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
 * HOW: Initialize sig=HMAC(key, identifier), scope_buf="", path_caveats[], last_cid/sig_before_cid state; loop packets (p+4≤end): parse_packet_len(p)→plen; data=p+4,dlen=plen-4; strip trailing newline if present; process packet types: "identifier " → HMAC(EVP_sha256,key,identifier)→sig, copy to claims->sub; "location " → copy to claims->iss; "cid " → save sig_before_cid, HMAC(sig,cid)→next_sig→sig, track last_cid for vid pairing; parse first-party caveats within cid data (activity:→scope mapping, before:→parse_iso8601→claims->exp min, path:→path_caveats array); "vid " → HMAC(sig,vid_data)→sig, record (cid+vid+sig_before) triple into tp_arr if available; "signature " → compare provided 32-byte sig against computed sig, reject mismatch; after loop: check found_sig and found_id, validate expiry (now>claims->exp), finalize scopes from scope_buf via brix_token_parse_scopes(), apply path caveats via macaroon_apply_path_caveats(); return 0 success or -1 failure. */
static int
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
        int     plen = parse_packet_len(p);
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
            if (cursor > token_start
                && *n_tokens <= BRIX_MACAROON_MAX_DISCHARGES) {
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

static int
macaroon_candidate_matches_cid(const u_char *candidate, ssize_t candidate_len,
                               brix_macaroon_tp_t *tp)
{
    const u_char *packet = candidate;
    const u_char *end = candidate + candidate_len;

    while (packet + 4 <= end) {
        int packet_len = parse_packet_len(packet);
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
 *       the root macaroon, indices 1..n_tokens-1 are candidate discharges.
 */
typedef struct {
    const char  **tokens;
    size_t       *token_lens;
    int           n_tokens;
} macaroon_bundle_t;

static ssize_t
macaroon_find_discharge(const macaroon_bundle_t *bundle,
                        brix_macaroon_tp_t *tp, u_char *discharge_bin,
                        size_t discharge_cap)
{
    int token_index;

    for (token_index = 1; token_index < bundle->n_tokens; token_index++) {
        u_char candidate[MACAROON_MAX_BIN];
        ssize_t candidate_len;

        candidate_len = b64url_decode(bundle->tokens[token_index],
                                      bundle->token_lens[token_index], candidate,
                                      sizeof(candidate));
        if (candidate_len < 4) {
            continue;
        }
        if (macaroon_candidate_matches_cid(candidate, candidate_len, tp)) {
            ngx_memcpy(discharge_bin, candidate, candidate_len);
            return candidate_len <= (ssize_t) discharge_cap ? candidate_len : -1;
        }
    }
    return -1;
}

static void
macaroon_intersect_discharge_claims(ngx_log_t *log,
                                    brix_token_claims_t *claims,
                                    brix_token_claims_t *d_claims)
{
    int discharge_scope_index;
    char discharge_paths[BRIX_MAX_TOKEN_SCOPES][BRIX_SCOPE_PATH_MAX];
    int n_discharge_paths = 0;

    if (d_claims->exp > 0
        && (claims->exp == 0 || d_claims->exp < claims->exp)) {
        claims->exp = d_claims->exp;
    }

    for (discharge_scope_index = 0;
         discharge_scope_index < d_claims->scope_count
         && n_discharge_paths < BRIX_MAX_TOKEN_SCOPES;
         discharge_scope_index++) {
        size_t path_len = strlen(
            d_claims->scopes[discharge_scope_index].path);
        if (path_len > 0 && path_len < BRIX_SCOPE_PATH_MAX) {
            memcpy(discharge_paths[n_discharge_paths],
                   d_claims->scopes[discharge_scope_index].path,
                   path_len + 1);
            n_discharge_paths++;
        }
    }

    if (n_discharge_paths > 0) {
        macaroon_apply_path_caveats(log, claims, discharge_paths,
                                    n_discharge_paths);
    }
}

static int
macaroon_validate_one_discharge(ngx_log_t *log,
                                const macaroon_bundle_t *bundle,
                                brix_macaroon_tp_t *tp,
                                brix_token_claims_t *claims, int caveat_index)
{
    brix_token_claims_t d_claims;
    u_char d_bin[MACAROON_MAX_BIN];
    ssize_t d_bin_len;
    u_char d_key[32];
    macaroon_parse_input_t d_in;

    d_bin_len = macaroon_find_discharge(bundle, tp, d_bin, sizeof(d_bin));
    if (d_bin_len < 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "brix_macaroon: no discharge Macaroon provided for "
            "third-party caveat #%d", caveat_index);
        return -1;
    }

    if (macaroon_decrypt_vid(tp->vid, tp->vid_len, tp->sig_before, d_key)
        != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "brix_macaroon: cannot decrypt vid for caveat #%d "
            "(unsupported vid format?)", caveat_index);
        OPENSSL_cleanse(d_key, sizeof(d_key));
        return -1;
    }

    ngx_memzero(&d_claims, sizeof(d_claims));
    ngx_memzero(&d_in, sizeof(d_in));
    d_in.log     = log;
    d_in.key     = d_key;
    d_in.key_len = 32;
    d_in.claims  = &d_claims;
    /* tp_arr/n_tp/max_tp stay NULL/0: discharge parse, no nested capture */
    if (macaroon_parse_core(&d_in, d_bin, (size_t)d_bin_len) != 0) {
        OPENSSL_cleanse(d_key, sizeof(d_key));
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "brix_macaroon: discharge Macaroon #%d is invalid",
            caveat_index);
        return -1;
    }
    OPENSSL_cleanse(d_key, sizeof(d_key));

    ngx_log_error(NGX_LOG_DEBUG, log, 0,
        "brix_macaroon: discharge #%d valid sub=\"%s\" scope=\"%s\"",
        caveat_index, d_claims.sub, d_claims.scope_raw);
    macaroon_intersect_discharge_claims(log, claims, &d_claims);
    return 0;
}

static int
macaroon_validate_discharges(ngx_log_t *log, const macaroon_bundle_t *bundle,
                             brix_macaroon_tp_t *tp_arr, int n_tp,
                             brix_token_claims_t *claims)
{
    int caveat_index;

    if (n_tp == 0) {
        return 0;
    }
    if (bundle->n_tokens < 2) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "brix_macaroon: root has %d third-party caveat(s) "
            "but no discharge Macaroons were provided", n_tp);
        return -1;
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
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_macaroon: empty token bundle");
        return -1;
    }

    /* Decode and validate the root Macaroon, collecting third-party caveats */
    root_bin_len = b64url_decode(tokens[0], tlens[0],
                                 root_bin, sizeof(root_bin));
    if (root_bin_len < 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
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

    if (macaroon_validate_discharges(log, &bundle, tp_arr, n_tp, claims) != 0) {
        return -1;
        }

    ngx_log_error(NGX_LOG_INFO, log, 0,
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
