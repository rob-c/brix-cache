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
 * HOW: xrootd_token_is_macaroon() — check token has no dots (JWTs have 3 dot-separated parts, macaroons don't).
 * xrootd_macaroon_secret_parse() — hex string to binary via nibble pairing. xrootd_macaroon_validate_bundle() — space-tokenize bundle,
 * base64url-decode root, parse_core with tp_arr for third-party tracking, iterate discharges matching cid identifiers, decrypt vid via AES-256-CBC,
 * validate each discharge, intersect expiry/paths into root claims. Static helpers: parse_packet_len (hex→uint32), parse_iso8601 (before: caveat time),
 * macaroon_decrypt_vid (AES-256-CBC vid decryption), macaroon_rebuild_scope_raw (scope string reconstruction from parsed scopes),
 * macaroon_apply_path_caveats (intersection logic for path caveats vs scope paths), macaroon_parse_core (HMAC chain reconstruction + caveat extraction). */

#include "token_internal.h"
#include "macaroon.h"
#include "b64url.h"
#include "scopes.h"
#include "../compat/hex.h"

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
 * HOW: Call xrootd_hex_from_char() on each of p[0..3], reject if any nibble invalid (<0); combine via bit shifts (v0<<12)|(v1<<8)|(v2<<4)|v3 to form uint32; return value or -1 on invalid nibble. */
{
    int v0, v1, v2, v3;
    v0 = xrootd_hex_from_char(p[0]);
    v1 = xrootd_hex_from_char(p[1]);
    v2 = xrootd_hex_from_char(p[2]);
    v3 = xrootd_hex_from_char(p[3]);
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
xrootd_token_is_macaroon(const char *token, size_t token_len)
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
xrootd_macaroon_secret_parse(const char *hex, size_t hex_len,
    u_char *bin, size_t bin_max)
/* WHAT: Convert a hex-encoded macaroon root secret string into binary bytes for HMAC computation.
 * WHY: Macaroon secrets are stored as hex strings (e.g., in config files or environment variables); the HMAC chain
 * requires raw binary key material. This helper performs safe hex-to-binary conversion with bounds checking.
 * HOW: Validate hex_len is even and hex_len/2 ≤ bin_max; iterate each nibble pair calling xrootd_hex_from_char() on positions i*2 and i*2+1,
 * reject if any nibble invalid (<0); combine nibbles via (v1<<4)|v2 into bin[i]; return hex_len/2 or -1 on failure. */
{
    size_t i;
    int    v1, v2;

    if (hex_len % 2 != 0 || hex_len / 2 > bin_max) return -1;

    for (i = 0; i < hex_len / 2; i++) {
        v1 = xrootd_hex_from_char((unsigned char) hex[i * 2]);
        v2 = xrootd_hex_from_char((unsigned char) hex[i * 2 + 1]);
        if (v1 < 0 || v2 < 0) return -1;
        bin[i] = (u_char) ((v1 << 4) | v2);
    }

    return (ssize_t) (hex_len / 2);
}

/* Discharge Macaroon support (Feature 8b) */
/* Max number of discharge Macaroons accepted in a single bundle */
#define XROOTD_MACAROON_MAX_DISCHARGES   8
/* Max third-party caveats tracked in one Macaroon (cid+vid pairs) */
#define XROOTD_MACAROON_MAX_TP_CAVEATS   8
#define XROOTD_MACAROON_MAX_CID_LEN      512
#define XROOTD_MACAROON_MAX_VID_LEN      256

/*
 * A third-party caveat (cid + vid pair) captured during root Macaroon parsing.
 *
 * sig_before is the HMAC sig value immediately before HMAC(sig, cid) was
 * computed.  At Macaroon creation time the discharge key was encrypted as:
 *   vid = [16-byte IV] || AES-256-CBC-encrypt(key=sig_before, IV, discharge_key)
 * so sig_before is the AES decryption key needed to recover the discharge key.
 */
typedef struct {
    u_char  cid[XROOTD_MACAROON_MAX_CID_LEN];
    size_t  cid_len;
    u_char  vid[XROOTD_MACAROON_MAX_VID_LEN];  /* raw binary — NOT base64 */
    size_t  vid_len;
    u_char  sig_before[32]; /* HMAC sig before the cid update — AES-256 key */
} xrootd_macaroon_tp_t;

/* WHAT: Decrypt a third-party caveat vid blob to recover the discharge macaroon's 32-byte root key via AES-256-CBC.
 * WHY: At macaroon creation time, the discharge key was encrypted as vid = [16-byte IV] || AES-256-CBC(sig_before_cid, discharge_key).
 * sig_before_cid (the HMAC signature before cid update) serves as the AES decryption key. This function reverses that encryption so we can validate the discharge macaroon with its recovered root key.
 * HOW: Validate vid_len≥32 (16-byte IV + minimum 16-byte ciphertext); EVP_CIPHER_CTX_new(); set_padding=0 to disable PKCS7 (discharge key is always 32 bytes = two AES blocks); EVP_DecryptInit_ex(ctx,EVP_aes_256_cbc,NULL,aes_key,vid) using vid[0..15] as IV; EVP_DecryptUpdate(plain,&olen,vid+16,vid_len-16); EVP_DecryptFinal_ex(plain+olen,&flen); verify olen+flen≥32; ngx_memcpy(discharge_key,plain,32); OPENSSL_cleanse plain; EVP_CIPHER_CTX_free(ctx); return 0 success or -1 failure. */
/*
 * Inner AES-256-CBC decrypt over an already-created ctx, writing the plaintext
 * into the caller's `plain` scratch and, on success, copying the recovered
 * 32-byte discharge key out. Returns 0 on success, -1 on any OpenSSL failure or
 * a plaintext shorter than 32 bytes. The caller owns ctx and the cleanse/free of
 * plain — keeping that cleanup at the edge lets this use flat early returns.
 */
static int
macaroon_decrypt_vid_inner(EVP_CIPHER_CTX *ctx, u_char *plain,
    const u_char *vid, size_t vid_len, const u_char *aes_key,
    u_char *discharge_key)
{
    int olen = 0, flen = 0;

    /*
     * Disable PKCS7 padding: the discharge key is always 32 bytes (two AES
     * blocks), so the ciphertext is always a multiple of the block size.
     * This avoids ambiguity regardless of whether the issuer used padding.
     */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* vid[0..15] = IV; vid[16..] = ciphertext; aes_key = 32-byte HMAC sig */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, vid) != 1) {
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plain, &olen,
                          vid + 16, (int)(vid_len - 16)) != 1) {
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, plain + olen, &flen) != 1) {
        return -1;
    }

    if (olen + flen < 32) {
        return -1;
    }

    ngx_memcpy(discharge_key, plain, 32);
    return 0;
}

static int
macaroon_decrypt_vid(const u_char *vid, size_t vid_len,
    const u_char *aes_key, u_char *discharge_key)
{
    EVP_CIPHER_CTX *ctx;
    u_char          plain[64];
    int             rc;

    /* Need at least 16-byte IV + 16-byte ciphertext (one AES block) */
    if (vid_len < 32) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    rc = macaroon_decrypt_vid_inner(ctx, plain, vid, vid_len, aes_key,
                                    discharge_key);

    OPENSSL_cleanse(plain, sizeof(plain));
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* WHAT: Reconstruct scope_raw from individual scope entries and re-parse to refresh claims->scopes[].
 * WHY: After path narrowing (macaroon_apply_path_caveats) modifies individual scope paths, the raw scope string becomes stale — it still contains old paths. This function rebuilds the canonical scope_raw string from the updated scopes[] array so downstream access checks use the correct narrowed paths.
 * HOW: Iterate each scope entry's permission bits (read/write/create/modify); for each enabled bit append "perm_name:path" to scope_raw with space separator between entries; check bounds against sizeof(claims->scope_raw) — break if overflow; re-parse the rebuilt string via xrootd_token_parse_scopes() to refresh claims->scopes[]. */
/* HOW: Clear scope_raw buffer. Iterate each scope entry's permission bits (read/write/create/modify).
 *       For each enabled bit, append "perm_name:path" to scope_raw with space separator between entries.
 *       Check bounds against sizeof(claims->scope_raw) — break if overflow.
 *       Re-parse the rebuilt string via xrootd_token_parse_scopes() to refresh claims->scopes[]. */
static void
macaroon_rebuild_scope_raw(xrootd_token_claims_t *claims)
{
    static const char *perm_names[] = {
        "storage.read", "storage.write",
        "storage.create", "storage.modify"
    };
    size_t off = 0;
    int    si;

    claims->scope_raw[0] = '\0';
    for (si = 0; si < claims->scope_count; si++) {
        xrootd_token_scope_t *sc = &claims->scopes[si];
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

    claims->scope_count = xrootd_token_parse_scopes(
        claims->scope_raw, claims->scopes, XROOTD_MAX_TOKEN_SCOPES);
}
/*
 * HOW: Clear scope_raw buffer. Iterate each scope entry's permission bits (read/write/create/modify).
 *       For each enabled bit, append "perm_name:path" to scope_raw with space separator between entries.
 *       Check bounds against sizeof(claims->scope_raw) — break if overflow.
 *       Re-parse the rebuilt string via xrootd_token_parse_scopes() to refresh claims->scopes[].
 */

/* WHAT: Apply path: caveats to restrict scope paths via intersection logic — each caveat narrows allowed paths further.
 * WHY: WLCG macaroon "path:" caveats enforce hierarchical path restrictions on top of already-granted scope permissions. The intersection ensures the final effective path is the most restrictive among all caveats and scopes, preventing over-authorization.
 * HOW: For each caveat path cp: strip trailing slash from scope paths for comparison; case 1 (cp equal/deeper than sc->path): narrow scope to cp if different; case 2 (sc->path deeper than cp): keep sc->path already more restrictive; case 3 (disjoint paths): revoke all permissions (read/write/create/modify=0) on this scope entry; track narrowed flag; after processing all caveats, call macaroon_rebuild_scope_raw() if any narrowing occurred. */
static void
macaroon_apply_path_caveats(ngx_log_t *log,
    xrootd_token_claims_t *claims,
    char path_caveats[][XROOTD_SCOPE_PATH_MAX], int n_path_caveats)
{
    int ci, si;
    int narrowed = 0;

    for (ci = 0; ci < n_path_caveats; ci++) {
        const char *cp    = path_caveats[ci];
        size_t      cplen = strlen(cp);

        for (si = 0; si < claims->scope_count; si++) {
            xrootd_token_scope_t *sc       = &claims->scopes[si];
            size_t                slen     = strlen(sc->path);
            size_t                slen_cmp = slen;

            /* Strip trailing slash for comparison */
            if (slen_cmp > 1 && sc->path[slen_cmp - 1] == '/') {
                slen_cmp--;
            }

            /* Case 1: caveat path is equal to or deeper than scope path */
            if (strncmp(cp, sc->path, slen_cmp) == 0
                && (cp[slen_cmp] == '/' || cp[slen_cmp] == '\0'))
            {
                if (strcmp(sc->path, cp) != 0) {
                    ngx_log_error(NGX_LOG_INFO, log, 0,
                        "xrootd_macaroon: path: caveat \"%s\" narrows "
                        "scope path \"%s\" → \"%s\"", cp, sc->path, cp);
                    memcpy(sc->path, cp, cplen + 1);
                    narrowed = 1;
                }
            }
            /* Case 2: scope path is already deeper than caveat path */
            else if (strncmp(sc->path, cp, cplen) == 0
                     && (sc->path[cplen] == '/' || sc->path[cplen] == '\0'))
            {
                /* keep sc->path — already more restrictive */
            }
            /* Case 3: disjoint paths — revoke all permissions for this scope */
            else {
                if (sc->read || sc->write || sc->create || sc->modify) {
                    ngx_log_error(NGX_LOG_INFO, log, 0,
                        "xrootd_macaroon: path: caveat \"%s\" revokes "
                        "scope path \"%s\" (disjoint)", cp, sc->path);
                    narrowed = 1;
                }
                sc->read = sc->write = sc->create = sc->modify = 0;
            }
        }
    }

    if (narrowed) {
        macaroon_rebuild_scope_raw(claims);
    }
}

/* WHAT: Parse one macaroon binary, reconstruct HMAC-SHA256 signature chain across all packets, verify final signature, and extract WLCG caveats into claims.
 * WHY: The macaroon security model requires each caveat to deterministically modify the HMAC chain — sig = HMAC(sig_prev, caveat_data). This ensures any tampered or reordered caveat produces a mismatched final signature. Extracting activity:/path:/before: caveats converts raw binary authorization into structured claims for access control decisions.
 * HOW: Initialize sig=HMAC(key, identifier), scope_buf="", path_caveats[], last_cid/sig_before_cid state; loop packets (p+4≤end): parse_packet_len(p)→plen; data=p+4,dlen=plen-4; strip trailing newline if present; process packet types: "identifier " → HMAC(EVP_sha256,key,identifier)→sig, copy to claims->sub; "location " → copy to claims->iss; "cid " → save sig_before_cid, HMAC(sig,cid)→next_sig→sig, track last_cid for vid pairing; parse first-party caveats within cid data (activity:→scope mapping, before:→parse_iso8601→claims->exp min, path:→path_caveats array); "vid " → HMAC(sig,vid_data)→sig, record (cid+vid+sig_before) triple into tp_arr if available; "signature " → compare provided 32-byte sig against computed sig, reject mismatch; after loop: check found_sig and found_id, validate expiry (now>claims->exp), finalize scopes from scope_buf via xrootd_token_parse_scopes(), apply path caveats via macaroon_apply_path_caveats(); return 0 success or -1 failure. */
static int
macaroon_parse_core(ngx_log_t *log,
    const u_char *bin, size_t bin_len,
    const u_char *key, size_t key_len,
    xrootd_token_claims_t *claims,
    xrootd_macaroon_tp_t *tp_arr, int *n_tp, int max_tp)
{
    u_char        sig[32];
    const u_char *p, *end;
    unsigned int  sig_out_len;
    int           found_sig     = 0;
    int           found_id      = 0;
    char          scope_buf[1024];
    size_t        scope_off     = 0;
    char          path_caveats[8][XROOTD_SCOPE_PATH_MAX];
    int           n_path_caveats = 0;
    /* State for cid+vid pairing within the packet loop */
    u_char        last_cid[XROOTD_MACAROON_MAX_CID_LEN];
    size_t        last_cid_len  = 0;
    u_char        sig_before_cid[32];
    int           have_last_cid = 0;

    ngx_memzero(scope_buf, sizeof(scope_buf));

    p   = bin;
    end = bin + bin_len;

    while (p + 4 <= end) {
        int     plen = parse_packet_len(p);
        u_char *data;
        size_t  dlen;

        if (plen < 4 || p + plen > end) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_macaroon: malformed packet length: %d", plen);
            return -1;
        }

        data = (u_char *)(p + 4);
        dlen = (size_t)(plen - 4);

        /* Strip trailing newline if present */
        if (dlen > 0 && data[dlen - 1] == '\n') {
            dlen--;
        }

        if (dlen >= 11 && memcmp(data, "identifier ", 11) == 0) {
            const u_char *id    = data + 11;
            size_t        idlen = dlen - 11;

            HMAC(EVP_sha256(), key, key_len, id, idlen, sig, &sig_out_len);
            ngx_memcpy(claims->sub, id,
                       idlen < sizeof(claims->sub) ? idlen : sizeof(claims->sub) - 1);
            found_id      = 1;
            have_last_cid = 0;

        } else if (dlen >= 9 && memcmp(data, "location ", 9) == 0) {
            const u_char *loc    = data + 9;
            size_t        loclen = dlen - 9;

            ngx_memcpy(claims->iss, loc,
                       loclen < sizeof(claims->iss) ? loclen : sizeof(claims->iss) - 1);

        } else if (dlen >= 4 && memcmp(data, "cid ", 4) == 0) {
            const u_char *caveat = data + 4;
            size_t        clen   = dlen - 4;
            u_char        next_sig[32];

            if (!found_id) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "xrootd_macaroon: caveat before identifier");
                return -1;
            }

            /*
             * Save the current sig before updating it.
             * If the next packet is a vid, sig_before_cid is the AES-256-CBC
             * key used to encrypt the discharge key in the vid blob.
             */
            ngx_memcpy(sig_before_cid, sig, 32);

            /* Update HMAC chain: sig = HMAC(sig, caveat) */
            HMAC(EVP_sha256(), sig, 32, caveat, clen, next_sig, &sig_out_len);
            ngx_memcpy(sig, next_sig, 32);

            /* Track this cid for a potential following vid packet */
            last_cid_len = clen < sizeof(last_cid) ? clen : sizeof(last_cid) - 1;
            ngx_memcpy(last_cid, caveat, last_cid_len);
            have_last_cid = 1;

            /* Parse WLCG first-party caveats */
            if (clen >= 9 && memcmp(caveat, "activity:", 9) == 0) {
                const char *act   = (const char *)(caveat + 9);
                size_t      alen  = clen - 9;
                const char *scope = NULL;

                if      (alen == 8 && memcmp(act, "DOWNLOAD", 8) == 0) scope = "storage.read";
                else if (alen == 4 && memcmp(act, "LIST",     4) == 0) scope = "storage.read";
                else if (alen == 6 && memcmp(act, "UPLOAD",   6) == 0) scope = "storage.write";
                else if (alen == 6 && memcmp(act, "DELETE",   6) == 0) scope = "storage.write";
                else if (alen == 6 && memcmp(act, "MANAGE",   6) == 0) scope = "storage.modify";

                if (scope) {
                    size_t slen = strlen(scope);
                    if (scope_off + slen + 2 < sizeof(scope_buf)) {
                        if (scope_off > 0) {
                            scope_buf[scope_off++] = ' ';
                        }
                        memcpy(scope_buf + scope_off, scope, slen);
                        scope_off += slen;
                    }
                }

            } else if (clen >= 7 && memcmp(caveat, "before:", 7) == 0) {
                time_t exp = parse_iso8601((const char *)(caveat + 7), clen - 7);
                if (exp != (time_t)-1) {
                    if (claims->exp == 0 || exp < claims->exp) {
                        claims->exp = exp;
                    }
                }

            } else if (clen >= 5 && memcmp(caveat, "path:", 5) == 0) {
                const char *cp    = (const char *)(caveat + 5);
                size_t      cplen = clen - 5;
                if (n_path_caveats < 8 && cplen > 0
                    && cplen < XROOTD_SCOPE_PATH_MAX)
                {
                    memcpy(path_caveats[n_path_caveats], cp, cplen);
                    path_caveats[n_path_caveats][cplen] = '\0';
                    n_path_caveats++;
                }
            }

        } else if (dlen >= 4 && memcmp(data, "vid ", 4) == 0) {
            /*
             * A vid packet pairs with the immediately preceding cid packet.
             * Together they form a third-party caveat: the vid contains the
             * discharge Macaroon's root key encrypted with AES-256-CBC using
             * sig_before_cid as the AES key.
             *
             * HMAC chain update: sig = HMAC(sig_after_cid, vid_data)
             */
            const u_char *vid_data = data + 4;
            size_t        vid_len  = dlen - 4;
            u_char        next_sig[32];

            HMAC(EVP_sha256(), sig, 32, vid_data, vid_len, next_sig, &sig_out_len);
            ngx_memcpy(sig, next_sig, 32);

            /* Record the (cid, vid, sig_before) triple for discharge validation */
            if (have_last_cid && tp_arr != NULL && n_tp != NULL
                && *n_tp < max_tp)
            {
                xrootd_macaroon_tp_t *tp = &tp_arr[(*n_tp)++];
                ngx_memcpy(tp->cid, last_cid, last_cid_len);
                tp->cid_len = last_cid_len;
                tp->vid_len = vid_len < sizeof(tp->vid)
                              ? vid_len : sizeof(tp->vid) - 1;
                ngx_memcpy(tp->vid, vid_data, tp->vid_len);
                ngx_memcpy(tp->sig_before, sig_before_cid, 32);
            }

            have_last_cid = 0;  /* vid consumed the pending cid */

        } else if (dlen >= 10 && memcmp(data, "signature ", 10) == 0) {
            const u_char *provided_sig = data + 10;
            /* Constant-time MAC compare: a timing-variable memcmp here is a
             * byte-by-byte forgery oracle on a bearer token's signature. */
            if (dlen < 10 + 32
                || CRYPTO_memcmp(sig, provided_sig, 32) != 0) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "xrootd_macaroon: signature mismatch");
                return -1;
            }
            found_sig = 1;
        }

        p += plen;
    }

    if (!found_sig) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_macaroon: no valid signature found");
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
    {
        time_t now = time(NULL);
        if (tp_arr != NULL && claims->exp <= 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_macaroon: rejected — no before: (expiry) caveat; "
                          "non-expiring macaroons are not accepted");
            return -1;
        }
        if (claims->exp > 0 && now > (time_t)claims->exp) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_macaroon: token expired at %L (now=%L)",
                          (long long)claims->exp, (long long)now);
            return -1;
        }
    }

    /* Finalize scopes from activity: caveats */
    ngx_memcpy(claims->scope_raw, scope_buf, scope_off);
    claims->scope_raw[scope_off] = '\0';
    claims->scope_count = xrootd_token_parse_scopes(
        claims->scope_raw, claims->scopes, XROOTD_MAX_TOKEN_SCOPES);

    /* Apply path: caveat restrictions */
    if (n_path_caveats > 0) {
        macaroon_apply_path_caveats(log, claims, path_caveats, n_path_caveats);
    }

    return 0;
}

/*
 * xrootd_macaroon_validate_bundle — validate a space-separated Macaroon bundle.
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
xrootd_macaroon_validate_bundle(ngx_log_t *log,
    const char *token, size_t token_len,
    const u_char *root_key, size_t root_key_len,
    xrootd_token_claims_t *claims)
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
    const char          *tokens[XROOTD_MACAROON_MAX_DISCHARGES + 1];
    size_t               tlens[XROOTD_MACAROON_MAX_DISCHARGES + 1];
    int                  n_tokens    = 0;
    const char          *p, *end, *tok_start;
    u_char               root_bin[MACAROON_MAX_BIN];
    ssize_t              root_bin_len;
    xrootd_macaroon_tp_t tp_arr[XROOTD_MACAROON_MAX_TP_CAVEATS];
    int                  n_tp = 0;
    int                  ti;

    ngx_memzero(claims, sizeof(*claims));
    ngx_memzero(tp_arr, sizeof(tp_arr));

    /* Tokenize the bundle on space boundaries */
    p         = token;
    end       = token + token_len;
    tok_start = p;
    for (;;) {
        if (p >= end || *p == ' ') {
            if (p > tok_start
                && n_tokens <= XROOTD_MACAROON_MAX_DISCHARGES)
            {
                tokens[n_tokens] = tok_start;
                tlens[n_tokens]  = (size_t)(p - tok_start);
                n_tokens++;
            }
            if (p >= end) {
                break;
            }
            tok_start = p + 1;
        }
        p++;
    }

    if (n_tokens == 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_macaroon: empty token bundle");
        return -1;
    }

    /* Decode and validate the root Macaroon, collecting third-party caveats */
    root_bin_len = b64url_decode(tokens[0], tlens[0],
                                 root_bin, sizeof(root_bin));
    if (root_bin_len < 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_macaroon: root token base64url decode failed");
        return -1;
    }

    if (macaroon_parse_core(log,
                            root_bin, (size_t)root_bin_len,
                            root_key, root_key_len,
                            claims,
                            tp_arr, &n_tp, XROOTD_MACAROON_MAX_TP_CAVEATS) != 0)
    {
        return -1;
    }

    /* Validate discharge Macaroons for each third-party caveat */
    if (n_tp > 0) {
        if (n_tokens < 2) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "xrootd_macaroon: root has %d third-party caveat(s) "
                "but no discharge Macaroons were provided", n_tp);
            return -1;
        }

        for (ti = 0; ti < n_tp; ti++) {
            xrootd_macaroon_tp_t  *tp        = &tp_arr[ti];
            xrootd_token_claims_t  d_claims;
            u_char                 d_bin[MACAROON_MAX_BIN];
            ssize_t                d_bin_len  = -1;
            u_char                 d_key[32];
            int                    di;

            /* Find the discharge Macaroon whose identifier matches tp->cid */
            for (di = 1; di < n_tokens; di++) {
                u_char       cand[MACAROON_MAX_BIN];
                ssize_t      cand_len;
                const u_char *pb, *pe;

                cand_len = b64url_decode(tokens[di], tlens[di],
                                         cand, sizeof(cand));
                if (cand_len < 4) {
                    continue;
                }

                /* Scan for the identifier packet */
                pb = cand;
                pe = cand + cand_len;
                while (pb + 4 <= pe) {
                    int     cplen = parse_packet_len(pb);
                    u_char *cdata;
                    size_t  cdlen;

                    if (cplen < 4 || pb + cplen > pe) {
                        break;
                    }
                    cdata = (u_char *)(pb + 4);
                    cdlen = (size_t)(cplen - 4);
                    if (cdlen > 0 && cdata[cdlen - 1] == '\n') {
                        cdlen--;
                    }

                    if (cdlen >= 11 && memcmp(cdata, "identifier ", 11) == 0) {
                        const u_char *id    = cdata + 11;
                        size_t        idlen = cdlen - 11;
                        if (idlen == tp->cid_len
                            && memcmp(id, tp->cid, idlen) == 0)
                        {
                            ngx_memcpy(d_bin, cand, cand_len);
                            d_bin_len = cand_len;
                        }
                        break;
                    }
                    pb += cplen;
                }

                if (d_bin_len >= 0) {
                    break;  /* matched this discharge Macaroon */
                }
            }

            if (d_bin_len < 0) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "xrootd_macaroon: no discharge Macaroon provided for "
                    "third-party caveat #%d", ti);
                return -1;
            }

            /* Decrypt the vid to recover the discharge Macaroon's root key */
            if (macaroon_decrypt_vid(tp->vid, tp->vid_len,
                                     tp->sig_before, d_key) != 0)
            {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "xrootd_macaroon: cannot decrypt vid for caveat #%d "
                    "(unsupported vid format?)", ti);
                OPENSSL_cleanse(d_key, sizeof(d_key));
                return -1;
            }

            /* Validate the discharge Macaroon with the recovered key.
             * Discharge Macaroons cannot themselves have third-party caveats
             * (depth limit = 1) so we pass NULL for the tp_arr argument. */
            ngx_memzero(&d_claims, sizeof(d_claims));
            if (macaroon_parse_core(log,
                                    d_bin, (size_t)d_bin_len,
                                    d_key, 32,
                                    &d_claims,
                                    NULL, NULL, 0) != 0)
            {
                OPENSSL_cleanse(d_key, sizeof(d_key));
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "xrootd_macaroon: discharge Macaroon #%d is invalid", ti);
                return -1;
            }
            OPENSSL_cleanse(d_key, sizeof(d_key));

            ngx_log_error(NGX_LOG_DEBUG, log, 0,
                "xrootd_macaroon: discharge #%d valid sub=\"%s\" scope=\"%s\"",
                ti, d_claims.sub, d_claims.scope_raw);

            /* Intersect discharge expiry with root expiry (take earliest) */
            if (d_claims.exp > 0) {
                if (claims->exp == 0 || d_claims.exp < claims->exp) {
                    claims->exp = d_claims.exp;
                }
            }

            /* Intersect discharge path/scope constraints into root claims */
            if (d_claims.scope_count > 0) {
                /* Treat discharge scope paths as additional path: caveats */
                int dsi;
                char dp_caveats[XROOTD_MAX_TOKEN_SCOPES][XROOTD_SCOPE_PATH_MAX];
                int  n_dp = 0;

                for (dsi = 0; dsi < d_claims.scope_count
                             && n_dp < XROOTD_MAX_TOKEN_SCOPES; dsi++) {
                    size_t plen = strlen(d_claims.scopes[dsi].path);
                    if (plen > 0 && plen < XROOTD_SCOPE_PATH_MAX) {
                        memcpy(dp_caveats[n_dp], d_claims.scopes[dsi].path,
                               plen + 1);
                        n_dp++;
                    }
                }

                if (n_dp > 0) {
                    macaroon_apply_path_caveats(log, claims, dp_caveats, n_dp);
                }
            }
        }
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "xrootd_macaroon: valid Macaroon bundle sub=\"%s\" "
                  "iss=\"%s\" scope=\"%s\" exp=%L "
                  "(third-party: %d, discharges: %d)",
                  claims->sub, claims->iss, claims->scope_raw,
                  (long long)claims->exp, n_tp, n_tokens - 1);

    return 0;
}

int
xrootd_macaroon_validate(ngx_log_t *log,
    const char *token, size_t token_len,
    const u_char *root_key, size_t root_key_len,
    xrootd_token_claims_t *claims)
/* WHAT: Thin wrapper — validate a single-root macaroon (no discharges required).
 * WHY: Provides the simple-entry-point for callers who only have a root macaroon without third-party caveats.
 * Internally delegates to validate_bundle which handles both single-root and multi-discharge cases uniformly.
 * HOW: Pass all arguments directly to xrootd_macaroon_validate_bundle() — identical behavior, no local logic. */
{
    return xrootd_macaroon_validate_bundle(log, token, token_len,
                                           root_key, root_key_len, claims);
}
