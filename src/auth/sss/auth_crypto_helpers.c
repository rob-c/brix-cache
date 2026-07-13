#include "sss_internal.h"
#include "auth/gsi/gsi_internal.h"
#include "protocols/root/session/registry.h"
#include "core/compat/crc32_ieee.h"   /* shared CRC-32/IEEE (libxrdproto) */
#include "core/compat/sss_bf.h"       /* shared Blowfish-CFB64 (libxrdproto) */

#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#include <string.h>

/*
 * WHAT: This file provides shared cryptographic helpers for Simple Shared Secret (SSS) authentication.
 *       Includes big-endian 32/64-bit read/write primitives for wire protocol framing, software CRC32c implementation
 *       for integrity verification (SSS uses CRC32 not HMAC), Blowfish-CFB encryption/decryption for challenge-response,
 *       and OpenSSL 3.x legacy provider loading for SHA-256 digest availability. All helpers are static or internal —
 *       used exclusively by sss/auth.c and sss/key_parse.c during SSS authentication flow.
 *
 * WHY: SSS authentication requires wire-format parsing (big-endian integers), integrity verification via CRC32 appended
 *      to plaintext before encryption, symmetric challenge encryption using Blowfish-CFB with zero IV, and OpenSSL 3.x
 *      compatibility for SHA-256 digest fetching from legacy provider. These helpers centralize crypto operations preventing
 *      duplication across SSS module files and ensuring consistent wire-format handling.
 *
 * HOW: Four helper categories → big-endian read/write (brix_sss_read_be32/be64, brix_sss_write_be32) for wire protocol parsing;
 *      CRC32 software implementation (brix_sss_crc32) using standard polynomial 0xedb88320u for integrity verification;
 *      Blowfish-CFB encryption/decryption (brix_sss_bf32_crypt) with EVP_CIPHER_CTX and zero IV for challenge-response;
 *      OpenSSL legacy provider loading (brix_sss_load_legacy_provider) ensuring SHA-256 digest availability on OpenSSL 3.x. */

uint32_t
brix_sss_read_be32(const u_char *p)
{
    return ((uint32_t) p[0] << 24)
         | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)
         |  (uint32_t) p[3];
}

uint64_t
brix_sss_read_be64(const u_char *p)
{
    return ((uint64_t) brix_sss_read_be32(p) << 32)
         |  (uint64_t) brix_sss_read_be32(p + 4);
}
/*
 * WHAT: Reads an 8-byte big-endian uint64_t from wire protocol payload by composing two be32 reads. Used for parsing larger integer fields in SSS credential payloads.
 */

void
brix_sss_write_be32(u_char *p, uint32_t v)
{
    p[0] = (u_char) (v >> 24);
    p[1] = (u_char) (v >> 16);
    p[2] = (u_char) (v >> 8);
    p[3] = (u_char) v;
}
/*
 * WHAT: Writes a uint32_t as 4 bytes in big-endian order into wire protocol buffer. Used by SSS auth challenge generation to encode timestamps and key IDs into server-to-client credential payloads.
 */

/* Forwards to the shared CRC-32/IEEE kernel (libxrdproto) — one source of truth
 * with the native client's SSS mint path. */
uint32_t
brix_sss_crc32(const u_char *p, size_t len)
{
    return brix_crc32_ieee(p, len);
}
/*
 * WHAT: Computes CRC32 checksum using standard polynomial 0xedb88320u (reflected form). Used by SSS authentication for integrity verification — CRC32 is appended to plaintext before Blowfish encryption, then verified after decryption via direct uint32_t comparison.
 */

/* Forwards to the shared Blowfish-CFB64 kernel (libxrdproto), which owns the
 * OpenSSL-3 legacy-provider load — one source of truth with the client's SSS mint. */
ngx_int_t
brix_sss_bf32_crypt(int encrypt, const u_char *key, size_t key_len,
    const u_char *src, size_t src_len, u_char *dst, size_t dst_len,
    size_t *out_len)
{
    return brix_sss_bf_crypt(encrypt, key, key_len, src, src_len,
                               dst, dst_len, out_len) == 0 ? NGX_OK : NGX_ERROR;
}
/*
 * WHAT: Blowfish-CFB symmetric encryption/decryption for SSS challenge-response authentication. Uses EVP_CIPHER_CTX with zero IV and no padding. Encrypt mode: EVP_EncryptInit → set_padding(0) → set_key_length(key_len) → init with key+iv → update → final. Decrypt mode mirrors encrypt flow using EVP_Decrypt*. Returns NGX_OK on success with out_len populated, NGX_ERROR on cipher operation failure or invalid parameters (key_len==0 or >INT_MAX). Key length is variable — SSS keys may be shorter than standard 56-byte Blowfish key.
 */

const brix_sss_key_t *
brix_sss_find_key_arr(ngx_array_t *keys_arr, int64_t id)
{
    brix_sss_key_t *keys;
    ngx_uint_t        i;

    if (keys_arr == NULL) {
        return NULL;
    }

    keys = keys_arr->elts;
    for (i = 0; i < keys_arr->nelts; i++) {
        if (keys[i].id == id && (!keys[i].exp || keys[i].exp > ngx_time())) {
            return &keys[i];
        }
    }

    return NULL;
}

const brix_sss_key_t *
brix_sss_find_key(ngx_stream_brix_srv_conf_t *conf, int64_t id)
{
    return brix_sss_find_key_arr(conf->sss_keys, id);
}
/*
 * WHAT: Searches configured SSS key table for a matching key ID that is not expired. Returns pointer to first matching active key or NULL if no match found. Used by sss/auth.c during kXR_auth handler to select the correct shared secret for decrypting client challenge.
 */

/*
 * WHAT: File-local working state for one SSS blob verification pass. Carries the
 *       inputs (keytab, lifetime, wire blob) and the derived intermediates
 *       (selected key, located cipher span, decrypted-plaintext scratch and its
 *       length) between the verify sub-steps so each helper takes a single ctx
 *       rather than a long parameter list.
 *
 * WHY:  brix_sss_verify_blob is an extern with an out-of-file caller
 *       (net/cms/server_auth.c) so its signature is frozen at 8 params; the
 *       decomposition threads this ctx internally instead. `clear` bounds the
 *       decrypt scratch — SSS credentials over any transport (XRootD kXR_auth or
 *       CMS kYR_xauth frame) are far smaller than this — and MUST be cleansed on
 *       every exit that touched it.
 *
 * HOW:  brix_sss_verify_blob zero-inits one of these, then calls the header /
 *       decrypt / crc-check / identity sub-steps in sequence, each reading and
 *       writing only ctx fields. `clear_len` is the plaintext length with the
 *       trailing 4-byte CRC stripped.
 */
typedef struct {
    ngx_array_t            *keys;
    time_t                  lifetime;
    const u_char           *blob;
    size_t                  blob_len;
    const brix_sss_key_t   *key;
    const u_char           *cipher;
    size_t                  cipher_len;
    u_char                  clear[8192];
    size_t                  clear_len;
} brix_sss_blob_ctx_t;

/*
 * WHAT: Validates the SSS credential wire framing (minimum length, magic bytes,
 *       encryption marker, key-name size, and header-length bound) and returns
 *       the derived header length that separates the header from the ciphertext.
 *
 * WHY:  Isolating pure framing validation keeps the CCN of each verify sub-step
 *       within the gate and lets the key-lookup step assume a well-formed header.
 *       Every framing failure is a fail-closed deny.
 *
 * HOW:  Checks the "sss\0" magic and BRIX_SSS_ENC_BF32 enc marker, bounds the
 *       key-name size (multiple-of-8, <= BRIX_SSS_NAME_MAX, NUL-terminated),
 *       derives hdr_len = BRIX_SSS_HDR_LEN + kn_size, and bounds it against the
 *       blob length. Writes the header length through *hdr_len_out. Returns
 *       NGX_OK on a well-formed header, NGX_ERROR (with err populated) otherwise.
 */
static ngx_int_t
brix_sss_blob_validate_framing(const brix_sss_blob_ctx_t *ctx,
    size_t *hdr_len_out, char *err, size_t errsz)
{
    const u_char *blob = ctx->blob;
    size_t        hdr_len;
    uint8_t       kn_size;

    if (blob == NULL
        || ctx->blob_len < BRIX_SSS_HDR_LEN + BRIX_SSS_DATA_HDR_LEN + 4)
    {
        snprintf(err, errsz, "sss credential too short");
        return NGX_ERROR;
    }

    if (blob[0] != 's' || blob[1] != 's' || blob[2] != 's' || blob[3] != '\0'
        || blob[7] != BRIX_SSS_ENC_BF32)
    {
        snprintf(err, errsz, "sss credential bad magic/enc");
        return NGX_ERROR;
    }

    kn_size = blob[6];
    if (kn_size != 0 && (kn_size > BRIX_SSS_NAME_MAX || (kn_size & 0x07))) {
        snprintf(err, errsz, "sss credential bad key-name size");
        return NGX_ERROR;
    }

    hdr_len = BRIX_SSS_HDR_LEN + kn_size;
    if (hdr_len >= ctx->blob_len || (kn_size && blob[hdr_len - 1] != '\0')) {
        snprintf(err, errsz, "sss credential malformed header");
        return NGX_ERROR;
    }

    *hdr_len_out = hdr_len;
    return NGX_OK;
}

/*
 * WHAT: Validates the SSS credential wire header, then locates the matching
 *       keytab entry by key id and records the ciphertext span into the ctx.
 *
 * WHY:  Every framing and key-lookup failure is a fail-closed deny; keeping them
 *       in one linear step lets the orchestrator read as a sequence and lets the
 *       decrypt step assume a validated cipher span.
 *
 * HOW:  Defers framing checks to brix_sss_blob_validate_framing, then reads the
 *       big-endian key id, resolves it against the keytab, and sets ctx->cipher /
 *       ctx->cipher_len (bounded against the scratch size). Returns NGX_OK on a
 *       well-formed header with a live key, NGX_ERROR (with err populated) on any
 *       framing or lookup failure.
 */
static ngx_int_t
brix_sss_blob_parse_header(brix_sss_blob_ctx_t *ctx, char *err, size_t errsz)
{
    size_t    hdr_len = 0;
    int64_t   key_id;
    ngx_int_t rc;

    rc = brix_sss_blob_validate_framing(ctx, &hdr_len, err, errsz);
    if (rc != NGX_OK) {
        return rc;
    }

    key_id = (int64_t) brix_sss_read_be64(ctx->blob + 8);
    ctx->key = brix_sss_find_key_arr(ctx->keys, key_id);
    if (ctx->key == NULL) {
        snprintf(err, errsz, "sss key id %lld not in keytab", (long long) key_id);
        return NGX_ERROR;
    }

    ctx->cipher = ctx->blob + hdr_len;
    ctx->cipher_len = ctx->blob_len - hdr_len;
    if (ctx->cipher_len <= 4 || ctx->cipher_len > sizeof(ctx->clear)) {
        snprintf(err, errsz, "sss ciphertext length out of range");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Decrypts the located ciphertext span with the selected SSS key into the
 *       ctx plaintext scratch and verifies the trailing CRC-32 over the payload.
 *
 * WHY:  A wrong key or tampered credential decrypts to garbage whose appended CRC
 *       will not match — this is the security-load-bearing gate that turns a bad
 *       key into a clean deny rather than a forged identity. On any failure that
 *       has touched the scratch it must be cleansed by the caller.
 *
 * HOW:  Runs brix_sss_bf32_crypt in decrypt mode; on success strips the trailing
 *       4-byte CRC to yield ctx->clear_len, reads the wire CRC big-endian, and
 *       compares it to brix_sss_crc32 over the payload. Also enforces the minimum
 *       data-header length. Returns NGX_OK when the CRC matches and the plaintext
 *       is long enough, NGX_ERROR (with err populated) otherwise. The scratch is
 *       left populated for the caller's cleanse on both paths.
 */
static ngx_int_t
brix_sss_blob_decrypt_verify_crc(brix_sss_blob_ctx_t *ctx, char *err,
    size_t errsz)
{
    size_t   out_len;
    uint32_t got_crc, want_crc;

    if (brix_sss_bf32_crypt(0, ctx->key->key, ctx->key->key_len,
                              ctx->cipher, ctx->cipher_len,
                              ctx->clear, sizeof(ctx->clear),
                              &out_len) != NGX_OK
        || out_len <= 4)
    {
        snprintf(err, errsz, "sss decrypt failed");
        return NGX_ERROR;
    }

    ctx->clear_len = out_len - 4;
    got_crc  = brix_sss_read_be32(ctx->clear + ctx->clear_len);
    want_crc = brix_sss_crc32(ctx->clear, ctx->clear_len);
    if (got_crc != want_crc || ctx->clear_len < BRIX_SSS_DATA_HDR_LEN) {
        snprintf(err, errsz, "sss CRC mismatch (wrong key or tampered)");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Enforces the SSS replay window on a CRC-verified plaintext by checking
 *       its generation timestamp against the configured credential lifetime.
 *
 * WHY:  A CRC-valid credential minted long ago is a replay; the replay window is
 *       frozen and rejecting the expired credential keeps stale captures from
 *       authenticating. The caller cleanses the scratch on the reject path.
 *
 * HOW:  Reads the big-endian gen_time at offset 32, computes `now` relative to
 *       BRIX_SSS_BASE_TIME, and denies when gen_time + lifetime has elapsed.
 *       Returns NGX_OK if still within window, NGX_ERROR (with err populated) if
 *       expired.
 */
static ngx_int_t
brix_sss_blob_check_replay(brix_sss_blob_ctx_t *ctx, char *err, size_t errsz)
{
    uint32_t gen_time = brix_sss_read_be32(ctx->clear + 32);
    uint32_t now = (uint32_t) (ngx_time() - BRIX_SSS_BASE_TIME);

    if (gen_time + (uint32_t) ctx->lifetime <= now) {
        snprintf(err, errsz, "sss credential expired (replay window)");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Applies the credential options byte and, when requested, parses the
 *       decrypted identity TLV block into the caller's identity struct.
 *
 * WHY:  SNDLID credentials are unsupported and must decline (not error) so the
 *       caller can distinguish them; identity parsing is the last step before a
 *       credential is trusted. The caller cleanses the scratch on every path.
 *
 * HOW:  Reads the options byte at offset 39; returns NGX_DECLINED for
 *       BRIX_SSS_OPT_SNDLID. Otherwise, when id_out is non-NULL, forwards the
 *       identity payload (past the data header) to brix_sss_parse_identity.
 *       Returns NGX_OK on success, NGX_DECLINED for SNDLID, NGX_ERROR (with err
 *       populated) on a parse failure.
 */
static ngx_int_t
brix_sss_blob_finish_identity(brix_sss_blob_ctx_t *ctx,
    brix_sss_identity_t *id_out, char *err, size_t errsz)
{
    uint8_t options = ctx->clear[39];

    if (options == BRIX_SSS_OPT_SNDLID) {
        snprintf(err, errsz, "sss SNDLID credential unsupported");
        return NGX_DECLINED;
    }

    if (id_out != NULL
        && brix_sss_parse_identity(ctx->clear + BRIX_SSS_DATA_HDR_LEN,
                                     ctx->clear_len - BRIX_SSS_DATA_HDR_LEN,
                                     id_out) != NGX_OK)
    {
        snprintf(err, errsz, "sss identity parse failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
brix_sss_verify_blob(ngx_array_t *keys, time_t lifetime,
    const u_char *blob, size_t blob_len,
    brix_sss_identity_t *id_out, const brix_sss_key_t **key_out,
    char *err, size_t errsz)
{
    brix_sss_blob_ctx_t ctx = {0};
    ngx_int_t           rc;

    ctx.keys = keys;
    ctx.lifetime = lifetime;
    ctx.blob = blob;
    ctx.blob_len = blob_len;

    if (key_out) {
        *key_out = NULL;
    }

    /* Header framing + key lookup + ciphertext location: no scratch touched yet. */
    rc = brix_sss_blob_parse_header(&ctx, err, errsz);
    if (rc != NGX_OK) {
        return rc;
    }

    /* From here the plaintext scratch is populated on every path and MUST be
     * cleansed before return. */
    rc = brix_sss_blob_decrypt_verify_crc(&ctx, err, errsz);
    if (rc == NGX_OK) {
        rc = brix_sss_blob_check_replay(&ctx, err, errsz);
    }
    if (rc == NGX_OK) {
        rc = brix_sss_blob_finish_identity(&ctx, id_out, err, errsz);
    }

    OPENSSL_cleanse(ctx.clear, sizeof(ctx.clear));

    if (rc == NGX_OK && key_out) {
        *key_out = ctx.key;
    }
    return rc;
}
/*
 * WHAT: Validates a self-contained SSS credential blob against a keytab: parses
 *       the wire header and selects the key, decrypts the ciphertext and verifies
 *       its trailing CRC-32 (wrong key or tampering → clean deny), enforces the
 *       replay window, and parses the identity. Returns NGX_OK with the resolved
 *       key on success, NGX_DECLINED for unsupported SNDLID credentials, and
 *       NGX_ERROR with a diagnostic in err for any framing, key, decrypt, CRC,
 *       expiry, or identity-parse failure. Used by sss/auth.c (kXR_auth) and
 *       net/cms/server_auth.c (kYR_xauth).
 */

