#include "../gsi/gsi_internal.h"
#include "../session/registry.h"

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#include <string.h>

/* Total byte length of the outer SSS packet header (magic + version + options
 * + padding + 8-byte key-id).  Must match XrdSsi/XrdSsiSecurity.cc. */
#define XROOTD_SSS_HDR_LEN       16

/* Byte length of the fixed-layout region at the start of the decrypted
 * cleartext: 32 bytes random nonce + 4 bytes gen_time + 4 bytes reserved. */
#define XROOTD_SSS_DATA_HDR_LEN  40

/* SSS timestamps are seconds since 2008-09-23T13:51:20Z.  This epoch
 * prevents year-2038 overflow on 32-bit time fields in the cleartext header
 * while still fitting a uint32_t through 2144. */
#define XROOTD_SSS_BASE_TIME     1222183880

#define XROOTD_SSS_ENC_BF32      '0'
#define XROOTD_SSS_OPT_USEDATA   0x00
#define XROOTD_SSS_OPT_SNDLID    0x01

#define XROOTD_SSS_TYPE_NAME     0x01
#define XROOTD_SSS_TYPE_GRPS     0x04
#define XROOTD_SSS_TYPE_RAND     0x07
#define XROOTD_SSS_TYPE_LGID     0x10
#define XROOTD_SSS_TYPE_HOST     0x20

typedef struct {
    char name[256];
    char grps[512];
    char host[256];
    char ip[128];
    int  id_count;
} xrootd_sss_identity_t;


static uint32_t
xrootd_sss_read_be32(const u_char *p)
{
    return ((uint32_t) p[0] << 24)
         | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)
         |  (uint32_t) p[3];
}


static uint64_t
xrootd_sss_read_be64(const u_char *p)
{
    return ((uint64_t) xrootd_sss_read_be32(p) << 32)
         |  (uint64_t) xrootd_sss_read_be32(p + 4);
}


static void
xrootd_sss_write_be32(u_char *p, uint32_t v)
{
    p[0] = (u_char) (v >> 24);
    p[1] = (u_char) (v >> 16);
    p[2] = (u_char) (v >> 8);
    p[3] = (u_char) v;
}


static uint32_t
xrootd_sss_crc32(const u_char *p, size_t len)
{
    uint32_t crc = 0xffffffffu;

    while (len--) {
        int i;

        crc ^= *p++;
        for (i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t) -(int32_t) (crc & 1));
        }
    }

    return crc ^ 0xffffffffu;
}


static void
xrootd_sss_load_legacy_provider(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    static int done;

    if (!done) {
        EVP_MD *md;

        md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
        if (md) {
            EVP_MD_free(md);
        }
        (void) OSSL_PROVIDER_load(NULL, "legacy");
        done = 1;
    }
#endif
}


static ngx_int_t
xrootd_sss_bf32_crypt(int encrypt, const u_char *key, size_t key_len,
    const u_char *src, size_t src_len, u_char *dst, size_t dst_len,
    size_t *out_len)
{
    EVP_CIPHER_CTX *evp;
    u_char          iv[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    int             len1, len2;

    if (key_len == 0 || key_len > INT_MAX || src_len > INT_MAX
        || dst_len > INT_MAX)
    {
        return NGX_ERROR;
    }

    xrootd_sss_load_legacy_provider();

    evp = EVP_CIPHER_CTX_new();
    if (evp == NULL) {
        return NGX_ERROR;
    }

    if (encrypt) {
        if (EVP_EncryptInit_ex(evp, EVP_bf_cfb64(), NULL, NULL, NULL) != 1
            || EVP_CIPHER_CTX_set_padding(evp, 0) != 1
            || EVP_CIPHER_CTX_set_key_length(evp, (int) key_len) != 1
            || EVP_EncryptInit_ex(evp, NULL, NULL, key, iv) != 1
            || EVP_EncryptUpdate(evp, dst, &len1, src, (int) src_len) != 1
            || EVP_EncryptFinal_ex(evp, dst + len1, &len2) != 1)
        {
            EVP_CIPHER_CTX_free(evp);
            return NGX_ERROR;
        }
    } else {
        if (EVP_DecryptInit_ex(evp, EVP_bf_cfb64(), NULL, NULL, NULL) != 1
            || EVP_CIPHER_CTX_set_padding(evp, 0) != 1
            || EVP_CIPHER_CTX_set_key_length(evp, (int) key_len) != 1
            || EVP_DecryptInit_ex(evp, NULL, NULL, key, iv) != 1
            || EVP_DecryptUpdate(evp, dst, &len1, src, (int) src_len) != 1
            || EVP_DecryptFinal_ex(evp, dst + len1, &len2) != 1)
        {
            EVP_CIPHER_CTX_free(evp);
            return NGX_ERROR;
        }
    }

    EVP_CIPHER_CTX_free(evp);
    *out_len = (size_t) (len1 + len2);
    return NGX_OK;
}


static const xrootd_sss_key_t *
xrootd_sss_find_key(ngx_stream_xrootd_srv_conf_t *conf, int64_t id)
{
    xrootd_sss_key_t *keys;
    ngx_uint_t        i;

    if (conf->sss_keys == NULL) {
        return NULL;
    }

    keys = conf->sss_keys->elts;
    for (i = 0; i < conf->sss_keys->nelts; i++) {
        if (keys[i].id == id && (!keys[i].exp || keys[i].exp > ngx_time())) {
            return &keys[i];
        }
    }

    return NULL;
}


static void
xrootd_sss_copy_packed_string(char *dst, size_t dst_len,
    const u_char *src, size_t len)
{
    if (len > 0 && src[len - 1] == '\0') {
        len--;
    }

    if (len >= dst_len) {
        len = dst_len - 1;
    }

    ngx_memcpy(dst, src, len);
    dst[len] = '\0';
}


/*
 * xrootd_sss_parse_identity — parse the decrypted SSS identity TLV block.
 *
 * After decryption and CRC32 verification, the cleartext body (past the
 * XROOTD_SSS_DATA_HDR_LEN fixed header) contains a compact TLV stream:
 *   [1-byte field_type][2-byte big-endian field_len][field_len bytes of value]
 *
 * Known field types:
 *   XROOTD_SSS_TYPE_NAME (0x01) — username
 *   XROOTD_SSS_TYPE_GRPS (0x04) — comma-separated groups
 *   XROOTD_SSS_TYPE_RAND (0x07) — random nonce (not counted for id_count)
 *   XROOTD_SSS_TYPE_LGID (0x10) — local group ID
 *   XROOTD_SSS_TYPE_HOST (0x20) — source hostname or [IP] literal
 *
 * This parser is security-sensitive: every length check must be explicit and
 * complete before advancing cursor.  A wrong check can turn a malformed
 * credential into an out-of-bounds read.
 *
 * Returns: NGX_OK if at least one non-random field was found, NGX_ERROR if
 *   the block is empty or truncated.
 */
static ngx_int_t
xrootd_sss_parse_identity(const u_char *data, size_t len,
    xrootd_sss_identity_t *id)
{
    const u_char *cursor;
    const u_char *end;

    ngx_memzero(id, sizeof(*id));
    cursor = data;
    end = data + len;

    /*
     * The decrypted SSS identity block is a compact TLV stream:
     *   [1-byte type][2-byte big-endian length][value bytes]
     *
     * Keep cursor movement explicit; this parser is security-sensitive and a
     * mistaken length check can turn malformed credentials into memory reads.
     */
    while (cursor < end) {
        const u_char *field_value;
        uint8_t       field_type;
        size_t        field_len;

        field_type = *cursor++;
        if ((size_t) (end - cursor) < 2) {
            return NGX_ERROR;
        }

        field_len = ((size_t) cursor[0] << 8) | (size_t) cursor[1];
        cursor += 2;
        if ((size_t) (end - cursor) < field_len) {
            return NGX_ERROR;
        }

        field_value = cursor;

        if (field_type != XROOTD_SSS_TYPE_RAND) {
            id->id_count++;
        }

        switch (field_type) {
        case XROOTD_SSS_TYPE_NAME:
            xrootd_sss_copy_packed_string(id->name, sizeof(id->name),
                                          field_value, field_len);
            break;

        case XROOTD_SSS_TYPE_GRPS:
            xrootd_sss_copy_packed_string(id->grps, sizeof(id->grps),
                                          field_value, field_len);
            break;

        case XROOTD_SSS_TYPE_HOST:
            if (field_len > 0 && field_value[0] == '[') {
                xrootd_sss_copy_packed_string(id->ip, sizeof(id->ip),
                                              field_value, field_len);
            } else {
                xrootd_sss_copy_packed_string(id->host, sizeof(id->host),
                                              field_value, field_len);
            }
            break;

        default:
            break;
        }

        cursor += field_len;
    }

    return id->id_count > 0 ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
xrootd_sss_auth_failed(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    xrootd_log_access(ctx, c, "AUTH", "-", "sss",
                      0, kXR_NotAuthorized, "SSS auth failed", 0);
    XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
    return xrootd_send_error(ctx, c, kXR_NotAuthorized, "SSS auth failed");
}


static ngx_int_t
xrootd_sss_send_authmore(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const xrootd_sss_key_t *key, const u_char *hdr, size_t hdr_len)
{
    u_char   clear[XROOTD_SSS_DATA_HDR_LEN + 1 + 2 + sizeof("nobody")];
    u_char   plain[sizeof(clear) + 4];
    u_char   cipher[sizeof(clear) + 4];
    u_char  *buf;
    u_char  *clear_cursor;
    size_t   clear_len, cipher_len, total, out_len;
    uint32_t crc, gen_time;

    ngx_memzero(clear, sizeof(clear));
    RAND_bytes(clear, 32);
    gen_time = (uint32_t) (ngx_time() - XROOTD_SSS_BASE_TIME);
    xrootd_sss_write_be32(clear + 32, gen_time);
    clear[39] = XROOTD_SSS_OPT_USEDATA;

    /*
     * Auth-more asks the client to use an explicit local identity.  The
     * identity body is the same TLV format parsed above; sizeof("nobody")
     * intentionally includes the terminating NUL expected by older clients.
     */
    clear_cursor = clear + XROOTD_SSS_DATA_HDR_LEN;
    *clear_cursor++ = XROOTD_SSS_TYPE_LGID;
    *clear_cursor++ = 0;
    *clear_cursor++ = (u_char) sizeof("nobody");
    ngx_memcpy(clear_cursor, "nobody", sizeof("nobody"));
    clear_cursor += sizeof("nobody");
    clear_len = (size_t) (clear_cursor - clear);

    ngx_memcpy(plain, clear, clear_len);
    crc = htonl(xrootd_sss_crc32(plain, clear_len));
    ngx_memcpy(plain + clear_len, &crc, sizeof(crc));

    if (xrootd_sss_bf32_crypt(1, key->key, key->key_len,
                              plain, clear_len + sizeof(crc),
                              cipher, sizeof(cipher), &out_len)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    cipher_len = out_len;

    total = XRD_RESPONSE_HDR_LEN + hdr_len + cipher_len;
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_authmore,
                          (uint32_t) (hdr_len + cipher_len),
                          (ServerResponseHdr *) buf);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, hdr, hdr_len);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + hdr_len, cipher, cipher_len);

    return xrootd_queue_response(ctx, c, buf, total);
}


/*
 * xrootd_sss_build_proxy_credential — build an SSS kXR_auth payload.
 *
 * Constructs the credential that a proxy sends to an upstream XRootD server
 * when the upstream requests SSS authentication via kXR_authmore.
 *
 * Output layout:
 *   [XROOTD_SSS_HDR_LEN bytes: magic + version + enc + key-id]
 *   [cipher_len bytes: BF32-encrypted cleartext + CRC32]
 *
 * buf must be at least XROOTD_SSS_HDR_LEN + XROOTD_SSS_DATA_HDR_LEN + 64 + 4
 * bytes (at least 256 bytes is always sufficient).
 *
 * Returns NGX_OK on success, NGX_ERROR if the key is missing or crypto fails.
 */
ngx_int_t
xrootd_sss_build_proxy_credential(const xrootd_sss_key_t *key,
    const char *username, u_char *buf, size_t buf_max, size_t *out_len)
{
    u_char   clear[XROOTD_SSS_DATA_HDR_LEN + 3 + 64 + 1]; /* hdr + TLV + username + NUL */
    u_char   plain[sizeof(clear) + 4];
    u_char  *cipher;
    u_char  *clear_cursor;
    size_t   clear_len, cipher_len, total, crypt_out;
    uint32_t crc, gen_time;
    uint64_t key_id_be;

    if (key == NULL || buf == NULL || buf_max < XROOTD_SSS_HDR_LEN + 64) {
        return NGX_ERROR;
    }

    if (username == NULL || *username == '\0') {
        username = "xrd";
    }

    /* Build cleartext: 40-byte fixed header + TLV NAME block */
    ngx_memzero(clear, sizeof(clear));
    RAND_bytes(clear, 32);
    gen_time = (uint32_t) (ngx_time() - XROOTD_SSS_BASE_TIME);
    xrootd_sss_write_be32(clear + 32, gen_time);
    clear[39] = XROOTD_SSS_OPT_USEDATA;   /* include identity TLV */

    clear_cursor = clear + XROOTD_SSS_DATA_HDR_LEN;

    /* TLV: NAME = username (NUL-terminated, NUL included in len) */
    {
        size_t ulen = ngx_strlen(username) + 1; /* +1 for NUL */
        if (ulen > 64) {
            ulen = 64;
        }
        *clear_cursor++ = XROOTD_SSS_TYPE_NAME;
        *clear_cursor++ = 0;
        *clear_cursor++ = (u_char) ulen;
        ngx_memcpy(clear_cursor, username, ulen - 1);
        clear_cursor[ulen - 1] = '\0';
        clear_cursor += ulen;
    }

    clear_len = (size_t) (clear_cursor - clear);

    /* plain = cleartext + CRC32 */
    ngx_memcpy(plain, clear, clear_len);
    crc = htonl(xrootd_sss_crc32(plain, clear_len));
    ngx_memcpy(plain + clear_len, &crc, sizeof(crc));

    /* Encrypt */
    cipher      = buf + XROOTD_SSS_HDR_LEN;
    cipher_len  = clear_len + 4;  /* BF-CFB64 has no padding */
    total       = XROOTD_SSS_HDR_LEN + cipher_len;
    if (total > buf_max) {
        return NGX_ERROR;
    }

    if (xrootd_sss_bf32_crypt(1, key->key, key->key_len,
                               plain, clear_len + 4,
                               cipher, buf_max - XROOTD_SSS_HDR_LEN,
                               &crypt_out)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Build the outer header in buf[0..15] */
    buf[0] = 's'; buf[1] = 's'; buf[2] = 's'; buf[3] = '\0';
    buf[4] = 1;       /* version */
    buf[5] = 0;       /* spare */
    buf[6] = 0;       /* kn_size: no named key */
    buf[7] = XROOTD_SSS_ENC_BF32;
    key_id_be = (uint64_t) key->id;
    /* Write as 8-byte BE */
    buf[ 8] = (u_char) (key_id_be >> 56);
    buf[ 9] = (u_char) (key_id_be >> 48);
    buf[10] = (u_char) (key_id_be >> 40);
    buf[11] = (u_char) (key_id_be >> 32);
    buf[12] = (u_char) (key_id_be >> 24);
    buf[13] = (u_char) (key_id_be >> 16);
    buf[14] = (u_char) (key_id_be >>  8);
    buf[15] = (u_char)  key_id_be;

    *out_len = XROOTD_SSS_HDR_LEN + crypt_out;
    return NGX_OK;
}


/*
 * xrootd_handle_sss_auth — process an XRootD Simple Shared Secret (SSS) auth
 * request.
 *
 * Wire format (outer packet, before decryption):
 *   [4-byte magic "sss\0"][1-byte version][1-byte ???][1-byte kn_size]
 *   [1-byte enc_type='0' (BF32)][8-byte key-id BE][kn_size-byte key-name]
 *   [N bytes: Blowfish-CFB64 encrypted cleartext + 4-byte CRC32]
 *
 * Verification steps:
 *   1. Magic and encryption type check.
 *   2. Look up the 8-byte key-id in conf->sss_keys; reject if not found or
 *      expired.  Prevents replay with a different (possibly stolen) key.
 *   3. Decrypt with Blowfish-CFB64 (key->key, zero IV).
 *   4. Verify CRC32 of the cleartext.  Detects decryption with wrong key.
 *   5. Check timestamp: gen_time must be within conf->sss_lifetime seconds
 *      of the server's current epoch.  Prevents credential replay.
 *   6. If options == XROOTD_SSS_OPT_SNDLID, send kXR_authmore challenge
 *      asking the client to include its local identity.
 *   7. Parse the TLV identity block.  Map name/group according to key opts.
 *
 * The login ctx is connection-scoped: ctx->dn and ctx->vo_list are set here
 * and persist for all subsequent requests on this TCP connection.
 *
 * Returns: NGX_OK on success (response sent), NGX_ERROR on fatal error.
 */
ngx_int_t
xrootd_handle_sss_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    const xrootd_sss_key_t *key;
    xrootd_sss_identity_t  id;
    const u_char          *payload, *cipher;
    u_char                *clear;
    size_t                 hdr_len, cipher_len, out_len, clear_len;
    uint8_t                kn_size, options;
    int64_t                key_id;
    uint32_t               got_crc, want_crc, gen_time, now;
    const char            *user, *group;

    payload = ctx->payload;
    if (payload == NULL || ctx->cur_dlen < XROOTD_SSS_HDR_LEN
        + XROOTD_SSS_DATA_HDR_LEN + 4)
    {
        return xrootd_sss_auth_failed(ctx, c);
    }

    if (payload[0] != 's' || payload[1] != 's' || payload[2] != 's'
        || payload[3] != '\0' || payload[7] != XROOTD_SSS_ENC_BF32)
    {
        return xrootd_sss_auth_failed(ctx, c);
    }

    kn_size = payload[6];
    if (kn_size != 0
        && (kn_size > XROOTD_SSS_NAME_MAX || (kn_size & 0x07)))
    {
        return xrootd_sss_auth_failed(ctx, c);
    }

    hdr_len = XROOTD_SSS_HDR_LEN + kn_size;
    if (hdr_len >= ctx->cur_dlen || (kn_size && payload[hdr_len - 1] != '\0')) {
        return xrootd_sss_auth_failed(ctx, c);
    }

    key_id = (int64_t) xrootd_sss_read_be64(payload + 8);
    key = xrootd_sss_find_key(conf, key_id);
    if (key == NULL) {
        return xrootd_sss_auth_failed(ctx, c);
    }

    cipher = payload + hdr_len;
    cipher_len = ctx->cur_dlen - hdr_len;
    if (cipher_len <= 4) {
        return xrootd_sss_auth_failed(ctx, c);
    }

    clear = ngx_palloc(c->pool, cipher_len);
    if (clear == NULL) {
        return NGX_ERROR;
    }

    if (xrootd_sss_bf32_crypt(0, key->key, key->key_len,
                              cipher, cipher_len, clear, cipher_len, &out_len)
        != NGX_OK)
    {
        return xrootd_sss_auth_failed(ctx, c);
    }

    if (out_len <= 4) {
        return xrootd_sss_auth_failed(ctx, c);
    }

    clear_len = out_len - 4;
    got_crc = xrootd_sss_read_be32(clear + clear_len);
    want_crc = xrootd_sss_crc32(clear, clear_len);
    /* Wrong-key detection: a CRC mismatch means either the wrong key was
     * used for decryption or the ciphertext was tampered with. */
    if (got_crc != want_crc || clear_len < XROOTD_SSS_DATA_HDR_LEN) {
        return xrootd_sss_auth_failed(ctx, c);
    }

    gen_time = xrootd_sss_read_be32(clear + 32);
    now = (uint32_t) (ngx_time() - XROOTD_SSS_BASE_TIME);
    /* Credential replay prevention: reject tokens older than sss_lifetime. */
    if (gen_time + (uint32_t) conf->sss_lifetime <= now) {
        return xrootd_sss_auth_failed(ctx, c);
    }

    options = clear[39];
    if (options == XROOTD_SSS_OPT_SNDLID) {
        return xrootd_sss_send_authmore(ctx, c, key, payload, hdr_len);
    }

    if (xrootd_sss_parse_identity(clear + XROOTD_SSS_DATA_HDR_LEN,
                                  clear_len - XROOTD_SSS_DATA_HDR_LEN,
                                  &id)
        != NGX_OK)
    {
        return xrootd_sss_auth_failed(ctx, c);
    }

    user = key->user;
    if (key->opts & (XROOTD_SSS_OPT_ANYUSR | XROOTD_SSS_OPT_ALLUSR)) {
        user = id.name[0] ? id.name : "nobody";
    }

    group = "";
    if (!(key->opts & XROOTD_SSS_OPT_USRGRP)) {
        if (key->opts & XROOTD_SSS_OPT_ANYGRP) {
            group = id.grps[0] ? id.grps : "nogroup";
        } else {
            group = key->group;
        }
    }

    ctx->auth_done = 1;
    ctx->token_auth = 0;
    ngx_cpystrn((u_char *) ctx->dn, (u_char *) user, sizeof(ctx->dn));
    if (group[0]) {
        ngx_cpystrn((u_char *) ctx->vo_list, (u_char *) group,
                    sizeof(ctx->vo_list));
        ngx_cpystrn((u_char *) ctx->primary_vo, (u_char *) group,
                    sizeof(ctx->primary_vo));
    }

    /* Track unique user and VO at auth completion. */
    {
        ngx_xrootd_metrics_t *shm = xrootd_metrics_shared();
        if (shm != NULL) {
            size_t vo_len = strlen(ctx->primary_vo);
            if (vo_len > 0 && vo_len < sizeof(ctx->primary_vo)) {
                xrootd_track_vo_activity(shm, ctx->primary_vo, 0, 0);
                ngx_uint_t vi;
                for (vi = 0; vi < XROOTD_VO_MAX_TRACKED; vi++) {
                    if (ngx_strncmp(shm->vo_global.slots[vi].name, ctx->primary_vo,
                                    XROOTD_VO_NAME_LEN) == 0)
                    {
                        XROOTD_ATOMIC_INC(&shm->vo_global.slots[vi].requests_total);
                        break;
                    }
                }
            }
            xrootd_track_unique_user(shm, ctx->dn, strlen(ctx->dn));
        }
    }

    xrootd_session_register(ctx->sessid, ctx->dn, ctx->vo_list, 0);

    {
        char safe_user[256], safe_group[256];
        xrootd_sanitize_log_string(user, safe_user, sizeof(safe_user));
        xrootd_sanitize_log_string(group[0] ? group : "-",
                                   safe_group, sizeof(safe_group));
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: SSS auth OK user=\"%s\" group=\"%s\"",
                      safe_user, safe_group);
    }

    xrootd_log_access(ctx, c, "AUTH", "-", user, 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_AUTH);

    return xrootd_send_ok(ctx, c, NULL, 0);
}
