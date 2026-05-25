/*
 * sss_internal.h — SSS (Simple Shared Secret) wire constants, types, and
 * helper function declarations shared across auth_crypto_helpers.c,
 * auth_identity_challenge.c, auth_proxy_credential.c, and auth_request.c.
 *
 * Include after "../ngx_xrootd_module.h".
 */
#pragma once

#include "../ngx_xrootd_module.h"

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

/*
 * xrootd_sss_identity_t — decoded identity fields from an SSS cleartext
 * payload.  Populated by xrootd_sss_parse_identity().
 */
typedef struct {
    char name[256];
    char grps[512];
    char host[256];
    char ip[128];
    int  id_count;
} xrootd_sss_identity_t;

/* ---- auth_crypto_helpers.c ---------------------------------------- */

/* Big-endian wire accessors. */
uint32_t xrootd_sss_read_be32(const u_char *p);
uint64_t xrootd_sss_read_be64(const u_char *p);
void     xrootd_sss_write_be32(u_char *p, uint32_t v);

/* CRC32 over the cleartext payload (used for integrity check). */
uint32_t xrootd_sss_crc32(const u_char *p, size_t len);

/* Blowfish-CFB64 encrypt/decrypt.  encrypt=1 → encrypt, 0 → decrypt. */
ngx_int_t xrootd_sss_bf32_crypt(int encrypt, const u_char *key, size_t key_len,
    const u_char *src, size_t src_len, u_char *dst, size_t dst_len,
    size_t *out_len);

/* Look up a configured SSS key by wire id; returns NULL if not found/expired. */
const xrootd_sss_key_t *xrootd_sss_find_key(
    ngx_stream_xrootd_srv_conf_t *conf, int64_t id);

/* ---- auth_identity_challenge.c ------------------------------------- */

/* Parse TAG-LEN-VALUE identity records from the decrypted cleartext body. */
ngx_int_t xrootd_sss_parse_identity(const u_char *data, size_t len,
    xrootd_sss_identity_t *id);

/* Send a kXR_error(kXR_NotAuthorized) and log the failure. */
ngx_int_t xrootd_sss_auth_failed(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* Encrypt a challenge with key and send a kXR_authmore response. */
ngx_int_t xrootd_sss_send_authmore(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const xrootd_sss_key_t *key, const u_char *hdr, size_t hdr_len);
