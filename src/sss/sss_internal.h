/*
 * sss_internal.h — SSS (Simple Shared Secret) wire constants, types, and
 * helper function declarations shared across auth_crypto_helpers.c,
 * auth_identity_challenge.c, auth_proxy_credential.c, and auth_request.c.
 *
 * Include after "../ngx_xrootd_module.h".
 */
#ifndef XROOTD_SSS_SSS_INTERNAL_H
#define XROOTD_SSS_SSS_INTERNAL_H

#include "ngx_xrootd_module.h"
#include "protocol/sss.h"   /* shared SSS wire constants (single source of truth) */

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

/* Array-based key lookup (same semantics as find_key but without a srv_conf —
 * used by callers that hold an sss_keys array directly, e.g. the CMS module). */
const xrootd_sss_key_t *xrootd_sss_find_key_arr(ngx_array_t *keys, int64_t id);

/*
 * xrootd_sss_verify_blob — validate a self-contained SSS credential against a
 * keytab, transport-independent (used by both the XRootD kXR_auth path and the
 * CMS kYR_xauth handshake).
 *
 * Performs the full verification chain: outer "sss\0"+BF32 header, key-id
 * lookup, Blowfish-CFB64 decrypt, CRC32 wrong-key detection, timestamp replay
 * window (lifetime seconds), and identity TLV parse.  Only the self-contained
 * USEDATA credential form is accepted; the interactive SNDLID (server-supplies
 * login-id) form returns NGX_DECLINED so the caller can reject it explicitly.
 *
 * Returns NGX_OK with *id_out filled and *key_out set to the matched key on
 * success; NGX_DECLINED for an unsupported SNDLID credential; NGX_ERROR for any
 * malformed/forged/expired credential (err filled).  Does not allocate.
 */
ngx_int_t xrootd_sss_verify_blob(ngx_array_t *keys, time_t lifetime,
    const u_char *blob, size_t blob_len,
    xrootd_sss_identity_t *id_out, const xrootd_sss_key_t **key_out,
    char *err, size_t errsz);

/* ---- auth_identity_challenge.c ------------------------------------- */

/* Parse TAG-LEN-VALUE identity records from the decrypted cleartext body. */
ngx_int_t xrootd_sss_parse_identity(const u_char *data, size_t len,
    xrootd_sss_identity_t *id);

/* Send a kXR_error(kXR_NotAuthorized) and log the failure. */
ngx_int_t xrootd_sss_auth_failed(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* Encrypt a challenge with key and send a kXR_authmore response. */
ngx_int_t xrootd_sss_send_authmore(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const xrootd_sss_key_t *key, const u_char *hdr, size_t hdr_len);

#endif /* XROOTD_SSS_SSS_INTERNAL_H */
