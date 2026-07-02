#include "sss_internal.h"
#include "path/path.h"
#include "response/response.h"
#include "session/registry.h"

#include <openssl/crypto.h>
#include <string.h>
#include "core/compat/alloc_guard.h"

/* Handle the kXR_auth SSS (XrdSecsss shared-secret) credential: verify the
 * client token against the keytab, set the identity/session, and return kXR_ok
 * or kXR_error. */
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

    XROOTD_PALLOC_OR_RETURN(clear, c->pool, cipher_len, NGX_ERROR);

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

    /* Zero the decrypted credential buffer before it ages in the pool.
     * Prevents plaintext identity data from lingering across later requests. */
    OPENSSL_cleanse(clear, cipher_len);

    ctx->auth_done = 1;
    ctx->token_auth = 0;
    ngx_cpystrn((u_char *) ctx->dn, (u_char *) user, sizeof(ctx->dn));
    if (group[0]) {
        ngx_cpystrn((u_char *) ctx->vo_list, (u_char *) group,
                    sizeof(ctx->vo_list));
        ngx_cpystrn((u_char *) ctx->primary_vo, (u_char *) group,
                    sizeof(ctx->primary_vo));
    }
    if (ctx->identity != NULL) {
        if (xrootd_identity_set_dn(ctx->identity, c->pool, ctx->dn,
                                   XROOTD_AUTHN_SSS) != NGX_OK
            || xrootd_identity_set_vos_csv(ctx->identity, c->pool,
                                           ctx->vo_list) != NGX_OK)
        {
            return xrootd_send_error(ctx, c, kXR_NoMemory,
                                     "identity allocation failed");
        }
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

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", user, 0);
}
