/*
 * auth.c — XRootD `pwd` (XrdSecpwd) password authentication handler — WS-B.
 *
 * WHAT: Implements the kXR_auth handler for the XRootD `pwd` security protocol as
 *       a 2-round DH-bootstrapped exchange:
 *         round 1  client → kXRS_puk(client DH pub) + kXRS_user;
 *                  server → kXR_authmore: kXRS_puk(server DH pub) + credsreq.
 *         round 2  client → kXRS_main = DH-session-encrypted { kXRS_creds };
 *                  server → kXR_ok iff PBKDF2(password, salt) == stored hash.
 *
 * WHY:  pwd is XRootD's legacy password scheme.  It is opt-in (conf->auth ==
 *       BRIX_AUTH_PWD), requires brix_pwd_file (empty = deny all), and SHOULD
 *       run only under TLS (the password is recoverable by the server, and the
 *       credential is only DH-session-encrypted on the wire).  Isolating it here
 *       keeps the password surface in one auditable place.
 *
 * HOW:  Reuses the shared GSI DH + session-cipher primitives (src/gsi/gsi_core.c)
 *       for the key agreement and the kXRS_main encryption, and the XrdSut bucket
 *       kernels for the wire.  The password never touches disk in cleartext — the
 *       check is PBKDF2-HMAC-SHA1 against brix_pwd_file (src/pwd/pwdfile.c).
 *
 * Wire reference: docs/refactor/phase-52-pwd-wire-spec.md.  Interop scope: this
 * exchanges DH publics in-band (no pre-shared srvpuk) and omits the mutual rtag
 * verification, so it is verified our-client ↔ our-server; full stock-XrdSecpwd
 * byte-interop (pre-shared srvpuk + 3-RT rtag) is a documented follow-on.
 */
#include "core/ngx_brix_module.h"
#include "protocols/root/session/registry.h"
#include "auth/gsi/gsi_core.h"
#include "protocols/root/protocol/gsi.h"
#include "pwd.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <string.h>

/*
 * pwd_status_word — marshal a pwdStatus_t {ctype,action,options} into the 4-byte
 * big-endian word stock XrdSecpwd puts in kXRS_status (it htonl's the whole struct
 * image; XrdSecProtocolpwd.cc:1127-1130).  ctype/action are bytes 0/1, options is
 * the low 2 bytes, then the 4-byte host image is htonl'd.
 */
static uint32_t
pwd_status_word(uint8_t ctype, uint8_t action, uint16_t options)
{
    uint8_t  img[4];

    img[0] = ctype;
    img[1] = action;
    img[2] = (uint8_t) (options & 0xff);
    img[3] = (uint8_t) (options >> 8);
    return htonl(*(uint32_t *) img);
}

/*
 * pwd_send_credsreq — round-1 reply: kXR_authmore carrying the server DH public
 * (so the client can derive the same session key) and a credsreq status word.
 */
static ngx_int_t
pwd_send_credsreq(brix_ctx_t *ctx, ngx_connection_t *c, EVP_PKEY *srv)
{
    brix_gbuf  g;
    char        *pub;
    size_t       pub_len = 0;
    uint32_t     status;
    u_char      *buf;
    size_t       total;

    pub = brix_gsi_cipher_public(srv, &pub_len);
    if (pub == NULL) {
        return brix_send_error(ctx, c, kXR_ServerError,
                                 "pwd: cannot encode server key");
    }

    status = pwd_status_word(kpCT_normal, 0, 0);

    brix_gbuf_init(&g);
    brix_gbuf_raw(&g, "pwd", 4);                 /* protocol name + NUL */
    brix_gbuf_u32(&g, kXPS_credsreq);            /* step */
    brix_gbuf_bucket(&g, kXRS_puk, pub, pub_len);
    brix_gbuf_bucket(&g, kXRS_status, &status, sizeof(status));
    brix_gbuf_end(&g);                           /* kXRS_none */
    free(pub);                                     /* malloc'd by cipher_public */

    if (g.err) {
        brix_gbuf_free(&g);
        return brix_send_error(ctx, c, kXR_NoMemory, "pwd: out of memory");
    }

    total = XRD_RESPONSE_HDR_LEN + g.len;
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        brix_gbuf_free(&g);
        return brix_send_error(ctx, c, kXR_NoMemory, "pwd: out of memory");
    }
    brix_build_resp_hdr(ctx->cur_streamid, kXR_authmore,
                          (uint32_t) g.len, (ServerResponseHdr *) buf);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, g.p, g.len);
    brix_gbuf_free(&g);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: pwd round 1 → credsreq (srv puk %uz B)", pub_len);
    return brix_queue_response(ctx, c, buf, total);
}

/*
 * pwd_round1 — establish the DH session key from the client's kXRS_puk, record the
 * asserted user, and ask for the credential.  The user is NOT looked up yet (that
 * happens at round 2, with the password in hand, to avoid a user-enumeration
 * oracle on the cheap first round).
 */
static ngx_int_t
pwd_round1(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    const uint8_t  *puk, *user;
    size_t          puk_len = 0, user_len = 0;
    EVP_PKEY       *peer, *srv;
    int             ok;

    (void) conf;

    if (brix_gsi_find_bucket(ctx->payload, ctx->cur_dlen,
                               (uint32_t) kXRS_puk, &puk, &puk_len) != 0
        || brix_gsi_find_bucket(ctx->payload, ctx->cur_dlen,
                                  (uint32_t) kXRS_user, &user, &user_len) != 0
        || user_len == 0 || user_len >= sizeof(ctx->pwd_user))
    {
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_PWD, 0);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "pwd",
                          kXR_NotAuthorized, "malformed pwd credential");
    }

    peer = brix_gsi_cipher_parse_peer(puk, puk_len);
    if (peer == NULL) {
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_PWD, 0);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "pwd",
                          kXR_NotAuthorized, "pwd: bad client key");
    }
    srv = brix_gsi_cipher_keygen_from(peer);
    if (srv == NULL) {
        EVP_PKEY_free(peer);
        return brix_send_error(ctx, c, kXR_ServerError, "pwd: keygen failed");
    }
    ok = brix_gsi_cipher_session_key(srv, peer, 0, ctx->pwd_session_key,
                                       BRIX_PWD_SESSION_KEYLEN);
    EVP_PKEY_free(peer);
    if (!ok) {
        EVP_PKEY_free(srv);
        return brix_send_error(ctx, c, kXR_ServerError,
                                 "pwd: key agreement failed");
    }

    ngx_memcpy(ctx->pwd_user, user, user_len);
    ctx->pwd_user[user_len] = '\0';
    ctx->pwd_round = 1;

    {
        ngx_int_t rc = pwd_send_credsreq(ctx, c, srv);
        EVP_PKEY_free(srv);
        return rc;
    }
}

/*
 * pwd_round2 — decrypt the credential with the DH session key and verify it
 * (PBKDF2-HMAC-SHA1) against the stored hash for the round-1 user.  On success the
 * connection is authenticated AS that user.
 */
static ngx_int_t
pwd_round2(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    const uint8_t       *main_blob, *creds;
    size_t               main_len = 0, creds_len = 0, plain_len = 0;
    uint8_t             *plain;
    brix_gsi_cipher_t  cipher;
    uint8_t              salt[BRIX_PWD_MAX_SALT];
    uint8_t              hash[BRIX_PWD_HASH_LEN];
    size_t               saltlen = 0, hashlen = 0;
    char                 pwdpath[1024];
    int                  verified;

    if (conf->pwd_file.len == 0 || conf->pwd_file.len >= sizeof(pwdpath)) {
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_PWD, 0);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "pwd",
                          kXR_NotAuthorized, "pwd auth not configured");
    }

    if (brix_gsi_find_bucket(ctx->payload, ctx->cur_dlen,
                               (uint32_t) kXRS_main, &main_blob, &main_len) != 0
        || !brix_gsi_cipher_lookup("aes-128-cbc", &cipher))
    {
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_PWD, 0);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "pwd",
                          kXR_NotAuthorized, "malformed pwd credential");
    }

    plain = brix_gsi_cipher_decrypt(&cipher, ctx->pwd_session_key,
                                      main_blob, main_len, 0, &plain_len);
    OPENSSL_cleanse(ctx->pwd_session_key, sizeof(ctx->pwd_session_key));
    if (plain == NULL
        || brix_gsi_find_bucket(plain, plain_len, (uint32_t) kXRS_creds,
                                  &creds, &creds_len) != 0
        || creds_len == 0)
    {
        if (plain != NULL) {
            OPENSSL_cleanse(plain, plain_len);
            free(plain);
        }
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_PWD, 0);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "pwd",
                          kXR_NotAuthorized, "pwd: credential decrypt failed");
    }

    ngx_memcpy(pwdpath, conf->pwd_file.data, conf->pwd_file.len);
    pwdpath[conf->pwd_file.len] = '\0';

    verified = 0;
    if (brix_pwd_file_lookup(pwdpath, ctx->pwd_user, salt, &saltlen,
                               hash, &hashlen) == NGX_OK)
    {
        verified = brix_pwd_verify(creds, creds_len, salt, saltlen,
                                     hash, hashlen);
    }
    OPENSSL_cleanse(plain, plain_len);
    free(plain);
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(hash, sizeof(hash));

    if (!verified) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                      "xrootd: pwd auth denied for user (bad credential)");
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_PWD, 0);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "pwd",
                          kXR_NotAuthorized, "invalid password");
    }

    ctx->auth_done = 1;
    ctx->token_auth = 0;
    ngx_cpystrn((u_char *) ctx->dn, (u_char *) ctx->pwd_user, sizeof(ctx->dn));
    ctx->vo_list[0] = '\0';
    ctx->primary_vo[0] = '\0';

    if (ctx->identity != NULL
        && brix_identity_set_dn(ctx->identity, c->pool, ctx->dn,
                                  BRIX_AUTHN_PWD) != NGX_OK)
    {
        return brix_send_error(ctx, c, kXR_NoMemory,
                                 "identity allocation failed");
    }

    brix_session_register(ctx->sessid, ctx->dn, ctx->vo_list, 0);

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "xrootd: pwd auth OK user=\"%s\"",
                  ctx->dn);
    brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_PWD, 1);
    BRIX_RETURN_OK(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "pwd", 0);
}

ngx_int_t
brix_handle_pwd_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    if (ctx->payload == NULL || ctx->cur_dlen < 8
        || ngx_strncmp(ctx->payload, "pwd", 4) != 0)
    {
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_PWD, 0);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "pwd",
                          kXR_NotAuthorized, "malformed pwd credential");
    }

    if (ctx->pwd_round == 0) {
        return pwd_round1(ctx, c, conf);
    }
    return pwd_round2(ctx, c, conf);
}
