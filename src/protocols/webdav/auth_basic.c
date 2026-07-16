/*
 * auth_basic.c — HTTP Basic password authentication for WebDAV/HTTP exports.
 *
 * WHAT: Verifies an `Authorization: Basic <base64 user:password>` header
 *       against the same PBKDF2 password db (`user:salthex:hashhex[:vo,..]`)
 *       the stream-side `brix_auth pwd` uses, and stamps the request identity
 *       (dn = username, BRIX_AUTHN_PWD, VO list from the entry's 4th field).
 *
 * WHY:  Gives http(s):// and dav(s):// clients the same low-friction
 *       username/password entry point root:// has (curl -u, browsers, simple
 *       tooling) without inventing a second credential store.  Password auth
 *       is poor practice for production — the config-time summary warns
 *       loudly — but it is invaluable for labs and first-run setups.
 *
 * HOW:  Opt-in via `brix_webdav_pwd_file`; returns NGX_DECLINED when
 *       unconfigured, when no Basic header is present, or when the credential
 *       fails verification (so the auth policy in access.c decides between
 *       anonymous fallback and 403).  Verification is brix_pwd_file_lookup +
 *       brix_pwd_verify (PBKDF2-HMAC-SHA1, constant-time compare).  On success
 *       the req ctx is created/marked verified exactly like the cert/token
 *       tiers, so authdb/VO ACLs and identity-aware backends (e.g. pblock's
 *       catalog-internal ownership) see one canonical identity object.
 */

#include "webdav.h"
#include "webdav_auth.h"
#include "auth/pwd/pwd.h"

#include <limits.h>
#include <string.h>

/*
 * WHAT: Extract and base64-decode the Basic credential from the request's
 *       Authorization header into a NUL-terminated `user` cstring and a
 *       password byte range.  NGX_OK, or NGX_DECLINED (absent header,
 *       different scheme, malformed base64/credential) — never an error the
 *       caller must distinguish, so other credential tiers can still run.
 *
 * WHY: RFC 7617 credential parsing kept out of the verify path so the crypto
 *      step reads linearly; the decoded buffer is pool-owned, letting the
 *      username be NUL-terminated in place for the C-string pwd-file API.
 *
 * HOW: Case-insensitive "Basic" match, skip the separating spaces, decode
 *      with ngx_decode_base64, split at the FIRST ':' (passwords may contain
 *      colons).  An empty username is rejected; an empty password is left to
 *      the verifier (it will not match any stored hash).
 */
static ngx_int_t
wb_parse_basic_userpass(ngx_http_request_t *r, ngx_str_t *user,
    ngx_str_t *pass)
{
    ngx_table_elt_t *h = r->headers_in.authorization;
    ngx_str_t        b64, plain;
    u_char          *colon;

    if (h == NULL || h->value.len < sizeof("Basic ") - 1
        || ngx_strncasecmp(h->value.data, (u_char *) "Basic ",
                           sizeof("Basic ") - 1) != 0)
    {
        return NGX_DECLINED;
    }

    b64.data = h->value.data + sizeof("Basic ") - 1;
    b64.len  = h->value.len - (sizeof("Basic ") - 1);
    while (b64.len > 0 && b64.data[0] == ' ') {
        b64.data++;
        b64.len--;
    }
    if (b64.len == 0) {
        return NGX_DECLINED;
    }

    plain.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(b64.len) + 1);
    if (plain.data == NULL) {
        return NGX_DECLINED;
    }
    if (ngx_decode_base64(&plain, &b64) != NGX_OK) {
        return NGX_DECLINED;
    }
    plain.data[plain.len] = '\0';

    colon = memchr(plain.data, ':', plain.len);
    if (colon == NULL || colon == plain.data) {
        return NGX_DECLINED;
    }

    user->data = plain.data;
    user->len  = (size_t) (colon - plain.data);
    *colon     = '\0';
    pass->data = colon + 1;
    pass->len  = plain.len - user->len - 1;
    return NGX_OK;
}

/*
 * WHAT: Get-or-create the WebDAV request context with an attached identity.
 *       Returns the ctx or NULL on allocation failure.
 *
 * WHY: Basic auth may be the FIRST credential tier that runs on a plain-http
 *      listener (no TLS handshake created a ctx), so it must be able to
 *      create the ctx the later authz/backends stages read.
 *
 * HOW: Mirrors the cert/token tiers' ensure step: ngx_http_get_module_ctx,
 *      allocate+attach on NULL, back-fill a missing identity.
 */
static ngx_http_brix_webdav_req_ctx_t *
wb_ensure_ctx(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            return NULL;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_brix_webdav_module);
    }
    if (ctx->identity == NULL) {
        ctx->identity = brix_identity_alloc(r->pool);
        if (ctx->identity == NULL) {
            return NULL;
        }
    }
    return ctx;
}

/*
 * WHAT: The Basic-password auth gate: verify the request's Basic credential
 *       against conf->pwd_file and mark the request authenticated (dn =
 *       username, BRIX_AUTHN_PWD, VOs from the entry).  NGX_OK on success;
 *       NGX_DECLINED when unconfigured/absent/invalid (policy decides);
 *       NGX_HTTP_INTERNAL_SERVER_ERROR on allocation failure.
 *
 * WHY: Completes credential parity with root:// so operators can test every
 *      protocol scheme with one pwd db; runs LAST in the tier order (cert,
 *      token, basic) so stronger credentials always win.
 *
 * HOW: Parse header → pwd-file lookup → constant-time PBKDF2 verify → stamp
 *      req ctx + identity.  A failed verify logs at NOTICE and counts a
 *      failed BRIX_AUTHN_PWD auth, matching the stream-side behaviour.
 */
ngx_int_t
webdav_verify_basic_pwd(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_http_brix_webdav_req_ctx_t *ctx;
    ngx_str_t   user, pass;
    char        path[PATH_MAX];
    uint8_t     salt[BRIX_PWD_MAX_SALT];
    uint8_t     hash[BRIX_PWD_HASH_LEN];
    size_t      saltlen = 0, hashlen = 0;
    char        vos[512];
    int         verified = 0;

    if (conf->pwd_file.len == 0 || conf->pwd_file.len >= sizeof(path)) {
        return NGX_DECLINED;
    }
    if (wb_parse_basic_userpass(r, &user, &pass) != NGX_OK) {
        return NGX_DECLINED;
    }

    ngx_memcpy(path, conf->pwd_file.data, conf->pwd_file.len);
    path[conf->pwd_file.len] = '\0';

    vos[0] = '\0';
    if (brix_pwd_file_lookup(path, (const char *) user.data, salt, &saltlen,
                               hash, &hashlen, vos, sizeof(vos)) == NGX_OK)
    {
        verified = brix_pwd_verify(pass.data, pass.len, salt, saltlen,
                                     hash, hashlen);
    }
    ngx_memzero(salt, sizeof(salt));
    ngx_memzero(hash, sizeof(hash));

    if (!verified) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "brix_webdav: Basic pwd auth denied for user \"%s\"",
                      user.data);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_PWD, 0);
        return NGX_DECLINED;
    }

    ctx = wb_ensure_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_cpystrn((u_char *) ctx->dn, user.data, sizeof(ctx->dn));
    ctx->verified = 1;
    ctx->auth_source = "basic";

    if (brix_identity_set_dn(ctx->identity, r->pool, ctx->dn,
                               BRIX_AUTHN_PWD) != NGX_OK
        || (vos[0] != '\0'
            && brix_identity_set_vos_csv(ctx->identity, r->pool,
                                           vos) != NGX_OK))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "brix_webdav: Basic pwd auth OK user=\"%s\"", ctx->dn);
    return NGX_OK;
}
