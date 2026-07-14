#include "dashboard_auth_internal.h"
#include "core/compat/alloc_guard.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <crypt.h>

/*
 * dashboard/dashboard_auth_creds.c — credential store and session-cookie HMAC
 * for the dashboard authentication unit (split from auth.c, phase-79).
 *
 * WHAT: The configured-user lookup and password verification (crypt(3) hash or
 *       legacy plaintext, both constant-time) plus the HMAC-SHA256 signature
 *       derivation that binds a session cookie to its key/message.
 *
 * WHY: This is the security core shared by the login flow (mint a cookie) and
 *       the verification path (recompute a cookie's signature). Keeping the
 *       credential comparison and the signed-message construction in one place
 *       guarantees issue-time and verify-time agree byte-for-byte. Behaviour is
 *       identical to the original auth.c — the same message layouts, the same
 *       CRYPTO_memcmp comparisons, the same caps.
 */

/*
 * WHAT: Compute HMAC-SHA256(key, msg) and emit it as 64 lowercase hex chars.
 * HOW:  out_hex must hold HMAC_HEX_LEN + 1 bytes; each of the 32 digest bytes
 *       becomes two hex chars, then a trailing NUL is written.
 */
static void
hmac_sha256_hex(const u_char *key, size_t key_len,
    const char *msg, size_t msg_len,
    char out_hex[HMAC_HEX_LEN + 1])
{
    u_char  digest[32];
    u_int   digest_len = sizeof(digest);
    int     i;

    HMAC(EVP_sha256(), key, (int) key_len,
         (const u_char *) msg, msg_len, digest, &digest_len);

    /* Byte i of the digest maps to hex chars [2*i, 2*i+1]; snprintf's size-3
     * cap covers the two hex digits plus its own NUL (overwritten next loop). */
    for (i = 0; i < 32; i++) {
        snprintf(out_hex + i * 2, 3, "%02x", (unsigned int) digest[i]);
    }
    out_hex[HMAC_HEX_LEN] = '\0';
}

ngx_uint_t
dashboard_users_enabled(const ngx_http_brix_dashboard_loc_conf_t *conf)
{
    return conf->users != NULL && conf->users->nelts > 0;
}

/* Linear lookup of a configured user by exact username; NULL if absent or the
 * multi-user mode is not enabled. Used by both login and cookie verification. */
ngx_http_brix_dashboard_user_t *
dashboard_find_user(const ngx_http_brix_dashboard_loc_conf_t *conf,
    const char *username, size_t username_len)
{
    ngx_http_brix_dashboard_user_t *users;
    ngx_uint_t                        i;

    if (!dashboard_users_enabled(conf) || username == NULL) {
        return NULL;
    }

    users = conf->users->elts;
    for (i = 0; i < conf->users->nelts; i++) {
        if (users[i].username.len == username_len
            && ngx_memcmp(users[i].username.data, username, username_len) == 0)
        {
            return &users[i];
        }
    }

    return NULL;
}

/* Copy an ngx_str_t (not NUL-terminated) into a fresh pool-allocated C string.
 * Needed because crypt()/strlen() require a NUL terminator. */
static ngx_int_t
dashboard_copy_str0(ngx_pool_t *pool, ngx_str_t *src, char **out)
{
    char *dst;

    BRIX_PNALLOC_OR_RETURN(dst, pool, src->len + 1, NGX_ERROR);

    ngx_memcpy(dst, src->data, src->len);
    dst[src->len] = '\0';
    *out = dst;
    return NGX_OK;
}

/*
 * WHAT: Verify a plaintext password against a stored user credential.
 * WHY:  htpasswd-style files may contain either a crypt(3) hash (modern, leading
 *       '$id$' marker) or — for legacy/test configs — a literal plaintext value.
 * HOW:  '$'-prefixed -> run crypt() with the stored hash as the salt and compare
 *       the re-derived hash; otherwise fall back to a direct byte comparison.
 *       Both comparisons use CRYPTO_memcmp to avoid leaking length/content via
 *       timing. Returns NGX_OK / NGX_DECLINED / NGX_ERROR (alloc failure).
 */
ngx_int_t
dashboard_verify_user_password(ngx_pool_t *pool,
    ngx_http_brix_dashboard_user_t *user,
    const char *password, size_t password_len)
{
    char *hash;
    char *candidate;
    char *plain;

    if (user == NULL || password == NULL) {
        return NGX_DECLINED;
    }

    if (dashboard_copy_str0(pool, &user->password_hash, &hash) != NGX_OK) {
        return NGX_ERROR;
    }

    /* crypt() needs a NUL-terminated plaintext copy (the wire password is not). */
    BRIX_PNALLOC_OR_RETURN(plain, pool, password_len + 1, NGX_ERROR);
    ngx_memcpy(plain, password, password_len);
    plain[password_len] = '\0';

    /* crypt(3) hash: the stored hash doubles as the salt; crypt re-derives the
     * full hash string, which must match byte-for-byte (incl. length). */
    if (hash[0] == '$') {
        candidate = crypt(plain, hash);
        if (candidate == NULL) {
            return NGX_DECLINED;
        }
        if (strlen(candidate) == strlen(hash)
            && CRYPTO_memcmp(candidate, hash, strlen(hash)) == 0)
        {
            return NGX_OK;
        }
        return NGX_DECLINED;
    }

    /* Legacy plaintext credential: constant-time equality of raw bytes. */
    if (password_len == user->password_hash.len
        && CRYPTO_memcmp(password, user->password_hash.data, password_len) == 0)
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}

/*
 * WHAT: Derive the cookie signature for a session.
 * WHY:  The signed message MUST be identical at issue (login) and verify time or
 *       the constant-time compare fails. The two auth modes sign different msgs:
 *         single-user  -> HMAC(password,        "<ts>")
 *         multi-user    -> HMAC(user_pw_hash,    "<ts>.<username>")
 *       Binding the username into the multi-user message prevents a cookie issued
 *       for one user being replayed as another. `out_hex` must hold
 *       HMAC_HEX_LEN + 1 bytes.
 * HOW:  msg[] is sized for "<ts>.<username>" (TIMESTAMP_MAX + '.' + 256 + NUL);
 *       inputs longer than those caps are rejected to avoid overflow.
 */
ngx_int_t
dashboard_cookie_hmac(const ngx_str_t *key, const char *ts, size_t ts_len,
    const char *username, size_t username_len,
    char out_hex[HMAC_HEX_LEN + 1])
{
    char   msg[TIMESTAMP_MAX + 1 + 256 + 1];
    size_t msg_len;

    /* Single-user mode: sign the bare timestamp only. */
    if (username == NULL) {
        hmac_sha256_hex(key->data, key->len, ts, ts_len, out_hex);
        return NGX_OK;
    }

    if (username_len > 256 || ts_len > TIMESTAMP_MAX) {
        return NGX_DECLINED;
    }

    /* Multi-user mode: sign "<ts>.<username>". */
    ngx_memcpy(msg, ts, ts_len);
    msg[ts_len] = '.';
    ngx_memcpy(msg + ts_len + 1, username, username_len);
    msg_len = ts_len + 1 + username_len;
    hmac_sha256_hex(key->data, key->len, msg, msg_len, out_hex);
    return NGX_OK;
}
