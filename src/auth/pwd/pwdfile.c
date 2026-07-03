/*
 * pwdfile.c — brix_pwd_file parsing + PBKDF2 password verification (WS-B).
 *
 * WHAT: Loads a user's salt + stored hash from the password database and verifies
 *       a presented plaintext password against it.
 * WHY:  The credential check must be done WITHOUT ever storing a cleartext
 *       password: brix_pwd_file holds only "user:salthex:hashhex" where
 *       hash = PBKDF2-HMAC-SHA1(password, salt, 10000, 24B) — byte-identical to the
 *       KDF stock XrdSecpwd uses (XrdCryptosslAux.cc DoubleHash/KDFun).  An operator
 *       generates entries with the same KDF (see docs/refactor/phase-52-pwd-wire-spec.md).
 * HOW:  A small line parser (no allocation; fixed buffers) finds the user, hex-
 *       decodes salt+hash, then PKCS5_PBKDF2_HMAC_SHA1 + a constant-time compare.
 *       Pure libc + OpenSSL; no nginx pool use beyond logging-free helpers.
 */
#include "pwd.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* Decode `hexlen` hex chars at `hex` into `out` (out must hold hexlen/2 bytes).
 * Returns the number of bytes written, or -1 on an odd length / bad nibble. */
static int
pwd_from_hex(const char *hex, size_t hexlen, uint8_t *out, size_t outcap)
{
    size_t i;

    if ((hexlen % 2) != 0 || (hexlen / 2) > outcap) {
        return -1;
    }
    for (i = 0; i < hexlen; i += 2) {
        int hi = hex[i], lo = hex[i + 1];

        hi = (hi >= '0' && hi <= '9') ? hi - '0'
           : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
           : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        lo = (lo >= '0' && lo <= '9') ? lo - '0'
           : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
           : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i / 2] = (uint8_t) ((hi << 4) | lo);
    }
    return (int) (hexlen / 2);
}

/* Parse one "user:salthex:hashhex" line for `user`.  Returns 1 on a match (salt +
 * hash filled), 0 otherwise. */
static int
pwd_parse_line(char *line, const char *user, uint8_t *salt, size_t *saltlen,
    uint8_t *hash, size_t *hashlen)
{
    char  *colon1, *colon2, *nl;
    int    n;

    while (*line == ' ' || *line == '\t') {
        line++;
    }
    if (*line == '#' || *line == '\n' || *line == '\0') {
        return 0;
    }
    nl = strpbrk(line, "\r\n");
    if (nl != NULL) {
        *nl = '\0';
    }
    colon1 = strchr(line, ':');
    if (colon1 == NULL) {
        return 0;
    }
    *colon1 = '\0';
    if (strcmp(line, user) != 0) {
        return 0;
    }
    colon2 = strchr(colon1 + 1, ':');
    if (colon2 == NULL) {
        return 0;
    }
    *colon2 = '\0';

    n = pwd_from_hex(colon1 + 1, strlen(colon1 + 1), salt, BRIX_PWD_MAX_SALT);
    if (n <= 0) {
        return 0;
    }
    *saltlen = (size_t) n;
    n = pwd_from_hex(colon2 + 1, strlen(colon2 + 1), hash, BRIX_PWD_HASH_LEN);
    if (n <= 0) {
        return 0;
    }
    *hashlen = (size_t) n;
    return 1;
}

ngx_int_t
brix_pwd_file_lookup(const char *path, const char *user, uint8_t *salt,
    size_t *saltlen, uint8_t *hash, size_t *hashlen)
{
    FILE  *f;
    char   line[512];
    int    found = 0;

    if (path == NULL || path[0] == '\0' || user == NULL || user[0] == '\0') {
        return NGX_DECLINED;
    }
    f = fopen(path, "re");
    if (f == NULL) {
        return NGX_DECLINED;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (pwd_parse_line(line, user, salt, saltlen, hash, hashlen)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? NGX_OK : NGX_DECLINED;
}

int
brix_pwd_verify(const uint8_t *password, size_t plen, const uint8_t *salt,
    size_t saltlen, const uint8_t *hash, size_t hashlen)
{
    uint8_t derived[BRIX_PWD_HASH_LEN];

    if (hashlen != BRIX_PWD_HASH_LEN || password == NULL || salt == NULL) {
        return 0;
    }
    if (PKCS5_PBKDF2_HMAC_SHA1((const char *) password, (int) plen,
                               salt, (int) saltlen, BRIX_PWD_KDF_ITERS,
                               BRIX_PWD_HASH_LEN, derived) != 1)
    {
        return 0;
    }
    /* Constant-time compare; CRYPTO_memcmp returns 0 on equal. */
    {
        int eq = (CRYPTO_memcmp(derived, hash, BRIX_PWD_HASH_LEN) == 0);
        OPENSSL_cleanse(derived, sizeof(derived));
        return eq;
    }
}
