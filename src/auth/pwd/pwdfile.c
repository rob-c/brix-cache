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

/* ---- Decode one ASCII hex character to its 4-bit value ----
 *
 * WHAT: Maps a single hex character (0-9, a-f, A-F) to its numeric value
 *       0..15; returns -1 for any non-hex byte.  `c` is passed as an int that
 *       the caller has already widened through `unsigned char`.
 *
 * WHY:  Hoisting the per-nibble range ladder out of pwd_from_hex keeps that
 *       loop's cyclomatic complexity bounded while preserving the EXACT accept
 *       set (only the three canonical hex ranges) that credential hex-decoding
 *       depends on — any widening here would weaken salt/hash parsing.
 *
 * HOW:  1. Return the offset from '0' for a decimal digit.
 *       2. Otherwise return 10 + offset from 'a' for a lowercase hex digit.
 *       3. Otherwise return 10 + offset from 'A' for an uppercase hex digit.
 *       4. Otherwise the byte is not hex; return -1.
 */
static int
pwd_hex_nibble(int c)
{
    return (c >= '0' && c <= '9') ? c - '0'
         : (c >= 'a' && c <= 'f') ? c - 'a' + 10
         : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
}

/* ---- Hex-decode a fixed-length string into a byte buffer ----
 *
 * WHAT: Decodes `hexlen` hex chars at `hex` into `out`, writing hexlen/2 bytes.
 *       Returns the number of bytes written, or -1 on an odd length, an
 *       over-capacity request, or any bad nibble.
 *
 * WHY:  Salt and stored-hash fields in brix_pwd_file are stored as hex; a
 *       precise decoder (rejecting odd lengths and non-hex bytes) is part of
 *       the credential-parsing contract.
 *
 * HOW:  1. Reject an odd length or a decode that would overflow `outcap`.
 *       2. For each byte, decode the high and low nibbles via pwd_hex_nibble.
 *          The input bytes are cast through unsigned char so high-bit values
 *          stay non-negative (signed-char-misuse); they still fail every hex
 *          range check inside the nibble decoder.
 *       3. Reject if either nibble is invalid; otherwise pack hi:lo into out.
 *       4. Return the byte count on success.
 */
static int
pwd_from_hex(const char *hex, size_t hexlen, uint8_t *out, size_t outcap)
{
    size_t i;

    if ((hexlen % 2) != 0 || (hexlen / 2) > outcap) {
        return -1;
    }
    for (i = 0; i < hexlen; i += 2) {
        int hi = pwd_hex_nibble((unsigned char) hex[i]);
        int lo = pwd_hex_nibble((unsigned char) hex[i + 1]);

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
    (void) fclose(f); /* phase74-fp: read-only stream, lookup outcome already decided from parsed lines */
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
