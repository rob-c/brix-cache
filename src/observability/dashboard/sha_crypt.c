/* sha_crypt.c — SHA-crypt ($5$ / $6$) on OpenSSL EVP.  See sha_crypt.h. */
#include "sha_crypt.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SHA_CRYPT_SALT_MAX     16
#define SHA_CRYPT_ROUNDS_DEF   5000
#define SHA_CRYPT_ROUNDS_MIN   1000
#define SHA_CRYPT_ROUNDS_MAX   999999999UL
#define SHA_CRYPT_DIGEST_MAX   64

static const char sha_crypt_b64[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* Parsed "$<id>$[rounds=N$]<salt>$" prefix. */
typedef struct {
    const EVP_MD  *md;
    char           id;             /* '5' or '6' */
    unsigned long  rounds;
    int            rounds_custom;  /* echo "rounds=N$" in the output */
    const char    *salt;
    size_t         salt_len;
} sha_crypt_setting_t;

int
brix_sha_crypt_handles(const char *setting)
{
    return setting != NULL && setting[0] == '$'
        && (setting[1] == '5' || setting[1] == '6') && setting[2] == '$';
}

/* Parse the optional "rounds=N$" clause; advances *p past it when present. */
static int
sha_crypt_parse_rounds(const char **p, sha_crypt_setting_t *s)
{
    const char   *q = *p;
    char         *end;
    unsigned long n;

    if (strncmp(q, "rounds=", 7) != 0) {
        s->rounds = SHA_CRYPT_ROUNDS_DEF;
        return 0;
    }
    n = strtoul(q + 7, &end, 10);
    if (end == q + 7 || *end != '$') {
        return -1;
    }
    if (n < SHA_CRYPT_ROUNDS_MIN) {
        n = SHA_CRYPT_ROUNDS_MIN;
    } else if (n > SHA_CRYPT_ROUNDS_MAX) {
        n = SHA_CRYPT_ROUNDS_MAX;
    }
    s->rounds = n;
    s->rounds_custom = 1;
    *p = end + 1;
    return 0;
}

static int
sha_crypt_parse(const char *setting, sha_crypt_setting_t *s)
{
    const char *p;
    size_t      n;

    memset(s, 0, sizeof(*s));
    if (!brix_sha_crypt_handles(setting)) {
        return -1;
    }
    s->id = setting[1];
    s->md = (s->id == '6') ? EVP_sha512() : EVP_sha256();
    p = setting + 3;
    if (sha_crypt_parse_rounds(&p, s) != 0) {
        return -1;
    }
    n = strcspn(p, "$");
    s->salt = p;
    s->salt_len = (n > SHA_CRYPT_SALT_MAX) ? SHA_CRYPT_SALT_MAX : n;
    return 0;
}

/* Feed `len` bytes taken cyclically from a `srclen`-byte block. */
static void
sha_crypt_update_repeat(EVP_MD_CTX *ctx, const unsigned char *src,
    size_t srclen, size_t len)
{
    while (len > 0) {
        size_t take = (len > srclen) ? srclen : len;
        EVP_DigestUpdate(ctx, src, take);
        len -= take;
    }
}

/* Steps 1-8: the "alternate" digest A = H(key salt key). */
static void
sha_crypt_alt(const sha_crypt_setting_t *s, const unsigned char *key,
    size_t keylen, unsigned char *alt)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, s->md, NULL);
    EVP_DigestUpdate(ctx, key, keylen);
    EVP_DigestUpdate(ctx, s->salt, s->salt_len);
    EVP_DigestUpdate(ctx, key, keylen);
    EVP_DigestFinal_ex(ctx, alt, NULL);
    EVP_MD_CTX_free(ctx);
}

/* Steps 9-12: digest B from key, salt, A and the key-length bit pattern. */
static void
sha_crypt_intermediate(const sha_crypt_setting_t *s, const unsigned char *key,
    size_t keylen, unsigned char *alt)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t      dlen = (size_t) EVP_MD_size(s->md);
    size_t      cnt;

    EVP_DigestInit_ex(ctx, s->md, NULL);
    EVP_DigestUpdate(ctx, key, keylen);
    EVP_DigestUpdate(ctx, s->salt, s->salt_len);
    sha_crypt_update_repeat(ctx, alt, dlen, keylen);
    for (cnt = keylen; cnt > 0; cnt >>= 1) {
        if (cnt & 1) {
            EVP_DigestUpdate(ctx, alt, dlen);
        } else {
            EVP_DigestUpdate(ctx, key, keylen);
        }
    }
    EVP_DigestFinal_ex(ctx, alt, NULL);
    EVP_MD_CTX_free(ctx);
}

/* Steps 13-15 / 17-19: DP = H(key x keylen), DS = H(salt x (16 + alt[0])). */
static void
sha_crypt_derive_block(const EVP_MD *md, const unsigned char *src,
    size_t srclen, size_t times, unsigned char *out)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t      i;

    EVP_DigestInit_ex(ctx, md, NULL);
    for (i = 0; i < times; i++) {
        EVP_DigestUpdate(ctx, src, srclen);
    }
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

/* Step 21: the rounds loop, in place on `alt`. */
static void
sha_crypt_rounds(const sha_crypt_setting_t *s, unsigned char *alt,
    const unsigned char *dp, size_t keylen, const unsigned char *ds)
{
    EVP_MD_CTX   *ctx = EVP_MD_CTX_new();
    size_t        dlen = (size_t) EVP_MD_size(s->md);
    unsigned long r;

    for (r = 0; r < s->rounds; r++) {
        EVP_DigestInit_ex(ctx, s->md, NULL);
        if (r & 1) {
            sha_crypt_update_repeat(ctx, dp, dlen, keylen);
        } else {
            EVP_DigestUpdate(ctx, alt, dlen);
        }
        if (r % 3) {
            EVP_DigestUpdate(ctx, ds, s->salt_len);
        }
        if (r % 7) {
            sha_crypt_update_repeat(ctx, dp, dlen, keylen);
        }
        if (r & 1) {
            EVP_DigestUpdate(ctx, alt, dlen);
        } else {
            sha_crypt_update_repeat(ctx, dp, dlen, keylen);
        }
        EVP_DigestFinal_ex(ctx, alt, NULL);
    }
    EVP_MD_CTX_free(ctx);
}

/* Emit `n` base-64 characters of the 24-bit group (b2 b1 b0). */
static char *
sha_crypt_b64_24(char *out, unsigned b2, unsigned b1, unsigned b0, int n)
{
    unsigned w = (b2 << 16) | (b1 << 8) | b0;

    while (n-- > 0) {
        *out++ = sha_crypt_b64[w & 0x3f];
        w >>= 6;
    }
    return out;
}

/* The byte-order tables of the reference implementation: each row is one
 * 24-bit group (b2, b1, b0) and the last row is the short tail. */
static const unsigned char sha256_order[][3] = {
    {0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14},
    {15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29},
};
static const unsigned char sha512_order[][3] = {
    {0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4},
    {47, 5, 26}, {6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51},
    {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13}, {56, 14, 35},
    {15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19},
    {62, 20, 41},
};

static char *
sha_crypt_encode(char id, const unsigned char *alt, char *out)
{
    size_t i;

    if (id == '6') {
        for (i = 0; i < sizeof(sha512_order) / sizeof(sha512_order[0]); i++) {
            out = sha_crypt_b64_24(out, alt[sha512_order[i][0]],
                                   alt[sha512_order[i][1]],
                                   alt[sha512_order[i][2]], 4);
        }
        return sha_crypt_b64_24(out, 0, 0, alt[63], 2);
    }
    for (i = 0; i < sizeof(sha256_order) / sizeof(sha256_order[0]); i++) {
        out = sha_crypt_b64_24(out, alt[sha256_order[i][0]],
                               alt[sha256_order[i][1]],
                               alt[sha256_order[i][2]], 4);
    }
    return sha_crypt_b64_24(out, 0, alt[31], alt[30], 3);
}

/* "$<id>$[rounds=N$]<salt>$" prefix; returns the write position or NULL. */
static char *
sha_crypt_prefix(const sha_crypt_setting_t *s, char *out, size_t outsz)
{
    int n;

    if (s->rounds_custom) {
        n = snprintf(out, outsz, "$%c$rounds=%lu$%.*s$", s->id, s->rounds,
                     (int) s->salt_len, s->salt);
    } else {
        n = snprintf(out, outsz, "$%c$%.*s$", s->id, (int) s->salt_len, s->salt);
    }
    if (n < 0 || (size_t) n + 87 > outsz) {   /* longest hash (86) + NUL */
        return NULL;
    }
    return out + n;
}

int
brix_sha_crypt(const char *key, const char *setting, char *out, size_t outsz)
{
    sha_crypt_setting_t s;
    unsigned char       alt[SHA_CRYPT_DIGEST_MAX];
    unsigned char       dp[SHA_CRYPT_DIGEST_MAX];
    unsigned char       ds[SHA_CRYPT_DIGEST_MAX];
    const unsigned char *k = (const unsigned char *) key;
    size_t              keylen;
    char               *p;

    if (key == NULL || out == NULL || sha_crypt_parse(setting, &s) != 0) {
        return -1;
    }
    p = sha_crypt_prefix(&s, out, outsz);
    if (p == NULL) {
        return -1;
    }
    keylen = strlen(key);
    sha_crypt_alt(&s, k, keylen, alt);
    sha_crypt_intermediate(&s, k, keylen, alt);
    sha_crypt_derive_block(s.md, k, keylen, keylen, dp);
    sha_crypt_derive_block(s.md, (const unsigned char *) s.salt, s.salt_len,
                           16 + (size_t) alt[0], ds);
    sha_crypt_rounds(&s, alt, dp, keylen, ds);
    p = sha_crypt_encode(s.id, alt, p);
    *p = '\0';
    OPENSSL_cleanse(alt, sizeof(alt));
    OPENSSL_cleanse(dp, sizeof(dp));
    OPENSSL_cleanse(ds, sizeof(ds));
    return 0;
}
