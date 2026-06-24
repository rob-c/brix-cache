/*
 * gsi_core.c — ngx-free GSI/sigver crypto + wire kernels.
 *
 * WHAT: The pure (OpenSSL + libc only) pieces of the GSI exchange and request
 *       signing: XrdSutBuffer bucket scan + build, ffdhe2048 DH keygen / pubkey
 *       encode-decode / peer build / shared-secret derive, and the sigver opcode
 *       policy. No ngx_*, no logging, no pools.
 * WHY:  Both the nginx module (the src/gsi server handlers) and the native client
 *       (client/lib/sec) need exactly this math. Keeping it here — compiled
 *       build-in-place into the module (via config) AND into libxrdproto (via
 *       shared/xrdproto/Makefile) — makes it a single source of truth instead of
 *       two copies, the same pattern as crc32c/hex/crypto.
 * HOW:  Functions return objects/codes and never touch ngx; callers add their own
 *       logging/allocation policy at the edge. The byte behaviour is identical to
 *       the prior server (src/gsi/{buffer,keypool,parse_crypto_helpers,parse_x509}.c)
 *       and client code it replaces.
 */
#include "gsi_core.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/dh.h>          /* EVP_PKEY_CTX_set_dh_pad */
#include <openssl/rand.h>        /* RAND_bytes (rtag) */
#include <openssl/pem.h>         /* PEM_{read,write}_bio_Parameters (W4 cipher) */
#include <openssl/evp.h>         /* EVP cipher ctx + EVP_get_cipherbyname (W4) */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>    /* phase-52: load legacy provider for bf/3des */
#endif
#include <openssl/rsa.h>         /* RSA_PKCS1_PADDING (rtag sign, W6) */

#include "../protocol/gsi.h"      /* GSI bucket + step constants (pure header) */
#include "../protocol/opcodes.h"  /* kXR opcodes for the sigver policy */
#include "../compat/crypto.h"     /* xrootd_hmac_sha256 for the sigver HMAC */

/* ------------------------------------------------------------------ */
/* XrdSutBuffer bucket scan (was src/gsi/buffer.c gsi_find_bucket).      */
/* ------------------------------------------------------------------ */
int
xrootd_gsi_find_bucket(const uint8_t *buf, size_t len, uint32_t type,
                       const uint8_t **out, size_t *outlen)
{
    const uint8_t *cur = buf;
    const uint8_t *end = buf + len;
    size_t         name_len;

    if (len < 8) {
        return -1;
    }
    name_len = strnlen((const char *) cur, len) + 1;   /* protocol name + NUL */
    if (name_len >= len) {
        return -1;
    }
    cur += name_len;
    if (cur + 4 > end) {                                /* step */
        return -1;
    }
    cur += 4;

    while (cur + 8 <= end) {
        uint32_t btype, blen;
        memcpy(&btype, cur, 4);
        memcpy(&blen, cur + 4, 4);
        btype = ntohl(btype);
        blen = ntohl(blen);
        cur += 8;
        if (btype == (uint32_t) kXRS_none) {
            break;
        }
        if ((size_t) (end - cur) < blen) {
            return -1;
        }
        if (btype == type) {
            *out = cur;
            *outlen = blen;
            return 0;
        }
        cur += blen;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* XrdSutBuffer builder.                                                 */
/* ------------------------------------------------------------------ */
void
xrootd_gbuf_init(xrootd_gbuf *g)
{
    g->p = NULL;
    g->len = 0;
    g->cap = 0;
    g->err = 0;
}

void
xrootd_gbuf_free(xrootd_gbuf *g)
{
    free(g->p);
    g->p = NULL;
    g->len = g->cap = 0;
}

void
xrootd_gbuf_raw(xrootd_gbuf *g, const void *data, size_t n)
{
    if (g->err) {
        return;
    }
    if (g->len + n > g->cap) {
        size_t   ncap = g->cap ? g->cap : 256;
        uint8_t *np;
        while (g->len + n > ncap) {
            ncap *= 2;
        }
        np = (uint8_t *) realloc(g->p, ncap);
        if (np == NULL) {
            g->err = 1;
            return;
        }
        g->p = np;
        g->cap = ncap;
    }
    memcpy(g->p + g->len, data, n);
    g->len += n;
}

void
xrootd_gbuf_u32(xrootd_gbuf *g, uint32_t v)
{
    uint32_t be = htonl(v);
    xrootd_gbuf_raw(g, &be, 4);
}

void
xrootd_gbuf_start(xrootd_gbuf *g, uint32_t step)
{
    xrootd_gbuf_raw(g, "gsi\0", 4);
    xrootd_gbuf_u32(g, step);
}

void
xrootd_gbuf_bucket(xrootd_gbuf *g, uint32_t type, const void *d, size_t n)
{
    xrootd_gbuf_u32(g, type);
    xrootd_gbuf_u32(g, (uint32_t) n);
    xrootd_gbuf_raw(g, d, n);
}

void
xrootd_gbuf_end(xrootd_gbuf *g)
{
    xrootd_gbuf_u32(g, (uint32_t) kXRS_none);
}

/* ------------------------------------------------------------------ */
/* Diffie-Hellman (ffdhe2048).                                          */
/* ------------------------------------------------------------------ */
EVP_PKEY *
xrootd_gsi_dh_keygen(void)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *k = NULL;
    OSSL_PARAM    params[] = {
        OSSL_PARAM_utf8_string("group", "ffdhe2048", 0),
        OSSL_PARAM_END
    };

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (ctx == NULL) {
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_params(ctx, params) <= 0
        || EVP_PKEY_keygen(ctx, &k) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return k;
}

BIGNUM *
xrootd_gsi_dh_pub_decode(const uint8_t *blob, size_t len)
{
    static const char b[] = "---BPUB---";
    static const char e[] = "---EPUB--";
    const uint8_t    *s = memmem(blob, len, b, sizeof(b) - 1);
    const uint8_t    *t = memmem(blob, len, e, sizeof(e) - 1);
    char             *hex;
    size_t            hl;
    BIGNUM           *bn = NULL;

    if (s == NULL || t == NULL || t <= s + (sizeof(b) - 1)) {
        return NULL;
    }
    s += sizeof(b) - 1;
    hl = (size_t) (t - s);
    hex = (char *) malloc(hl + 1);
    if (hex == NULL) {
        return NULL;
    }
    memcpy(hex, s, hl);
    hex[hl] = '\0';
    if (BN_hex2bn(&bn, hex) == 0) {
        free(hex);
        BN_free(bn);
        return NULL;
    }
    free(hex);
    return bn;
}

char *
xrootd_gsi_dh_pub_encode(EVP_PKEY *dh)
{
    BIGNUM *pub = NULL;
    char   *hex, *blob;
    size_t  n;

    if (!EVP_PKEY_get_bn_param(dh, "pub", &pub)) {
        return NULL;
    }
    hex = BN_bn2hex(pub);
    BN_free(pub);
    if (hex == NULL) {
        return NULL;
    }
    n = strlen(hex) + 32;
    blob = (char *) malloc(n);
    if (blob != NULL) {
        snprintf(blob, n, "---BPUB---%s---EPUB--", hex);
    }
    OPENSSL_free(hex);
    return blob;
}

EVP_PKEY *
xrootd_gsi_dh_build_peer(EVP_PKEY *mine, BIGNUM *peer_pub)
{
    OSSL_PARAM     *mparams = NULL, *cparams = NULL, *merged = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    EVP_PKEY_CTX   *ctx = NULL;
    EVP_PKEY       *peer = NULL;

    if (EVP_PKEY_todata(mine, EVP_PKEY_KEY_PARAMETERS, &mparams) != 1) {
        return NULL;
    }
    bld = OSSL_PARAM_BLD_new();
    if (bld != NULL
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, peer_pub) == 1) {
        cparams = OSSL_PARAM_BLD_to_param(bld);
    }
    if (cparams != NULL) {
        merged = OSSL_PARAM_merge(mparams, cparams);
    }
    if (merged != NULL) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
        if (ctx != NULL && EVP_PKEY_fromdata_init(ctx) == 1) {
            if (EVP_PKEY_fromdata(ctx, &peer, EVP_PKEY_PUBLIC_KEY, merged) != 1) {
                peer = NULL;
            }
        }
    }

    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(merged);
    OSSL_PARAM_free(cparams);
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(mparams);
    return peer;
}

uint8_t *
xrootd_gsi_dh_derive(EVP_PKEY *mine, EVP_PKEY *peer, size_t *slen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(mine, NULL);
    uint8_t      *secret = NULL;

    /* dh_pad=0 → unpadded big-endian secret (leading zeros stripped); both sides
     * must use the same so SHA256(secret) and the AES key match. */
    if (ctx == NULL
        || EVP_PKEY_derive_init(ctx) != 1
        || EVP_PKEY_CTX_set_dh_pad(ctx, 0) != 1
        || EVP_PKEY_derive_set_peer(ctx, peer) != 1
        || EVP_PKEY_derive(ctx, NULL, slen) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    secret = (uint8_t *) malloc(*slen);
    if (secret == NULL || EVP_PKEY_derive(ctx, secret, slen) != 1) {
        free(secret);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return secret;
}

/* ------------------------------------------------------------------ */
/* XrdCryptosslCipher-compatible session cipher (phase-48 W4).           */
/*                                                                       */
/* Byte-exact with stock XrdSecgsi so our client talks to stock servers  */
/* (EOS) and our server talks to stock clients.  Both ends use one FIXED */
/* 3072-bit DH group (XrdCryptosslCipher dh_param_enc); the wire pubkey   */
/* form is Public(): the PEM params block + "---BPUB---"<UPPER hex>       */
/* "---EPUB---".  The AES-128 key is the first 16 bytes of the PADDED DH  */
/* shared secret (dh_pad=1).  Encrypt() prepends a random 16-byte IV to   */
/* AES-128-CBC/PKCS7 ciphertext.                                          */
/* ------------------------------------------------------------------ */

/* The fixed DH parameters, verbatim from XrdCryptosslCipher.cc. */
static const char xrootd_gsi_dh_params_pem[] =
"-----BEGIN DH PARAMETERS-----\n"
"MIIBiAKCAYEAzcEAf3ZCkm0FxJLgKd1YoT16Hietl7QV8VgJNc5CYKmRu/gKylxT\n"
"MVZJqtUmoh2IvFHCfbTGEmZM5LdVaZfMLQf7yXjecg0nSGklYZeQQ3P0qshFLbI9\n"
"u3z1XhEeCbEZPq84WWwXacSAAxwwRRrN5nshgAavqvyDiGNi+GqYpqGPb9JE38R3\n"
"GJ51FTPutZlvQvEycjCbjyajhpItBB+XvIjWj2GQyvi+cqB0WrPQAsxCOPrBTCZL\n"
"OjM0NfJ7PQfllw3RDQev2u1Q+Rt8QyScJQCFUj/SWoxpw2ydpWdgAkrqTmdVYrev\n"
"x5AoXE52cVIC8wfOxaaJ4cBpnJui3Y0jZcOQj0FtC0wf4WcBpHnLLBzKSOQwbxts\n"
"WE8LkskPnwwrup/HqWimFFg40bC9F5Lm3CTDCb45mtlBxi3DydIbRLFhGAjlKzV3\n"
"s9G3opHwwfgXpFf3+zg7NPV3g1//HLgWCvooOvMqaO+X7+lXczJJLMafEaarcAya\n"
"Kyo8PGKIAORrAgEF\n"
"-----END DH PARAMETERS-----\n";

/* Load the fixed DH params as an EVP_PKEY (params only). */
static EVP_PKEY *
gsi_fixed_dh_params(void)
{
    BIO      *bio = BIO_new_mem_buf(xrootd_gsi_dh_params_pem, -1);
    EVP_PKEY *p   = NULL;

    if (bio != NULL) {
        p = PEM_read_bio_Parameters(bio, NULL);
        BIO_free(bio);
    }
    return p;
}

/* Generate a DH keypair using the params held by `dhparams` (a params-or-public
 * EVP_PKEY).  NULL → the fixed 3072-bit params. */
static EVP_PKEY *
gsi_dh_keygen_with(EVP_PKEY *dhparams)
{
    EVP_PKEY     *params = dhparams ? dhparams : gsi_fixed_dh_params();
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *key = NULL;

    if (params == NULL) {
        return NULL;
    }
    ctx = EVP_PKEY_CTX_new(params, NULL);
    if (ctx != NULL && EVP_PKEY_keygen_init(ctx) == 1) {
        EVP_PKEY_keygen(ctx, &key);
    }
    EVP_PKEY_CTX_free(ctx);
    if (dhparams == NULL) {
        EVP_PKEY_free(params);
    }
    return key;
}

EVP_PKEY *
xrootd_gsi_cipher_keygen(void)
{
    return gsi_dh_keygen_with(NULL);
}

EVP_PKEY *
xrootd_gsi_cipher_keygen_from(EVP_PKEY *peer)
{
    /* CRITICAL: key with the PEER's params, not the fixed group — a peer may use
     * a different DH group (e.g. ffdhe2048 vs the fixed 3072-bit) and the derive
     * only works when both sides share the group. */
    return gsi_dh_keygen_with(peer);
}

char *
xrootd_gsi_cipher_public(EVP_PKEY *dh, size_t *outlen)
{
    BIGNUM *pub = NULL;
    char   *phex = NULL;
    BIO    *bio = NULL;
    char   *pem = NULL;
    long    pemlen;
    char   *out = NULL;
    size_t  total;

    if (!EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_PUB_KEY, &pub)) {
        return NULL;
    }
    phex = BN_bn2hex(pub);                 /* UPPERCASE hex, as XrdCrypto */
    BN_free(pub);
    bio = BIO_new(BIO_s_mem());

    if (phex != NULL && bio != NULL
        && PEM_write_bio_Parameters(bio, dh) == 1) {
        pemlen = BIO_get_mem_data(bio, &pem);   /* PEM params incl END+\n */
        total  = (size_t) pemlen + 10 + strlen(phex) + 10;
        out    = (char *) malloc(total);
        if (out != NULL) {
            size_t cur = 0;
            memcpy(out + cur, pem, (size_t) pemlen); cur += (size_t) pemlen;
            memcpy(out + cur, "---BPUB---", 10);     cur += 10;
            memcpy(out + cur, phex, strlen(phex));   cur += strlen(phex);
            memcpy(out + cur, "---EPUB---", 10);     cur += 10;
            *outlen = cur;
        }
    }

    if (phex != NULL) { OPENSSL_free(phex); }
    BIO_free(bio);
    return out;
}

EVP_PKEY *
xrootd_gsi_cipher_parse_peer(const uint8_t *buf, size_t len)
{
    const char *pb = (const char *) memmem(buf, len, "---BPUB---", 10);
    const char *pe = (const char *) memmem(buf, len, "---EPUB--", 9);
    BIGNUM     *bnpub = NULL;
    EVP_PKEY   *peer = NULL;
    char       *hex;
    size_t      hlen, pemlen;

    if (pb == NULL || pe == NULL || pe <= pb + 10) {
        return NULL;
    }
    pemlen = (size_t) ((const uint8_t *) pb - buf);     /* PEM params length */
    hlen   = (size_t) (pe - (pb + 10));
    hex    = (char *) malloc(hlen + 1);
    if (hex == NULL) {
        return NULL;
    }
    memcpy(hex, pb + 10, hlen);
    hex[hlen] = '\0';
    BN_hex2bn(&bnpub, hex);
    free(hex);
    if (bnpub == NULL) {
        return NULL;
    }

    {
        BIO      *bio = BIO_new_mem_buf(buf, (int) pemlen);
        EVP_PKEY *params = bio ? PEM_read_bio_Parameters(bio, NULL) : NULL;
        OSSL_PARAM     *pp = NULL, *pk = NULL, *merged = NULL;
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        EVP_PKEY_CTX   *ctx = NULL;

        if (params != NULL && bld != NULL
            && EVP_PKEY_todata(params, EVP_PKEY_KEY_PARAMETERS, &pp) == 1
            && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bnpub) == 1
            && (pk = OSSL_PARAM_BLD_to_param(bld)) != NULL
            && (merged = OSSL_PARAM_merge(pp, pk)) != NULL) {
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
            if (ctx != NULL && EVP_PKEY_fromdata_init(ctx) == 1) {
                if (EVP_PKEY_fromdata(ctx, &peer, EVP_PKEY_PUBLIC_KEY,
                                      merged) != 1) {
                    peer = NULL;
                }
            }
        }
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(merged);
        OSSL_PARAM_free(pk);
        OSSL_PARAM_free(pp);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_free(params);
        BIO_free(bio);
    }
    BN_free(bnpub);
    return peer;
}

/* ------------------------------------------------------------------ */
/* Phase 52 (WS-A): GSI session-cipher negotiation (table-driven).       */
/*                                                                       */
/* The XrdSecgsi handshake negotiates a symmetric session cipher from a  */
/* colon-separated list (XrdCrypto default aes-128-cbc:bf-cbc:des-ede3-  */
/* cbc).  The session key is the first EVP_CIPHER_key_length bytes of the */
/* DH shared secret; the IV length is the cipher's native block size     */
/* (16 for AES, 8 for Blowfish/3DES).  We allow only this fixed set (so a */
/* hostile peer cannot select an arbitrary/weak EVP cipher by name), and */
/* resolve each via EVP_get_cipherbyname so bf/3des work only when their  */
/* provider (OpenSSL 3 legacy) is loaded — aes-128/256 are always present. */
/* aes-128-cbc stays first, so the proven default + stock interop is      */
/* byte-for-byte unchanged.                                              */
/* ------------------------------------------------------------------ */

/* Allowlist of negotiable GSI session ciphers (XrdCrypto/OpenSSL names). */
static const char *const gsi_cipher_allow[] = {
    "aes-128-cbc", "aes-256-cbc", "bf-cbc", "des-ede3-cbc", NULL
};

const char *
xrootd_gsi_cipher_default_list(void)
{
    return "aes-128-cbc:aes-256-cbc:bf-cbc:des-ede3-cbc";
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/* Best-effort one-shot load of the OpenSSL 3 legacy provider so bf-cbc /
 * des-ede3-cbc resolve.  No-op / harmless when unavailable; aes-* never need it. */
static void
gsi_load_legacy_once(void)
{
    static int tried = 0;
    if (!tried) {
        tried = 1;
        (void) OSSL_PROVIDER_load(NULL, "legacy");
        (void) OSSL_PROVIDER_load(NULL, "default");
    }
}
#endif

int
xrootd_gsi_cipher_lookup(const char *name, xrootd_gsi_cipher_t *out)
{
    const EVP_CIPHER *evp;
    int               i, allowed = 0;

    if (name == NULL || out == NULL) {
        return 0;
    }
    for (i = 0; gsi_cipher_allow[i] != NULL; i++) {
        if (strcmp(name, gsi_cipher_allow[i]) == 0) { allowed = 1; break; }
    }
    if (!allowed) {
        return 0;                  /* not a negotiable GSI cipher */
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    gsi_load_legacy_once();
#endif
    evp = EVP_get_cipherbyname(name);
    if (evp == NULL) {
        return 0;                  /* provider not loaded (e.g. legacy bf/3des) */
    }
    out->evp     = evp;
    out->key_len = EVP_CIPHER_key_length(evp);
    out->iv_len  = EVP_CIPHER_iv_length(evp);
    if (out->key_len <= 0 || out->key_len > XROOTD_GSI_MAX_KEY
        || out->iv_len < 0 || out->iv_len > XROOTD_GSI_MAX_IV) {
        return 0;
    }
    return 1;
}

int
xrootd_gsi_cipher_pick(const char *offered, xrootd_gsi_cipher_t *out,
                       char chosen[24])
{
    const char *p = offered;

    if (offered == NULL || out == NULL) {
        return 0;
    }
    while (*p) {
        char        name[24];
        size_t      n = 0;
        const char *start = p;

        while (*p && *p != ':') { p++; }
        n = (size_t) (p - start);
        if (n > 0 && n < sizeof(name)) {
            memcpy(name, start, n);
            name[n] = '\0';
            if (xrootd_gsi_cipher_lookup(name, out)) {
                if (chosen != NULL) {
                    memcpy(chosen, name, n + 1);
                }
                return 1;
            }
        }
        if (*p == ':') { p++; }
    }
    return 0;
}

int
xrootd_gsi_cipher_session_key(EVP_PKEY *mine, EVP_PKEY *peer, int padded,
                              uint8_t *key, int key_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(mine, NULL);
    uint8_t      *secret;
    size_t        slen = 0;
    int           ok = 0;

    /* `padded` MUST match the peer's XrdSecgsi HasPad: pre-DHsigned (<10400)
     * peers use dh_pad=0 (leading zeros stripped), newer ones dh_pad=1.  The
     * session key is the first key_len bytes of the resulting secret. */
    if (key_len <= 0 || key_len > XROOTD_GSI_MAX_KEY
        || ctx == NULL
        || EVP_PKEY_derive_init(ctx) != 1
        || EVP_PKEY_CTX_set_dh_pad(ctx, padded ? 1 : 0) != 1
        || EVP_PKEY_derive_set_peer(ctx, peer) != 1
        || EVP_PKEY_derive(ctx, NULL, &slen) != 1
        || slen < (size_t) key_len) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    secret = (uint8_t *) malloc(slen);
    if (secret != NULL && EVP_PKEY_derive(ctx, secret, &slen) == 1) {
        memcpy(key, secret, (size_t) key_len);
        ok = 1;
    }
    if (secret != NULL) {
        OPENSSL_cleanse(secret, slen);
        free(secret);
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

uint8_t *
xrootd_gsi_cipher_encrypt(const xrootd_gsi_cipher_t *c, const uint8_t *key,
                          const uint8_t *in, size_t inlen, int use_iv,
                          size_t *outlen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t         iv[XROOTD_GSI_MAX_IV];
    size_t          ivl = (size_t) c->iv_len;
    size_t          off = use_iv ? ivl : 0;    /* IV prepended only when use_iv */
    uint8_t        *out;
    int             l1 = 0, l2 = 0;

    /* use_iv: a fresh random IV is prepended (XrdSecgsi >=DHsigned).  Otherwise
     * a zero IV is used and nothing is prepended (pre-DHsigned peers). */
    if (ctx == NULL) {
        return NULL;
    }
    if (use_iv) {
        if (RAND_bytes(iv, c->iv_len) != 1) { EVP_CIPHER_CTX_free(ctx); return NULL; }
    } else {
        memset(iv, 0, ivl);
    }
    out = (uint8_t *) malloc(off + inlen + (size_t) EVP_CIPHER_block_size(c->evp));
    if (out == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    if (use_iv) {
        memcpy(out, iv, ivl);
    }
    if (EVP_EncryptInit_ex(ctx, c->evp, NULL, key, iv) == 1
        && EVP_EncryptUpdate(ctx, out + off, &l1, in, (int) inlen) == 1
        && EVP_EncryptFinal_ex(ctx, out + off + l1, &l2) == 1) {
        *outlen = off + (size_t) (l1 + l2);
    } else {
        free(out);
        out = NULL;
    }
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

uint8_t *
xrootd_gsi_cipher_decrypt(const xrootd_gsi_cipher_t *c, const uint8_t *key,
                          const uint8_t *in, size_t inlen, int use_iv,
                          size_t *outlen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t         iv[XROOTD_GSI_MAX_IV];
    size_t          ivl = (size_t) c->iv_len;
    size_t          off = use_iv ? ivl : 0;
    uint8_t        *out;
    int             l1 = 0, l2 = 0;

    if (ctx == NULL || inlen < off) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    if (use_iv) {
        memcpy(iv, in, ivl);                      /* IV is the first iv_len bytes */
    } else {
        memset(iv, 0, ivl);
    }
    out = (uint8_t *) malloc(inlen - off + (size_t) EVP_CIPHER_block_size(c->evp));
    if (out == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    if (EVP_DecryptInit_ex(ctx, c->evp, NULL, key, iv) == 1
        && EVP_DecryptUpdate(ctx, out, &l1, in + off, (int) (inlen - off)) == 1
        && EVP_DecryptFinal_ex(ctx, out + l1, &l2) == 1) {
        *outlen = (size_t) (l1 + l2);
    } else {
        free(out);
        out = NULL;
    }
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

/* ------------------------------------------------------------------ */
/* XrdSecgsi handshake helpers (shared client/server, phase-48).        */
/* ------------------------------------------------------------------ */

int
xrootd_gsi_rand(uint8_t *out, size_t n)
{
    return RAND_bytes(out, (int) n) == 1;
}

/*
 * RSA private-key signature, byte-exact with XrdCryptosslRSA::EncryptPrivate:
 * EVP_PKEY_sign over the RAW input (no message digest) with RSA PKCS#1 v1.5
 * padding.  This is the GSI proof-of-possession op — the client signs the
 * server's random tag with the proxy private key (kXRS_signed_rtag); the server
 * recovers it with the public key.  `out` must hold >= EVP_PKEY_size(key) bytes.
 * Returns the signature length, or 0 on failure.  (Single-chunk: the rtag is far
 * smaller than the key modulus, so no chunking loop is needed.)
 */
size_t
xrootd_gsi_rsa_sign_raw(EVP_PKEY *key, const uint8_t *in, size_t inlen,
                        uint8_t *out)
{
    return xrootd_gsi_rsa_encrypt_private(key, in, inlen, out,
                                          (size_t) EVP_PKEY_size(key) + inlen);
}

/*
 * XrdCryptosslRSA::EncryptPrivate — RSA private-key "encrypt" (sign), chunked.
 * Input is split into <key_size - 11>-byte chunks; each is EVP_PKEY_sign'd with
 * PKCS#1 v1.5 into a key_size-byte output block.  Used to sign the DH cipher
 * blob (v>=DHsigned) and the rtag.  out must hold >= ceil(inlen/lcmax)*key_size.
 * Returns the total signature length, or 0.
 */
size_t
xrootd_gsi_rsa_encrypt_private(EVP_PKEY *key, const uint8_t *in, size_t inlen,
                               uint8_t *out, size_t outmax)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    size_t        ksz = (size_t) EVP_PKEY_size(key);
    size_t        lcmax = ksz > 11 ? ksz - 11 : 1;
    size_t        kk = 0, ke = 0;
    int           ok = 1;

    if (ctx == NULL || EVP_PKEY_sign_init(ctx) != 1
        || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    while (kk < inlen && ok) {
        size_t lc = (inlen - kk < lcmax) ? (inlen - kk) : lcmax;
        size_t lout = outmax - ke;
        if (EVP_PKEY_sign(ctx, out + ke, &lout, in + kk, lc) != 1) {
            ok = 0;
        } else {
            kk += lc;
            ke += lout;
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return ok ? ke : 0;
}

/*
 * XrdCryptosslRSA::DecryptPublic — RSA public-key "decrypt" (verify-recover),
 * chunked: each key_size-byte input block is EVP_PKEY_verify_recover'd (PKCS#1)
 * back to plaintext.  Recovers a DH cipher blob signed by the peer's cert key.
 * Returns the recovered length, or 0.
 */
size_t
xrootd_gsi_rsa_decrypt_public(EVP_PKEY *key, const uint8_t *in, size_t inlen,
                              uint8_t *out, size_t outmax)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    size_t        ksz = (size_t) EVP_PKEY_size(key);
    size_t        kk = 0, ke = 0;
    int           ok = 1;

    if (ctx == NULL || ksz == 0 || EVP_PKEY_verify_recover_init(ctx) != 1
        || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    while (kk + ksz <= inlen && ok) {
        size_t lout = outmax - ke;
        if (EVP_PKEY_verify_recover(ctx, out + ke, &lout, in + kk, ksz) != 1) {
            ok = 0;
        } else {
            kk += ksz;
            ke += lout;
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return ok ? ke : 0;
}

/* Parse a gsi protocol parms string "v:10600,c:ssl,ca:HASH|HASH" into fields.
 * Any out pointer may be NULL.  `crypto`/`ca` are NUL-terminated, truncated. */
void
xrootd_gsi_parse_parms(const char *parms, uint32_t *version,
                       char *crypto, size_t cryptosz,
                       char *ca, size_t casz)
{
    const char *p;

    if (version != NULL) { *version = 0; }
    if (crypto != NULL && cryptosz > 0) { crypto[0] = '\0'; }
    if (ca != NULL && casz > 0) { ca[0] = '\0'; }
    if (parms == NULL) {
        return;
    }

    for (p = parms; *p != '\0'; ) {
        const char *comma = strchr(p, ',');
        size_t      flen  = comma ? (size_t) (comma - p) : strlen(p);

        if (flen > 2 && p[1] == ':') {
            const char *val = p + 2;
            size_t      vlen = flen - 2;
            if (p[0] == 'v' && version != NULL) {
                *version = (uint32_t) strtoul(val, NULL, 10);
            } else if (p[0] == 'c' && crypto != NULL && cryptosz > 0) {
                size_t n = vlen < cryptosz - 1 ? vlen : cryptosz - 1;
                memcpy(crypto, val, n);
                crypto[n] = '\0';
            }
        } else if (flen > 3 && p[0] == 'c' && p[1] == 'a' && p[2] == ':'
                   && ca != NULL && casz > 0) {
            const char *val = p + 3;
            size_t      vlen = flen - 3;
            size_t      n = vlen < casz - 1 ? vlen : casz - 1;
            memcpy(ca, val, n);
            ca[n] = '\0';
        }
        p += flen;
        if (*p == ',') { p++; }
    }
}

/*
 * Build the standard XrdSecgsi round-1 certreq buffer.  Outer (Step
 * kXGC_certreq) carries kXRS_cryptomod, kXRS_version, kXRS_issuer_hash,
 * kXRS_clnt_opts and a kXRS_main bucket whose data is a *nested* buffer
 * (Step kXGC_certreq + kXRS_rtag + kXRS_none).  Mirrors a stock client's first
 * message; the server's XrdSutBuffer parser reads the certreq opcode from the
 * main bucket (a bare top-level opcode is rejected with "main buffer missing").
 * Returns a malloc'd buffer (*outlen set), or NULL.
 */
uint8_t *
xrootd_gsi_build_certreq(const char *cryptomod, uint32_t version,
                         const char *issuer_hash, uint32_t clnt_opts,
                         const uint8_t *rtag, size_t rtaglen, size_t *outlen)
{
    xrootd_gbuf inner, outer;
    uint32_t    ver_be  = htonl(version);
    uint32_t    opts_be = htonl(clnt_opts);
    uint8_t    *result  = NULL;

    /* Nested main: "gsi\0" + kXGC_certreq + rtag bucket + terminator. */
    xrootd_gbuf_init(&inner);
    xrootd_gbuf_start(&inner, (uint32_t) kXGC_certreq);
    xrootd_gbuf_bucket(&inner, (uint32_t) kXRS_rtag, rtag, rtaglen);
    xrootd_gbuf_end(&inner);
    if (inner.err) {
        xrootd_gbuf_free(&inner);
        return NULL;
    }

    xrootd_gbuf_init(&outer);
    xrootd_gbuf_start(&outer, (uint32_t) kXGC_certreq);
    xrootd_gbuf_bucket(&outer, (uint32_t) kXRS_cryptomod,
                       cryptomod, strlen(cryptomod));
    xrootd_gbuf_bucket(&outer, (uint32_t) kXRS_version, &ver_be, 4);
    xrootd_gbuf_bucket(&outer, (uint32_t) kXRS_issuer_hash,
                       issuer_hash, strlen(issuer_hash));
    xrootd_gbuf_bucket(&outer, (uint32_t) kXRS_clnt_opts, &opts_be, 4);
    xrootd_gbuf_bucket(&outer, (uint32_t) kXRS_main, inner.p, inner.len);
    xrootd_gbuf_end(&outer);

    if (!outer.err) {
        result  = outer.p;
        *outlen = outer.len;
        outer.p = NULL;          /* ownership → caller */
    }
    xrootd_gbuf_free(&inner);
    xrootd_gbuf_free(&outer);
    return result;
}

/* ------------------------------------------------------------------ */
/* Request-signing (kXR_sigver) opcode policy — verbatim from           */
/* src/handshake/sigver.c xrootd_sigver_opcode_requires().              */
/* ------------------------------------------------------------------ */
int
xrootd_gsi_sigver_required(uint16_t op, int level)
{
    if (level <= 1) {
        return 0;
    }
    if (op == kXR_login || op == kXR_protocol || op == kXR_auth
        || op == kXR_endsess || op == kXR_ping || op == kXR_sigver
        || op == kXR_bind) {
        return 0;
    }
    if (level == 2) {
        return (op == kXR_open || op == kXR_write || op == kXR_pgwrite
                || op == kXR_writev || op == kXR_truncate || op == kXR_mkdir
                || op == kXR_rm || op == kXR_rmdir || op == kXR_mv
                || op == kXR_chmod || op == kXR_fattr || op == kXR_chkpoint
                || op == kXR_clone);
    }
    return 1;   /* level >= 3 */
}

/* ------------------------------------------------------------------ */
/* kXR_sigver HMAC — request signing (client) / verification (server). */
/* The producer and the verifier MUST agree on the covered bytes; this  */
/* is the single source of that layout.                                 */
/* ------------------------------------------------------------------ */

void
xrootd_gsi_sigver_seqno_be(uint64_t seq, uint8_t out[8])
{
    out[0] = (uint8_t) (seq >> 56);
    out[1] = (uint8_t) (seq >> 48);
    out[2] = (uint8_t) (seq >> 40);
    out[3] = (uint8_t) (seq >> 32);
    out[4] = (uint8_t) (seq >> 24);
    out[5] = (uint8_t) (seq >> 16);
    out[6] = (uint8_t) (seq >> 8);
    out[7] = (uint8_t) seq;
}

int
xrootd_gsi_sigver_hmac(const uint8_t key[32], uint64_t seqno,
                       const uint8_t hdr24[24], const uint8_t *payload,
                       size_t plen, int nodata, uint8_t mac_out[32])
{
    uint8_t  seqbe[8];
    uint8_t *msg;
    size_t   mlen;
    int      cover_payload, ok;

    if (key == NULL || hdr24 == NULL || mac_out == NULL) {
        return 0;
    }
    cover_payload = (!nodata && payload != NULL && plen > 0);
    mlen = 8 + 24 + (cover_payload ? plen : 0);
    msg  = (uint8_t *) malloc(mlen);
    if (msg == NULL) {
        return 0;
    }
    xrootd_gsi_sigver_seqno_be(seqno, seqbe);
    memcpy(msg, seqbe, 8);
    memcpy(msg + 8, hdr24, 24);
    if (cover_payload) {
        memcpy(msg + 32, payload, plen);
    }
    ok = xrootd_hmac_sha256(key, 32, msg, mlen, mac_out);
    free(msg);
    return ok;
}
