/*
 * gsi_cipher.c - extracted concern
 * Phase-38 split of gsi_core.c; behavior-identical.
 */
#include "gsi_core_internal.h"
#include "core/compat/openssl_auto.h"   /* XRD_AUTO scope cleanup for EVP_CIPHER_CTX */


EVP_PKEY *
brix_gsi_cipher_keygen(void)
{
    return gsi_dh_keygen_with(NULL);
}


EVP_PKEY *
brix_gsi_cipher_keygen_from(EVP_PKEY *peer)
{
    /* CRITICAL: key with the PEER's params, not the fixed group — a peer may use
     * a different DH group (e.g. ffdhe2048 vs the fixed 3072-bit) and the derive
     * only works when both sides share the group. */
    return gsi_dh_keygen_with(peer);
}


char *
brix_gsi_cipher_public(EVP_PKEY *dh, size_t *outlen)
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
            /* phase74-fp: out is a length-tracked binary blob (*outlen); both
             * consumers (pwd credsreq, gsi kXGC_cert) bucket it by length and
             * never treat it as a NUL-terminated string. */
            memcpy(out + cur, pem, (size_t) pemlen); cur += (size_t) pemlen;  // NOLINT(bugprone-not-null-terminated-result)
            memcpy(out + cur, "---BPUB---", 10);     cur += 10;               // NOLINT(bugprone-not-null-terminated-result)
            memcpy(out + cur, phex, strlen(phex));   cur += strlen(phex);     // NOLINT(bugprone-not-null-terminated-result)
            memcpy(out + cur, "---EPUB---", 10);     cur += 10;               // NOLINT(bugprone-not-null-terminated-result)
            *outlen = cur;
        }
    }

    if (phex != NULL) { OPENSSL_free(phex); }
    BIO_free(bio);
    return out;
}


EVP_PKEY *
brix_gsi_cipher_parse_peer(const uint8_t *buf, size_t len)
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


/*                                                                       */
/* cbc).  The session key is the first EVP_CIPHER_key_length bytes of the */
/* (16 for AES, 8 for Blowfish/3DES).  We allow only this fixed set (so a */
/* hostile peer cannot select an arbitrary/weak EVP cipher by name), and */
/* provider (OpenSSL 3 legacy) is loaded — aes-128/256 are always present. */

/* Allowlist of negotiable GSI session ciphers (XrdCrypto/OpenSSL names). */

const char *
brix_gsi_cipher_default_list(void)
{
    return "aes-128-cbc:aes-256-cbc:bf-cbc:des-ede3-cbc";
}


/* Best-effort one-shot load of the OpenSSL 3 legacy provider so bf-cbc /
 * des-ede3-cbc resolve.  No-op / harmless when unavailable; aes-* never need it. */
void
gsi_load_legacy_once(void)
{
    static int tried = 0;
    if (!tried) {
        tried = 1;
        (void) OSSL_PROVIDER_load(NULL, "legacy");
        (void) OSSL_PROVIDER_load(NULL, "default");
    }
}


int
brix_gsi_cipher_lookup(const char *name, brix_gsi_cipher_t *out)
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
    if (out->key_len <= 0 || out->key_len > BRIX_GSI_MAX_KEY
        || out->iv_len < 0 || out->iv_len > BRIX_GSI_MAX_IV) {
        return 0;
    }
    return 1;
}


int
brix_gsi_cipher_pick(const char *offered, brix_gsi_cipher_t *out,
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
            if (brix_gsi_cipher_lookup(name, out)) {
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
brix_gsi_cipher_session_key(EVP_PKEY *mine, EVP_PKEY *peer, int padded,
                              uint8_t *key, int key_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(mine, NULL);
    uint8_t      *secret;
    size_t        slen = 0;
    int           ok = 0;

    /* `padded` MUST match the peer's XrdSecgsi HasPad: pre-DHsigned (<10400)
     * peers use dh_pad=0 (leading zeros stripped), newer ones dh_pad=1.  The
     * session key is the first key_len bytes of the resulting secret. */
    if (key_len <= 0 || key_len > BRIX_GSI_MAX_KEY
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
brix_gsi_cipher_encrypt(const brix_gsi_cipher_t *c, const uint8_t *key,
                          const uint8_t *in, size_t inlen, int use_iv,
                          size_t *outlen)
{
    XRD_AUTO(EVP_CIPHER_CTX) *ctx = EVP_CIPHER_CTX_new();
    uint8_t         iv[BRIX_GSI_MAX_IV];
    size_t          ivl = (size_t) c->iv_len;
    size_t          off = use_iv ? ivl : 0;    /* IV prepended only when use_iv */
    uint8_t        *out;
    int             l1 = 0, l2 = 0;

    /* ctx is scope-owned (XRD_AUTO): freed automatically on every return below.
     * use_iv: a fresh random IV is prepended (XrdSecgsi >=DHsigned).  Otherwise
     * a zero IV is used and nothing is prepended (pre-DHsigned peers). */
    if (ctx == NULL) {
        return NULL;
    }
    if (use_iv) {
        if (RAND_bytes(iv, c->iv_len) != 1) {
            return NULL;
        }
    } else {
        memset(iv, 0, ivl);
    }
    out = (uint8_t *) malloc(off + inlen + (size_t) EVP_CIPHER_block_size(c->evp));
    if (out == NULL) {
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
        free(out);              /* out is caller-owned on success — freed only here */
        out = NULL;
    }
    return out;
}


uint8_t *
brix_gsi_cipher_decrypt(const brix_gsi_cipher_t *c, const uint8_t *key,
                          const uint8_t *in, size_t inlen, int use_iv,
                          size_t *outlen)
{
    XRD_AUTO(EVP_CIPHER_CTX) *ctx = EVP_CIPHER_CTX_new();
    uint8_t         iv[BRIX_GSI_MAX_IV];
    size_t          ivl = (size_t) c->iv_len;
    size_t          off = use_iv ? ivl : 0;
    uint8_t        *out;
    int             l1 = 0, l2 = 0;

    /* ctx is scope-owned (XRD_AUTO): freed automatically on every return below. */
    if (ctx == NULL || inlen < off) {
        return NULL;
    }
    if (use_iv) {
        memcpy(iv, in, ivl);                      /* IV is the first iv_len bytes */
    } else {
        memset(iv, 0, ivl);
    }
    out = (uint8_t *) malloc(inlen - off + (size_t) EVP_CIPHER_block_size(c->evp));
    if (out == NULL) {
        return NULL;
    }
    if (EVP_DecryptInit_ex(ctx, c->evp, NULL, key, iv) == 1
        && EVP_DecryptUpdate(ctx, out, &l1, in + off, (int) (inlen - off)) == 1
        && EVP_DecryptFinal_ex(ctx, out + l1, &l2) == 1) {
        *outlen = (size_t) l1 + (size_t) l2;    /* widen BEFORE adding */
    } else {
        free(out);              /* out is caller-owned on success — freed only here */
        out = NULL;
    }
    return out;
}
