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

#include "../protocol/gsi.h"      /* GSI bucket + step constants (pure header) */
#include "../protocol/opcodes.h"  /* kXR opcodes for the sigver policy */

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
