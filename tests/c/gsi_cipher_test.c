/*
 * gsi_cipher_test.c — unit vectors for the shared XrdCryptosslCipher-compatible
 * GSI primitives in src/auth/gsi/gsi_core.c (phase-48 W4).  These verify the crypto
 * MATH is self-consistent (DH agreement survives the Public()/parse_peer wire
 * round-trip; AES-128 encrypt/decrypt round-trips) without needing a live peer —
 * the live-interop check is tests/test_native_gsi_interop.py.  Run by
 * tests/test_gsi_cipher.py.  Prints "ALL PASSED" on success.
 */
#include "auth/gsi/gsi_core.h"
#include "protocols/root/protocol/gsi.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } } while (0)

/* The two ends derive an identical AES-128 key through the wire serialization. */
static void
test_dh_agreement(void)
{
    EVP_PKEY *a = xrootd_gsi_cipher_keygen();
    EVP_PKEY *b = xrootd_gsi_cipher_keygen();
    size_t    la = 0, lb = 0;
    char     *pa, *pb;
    EVP_PKEY *a_peer, *b_peer;
    uint8_t   k1[16], k2[16];

    CHECK(a && b, "cipher_keygen");
    pa = xrootd_gsi_cipher_public(a, &la);
    pb = xrootd_gsi_cipher_public(b, &lb);
    CHECK(pa && pb && la > 0 && lb > 0, "cipher_public");
    /* The blob carries the PEM params + the BPUB/EPUB-framed public key. */
    CHECK(pa && memmem(pa, la, "---BPUB---", 10) && memmem(pa, la, "---EPUB---", 10),
          "public blob framing");

    a_peer = xrootd_gsi_cipher_parse_peer((uint8_t *) pa, la);
    b_peer = xrootd_gsi_cipher_parse_peer((uint8_t *) pb, lb);
    CHECK(a_peer && b_peer, "cipher_parse_peer");

    CHECK(xrootd_gsi_cipher_session_key(b, a_peer, 0, k1, 16), "session_key b·A");
    CHECK(xrootd_gsi_cipher_session_key(a, b_peer, 0, k2, 16), "session_key a·B");
    CHECK(memcmp(k1, k2, 16) == 0, "DH agreement (shared AES key matches)");

    free(pa); free(pb);
    EVP_PKEY_free(a); EVP_PKEY_free(b);
    EVP_PKEY_free(a_peer); EVP_PKEY_free(b_peer);
}

/* Negotiated-cipher encrypt/decrypt with the prepended random IV round-trips,
 * for every cipher the build can resolve (phase-52 WS-A). */
static void
test_encrypt_roundtrip(void)
{
    static const char *names[] = {
        "aes-128-cbc", "aes-256-cbc", "bf-cbc", "des-ede3-cbc"
    };
    size_t  n, i, ctl = 0, ptl = 0;
    uint8_t *ct, *pt;
    /* a multi-block, non-block-aligned payload (exercises PKCS#7 padding) */
    const char *msg = "gsi main: signed_rtag + rtag, 62 bytes of plaintext here!!";

    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        xrootd_gsi_cipher_t c;
        uint8_t             key[XROOTD_GSI_MAX_KEY];

        if (!xrootd_gsi_cipher_lookup(names[n], &c)) {
            /* bf-cbc / des-ede3-cbc need the OpenSSL legacy provider; skip when
             * the build/runtime cannot resolve them. */
            printf("SKIP: %s (provider unavailable)\n", names[n]);
            continue;
        }
        for (i = 0; i < (size_t) c.key_len; i++) { key[i] = (uint8_t) (i * 7 + 1); }

        ct = xrootd_gsi_cipher_encrypt(&c, key, (const uint8_t *) msg,
                                       strlen(msg), 1, &ctl);
        CHECK(ct != NULL, names[n]);
        CHECK(ct == NULL || ctl >= (size_t) c.iv_len + strlen(msg),
              "ciphertext carries IV + padded block");

        pt = xrootd_gsi_cipher_decrypt(&c, key, ct, ctl, 1, &ptl);
        CHECK(pt != NULL, "decrypt");
        CHECK(ptl == strlen(msg) && pt && memcmp(pt, msg, ptl) == 0,
              "encrypt/decrypt round-trip");

        free(ct); free(pt);
    }
}

/* The standard round-1 certreq carries the required buckets + a nested main. */
static void
test_certreq(void)
{
    uint8_t        rtag[8] = { 'r','t','a','g','1','2','3','4' };
    size_t         len = 0;
    uint8_t       *buf;
    const uint8_t *main_buf = NULL, *rt = NULL;
    size_t         main_len = 0, rtlen = 0;

    buf = xrootd_gsi_build_certreq("ssl", 10600, "638d0780.0", 0x80,
                                   rtag, sizeof(rtag), &len);
    CHECK(buf && len > 0, "build_certreq");
    /* The outer buffer must carry cryptomod + the main bucket. */
    CHECK(buf && xrootd_gsi_find_bucket(buf, len, kXRS_cryptomod, &rt, &rtlen) == 0
          && rtlen == 3 && memcmp(rt, "ssl", 3) == 0, "cryptomod bucket");
    CHECK(buf && xrootd_gsi_find_bucket(buf, len, kXRS_main, &main_buf, &main_len) == 0,
          "main bucket present");
    /* The nested main must carry the client rtag. */
    CHECK(main_buf && xrootd_gsi_find_bucket(main_buf, main_len, kXRS_rtag,
                                             &rt, &rtlen) == 0
          && rtlen == 8 && memcmp(rt, rtag, 8) == 0, "nested rtag");
    free(buf);
}

/* parms parsing for "v:...,c:...,ca:..." */
static void
test_parms(void)
{
    uint32_t v = 0;
    char     crypto[16] = { 0 }, ca[64] = { 0 };

    xrootd_gsi_parse_parms("v:10600,c:ssl,ca:638d0780.0|7a2dc0da.0",
                           &v, crypto, sizeof(crypto), ca, sizeof(ca));
    CHECK(v == 10600, "parms version");
    CHECK(strcmp(crypto, "ssl") == 0, "parms crypto");
    CHECK(strcmp(ca, "638d0780.0|7a2dc0da.0") == 0, "parms ca");
}

/* EncryptPrivate (sign) then DecryptPublic (verify-recover) round-trips — the
 * v>=DHsigned cipher-signing layer.  >key-size payload exercises the chunking. */
static void
test_rsa_sign_recover(void)
{
    EVP_PKEY     *rsa = NULL;
    EVP_PKEY_CTX *kc  = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    uint8_t       msg[600], sig[2048], rec[2048];
    size_t        i, slen, rlen;

    CHECK(kc && EVP_PKEY_keygen_init(kc) == 1
          && EVP_PKEY_CTX_set_rsa_keygen_bits(kc, 2048) == 1
          && EVP_PKEY_keygen(kc, &rsa) == 1, "rsa keygen");
    for (i = 0; i < sizeof(msg); i++) { msg[i] = (uint8_t) (i & 0xff); }

    slen = xrootd_gsi_rsa_encrypt_private(rsa, msg, sizeof(msg), sig, sizeof(sig));
    CHECK(slen > 0, "encrypt_private (chunked sign)");
    rlen = xrootd_gsi_rsa_decrypt_public(rsa, sig, slen, rec, sizeof(rec));
    CHECK(rlen == sizeof(msg) && memcmp(rec, msg, rlen) == 0,
          "decrypt_public recovers the signed blob");

    EVP_PKEY_CTX_free(kc);
    EVP_PKEY_free(rsa);
}

int
main(void)
{
    test_parms();
    test_certreq();
    test_dh_agreement();
    test_encrypt_roundtrip();
    test_rsa_sign_recover();
    if (fails == 0) {
        printf("ALL PASSED\n");
        return 0;
    }
    printf("%d CHECK(S) FAILED\n", fails);
    return 1;
}
