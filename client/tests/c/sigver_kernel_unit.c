/* sigver_kernel_unit.c — brix_gsi_sigver_{hash,sign,verify}: the shared
 * secver-0 request-signing kernels (stock XrdSecProtect scheme: SHA-256 over
 * seqno_be || hdr24 || payload-unless-nodata, encrypted with the GSI session
 * cipher, fresh IV prepended when use_iv).  Covers the sign→verify roundtrip
 * in both IV modes, the nodata payload exclusion, and the tamper negatives:
 * corrupted/truncated blob, wrong key, wrong seqno, altered header/payload.
 * Build+run: see the `test` target in client/Makefile (links the client lib +
 * libxrdproto + OpenSSL, same recipe as every unit test here). */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "auth/gsi/gsi_core.h"
#include "core/compat/crypto.h"   /* brix_crypto_init — arms brix_sha256 */

/* Fixed session key material (32 bytes: enough for aes-256-cbc). */
static const uint8_t KEY[32] = {
    0x8f, 0x1d, 0x4a, 0x3c, 0x55, 0xe2, 0x90, 0x7b,
    0x06, 0xc9, 0xd8, 0x21, 0x6e, 0xb4, 0x3f, 0xa7,
    0x19, 0x72, 0xee, 0x0d, 0x84, 0x5b, 0xc1, 0x30,
    0xfa, 0x47, 0x9c, 0x62, 0x0b, 0xd5, 0x2e, 0x98,
};

static void
fill_hdr(uint8_t hdr[24], uint16_t reqid)
{
    memset(hdr, 0, 24);
    hdr[0] = 0xab;                       /* streamid */
    hdr[1] = 0xcd;
    hdr[2] = (uint8_t) (reqid >> 8);     /* requestid, big-endian */
    hdr[3] = (uint8_t) reqid;
    hdr[4] = 0x11;                       /* arbitrary body bytes */
    hdr[23] = 0x42;
}

/* Roundtrip + every single-field perturbation must break verification. */
static void
test_roundtrip_and_tampers(void)
{
    brix_gsi_cipher_t c;
    uint8_t  hdr[24], bad[24];
    uint8_t  payload[] = "covered-payload-bytes";
    uint8_t *sig;
    size_t   siglen = 0;
    uint8_t  key2[32];

    assert(brix_gsi_cipher_lookup("aes-128-cbc", &c));
    fill_hdr(hdr, 3010);

    sig = brix_gsi_sigver_sign(&c, KEY, 0, 7, hdr,
                                 payload, sizeof(payload), 0, &siglen);
    assert(sig != NULL && siglen > 0 && siglen <= BRIX_GSI_SIGVER_SIG_MAX);

    assert(brix_gsi_sigver_verify(&c, KEY, 0, sig, siglen, 7, hdr,
                                    payload, sizeof(payload), 0) == 1);

    /* Wrong seqno (replay protection depends on seqno being covered). */
    assert(brix_gsi_sigver_verify(&c, KEY, 0, sig, siglen, 8, hdr,
                                    payload, sizeof(payload), 0) == 0);

    /* Altered header (opcode swap open→rm must not verify). */
    memcpy(bad, hdr, 24);
    bad[3] = (uint8_t) (bad[3] + 1);
    assert(brix_gsi_sigver_verify(&c, KEY, 0, sig, siglen, 7, bad,
                                    payload, sizeof(payload), 0) == 0);

    /* Altered payload. */
    payload[0] ^= 0x01;
    assert(brix_gsi_sigver_verify(&c, KEY, 0, sig, siglen, 7, hdr,
                                    payload, sizeof(payload), 0) == 0);
    payload[0] ^= 0x01;

    /* Corrupted blob byte. */
    sig[siglen / 2] ^= 0x40;
    assert(brix_gsi_sigver_verify(&c, KEY, 0, sig, siglen, 7, hdr,
                                    payload, sizeof(payload), 0) == 0);
    sig[siglen / 2] ^= 0x40;

    /* Truncated blob. */
    assert(brix_gsi_sigver_verify(&c, KEY, 0, sig, siglen - 1, 7, hdr,
                                    payload, sizeof(payload), 0) == 0);

    /* Wrong key. */
    memcpy(key2, KEY, sizeof(key2));
    key2[0] ^= 0xff;
    assert(brix_gsi_sigver_verify(&c, key2, 0, sig, siglen, 7, hdr,
                                    payload, sizeof(payload), 0) == 0);

    free(sig);
}

/* use_iv=1 (signed-DH peers): a fresh IV is prepended, so two signatures of
 * the same request differ on the wire yet both verify; an IV-mode mismatch
 * between signer and verifier must fail. */
static void
test_iv_mode(void)
{
    brix_gsi_cipher_t c;
    uint8_t  hdr[24];
    uint8_t  payload[] = "iv-mode-payload";
    uint8_t *s1, *s2;
    size_t   l1 = 0, l2 = 0;

    assert(brix_gsi_cipher_lookup("aes-256-cbc", &c));
    fill_hdr(hdr, 3019);

    s1 = brix_gsi_sigver_sign(&c, KEY, 1, 42, hdr, payload, sizeof(payload), 0, &l1);
    s2 = brix_gsi_sigver_sign(&c, KEY, 1, 42, hdr, payload, sizeof(payload), 0, &l2);
    assert(s1 != NULL && s2 != NULL && l1 == l2);
    assert(memcmp(s1, s2, l1) != 0);   /* fresh IV each time */

    assert(brix_gsi_sigver_verify(&c, KEY, 1, s1, l1, 42, hdr,
                                    payload, sizeof(payload), 0) == 1);
    assert(brix_gsi_sigver_verify(&c, KEY, 1, s2, l2, 42, hdr,
                                    payload, sizeof(payload), 0) == 1);

    /* Verifier expecting no IV must reject an IV-framed blob. */
    assert(brix_gsi_sigver_verify(&c, KEY, 0, s1, l1, 42, hdr,
                                    payload, sizeof(payload), 0) == 0);

    free(s1);
    free(s2);
}

/* nodata (kXR_write/kXR_pgwrite below secOData): the payload is excluded from
 * the hash, so a different payload still verifies — but only when BOTH sides
 * agree on the flag. */
static void
test_nodata_exclusion(void)
{
    brix_gsi_cipher_t c;
    uint8_t  hdr[24];
    uint8_t  pay_a[] = "payload-as-signed";
    uint8_t  pay_b[] = "totally-different!";
    uint8_t *sig;
    size_t   siglen = 0;

    assert(brix_gsi_cipher_lookup("aes-128-cbc", &c));
    fill_hdr(hdr, 3019);

    sig = brix_gsi_sigver_sign(&c, KEY, 0, 3, hdr, pay_a, sizeof(pay_a), 1, &siglen);
    assert(sig != NULL && siglen > 0);

    assert(brix_gsi_sigver_verify(&c, KEY, 0, sig, siglen, 3, hdr,
                                    pay_b, sizeof(pay_b), 1) == 1);
    assert(brix_gsi_sigver_verify(&c, KEY, 0, sig, siglen, 3, hdr,
                                    pay_a, sizeof(pay_a), 0) == 0);

    free(sig);
}

/* The bare hash kernel: deterministic, and every covered field perturbs it. */
static void
test_hash_kernel(void)
{
    uint8_t hdr[24];
    uint8_t payload[] = "hash-me";
    uint8_t h1[32], h2[32];

    fill_hdr(hdr, 3004);

    assert(brix_gsi_sigver_hash(1, hdr, payload, sizeof(payload), 0, h1) == 1);
    assert(brix_gsi_sigver_hash(1, hdr, payload, sizeof(payload), 0, h2) == 1);
    assert(memcmp(h1, h2, 32) == 0);

    assert(brix_gsi_sigver_hash(2, hdr, payload, sizeof(payload), 0, h2) == 1);
    assert(memcmp(h1, h2, 32) != 0);

    /* nodata=1 must equal hashing with no payload at all. */
    assert(brix_gsi_sigver_hash(1, hdr, payload, sizeof(payload), 1, h1) == 1);
    assert(brix_gsi_sigver_hash(1, hdr, NULL, 0, 0, h2) == 1);
    assert(memcmp(h1, h2, 32) == 0);
}

int
main(void)
{
    assert(brix_crypto_init() == 1);   /* the client arms this via pthread_once */
    test_roundtrip_and_tampers();
    test_iv_mode();
    test_nodata_exclusion();
    test_hash_kernel();
    printf("sigver_kernel_unit: ALL PASS\n");
    return 0;
}
