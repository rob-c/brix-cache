/*
 * gsi_interop_test.c — server/dCache/EOS GSI interoperability invariants.
 *
 * WHAT: Pins the shared-gsi_core wire behaviors that real-XRootD interop depends
 *       on, so a refactor cannot silently regress support for EOS / dCache / stock
 *       XRootD. Compiled against the *shared* src/gsi/gsi_core.c + src/compat/
 *       crypto.c (the exact code in both the nginx server and the native client),
 *       and run with no live peer. Prints "ALL PASSED" on success; driven by
 *       tests/test_gsi_interop_guards.py.
 *
 * WHY: The GSI handshake broke against real dCache and EOS in three places that
 *      have no other CI-visible signal: (1) the IV must be present-and-advertised
 *      together (version-gated useIV + "cipher#ivlen" suffix) — a peer that
 *      disagrees on the IV bit must FAIL, never silently half-work; (2) the
 *      cipher allowlist must stay closed and aes-128-cbc-first; (3) the encrypted
 *      bucket list must end with a kXRS_none terminator (dCache parses until it).
 *      These asserts make each of those load-bearing facts a red test if reverted.
 *
 * Clean-room: links only the public gsi_core API. See
 *      docs/10-reference/comparison/xrootd-implementations.md §5.
 */
#include "gsi/gsi_core.h"
#include "protocol/gsi.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/crypto.h>

static int fails;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } } while (0)

/*
 * Invariant 1 — the IV is load-bearing.
 * Stock XRootD keys useIV off the negotiated version (>=10400 signed-DH) and
 * advertises the length via the kXRS_cipher_alg "name#ivlen" suffix; EOS REQUIRES
 * the IV, dCache accepts it. The critical anti-regression property is that the two
 * directions must AGREE: a ciphertext produced with use_iv=1 must NOT decrypt with
 * use_iv=0 (or vice-versa). If that ever silently "works", a future client/server
 * that disagrees on the IV would appear to interoperate and then corrupt data.
 */
static void
test_iv_is_load_bearing(void)
{
    xrootd_gsi_cipher_t c;
    const char         *msg = "the quick brown fox jumps over the lazy dog!!";
    uint8_t             key[XROOTD_GSI_MAX_KEY];
    uint8_t            *ct_iv = NULL, *ct_noiv = NULL, *pt = NULL;
    size_t              ctl_iv = 0, ctl_noiv = 0, ptl = 0;
    size_t              i;

    for (i = 0; i < sizeof(key); i++) { key[i] = (uint8_t) (i * 7 + 1); }

    if (!xrootd_gsi_cipher_lookup("aes-128-cbc", &c)) {
        printf("SKIP: aes-128-cbc unavailable\n");
        return;
    }

    ct_iv   = xrootd_gsi_cipher_encrypt(&c, key, (const uint8_t *) msg,
                                        strlen(msg), 1, &ctl_iv);
    ct_noiv = xrootd_gsi_cipher_encrypt(&c, key, (const uint8_t *) msg,
                                        strlen(msg), 0, &ctl_noiv);
    CHECK(ct_iv != NULL && ct_noiv != NULL, "encrypt returned NULL");

    if (ct_iv != NULL && ct_noiv != NULL) {
        /* use_iv prepends exactly iv_len bytes; the CBC/PKCS body is identical. */
        CHECK(ctl_iv == ctl_noiv + (size_t) c.iv_len,
              "use_iv=1 must prepend exactly iv_len bytes (the #ivlen contract)");

        /* Matching directions round-trip. */
        pt = xrootd_gsi_cipher_decrypt(&c, key, ct_iv, ctl_iv, 1, &ptl);
        CHECK(pt != NULL && ptl == strlen(msg)
              && memcmp(pt, msg, ptl) == 0, "use_iv=1 round-trip failed");
        free(pt); pt = NULL;

        pt = xrootd_gsi_cipher_decrypt(&c, key, ct_noiv, ctl_noiv, 0, &ptl);
        CHECK(pt != NULL && ptl == strlen(msg)
              && memcmp(pt, msg, ptl) == 0, "use_iv=0 round-trip failed");
        free(pt); pt = NULL;

        /* Mismatched directions MUST NOT yield the plaintext (the whole point). */
        pt = xrootd_gsi_cipher_decrypt(&c, key, ct_iv, ctl_iv, 0, &ptl);
        CHECK(pt == NULL || ptl != strlen(msg) || memcmp(pt, msg, ptl) != 0,
              "decrypt(use_iv=0) of a use_iv=1 ciphertext must NOT succeed");
        free(pt); pt = NULL;

        pt = xrootd_gsi_cipher_decrypt(&c, key, ct_noiv, ctl_noiv, 1, &ptl);
        CHECK(pt == NULL || ptl != strlen(msg) || memcmp(pt, msg, ptl) != 0,
              "decrypt(use_iv=1) of a use_iv=0 ciphertext must NOT succeed");
        free(pt); pt = NULL;
    }
    free(ct_iv);
    free(ct_noiv);
}

/*
 * Invariant 2 — the cipher allowlist stays closed and aes-128-cbc-first.
 * Interop with stock XRootD/EOS/dCache requires aes-128-cbc to be the preferred
 * default (byte-identical handshake), and the negotiator must never key an
 * attacker-named arbitrary EVP cipher.
 */
static void
test_cipher_negotiation(void)
{
    xrootd_gsi_cipher_t c;
    char                name[24];

    /* Default preference list must lead with aes-128-cbc. */
    CHECK(strncmp(xrootd_gsi_cipher_default_list(), "aes-128-cbc", 11) == 0,
          "default cipher list must start with aes-128-cbc");

    /* aes-128-cbc resolves to a 16/16 cipher. */
    CHECK(xrootd_gsi_cipher_lookup("aes-128-cbc", &c)
          && c.key_len == 16 && c.iv_len == 16,
          "aes-128-cbc must resolve to key=16 iv=16");

    /* An unknown name is rejected (closed allowlist, not EVP_get_cipherbyname). */
    CHECK(!xrootd_gsi_cipher_lookup("rc4", &c)
          && !xrootd_gsi_cipher_lookup("totally-bogus-cbc", &c),
          "unknown cipher names must be rejected by the allowlist");

    /* Pick skips an unknown leading token and selects a supported one. */
    name[0] = '\0';
    CHECK(xrootd_gsi_cipher_pick("bogus-cbc:aes-128-cbc", &c, name)
          && strcmp(name, "aes-128-cbc") == 0,
          "pick must skip unknown tokens and select aes-128-cbc");

    /* Pick honors a server offering aes-256 first (we support it). */
    name[0] = '\0';
    CHECK(xrootd_gsi_cipher_pick("aes-256-cbc:aes-128-cbc", &c, name)
          && c.key_len == 32,
          "pick must honor a server's aes-256-cbc-first offer");
}

/*
 * Invariant 3 — the encrypted bucket list ends with a kXRS_none terminator.
 * A standards-compliant peer (dCache/xrootd4j, stock XrdSecgsi) parses buckets
 * until kXRS_none and overruns the buffer without it ("readerIndex exceeds
 * writerIndex"). gbuf_end() must append it, and find_bucket() must still locate
 * earlier buckets.
 */
static void
test_bucket_terminator(void)
{
    xrootd_gbuf    g;
    const char    *pem = "-----BEGIN CERT-----proxy-----END CERT-----";
    size_t         len_no_term;
    const uint8_t *found = NULL;
    size_t         found_len = 0;

    xrootd_gbuf_init(&g);
    xrootd_gbuf_start(&g, (uint32_t) kXGC_cert);
    xrootd_gbuf_bucket(&g, (uint32_t) kXRS_x509, pem, strlen(pem));
    len_no_term = g.len;
    xrootd_gbuf_end(&g);

    CHECK(!g.err, "gbuf must not error");
    CHECK(g.len == len_no_term + 4,
          "gbuf_end must append a 4-byte kXRS_none terminator");
    /* The trailing 4 bytes are kXRS_none (0) big-endian. */
    CHECK(g.len >= 4 && g.p[g.len-4] == 0 && g.p[g.len-3] == 0
          && g.p[g.len-2] == 0 && g.p[g.len-1] == 0,
          "terminator must be kXRS_none (0x00000000)");
    /* The terminator must not break parsing of earlier buckets. */
    CHECK(xrootd_gsi_find_bucket(g.p, g.len, (uint32_t) kXRS_x509,
                                 &found, &found_len) == 0
          && found_len == strlen(pem)
          && memcmp(found, pem, found_len) == 0,
          "kXRS_x509 must be findable past the terminator");

    xrootd_gbuf_free(&g);
}

int
main(void)
{
    OPENSSL_init_crypto(0, NULL);
    test_iv_is_load_bearing();
    test_cipher_negotiation();
    test_bucket_terminator();

    if (fails == 0) {
        printf("ALL PASSED\n");
        return 0;
    }
    printf("%d CHECK(S) FAILED\n", fails);
    return 1;
}
