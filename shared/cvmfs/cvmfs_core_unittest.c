/*
 * cvmfs_core_unittest.c — standalone tests for the shared CVMFS inner-ring core.
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -I src -o /tmp/cvmfs_core_ut \
 *       shared/cvmfs/cvmfs_core_unittest.c \
 *       shared/cvmfs/grammar/classify.c shared/cvmfs/grammar/hash.c \
 *       shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
 *       shared/cvmfs/signature/verify.c shared/cvmfs/config/repo.c \
 *       shared/cvmfs/object/object.c shared/cvmfs/failover/failover.c \
 *       -lcrypto -lz && /tmp/cvmfs_core_ut
 *
 * Exit 0 = all checks pass.
 */
#include "cvmfs/grammar/classify.h"
#include "cvmfs/grammar/hash.h"
#include "cvmfs/signature/manifest.h"
#include "cvmfs/signature/whitelist.h"
#include "cvmfs/signature/verify.h"
#include "cvmfs/config/repo.h"
#include "cvmfs/failover/failover.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks, g_failed;

#define CHECK(cond, name) do {                                    \
    g_checks++;                                                   \
    if (cond) { printf("  ok   %s\n", name); }                    \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

/* ------------------------------------------------------------------ A1 */
static void test_classify(void) {
    cvmfs_url_info_t u;

    const char cas[] = "/cvmfs/atlas.cern.ch/data/ab/"
                       "cdef0123456789abcdef0123456789abcdef01";
    cvmfs_classify_url(cas, strlen(cas), &u);
    CHECK(u.cls == CVMFS_URL_CAS, "cas classified");
    CHECK(u.cas_hex_len == 40 && u.cas_hex[0] == 'a' && u.cas_hex[1] == 'b',
          "cas hex rejoined");

    const char man[] = "/cvmfs/atlas.cern.ch/.cvmfspublished";
    cvmfs_classify_url(man, strlen(man), &u);
    CHECK(u.cls == CVMFS_URL_MANIFEST, "manifest classified");

    const char bad[] = "/etc/passwd";
    cvmfs_classify_url(bad, strlen(bad), &u);
    CHECK(u.cls == CVMFS_URL_REJECT, "escape rejected");   /* security-negative */
}

/* ------------------------------------------------------------------ A2 */
static void test_hash(void) {
    cvmfs_hash_t h;
    const char   hex[] = "cdef0123456789abcdef0123456789abcdef0123";
    CHECK(cvmfs_hash_parse(hex, 40, &h) == 0 && h.algo == CVMFS_HASH_SHA1
          && h.len == 20, "sha1 parsed");

    char path[80];
    int  n = cvmfs_hash_to_object_path(&h, 'C', path, sizeof(path));
    CHECK(n > 0 && strncmp(path, "cd/", 3) == 0 && path[n - 1] == 'C',
          "object path built with suffix");

    cvmfs_hash_t r;
    const char   rmd[] = "cdef0123456789abcdef0123456789abcdef0123-rmd160";
    CHECK(cvmfs_hash_parse(rmd, strlen(rmd), &r) == 0
          && r.algo == CVMFS_HASH_RMD160, "rmd160 suffix parsed");

    const char bad[] = "xyz";
    CHECK(cvmfs_hash_parse(bad, 3, &h) != 0, "bad hash rejected");  /* neg */
}

/* ------------------------------------------------------------------ A3 */
static void test_manifest(void) {
    const char body[] =
        "Cabcdef0123456789abcdef0123456789abcdef01\n"
        "B4096\n"
        "Rd41d8cd98f00b204e9800998ecf8427e\n"
        "Xfedcba9876543210fedcba9876543210fedcba98\n"
        "S42\nNatlas.cern.ch\nT1700000000\nD240\n"
        "--\n"
        "1111111111111111111111111111111111111111\n"
        "\x01\x02\x03\x04";
    cvmfs_manifest_t man;
    int rc = cvmfs_manifest_parse((const unsigned char *) body, sizeof(body) - 1, &man);
    CHECK(rc == 0, "manifest parsed");
    CHECK(man.root_catalog.bytes[0] == 0xab, "root catalog hash");
    CHECK(strcmp(man.repo_name, "atlas.cern.ch") == 0, "repo name");
    CHECK(man.ttl == 240 && man.revision == 42, "ttl+revision");
    CHECK(man.signature_len == 4, "signature blob captured");

    const char trunc[] = "Cabc\n";  /* no --, no sig */
    CHECK(cvmfs_manifest_parse((const unsigned char *) trunc, 5, &man) != 0,
          "truncated manifest rejected");   /* security-negative */
}

/* ------------------------------------------------------------------ A4 */
static void test_whitelist(void) {
    const char w[] =
        "20991231235959\n"
        "Natlas.cern.ch\n"
        "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01\n"
        "--\n"
        "2222222222222222222222222222222222222222\n"
        "\x09\x08\x07";
    cvmfs_whitelist_t wl;
    CHECK(cvmfs_whitelist_parse((const unsigned char *) w, sizeof(w) - 1, &wl) == 0,
          "whitelist parsed");
    CHECK(wl.n_fingerprints == 1, "one fingerprint");
    CHECK(cvmfs_whitelist_lists_fp(&wl,
          "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01") == 1,
          "fingerprint listed");
    CHECK(cvmfs_whitelist_expired(&wl, 1700000000L) == 0, "not expired");
    CHECK(cvmfs_whitelist_expired(&wl, 99999999999L) == 1,
          "expired detected");            /* security-negative */
}

/* ------------------------------------------------------------------ A5 */
/* Sign `msg` the CVMFS way: RAW RSA-PKCS#1-v1.5 of the message bytes (the printed
 * hash text) — no SHA-1 DigestInfo, matching real CVMFS. Returns signature len. */
static size_t cvmfs_style_sign(EVP_PKEY *pk, const unsigned char *msg, size_t mlen,
                               unsigned char *sig, size_t sigcap) {
    EVP_PKEY_CTX *sc = EVP_PKEY_CTX_new(pk, NULL);
    EVP_PKEY_sign_init(sc);
    EVP_PKEY_CTX_set_rsa_padding(sc, RSA_PKCS1_PADDING);
    size_t sl = sigcap;
    EVP_PKEY_sign(sc, sig, &sl, msg, mlen);
    EVP_PKEY_CTX_free(sc);
    return sl;
}

static void test_verify(void) {
    EVP_PKEY *pk = EVP_RSA_gen(2048);
    X509     *x  = X509_new();
    X509_set_pubkey(x, pk);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_sign(x, pk, EVP_sha256());

    BIO  *b   = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b, x);
    char *pem = NULL;
    long  plen = BIO_get_mem_data(b, &pem);

    /* CVMFS signs the printed hash-LINE text, and that line is the body's own
     * SHA-1 digest — recomputing it binds the whole body to the signature.
     * Stock coverage EXCLUDES the trailing "--\n" separator. */
    const char body[] =
        "Cabcdef0123456789abcdef0123456789abcdef01\nNatlas.cern.ch\nD240\n--\n";
    unsigned char bd[20];
    SHA1((const unsigned char *) body, sizeof(body) - 1 - 3, bd);
    char hash_text[41];
    for (int i = 0; i < 20; i++)
        snprintf(hash_text + i * 2, 3, "%02x", bd[i]);
    unsigned char sig[512];
    size_t        sl = cvmfs_style_sign(pk, (const unsigned char *) hash_text,
                                        strlen(hash_text), sig, sizeof(sig));

    unsigned char mb[1024];
    size_t        o = 0;
    memcpy(mb, body, sizeof(body) - 1);   o = sizeof(body) - 1;
    memcpy(mb + o, hash_text, strlen(hash_text)); o += strlen(hash_text);
    mb[o++] = '\n';
    size_t sig_off = o;
    memcpy(mb + o, sig, sl);              o += sl;

    cvmfs_manifest_t man;
    CHECK(cvmfs_manifest_parse(mb, o, &man) == 0, "assembled manifest parses");
    CHECK(man.signed_hash_text_len == strlen(hash_text), "hash-line text captured");
    CHECK(cvmfs_verify_manifest(&man, (unsigned char *) pem, plen) == 0,
          "genuine signature verifies");

    mb[sig_off] ^= 0xff;   /* forge */
    cvmfs_manifest_parse(mb, o, &man);
    CHECK(cvmfs_verify_manifest(&man, (unsigned char *) pem, plen) != 0,
          "forged signature rejected");     /* security-negative */
    mb[sig_off] ^= 0xff;   /* restore the genuine signature */

    /* Body tamper with an AUTHENTIC signature: keep the signed hash-line + RSA
     * signature verbatim, flip a byte in an unsigned body field (here the root
     * catalog hash). The signature still verifies, but SHA1(body) no longer
     * matches the hash-line, so body-binding must refuse it. */
    mb[3] ^= 0xff;
    cvmfs_manifest_parse(mb, o, &man);
    CHECK(cvmfs_verify_manifest(&man, (unsigned char *) pem, plen) != 0,
          "body tamper under a valid signature rejected");  /* security-negative */
    mb[3] ^= 0xff;

    char fp[64];
    CHECK(cvmfs_cert_fingerprint((unsigned char *) pem, plen, fp, sizeof(fp)) == 0
          && strlen(fp) == 59, "cert fingerprint formatted");

    BIO_free(b);
    X509_free(x);
    EVP_PKEY_free(pk);
}

/* ------------------------------------------------------------------ A6 */
static void test_repo_config(void) {
    cvmfs_repo_config_t c;
    CHECK(cvmfs_repo_config_defaults("atlas.cern.ch", &c) == 0, "defaults built");
    CHECK(strcmp(c.name, "atlas.cern.ch") == 0, "name set");
    CHECK(strstr(c.master_pub_path, "cern.ch.pub") != NULL,
          "master key path from domain");
    CHECK(cvmfs_repo_config_add_proxy(&c, "DIRECT") == 0 && c.n_proxies == 1,
          "DIRECT proxy accepted");
    CHECK(cvmfs_repo_config_defaults("no-domain", &c) != 0,
          "FQRN without domain rejected");   /* negative */
}

/* ------------------------------------------------------------------ B */
static void test_failover(void) {
    cvmfs_failover_t fo;
    cvmfs_failover_init(&fo, 60);            /* 60s blacklist reset */
    cvmfs_failover_add_proxy(&fo, "http://proxy-a:3128", 0);
    cvmfs_failover_add_proxy(&fo, "http://proxy-b:3128", 1);
    cvmfs_failover_add_proxy(&fo, "DIRECT", 2);
    cvmfs_failover_add_host(&fo, "http://s1a.cern.ch");
    cvmfs_failover_add_host(&fo, "http://s1b.cern.ch");

    cvmfs_fo_route_t r;
    CHECK(cvmfs_failover_select(&fo, 1000, &r) == 0, "route selected");
    CHECK(r.proxy == 0 && r.host == 0, "lowest group + first host preferred");

    /* SNAP-BACK: proxy-a fails → SHORT (base 2s) probation → failover to next group,
     * then return to the preferred proxy once the probation lapses. */
    cvmfs_failover_record(&fo, &r, 0 /*fail*/, 0, 1000);
    cvmfs_failover_select(&fo, 1001, &r);
    CHECK(r.proxy == 1, "failed proxy → short blacklist → failover to next group");
    cvmfs_failover_select(&fo, 1003, &r);        /* after the ~2s probation */
    CHECK(r.proxy == 0, "snap back to preferred proxy after short probation");

    /* STICKY hosts: selection is by index (geo/preference order), NOT EWMA — even
     * with host-1 measured faster, the closest (index 0) is used while it's live. */
    cvmfs_fo_route_t rh1 = { -1, 1 };
    cvmfs_failover_record(&fo, &rh1, 1, 500, 2000);   /* host1 fast (500us) */
    cvmfs_fo_route_t rh0 = { -1, 0 };
    cvmfs_failover_record(&fo, &rh0, 1, 9000, 2000);  /* host0 slow (9ms)   */
    cvmfs_failover_select(&fo, 2001, &r);
    CHECK(r.host == 0, "sticky: closest (index 0) preferred over faster peer");

    /* fail the closest host → short probation → failover, snap back after. */
    cvmfs_fo_route_t rf0 = { -1, 0 };
    cvmfs_failover_record(&fo, &rf0, 0, 0, 2002);     /* host0 1st fail → 2s (→2004) */
    cvmfs_failover_select(&fo, 2003, &r);
    CHECK(r.host == 1, "closest host benched briefly → failover to next-closest");
    cvmfs_failover_select(&fo, 2005, &r);
    CHECK(r.host == 0, "snap back to closest host");

    /* repeated failure escalates the probation (2s → 4s). */
    cvmfs_failover_record(&fo, &rf0, 0, 0, 2005);     /* host0 2nd fail → 4s (→2009) */
    cvmfs_failover_select(&fo, 2008, &r);
    CHECK(r.host == 1, "repeated failure → longer (escalated) blacklist");
    cvmfs_failover_select(&fo, 2010, &r);
    CHECK(r.host == 0, "returns after escalated probation");

    /* success resets escalation → next failure is short again. */
    cvmfs_failover_record(&fo, &rf0, 1, 1000, 2010);  /* ok → reset fail_count */
    cvmfs_failover_record(&fo, &rf0, 0, 0, 2010);     /* fail → base 2s (→2012) */
    cvmfs_failover_select(&fo, 2013, &r);
    CHECK(r.host == 0, "success resets escalation → short probation again");

    /* geo reorder: promote host-1 to index 0 (as if it were geo-closest). */
    int order[2] = { 1, 0 };
    cvmfs_failover_reorder_hosts(&fo, order, 2);
    cvmfs_failover_select(&fo, 3000, &r);
    CHECK(r.host == 0 && strstr(fo.hosts[0].url, "s1b") != NULL,
          "geo reorder: closest becomes index 0");
    int bad[2] = { 0, 0 };                            /* duplicate → no-op */
    cvmfs_failover_reorder_hosts(&fo, bad, 2);
    CHECK(strstr(fo.hosts[0].url, "s1b") != NULL, "invalid reorder is a no-op");

    /* geo-API order parsing (1-based, comma/newline separated → 0-based). */
    int go[4];
    CHECK(cvmfs_geo_parse_order("2,1,3", 5, go, 4) == 3 && go[0] == 1 && go[1] == 0 && go[2] == 2,
          "geo parse comma-separated");
    CHECK(cvmfs_geo_parse_order("3\n1\n2\n", 7, go, 4) == 3 && go[0] == 2 && go[2] == 1,
          "geo parse newline-separated");
    CHECK(cvmfs_geo_parse_order("", 0, go, 4) == 0, "geo parse empty → 0");

    /* backoff grows and caps. */
    CHECK(cvmfs_failover_backoff_ms(0) == 200, "backoff base");
    CHECK(cvmfs_failover_backoff_ms(3) == 1600, "backoff exponential");
    CHECK(cvmfs_failover_backoff_ms(100) == 30000, "backoff capped");

    /* all endpoints down → select fails → offline mode. */
    cvmfs_failover_t off;
    cvmfs_failover_init(&off, 60);
    cvmfs_failover_add_host(&off, "http://only.cern.ch");
    cvmfs_fo_route_t ro;
    cvmfs_failover_select(&off, 100, &ro);
    cvmfs_failover_record(&off, &ro, 0, 0, 100);
    CHECK(cvmfs_failover_select(&off, 101, &ro) == -1,
          "all-down → offline");           /* security/resilience-negative */
    CHECK(cvmfs_failover_all_down(&off, 101) == 1, "all_down reported");
}

int main(void) {
    test_classify();
    test_hash();
    test_manifest();
    test_whitelist();
    test_verify();
    test_repo_config();
    test_failover();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
