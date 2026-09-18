/*
 * credinfo_voms_unittest.c — unit test for the VOMS narration in
 * credinfo_voms.c (brix_credinfo_voms_explain over the shared native decoder).
 *
 *   cc $(ALL_CFLAGS from client/Makefile) -Werror \
 *      lib/auth/cred/credinfo_voms_unittest.c \
 *      ../shared/voms/voms_asn1.c ../shared/voms/voms_decode.c \
 *      ../shared/voms/voms_verify.c ../shared/voms/voms_lsc.c \
 *      libbrix.a ../shared/xrdproto/libxrdproto.a $(LDLIBS from client/Makefile) \
 *      -o /tmp/vut && /tmp/vut                                  (run from client/)
 *
 * Exit 0 = all checks pass. The REAL credinfo.c and credinfo_voms.c are
 * #included (the chain loader and the renderer's helpers are static); the
 * remaining libbrix/openssl symbols come from the archive. Driven over the
 * shared GENUINE LHCb-proxy VOMS extension (shared/voms/voms_ac_fixture.h).
 *
 * Success: the fixture on the leaf, and on a chain member, prints exactly the
 * two FQANs once each plus a vo=lhcb summary. Error: no extension → "none";
 * truncated DER → "undecodable". Security-negative: with trust directories
 * present, a certificate that is NOT the AC's holder is reported "NOT
 * verified" — never "verified".
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE            /* open_memstream, mkdtemp, setenv */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "credinfo.c"           /* real chain loader under test (static) */
#include "credinfo_voms.c"      /* real renderer under test (static helpers) */
#include "voms/voms_ac_fixture.h"

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

#define FQAN_USER "      VOMS:  /lhcb/Role=user/Capability=NULL\n"
#define FQAN_NULL "      VOMS:  /lhcb/Role=NULL/Capability=NULL\n"

static int
has(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

/* Count non-overlapping occurrences of needle in hay. */
static int
count(const char *hay, const char *needle)
{
    int         n = 0;
    const char *p = hay;
    size_t      nl = strlen(needle);

    while ((p = strstr(p, needle)) != NULL) { n++; p += nl; }
    return n;
}

/* A throwaway self-signed CN=nobody certificate, optionally carrying `ext_der`
 * as its VOMS extension. Never the fixture AC's holder. */
static X509 *
make_cert(const unsigned char *ext_der, int ext_len)
{
    EVP_PKEY  *key = EVP_RSA_gen(2048);
    X509      *cert = X509_new();
    X509_NAME *name = X509_NAME_new();

    CHECK(key != NULL && cert != NULL && name != NULL);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *) "nobody", -1, -1, 0);
    X509_set_version(cert, 2);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_set_pubkey(cert, key);
    if (ext_der != NULL) {
        ASN1_OCTET_STRING *data = ASN1_OCTET_STRING_new();
        ASN1_OBJECT       *obj = OBJ_txt2obj(BRIX_VOMS_OID_ACSEQ, 1);
        X509_EXTENSION    *ext;

        ASN1_OCTET_STRING_set(data, ext_der, ext_len);
        ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 0, data);
        CHECK(ext != NULL && X509_add_ext(cert, ext, -1) == 1);
        X509_EXTENSION_free(ext);
        ASN1_OBJECT_free(obj);
        ASN1_OCTET_STRING_free(data);
    }
    CHECK(X509_sign(cert, key, EVP_sha256()) > 0);
    X509_NAME_free(name);
    EVP_PKEY_free(key);
    return cert;
}

/* Render brix_credinfo_voms_explain(leaf, chain) to a heap string (caller frees). */
static char *
render(X509 *leaf, STACK_OF(X509) *chain)
{
    char   *buf = NULL;
    size_t  sz = 0;
    FILE   *ms = open_memstream(&buf, &sz);

    brix_credinfo_voms_explain(leaf, chain, ms);
    fclose(ms);
    return buf;
}

/* The decoded-facts pins every fixture rendering must satisfy. */
static void
check_fixture_facts(const char *s)
{
    CHECK(count(s, FQAN_USER) == 1);
    CHECK(count(s, FQAN_NULL) == 1);
    CHECK(count(s, "      VOMS:  /") == 2);                 /* exactly two FQAN lines */
    CHECK(count(s, "      VOMS:  vo=lhcb server=voms-lhcb-auth.cern.ch:443 "
                   "issuer=/DC=ch/DC=cern/OU=computers/CN=lhcb-auth.cern.ch "
                   "valid 2026-08-03T10:34:22Z..2026-08-10T10:34:22Z\n") == 1);
    /* none of the blind-scan noise the old byte parser emitted */
    CHECK(!has(s, "cafiles.cern.ch"));                      /* signer CRL/AIA URI */
    CHECK(!has(s, "ocsp.cern.ch"));                         /* signer OCSP URI */
    CHECK(!has(s, "ldap:"));                                /* signer LDAP CRL URI */
    CHECK(!has(s, "Capability=NULL0"));                     /* trailing tag byte */
    CHECK(!has(s, ":4430"));                                /* URI port over-read */
    CHECK(!has(s, "undecodable"));
    CHECK(!has(s, "VOMS:  none"));
}

/* Success: the fixture on the leaf, no trust dirs → decoded + "unverified". */
static void
test_leaf_decodes(X509 *with_ext)
{
    char *s;

    setenv("X509_CERT_DIR", "/nonexistent/certificates", 1);
    setenv("X509_VOMS_DIR", "/nonexistent/vomsdir", 1);
    s = render(with_ext, NULL);
    check_fixture_facts(s);
    CHECK(count(s, "      VOMS:  unverified (no /nonexistent/certificates)\n") == 1);
    CHECK(count(s, "      VOMS:  ") == 4);                  /* 2 FQAN + summary + verdict */
    CHECK(!has(s, "      VOMS:  verified\n"));
    CHECK(!has(s, "NOT verified"));
    free(s);
}

/* Success: a plain leaf whose CHAIN member carries the extension is found. */
static void
test_chain_member_decodes(X509 *plain, X509 *with_ext)
{
    STACK_OF(X509) *chain = sk_X509_new_null();
    char           *s;

    CHECK(sk_X509_push(chain, with_ext) == 1);
    s = render(plain, chain);
    check_fixture_facts(s);
    free(s);
    sk_X509_free(chain);                                    /* borrowed member */
}

/* Error: no extension anywhere → exactly "VOMS:  none". */
static void
test_no_extension(X509 *plain)
{
    char *s = render(plain, NULL);

    CHECK(strcmp(s, "      VOMS:  none\n") == 0);
    free(s);
}

/* Error: a truncated AC_SEQ → "present (undecodable: ...)", no FQAN lines. */
static void
test_truncated(void)
{
    X509 *bad = make_cert(VOMS_AC_FIXTURE, (int) VOMS_AC_FIXTURE_LEN / 2);
    char *s = render(bad, NULL);

    CHECK(has(s, "      VOMS:  present (undecodable: "));
    CHECK(count(s, "      VOMS:  ") == 1);
    CHECK(!has(s, "/lhcb/"));
    free(s);
    X509_free(bad);
}

/* Security-negative: trust directories present, but the certificate is not
 * the AC's holder → "NOT verified: ..." — the verdict is never "verified". */
static void
test_not_holder_is_rejected(X509 *with_ext)
{
    const char *tmp = getenv("TMPDIR");
    char        cert_dir[256], voms_dir[256];
    char       *s;

    snprintf(cert_dir, sizeof(cert_dir), "%s/credinfo_voms_certs_XXXXXX",
             (tmp != NULL && tmp[0] != '\0') ? tmp : "/tmp");
    snprintf(voms_dir, sizeof(voms_dir), "%s/credinfo_voms_vomsdir_XXXXXX",
             (tmp != NULL && tmp[0] != '\0') ? tmp : "/tmp");
    CHECK(mkdtemp(cert_dir) != NULL && mkdtemp(voms_dir) != NULL);
    setenv("X509_CERT_DIR", cert_dir, 1);
    setenv("X509_VOMS_DIR", voms_dir, 1);
    s = render(with_ext, NULL);
    check_fixture_facts(s);
    CHECK(count(s, "      VOMS:  NOT verified: ") == 1);
    CHECK(!has(s, "      VOMS:  verified\n"));
    CHECK(!has(s, "unverified"));
    free(s);
    rmdir(cert_dir);
    rmdir(voms_dir);
}

int
main(void)
{
    X509 *plain = make_cert(NULL, 0);
    X509 *with_ext = make_cert(VOMS_AC_FIXTURE, (int) VOMS_AC_FIXTURE_LEN);

    test_leaf_decodes(with_ext);
    test_chain_member_decodes(plain, with_ext);
    test_no_extension(plain);
    test_truncated();
    test_not_holder_is_rejected(with_ext);

    X509_free(plain);
    X509_free(with_ext);
    if (g_fail) {
        printf("%d CHECK(s) FAILED\n", g_fail);
        return 1;
    }
    printf("OK all VOMS AC parser checks passed\n");
    return 0;
}
