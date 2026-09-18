/*
 * shared/voms/voms_ac_unittest.c — unit suite for the native VOMS AC verifier
 *
 * Driven over a GENUINE LHCb-proxy VOMS extension (voms_ac_fixture.h): the
 * AC was signed by lhcb-auth.cern.ch, whose certificate is embedded, so the
 * signature check is exercised against real VOMS output. The holder (the
 * user's end-entity certificate) is not in the fixture; the suite rebuilds a
 * stand-in with the AC's own holder name and serial.
 *
 *   cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -I shared \
 *      shared/voms/voms_ac_unittest.c shared/voms/voms_asn1.c \
 *      shared/voms/voms_decode.c shared/voms/voms_verify.c shared/voms/voms_lsc.c \
 *      -lcrypto -o /tmp/voms_ut && /tmp/voms_ut
 *
 * Exit 0 and "all checks passed" = every success, error and security-negative
 * pin holds.
 */

#include "voms/voms_ac.h"
#include "voms/voms_asn1.h"
#include "voms/voms_lsc.h"
#include "voms/voms_ac_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); g_fail++; } \
} while (0)

/* The AC is valid 2026-08-03 .. 2026-08-10; a moment inside that window. */
#define INSIDE_VALIDITY 1785888000L   /* 2026-08-05T00:00:00Z */
#define BEFORE_VALIDITY 1780000000L
#define AFTER_VALIDITY  1790000000L

static const unsigned char *fixture_der(int *len)
{
    *len = VOMS_AC_FIXTURE_LEN;
    return VOMS_AC_FIXTURE;
}

/* A throwaway self-signed certificate with the given subject and serial —
 * the stand-in for the user's end-entity certificate the AC was issued to. */
static X509 *
make_cert(const X509_NAME *subject, const ASN1_INTEGER *serial,
    const unsigned char *ext_der, int ext_len)
{
    EVP_PKEY     *key = EVP_RSA_gen(2048);
    X509         *cert = X509_new();
    ASN1_INTEGER *serial_copy = ASN1_INTEGER_dup(serial);

    CHECK(key != NULL && cert != NULL && serial_copy != NULL);
    X509_set_version(cert, 2);
    X509_set_subject_name(cert, subject);
    X509_set_issuer_name(cert, subject);
    X509_set_serialNumber(cert, serial_copy);
    ASN1_INTEGER_free(serial_copy);
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
    EVP_PKEY_free(key);
    return cert;
}

/* The holder name and serial the fixture AC names. */
static X509 *
fixture_holder(const brix_voms_result_t *res, int serial_delta)
{
    VOMS_AC            *ac = res->entries[0].ac;
    VOMS_ISSUER_SERIAL *id = ac->acinfo->holder->base_certificate_id;
    X509_NAME          *name = sk_GENERAL_NAME_value(id->issuer, 0)->d.directoryName;
    ASN1_INTEGER       *serial = ASN1_INTEGER_dup(id->serial);
    X509               *cert;

    if (serial_delta != 0) {
        ASN1_INTEGER_set(serial, 42);
    }
    cert = make_cert(name, serial, NULL, 0);
    ASN1_INTEGER_free(serial);
    return cert;
}

static void
test_decode_fixture(void)
{
    brix_voms_result_t *res = NULL;
    int                 len;
    const unsigned char *der = fixture_der(&len);

    CHECK(brix_voms_decode(der, len, &res) == BRIX_VOMS_OK);
    CHECK(res != NULL && res->n == 1);
    if (res == NULL || res->n != 1) {
        return;
    }
    CHECK(strcmp(res->entries[0].vo, "lhcb") == 0);
    CHECK(strstr(res->entries[0].uri, "lhcb-auth.cern.ch") != NULL);
    CHECK(res->entries[0].nfqans == 2);
    CHECK(res->entries[0].nfqans == 2
          && strcmp(res->entries[0].fqans[0], "/lhcb/Role=user/Capability=NULL") == 0
          && strcmp(res->entries[0].fqans[1], "/lhcb/Role=NULL/Capability=NULL") == 0);
    CHECK(strstr(res->entries[0].issuer_dn, "CN=lhcb-auth.cern.ch") != NULL);
    CHECK(strstr(res->entries[0].holder_dn, "CN=rcurrie") != NULL);
    CHECK(res->entries[0].not_before < res->entries[0].not_after);
    CHECK(res->entries[0].verdict != BRIX_VOMS_OK);   /* decoded, not verified */
    brix_voms_result_free(res);
}

static brix_voms_status_t
verify_fixture(time_t now, int serial_delta, X509_STORE *store, const char *vomsdir,
    brix_voms_result_t **keep)
{
    brix_voms_result_t *res = NULL;
    brix_voms_trust_t   trust = { store, vomsdir, now, 300 };
    int                 len;
    const unsigned char *der = fixture_der(&len);
    X509               *holder;
    brix_voms_status_t  rc;

    if (brix_voms_decode(der, len, &res) != BRIX_VOMS_OK) {
        return BRIX_VOMS_ERR_DECODE;
    }
    holder = fixture_holder(res, serial_delta);
    rc = brix_voms_verify(res, holder, NULL, &trust);
    X509_free(holder);
    if (keep != NULL) {
        *keep = res;
    } else {
        brix_voms_result_free(res);
    }
    return rc;
}

static void
test_genuine_signature_verifies(void)
{
    brix_voms_result_t *res = NULL;

    CHECK(verify_fixture(INSIDE_VALIDITY, 0, NULL, NULL, &res) == BRIX_VOMS_OK);
    CHECK(res != NULL && res->entries[0].verdict == BRIX_VOMS_OK);
    CHECK(res != NULL && strstr(res->entries[0].issuer_ca_dn, "CERN") != NULL);
    brix_voms_result_free(res);
}

static void
test_validity_window(void)
{
    CHECK(verify_fixture(AFTER_VALIDITY, 0, NULL, NULL, NULL) == BRIX_VOMS_ERR_EXPIRED);
    CHECK(verify_fixture(BEFORE_VALIDITY, 0, NULL, NULL, NULL) == BRIX_VOMS_ERR_NOTYET);
    CHECK(verify_fixture(0, 0, NULL, NULL, NULL) == BRIX_VOMS_ERR_EXPIRED);  /* real clock */
}

static void
test_holder_binding(void)
{
    CHECK(verify_fixture(INSIDE_VALIDITY, 1, NULL, NULL, NULL) == BRIX_VOMS_ERR_HOLDER);
}

static void
test_tampered_signature(void)
{
    int                  len;
    const unsigned char *der = fixture_der(&len);
    unsigned char       *copy = malloc((size_t) len);
    brix_voms_result_t  *res = NULL;
    brix_voms_trust_t    trust = { NULL, NULL, INSIDE_VALIDITY, 0 };
    X509                *holder;

    memcpy(copy, der, (size_t) len);
    copy[len - 1] ^= 0x01;                      /* last signature byte */
    CHECK(brix_voms_decode(copy, len, &res) == BRIX_VOMS_OK);
    holder = fixture_holder(res, 0);
    CHECK(brix_voms_verify(res, holder, NULL, &trust) == BRIX_VOMS_ERR_SIGNATURE);
    X509_free(holder);
    brix_voms_result_free(res);
    free(copy);
}

static void
test_untrusted_chain(void)
{
    X509_STORE *empty = X509_STORE_new();

    CHECK(verify_fixture(INSIDE_VALIDITY, 0, empty, NULL, NULL) == BRIX_VOMS_ERR_UNTRUSTED);
    X509_STORE_free(empty);
}

static void
write_file(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");

    CHECK(fp != NULL);
    if (fp != NULL) {
        fputs(text, fp);
        fclose(fp);
    }
}

static void
test_lsc(void)
{
    char                template[] = "/tmp/voms_ut_XXXXXX";
    char               *dir = mkdtemp(template);
    char                vodir[512], lsc[512], text[2048];
    brix_voms_result_t *res = NULL;

    CHECK(dir != NULL);
    snprintf(vodir, sizeof(vodir), "%s/lhcb", dir);
    mkdir(vodir, 0700);
    snprintf(lsc, sizeof(lsc), "%s/lhcb/voms-lhcb-auth.cern.ch.lsc", dir);

    /* no LSC at all: rejected */
    CHECK(verify_fixture(INSIDE_VALIDITY, 0, NULL, dir, NULL) == BRIX_VOMS_ERR_LSC);

    /* an LSC naming another server: rejected */
    write_file(lsc, "/DC=ch/DC=cern/OU=computers/CN=voms.example.org\n"
                    "/DC=ch/DC=cern/CN=CERN Grid Certification Authority\n");
    CHECK(verify_fixture(INSIDE_VALIDITY, 0, NULL, dir, NULL) == BRIX_VOMS_ERR_LSC);

    /* the genuine signer subject/issuer pair: accepted */
    CHECK(verify_fixture(INSIDE_VALIDITY, 0, NULL, NULL, &res) == BRIX_VOMS_OK);
    snprintf(text, sizeof(text), "# lhcb\n%s\n\n%s\n",
             res->entries[0].issuer_dn, res->entries[0].issuer_ca_dn);
    brix_voms_result_free(res);
    write_file(lsc, text);
    CHECK(verify_fixture(INSIDE_VALIDITY, 0, NULL, dir, NULL) == BRIX_VOMS_OK);

    /* a VO name that tries to escape the vomsdir never matches */
    CHECK(brix_voms_lsc_match(dir, "../lhcb", NULL) == 0);
    CHECK(brix_voms_lsc_match(dir, "lhcb/../lhcb", NULL) == 0);

    unlink(lsc);
    rmdir(vodir);
    rmdir(dir);
}

static void
test_malformed(void)
{
    int                  len;
    const unsigned char *der = fixture_der(&len);
    brix_voms_result_t  *res = NULL;
    unsigned char        junk[64];

    memset(junk, 0x30, sizeof(junk));
    CHECK(brix_voms_decode(der, len / 2, &res) == BRIX_VOMS_ERR_DECODE && res == NULL);
    CHECK(brix_voms_decode(junk, (int) sizeof(junk), &res) == BRIX_VOMS_ERR_DECODE && res == NULL);
    CHECK(brix_voms_decode(NULL, 0, &res) == BRIX_VOMS_ERR_ARGS);
    CHECK(brix_voms_decode(der, 0, &res) == BRIX_VOMS_ERR_ARGS);
}

static void
test_retrieve_from_certificate(void)
{
    int                  len;
    const unsigned char *der = fixture_der(&len);
    brix_voms_result_t  *res = NULL;
    brix_voms_trust_t    trust = { NULL, NULL, INSIDE_VALIDITY, 0 };
    X509                *plain, *with_ext;
    X509_NAME           *name = X509_NAME_new();

    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *) "nobody", -1, -1, 0);
    {
        ASN1_INTEGER *one = ASN1_INTEGER_new();

        ASN1_INTEGER_set(one, 1);
        plain = make_cert(name, one, NULL, 0);
        ASN1_INTEGER_free(one);
    }
    CHECK(brix_voms_retrieve(plain, NULL, &trust, &res) == BRIX_VOMS_ERR_NOEXT && res == NULL);

    /* the extension on a certificate that is not the AC's holder: decodes, then
     * fails the holder binding — never silently accepted */
    with_ext = make_cert(name, X509_get0_serialNumber(plain), der, len);
    CHECK(brix_voms_retrieve(with_ext, NULL, &trust, &res) == BRIX_VOMS_ERR_HOLDER);
    CHECK(res != NULL && res->n == 1 && res->entries[0].verdict == BRIX_VOMS_ERR_HOLDER);
    brix_voms_result_free(res);
    X509_free(plain);
    X509_free(with_ext);
    X509_NAME_free(name);
}

/* A legacy GT2-shaped proxy of `parent`: subject = parent subject + CN=proxy,
 * no proxyCertInfo; carries `ext_der` when given. */
static X509 *
make_legacy_proxy(X509 *parent, const unsigned char *ext_der, int ext_len)
{
    X509_NAME    *name = X509_NAME_dup(X509_get_subject_name(parent));
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    X509         *proxy;

    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *) "proxy", -1, -1, 0);
    ASN1_INTEGER_set(serial, 7);
    proxy = make_cert(name, serial, ext_der, ext_len);
    X509_set_issuer_name(proxy, X509_get_subject_name(parent));
    ASN1_INTEGER_free(serial);
    X509_NAME_free(name);
    return proxy;
}

static void
test_proxy_shapes_and_eec_walk(void)
{
    brix_voms_result_t *res = NULL;
    int                 len;
    const unsigned char *der = fixture_der(&len);
    X509               *eec, *proxy1, *proxy2;
    STACK_OF(X509)     *chain = sk_X509_new_null();

    CHECK(brix_voms_decode(der, len, &res) == BRIX_VOMS_OK);
    eec = fixture_holder(res, 0);
    proxy1 = make_legacy_proxy(eec, NULL, 0);
    proxy2 = make_legacy_proxy(proxy1, NULL, 0);
    CHECK(!brix_voms_is_proxy(eec));
    CHECK(brix_voms_is_proxy(proxy1) && brix_voms_is_proxy(proxy2));

    /* CA-first order must not matter: the walk follows issuer links */
    sk_X509_push(chain, eec);
    sk_X509_push(chain, proxy1);
    CHECK(brix_voms_find_eec(proxy2, chain) == eec);
    CHECK(brix_voms_parent(proxy2, chain) == proxy1);
    CHECK(brix_voms_parent(eec, chain) == NULL);
    /* a chain that ends in a proxy: the topmost proxy is the best answer */
    sk_X509_delete(chain, 0);
    CHECK(brix_voms_find_eec(proxy2, chain) == proxy1);

    sk_X509_free(chain);
    X509_free(proxy2);
    X509_free(proxy1);
    X509_free(eec);
    brix_voms_result_free(res);
}

/* The AC on a parent proxy is found and bound along the proxy path: the
 * shape of a delegated VOMS proxy (grid-proxy-init over voms-proxy-init). */
static void
test_ac_on_parent_proxy(void)
{
    brix_voms_result_t *res = NULL;
    brix_voms_trust_t   trust = { NULL, NULL, INSIDE_VALIDITY, 0 };
    int                 len;
    const unsigned char *der = fixture_der(&len);
    X509               *eec, *carrier, *leaf;
    STACK_OF(X509)     *chain = sk_X509_new_null();

    CHECK(brix_voms_decode(der, len, &res) == BRIX_VOMS_OK);
    eec = fixture_holder(res, 0);
    brix_voms_result_free(res);
    res = NULL;
    carrier = make_legacy_proxy(eec, der, len);     /* the VOMS proxy */
    leaf = make_legacy_proxy(carrier, NULL, 0);     /* a plain proxy of it */
    sk_X509_push(chain, carrier);
    sk_X509_push(chain, eec);

    CHECK(brix_voms_retrieve(leaf, chain, &trust, &res) == BRIX_VOMS_OK);
    CHECK(res != NULL && res->n == 1 && res->entries[0].carrier == 1);
    CHECK(res != NULL && res->entries[0].verdict == BRIX_VOMS_OK);
    CHECK(res != NULL && strcmp(res->entries[0].digest, "sha512") == 0);
    brix_voms_result_free(res);

    /* the same AC with the EEC missing from the chain: the holder cannot be bound */
    res = NULL;
    sk_X509_delete(chain, 1);
    CHECK(brix_voms_retrieve(leaf, chain, &trust, &res) == BRIX_VOMS_ERR_HOLDER);
    brix_voms_result_free(res);

    sk_X509_free(chain);
    X509_free(leaf);
    X509_free(carrier);
    X509_free(eec);
}

static void
test_status_tokens(void)
{
    CHECK(strcmp(brix_voms_status_name(BRIX_VOMS_OK), "ok") == 0);
    CHECK(strcmp(brix_voms_status_name(BRIX_VOMS_ERR_LSC), "lsc") == 0);
    CHECK(strcmp(brix_voms_status_name(BRIX_VOMS_ERR_EXTENSION), "extension") == 0);
    CHECK(strcmp(brix_voms_status_name((brix_voms_status_t) 99), "unknown") == 0);
    CHECK(strstr(brix_voms_strerror(BRIX_VOMS_ERR_EXTENSION), "critical") != NULL);
}

int
main(void)
{
    test_proxy_shapes_and_eec_walk();
    test_ac_on_parent_proxy();
    test_status_tokens();
    test_decode_fixture();
    test_genuine_signature_verifies();
    test_validity_window();
    test_holder_binding();
    test_tampered_signature();
    test_untrusted_chain();
    test_lsc();
    test_malformed();
    test_retrieve_from_certificate();
    if (g_fail) {
        printf("%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
