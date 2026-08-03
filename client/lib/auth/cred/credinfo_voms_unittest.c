/*
 * credinfo_voms_unittest.c — unit test for the VOMS attribute-certificate FQAN
 * decoder in credinfo.c (voms_scan / der_tlv / voms_is_fqan / voms_emit_values).
 *
 *   cc -std=c11 -Wall -Wextra -Werror -Ilib -I../src -I../shared \
 *      -DXRDPROTO_NO_NGX lib/auth/cred/credinfo_voms_unittest.c \
 *      libbrix.a ../shared/xrdproto/libxrdproto.a -lssl -lcrypto -lz -lkrb5 \
 *      -lk5crypto -lcom_err -lzstd -llzma -lbrotlienc -lbrotlidec -lbz2 \
 *      -l:liblz4.so.1 -luring -o /tmp/vut && /tmp/vut          (run from client/)
 *
 * Exit 0 = all checks pass. The REAL credinfo.c is #included (its VOMS parser is
 * static); the remaining libbrix/openssl symbols it references are pulled from
 * the archive (its own credinfo.o is NOT — the #include already defines those
 * symbols). Driven over a genuine LHCb-proxy VOMS AC extracted into the fixture.
 */
#define _GNU_SOURCE            /* open_memstream */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "credinfo.c"          /* real parser under test (static functions) */
#include "voms_ac_fixture.h"   /* genuine VOMS AC DER: two FQANs + URI noise */

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static int
has(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

/* Count non-overlapping occurrences of needle in hay. */
static int
count(const char *hay, const char *needle)
{
    int n = 0;
    const char *p = hay;
    size_t nl = strlen(needle);
    while ((p = strstr(p, needle)) != NULL) { n++; p += nl; }
    return n;
}

/* Render voms_scan(der,len) to a heap string (caller frees). */
static char *
scan(const unsigned char *der, int len)
{
    char   *buf = NULL;
    size_t  sz = 0;
    FILE   *ms = open_memstream(&buf, &sz);
    voms_scan(der, len, ms);
    fclose(ms);
    return buf;
}

int
main(void)
{
    char *s;

    /* ---- der_tlv: short form, long form, truncation ---- */
    {
        /* SEQUENCE (0x30) len 2, content {0x04,0x00} */
        const unsigned char a[] = { 0x30, 0x02, 0x04, 0x00 };
        int pos = 0, tag = 0, vlen = 0;
        CHECK(der_tlv(a, sizeof(a), &pos, &tag, &vlen) == 0);
        CHECK(tag == 0x30 && vlen == 2 && pos == 2);

        /* long form: 0x82 0x01 0x00 => len 256, but buffer too short => -1 */
        const unsigned char b[] = { 0x04, 0x82, 0x01, 0x00 };
        pos = 0;
        CHECK(der_tlv(b, sizeof(b), &pos, &tag, &vlen) == -1);

        /* truncated header */
        const unsigned char c[] = { 0x04 };
        pos = 0;
        CHECK(der_tlv(c, sizeof(c), &pos, &tag, &vlen) == -1);
    }

    /* ---- voms_is_fqan: accepts real FQAN, rejects URI / binary / '//' ---- */
    {
        const char *f = "/lhcb/Role=user/Capability=NULL";
        CHECK(voms_is_fqan(f, (int) strlen(f)) == 1);
        const char *u = "lhcb://voms-lhcb-auth.cern.ch:4430";
        CHECK(voms_is_fqan(u, (int) strlen(u)) == 0);      /* no leading '/' */
        const char *dd = "//voms-lhcb-auth.cern.ch:4430";
        CHECK(voms_is_fqan(dd, (int) strlen(dd)) == 0);    /* leading '//' */
        const char *colon = "/lhcb:4430";
        CHECK(voms_is_fqan(colon, (int) strlen(colon)) == 0); /* ':' banned */
        const char bin[] = { '/', 'x', 0x01, 'y' };
        CHECK(voms_is_fqan(bin, 4) == 0);                  /* non-printable */
        CHECK(voms_is_fqan("/", 1) == 0);                  /* too short */
    }

    /* ---- the real AC: exactly the two FQANs, no URI/junk ---- */
    s = scan(VOMS_AC_FIXTURE, (int) sizeof(VOMS_AC_FIXTURE));
    CHECK(has(s, "/lhcb/Role=user/Capability=NULL"));
    CHECK(has(s, "/lhcb/Role=NULL/Capability=NULL"));
    CHECK(count(s, "      VOMS:  ") == 2);                 /* exactly two lines */
    /* none of the blind-scan noise the old parser emitted */
    CHECK(!has(s, "voms-lhcb-auth"));                      /* policyAuthority URI */
    CHECK(!has(s, "cafiles.cern.ch"));                     /* signer CRL/AIA URI */
    CHECK(!has(s, "ocsp.cern.ch"));                        /* signer OCSP URI */
    CHECK(!has(s, "ldap:"));                               /* signer LDAP CRL URI */
    CHECK(!has(s, "Capability=NULL0"));                    /* trailing tag byte */
    CHECK(!has(s, ":4430"));                               /* URI port over-read */
    CHECK(!has(s, "present (no FQAN decoded)"));           /* we DID decode */
    free(s);

    /* ---- degenerate inputs: no crash, graceful note ---- */
    s = scan(NULL, 0);
    CHECK(has(s, "present (no FQAN decoded)"));
    free(s);
    s = scan(VOMS_AC_FIXTURE, 0);
    CHECK(has(s, "present (no FQAN decoded)"));
    free(s);
    {
        /* an AC with the FQAN OID but a truncated SET => no FQANs, graceful */
        const unsigned char oid_only[] = {
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xbe, 0x45, 0x64, 0x64,
            0x04, 0x31              /* SET tag with no length/content */
        };
        s = scan(oid_only, (int) sizeof(oid_only));
        CHECK(has(s, "present (no FQAN decoded)"));
        free(s);
    }

    if (g_fail) {
        printf("%d CHECK(s) FAILED\n", g_fail);
        return 1;
    }
    printf("OK all VOMS AC parser checks passed\n");
    return 0;
}
