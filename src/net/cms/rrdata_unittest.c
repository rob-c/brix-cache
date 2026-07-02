/*
 * rrdata_unittest.c — standalone unit test for the CMS RRData Pup decoder.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/cms_rrdata_ut \
 *       src/cms/rrdata_unittest.c src/cms/rrdata.c && /tmp/cms_rrdata_ut
 *
 * Exit 0 = all checks pass. No nginx dependency (rrdata.c is pure C).
 */

#include "rrdata.h"

#include <stdio.h>
#include <string.h>

/* CMS opcodes (kYR_* wire constants). */
#define K_CHMOD   1
#define K_MKDIR   3
#define K_MV      5
#define K_PREPADD 6
#define K_PREPDEL 7
#define K_RM      8
#define K_SELECT 10

static int   g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* Pup wire builders (mirror src/cms/wire.c put_string / put_int) */
/* Append a Pup string: [2B BE len incl NUL][bytes][NUL]. Empty -> [00 00]. */
static unsigned char *
put_str(unsigned char *p, const char *s)
{
    size_t n = (s == NULL) ? 0 : strlen(s);
    if (n == 0) { *p++ = 0; *p++ = 0; return p; }
    unsigned wlen = (unsigned) (n + 1);
    *p++ = (unsigned char) (wlen >> 8);
    *p++ = (unsigned char) wlen;
    memcpy(p, s, n); p += n;
    *p++ = '\0';
    return p;
}

/* Append a Pup int: tag 0xa0 + 4B BE. */
static unsigned char *
put_int(unsigned char *p, uint32_t v)
{
    *p++ = 0xa0;
    *p++ = (unsigned char) (v >> 24);
    *p++ = (unsigned char) (v >> 16);
    *p++ = (unsigned char) (v >> 8);
    *p++ = (unsigned char) v;
    return p;
}

static int
span_eq(const unsigned char *p, size_t len, const char *s)
{
    return p != NULL && len == strlen(s) && memcmp(p, s, len) == 0;
}

/* tests */
static void
test_mkdir(void)
{
    /* fwdArgA: ident, mode, path, [fence], opaque(absent) */
    unsigned char buf[256], *p = buf;
    p = put_str(p, "alice.0:1@host");
    p = put_str(p, "755");
    p = put_str(p, "/atlas/new");
    xrootd_cms_rrdata_t d;
    int rc = xrootd_cms_rrdata_parse(K_MKDIR, buf, (size_t)(p - buf), &d);
    CHECK(rc == 0);
    CHECK(span_eq(d.ident, d.ident_len, "alice.0:1@host"));
    CHECK(span_eq(d.mode,  d.mode_len,  "755"));
    CHECK(span_eq(d.path,  d.path_len,  "/atlas/new"));
    CHECK(d.opaque == NULL);
    /* the path span is NUL-terminated in place (wire NUL retained) */
    CHECK(d.path != NULL && d.path[d.path_len] == '\0');
}

static void
test_chmod_with_opaque(void)
{
    unsigned char buf[256], *p = buf;
    p = put_str(p, "id");
    p = put_str(p, "640");
    p = put_str(p, "/data/f");
    p = put_str(p, "authz=tok");          /* post-fence opaque */
    xrootd_cms_rrdata_t d;
    int rc = xrootd_cms_rrdata_parse(K_CHMOD, buf, (size_t)(p - buf), &d);
    CHECK(rc == 0);
    CHECK(span_eq(d.path,   d.path_len,   "/data/f"));
    CHECK(span_eq(d.opaque, d.opaque_len, "authz=tok"));
}

static void
test_mv(void)
{
    /* fwdArgB: ident, path, path2, [fence], opaque, opaque2 */
    unsigned char buf[256], *p = buf;
    p = put_str(p, "id");
    p = put_str(p, "/a/src");
    p = put_str(p, "/a/dst");
    xrootd_cms_rrdata_t d;
    int rc = xrootd_cms_rrdata_parse(K_MV, buf, (size_t)(p - buf), &d);
    CHECK(rc == 0);
    CHECK(span_eq(d.path,  d.path_len,  "/a/src"));
    CHECK(span_eq(d.path2, d.path2_len, "/a/dst"));
}

static void
test_rm(void)
{
    /* fwdArgC: ident, path, [fence], opaque(absent) */
    unsigned char buf[256], *p = buf;
    p = put_str(p, "id");
    p = put_str(p, "/a/gone");
    xrootd_cms_rrdata_t d;
    int rc = xrootd_cms_rrdata_parse(K_RM, buf, (size_t)(p - buf), &d);
    CHECK(rc == 0);
    CHECK(span_eq(d.path, d.path_len, "/a/gone"));
}

static void
test_select_with_opts(void)
{
    /* locArgs: ident, opts(int), path, [fence], opaque, avoid */
    unsigned char buf[256], *p = buf;
    p = put_str(p, "id");
    p = put_int(p, 0x00000010);
    p = put_str(p, "/sel/path");
    xrootd_cms_rrdata_t d;
    int rc = xrootd_cms_rrdata_parse(K_SELECT, buf, (size_t)(p - buf), &d);
    CHECK(rc == 0);
    CHECK(d.has_opts == 1);
    CHECK(d.opts == 0x10);
    CHECK(span_eq(d.path, d.path_len, "/sel/path"));
}

static void
test_prepadd(void)
{
    /* padArgs: ident, reqid, notify, prty, mode, path, [fence], opaque */
    unsigned char buf[256], *p = buf;
    p = put_str(p, "id");
    p = put_str(p, "req-42");
    p = put_str(p, "noteme");
    p = put_str(p, "1");
    p = put_str(p, "0");
    p = put_str(p, "/stage/me");
    xrootd_cms_rrdata_t d;
    int rc = xrootd_cms_rrdata_parse(K_PREPADD, buf, (size_t)(p - buf), &d);
    CHECK(rc == 0);
    CHECK(span_eq(d.reqid, d.reqid_len, "req-42"));
    CHECK(span_eq(d.path,  d.path_len,  "/stage/me"));
}

static void
test_prepdel(void)
{
    /* pdlArgs: ident, reqid */
    unsigned char buf[64], *p = buf;
    p = put_str(p, "id");
    p = put_str(p, "req-42");
    xrootd_cms_rrdata_t d;
    int rc = xrootd_cms_rrdata_parse(K_PREPDEL, buf, (size_t)(p - buf), &d);
    CHECK(rc == 0);
    CHECK(span_eq(d.reqid, d.reqid_len, "req-42"));
}

static void
test_truncated_string_rejected(void)
{
    /* claims a 10-byte string but only 3 bytes follow */
    unsigned char buf[8];
    buf[0] = 0x00; buf[1] = 0x0a;          /* len = 10 */
    buf[2] = 'a';  buf[3] = 'b'; buf[4] = 'c';
    xrootd_cms_rrdata_t d;
    int rc = xrootd_cms_rrdata_parse(K_RM, buf, 5, &d);
    CHECK(rc == -1);
}

static void
test_unknown_opcode_rejected(void)
{
    unsigned char buf[4] = {0,0,0,0};
    xrootd_cms_rrdata_t d;
    int rc = xrootd_cms_rrdata_parse(99, buf, 4, &d);
    CHECK(rc == -1);
}

static void
test_encode_roundtrip_mkdir(void)
{
    unsigned char buf[256];
    int n = xrootd_cms_rrdata_encode(K_MKDIR, "ident.0", "/a/b", NULL,
                                     "750", NULL, buf, sizeof(buf));
    CHECK(n > 0);
    xrootd_cms_rrdata_t d;
    CHECK(xrootd_cms_rrdata_parse(K_MKDIR, buf, (size_t) n, &d) == 0);
    CHECK(span_eq(d.ident, d.ident_len, "ident.0"));
    CHECK(span_eq(d.mode,  d.mode_len,  "750"));
    CHECK(span_eq(d.path,  d.path_len,  "/a/b"));
}

static void
test_encode_roundtrip_mv_with_opaque(void)
{
    unsigned char buf[256];
    int n = xrootd_cms_rrdata_encode(K_MV, "id", "/s", "/d",
                                     NULL, "authz=x", buf, sizeof(buf));
    CHECK(n > 0);
    xrootd_cms_rrdata_t d;
    CHECK(xrootd_cms_rrdata_parse(K_MV, buf, (size_t) n, &d) == 0);
    CHECK(span_eq(d.path,   d.path_len,   "/s"));
    CHECK(span_eq(d.path2,  d.path2_len,  "/d"));
    CHECK(span_eq(d.opaque, d.opaque_len, "authz=x"));
}

static void
test_encode_roundtrip_rm(void)
{
    unsigned char buf[256];
    int n = xrootd_cms_rrdata_encode(K_RM, "id", "/gone", NULL,
                                     NULL, NULL, buf, sizeof(buf));
    CHECK(n > 0);
    xrootd_cms_rrdata_t d;
    CHECK(xrootd_cms_rrdata_parse(K_RM, buf, (size_t) n, &d) == 0);
    CHECK(span_eq(d.path, d.path_len, "/gone"));
}

static void
test_encode_overflow_rejected(void)
{
    unsigned char small[4];
    int n = xrootd_cms_rrdata_encode(K_MKDIR, "ident", "/path", NULL,
                                     "755", NULL, small, sizeof(small));
    CHECK(n == -1);
}

static void
test_statfs_encode(void)
{
    unsigned char buf[64];
    int n = xrootd_cms_statfs_encode(2, 1000, 50, 2, 1000, 50, buf, sizeof(buf));
    CHECK(n == 24);                                /* 4 + strlen("...")=19 + NUL */
    CHECK(buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0);
    CHECK(strcmp((const char *) buf + 4, "2 1000 50 2 1000 50") == 0);
}

static void
test_statfs_encode_overflow(void)
{
    unsigned char small[6];
    CHECK(xrootd_cms_statfs_encode(2, 1000, 50, 2, 1000, 50,
                                   small, sizeof(small)) == -1);
}

int
main(void)
{
    test_mkdir();
    test_chmod_with_opaque();
    test_mv();
    test_rm();
    test_select_with_opts();
    test_prepadd();
    test_prepdel();
    test_truncated_string_rejected();
    test_unknown_opcode_rejected();
    test_encode_roundtrip_mkdir();
    test_encode_roundtrip_mv_with_opaque();
    test_encode_roundtrip_rm();
    test_encode_overflow_rejected();
    test_statfs_encode();
    test_statfs_encode_overflow();

    if (g_fail) { printf("%d check(s) FAILED\n", g_fail); return 1; }
    printf("all rrdata checks passed\n");
    return 0;
}
