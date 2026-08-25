/*
 * rrdata_unittest.c — standalone unit test for the CMS RRData Pup decoder.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/cms_rrdata_ut \
 *       src/net/cms/rrdata_unittest.c src/net/cms/rrdata.c && /tmp/cms_rrdata_ut
 *
 * Exit 0 = all checks pass. No nginx dependency (rrdata.c is pure C).
 */

#include "rrdata.h"

#include <stdarg.h>
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

/*
 * Decoded-slot lookup by layout letter — the test's own statement of which
 * struct member each wire field lands in (independent of rrdata.c's table).
 */
static const unsigned char **
slot_ptr(brix_cms_rrdata_t *d, char key, size_t **len)
{
    switch (key) {
    case 'i': *len = &d->ident_len;  return &d->ident;
    case 'p': *len = &d->path_len;   return &d->path;
    case '2': *len = &d->path2_len;  return &d->path2;
    case 'o': *len = &d->opaque_len; return &d->opaque;
    case 'r': *len = &d->reqid_len;  return &d->reqid;
    case 'n': *len = &d->notify_len; return &d->notify;
    case 'y': *len = &d->prty_len;   return &d->prty;
    case 'm': *len = &d->mode_len;   return &d->mode;
    }
    return NULL;
}

/*
 * run_case — build a Pup payload from `layout` and CHECK its decode.
 *
 * layout is one char per wire field, in order: a slot letter (see slot_ptr)
 * consumes the next (const char *) vararg and appends it as a Pup string;
 * '#' consumes an unsigned vararg and appends the tagged int. The payload is
 * parsed under `code`; rc must be 0, every slot letter must decode back to
 * exactly its input string, and '#' must set has_opts/opts. Returns the
 * decoded struct for test-specific extra CHECKs.
 */
static brix_cms_rrdata_t
run_case(unsigned char code, const char *layout, ...)
{
    brix_cms_rrdata_t out;
    unsigned char buf[512], *p = buf;
    const char *want[8];
    unsigned want_opts = 0;
    size_t nstr = 0;
    va_list ap;
    const char *k;

    va_start(ap, layout);
    for (k = layout; *k != '\0'; k++) {
        if (*k == '#') {
            want_opts = va_arg(ap, unsigned);
            p = put_int(p, want_opts);
        } else {
            want[nstr] = va_arg(ap, const char *);
            p = put_str(p, want[nstr++]);
        }
    }
    va_end(ap);

    CHECK(brix_cms_rrdata_parse(code, buf, (size_t) (p - buf), &out) == 0);

    nstr = 0;
    for (k = layout; *k != '\0'; k++) {
        if (*k == '#') {
            CHECK(out.has_opts == 1 && out.opts == want_opts);
        } else {
            size_t *len;
            const unsigned char **sp = slot_ptr(&out, *k, &len);
            CHECK(sp != NULL && span_eq(*sp, *len, want[nstr++]));
        }
    }
    return out;
}

/* tests — layouts restate the XrdCmsParser arg vectors independently of the
 * decoder's own spec strings (fwdArgA/B/C, padArgs, pdlArgs, locArgs). */
static void
test_mkdir(void)
{
    /* fwdArgA: ident, mode, path, [fence], opaque(absent) */
    brix_cms_rrdata_t d =
        run_case(K_MKDIR, "imp", "alice.0:1@host", "755", "/atlas/new");
    CHECK(d.opaque == NULL);
    /* the path span is NUL-terminated in place (wire NUL retained) */
    CHECK(d.path != NULL && d.path[d.path_len] == '\0');
}

static void
test_chmod_with_opaque(void)
{
    /* fwdArgA with the post-fence opaque present */
    (void) run_case(K_CHMOD, "impo", "id", "640", "/data/f", "authz=tok");
}

static void
test_mv(void)
{
    /* fwdArgB: ident, path, path2, [fence], opaque, opaque2 */
    (void) run_case(K_MV, "ip2", "id", "/a/src", "/a/dst");
}

static void
test_rm(void)
{
    /* fwdArgC: ident, path, [fence], opaque(absent) */
    (void) run_case(K_RM, "ip", "id", "/a/gone");
}

static void
test_select_with_opts(void)
{
    /* locArgs: ident, opts(int), path, [fence], opaque, avoid */
    (void) run_case(K_SELECT, "i#p", "id", 0x10u, "/sel/path");
}

static void
test_prepadd(void)
{
    /* padArgs: ident, reqid, notify, prty, mode, path, [fence], opaque */
    (void) run_case(K_PREPADD, "irnymp",
                    "id", "req-42", "noteme", "1", "0", "/stage/me");
}

static void
test_prepdel(void)
{
    /* pdlArgs: ident, reqid */
    (void) run_case(K_PREPDEL, "ir", "id", "req-42");
}

static void
test_truncated_string_rejected(void)
{
    /* claims a 10-byte string but only 3 bytes follow */
    unsigned char buf[8];
    buf[0] = 0x00; buf[1] = 0x0a;          /* len = 10 */
    buf[2] = 'a';  buf[3] = 'b'; buf[4] = 'c';
    brix_cms_rrdata_t d;
    int rc = brix_cms_rrdata_parse(K_RM, buf, 5, &d);
    CHECK(rc == -1);
}

static void
test_unknown_opcode_rejected(void)
{
    unsigned char buf[4] = {0,0,0,0};
    brix_cms_rrdata_t d;
    int rc = brix_cms_rrdata_parse(99, buf, 4, &d);
    CHECK(rc == -1);
}

static void
test_encode_roundtrip_mkdir(void)
{
    unsigned char buf[256];
    brix_cms_fwd_fields_t f = { "ident.0", "/a/b", NULL, "750", NULL };
    int n = brix_cms_rrdata_encode(K_MKDIR, &f, buf, sizeof(buf));
    CHECK(n > 0);
    brix_cms_rrdata_t d;
    CHECK(brix_cms_rrdata_parse(K_MKDIR, buf, (size_t) n, &d) == 0);
    CHECK(span_eq(d.ident, d.ident_len, "ident.0"));
    CHECK(span_eq(d.mode,  d.mode_len,  "750"));
    CHECK(span_eq(d.path,  d.path_len,  "/a/b"));
}

static void
test_encode_roundtrip_mv_with_opaque(void)
{
    unsigned char buf[256];
    brix_cms_fwd_fields_t f = { "id", "/s", "/d", NULL, "authz=x" };
    int n = brix_cms_rrdata_encode(K_MV, &f, buf, sizeof(buf));
    CHECK(n > 0);
    brix_cms_rrdata_t d;
    CHECK(brix_cms_rrdata_parse(K_MV, buf, (size_t) n, &d) == 0);
    CHECK(span_eq(d.path,   d.path_len,   "/s"));
    CHECK(span_eq(d.path2,  d.path2_len,  "/d"));
    CHECK(span_eq(d.opaque, d.opaque_len, "authz=x"));
}

static void
test_encode_roundtrip_rm(void)
{
    unsigned char buf[256];
    brix_cms_fwd_fields_t f = { "id", "/gone", NULL, NULL, NULL };
    int n = brix_cms_rrdata_encode(K_RM, &f, buf, sizeof(buf));
    CHECK(n > 0);
    brix_cms_rrdata_t d;
    CHECK(brix_cms_rrdata_parse(K_RM, buf, (size_t) n, &d) == 0);
    CHECK(span_eq(d.path, d.path_len, "/gone"));
}

static void
test_encode_overflow_rejected(void)
{
    unsigned char small[4];
    brix_cms_fwd_fields_t f = { "ident", "/path", NULL, "755", NULL };
    int n = brix_cms_rrdata_encode(K_MKDIR, &f, small, sizeof(small));
    CHECK(n == -1);
}

static void
test_statfs_encode(void)
{
    unsigned char buf[64];
    brix_cms_statfs_fields_t sp = { 2, 1000, 50, 2, 1000, 50 };
    int n = brix_cms_statfs_encode(&sp, buf, sizeof(buf));
    CHECK(n == 24);                                /* 4 + strlen("...")=19 + NUL */
    CHECK(buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0);
    CHECK(strcmp((const char *) buf + 4, "2 1000 50 2 1000 50") == 0);
}

static void
test_statfs_encode_overflow(void)
{
    unsigned char small[6];
    brix_cms_statfs_fields_t sp = { 2, 1000, 50, 2, 1000, 50 };
    CHECK(brix_cms_statfs_encode(&sp, small, sizeof(small)) == -1);
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
