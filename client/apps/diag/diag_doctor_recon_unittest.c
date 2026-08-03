/*
 * diag_doctor_recon_unittest.c — standalone unit test for the phase-93 deep
 * read-only reconnaissance parsers (the `query stats a` XML field extractor,
 * the per-plane stats decode, and the capability-flag renderer).
 *
 *   cc -std=c11 -Wall -Wextra -Werror -Ilib -I../src -I../shared \
 *      -DXRDPROTO_NO_NGX apps/diag/diag_doctor_recon_unittest.c -o /tmp/ut \
 *   && /tmp/ut          (run from client/)
 *
 * Exit 0 = all checks pass. Pure C — no server, no connection, no libbrix: the
 * TU under test is #included and the handful of wire/render externs it references
 * (brix_query/brix_dirlist/brix_close/brix_status_clear/fjson_str) are satisfied
 * by trivial stubs. Only the pure parsers are exercised here; the live probe
 * (doctor_recon_probe) is covered online by test_xrddiag_remote_doctor.py.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag_internal.h"

/* ---- extern stubs (never reached by the pure parsers under test) ---- */
void brix_status_clear(brix_status *st) { (void) st; }
int  brix_query(brix_conn *c, int it, const char *a, char *o, size_t n, brix_status *s)
{ (void) c; (void) it; (void) a; (void) o; (void) n; (void) s; return -1; }
int  brix_dirlist(brix_conn *c, const char *p, int ws, brix_dirent **e,
                  size_t *n, brix_status *s)
{ (void) c; (void) p; (void) ws; (void) e; (void) n; (void) s; return -1; }
void brix_close(brix_conn *c) { (void) c; }
void fjson_str(FILE *o, const char *s) { (void) o; (void) s; }

#include "diag_doctor_recon.c"

/* ---- harness ---- */
static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* A representative `query stats a` reply: header + the planes deep-recon reads.
 * Note the deliberately colliding tag names across blocks — <num> appears in
 * link, xrootd and lgn; <err> in xrootd and ofs; <in>/<out> in link — so the
 * scoped extractor is proven to resolve each within the right block. */
static const char *STATS =
    "<statistics tod=\"1700000000\" ver=\"v5.6.0\" src=\"h:1094\" pgm=\"xrootd\">"
    "<stats id=\"link\"><num>7</num><maxn>9</maxn><tot>123</tot>"
    "<in>456789</in><out>987654</out><ctime>0</ctime></stats>"
    "<stats id=\"xrootd\"><num>3</num>"
    "<ops><open>50</open><rf>1</rf><rd>2000</rd><pr>0</pr><rv>4</rv><wr>30</wr></ops>"
    "<aio><num>0</num><max>0</max><rej>0</rej></aio>"
    "<err>11</err><rdr>5</rdr><dly>2</dly>"
    "<lgn><num>40</num><af>3</af><au>37</au><ua>0</ua></lgn></stats>"
    "<stats id=\"ofs\"><role>server</role><opr>10</opr><opw>1</opw>"
    "<tpc><grnt>8</grnt><deny>2</deny><err>1</err><exp>0</exp></tpc></stats>"
    "<stats id=\"oss\"><paths>1<stats id=\"oss.0\"><lp>\"/data\"</lp>"
    "<tote>1000000000</tote><free>250000000</free>"
    "<ino>2048</ino><ifr>1024</ifr></stats></paths></stats>"
    "<stats id=\"http\"><requests>777</requests><bytes_in>10</bytes_in>"
    "<bytes_out>20</bytes_out><tpc_pull>3</tpc_pull><tpc_push>4</tpc_push></stats>"
    "</statistics>";


/* SUCCESS: every plane decodes to the expected scoped value. */
static void
test_parse_full(void)
{
    doctor_recon r;
    memset(&r, 0, sizeof(r));
    recon_init(&r, 0);
    doctor_recon_parse_stats(STATS, &r);

    /* link plane */
    CHECK(r.conns_total == 123);
    CHECK(r.bytes_in == 456789);
    CHECK(r.bytes_out == 987654);
    /* xrootd op plane (ops scoped; top-level err/rdr/dly) */
    CHECK(r.ops_open == 50);
    CHECK(r.ops_rd == 2000);
    CHECK(r.ops_wr == 30);
    CHECK(r.ops_err == 11);
    CHECK(r.ops_rdr == 5);
    CHECK(r.ops_dly == 2);
    /* lgn sub-block: num here is 40, NOT the xrootd-level <num>3 or link <num>7 */
    CHECK(r.lgn_num == 40);
    CHECK(r.lgn_au == 37);
    CHECK(r.lgn_af == 3);
    /* ofs tpc */
    CHECK(r.have_tpc == 1);
    CHECK(r.tpc_grant == 8);
    CHECK(r.tpc_deny == 2);
    CHECK(r.tpc_err == 1);
    /* oss capacity/inodes */
    CHECK(r.oss_total == 1000000000);
    CHECK(r.oss_free == 250000000);
    CHECK(r.ino_total == 2048);
    CHECK(r.ino_free == 1024);
    /* http */
    CHECK(r.have_http == 1);
    CHECK(r.http_reqs == 777);
    CHECK(r.http_in == 10);
    CHECK(r.http_out == 20);
    CHECK(r.http_tpc_pull == 3);
    CHECK(r.http_tpc_push == 4);
}


/* SCOPING: doctor_recon_xml_i64 reads the tag only from the named block. */
static void
test_scoped_reads(void)
{
    /* <in>/<out> live in link, not xrootd. */
    CHECK(doctor_recon_xml_i64(STATS, "link", "in") == 456789);
    CHECK(doctor_recon_xml_i64(STATS, "link", "tot") == 123);
    /* xrootd top-level <err> is 11 (ofs also has <err>1, must not leak). */
    CHECK(doctor_recon_xml_i64(STATS, "xrootd", "err") == 11);
    CHECK(doctor_recon_xml_i64(STATS, "ofs", "err") == 1);
    /* a tag absent from the block => -1, even though it exists elsewhere. */
    CHECK(doctor_recon_xml_i64(STATS, "link", "grnt") == -1);
    /* an absent block => -1. */
    CHECK(doctor_recon_xml_i64(STATS, "sched", "jobs") == -1);
}


/* ERROR / EDGE: empty, malformed, unterminated, and non-numeric inputs never
 * crash and never fabricate a value — the "-1 = not reported" contract holds. */
static void
test_error_and_edge(void)
{
    doctor_recon r;

    /* NULL / empty XML: parse is a no-op, sentinels intact. */
    memset(&r, 0, sizeof(r));
    recon_init(&r, 0);
    doctor_recon_parse_stats(NULL, &r);
    doctor_recon_parse_stats("", &r);
    CHECK(r.conns_total == -1 && r.bytes_in == -1 && r.have_tpc == 0);

    /* NULL args to the public reader. */
    CHECK(doctor_recon_xml_i64(NULL, "link", "in") == -1);
    CHECK(doctor_recon_xml_i64(STATS, NULL, "in") == -1);
    CHECK(doctor_recon_xml_i64(STATS, "link", NULL) == -1);

    /* block open tag but no </stats> close => treated as absent. */
    CHECK(doctor_recon_xml_i64("<stats id=\"link\"><in>5</in>", "link", "in")
          == -1);
    /* tag opened but not closed within the block => still parses the digits up
     * to end-of-buffer (strtoll stops at non-digit); a non-numeric body => -1. */
    CHECK(doctor_recon_xml_i64("<stats id=\"link\"><in>x</in></stats>",
                               "link", "in") == -1);
    /* negative values are honoured. */
    CHECK(doctor_recon_xml_i64("<stats id=\"link\"><in>-9</in></stats>",
                               "link", "in") == -9);
    /* "oss" must not match "oss.0" (closing-quote precision). */
    CHECK(doctor_recon_xml_i64("<stats id=\"oss.0\"><tote>1</tote></stats>",
                               "oss", "tote") == -1);
}


/* CAPABILITY DECODE: bit set → names present; empty flags → empty string. */
static void
test_caps_decode(void)
{
    char buf[256];
    int  n;

    /* no flags set => zero names, empty string (not garbage). */
    buf[0] = 'x';
    n = doctor_recon_caps_str(0, buf, sizeof(buf));
    CHECK(n == 0 && buf[0] == '\0');

    /* manager + TLS-available + gotoTLS + posc. */
    n = doctor_recon_caps_str(kXR_isManager | kXR_haveTLS | kXR_gotoTLS
                              | kXR_supposc, buf, sizeof(buf));
    CHECK(n == 4);
    CHECK(strstr(buf, "manager") != NULL);
    CHECK(strstr(buf, "tls-available") != NULL);
    CHECK(strstr(buf, "tls-required") != NULL);
    CHECK(strstr(buf, "posc") != NULL);
    /* a bit NOT set must not appear. */
    CHECK(strstr(buf, "proxy") == NULL);

    /* server + proxy: comma-joined, order follows the table. */
    n = doctor_recon_caps_str(kXR_isServer | kXR_attrProxy, buf, sizeof(buf));
    CHECK(n == 2 && strcmp(buf, "server,proxy") == 0);
}


int
main(void)
{
    test_parse_full();
    test_scoped_reads();
    test_error_and_edge();
    test_caps_decode();

    if (g_fail == 0) {
        printf("all checks passed\n");
        return 0;
    }
    printf("%d check(s) FAILED\n", g_fail);
    return 1;
}
