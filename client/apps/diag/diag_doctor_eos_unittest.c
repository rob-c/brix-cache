/*
 * diag_doctor_eos_unittest.c — standalone unit test for the EOS-dialect topology
 * enrichment (diag_doctor_eos.c): the pure /proc-reply parsers, the fs-ls
 * monitoring-format FST parser, and the text/JSON renderers.
 *
 *   cc -std=c11 -Wall -Wextra -Werror -Ilib -I../src -I../shared \
 *      -DXRDPROTO_NO_NGX apps/diag/diag_doctor_eos_unittest.c -o /tmp/ut \
 *   && /tmp/ut          (run from client/)
 *
 * Exit 0 = all checks pass. Pure C — no server, no libbrix: the TU is #included
 * and its externs (fjson_str, capacity_pct) + libbrix wire calls are satisfied
 * by trivial stubs. brix_endpoint_parse is stubbed to fail, so doctor_eos_map
 * exercises its early guard deterministically. The version parser runs over the
 * GENUINE eospublic reply envelope; the FST parser over a constructed `fs ls -m`
 * fixture (live enumeration is admin-gated, so it cannot be recorded here).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* open_memstream */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag_internal.h"

/* ---- externs the EOS TU references (report/JSON + config capacity). ---- */
void
fjson_str(FILE *o, const char *s)
{
    /* minimal quoting — enough for the constrained EOS token charset */
    fputc('"', o);
    for (; s && *s; s++) {
        if (*s == '"' || *s == '\\') { fputc('\\', o); }
        fputc(*s, o);
    }
    fputc('"', o);
}

int
doctor_cfg_capacity_pct(int64_t total, int64_t freeb)
{
    if (total <= 0 || freeb < 0) { return -1; }
    return (int) ((freeb * 100) / total);
}

/* ---- libbrix wire externs (doctor_eos_map bails at brix_endpoint_parse). ---- */
void brix_status_clear(brix_status *st) { (void) st; }
int  brix_endpoint_parse(const char *e, brix_url *u, brix_status *s)
{ (void) e; (void) u; (void) s; return -1; }   /* force the early guard */
int  brix_connect(brix_conn *c, const brix_url *u, const brix_opts *o, brix_status *s)
{ (void) c; (void) u; (void) o; (void) s; return -1; }
void brix_close(brix_conn *c) { (void) c; }
int  brix_file_open_opaque(brix_conn *c, const char *p, const char *o, int w,
                           int f, int po, brix_file *fh, brix_status *s)
{ (void) c; (void) p; (void) o; (void) w; (void) f; (void) po; (void) fh;
  (void) s; return -1; }
ssize_t brix_file_read(brix_conn *c, brix_file *f, int64_t off, void *b,
                       size_t l, brix_status *s)
{ (void) c; (void) f; (void) off; (void) b; (void) l; (void) s; return -1; }
int  brix_file_close(brix_conn *c, brix_file *f, brix_status *s)
{ (void) c; (void) f; (void) s; return 0; }

/* The fileinfo-sampling fallback lives in a sibling TU (diag_doctor_eos_fileinfo.c,
 * exercised by its own suite). doctor_eos_map references these on its gated branch,
 * which brix_endpoint_parse-fails before ever reaching — trivial stubs satisfy the
 * link. */
int  doctor_eos_url_path(const char *url, char *out, size_t osz)
{ (void) url; if (out && osz) { out[0] = '\0'; } return 0; }
int  doctor_eos_discover_fileinfo(brix_conn *c, const char *root, doctor_ep *arr,
                                  int cap, int start, int *n, brix_status *st)
{ (void) c; (void) root; (void) arr; (void) cap; (void) start; (void) n;
  (void) st; return 0; }

#include "diag_doctor_eos.c"

/* ---- harness ---- */
static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static int has(const char *hay, const char *needle)
{ return strstr(hay, needle) != NULL; }

/* Capture a printf-emitting renderer by swapping the stdout stream (glibc). */
static char *
capture(void (*fn)(const doctor_ep *), const doctor_ep *e)
{
    char *buf = NULL;
    size_t sz = 0;
    FILE  *ms = open_memstream(&buf, &sz);
    FILE  *save = stdout;
    stdout = ms;
    fn(e);
    fflush(ms);
    stdout = save;
    fclose(ms);
    return buf;
}

/* report_fst has a return value, so it needs its own wrapper for capture. */
static int g_fst_rv;
static void
call_report_fst(const doctor_ep *e) { g_fst_rv = doctor_eos_report_fst(e); }

/* The genuine eospublic version reply envelope (captured live 2026-08-03). */
static const char VERSION_REPLY[] =
    "mgm.proc.stdout=EOS_INSTANCE=eospublic\n"
    "EOS_SERVER_VERSION=5.3.36 EOS_SERVER_RELEASE=1"
    "&mgm.proc.stderr=&mgm.proc.retc=0";

/* A constructed `fs ls -m` reply: three filesystems exercising the health
 * branches (booted+online → green, booted+offline → yellow, down → red). */
static const char FS_LS_REPLY[] =
    "mgm.proc.stdout="
    "host=fst01.cern.ch port=1095 id=1 schedgroup=default.0 path=/data01 "
      "stat.boot=booted configstatus=rw stat.geotag=CERN::rack1 "
      "stat.active=online stat.statfs.capacity=100000000000 "
      "stat.statfs.freebytes=40000000000 stat.statfs.usedbytes=60000000000\n"
    "host=fst02.cern.ch port=1096 id=2 schedgroup=default.1 path=/data02 "
      "stat.boot=booted configstatus=ro stat.geotag=CERN::rack2 "
      "stat.active=offline stat.statfs.capacity=200000000000 "
      "stat.statfs.freebytes=10000000000\n"
    "host=fst03.cern.ch port=1095 id=3 schedgroup=default.2 path=/data03 "
      "stat.boot=down configstatus=drain stat.geotag=CERN::rack3 "
      "stat.active=offline stat.statfs.capacity=50000000000 "
      "stat.statfs.freebytes=0\n"
    "&mgm.proc.stderr=&mgm.proc.retc=0";

int
main(void)
{
    char       out[128];
    doctor_ep  arr[8];
    char      *s;

    /* ---- doctor_eos_kv: exact token-boundary matching ---- */
    {
        const char *rec = "host=fst01.cern.ch port=1095 stat.host=x";
        CHECK(doctor_eos_kv(rec, "host", out, sizeof(out)) == 0);
        CHECK(strcmp(out, "fst01.cern.ch") == 0);         /* not stat.host */
        CHECK(doctor_eos_kv(rec, "port", out, sizeof(out)) == 0);
        CHECK(strcmp(out, "1095") == 0);
        /* "host" must NOT match inside "hostport" */
        CHECK(doctor_eos_kv("hostport=a.b:1 x=y", "host", out, sizeof(out)) != 0);
        CHECK(doctor_eos_kv("hostport=a.b:1", "hostport", out, sizeof(out)) == 0);
        CHECK(strcmp(out, "a.b:1") == 0);
        CHECK(doctor_eos_kv(rec, "missing", out, sizeof(out)) != 0);
        CHECK(doctor_eos_kv(NULL, "host", out, sizeof(out)) != 0);
        CHECK(doctor_eos_kv(rec, "host", out, 4) == 0);   /* truncates safely */
    }

    /* ---- doctor_eos_stdout / _retc ---- */
    {
        const char *st;
        int         ln;
        CHECK(doctor_eos_stdout(VERSION_REPLY, &st, &ln) == 0);
        CHECK(ln > 0 && strncmp(st, "EOS_INSTANCE=eospublic", 22) == 0);
        CHECK(doctor_eos_stdout("no envelope here", &st, &ln) != 0);
        CHECK(doctor_eos_retc(VERSION_REPLY) == 0);
        CHECK(doctor_eos_retc("...&mgm.proc.retc=95") == 95);
        CHECK(doctor_eos_retc("{\"retc\" : 22, ...}") == 22);
        CHECK(doctor_eos_retc("nothing") == -1);
    }

    /* ---- doctor_eos_parse_version over the genuine reply ---- */
    {
        doctor_eos eos;
        memset(&eos, 0, sizeof(eos));
        CHECK(doctor_eos_parse_version(VERSION_REPLY, &eos) == 1);
        CHECK(eos.kind == DOC_EOS_MGM);
        CHECK(strcmp(eos.instance, "eospublic") == 0);
        CHECK(strcmp(eos.version, "5.3.36") == 0);
        /* a non-EOS reply is rejected */
        memset(&eos, 0, sizeof(eos));
        CHECK(doctor_eos_parse_version("mgm.proc.stdout=hello&mgm.proc.retc=0",
                                       &eos) == 0);
        CHECK(eos.kind == DOC_EOS_NONE);
    }

    /* ---- doctor_eos_parse_fs: build the FST inventory ---- */
    {
        const char *st;
        int         ln, added;
        memset(arr, 0, sizeof(arr));
        CHECK(doctor_eos_stdout(FS_LS_REPLY, &st, &ln) == 0);
        added = doctor_eos_parse_fs(st, ln, arr, 8, 1);
        CHECK(added == 3);

        /* fst01 — booted + online + rw */
        CHECK(strcmp(arr[1].host, "fst01.cern.ch") == 0);
        CHECK(arr[1].port == 1095);
        CHECK(arr[1].eos.kind == DOC_EOS_FST);
        CHECK(strcmp(arr[1].eos.geotag, "CERN::rack1") == 0);
        CHECK(strcmp(arr[1].eos.cfgstatus, "rw") == 0);
        CHECK(arr[1].eos.booted == 1 && arr[1].eos.active == 1);
        CHECK(arr[1].eos.cap_bytes == 100000000000LL);
        CHECK(arr[1].eos.free_bytes == 40000000000LL);
        CHECK(arr[1].cfg.space_total == 100000000000LL);  /* mirrored for pct */
        CHECK(arr[1].cfg.scraped == 1);
        CHECK(arr[1].cms.reported == 1 && arr[1].cms.role == DOC_CMS_SERVER);
        CHECK(arr[1].cms.write == 1);                      /* configstatus rw */

        /* fst02 — booted + offline + ro */
        CHECK(strcmp(arr[2].host, "fst02.cern.ch") == 0 && arr[2].port == 1096);
        CHECK(arr[2].eos.booted == 1 && arr[2].eos.active == 0);
        CHECK(arr[2].cms.write == 0);                      /* configstatus ro */

        /* fst03 — down + drain */
        CHECK(arr[3].eos.booted == 0 && arr[3].eos.active == 0);
        CHECK(strcmp(arr[3].eos.cfgstatus, "drain") == 0);
        CHECK(arr[3].eos.free_bytes == 0);

        /* respects the cap: only room for 1 more from start=7 */
        memset(arr, 0, sizeof(arr));
        CHECK(doctor_eos_parse_fs(st, ln, arr, 8, 7) == 1);
    }

    /* ---- renderers: report_fst ---- */
    {
        doctor_ep e;
        memset(&e, 0, sizeof(e));
        e.eos.kind = DOC_EOS_FST;
        e.eos.booted = 1;
        e.eos.active = 1;
        snprintf(e.host, sizeof(e.host), "fst01.cern.ch");
        e.port = 1095;
        snprintf(e.eos.geotag, sizeof(e.eos.geotag), "CERN::rack1");
        snprintf(e.eos.cfgstatus, sizeof(e.eos.cfgstatus), "rw");
        e.cfg.space_total = 100;
        e.cfg.space_free  = 40;

        s = capture(call_report_fst, &e);
        CHECK(g_fst_rv == 1);
        CHECK(has(s, "EOS FST fst01.cern.ch:1095"));
        CHECK(has(s, "GREEN"));
        CHECK(has(s, "geo=CERN::rack1"));
        CHECK(has(s, "cfg=rw"));
        CHECK(has(s, "40% free"));
        CHECK(has(s, "from MGM fs ls"));                  /* provenance: admin path */
        free(s);

        /* a sampled FST names its provenance instead */
        e.eos.sampled = 1;
        s = capture(call_report_fst, &e);
        CHECK(has(s, "via fileinfo replica sampling"));
        CHECK(!has(s, "from MGM fs ls"));
        free(s);
        e.eos.sampled = 0;

        /* a non-FST endpoint: report_fst declines (returns 0, prints nothing) */
        memset(&e, 0, sizeof(e));
        e.eos.kind = DOC_EOS_NONE;
        s = capture(call_report_fst, &e);
        CHECK(g_fst_rv == 0);
        CHECK(s[0] == '\0');
        free(s);
    }

    /* ---- renderers: report_mgm (gated vs enumerated) ---- */
    {
        doctor_ep e;
        memset(&e, 0, sizeof(e));
        e.eos.kind = DOC_EOS_MGM;
        snprintf(e.eos.instance, sizeof(e.eos.instance), "eospublic");
        snprintf(e.eos.version, sizeof(e.eos.version), "5.3.36");
        e.eos.gated = 1;
        s = capture(doctor_eos_report_mgm, &e);
        CHECK(has(s, "EOS MGM eospublic v5.3.36"));
        CHECK(has(s, "admin-gated"));
        free(s);

        e.eos.gated = 0;
        e.eos.fst_count = 42;
        s = capture(doctor_eos_report_mgm, &e);
        CHECK(has(s, "42 FSTs enumerated"));
        free(s);

        /* sampled (admin gated → fileinfo fallback): distinct, honest wording */
        e.eos.gated = 1;
        e.eos.sampled = 1;
        e.eos.fst_count = 7;
        s = capture(doctor_eos_report_mgm, &e);
        CHECK(has(s, "7 FSTs via fileinfo replica sampling"));
        CHECK(has(s, "partial"));
        CHECK(!has(s, "admin-gated —"));      /* not the zero-FST gated wording */
        free(s);

        /* a non-MGM endpoint prints nothing */
        memset(&e, 0, sizeof(e));
        s = capture(doctor_eos_report_mgm, &e);
        CHECK(s[0] == '\0');
        free(s);
    }

    /* ---- renderers: emit_json ---- */
    {
        doctor_ep e;
        char     *buf = NULL;
        size_t    sz = 0;
        FILE     *ms;

        memset(&e, 0, sizeof(e));
        e.eos.kind = DOC_EOS_MGM;
        snprintf(e.eos.instance, sizeof(e.eos.instance), "eospublic");
        snprintf(e.eos.version, sizeof(e.eos.version), "5.3.36");
        e.eos.gated = 1;
        ms = open_memstream(&buf, &sz);
        doctor_eos_emit_json(&e, ms);
        fclose(ms);
        CHECK(has(buf, "\"eos\":{\"kind\":\"mgm\""));
        CHECK(has(buf, "\"instance\":\"eospublic\""));
        CHECK(has(buf, "\"gated\":true"));
        CHECK(has(buf, "\"sampled\":false"));
        free(buf);

        memset(&e, 0, sizeof(e));
        e.eos.kind = DOC_EOS_FST;
        e.eos.booted = 1;
        e.eos.active = 1;
        snprintf(e.eos.geotag, sizeof(e.eos.geotag), "CERN::rack1");
        snprintf(e.eos.cfgstatus, sizeof(e.eos.cfgstatus), "rw");
        e.eos.cap_bytes = 100;
        e.eos.free_bytes = 40;
        buf = NULL; sz = 0;
        ms = open_memstream(&buf, &sz);
        doctor_eos_emit_json(&e, ms);
        fclose(ms);
        CHECK(has(buf, "\"eos\":{\"kind\":\"fst\""));
        CHECK(has(buf, "\"geotag\":\"CERN::rack1\""));
        CHECK(has(buf, "\"booted\":true,\"active\":true"));
        CHECK(has(buf, "\"capacity\":100,\"free\":40"));
        free(buf);
    }

    /* ---- doctor_eos_map: early guard (endpoint_parse stubbed to fail) ---- */
    {
        diag_args a;
        int       n = 1;
        memset(&a, 0, sizeof(a));
        memset(arr, 0, sizeof(arr));
        a.map = 1;
        a.urls[0] = "root://eos.example.org:1094//eos";
        CHECK(doctor_eos_map(&a, arr, 8, &n) == 0);
        CHECK(n == 1);                          /* untouched */
        /* not requested for a non-map run either */
        a.map = 0;
        CHECK(doctor_eos_map(&a, arr, 8, &n) == 0);
    }

    if (g_fail) {
        printf("%d CHECK(s) FAILED\n", g_fail);
        return 1;
    }
    printf("OK all EOS-dialect parser/renderer checks passed\n");
    return 0;
}
