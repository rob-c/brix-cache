/*
 * diag_doctor_eos_fileinfo_unittest.c — unit test for the unprivileged EOS FST
 * discovery path (diag_doctor_eos_fileinfo.c): the URL-path helper, the fileinfo
 * replica-table parser (driven over a GENUINE eospublic `fileinfo` reply, box-
 * drawing + ANSI colour and all), and the bounded sampling walk end-to-end over
 * faked wire primitives (doctor_eos_proc / brix_dirlist), including FST dedup.
 *
 *   cc -std=c11 -Wall -Wextra -Werror -Ilib -I../src -I../shared \
 *      -DXRDPROTO_NO_NGX apps/diag/diag_doctor_eos_fileinfo_unittest.c -o /tmp/ut \
 *   && /tmp/ut          (run from client/)
 *
 * Exit 0 = all checks pass. Pure C — no server, no libbrix: the TU is #included
 * and its externs (doctor_eos_proc, doctor_eos_stdout, brix_dirlist) are satisfied
 * by fakes that model a tiny two-level EOS tree with two files whose replica sets
 * overlap, so the walk must dedup to three distinct FSTs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag_internal.h"

/* ---- a genuine eospublic `fileinfo` reply for /eos/opendata/.space/opendata-
 * logo.png (captured live 2026-08-03): pretty table, box-drawing rules, and the
 * ANSI-coloured `online` cell — exactly what the /proc route returns (it ignores
 * the -m monitoring flag). Two replicas on two real FSTs. ---- */
static const char FILEINFO_A[] =
    "  File: '/eos/opendata/.space/opendata-logo.png'  Flags: 0444\n"
    "  Size: 59248\n"
    "Status: healthy\n"
    "Layout: replica Stripes: 2 Blocksize: 4k LayoutId: 00600112\n"
    "  #Rep: 2\n"
    "\xe2\x94\x8c\xe2\x94\x80\xe2\x94\xac\xe2\x94\x80\xe2\x94\x90\n"
    "\xe2\x94\x82no.\xe2\x94\x82 fs-id\xe2\x94\x82  host\xe2\x94\x82  geotag\xe2\x94\x82\n"
    "\xe2\x94\x94\xe2\x94\x80\xe2\x94\xb4\xe2\x94\x80\xe2\x94\x98\n"
    " 0    24007  st-096-dd904018.cern.ch        default.2          /data10"
      "     booted             rw      nodrain   \x1b[1;39monline\x1b[0m"
      " 1b677da0::0513::S::0034::SL09 \n"
    " 1    17541  st-096-ff809a33.cern.ch        default.2          /data88"
      "     booted             rw      nodrain   \x1b[1;39monline\x1b[0m"
      " 198892e9::0513::S::0034::SE15 \n"
    "\n*******\n";

/* A second file whose replicas overlap FILEINFO_A (ff809a33 shared) plus a third
 * FST — so the union across the two files is three distinct hosts, and one of the
 * three is offline+drain to exercise the non-green mapping. */
static const char FILEINFO_B[] =
    "  File: '/eos/opendata/b.root'  Flags: 0644\n"
    "  #Rep: 2\n"
    " 0    17541  st-096-ff809a33.cern.ch        default.2          /data88"
      "     booted             rw      nodrain   \x1b[1;39monline\x1b[0m"
      " 198892e9::0513::S::0034::SE15 \n"
    " 1    30011  st-042-aa112233.cern.ch        default.7          /data03"
      "     booting            drain   draining          offline"
      " 7c001199::0042::S::0007::SL02 \n";

/* ---- fakes for the externs the discovery TU references ---- */
void brix_status_clear(brix_status *st) { (void) st; }

/* doctor_eos_proc: hand back the fixture whose file the command names. The `cmd`
 * carries `mgm.cmd=fileinfo&mgm.path=<full>`; we key on the basename. */
int
doctor_eos_proc(brix_conn *c, const char *dir, const char *cmd,
                char **out, brix_status *st)
{
    const char *body;
    (void) c; (void) dir; (void) st;

    if (strstr(cmd, "opendata-logo.png") != NULL) { body = FILEINFO_A; }
    else if (strstr(cmd, "b.root") != NULL)       { body = FILEINFO_B; }
    else { return -1; }
    *out = strdup(body);
    return *out ? 0 : -1;
}

/* doctor_eos_stdout: the fakes above return raw table text (no envelope), so the
 * whole body IS the stdout span. */
int
doctor_eos_stdout(const char *body, const char **start, int *len)
{
    if (body == NULL) { return -1; }
    *start = body;
    *len = (int) strlen(body);
    return 0;
}

/* brix_dirlist: model /eos → [opendata/] and /eos/opendata → [logo.png,
 * b.root, sub/]; `sub` is an empty dir (tests the descend budget without adding
 * FSTs). Any other path lists empty. Entries carry have_stat + the isDir flag. */
int
brix_dirlist(brix_conn *c, const char *path, int want_stat,
             brix_dirent **ents, size_t *count, brix_status *st)
{
    brix_dirent *e;
    (void) c; (void) want_stat; (void) st;

    if (strcmp(path, "/eos") == 0) {
        e = calloc(1, sizeof(*e));
        if (!e) { return -1; }
        snprintf(e[0].name, sizeof(e[0].name), "opendata");
        e[0].have_stat = 1; e[0].st.flags = kXR_isDir;
        *ents = e; *count = 1; return 0;
    }
    if (strcmp(path, "/eos/opendata") == 0) {
        e = calloc(3, sizeof(*e));
        if (!e) { return -1; }
        snprintf(e[0].name, sizeof(e[0].name), "opendata-logo.png");
        e[0].have_stat = 1; e[0].st.flags = 0;             /* a file */
        snprintf(e[1].name, sizeof(e[1].name), "b.root");
        e[1].have_stat = 1; e[1].st.flags = 0;             /* a file */
        snprintf(e[2].name, sizeof(e[2].name), "sub");
        e[2].have_stat = 1; e[2].st.flags = kXR_isDir;     /* empty subdir */
        *ents = e; *count = 3; return 0;
    }
    *ents = NULL; *count = 0; return 0;                    /* /eos/opendata/sub */
}

#include "diag_doctor_eos_fileinfo.c"

/* ---- harness ---- */
static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

int
main(void)
{
    char out[128];

    /* ---- doctor_eos_url_path ---- */
    CHECK(doctor_eos_url_path("root://eospublic.cern.ch:1094//eos", out,
                              sizeof(out)) == 0);
    CHECK(strcmp(out, "/eos") == 0);                         /* double slash */
    doctor_eos_url_path("roots://h.example//eos/opendata/", out, sizeof(out));
    CHECK(strcmp(out, "/eos/opendata") == 0);                /* trailing / trimmed */
    doctor_eos_url_path("root://h.example/eos", out, sizeof(out));
    CHECK(strcmp(out, "/eos") == 0);                         /* single slash */
    doctor_eos_url_path("root://h.example//eos?authz=xxx", out, sizeof(out));
    CHECK(strcmp(out, "/eos") == 0);                         /* opaque stripped */
    doctor_eos_url_path("root://h.example", out, sizeof(out));
    CHECK(strcmp(out, "/") == 0);                            /* no path */
    doctor_eos_url_path(NULL, out, sizeof(out));
    CHECK(out[0] == '\0');

    /* ---- doctor_eos_parse_fileinfo over the genuine table ---- */
    {
        doctor_eos_rep reps[16];
        int            nr = doctor_eos_parse_fileinfo(FILEINFO_A,
                                (int) strlen(FILEINFO_A), reps, 16);
        CHECK(nr == 2);                                      /* only the 2 data rows */
        CHECK(strcmp(reps[0].host, "st-096-dd904018.cern.ch") == 0);
        CHECK(reps[0].port == 1095);                         /* fileinfo omits port */
        CHECK(strcmp(reps[0].cfgstatus, "rw") == 0);
        CHECK(reps[0].booted == 1 && reps[0].active == 1);   /* ANSI-online parsed */
        CHECK(strcmp(reps[0].geotag, "1b677da0::0513::S::0034::SL09") == 0);
        CHECK(strcmp(reps[1].host, "st-096-ff809a33.cern.ch") == 0);
        CHECK(reps[1].active == 1);

        /* the booting/drain/offline row from B maps to not-booted/offline */
        nr = doctor_eos_parse_fileinfo(FILEINFO_B, (int) strlen(FILEINFO_B),
                                       reps, 16);
        CHECK(nr == 2);
        CHECK(strcmp(reps[1].host, "st-042-aa112233.cern.ch") == 0);
        CHECK(reps[1].booted == 0 && reps[1].active == 0);
        CHECK(strcmp(reps[1].cfgstatus, "drain") == 0);

        /* respects the output cap */
        CHECK(doctor_eos_parse_fileinfo(FILEINFO_A, (int) strlen(FILEINFO_A),
                                        reps, 1) == 1);
    }

    /* ---- doctor_eos_discover_fileinfo: walk + sample + dedup end-to-end ---- */
    {
        doctor_ep arr[16];
        int       n = 1, added;                              /* arr[0] = the MGM */
        brix_status st;

        memset(arr, 0, sizeof(arr));
        arr[0].eos.kind = DOC_EOS_MGM;
        added = doctor_eos_discover_fileinfo(NULL /*unused by fakes*/, "/eos",
                                             arr, 16, 1, &n, &st);
        CHECK(added == 3);                                   /* union of A ∪ B */
        CHECK(n == 4);
        /* the shared FST appears exactly once */
        {
            int i, seen = 0;
            for (i = 1; i < n; i++) {
                CHECK(arr[i].eos.kind == DOC_EOS_FST);
                CHECK(arr[i].eos.sampled == 1);
                CHECK(arr[i].cms.reported == 1);
                if (strcmp(arr[i].host, "st-096-ff809a33.cern.ch") == 0) { seen++; }
            }
            CHECK(seen == 1);
        }
        /* the offline/drain FST is typed read-only (no "rw" in configstatus) */
        {
            int i;
            for (i = 1; i < n; i++) {
                if (strcmp(arr[i].host, "st-042-aa112233.cern.ch") == 0) {
                    CHECK(arr[i].cms.write == 0);
                    CHECK(arr[i].eos.booted == 0);
                }
            }
        }
    }

    if (g_fail) {
        printf("%d CHECK(s) FAILED\n", g_fail);
        return 1;
    }
    printf("OK all EOS fileinfo-discovery checks passed\n");
    return 0;
}
