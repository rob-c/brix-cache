/*
 * node_ops_unittest.c — standalone unit test for the forwarded-op planner.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/cms_nodeops_ut \
 *       src/cms/node_ops_unittest.c src/cms/node_ops.c && /tmp/cms_nodeops_ut
 *
 * Exit 0 = all checks pass. Pure C (no nginx, no filesystem).
 */

#include "node_ops.h"

#include <stdio.h>
#include <string.h>

#define K_CHMOD   1
#define K_MKDIR   3
#define K_MKPATH  4
#define K_MV      5
#define K_RM      8
#define K_RMDIR   9
#define K_TRUNC  23
#define K_PREPADD 6
#define K_PREPDEL 7

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* Build an rrdata with C-string fields (lengths excluding NUL, as the real
 * decoder produces). */
static brix_cms_rrdata_t
rr(const char *path, const char *path2, const char *mode)
{
    brix_cms_rrdata_t d;
    memset(&d, 0, sizeof(d));
    if (path)  { d.path  = (const unsigned char *) path;  d.path_len  = strlen(path); }
    if (path2) { d.path2 = (const unsigned char *) path2; d.path2_len = strlen(path2); }
    if (mode)  { d.mode  = (const unsigned char *) mode;  d.mode_len  = strlen(mode); }
    return d;
}

static void
test_mkdir_mode(void)
{
    brix_cms_rrdata_t d = rr("/atlas/d", NULL, "750");
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_MKDIR, &d, &p) == 0);
    CHECK(p.action == XRDCMS_NACT_MKDIR);
    CHECK(p.path && strcmp(p.path, "/atlas/d") == 0);
    CHECK(p.mode == 0750);
}

static void
test_mkdir_default_mode(void)
{
    brix_cms_rrdata_t d = rr("/d", NULL, NULL);   /* no mode field */
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_MKDIR, &d, &p) == 0);
    CHECK(p.mode == XRDCMS_NODE_DEFAULT_DIR_MODE);
}

static void
test_mkpath(void)
{
    brix_cms_rrdata_t d = rr("/a/b/c", NULL, "755");
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_MKPATH, &d, &p) == 0);
    CHECK(p.action == XRDCMS_NACT_MKPATH);
}

static void
test_chmod(void)
{
    brix_cms_rrdata_t d = rr("/f", NULL, "640");
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_CHMOD, &d, &p) == 0);
    CHECK(p.action == XRDCMS_NACT_CHMOD);
    CHECK(p.mode == 0640);
}

static void
test_chmod_requires_mode(void)
{
    brix_cms_rrdata_t d = rr("/f", NULL, NULL);
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_CHMOD, &d, &p) == -1);
}

static void
test_trunc_size(void)
{
    brix_cms_rrdata_t d = rr("/big", NULL, "1048576");  /* size in Mode field */
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_TRUNC, &d, &p) == 0);
    CHECK(p.action == XRDCMS_NACT_TRUNC);
    CHECK(p.size == 1048576);
}

static void
test_mv(void)
{
    brix_cms_rrdata_t d = rr("/src", "/dst", NULL);
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_MV, &d, &p) == 0);
    CHECK(p.action == XRDCMS_NACT_MV);
    CHECK(p.path && strcmp(p.path, "/src") == 0);
    CHECK(p.path2 && strcmp(p.path2, "/dst") == 0);
}

static void
test_mv_requires_two_paths(void)
{
    brix_cms_rrdata_t d = rr("/src", NULL, NULL);
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_MV, &d, &p) == -1);
}

static void
test_rm_and_rmdir(void)
{
    brix_cms_rrdata_t d = rr("/x", NULL, NULL);
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_RM, &d, &p) == 0 && p.action == XRDCMS_NACT_RM);
    CHECK(brix_cms_node_plan(K_RMDIR, &d, &p) == 0 && p.action == XRDCMS_NACT_RMDIR);
}

static void
test_missing_path_rejected(void)
{
    brix_cms_rrdata_t d = rr(NULL, NULL, "755");
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_MKDIR, &d, &p) == -1);
}

static void
test_non_executed_opcode(void)
{
    /* an opcode this node does not execute at all (kYR_statfs = 21 routes
     * elsewhere; use an unmapped code) */
    brix_cms_rrdata_t d = rr("/x", NULL, "0");
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(99, &d, &p) == -1);
}

static void
test_prepadd_plan(void)
{
    /* prepadd needs path + reqid; notify/prty pass through when present. */
    brix_cms_rrdata_t d = rr("/atlas/f.root", NULL, NULL);
    brix_cms_node_plan_t p;
    d.reqid  = (const unsigned char *) "42.7@mgr"; d.reqid_len  = 8;
    d.notify = (const unsigned char *) "udp://n:1"; d.notify_len = 9;
    d.prty   = (const unsigned char *) "2";         d.prty_len   = 1;
    CHECK(brix_cms_node_plan(K_PREPADD, &d, &p) == 0);
    CHECK(p.action == XRDCMS_NACT_PREPADD);
    CHECK(p.path && strcmp(p.path, "/atlas/f.root") == 0);
    CHECK(p.reqid && strcmp(p.reqid, "42.7@mgr") == 0);
    CHECK(p.notify && strcmp(p.notify, "udp://n:1") == 0);
    CHECK(p.prty && strcmp(p.prty, "2") == 0);
}

static void
test_prepadd_requires_reqid(void)
{
    brix_cms_rrdata_t d = rr("/atlas/f.root", NULL, NULL);
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_PREPADD, &d, &p) == -1);
}

static void
test_prepdel_plan(void)
{
    /* prepdel carries only ident+reqid — no path required. */
    brix_cms_rrdata_t d = rr(NULL, NULL, NULL);
    brix_cms_node_plan_t p;
    d.reqid = (const unsigned char *) "42.7@mgr"; d.reqid_len = 8;
    CHECK(brix_cms_node_plan(K_PREPDEL, &d, &p) == 0);
    CHECK(p.action == XRDCMS_NACT_PREPDEL);
    CHECK(p.reqid && strcmp(p.reqid, "42.7@mgr") == 0);
}

static void
test_prepdel_requires_reqid(void)
{
    brix_cms_rrdata_t d = rr(NULL, NULL, NULL);
    brix_cms_node_plan_t p;
    CHECK(brix_cms_node_plan(K_PREPDEL, &d, &p) == -1);
}

int
main(void)
{
    test_mkdir_mode();
    test_mkdir_default_mode();
    test_mkpath();
    test_chmod();
    test_chmod_requires_mode();
    test_trunc_size();
    test_mv();
    test_mv_requires_two_paths();
    test_rm_and_rmdir();
    test_missing_path_rejected();
    test_non_executed_opcode();
    test_prepadd_plan();
    test_prepadd_requires_reqid();
    test_prepdel_plan();
    test_prepdel_requires_reqid();

    if (g_fail) { printf("%d check(s) FAILED\n", g_fail); return 1; }
    printf("all node_ops checks passed\n");
    return 0;
}
