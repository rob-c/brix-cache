/*
 * node_ops_unittest.c — standalone unit test for the forwarded-op planner.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/cms_nodeops_ut \
 *       src/net/cms/node_ops_unittest.c src/net/cms/node_ops.c \
 *       && /tmp/cms_nodeops_ut
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

/* short aliases for the planned actions (mirror the K_* opcode shorthands) */
#define A_CHMOD  XRDCMS_NACT_CHMOD
#define A_MKDIR  XRDCMS_NACT_MKDIR
#define A_MKPATH XRDCMS_NACT_MKPATH
#define A_MV     XRDCMS_NACT_MV
#define A_TRUNC  XRDCMS_NACT_TRUNC

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

/* Plan `kind` over an rrdata built from C-string fields, asserting the planner
 * verdict and the resulting action here so each test checks only its
 * op-specific plan fields. (Returned plan pointers reference the caller's
 * string literals, so the copy outlives the local rrdata.) */
static brix_cms_node_plan_t
plan_ok(int kind, const char *path, const char *path2, const char *mode,
    int want_action)
{
    brix_cms_rrdata_t d = rr(path, path2, mode);
    brix_cms_node_plan_t p;

    memset(&p, 0, sizeof(p));
    CHECK(brix_cms_node_plan(kind, &d, &p) == 0);
    CHECK((int) p.action == want_action);
    return p;
}

/* Planner verdict alone, for the rejection tests. */
static int
plan_rc(int kind, const char *path, const char *path2, const char *mode)
{
    brix_cms_rrdata_t d = rr(path, path2, mode);
    brix_cms_node_plan_t p;

    return brix_cms_node_plan(kind, &d, &p);
}

static void
test_mkdir_mode(void)
{
    brix_cms_node_plan_t p = plan_ok(K_MKDIR, "/atlas/d", NULL, "750", A_MKDIR);
    CHECK(p.path && strcmp(p.path, "/atlas/d") == 0);
    CHECK(p.mode == 0750);
}

static void
test_mkdir_default_mode(void)
{
    /* no mode field on the wire */
    brix_cms_node_plan_t p = plan_ok(K_MKDIR, "/d", NULL, NULL, A_MKDIR);
    CHECK(p.mode == XRDCMS_NODE_DEFAULT_DIR_MODE);
}

static void
test_mkpath(void)
{
    (void) plan_ok(K_MKPATH, "/a/b/c", NULL, "755", A_MKPATH);
}

static void
test_chmod(void)
{
    brix_cms_node_plan_t p = plan_ok(K_CHMOD, "/f", NULL, "640", A_CHMOD);
    CHECK(p.mode == 0640);
}

static void
test_chmod_requires_mode(void)
{
    CHECK(plan_rc(K_CHMOD, "/f", NULL, NULL) == -1);
}

static void
test_trunc_size(void)
{
    /* size travels in the Mode field */
    brix_cms_node_plan_t p = plan_ok(K_TRUNC, "/big", NULL, "1048576", A_TRUNC);
    CHECK(p.size == 1048576);
}

static void
test_mv(void)
{
    brix_cms_node_plan_t p = plan_ok(K_MV, "/src", "/dst", NULL, A_MV);
    CHECK(p.path && strcmp(p.path, "/src") == 0);
    CHECK(p.path2 && strcmp(p.path2, "/dst") == 0);
}

static void
test_mv_requires_two_paths(void)
{
    CHECK(plan_rc(K_MV, "/src", NULL, NULL) == -1);
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
    CHECK(plan_rc(K_MKDIR, NULL, NULL, "755") == -1);
}

static void
test_non_executed_opcode(void)
{
    /* an opcode this node does not execute at all (kYR_statfs = 21 routes
     * elsewhere; use an unmapped code) */
    CHECK(plan_rc(99, "/x", NULL, "0") == -1);
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
    CHECK(plan_rc(K_PREPADD, "/atlas/f.root", NULL, NULL) == -1);
}

static void
test_prepdel_plan(void)
{
    /* prepdel carries only ident+reqid — no path required. */
    brix_cms_rrdata_t d = rr(NULL, NULL, NULL);
    brix_cms_node_plan_t p;
    d.reqid = (const unsigned char *) "42.7@mgr"; d.reqid_len = 8;
    CHECK(brix_cms_node_plan(K_PREPDEL, &d, &p) == 0
          && p.action == XRDCMS_NACT_PREPDEL);
    CHECK(p.reqid && strcmp(p.reqid, "42.7@mgr") == 0);
}

static void
test_prepdel_requires_reqid(void)
{
    CHECK(plan_rc(K_PREPDEL, NULL, NULL, NULL) == -1);
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
