/*
 * creds_guard_test.c — exhaustive unit test of brix_imp_creds_privileged()
 * (the single authoritative reserved-id test used by BOTH the mapping layer and
 * the broker's setfsuid-edge guard).
 *
 * This is the brain of "it is impossible to drop to uid/gid < the floor": the
 * broker calls this with floor = BRIX_IMP_HARD_MIN_ID before any credential
 * syscall, and refuses (touching no setfsuid) whenever it returns 1.  Proving the
 * predicate flags every reserved primary uid, primary gid, supplementary gid,
 * bad ngroups, and NULL is therefore the core proof of the guarantee.
 *
 * Pure logic — needs no user namespace, no root, no server.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "impersonate.h"

/* idmap.o references ngx_log_error_core via other functions; stub it. */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
                   const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

static int g_pass, g_fail;

#define CK(cond, msg)                                                          \
    do {                                                                       \
        if (cond) { g_pass++; }                                               \
        else { g_fail++; fprintf(stderr, "FAIL: %s\n", (msg)); }              \
    } while (0)

/* Build a creds struct: uid, gid, then a NULL-terminated list of supp gids. */
static brix_idmap_creds_t
mk(uid_t uid, gid_t gid, int ngroups, const gid_t *groups)
{
    brix_idmap_creds_t c;
    int i;
    memset(&c, 0, sizeof(c));
    c.uid = uid;
    c.gid = gid;
    c.ngroups = ngroups;
    /* Only copy when a real array was supplied (out-of-range ngroups cases pass
     * NULL deliberately to exercise the predicate's bounds check). */
    for (i = 0; groups != NULL && i < ngroups && i < BRIX_IDMAP_MAXGROUPS; i++) {
        c.groups[i] = groups[i];
    }
    return c;
}

int
main(void)
{
    const uid_t FLOOR = BRIX_IMP_HARD_MIN_ID;   /* 1000 */
    uint32_t    id;
    char        kind;
    int         r;

    /* The hard floor must be exactly 1000 as documented/requested. */
    CK(BRIX_IMP_HARD_MIN_ID == 1000, "hard floor == 1000");

    /* ---- clean creds pass ---- */
    {
        gid_t g[] = { 1001, 1500 };
        brix_idmap_creds_t c = mk(1001, 1001, 2, g);
        r = brix_imp_creds_privileged(&c, FLOOR, &id, &kind);
        CK(r == 0, "clean uid/gid/supp >= floor -> allowed");
    }
    /* uid exactly at the floor is allowed (floor is inclusive lower bound). */
    {
        gid_t g[] = { 1000 };
        brix_idmap_creds_t c = mk(1000, 1000, 1, g);
        CK(brix_imp_creds_privileged(&c, FLOOR, NULL, NULL) == 0,
           "uid/gid == floor (1000) -> allowed");
    }

    /* ---- primary uid ---- */
    {
        gid_t g[] = { 1001 };
        brix_idmap_creds_t c = mk(0, 1001, 1, g);
        r = brix_imp_creds_privileged(&c, FLOOR, &id, &kind);
        CK(r == 1 && kind == 'u' && id == 0, "uid 0 -> privileged (u,0)");
    }
    {
        gid_t g[] = { 1001 };
        brix_idmap_creds_t c = mk(999, 1001, 1, g);
        r = brix_imp_creds_privileged(&c, FLOOR, &id, &kind);
        CK(r == 1 && kind == 'u' && id == 999, "uid 999 -> privileged (u,999)");
    }
    {
        gid_t g[] = { 1001 };
        brix_idmap_creds_t c = mk(1, 1001, 1, g);
        CK(brix_imp_creds_privileged(&c, FLOOR, NULL, NULL) == 1,
           "uid 1 -> privileged");
    }

    /* ---- primary gid ---- */
    {
        gid_t g[] = { 0 };
        brix_idmap_creds_t c = mk(1001, 0, 1, g);
        r = brix_imp_creds_privileged(&c, FLOOR, &id, &kind);
        CK(r == 1 && kind == 'g' && id == 0, "gid 0 -> privileged (g,0)");
    }
    {
        gid_t g[] = { 50 };
        brix_idmap_creds_t c = mk(1001, 50, 1, g);
        r = brix_imp_creds_privileged(&c, FLOOR, &id, &kind);
        CK(r == 1 && kind == 'g' && id == 50, "gid 50 -> privileged (g,50)");
    }

    /* ---- supplementary gids ---- */
    {
        gid_t g[] = { 1001, 50 };
        brix_idmap_creds_t c = mk(1001, 1001, 2, g);
        r = brix_imp_creds_privileged(&c, FLOOR, &id, &kind);
        CK(r == 1 && kind == 's' && id == 50, "supp gid 50 -> privileged (s,50)");
    }
    {
        gid_t g[] = { 1001, 1500, 0 };
        brix_idmap_creds_t c = mk(1001, 1001, 3, g);
        r = brix_imp_creds_privileged(&c, FLOOR, &id, &kind);
        CK(r == 1 && kind == 's' && id == 0, "supp gid 0 -> privileged (s,0)");
    }
    {   /* a high supp gid is fine */
        gid_t g[] = { 1001, 65000 };
        brix_idmap_creds_t c = mk(1001, 1001, 2, g);
        CK(brix_imp_creds_privileged(&c, FLOOR, NULL, NULL) == 0,
           "supp gid 65000 -> allowed");
    }

    /* ---- ngroups bounds + NULL ---- */
    {
        brix_idmap_creds_t c = mk(1001, 1001, 0, NULL);
        CK(brix_imp_creds_privileged(&c, FLOOR, NULL, NULL) == 0,
           "ngroups 0 with safe uid/gid -> allowed");
    }
    {
        brix_idmap_creds_t c = mk(1001, 1001, -1, NULL);
        r = brix_imp_creds_privileged(&c, FLOOR, &id, &kind);
        CK(r == 1 && kind == 'n', "ngroups -1 -> privileged (n)");
    }
    {
        brix_idmap_creds_t c = mk(1001, 1001, BRIX_IDMAP_MAXGROUPS + 1, NULL);
        r = brix_imp_creds_privileged(&c, FLOOR, &id, &kind);
        CK(r == 1 && kind == 'n', "ngroups > MAXGROUPS -> privileged (n)");
    }
    CK(brix_imp_creds_privileged(NULL, FLOOR, &id, &kind) == 1
           && kind == 'n', "NULL creds -> privileged (n)");

    /* ---- a higher configured floor refuses ids that are fine at 1000 ---- */
    {
        gid_t g[] = { 1500 };
        brix_idmap_creds_t c = mk(1500, 1500, 1, g);
        CK(brix_imp_creds_privileged(&c, FLOOR, NULL, NULL) == 0,
           "uid/gid 1500 allowed at floor 1000");
        CK(brix_imp_creds_privileged(&c, 2000, NULL, NULL) == 1,
           "uid/gid 1500 refused at floor 2000");
    }

    /* ---- exhaustive sweep: every id 0..1000 below floor must be refused ---- */
    {
        uid_t u;
        int   bad = 0;
        for (u = 0; u < FLOOR; u++) {
            gid_t g1[] = { 1001 };
            brix_idmap_creds_t cu = mk(u, 1001, 1, g1);   /* sub-floor uid */
            gid_t g2[] = { (gid_t) u };
            brix_idmap_creds_t cg = mk(1001, (gid_t) u, 1, g2); /* sub-floor gid */
            gid_t g3[] = { 1001, (gid_t) u };
            brix_idmap_creds_t cs = mk(1001, 1001, 2, g3); /* sub-floor supp */
            if (brix_imp_creds_privileged(&cu, FLOOR, NULL, NULL) != 1) bad++;
            if (brix_imp_creds_privileged(&cg, FLOOR, NULL, NULL) != 1) bad++;
            if (brix_imp_creds_privileged(&cs, FLOOR, NULL, NULL) != 1) bad++;
        }
        CK(bad == 0, "exhaustive 0..999 sweep: EVERY sub-floor uid/gid/supp refused");
    }

    fprintf(stderr, "%d passed, %d failed\n", g_pass, g_fail);
    if (g_fail == 0) {
        printf("ALL PASSED\n");
        return 0;
    }
    printf("FAILED\n");
    return 1;
}
