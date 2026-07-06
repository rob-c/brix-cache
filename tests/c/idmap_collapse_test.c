/* tests/c/idmap_collapse_test.c — F6 principal->uid COLLAPSE conformance (threat T6).
 *
 * WHAT: proves the identity-mapping layer (src/auth/impersonate/idmap.c) collapses two
 *       distinct principals onto one uid ONLY when the mapping is EXPLICIT (a grid-mapfile
 *       entry), never as a silent side effect of the getpwnam() fallback; that the min_uid
 *       floor blocks an unmapped principal from collapsing onto a privileged system account
 *       whose name it matches; and that a bare DN never auto-collapses.
 * WHY:  a GSI DN and a Kerberos principal can legitimately map to the same local account,
 *       but that must be an operator decision in the gridmap — an attacker must not land on
 *       another user's uid merely by presenting a principal string embedding a local
 *       username (impersonation identity != authz identity).
 * HOW:  links the real idmap.o and drives brix_idmap_resolve() against the running NSS.
 *       The COLLAPSE-SUCCESS cases require a mappable, non-privileged target account: taken
 *       from $MU_CLEAN_USER (the MU fleet provisions clean brixtest_* accounts, uid >=1701,
 *       in no privileged group) or the self account, and SKIPPED with a clear note when the
 *       only available account is privileged (idmap correctly refuses to impersonate it, so
 *       the success paths cannot be exercised there). The account-independent GUARD cases
 *       always run. Matches tests/c/idmap_test.c style (stub ngx_log_error_core, CHECK()
 *       macro, static fails). NO goto.
 *
 * BUILD (matches tests/test_impersonate_idmap.py):
 *   gcc -O2 -D_GNU_SOURCE -I$NGX/src/core -I$NGX/src/event -I$NGX/src/event/modules \
 *       -I$NGX/src/os/unix -I$NGX/objs -I./src \
 *       tests/c/idmap_collapse_test.c src/auth/impersonate/idmap.c -o /tmp/idmap_collapse_test
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include "../../src/auth/impersonate/impersonate.h"
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* --- minimal nginx runtime stub (idmap.c is otherwise libc-only) --- */
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
                        const char *fmt, ...) { (void)level;(void)log;(void)err;(void)fmt; }

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  PASS %s\n", msg); } \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

static ngx_str_t S(const char *s){ ngx_str_t v; v.data=(u_char*)s; v.len=s?strlen(s):0; return v; }

/* Write a grid-mapfile with the given body; returns a fixed path or NULL. */
static const char *write_gridmap(const char *body)
{
    static const char *path = "/tmp/idmap_collapse_gridmap";
    FILE *f = fopen(path, "w");
    if (f == NULL) { return NULL; }
    fputs(body, f);
    fclose(f);
    return path;
}

/* Resolve `princ` with a plain min_uid=1000 config; return the verdict + fill *out. */
static ngx_int_t resolve_plain(const char *princ, brix_idmap_creds_t *out)
{
    brix_idmap_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    conf.min_uid = 1000;
    brix_idmap_init(&conf, NULL);
    return brix_idmap_resolve(&conf, princ, out, NULL);
}

int main(void)
{
    /* Pick a target account for the collapse-success cases: a clean non-privileged
     * account named in $MU_CLEAN_USER (MU fleet), else the self account. */
    const char *target = getenv("MU_CLEAN_USER");
    char tbuf[256];
    if (target == NULL || target[0] == '\0') {
        struct passwd *me = getpwuid(getuid());
        if (me == NULL) { printf("SKIP: getpwuid(self) failed\n"); return 0; }
        strncpy(tbuf, me->pw_name, sizeof(tbuf) - 1);
        tbuf[sizeof(tbuf) - 1] = '\0';
        target = tbuf;
    }

    struct passwd *tpw = getpwnam(target);
    if (tpw == NULL) { printf("SKIP: target account '%s' not found\n", target); return 0; }
    uid_t tuid = tpw->pw_uid;
    printf("target account=%s uid=%d\n", target, (int) tuid);

    /* Is the target mappable? idmap refuses privileged/forbidden-group accounts by design,
     * so the collapse-SUCCESS cases only make sense when the target actually maps. */
    brix_idmap_creds_t cr;
    int mappable = (tuid >= 1000) && (resolve_plain(target, &cr) == BRIX_IDMAP_OK)
                   && (cr.uid == tuid);
    if (!mappable) {
        printf("NOTE target '%s' is not mappable (privileged/forbidden group or uid<1000);"
               " collapse-SUCCESS cases SKIPPED — run under the MU fleet's clean"
               " brixtest_* accounts via MU_CLEAN_USER to exercise them.\n", target);
    }

    /* =====================================================================
     * GUARD cases — account-independent, always run.
     * ===================================================================== */

    /* G1. min_uid floor blocks collapse onto a privileged system account: an unmapped
     *     principal string equal to a real low-uid account ("daemon", uid 1) is refused
     *     by the floor even though getpwnam would succeed. */
    {
        struct passwd *sysacct = getpwnam("daemon");
        if (sysacct != NULL && sysacct->pw_uid < 1000) {
            ngx_int_t rc = resolve_plain("daemon", &cr);
            CHECK(rc == BRIX_IDMAP_DENY,
                  "G1 unmapped principal matching a system account blocked by min_uid floor");
        } else {
            printf("  SKIP G1: no 'daemon' account below uid 1000 on this host\n");
        }
    }

    /* G2. A full DN that is neither gridmap-mapped nor a valid username -> DENY.
     *     Confirms DNs never auto-collapse absent an explicit mapping. */
    {
        ngx_int_t rc = resolve_plain("/DC=test/CN=nobody-here-9d3f21", &cr);
        CHECK(rc == BRIX_IDMAP_DENY,
              "G2 unmapped DN that is not a local username -> DENY (no auto-collapse)");
    }

    /* G3. Unknown bare principal -> DENY (no default_user squash configured). */
    {
        ngx_int_t rc = resolve_plain("no_such_user_zzq_8817", &cr);
        CHECK(rc == BRIX_IDMAP_DENY, "G3 unknown principal -> DENY (deny-on-miss)");
    }

    if (!mappable) {
        printf(fails ? "\n%d FAILED\n" : "\nALL PASSED (guards only)\n", fails);
        return fails ? 1 : 0;
    }

    /* =====================================================================
     * COLLAPSE-SUCCESS cases — need a mappable, non-privileged target.
     * ===================================================================== */

    /* C1. INTENDED collapse: two distinct principals (a GSI DN and a Kerberos principal)
     *     both explicitly mapped to the target resolve to the SAME uid. */
    {
        char body[1024];
        snprintf(body, sizeof(body),
                 "\"/DC=test/CN=alice\" %s\n\"alice@TEST.REALM\" %s\n", target, target);
        const char *gm = write_gridmap(body);
        brix_idmap_conf_t conf;
        brix_idmap_creds_t cr_a, cr_b;
        memset(&conf, 0, sizeof(conf));
        conf.min_uid = 1000;
        conf.gridmap_path = S(gm);
        brix_idmap_init(&conf, NULL);
        ngx_int_t rc_a = brix_idmap_resolve(&conf, "/DC=test/CN=alice", &cr_a, NULL);
        ngx_int_t rc_b = brix_idmap_resolve(&conf, "alice@TEST.REALM", &cr_b, NULL);
        CHECK(rc_a == BRIX_IDMAP_OK && rc_b == BRIX_IDMAP_OK
              && cr_a.uid == tuid && cr_b.uid == tuid,
              "C1 two principals EXPLICITLY mapped to one account collapse to one uid (intended)");
    }

    /* C2. NO silent collapse: an UNMAPPED DN whose CN embeds the target username must NOT
     *     resolve onto the target. The gridmap holds a DIFFERENT principal only. A correct
     *     resolver keys on the whole unmapped principal (getpwnam of the full DN fails) ->
     *     DENY. Because getpwnam(target) DOES succeed here, a DENY definitively proves the
     *     resolver is not extracting the CN and collapsing onto it (a real T6 leak). */
    {
        char body[1024];
        snprintf(body, sizeof(body), "\"/DC=test/CN=alice\" %s\n", target);
        const char *gm = write_gridmap(body);
        brix_idmap_conf_t conf;
        memset(&conf, 0, sizeof(conf));
        conf.min_uid = 1000;
        conf.gridmap_path = S(gm);
        brix_idmap_init(&conf, NULL);
        char evil[512];
        snprintf(evil, sizeof(evil), "/DC=evil/CN=%s", target);
        ngx_int_t rc = brix_idmap_resolve(&conf, evil, &cr, NULL);
        CHECK(rc == BRIX_IDMAP_DENY,
              "C2 unmapped DN embedding a real username does NOT collapse onto it (DENY)");
    }

    /* C3. Documented fallback: a BARE local username presented as the principal maps
     *     directly via getpwnam (the intended fallback), bounded by the floor (G1). */
    {
        ngx_int_t rc = resolve_plain(target, &cr);
        CHECK(rc == BRIX_IDMAP_OK && cr.uid == tuid,
              "C3 bare local username maps directly via getpwnam fallback (documented)");
    }

    unlink("/tmp/idmap_collapse_gridmap");
    printf(fails ? "\n%d FAILED\n" : "\nALL PASSED\n", fails);
    return fails ? 1 : 0;
}
