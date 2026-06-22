/* Standalone unit test for src/impersonate/idmap.c (phase 40).
 * Links idmap.o; stubs the single nginx runtime symbol (ngx_log_error_core).
 * Exercises grid-mapfile + getpwnam + policy + squash against the real NSS. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "../../src/impersonate/impersonate.h"
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* --- minimal nginx runtime stub --- */
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
                        const char *fmt, ...) { (void)level;(void)log;(void)err;(void)fmt; }

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  PASS %s\n", msg); } \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

static ngx_str_t S(const char *s){ ngx_str_t v; v.data=(u_char*)s; v.len=s?strlen(s):0; return v; }

int main(void)
{
    struct passwd *me = getpwuid(getuid());
    if (!me) { printf("SKIP: getpwuid(self) failed\n"); return 0; }
    char myname[256]; strncpy(myname, me->pw_name, sizeof(myname)-1);
    uid_t myuid = me->pw_uid; gid_t mygid = me->pw_gid;
    printf("self user=%s uid=%d gid=%d\n", myname, (int)myuid, (int)mygid);
    if (myuid < 1000) { printf("SKIP: self uid < 1000 (need a normal user)\n"); return 0; }

    xrootd_idmap_conf_t conf; xrootd_idmap_creds_t cr; ngx_int_t rc;

    /* 1. direct getpwnam of self -> OK, uid matches */
    memset(&conf,0,sizeof(conf)); conf.min_uid = 1000;
    xrootd_idmap_init(&conf, NULL);
    rc = xrootd_idmap_resolve(&conf, myname, &cr, NULL);
    CHECK(rc==XROOTD_IDMAP_OK && cr.uid==myuid && cr.gid==mygid, "direct getpwnam(self) -> OK with right uid/gid");
    CHECK(cr.ngroups>=1, "self has >=1 supplementary group");

    /* 2. unknown principal -> DENY */
    rc = xrootd_idmap_resolve(&conf, "no_such_user_zzz_42", &cr, NULL);
    CHECK(rc==XROOTD_IDMAP_DENY, "unknown principal -> DENY");

    /* 3. root -> DENY (uid 0 reserved) */
    rc = xrootd_idmap_resolve(&conf, "root", &cr, NULL);
    CHECK(rc==XROOTD_IDMAP_DENY, "root (uid 0) -> DENY (reserved)");

    /* 4. min_uid floor above self -> DENY */
    memset(&conf,0,sizeof(conf)); conf.min_uid = myuid + 1;
    xrootd_idmap_init(&conf, NULL);
    rc = xrootd_idmap_resolve(&conf, myname, &cr, NULL);
    CHECK(rc==XROOTD_IDMAP_DENY, "min_uid above self -> DENY (floor)");

    /* 5. grid-mapfile: DN -> self */
    {
        FILE *f = fopen("/tmp/idmap_test_gridmap","w");
        fprintf(f, "# test mapfile\n\"/DC=org/CN=Test User\" %s\n", myname);
        fclose(f);
        memset(&conf,0,sizeof(conf)); conf.min_uid = 1000;
        conf.gridmap_path = S("/tmp/idmap_test_gridmap");
        xrootd_idmap_init(&conf, NULL);
        rc = xrootd_idmap_resolve(&conf, "/DC=org/CN=Test User", &cr, NULL);
        CHECK(rc==XROOTD_IDMAP_OK && cr.uid==myuid, "grid-mapfile DN -> self uid");
        rc = xrootd_idmap_resolve(&conf, "/DC=org/CN=Unmapped", &cr, NULL);
        CHECK(rc==XROOTD_IDMAP_DENY, "DN not in mapfile + not a user -> DENY");
        unlink("/tmp/idmap_test_gridmap");
    }

    /* 6. squash: default_user=self, unknown principal -> SQUASH to self */
    memset(&conf,0,sizeof(conf)); conf.min_uid = 1000;
    conf.default_user = S(myname);
    xrootd_idmap_init(&conf, NULL);
    rc = xrootd_idmap_resolve(&conf, "no_such_user_zzz_42", &cr, NULL);
    CHECK(rc==XROOTD_IDMAP_SQUASH && cr.uid==myuid, "unknown + default_user -> SQUASH to default uid");

    /* 7. cache: repeat resolve is stable */
    rc = xrootd_idmap_resolve(&conf, "no_such_user_zzz_42", &cr, NULL);
    CHECK(rc==XROOTD_IDMAP_SQUASH && cr.uid==myuid, "repeat (cached) -> same verdict");

    /* 8. primary_only */
    memset(&conf,0,sizeof(conf)); conf.min_uid=1000; conf.primary_only=1;
    xrootd_idmap_init(&conf, NULL);
    rc = xrootd_idmap_resolve(&conf, myname, &cr, NULL);
    CHECK(rc==XROOTD_IDMAP_OK && cr.ngroups==1 && cr.groups[0]==mygid, "primary_only -> ngroups==1 (primary gid)");

    printf(fails? "\n%d FAILED\n" : "\nALL PASSED\n", fails);
    return fails ? 1 : 0;
}
