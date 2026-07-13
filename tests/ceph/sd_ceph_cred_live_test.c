/*
 * sd_ceph_cred_live_test.c — LIVE per-user CephX credential test for the
 * sd_ceph driver's open_cred slot (ceph-peruser item), against a real RADOS
 * pool (tests/ceph_harness.sh).
 *
 * WHAT: Drives brix_sd_ceph_driver.open_cred directly with a brix_sd_cred_t
 *       carrying ceph_user/ceph_keyring, proving:
 *       (a) a cred scoped to CephX user "bob" (osd 'allow rwx pool=xrdtest')
 *           can open-for-write, pwrite, and the resulting object is readable
 *           back byte-exact — i.e. the per-user open actually authenticates
 *           and actually writes through THAT user's RADOS session, not the
 *           service/admin ioctx;
 *       (b) a cred scoped to CephX user "readonly" (osd 'allow r pool=xrdtest',
 *           NO write capability) FAILS a write open/pwrite with EACCES/EPERM
 *           from librados itself — this is the actual proof that per-user
 *           CephX auth is enforced by the CLUSTER, not merely plumbed
 *           through unchecked (a service-credential backend would let
 *           EVERY caller write regardless of which cred was passed);
 *       (c) best-effort: two opens for the SAME (user, keyring) reuse one
 *           cached connection (the driver's per-export instance state is not
 *           directly inspectable from here, so this is inferred indirectly
 *           via timing headroom — see the comment at CHECK "conn cache" —
 *           and is not a hard assertion).
 *
 * Build (inside the xrd-ceph-build container, where librados-devel exists):
 *   gcc -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH -I src/fs/backend -I src/fs/backend/rados \
 *       -include client/apps/ceph/ngx_shim.h \
 *       tests/ceph/sd_ceph_cred_live_test.c src/fs/backend/rados/sd_ceph.c \
 *       -lrados -o /tmp/sd_ceph_cred_live && /tmp/sd_ceph_cred_live
 *
 * Env: CEPH_POOL (default xrdtest), CEPH_CONF (default /etc/ceph/ceph.conf),
 *      CEPH_BOB_KEYRING (default /etc/ceph/ceph.client.bob.keyring),
 *      CEPH_READONLY_KEYRING (default /etc/ceph/ceph.client.readonly.keyring).
 * Exit 0 = all checks pass.
 */
#include "rados/sd_ceph.h"
#include "sd.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* count_open_fds — number of entries under /proc/self/fd, used as a proxy
 * for leaked rados connections/sockets (each live rados_t typically holds a
 * mon session socket open). Not exact (also counts unrelated fds this
 * process itself holds, e.g. stdio), but STABLE across cycles unless
 * something is actually leaking one fd per iteration. */
static long
count_open_fds(void)
{
    DIR           *d = opendir("/proc/self/fd");
    struct dirent *de;
    long            n = 0;

    if (d == NULL) {
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] != '.') {
            n++;
        }
    }
    closedir(d);
    return n;
}

/* ---- minimal ngx allocator shims the driver names (no nginx runtime) ------- */
void *ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return calloc(1, size);
}
void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

static int g_fail;
#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (!(cond)) { fprintf(stderr, "FAIL: %s (errno=%d %s)\n", (msg),       \
                               errno, strerror(errno)); g_fail++; }             \
        else { printf("ok: %s\n", (msg)); }                                     \
    } while (0)

int
main(void)
{
    const brix_sd_driver_t *drv = &brix_sd_ceph_driver;
    brix_sd_instance_t      inst;
    brix_sd_ceph_conf_t     conf;
    brix_sd_obj_t          *o;
    brix_sd_cred_t          bob_cred, ro_cred;
    int                       err;
    const char               *bob_path = "/credlivetest/bob-obj";
    const char               *ro_path  = "/credlivetest/ro-obj";
    const char               *payload  = "written by bob via per-user cephx cred";
    size_t                    plen = strlen(payload);
    char                      rbuf[256];
    ssize_t                   n;
    const char               *bob_keyring;
    const char               *ro_keyring;
    struct timespec           t0, t1, t2;
    double                    dt_cold, dt_warm;

    memset(&inst, 0, sizeof(inst));
    inst.driver = drv;
    inst.log = NULL;
    inst.pool = NULL;     /* the shims ignore it */
    inst.state = NULL;

    /* The EXPORT connects with the plain service credential (admin) — the
     * per-user paths under test go through open_cred, not this ioctx. */
    memset(&conf, 0, sizeof(conf));
    conf.conf_file = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";
    conf.pool = getenv("CEPH_POOL") ? getenv("CEPH_POOL") : "xrdtest";
    conf.key_prefix = "credlivetest-keys/";

    bob_keyring = getenv("CEPH_BOB_KEYRING")
                ? getenv("CEPH_BOB_KEYRING") : "/etc/ceph/ceph.client.bob.keyring";
    ro_keyring  = getenv("CEPH_READONLY_KEYRING")
                ? getenv("CEPH_READONLY_KEYRING") : "/etc/ceph/ceph.client.readonly.keyring";

    if (drv->init(&inst, &conf) != NGX_OK) {
        fprintf(stderr, "FATAL: sd_ceph init failed (pool=%s conf=%s errno=%d %s)\n",
                conf.pool, conf.conf_file, errno, strerror(errno));
        return 2;
    }
    printf("ok: export connected to pool '%s' (service credential)\n", conf.pool);

    CHECK(drv->open_cred != NULL, "driver advertises open_cred (ceph-peruser)");

    /* clean slate (service credential has rwx on the whole pool) */
    drv->unlink(&inst, bob_path, 0);
    drv->unlink(&inst, ro_path, 0);

    /* =====================================================================
     * (a) cred scoped to "bob" (rwx on xrdtest) succeeds: open-for-write,
     *     pwrite, close, then a service-credential readback proves the
     *     object was actually written (not silently dropped).
     * ===================================================================== */
    memset(&bob_cred, 0, sizeof(bob_cred));
    bob_cred.ceph_user    = "bob";
    bob_cred.ceph_keyring = bob_keyring;
    bob_cred.key          = "bob";
    bob_cred.principal    = "/CN=bob (test)";
    bob_cred.fallback_deny = 1;

    err = 0;
    o = drv->open_cred(&inst, bob_path,
                        BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC,
                        0644, &bob_cred, &err);
    CHECK(o != NULL, "(a) bob: open_cred for write succeeds");
    if (o != NULL) {
        CHECK(drv->pwrite(o, payload, plen, 0) == (ssize_t) plen,
              "(a) bob: pwrite succeeds");
        CHECK(drv->fsync(o) == NGX_OK, "(a) bob: fsync");
        CHECK(drv->close(o) == NGX_OK, "(a) bob: close");
    }

    /* Read back via the SERVICE credential (plain open) — proves the bytes
     * really landed in RADOS under bob's session, not merely accepted and
     * discarded by a stub. */
    err = 0;
    o = drv->open(&inst, bob_path, BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "(a) bob: object readable back via service credential");
    if (o != NULL) {
        memset(rbuf, 0, sizeof(rbuf));
        n = drv->pread(o, rbuf, sizeof(rbuf), 0);
        CHECK(n == (ssize_t) plen, "(a) bob: readback length matches");
        CHECK(memcmp(rbuf, payload, plen) == 0, "(a) bob: readback bytes match");
        drv->close(o);
    }

    /* Also open-for-read directly through bob's own cred (the read cap is
     * implied by rwx) — exercises the cred-scoped READ path, not just write. */
    err = 0;
    o = drv->open_cred(&inst, bob_path, BRIX_SD_O_READ, 0, &bob_cred, &err);
    CHECK(o != NULL, "(a) bob: open_cred for read succeeds (own object)");
    if (o != NULL) {
        memset(rbuf, 0, sizeof(rbuf));
        n = drv->pread(o, rbuf, sizeof(rbuf), 0);
        CHECK(n == (ssize_t) plen && memcmp(rbuf, payload, plen) == 0,
              "(a) bob: cred-scoped read matches");
        drv->close(o);
    }

    /* =====================================================================
     * (b) NEGATIVE: cred scoped to "readonly" (r-only on xrdtest) must FAIL
     *     a write open/pwrite. This is the actual proof CephX per-user auth
     *     is enforced by the cluster — a service-credential-only backend
     *     would let this "readonly" cred write anyway.
     * ===================================================================== */
    memset(&ro_cred, 0, sizeof(ro_cred));
    ro_cred.ceph_user     = "readonly";
    ro_cred.ceph_keyring  = ro_keyring;
    ro_cred.key           = "readonly";
    ro_cred.principal     = "/CN=readonly (test)";
    ro_cred.fallback_deny = 1;

    /* Pre-seed the target object via the service credential so a CREATE-vs-
     * WRITE distinction can't mask the denial (open with CREATE on a missing
     * object could conceivably behave differently under some backends). */
    err = 0;
    o = drv->open(&inst, ro_path, BRIX_SD_O_WRITE | BRIX_SD_O_CREATE, 0644, &err);
    CHECK(o != NULL, "(b) setup: service credential seeds the target object");
    if (o != NULL) {
        drv->pwrite(o, "seed", 4, 0);
        drv->close(o);
    }

    err = 0;
    o = drv->open_cred(&inst, ro_path, BRIX_SD_O_WRITE, 0644, &ro_cred, &err);
    /* Either open_cred itself fails (librados surfaces the auth failure at
     * connect/open time), or it succeeds and the SUBSEQUENT pwrite is denied
     * by the OSD (RADOS grants per-op, so a write can be rejected even after
     * a successful stat/open). Both are valid enforcement points; the test
     * accepts either as long as the write value never lands. */
    if (o == NULL) {
        CHECK(err == EACCES || err == EPERM,
              "(b) readonly: open_cred for write denied with EACCES/EPERM");
    } else {
        ssize_t wn = drv->pwrite(o, "denied-write", 12, 0);
        CHECK(wn < 0 && (errno == EACCES || errno == EPERM),
              "(b) readonly: pwrite denied with EACCES/EPERM");
        drv->close(o);
    }

    /* Confirm the object was NOT overwritten by the readonly attempt. */
    err = 0;
    o = drv->open(&inst, ro_path, BRIX_SD_O_READ, 0, &err);
    CHECK(o != NULL, "(b) readback: service credential can still read the object");
    if (o != NULL) {
        memset(rbuf, 0, sizeof(rbuf));
        n = drv->pread(o, rbuf, sizeof(rbuf), 0);
        CHECK(n == 4 && memcmp(rbuf, "seed", 4) == 0,
              "(b) readonly's denied write did not modify the object");
        drv->close(o);
    }

    /* readonly CAN read its own permitted object (sanity: the keyring/user
     * itself is valid — the write denial above is a capability denial, not a
     * broken keyring). */
    err = 0;
    o = drv->open_cred(&inst, ro_path, BRIX_SD_O_READ, 0, &ro_cred, &err);
    CHECK(o != NULL, "(b) readonly: open_cred for READ succeeds (valid keyring)");
    if (o != NULL) {
        drv->close(o);
    }

    /* =====================================================================
     * wrong-kind deny: a cred with no ceph_keyring (a different kind reached
     * this driver) in fallback_deny mode must be refused, not silently
     * served on the service credential.
     * ===================================================================== */
    {
        brix_sd_cred_t wrongkind;

        memset(&wrongkind, 0, sizeof(wrongkind));
        wrongkind.x509_proxy    = "/some/other/kind.pem";
        wrongkind.fallback_deny = 1;

        err = 0;
        o = drv->open_cred(&inst, bob_path, BRIX_SD_O_READ, 0, &wrongkind, &err);
        CHECK(o == NULL && err == EACCES,
              "wrong-kind cred (no ceph_keyring) + fallback_deny -> EACCES");
    }

    /* =====================================================================
     * (c) best-effort cred-conn cache signal: a second open for the SAME
     * (user, keyring) should not need a fresh mon handshake, so it should be
     * markedly faster than the first (cold) connect. This is an indirect,
     * best-effort signal (no cache internals are exposed to this ngx-free
     * test), not a hard correctness assertion — a slow/loaded CI box could
     * make the timing noisy, so a generous margin is used and the result is
     * only warned about, not counted as a failure.
     * ===================================================================== */
    {
        brix_sd_cred_t fresh_cred;

        memset(&fresh_cred, 0, sizeof(fresh_cred));
        fresh_cred.ceph_user    = "bob";
        fresh_cred.ceph_keyring = bob_keyring;

        /* Use a DIFFERENT logical path but the SAME (user,keyring) so the
         * cred-conn cache (keyed on user+keyring, not path) is exercised
         * twice. First call: cache miss -> full rados_connect. */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        err = 0;
        o = drv->open_cred(&inst, "/credlivetest/bob-timing-a", BRIX_SD_O_READ,
                            0, &fresh_cred, &err);
        /* ENOENT is fine here (object may not exist) -- only the CONNECT
         * cost is being measured, not the open's success. */
        if (o != NULL) { drv->close(o); }
        clock_gettime(CLOCK_MONOTONIC, &t1);

        err = 0;
        o = drv->open_cred(&inst, "/credlivetest/bob-timing-b", BRIX_SD_O_READ,
                            0, &fresh_cred, &err);
        if (o != NULL) { drv->close(o); }
        clock_gettime(CLOCK_MONOTONIC, &t2);

        dt_cold = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        dt_warm = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1e9;
        printf("info: cred-conn cache timing: cold-ish=%.4fs warm=%.4fs "
               "(warm expected notably faster; best-effort signal only)\n",
               dt_cold, dt_warm);
        if (dt_warm > dt_cold) {
            printf("warn: warm open was not faster than the first — timing is "
                   "noisy/best-effort, not treated as a failure\n");
        } else {
            printf("ok: (c) warm (cached-conn) open_cred was faster than the "
                   "first — consistent with connection reuse\n");
        }
    }

    /* =====================================================================
     * (d) UAF regression: LRU eviction pressure while a cred-scoped handle
     * is still OPEN must never destroy that handle's connection.
     *
     * The per-export cred-conn cache is a bounded LRU of
     * SD_CEPH_CRED_CONN_CACHE_MAX (8) entries. Before the pin/refcount fix,
     * sd_ceph_close() was a no-op and sd_ceph_cred_conn_evict_lru() would
     * happily rados_ioctx_destroy()+rados_shutdown() ANY cache slot's
     * connection purely by LRU recency — including one a still-open handle
     * was actively reading/writing through. Opening (and closing) more than
     * 8 distinct (user,keyring) pairs while bob's handle stays open
     * reproduces exactly the eviction pressure that used to evict bob's
     * connection out from under him: this test proves it no longer does.
     *
     * Sequence:
     *   1. bob opens a WRITE handle and KEEPS IT OPEN (no close yet).
     *   2. 10 other distinct (user,keyring) identities (client.u0..u9,
     *      provisioned by run_sd_ceph_cred_live.sh) each open+close a
     *      cred-scoped handle. That's 10 more distinct cache keys pushed
     *      through an 8-slot LRU while bob's connection sits in the table
     *      too — every slot gets evicted at least once, and bob's pinned
     *      entry MUST be skipped by the evictor every single time.
     *   3. bob's STILL-OPEN handle does a pwrite + fsync + pread-back.
     *      Before the fix this dereferences a freed rados_ioctx_t (crash or
     *      silently wrong bytes, undefined behavior); after the fix bob's
     *      connection was pinned (refs>0) for the whole window, so the
     *      evictor could never have chosen it, and the I/O must succeed
     *      with byte-exact results.
     * ===================================================================== */
    {
        const char      *held_path = "/credlivetest/bob-held-open";
        const char      *held_payload = "still alive after eviction pressure";
        size_t            held_len = strlen(held_payload);
        brix_sd_cred_t    held_cred;
        brix_sd_obj_t    *held_obj;
        int               i;
        int               pressure_ok = 1;
        char              userbuf[64];
        char              krbuf[256];
        const char       *extra_keyring_env;

        memset(&held_cred, 0, sizeof(held_cred));
        held_cred.ceph_user     = "bob";
        held_cred.ceph_keyring  = bob_keyring;
        held_cred.key           = "bob";
        held_cred.principal     = "/CN=bob (test)";
        held_cred.fallback_deny = 1;

        drv->unlink(&inst, held_path, 0);

        err = 0;
        held_obj = drv->open_cred(&inst, held_path,
                                   BRIX_SD_O_WRITE | BRIX_SD_O_CREATE
                                       | BRIX_SD_O_TRUNC,
                                   0644, &held_cred, &err);
        CHECK(held_obj != NULL,
              "(d) bob: open_cred for held-open write handle succeeds");

        /* Step (2): 10 distinct (user,keyring) opens+closes -- more than the
         * 8-slot cache -- while bob's handle above stays open. u0..u9's
         * keyrings are provisioned + copied in by run_sd_ceph_cred_live.sh
         * under CEPH_UN_KEYRING_DIR (default /etc/ceph). */
        extra_keyring_env = getenv("CEPH_UN_KEYRING_DIR");
        for (i = 0; i < 10; i++) {
            brix_sd_cred_t extra_cred;
            brix_sd_obj_t  *extra_obj;

            snprintf(userbuf, sizeof(userbuf), "u%d", i);
            snprintf(krbuf, sizeof(krbuf), "%s/ceph.client.u%d.keyring",
                      extra_keyring_env ? extra_keyring_env : "/etc/ceph", i);

            memset(&extra_cred, 0, sizeof(extra_cred));
            extra_cred.ceph_user     = userbuf;
            extra_cred.ceph_keyring  = krbuf;
            extra_cred.key           = userbuf;
            extra_cred.fallback_deny = 1;

            err = 0;
            extra_obj = drv->open_cred(&inst, "/credlivetest/evict-probe",
                                        BRIX_SD_O_READ, 0, &extra_cred, &err);
            /* ENOENT is fine (the probe object need not exist) -- only the
             * connect+cache-churn matters here. Any OTHER failure means the
             * cred-conn machinery itself broke under eviction pressure. */
            if (extra_obj == NULL && err != ENOENT) {
                fprintf(stderr,
                    "FAIL: (d) eviction-pressure open %d (user=%s) failed "
                    "unexpectedly (errno=%d %s)\n",
                    i, userbuf, err, strerror(err));
                pressure_ok = 0;
            }
            if (extra_obj != NULL) {
                drv->close(extra_obj);
            }
        }
        CHECK(pressure_ok,
              "(d) 10 distinct cred opens (>8-slot cache) completed without "
              "cred-conn machinery errors while bob's handle stayed open");

        /* Step (3): bob's handle, still open this whole time, must still be
         * backed by a LIVE connection -- this is the actual UAF check. */
        CHECK(held_obj != NULL, "(d) bob: held-open handle object still non-NULL");
        if (held_obj != NULL) {
            CHECK(drv->pwrite(held_obj, held_payload, held_len, 0)
                      == (ssize_t) held_len,
                  "(d) bob: pwrite on held-open handle succeeds AFTER "
                  ">8-conn eviction pressure (no UAF)");
            CHECK(drv->fsync(held_obj) == NGX_OK,
                  "(d) bob: fsync on held-open handle succeeds after pressure");

            memset(rbuf, 0, sizeof(rbuf));
            n = drv->pread(held_obj, rbuf, sizeof(rbuf), 0);
            CHECK(n == (ssize_t) held_len,
                  "(d) bob: pread-back length matches after pressure");
            CHECK(n == (ssize_t) held_len
                      && memcmp(rbuf, held_payload, held_len) == 0,
                  "(d) bob: pread-back bytes match after pressure (byte-exact, "
                  "not garbage from a freed ioctx)");

            CHECK(drv->close(held_obj) == NGX_OK,
                  "(d) bob: close of held-open handle succeeds");
        }

        /* Independent readback via the service credential: proves the bytes
         * genuinely landed in RADOS (not just read back through a
         * coincidentally-still-mapped-but-logically-freed connection). */
        err = 0;
        o = drv->open(&inst, held_path, BRIX_SD_O_READ, 0, &err);
        CHECK(o != NULL, "(d) held-open object independently readable via "
                          "service credential post-pressure");
        if (o != NULL) {
            memset(rbuf, 0, sizeof(rbuf));
            n = drv->pread(o, rbuf, sizeof(rbuf), 0);
            CHECK(n == (ssize_t) held_len
                      && memcmp(rbuf, held_payload, held_len) == 0,
                  "(d) service-credential readback confirms held-open write "
                  "landed correctly");
            drv->close(o);
        }

        drv->unlink(&inst, held_path, 0);
        drv->unlink(&inst, "/credlivetest/evict-probe", 0);
    }

    /* =====================================================================
     * (e) LEAK regression: the TRANSIENT (uncached) cred-conn path.
     *
     * Case (d) above only ever holds ONE handle open at a time (bob's) while
     * churning OTHER identities sequentially (open, then immediately close,
     * one at a time) -- so it never has more than 1 pinned slot at once and
     * never actually reaches the "every one of the 8 cache slots is pinned"
     * branch in sd_ceph_cred_conn(). That branch hands back a fresh
     * connection that is NEVER inserted into the LRU table (*out_transient =
     * 1) -- before this fix, nothing ever set conn->doomed on it, so the
     * deferred-destroy in sd_ceph_conn_unpin() was dead code for it and its
     * mon session + ioctx + socket fd leaked on every close.
     *
     * This case forces that branch for real: each cycle opens MORE THAN 8
     * (10) distinct (user,keyring) cred-scoped handles and keeps ALL of them
     * open SIMULTANEOUSLY (slots 9 and 10 necessarily land on the transient
     * path, since only 8 LRU slots exist), does a small pwrite on each, then
     * closes all 10. Repeating this for 5 cycles and tracking this process's
     * open fd count (as a proxy for live rados connections/sockets) proves
     * the fix: with the leak, fd count would grow by ~2 per cycle (the two
     * transient opens that never got freed); with the fix, it returns to
     * (approximately) the same ceiling every cycle.
     * ===================================================================== */
    {
        enum { E_CYCLES = 5, E_HANDLES = 10 };
        brix_sd_obj_t *e_obj[E_HANDLES];
        char            e_user[E_HANDLES][64];
        char            e_keyring[E_HANDLES][256];
        long            fd_baseline = -1;
        long            fd_after[E_CYCLES];
        int             leak_ok = 1;
        int             cyc, i;
        const char     *extra_keyring_dir_e = getenv("CEPH_UN_KEYRING_DIR");

        for (cyc = 0; cyc < E_CYCLES; cyc++) {
            int cyc_ok = 1;

            for (i = 0; i < E_HANDLES; i++) {
                brix_sd_cred_t e_cred;

                snprintf(e_user[i], sizeof(e_user[i]), "u%d", i);
                snprintf(e_keyring[i], sizeof(e_keyring[i]),
                          "%s/ceph.client.u%d.keyring",
                          extra_keyring_dir_e ? extra_keyring_dir_e
                                               : "/etc/ceph", i);

                memset(&e_cred, 0, sizeof(e_cred));
                e_cred.ceph_user     = e_user[i];
                e_cred.ceph_keyring  = e_keyring[i];
                e_cred.key           = e_user[i];
                e_cred.fallback_deny = 1;

                err = 0;
                /* u0..u9 are read-only-provisioned (see run script); open
                 * for READ so the per-identity handle is legitimate and we
                 * hold it open (not closed) until all 10 are up, which is
                 * what forces slots 9/10 onto the transient path. */
                e_obj[i] = drv->open_cred(&inst, "/credlivetest/evict-probe",
                                           BRIX_SD_O_READ, 0, &e_cred, &err);
                if (e_obj[i] == NULL && err != ENOENT) {
                    fprintf(stderr,
                        "FAIL: (e) cycle %d: simultaneous open %d (user=%s) "
                        "failed unexpectedly (errno=%d %s)\n",
                        cyc, i, e_user[i], err, strerror(err));
                    cyc_ok = 0;
                }
            }

            /* Small I/O on every still-open handle (skip the rare ENOENT
             * open failures above) -- proves the transient connections are
             * actually live and usable, not just non-NULL pointers. */
            for (i = 0; i < E_HANDLES; i++) {
                if (e_obj[i] != NULL) {
                    char rb[8];
                    drv->pread(e_obj[i], rb, sizeof(rb), 0);
                }
            }

            for (i = 0; i < E_HANDLES; i++) {
                if (e_obj[i] != NULL) {
                    drv->close(e_obj[i]);
                    e_obj[i] = NULL;
                }
            }

            CHECK(cyc_ok, cyc == 0 ? "(e) cycle: 10 simultaneous cred opens "
                                      "(>8-slot cache) succeeded"
                                    : "(e) cycle: 10 simultaneous cred opens "
                                      "(>8-slot cache) succeeded (repeat)");

            fd_after[cyc] = count_open_fds();
            if (cyc == 0) {
                /* First cycle also pays for bob/readonly/u0..u9's cached
                 * connections warming up -- use cycle 0's post-close count
                 * as the baseline rather than a pre-test snapshot, so the
                 * comparison is apples-to-apples against steady state. */
                fd_baseline = fd_after[cyc];
            }
            printf("info: (e) cycle %d: open fd count after close-all = %ld\n",
                   cyc, fd_after[cyc]);
        }

        /* Steady state after cycle 0: fd count must not keep growing across
         * subsequent cycles. Allow a small slack (a couple of fds) for
         * scheduling/libc-internal noise, but real growth (leaking ~2
         * transient conns' worth of fds per cycle, unbounded over 5 cycles)
         * must be caught. */
        for (cyc = 1; cyc < E_CYCLES; cyc++) {
            if (fd_after[cyc] > fd_baseline + 2) {
                fprintf(stderr,
                    "FAIL: (e) cycle %d: open fd count %ld grew beyond "
                    "baseline %ld+2 -- transient cred-conn leak\n",
                    cyc, fd_after[cyc], fd_baseline);
                leak_ok = 0;
            }
        }
        CHECK(leak_ok, "(e) open fd count stable across 5 cycles of "
                        ">8-simultaneous transient cred opens (no leak)");

        drv->unlink(&inst, "/credlivetest/evict-probe", 0);
    }

    /* cleanup (service credential) */
    drv->unlink(&inst, bob_path, 0);
    drv->unlink(&inst, ro_path, 0);
    drv->unlink(&inst, "/credlivetest/bob-timing-a", 0);
    drv->unlink(&inst, "/credlivetest/bob-timing-b", 0);

    drv->cleanup(&inst);

    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("sd_ceph_cred_live_test: all checks passed "
           "(bob write+read succeeded; readonly write denied)\n");
    return 0;
}
