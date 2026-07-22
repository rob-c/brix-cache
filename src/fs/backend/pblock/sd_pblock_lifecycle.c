/*
 * sd_pblock_lifecycle.c — the pblock storage-driver instance lifecycle: the
 * root-privilege backstop, the phase-83 lab/feature arming helpers, and the
 * driver init/cleanup slots.
 *
 * WHAT: Owns sd_pblock_init / sd_pblock_cleanup (the .init/.cleanup vtable slots
 *       named in the descriptor in sd_pblock.c) plus their private helpers —
 *       brix_pblock_drop_privilege and the pblock_arm_* feature-arming routines.
 *
 * WHY:  Split from sd_pblock.c (phase-79/guard burndown) to hold every pblock
 *       file under the one-concept size cap; the instance lifecycle is the most
 *       self-contained slice of the former driver core. The object open/close
 *       lifecycle lives in sd_pblock_open.c, the descriptor + the space/nearline
 *       slots stay in sd_pblock.c.
 *
 * HOW:  Same ngx-free (libc + sqlite, malloc-owned state) contract as the rest of
 *       the driver, compiled only when the build found libsqlite3
 *       (BRIX_HAVE_SQLITE) so a no-sqlite build stays empty.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* preadv2(2) (the module build sets it) */
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"        /* packed-block storage engine (split out) */
#include "sd_pblock_internal.h"  /* shared obj state + split-out vtable slots */
#include "pblock_ctl.h"          /* Phase-83 lab control plane (opts + ctl table) */
#include "pblock_fault.h"        /* Phase-83 fault injection + I/O shaping */
#include "pblock_csi.h"          /* Phase-83 F3 per-block CRC32c integrity */
#include "pblock_quota.h"        /* Phase-83 F5 quotas + space accounting */
#include "pblock_nearline.h"     /* Phase-83 F4 nearline/tape simulation */
#include "pblock_anomaly.h"      /* Phase-83 F9 consistency anomalies */
#include "pblock_locks.h"        /* Phase-83 F15 mandatory lease enforcement */
#include "pblock_refs.h"         /* Phase-83 F10 refcounted blobs + dedup */
#include "pblock_snap.h"         /* Phase-83 F6 snapshots / fixture reset */
#include "pblock_hist.h"         /* Phase-83 F11 versioning + trash/undelete */
#include "core/compat/wverify.h" /* F10 whole-object CRC accumulator */

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

/* ---- brix_pblock_drop_privilege ------------------------------------------
 *
 * WHAT: Guarantee the calling (worker) process is unprivileged before pblock
 *       creates any on-disk state, by permanently dropping to `want_user`
 *       (default "nobody"). Returns 0 on success or when already unprivileged,
 *       -1 (caller must fail closed) if a root worker cannot be dropped.
 *
 * WHY:  pblock writes blob files (0600), block dirs (0700) and the SQLite
 *       catalog.db as the worker's OWN uid — it has no impersonation broker and
 *       never chowns (per-principal ownership is synthetic, in the catalog only).
 *       So a worker that runs as root (an explicit `user root;`, or any config
 *       that fails to drop) would create every blob/dir/DB owned by root — a
 *       privilege-escape foothold letting a client's data land as root. This
 *       backstop makes pblock on-disk data never owned by root (or the account
 *       that launched nginx), independent of the `user` directive.
 *
 * HOW:  1. euid != 0 → already unprivileged; nothing to do (the normal case,
 *          including impersonation `map` where the worker is a service account).
 *          This also makes the function idempotent: after the first drop every
 *          later call in the worker short-circuits here.
 *       2. Resolve `want_user` (else "nobody"); refuse a uid/gid-0 target.
 *       3. setgroups({gid}) → setgid → setuid — permanent (real+eff+saved).
 *       4. Re-read getuid/geteuid; FAIL CLOSED if either is still 0.
 *       5. Warn (fires only on the one transition). Diagnostics go to stderr,
 *          which nginx redirects into the worker error_log; this file is ngx-free
 *          (shared with the standalone unit test) so it cannot call ngx_log_*.
 */
static int
brix_pblock_drop_privilege(const char *want_user)
{
    const char    *acct;
    struct passwd *pw;
    gid_t          gid;

    if (geteuid() != 0) {
        return 0;
    }

    acct = (want_user != NULL && want_user[0] != '\0') ? want_user : "nobody";
    errno = 0;
    pw = getpwnam(acct);
    if (pw == NULL) {
        fprintf(stderr, "pblock: refusing to run as root — unprivileged account "
                        "\"%s\" not found (set brix_pblock_unprivileged_user)\n",
                        acct);
        return -1;
    }
    if (pw->pw_uid == 0 || pw->pw_gid == 0) {
        fprintf(stderr, "pblock: refusing to drop to \"%s\" — it is a uid/gid 0 "
                        "account\n", acct);
        return -1;
    }

    gid = pw->pw_gid;
    if (setgroups(1, &gid) != 0 || setgid(gid) != 0 || setuid(pw->pw_uid) != 0) {
        fprintf(stderr, "pblock: FAILED to drop root to \"%s\": %s — refusing to "
                        "serve (blobs/catalog.db must never be root-owned)\n",
                        acct, strerror(errno));
        return -1;
    }
    if (getuid() == 0 || geteuid() == 0) {
        fprintf(stderr, "pblock: privilege drop to \"%s\" did not stick — "
                        "refusing to serve\n", acct);
        return -1;
    }

    fprintf(stderr, "pblock: worker was running as root; dropped to \"%s\" "
                    "(uid=%ld) so blobs and catalog.db are never root-owned — set "
                    "the nginx 'user <acct>;' directive to run the worker (and own "
                    "pblock data) as a chosen account instead\n",
                    acct, (long) pw->pw_uid);
    return 0;
}

/* ---- lab / feature arming (phase-83) -------------------------------------- */

/* Arm the lab control plane + its perf knob from the sidecar opts. With lab OFF
 * (the default — no sidecar) this is a no-op and the driver stays byte-for-byte
 * the production backend: st->lab stays NULL, the hot path never consults it. */
static void
pblock_arm_lab(brix_sd_instance_t *inst, pblock_state_t *st,
    const pblock_opts_t *opts)
{
    if (opts->mem) {                                     /* F16 */
        (void) pblock_ctl_mem_pragmas(st->cat);
    }
    if (opts->lab) {
        inst->caps = pblock_caps_apply(inst->caps, opts);    /* F2 */
        st->lab    = pblock_lab_state_create(st->cat);       /* F1/F8 */
        if (st->lab != NULL) {
            /* F9 rides the lab master gate (an anomaly simulator is a lab toy
             * by definition). Best-effort: with no `recent` table the event
             * writers no-op and consultation finds nothing. */
            (void) pblock_anomaly_init(st);
        }
    }
}

/* Arm the per-instance data features that each advertise/enable only when their
 * catalog table actually installed — an init failure for any one leaves that
 * feature off and the byte-for-byte production path intact. */
static void
pblock_arm_data_features(brix_sd_instance_t *inst, pblock_state_t *st,
    const pblock_opts_t *opts)
{
    if (opts->audit) {                                   /* F17 */
        /* Independent of the lab gate (its own opt): only turn audit on if the
         * oplog table is actually present. */
        st->audit = (pblock_audit_init(st->cat) == 0);
    }
    if (opts->csi) {                                     /* F3 */
        /* Advertise CAP_FSCS only when the csi table installed — an honest
         * per-instance capability the driver will really honour. */
        if (pblock_csi_init(st->cat) == 0) {
            st->csi     = 1;
            inst->caps |= BRIX_SD_CAP_FSCS;
        }
    }
    if (opts->nearline) {                                /* F4 */
        /* Advertise CAP_NEARLINE only when the residency table installed (the
         * residency seam and the cache tier's recall-at-fill key off it). */
        if (pblock_nearline_init(st) == 0) {
            st->nearline = 1;
            inst->caps  |= BRIX_SD_CAP_NEARLINE;
        }
    }
    if (opts->locks) {                                   /* F15 */
        /* Mandatory lease enforcement only arms when the locks table installed;
         * a failure leaves the production path (no lease reads anywhere). */
        st->locks = (pblock_locks_init(st) == 0);
    }
    if (opts->dedup) {                                   /* F10 */
        /* Refcounted blobs + dedup only arm when the blobs table installed. */
        st->refs = (pblock_refs_init(st) == 0);
    }
}

/* Arm the F12/F13 per-block transform — the one HARD config gate. A bad spec
 * (unknown transform, unreadable crypt keyfile, `zstd` without libzstd) fails
 * instance init fail-closed rather than silently serving unreadable transformed
 * bytes as raw. Returns 0 (incl. no xform requested), or -1 with errno set from
 * pblock_xform_config; the caller owns st->cat/st cleanup on -1. A transformed
 * export cannot hand out a block-0 fd, so the zero-copy caps are dropped. */
static int
pblock_arm_xform(brix_sd_instance_t *inst, pblock_state_t *st,
    const pblock_opts_t *opts)
{
    if (opts->xform_len == 0) {
        return 0;
    }
    if (pblock_xform_config(&st->xform, opts->xform, opts->xform_len) != 0) {
        return -1;                                       /* errno set by config */
    }
    if (pblock_xform_active(&st->xform)) {
        inst->caps &= ~(uint32_t) (BRIX_SD_CAP_SENDFILE | BRIX_SD_CAP_IOURING);
    }
    return 0;
}

/* Arm the retention/accounting features. Snapshots (F6) and versioning/trash
 * (F11) both HOLD prior blobs, so they build ON refcounted blobs (F10): arm
 * refs first (idempotent), then the history tables — armed only when both
 * installed, else the byte-for-byte production path is untouched. */
static void
pblock_arm_storage_features(pblock_state_t *st, const pblock_opts_t *opts)
{
    if (opts->snapshots) {                               /* F6 */
        if (!st->refs) {
            st->refs = (pblock_refs_init(st) == 0);
        }
        if (st->refs && pblock_snap_init(st) == 0) {
            st->snap = 1;
        }
    }
    if (opts->versions > 0 || opts->trash) {             /* F11 */
        if (!st->refs) {
            st->refs = (pblock_refs_init(st) == 0);
        }
        if (st->refs && pblock_hist_init(st) == 0) {
            st->versions = opts->versions;
            st->trash    = opts->trash;
        }
    }
    if (opts->quota_bytes > 0 || opts->quota_inodes > 0) {  /* F5 */
        /* Its own opt: quota only arms when the rollup table + triggers actually
         * installed, so an init failure leaves the production catalog path. */
        if (pblock_quota_init(st) == 0) {
            st->quota        = 1;
            st->quota_bytes  = opts->quota_bytes;
            st->quota_inodes = opts->quota_inodes;
        }
    }
}

/* ---- instance lifecycle --------------------------------------------------- */

ngx_int_t
sd_pblock_init(brix_sd_instance_t *inst, void *driver_conf)
{
    const brix_sd_pblock_conf_t *conf = driver_conf;
    pblock_state_t                *st;
    char                           db[PATH_MAX];

    if (conf == NULL || conf->root == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    /* Never create pblock on-disk state (dirs/blobs/catalog.db) as root: a
     * worker-time production build sets enforce_unprivileged, which drops a root
     * worker to an unprivileged account here — BEFORE the pblock_mkdir_p below.
     * Fail closed if the drop is impossible. */
    if (conf->enforce_unprivileged
        && brix_pblock_drop_privilege(conf->unpriv_user) != 0)
    {
        errno = EPERM;
        return NGX_ERROR;
    }

    st = calloc(1, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    snprintf(st->root, sizeof(st->root), "%s", conf->root);
    snprintf(st->data_dir, sizeof(st->data_dir), "%s/data", conf->root);
    st->block_size = conf->block_size > 0 ? conf->block_size
                                          : PBLOCK_DEFAULT_BLOCK_SIZE;

    if (pblock_mkdir_p(st->root) != 0 || pblock_mkdir_p(st->data_dir) != 0) {
        int err = errno;

        free(st);
        errno = err;
        return NGX_ERROR;
    }

    snprintf(db, sizeof(db), "%s/catalog.db", conf->root);
    st->cat = pblock_catalog_open(db, conf->busy_timeout_ms);
    if (st->cat == NULL) {
        int err = errno;

        free(st);
        errno = err;
        return NGX_ERROR;
    }

    /* Phase-83 lab control plane. The static opts sidecar (<root>/pblock.opts,
     * written by the config finaliser when it strips a `?tail` off a pblock://
     * root) selects the fail-closed master gate and the caps/mem knobs. With
     * lab OFF (the default — no sidecar) the driver stays byte-for-byte the
     * production backend: st->lab is NULL and the hot path never consults it. */
    {
        pblock_opts_t opts;

        (void) pblock_opts_load_sidecar(st->root, &opts);   /* absent ⇒ all-zero */

        pblock_arm_lab(inst, st, &opts);
        pblock_arm_data_features(inst, st, &opts);

        /* F12/F13 transform is the one hard config gate — fail instance init
         * fail-closed on a bad spec (the store is never built for the export,
         * logged "backend init failed") rather than serving garbage as raw. */
        if (pblock_arm_xform(inst, st, &opts) != 0) {
            int err = errno;

            pblock_catalog_close(st->cat);
            free(st);
            errno = err;
            return NGX_ERROR;
        }

        pblock_arm_storage_features(st, &opts);
    }

    /* The export root "/" always exists (a directory), like a POSIX mount point —
     * so stat("/")/opendir("/")/PROPFIND on the root succeed before anything is
     * written. Created once; harmless if a concurrent worker also creates it.
     * Sticky world-writable (/tmp semantics) so identity-enforced multi-user
     * exports work out of the box: anyone may create top-level entries, only
     * owners may remove them (pblock_ident_sticky_gate). Operators wanting a
     * stricter top level chmod "/" or pre-create VO directories. */
    if (pblock_catalog_lookup(st->cat, "/", NULL) == 1) {
        pblock_meta root_meta;

        memset(&root_meta, 0, sizeof(root_meta));
        root_meta.is_dir = 1;
        root_meta.mtime  = root_meta.ctime = pblock_now();
        root_meta.mode   = S_IFDIR | S_ISVTX | 0777;
        (void) pblock_catalog_put(st->cat, "/", &root_meta);
    }

    inst->state = st;
    return NGX_OK;
}

void
sd_pblock_cleanup(brix_sd_instance_t *inst)
{
    pblock_state_t *st = inst->state;

    if (st != NULL) {
        pblock_lab_state_destroy(st->lab);
        pblock_catalog_close(st->cat);
        free(st);
        inst->state = NULL;
    }
}

#endif /* BRIX_HAVE_SQLITE */
