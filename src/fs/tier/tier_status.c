/*
 * tier_status.c - report a tier's readiness against its role contract
 * (phase-64 section 2.2).  Split out of tier_config.c, which owns the other
 * half of tier.h's public surface (store-URL parsing): the two shared nothing
 * but the header, and together they crossed the 600-line file cap.
 *
 * brix_tier_status checks the built driver against the per-role slot+cap
 * contract: a missing slot/cap is a tracked "needs development" (NEEDS_DEV +
 * the closing sub-project), never a hard failure (P1).
 */
#include "tier.h"

/* The sub-project that closes a gap for (driver, role) - the §3 status matrix. */
static const char *
tier_sp_for(const char *driver, brix_tier_role_t role)
{
    (void) role;
    if (ngx_strcmp(driver, "pblock") == 0 || ngx_strcmp(driver, "xroot") == 0) {
        return "SP2";
    }
    if (ngx_strcmp(driver, "tape") == 0) {
        return "SP5";
    }
    return "SP3";   /* writable http/s3 + rados stores */
}

/* ---- public: report a tier's readiness ------------------------------------ */

brix_tier_status_t
brix_tier_status(const brix_tier_cfg_t *t, brix_sd_instance_t *probe,
    brix_tier_gap_t *gap_out)
{
    const brix_sd_driver_t *d;
    uint32_t                  caps;
    brix_tier_gap_t         g;

    ngx_memzero(&g, sizeof(g));

    if (t == NULL || probe == NULL || probe->driver == NULL) {
        ngx_cpystrn((u_char *) g.slot, (u_char *) "open", sizeof(g.slot));
        ngx_cpystrn((u_char *) g.sp_item, (u_char *) "SP1", sizeof(g.sp_item));
        if (gap_out != NULL) { *gap_out = g; }
        return BRIX_TIER_NEEDS_DEV;
    }
    d    = probe->driver;
    caps = d->caps;
    ngx_cpystrn((u_char *) g.sp_item, (u_char *) tier_sp_for(t->driver, t->role),
                sizeof(g.sp_item));

#define MISS_SLOT(field, nm)                                                   \
    do {                                                                       \
        if (d->field == NULL) {                                                \
            ngx_cpystrn((u_char *) g.slot, (u_char *) (nm), sizeof(g.slot));    \
            if (gap_out != NULL) { *gap_out = g; }                             \
            return BRIX_TIER_NEEDS_DEV;                                       \
        }                                                                      \
    } while (0)

#define MISS_CAP(bit, nm)                                                      \
    do {                                                                       \
        if ((caps & (bit)) == 0) {                                             \
            ngx_cpystrn((u_char *) g.cap, (u_char *) (nm), sizeof(g.cap));      \
            if (gap_out != NULL) { *gap_out = g; }                             \
            return BRIX_TIER_NEEDS_DEV;                                       \
        }                                                                      \
    } while (0)

    switch (t->role) {
    case BRIX_TIER_BACKEND:
        MISS_SLOT(open, "open");
        MISS_SLOT(pread, "pread");
        MISS_SLOT(stat, "stat");
        MISS_SLOT(fstat, "fstat");
        MISS_CAP(BRIX_SD_CAP_RANGE_READ, "RANGE_READ");
        if (t->nearline) {
            MISS_SLOT(recall, "recall");
            MISS_CAP(BRIX_SD_CAP_NEARLINE, "NEARLINE");
        }
        break;

    case BRIX_TIER_CACHE:
        MISS_SLOT(open, "open");
        MISS_SLOT(pread, "pread");
        MISS_SLOT(stat, "stat");
        MISS_SLOT(staged_open, "staged_open");
        MISS_SLOT(staged_write, "staged_write");
        MISS_SLOT(staged_commit, "staged_commit");
        MISS_SLOT(staged_abort, "staged_abort");
        MISS_SLOT(unlink, "unlink");
        MISS_SLOT(opendir, "opendir");
        MISS_SLOT(readdir, "readdir");
        MISS_SLOT(closedir, "closedir");
        MISS_SLOT(getxattr, "getxattr");
        MISS_SLOT(setxattr, "setxattr");
        MISS_CAP(BRIX_SD_CAP_RANGE_READ, "RANGE_READ");
        MISS_CAP(BRIX_SD_CAP_RANDOM_WRITE, "RANDOM_WRITE");
        MISS_CAP(BRIX_SD_CAP_DIRS, "DIRS");
        MISS_CAP(BRIX_SD_CAP_XATTR, "XATTR");
        break;

    case BRIX_TIER_STAGE:
        MISS_SLOT(staged_open, "staged_open");
        MISS_SLOT(staged_write, "staged_write");
        MISS_SLOT(staged_commit, "staged_commit");
        MISS_SLOT(staged_abort, "staged_abort");
        MISS_SLOT(open, "open");
        MISS_SLOT(pread, "pread");
        MISS_SLOT(unlink, "unlink");
        MISS_SLOT(getxattr, "getxattr");
        MISS_SLOT(setxattr, "setxattr");
        MISS_CAP(BRIX_SD_CAP_RANDOM_WRITE, "RANDOM_WRITE");
        MISS_CAP(BRIX_SD_CAP_XATTR, "XATTR");
        break;
    }

#undef MISS_SLOT
#undef MISS_CAP

    if (gap_out != NULL) {
        ngx_memzero(gap_out, sizeof(*gap_out));   /* READY: no gap */
    }
    return BRIX_TIER_READY;
}
