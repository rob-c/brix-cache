/*
 * sd_frm_purge.c — phase-115 W3.2: the tape-buffer purge engine.
 *
 * WHAT: One LRU pass over a tape:// tier's online buffer (<base>/.online)
 *       that releases migrated, unpinned, cold copies until the filesystem
 *       watermark and/or the owned-bytes cap are satisfied. Pure libc + the
 *       instance's MSS adapter; the nginx timer that paces it lives in
 *       core/config/process_frm_purge.c.
 *
 * WHY:  The WLCG Tape REST / kXR_prepare surface recalls into the buffer and
 *       staged writes land there before migrating, but nothing ever released
 *       a copy on its own — an operator either ran a cron over the directory
 *       or watched the buffer fill (parity audit §3.4). The cache tier's LRU
 *       reaper cannot do it: the buffer is the BACKEND's, invisible above the
 *       seam, and a cache-style unlink of an un-migrated copy loses data.
 *
 * HOW:  1. Take a non-blocking flock on <online>/.brix-purge.lock so two
 *          workers (or a worker and an operator's manual run) never race.
 *       2. nftw(FTW_PHYS|FTW_MOUNT) the online root collecting regular files
 *          (path, size, last-touch = max(atime, mtime)); symlinks are counted
 *          and never followed, the lock file is skipped.
 *       3. Compute the byte target: arm 1 = used - lo*total/1e6 when the tick
 *          saw occupancy > hi; arm 2 = owned - max_bytes; need = max of the
 *          armed arms (<= 0 => nothing to do).
 *       4. Sort by last-touch ascending and walk: skip young / pinned /
 *          on_tape != 1, else adapter->purge(key). Stop once `need` is met.
 *       5. Book brix_frm_purge_total per release + brix_vfs_evict_bytes_total
 *          {driver="frm"} once; NOTICE one summary line.
 *       2.0 F4: between 3 and 4 sd_frm_purge_policy.c tags every candidate
 *          with its brix_frm_purge_policy rule (a per-group owned-bytes arm
 *          with its own hold) and may run the operator's policy program
 *          once; the walk asks it per copy and books held/unapproved.
 *
 * Raw filesystem calls here are legitimate: this TU is UNDER src/fs/backend/
 * (invariant 12), operating on the backend's own private buffer directory.
 */

#include "sd_frm.h"
#include "sd_frm_internal.h"
#include "sd_frm_purge_internal.h"
#include "observability/metrics/metrics.h"   /* BRIX_FRM_METRIC_INC */
#include "observability/metrics/unified.h"   /* brix_metric_vfs_evict */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define FRM_PURGE_MAX_CANDIDATES 65536u
#define FRM_PURGE_NFTW_FDS       32

/* nftw() has no user-data argument; one scan runs at a time under the flock,
 * and the pointer is reset to NULL before the lock is released. */
static frm_purge_scan_t *frm_purge_active_scan;

ngx_int_t
brix_sd_frm_online_root(const brix_sd_instance_t *inst, char *buf, size_t cap)
{
    const sd_frm_state *st;
    int                 n;

    if (inst == NULL || inst->driver == NULL || inst->state == NULL
        || ngx_strcmp(inst->driver->name, "frm") != 0)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }
    st = SD_FRM_ST(inst);
    n  = snprintf(buf, cap, "%s/.online", st->location);
    if (n <= 0 || (size_t) n >= cap) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    return NGX_OK;
}

static int
frm_purge_push(frm_purge_scan_t *s, const char *rel, const struct stat *sb)
{
    frm_purge_cand_t *c;

    if (s->n >= FRM_PURGE_MAX_CANDIDATES) {
        return 0;                                  /* cap: next tick continues */
    }
    if (s->n == s->cap) {
        size_t             ncap = s->cap ? s->cap * 2 : 256;
        frm_purge_cand_t  *nv   = realloc(s->v, ncap * sizeof(*nv));

        if (nv == NULL) {
            s->oom = 1;
            return -1;
        }
        s->v   = nv;
        s->cap = ncap;
    }
    c = &s->v[s->n];
    c->rel = strdup(rel);
    if (c->rel == NULL) {
        s->oom = 1;
        return -1;
    }
    c->size     = (uint64_t) sb->st_size;
    c->touched  = (sb->st_atime > sb->st_mtime) ? sb->st_atime : sb->st_mtime;
    c->rule     = -1;
    c->approved = 0;
    s->n++;
    return 0;
}

static int
frm_purge_visit(const char *path, const struct stat *sb, int flag,
    struct FTW *ftw)
{
    frm_purge_scan_t *s = frm_purge_active_scan;
    const char       *rel;

    (void) ftw;
    if (s == NULL) {
        return -1;
    }
    if (flag == FTW_SL || flag == FTW_SLN) {
        s->symlinks++;                             /* never followed (FTW_PHYS) */
        return 0;
    }
    if (flag != FTW_F || !S_ISREG(sb->st_mode)) {
        return 0;
    }
    rel = path + s->root_len;                      /* "/<key>" */
    if (strncmp(rel, FRM_PURGE_PRIVATE_PREFIX,
                sizeof(FRM_PURGE_PRIVATE_PREFIX) - 1) == 0)
    {
        return 0;                                  /* the engine's own files */
    }
    s->owned += (uint64_t) sb->st_size;
    return frm_purge_push(s, rel, sb);
}

static int
frm_purge_cmp_lru(const void *a, const void *b)
{
    const frm_purge_cand_t *x = a, *y = b;

    if (x->touched != y->touched) {
        return (x->touched < y->touched) ? -1 : 1;
    }
    return strcmp(x->rel, y->rel);
}

static void
frm_purge_scan_free(frm_purge_scan_t *s)
{
    size_t i;

    for (i = 0; i < s->n; i++) {
        free(s->v[i].rel);
    }
    free(s->v);
    s->v = NULL;
    s->n = s->cap = 0;
}

/* Bytes the pass must release: the larger demand of the armed arms, 0 when
 * neither arm is armed or both are already satisfied. */
static uint64_t
frm_purge_need(const brix_sd_frm_purge_policy_t *pol, uint64_t owned)
{
    uint64_t need = 0;

    if (pol->hi_ppm > 0 && pol->hi_ppm < 1000000 && pol->fs_total > 0) {
        uint64_t occ_ppm = (uint64_t) ((pol->fs_used * 1000000.0) / pol->fs_total);
        uint64_t lo_bytes = (uint64_t) (pol->fs_total * (pol->lo_ppm / 1000000.0));

        if (occ_ppm > pol->hi_ppm && pol->fs_used > lo_bytes) {
            need = pol->fs_used - lo_bytes;
        }
    }
    if (pol->max_bytes > 0 && owned > (uint64_t) pol->max_bytes) {
        uint64_t cap_need = owned - (uint64_t) pol->max_bytes;

        if (cap_need > need) {
            need = cap_need;
        }
    }
    return need;
}

/* Classify + release one candidate; returns the bytes freed (0 when skipped). */
static uint64_t
frm_purge_one(sd_frm_state *st, const brix_sd_frm_purge_policy_t *pol,
    const frm_purge_cand_t *c, time_t now, brix_sd_frm_purge_report_t *rep,
    const frm_purge_policy_t *pp)
{
    int on_tape;

    if (now - c->touched < pol->min_age_s) {
        rep->young++;
        return 0;
    }
    if (now - c->touched < frm_purge_policy_hold(pol, c)) {
        rep->held++;                               /* 2.0 F4 rule hold */
        return 0;
    }
    if (pol->is_pinned != NULL && pol->is_pinned(pol->ud, c->rel)) {
        rep->pinned++;
        return 0;
    }
    /* A NULL probe means the adapter cannot tell; ONLINE copies then exist only
     * via a completed staged commit (sd_frm_staged.c migrates before publish)
     * or a recall, so the invariant ONLINE => on tape holds and we proceed. */
    on_tape = (st->mss->on_tape != NULL) ? st->mss->on_tape(st->mss_ctx, c->rel)
                                         : 1;
    if (on_tape != 1) {
        rep->unmigrated++;
        return 0;
    }
    if (!frm_purge_policy_allows(pp, pol, c)) {
        rep->unapproved++;                         /* 2.0 F4 polprog rule */
        return 0;
    }
    if (st->mss->purge == NULL || st->mss->purge(st->mss_ctx, c->rel) != 0) {
        rep->failed++;
        return 0;
    }
    rep->evicted++;
    BRIX_FRM_METRIC_INC(purge_total);
    return c->size;
}

/* LRU walk: a copy is considered while the export-wide `need` is unmet or
 * its own rule still wants bytes (2.0 F4); the walk ends once neither holds. */
static void
frm_purge_release(sd_frm_state *st, const brix_sd_frm_purge_policy_t *pol,
    frm_purge_scan_t *s, uint64_t need, brix_sd_frm_purge_report_t *rep,
    frm_purge_policy_t *pp)
{
    time_t   now = time(NULL);
    size_t   i;

    qsort(s->v, s->n, sizeof(s->v[0]), frm_purge_cmp_lru);
    for (i = 0; i < s->n; i++) {
        const frm_purge_cand_t *c = &s->v[i];
        uint64_t                freed;

        if (rep->bytes >= need && !frm_purge_policy_wants(pp, c)) {
            if (!frm_purge_policy_pending(pp)) {
                break;
            }
            continue;
        }
        freed = frm_purge_one(st, pol, c, now, rep, pp);
        if (freed > 0) {
            rep->bytes += freed;
            frm_purge_policy_account(pp, c);
        }
    }
}

static int
frm_purge_lock(const char *online, char *lockpath, size_t cap, ngx_log_t *log)
{
    int fd;

    if (snprintf(lockpath, cap, "%s/" FRM_PURGE_LOCK_NAME, online) >= (int) cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
            "brix: tape purge cannot open lock \"%s\"", lockpath);
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int saved = errno;

        close(fd);
        errno = saved;
        return -2;
    }
    return fd;
}

static void
frm_purge_log(ngx_log_t *log, const char *online,
    const brix_sd_frm_purge_policy_t *pol, const brix_sd_frm_purge_report_t *rep)
{
    ngx_uint_t occ_before = 0, occ_after = 0;
    ngx_uint_t level = rep->evicted ? NGX_LOG_NOTICE : NGX_LOG_INFO;

    if (pol->fs_total > 0) {
        uint64_t used_after = (pol->fs_used > rep->bytes) ? pol->fs_used - rep->bytes : 0;

        occ_before = (ngx_uint_t) ((pol->fs_used * 1000000.0) / pol->fs_total);
        occ_after  = (ngx_uint_t) ((used_after * 1000000.0) / pol->fs_total);
    }
    ngx_log_error(level, log, 0,
        "brix: tape purge \"%s\": released %ui file(s), %uL bytes "
        "(occupancy %ui -> %ui ppm, owned %uL -> %uL bytes; skipped young=%ui "
        "pinned=%ui unmigrated=%ui symlink=%ui failed=%ui)",
        online, rep->evicted, rep->bytes, occ_before, occ_after,
        rep->owned_before, rep->owned_after, rep->young, rep->pinned,
        rep->unmigrated, rep->symlinks, rep->failed);
}

ngx_int_t
brix_sd_frm_purge(brix_sd_instance_t *inst,
    const brix_sd_frm_purge_policy_t *pol, brix_sd_frm_purge_report_t *rep,
    ngx_log_t *log)
{
    char                online[PATH_MAX], lockpath[PATH_MAX];
    frm_purge_scan_t    scan;
    frm_purge_policy_t  pp;
    uint64_t            need;
    int                 lockfd, rc;

    ngx_memzero(rep, sizeof(*rep));
    if (brix_sd_frm_online_root(inst, online, sizeof(online)) != NGX_OK) {
        return NGX_ERROR;
    }
    if (access(online, F_OK) != 0 && errno == ENOENT) {
        return NGX_OK;             /* nothing recalled or staged yet: no buffer */
    }
    lockfd = frm_purge_lock(online, lockpath, sizeof(lockpath), log);
    if (lockfd == -2) {
        return NGX_DECLINED;
    }
    if (lockfd < 0) {
        return NGX_ERROR;
    }

    ngx_memzero(&scan, sizeof(scan));
    scan.root_len = strlen(online);
    frm_purge_active_scan = &scan;
    rc = nftw(online, frm_purge_visit, FRM_PURGE_NFTW_FDS, FTW_PHYS | FTW_MOUNT);
    frm_purge_active_scan = NULL;
    if (rc != 0 || scan.oom) {
        ngx_log_error(NGX_LOG_ERR, log, scan.oom ? ENOMEM : errno,
            "brix: tape purge walk of \"%s\" failed", online);
        frm_purge_scan_free(&scan);
        close(lockfd);
        return NGX_ERROR;
    }

    rep->symlinks     = scan.symlinks;
    rep->owned_before = scan.owned;
    if (frm_purge_policy_init(&pp, pol, &scan) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ENOMEM,
            "brix: tape purge of \"%s\": cannot size the policy table", online);
        frm_purge_scan_free(&scan);
        close(lockfd);
        return NGX_ERROR;
    }
    need = frm_purge_need(pol, scan.owned);
    if (need > 0 || frm_purge_policy_pending(&pp)) {
        frm_purge_policy_consult(&pp, pol, &scan, online, need, log);
        frm_purge_release(SD_FRM_ST(inst), pol, &scan, need, rep, &pp);
    }
    rep->owned_after = scan.owned - rep->bytes;
    if (rep->bytes > 0) {
        brix_metric_vfs_evict("frm", rep->bytes);
    }
    frm_purge_log(log, online, pol, rep);
    frm_purge_policy_log(&pp, pol, online, rep, log);

    frm_purge_policy_free(&pp);
    frm_purge_scan_free(&scan);
    close(lockfd);                                 /* releases the flock */
    return NGX_OK;
}
