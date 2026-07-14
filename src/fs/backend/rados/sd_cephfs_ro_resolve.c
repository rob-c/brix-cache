/*
 * sd_cephfs_ro_resolve.c — path resolution + retry policy for the read-only
 * CephFS-via-RADOS driver ("cephfsro").
 *
 * WHAT: The RADOS metadata-decode + inode-resolution path split out of
 *       sd_cephfs_ro.c: reading a dentry omap value from a directory fragment
 *       object, decoding the embedded inode, walking dentries from the root inode
 *       to resolve an absolute path, and the consistency-mode retry policy
 *       (transient-error backoff + live-mode optimistic revalidation).
 *
 * WHY:  This is the largest and most self-contained concern of the driver; it is
 *       exercised by every op (open/stat/opendir/xattr → cephfsro_resolve_retry)
 *       and by the data/dir read paths (cephfsro_is_transient / cephfsro_backoff).
 *       See sd_cephfs_ro.c for the driver-level narrative.
 *
 * The whole driver compiles only when the build found librados (BRIX_HAVE_CEPH);
 * otherwise this is an empty translation unit.
 */
#include "sd_ceph.h"

#if BRIX_HAVE_CEPH

#include "cephfs_layout.h"
#include "sd_cephfs_ro_internal.h"

#include <rados/librados.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CEPHFS_ROOT_INO       1ull
#define CEPHFS_DENTRY_VAL_MAX (64u * 1024u)   /* a dentry omap value is ~0.5–4 KiB */
#define CEPHFS_RO_MAXDEPTH    128             /* path components tracked for revalid*/
#define CEPHFS_RO_BACKOFF_US  2000            /* base backoff (×2^attempt, capped)  */

/* ---- resolve-private state ------------------------------------------------ */

/* One on-path directory object captured during a resolve, with the RADOS object
 * version at read time, so a later revalidation can tell if it changed under us. */
typedef struct {
    char     oid[64];
    uint64_t version;
} cephfsro_pathver_t;

/* Optional per-resolve walk record (live mode): the dir objects touched on the
 * path and their versions, for optimistic revalidation. */
typedef struct {
    cephfsro_pathver_t ent[CEPHFS_RO_MAXDEPTH];
    int                n;
} cephfsro_walk_t;

/* ---- retry policy --------------------------------------------------------- */

/* A transient cluster error is worth retrying regardless of consistency mode
 * (cluster blip, peering, blocklist churn); a permanent one (ENOENT/EACCES/…) is
 * fast-failed. EIO is treated as transient because librados surfaces several
 * recoverable conditions as EIO. */
int
cephfsro_is_transient(int err)
{
    switch (err) {
    case EAGAIN: case ETIMEDOUT: case EBUSY: case EINTR: case EIO:
        return 1;
    default:
        return 0;
    }
}

/* Sleep an exponentially-growing, jittered, capped backoff before a retry. Held
 * only on the (rare) error/race path; the ceph data path is synchronous anyway. */
void
cephfsro_backoff(int attempt)
{
    long            us = (long) CEPHFS_RO_BACKOFF_US << attempt;
    struct timespec ts;

    if (us > 50000) { us = 50000; }                 /* cap at 50 ms */
    us += (long) (us / 4) ? (long) (clock() % (us / 4 + 1)) : 0;   /* light jitter */
    ts.tv_sec  = us / 1000000;
    ts.tv_nsec = (us % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

/* ---- small helpers -------------------------------------------------------- */

/* Read a single omap value by key from `oid` into `buf`. On success returns the
 * value length (>=0) via *outlen and 0; returns -1/errno on a RADOS error and 1
 * when the key is simply absent (so callers distinguish "not found" from error).
 * When `version` is non-NULL it receives the RADOS object version at read time
 * (for optimistic revalidation). */
static int
cephfsro_omap_get1(rados_ioctx_t ioctx, const char *oid, const char *key,
                   void *buf, size_t cap, size_t *outlen, uint64_t *version)
{
    const char        *keys[1];
    rados_omap_iter_t  it = NULL;
    rados_read_op_t    op;
    int                prval = 0, rc, found = 0;
    char              *k = NULL, *v = NULL;
    size_t             vlen = 0;

    keys[0] = key;
    op = rados_create_read_op();
    rados_read_op_omap_get_vals_by_keys(op, keys, 1, &it, &prval);
    rc = rados_read_op_operate(op, ioctx, oid, 0);
    if (rc < 0) {
        rados_release_read_op(op);
        errno = -rc;
        return -1;
    }
    if (version != NULL) { *version = rados_get_last_version(ioctx); }
    if (it != NULL && rados_omap_get_next(it, &k, &v, &vlen) == 0
        && k != NULL && v != NULL)
    {
        size_t n = (vlen < cap) ? vlen : cap;
        memcpy(buf, v, n);
        *outlen = n;
        found = 1;
    }
    if (it != NULL) { rados_omap_get_end(it); }
    rados_release_read_op(op);
    return found ? 0 : 1;
}

/* Current RADOS version of `oid` (a cheap stat op). Returns 0 / -1 (errno). */
static int
cephfsro_obj_version(rados_ioctx_t ioctx, const char *oid, uint64_t *version)
{
    rados_read_op_t op = rados_create_read_op();
    uint64_t        psize = 0;
    struct timespec pmt;
    int             prval = 0, rc;

    rados_read_op_stat2(op, &psize, &pmt, &prval);
    rc = rados_read_op_operate(op, ioctx, oid, 0);
    rados_release_read_op(op);
    if (rc < 0) { errno = -rc; return -1; }
    *version = rados_get_last_version(ioctx);
    return 0;
}

/* Append a (oid, version) record to a walk, if capturing and not full. */
static void
cephfsro_walk_add(cephfsro_walk_t *w, const char *oid, uint64_t version)
{
    if (w == NULL || w->n >= CEPHFS_RO_MAXDEPTH) { return; }
    snprintf(w->ent[w->n].oid, sizeof(w->ent[w->n].oid), "%s", oid);
    w->ent[w->n].version = version;
    w->n++;
}

/* Look up `name` directly beneath directory inode `dirino` whose leaf fragments
 * are `frags[0..nfrags)`: scan each fragment object for "<name>_head" and decode
 * the first hit into *out. Scanning every leaf frag is correct for both unsplit
 * and fragmented dirs (a dentry lives in exactly one frag) and avoids needing the
 * dentry-hash→frag mapping. When `walk` is non-NULL the dir object the result
 * depended on (the frag that held the entry, or the first frag searched when
 * absent) is recorded with its version for later revalidation. Returns 0 (found),
 * 1 (absent), -1 (error). */
static int
cephfsro_lookup(cephfsro_state_t *st, uint64_t dirino, const uint32_t *frags,
                uint32_t nfrags, const char *name, cephfs_dentry_t *out,
                cephfsro_walk_t *walk)
{
    rados_ioctx_t meta = sd_ceph_conn_ioctx(st->meta);
    char          key[300];
    char          first_oid[64] = "";
    uint64_t      first_ver = 0;
    int           have_first = 0;
    uint32_t      i;

    if (snprintf(key, sizeof(key), "%s_head", name) >= (int) sizeof(key)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    for (i = 0; i < nfrags; i++) {
        char     oid[64];
        char     val[CEPHFS_DENTRY_VAL_MAX];
        size_t   vlen = 0;
        uint64_t ver = 0;
        int      rc;

        snprintf(oid, sizeof(oid), "%llx.%08llx",
                 (unsigned long long) dirino, (unsigned long long) frags[i]);
        rc = cephfsro_omap_get1(meta, oid, key, val, sizeof(val), &vlen, &ver);
        if (rc < 0) {
            /* an absent fragment object is not an error — try the next frag */
            if (errno == ENOENT) { continue; }
            return -1;
        }
        if (!have_first) {
            snprintf(first_oid, sizeof(first_oid), "%s", oid);
            first_ver = ver; have_first = 1;
        }
        if (rc == 0) {
            if (cephfs_decode_dentry(val, vlen, out) != 0) {
                errno = EIO;
                return -1;
            }
            cephfsro_walk_add(walk, oid, ver);     /* depended on this frag */
            return 0;
        }
    }
    /* absent: record the dir we searched so a concurrent change is detectable */
    if (have_first) { cephfsro_walk_add(walk, first_oid, first_ver); }
    return 1;   /* not found in any fragment */
}

/* Fill *out with a synthetic dentry for the CephFS root (inode 1). The root is
 * assumed unfragmented (the overwhelmingly common case); its single fragment
 * object is "1.00000000". */
static void
cephfsro_fill_root(cephfs_dentry_t *out)
{
    memset(out, 0, sizeof(*out));
    out->kind          = CEPHFS_DENTRY_PRIMARY;
    out->inode.ino     = CEPHFS_ROOT_INO;
    out->inode.mode    = CEPHFS_S_IFDIR | 0755;
    out->inode.nlink   = 2;
    out->nfrags        = 1;
    out->frag_enc[0]   = 0;
}

/* Resolve an absolute logical path to its dentry by walking from the root. The
 * leading '/' is optional; "" or "/" resolves to the root. When `walk` is
 * non-NULL, the dir objects each component depended on are recorded with their
 * versions for optimistic revalidation. Returns 0 on success, 1 when a component
 * is absent (ENOENT), -1 on error. */
static int
cephfsro_resolve(cephfsro_state_t *st, const char *path, cephfs_dentry_t *out,
                 cephfsro_walk_t *walk)
{
    uint64_t parent_ino = CEPHFS_ROOT_INO;
    uint32_t parent_frags[CEPHFS_MAX_FRAGS];
    uint32_t parent_nfrags = 1;
    const char *p = (path != NULL) ? path : "";

    parent_frags[0] = 0;
    cephfsro_fill_root(out);
    if (walk != NULL) { walk->n = 0; }

    while (*p != '\0') {
        char     comp[256];
        size_t   len = 0;
        int      rc;

        while (*p == '/') { p++; }
        if (*p == '\0') { break; }
        while (*p != '\0' && *p != '/') {
            if (len + 1 >= sizeof(comp)) { errno = ENAMETOOLONG; return -1; }
            comp[len++] = *p++;
        }
        comp[len] = '\0';

        rc = cephfsro_lookup(st, parent_ino, parent_frags, parent_nfrags, comp,
                             out, walk);
        if (rc != 0) { return rc; }            /* absent (1) or error (-1) */

        if (out->kind == CEPHFS_DENTRY_REMOTE) {
            /* a hardlink: terminal use is fine, but we cannot descend through it */
            while (*p == '/') { p++; }
            if (*p != '\0') { errno = ENOTDIR; return -1; }
            return 0;
        }

        parent_ino    = out->inode.ino;
        parent_nfrags = (out->nfrags < CEPHFS_MAX_FRAGS) ? out->nfrags
                                                         : CEPHFS_MAX_FRAGS;
        memcpy(parent_frags, out->frag_enc, parent_nfrags * sizeof(uint32_t));
    }
    return 0;
}

/* Re-check every dir object a resolve depended on: 1 if any changed version
 * since the walk (an MDS write landed mid-walk → the result may be inconsistent),
 * 0 if all stable, and 1 (conservatively "changed") if a probe errors. */
static int
cephfsro_walk_changed(cephfsro_state_t *st, const cephfsro_walk_t *w)
{
    rados_ioctx_t meta = sd_ceph_conn_ioctx(st->meta);
    int           i;

    for (i = 0; i < w->n; i++) {
        uint64_t now = 0;
        if (cephfsro_obj_version(meta, w->ent[i].oid, &now) != 0) {
            return 1;                          /* can't confirm stable → retry */
        }
        if (now != w->ent[i].version) { return 1; }
    }
    return 0;
}

/* Resolve with the consistency policy applied: bounded retries on a transient
 * cluster error always, and — in live mode — a retry when optimistic
 * revalidation shows a dir on the path changed during the walk (so an infrequent
 * MDS sync that lands mid-resolve is picked up rather than served torn/stale).
 * A genuine, stable not-found or permanent error fast-fails. Returns 0 / 1 / -1
 * like cephfsro_resolve, with errno set. */
int
cephfsro_resolve_retry(cephfsro_state_t *st, const char *path,
                       cephfs_dentry_t *out)
{
    int attempt;

    for (attempt = 0; ; attempt++) {
        cephfsro_walk_t  walk;
        cephfsro_walk_t *wp = st->live ? &walk : NULL;
        int              rc;

        walk.n = 0;
        rc = cephfsro_resolve(st, path, out, wp);

        if (rc == 0) {                                     /* found */
            if (wp != NULL && cephfsro_walk_changed(st, wp)
                && attempt < st->max_retry)
            {
                cephfsro_backoff(attempt);                 /* raced — re-resolve */
                continue;
            }
            return 0;
        }
        if (rc < 0 && cephfsro_is_transient(errno)
            && attempt < st->max_retry)
        {
            cephfsro_backoff(attempt);                     /* transient — retry  */
            continue;
        }
        if (rc == 1 && wp != NULL && cephfsro_walk_changed(st, wp)
            && attempt < st->max_retry)
        {
            cephfsro_backoff(attempt);     /* not-found but path raced — retry   */
            continue;
        }
        return rc;                                         /* stable result      */
    }
}

/* Fill an SD stat from a decoded primary inode. */
void
cephfsro_stat_from_inode(const cephfs_inode_t *in, brix_sd_stat_t *out)
{
    memset(out, 0, sizeof(*out));
    out->size   = (off_t) in->size;
    out->mtime  = (time_t) in->mtime_sec;
    out->ctime  = (time_t) in->ctime_sec;
    out->mode   = (mode_t) in->mode;
    out->ino    = (ino_t) in->ino;
    out->is_dir = cephfs_mode_is_dir(in->mode) ? 1 : 0;
    out->is_reg = cephfs_mode_is_reg(in->mode) ? 1 : 0;
}

#endif /* BRIX_HAVE_CEPH */
