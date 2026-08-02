/*
 * fs/backend/csi_scrub.c — the paced background CSI scrub (phase-59 W2b).
 * See csi_scrub.h for the contract. Pure engine: libc + xmeta + crc32c, no
 * nginx runtime, so it unit-tests standalone (tests/c/test_csi_scrub.c) and
 * the per-server maintenance timer (process_timers.c) is a thin caller.
 */

#include "csi_scrub.h"
#include "csi_tagstore.h"                /* BRIX_CSI_OK / _MISMATCH / _NOTAGS / _ERR */
#include "fs/meta/xmeta_path.h"
#include "core/compat/crc32c.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* A sidecar / slice file the scrub drives off its data file, never as data of
 * its own (mirrors cache_reap.c::reap_is_sidecar). The .cinfo/.meta records are
 * the checksum carriers themselves. */
static int
scrub_is_sidecar(const char *name)
{
    const char *dot = strrchr(name, '.');

    if (dot != NULL && (strcmp(dot, ".cinfo") == 0 || strcmp(dot, ".meta") == 0
                        || strcmp(dot, ".part") == 0 || strcmp(dot, ".lock") == 0))
    {
        return 1;
    }
    return strstr(name, ".__xrds") != NULL;   /* slice files + slice meta */
}

/* Read exactly len bytes at off (EINTR-retried). 1 = full, 0 = short/error. */
static int
scrub_pread_full(int fd, unsigned char *buf, size_t len, off_t off)
{
    size_t got = 0;

    while (got < len) {
        ssize_t n = pread(fd, buf + got, len - got, off + (off_t) got);

        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return 0;
        }
        got += (size_t) n;
    }
    return 1;
}

/* Verify every set block CRC in *xm against fd's bytes. Returns the number of
 * mismatches found (bumping the per-block stat counters); a short on-disk block
 * (record longer than the file) is skipped, never failed. */
static uint64_t
scrub_verify_fd(const char *path, int fd, off_t fsize, const brix_xmeta_t *xm,
    brix_csi_scrub_stats_t *st, brix_csi_scrub_report_fn report, void *u)
{
    int64_t        g = xm->buffer_size;
    uint64_t       b, mism = 0;
    unsigned char *blockbuf = malloc((size_t) g);

    if (blockbuf == NULL) {
        st->errors++;
        return 0;
    }
    for (b = 0; b < xm->nblocks; b++) {
        int64_t  bstart = (int64_t) b * g;
        int64_t  bend   = bstart + g;
        uint32_t got;

        if (xm->blockcrc[b] == BRIX_XMETA_CRC_UNSET) {
            st->blocks_unset++;
            continue;
        }
        if (bend > xm->file_size) {
            bend = xm->file_size;
        }
        if (bend > fsize || bend <= bstart
            || !scrub_pread_full(fd, blockbuf, (size_t) (bend - bstart), bstart))
        {
            st->blocks_short++;           /* cannot vouch for it — skip */
            continue;
        }
        got = brix_crc32c_value(blockbuf, (size_t) (bend - bstart));
        if (got != xm->blockcrc[b]) {
            st->mismatches++;
            mism++;
            if (report != NULL) {
                report(u, path, b, xm->blockcrc[b], got);
            }
        } else {
            st->blocks_verified++;
        }
    }
    free(blockbuf);
    return mism;
}

int
brix_csi_scrub_file(const char *path, brix_csi_scrub_stats_t *st,
    brix_csi_scrub_report_fn report, void *u)
{
    brix_xmeta_t xm;
    struct stat  fst;
    int          fd, rc;
    uint64_t     mism;

    if (path == NULL || st == NULL) {
        errno = EINVAL;
        return BRIX_CSI_ERR;
    }
    st->files_scanned++;

    switch (brix_xmeta_path_load(path, &xm)) {
    case BRIX_XMETA_OK:
        break;
    case BRIX_XMETA_FOREIGN:
        return BRIX_CSI_NOTAGS;
    default:
        st->errors++;
        return BRIX_CSI_ERR;
    }
    if (!xm.have_blockcrc || xm.blockcrc == NULL || xm.buffer_size <= 0
        || xm.nblocks == 0)
    {
        brix_xmeta_free(&xm);
        return BRIX_CSI_NOTAGS;
    }
    st->files_tagged++;

    fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &fst) != 0 || !S_ISREG(fst.st_mode)) {
        if (fd >= 0) {
            close(fd);
        }
        brix_xmeta_free(&xm);
        st->errors++;
        return BRIX_CSI_ERR;
    }

    mism = scrub_verify_fd(path, fd, fst.st_size, &xm, st, report, u);
    close(fd);
    brix_xmeta_free(&xm);
    rc = (mism > 0) ? BRIX_CSI_MISMATCH : BRIX_CSI_OK;
    return rc;
}

/* Immutable per-walk context: root device (never crossed) + report sink. */
typedef struct {
    dev_t                    dev;
    brix_csi_scrub_report_fn report;
    void                    *u;
} scrub_ctx_t;

/* Recurse dir (same device as root), scrubbing regular data files, stopping
 * once *remaining files have been scanned (SIZE_MAX = unlimited). Returns the
 * count scanned in this subtree. */
static long
scrub_dir(const char *dir, const scrub_ctx_t *sc, brix_csi_scrub_stats_t *st,
    long *remaining)
{
    DIR           *dp;
    struct dirent *de;
    long           n = 0;
    char           child[PATH_MAX];

    dp = opendir(dir);
    if (dp == NULL) {
        return 0;
    }
    while (*remaining != 0 && (de = readdir(dp)) != NULL) {
        struct stat st_c;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0
            || scrub_is_sidecar(de->d_name))
        {
            continue;
        }
        if (snprintf(child, sizeof(child), "%s/%s", dir, de->d_name)
            >= (int) sizeof(child))
        {
            continue;
        }
        if (lstat(child, &st_c) != 0 || st_c.st_dev != sc->dev) {
            continue;
        }
        if (S_ISDIR(st_c.st_mode)) {
            n += scrub_dir(child, sc, st, remaining);
            continue;
        }
        if (!S_ISREG(st_c.st_mode)) {
            continue;
        }
        (void) brix_csi_scrub_file(child, st, sc->report, sc->u);
        n++;
        if (*remaining > 0) {
            (*remaining)--;
        }
    }
    closedir(dp);
    return n;
}

long
brix_csi_scrub_walk(const char *root, brix_csi_scrub_stats_t *st,
    long budget, brix_csi_scrub_report_fn report, void *u)
{
    struct stat rs;
    scrub_ctx_t sc;
    long        remaining = (budget > 0) ? budget : -1;   /* -1 = unlimited */

    if (root == NULL || st == NULL || stat(root, &rs) != 0
        || !S_ISDIR(rs.st_mode))
    {
        return 0;
    }
    sc.dev    = rs.st_dev;
    sc.report = report;
    sc.u      = u;
    return scrub_dir(root, &sc, st, &remaining);
}
