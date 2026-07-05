/*
 * overlay.h — writable union overlay core for brixMount cvmfs-rw (pure C; no
 * FUSE, no CVMFS, no ngx).
 *
 * WHAT: the union-layer primitives over an "upper" directory tree stored at
 *       <mnt>/.brixwrites/upper — classify a path (upper / masked / fall
 *       through to lower), whiteout + opaque markers, upper-tree mutations,
 *       atomic copy-up, merged-readdir support, and the --overlay-list /
 *       --overlay-reset CLI cores.
 * WHY:  full POSIX write semantics on top of a read-only CVMFS mount, with the
 *       local changes kept as a plain path-mirroring tree beside .brixcache —
 *       human-inspectable, diffable, rm -rf-resettable. Keeping the module
 *       FUSE/CVMFS-free makes every union corner unit-testable on tmp dirs.
 * HOW:  every upper access goes through a per-component O_NOFOLLOW walk rooted
 *       at the upper dirfd, so a symlink planted in the user-writable upper
 *       tree can never redirect the driver outside .brixwrites. The lower
 *       (read-only) layer is reached only via an injected read callback
 *       (copy-up); the FUSE driver composes overlay-first / cvmfs-fallback.
 *       Single-threaded by contract (the brixcvmfs FUSE loop runs -s).
 *       Functions return 0 / -errno (FUSE convention); fd-returning functions
 *       return fd >= 0 / -errno. Paths are repo-relative WITHOUT a leading
 *       slash ("" = the repo root), matching brixcvmfs's cat_path().
 */
#ifndef XRDC_OVERLAY_H
#define XRDC_OVERLAY_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

/* on-disk marker vocabulary (all names reserved through the mount) */
#define BRIX_OV_WH_PREFIX     ".brix.wh."    /* whiteout: deleted lower name  */
#define BRIX_OV_OPQ_NAME      ".brix.opq"    /* opaque dir: don't merge lower */
#define BRIX_OV_TMP_PREFIX    ".brix.tmp."   /* in-flight copy-up             */
#define BRIX_OV_DIRNAME       ".brixwrites"  /* overlay root under the mount  */
#define BRIX_OV_UPPER_DIRNAME "upper"        /* the path-mirroring upper tree */

/* union classification of one repo-relative path */
typedef enum {
    BRIX_OV_NONE = 0,     /* not in upper, not masked → fall through to lower */
    BRIX_OV_UPPER,        /* present in upper (stat filled)                   */
    BRIX_OV_MASKED,       /* whiteout / opaque / shadowing upper file → the   */
                          /* lower entry (if any) must read as ENOENT         */
} brix_ov_state;

typedef struct {
    int writes_fd;        /* <mnt>/.brixwrites dirfd (caller owns)            */
    int upper_fd;         /* .brixwrites/upper dirfd (owned by the overlay)   */
} brix_overlay;

/* Open (creating if needed) the upper/ tree under `writes_fd` and bind the
 * overlay to it. The caller keeps ownership of writes_fd. 0 / -errno. */
int  brix_overlay_init(brix_overlay *ov, int writes_fd);
void brix_overlay_close(brix_overlay *ov);

/* 1 when `name` (a single path component) is overlay-reserved vocabulary. */
int brix_ov_name_reserved(const char *name);

/* Classify `rel` against the upper tree; fills *st (lstat semantics) when the
 * result is BRIX_OV_UPPER. 0 / -errno (bad path components are -EINVAL). */
int brix_overlay_classify(const brix_overlay *ov, const char *rel,
                          struct stat *st, brix_ov_state *state);

/* Whiteout marker for `rel`: query (1/0/-errno), set (parent chain created),
 * clear (absent marker or parent is a no-op success). */
int brix_overlay_whiteout(const brix_overlay *ov, const char *rel);
int brix_overlay_whiteout_set(const brix_overlay *ov, const char *rel);
int brix_overlay_whiteout_clear(const brix_overlay *ov, const char *rel);

#endif /* XRDC_OVERLAY_H */
