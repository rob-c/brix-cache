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

/* ---- upper-tree mutations (all O_NOFOLLOW-walked, 0 / -errno) ------------ */

/* Ensure the upper dir chain `rel_dir` exists. `mode_fn(ud, prefix)` supplies
 * the mode of each newly created level (the FUSE layer mirrors lower dir
 * modes with it); NULL → 0755. */
int brix_overlay_mkdirs(const brix_overlay *ov, const char *rel_dir,
                        mode_t (*mode_fn)(void *ud, const char *rel_dir),
                        void *ud);

/* openat the upper leaf with `oflags|O_NOFOLLOW` (parents are NOT created —
 * call mkdirs first). Returns fd >= 0 or -errno. */
int brix_overlay_open(const brix_overlay *ov, const char *rel,
                      int oflags, mode_t mode);

int brix_overlay_mkdir(const brix_overlay *ov, const char *rel, mode_t mode);

/* Drop the ".brix.opq" marker inside existing upper dir `rel_dir` (a deleted
 * lower dir was re-created: stop merging the lower listing). */
int brix_overlay_set_opaque(const brix_overlay *ov, const char *rel_dir);

int brix_overlay_unlink_upper(const brix_overlay *ov, const char *rel);

/* Remove upper dir `rel`, first clearing any marker files inside it; a real
 * (non-marker) entry inside → -ENOTEMPTY. */
int brix_overlay_rmdir_upper(const brix_overlay *ov, const char *rel);

int brix_overlay_rename_upper(const brix_overlay *ov, const char *from,
                              const char *to);

int brix_overlay_symlink(const brix_overlay *ov, const char *target,
                         const char *rel);
int brix_overlay_readlink(const brix_overlay *ov, const char *rel,
                          char *buf, size_t n);

/* chmod refuses symlink leaves (-EOPNOTSUPP); utimens never follows. */
int brix_overlay_chmod(const brix_overlay *ov, const char *rel, mode_t mode);
int brix_overlay_utimens(const brix_overlay *ov, const char *rel,
                         const struct timespec tv[2]);
int brix_overlay_truncate(const brix_overlay *ov, const char *rel, off_t len);

/* ---- copy-up ------------------------------------------------------------- */

/* Lower-layer reader injected by the FUSE driver (cvmfs_client_read shaped):
 * fill buf with up to `len` bytes at `off`; *outlen = bytes produced (0 only
 * at/after EOF). Returns 0 / -errno. */
typedef int (*brix_ov_read_fn)(void *ud, const char *rel, uint64_t off,
                               size_t len, unsigned char *buf, size_t *outlen);

/* Materialise lower file `rel` in the upper tree: parent chain is created,
 * bytes stream into a ".brix.tmp.<leaf>" sibling (1 MiB chunks) which is
 * renamed into place only when complete — a failure leaves NO trace. Lower
 * mode bits and mtime are preserved; any whiteout on `rel` is cleared. */
int brix_overlay_copyup(const brix_overlay *ov, const char *rel,
                        const struct stat *lower_st,
                        brix_ov_read_fn read_lower, void *ud);

/* ---- merged-readdir support ---------------------------------------------- */

/* Packed upper-dir listing: entries are `<flag><name>\0` where flag 'u' = a
 * real upper entry (emit it; suppress the lower duplicate) and 'w' = a
 * whiteout base-name (suppress the lower entry). Marker files themselves
 * (.brix.opq / .brix.tmp.*) never appear. */
typedef struct {
    char  *buf;
    size_t used, cap;
    size_t count;
} brix_ov_nameset;

/* List upper dir `rel` into *set (caller frees); *opaque = 1 when the dir
 * carries .brix.opq (don't merge the lower listing). A missing upper dir is
 * an empty set, not an error. */
int brix_overlay_read_upper(const brix_overlay *ov, const char *rel,
                            brix_ov_nameset *set, int *opaque);

/* 0 = absent, else the entry's flag ('u' / 'w'). */
char brix_ov_nameset_flag(const brix_ov_nameset *s, const char *name);

/* i-th entry name (NULL past the end); *flag gets its flag when non-NULL. */
const char *brix_ov_nameset_at(const brix_ov_nameset *s, size_t i, char *flag);

void brix_ov_nameset_free(brix_ov_nameset *s);

/* ---- CLI cores (brixMount --overlay-list / --overlay-reset) -------------- */

/* Walk <mountdir>/.brixwrites/upper and print one change per line to `out`:
 *   deleted <rel>   whiteout marker
 *   dir <rel>       directory
 *   new|modified <rel>   when the live mount answers the user.overlay xattr
 *   upper <rel>     files, when unmounted (no xattr available)
 * Works identically on a live cvmfs-rw mount (via the /.brixwrites
 * passthrough subtree) and on the raw on-disk tree. Returns an exit code:
 * 0 ok, 2 when <mountdir> has no .brixwrites (wrong-mountpoint guard). */
int brix_overlay_cli_list(const char *mountdir, FILE *out);

/* Recursively empty <mountdir>/.brixwrites/upper (the dir itself stays) —
 * every local change is discarded and lower shows through again. Same
 * exit-code contract as list. */
int brix_overlay_cli_reset(const char *mountdir);

#endif /* XRDC_OVERLAY_H */
