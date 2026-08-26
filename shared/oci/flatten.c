/* flatten.c — apply one OCI layer to an overlay upper tree (phase-104 D7).
 *
 * WHAT: the flatten.h contract — the D7.1 translation table over a tar.h
 *       entry stream, confined to upper_dir.
 * WHY:  see flatten.h; this TU is the security core of the ingest path.
 * HOW:  a path is parsed into components ("." dropped, ".." and reserved
 *       marker names refused) BEFORE any syscall, then walked with
 *       per-component O_NOFOLLOW openat from the upper_dir dirfd. Files
 *       land temp+rename; whiteouts remove-and-mark; opaques clear-and-
 *       mark. eStargz's own root entries (TOC + landmarks) are dropped
 *       before any syscall, counted in skipped_toc (D15.7). The marker
 *       strings are the overlay grammar's third spelling
 *       (client/lib/fs/overlay.h and publish/changeset.c are the others) —
 *       the three are lockstep by test, not by include, because shared/
 *       must not include client headers.
 */
#define _POSIX_C_SOURCE 200809L         /* *at() + fdopendir under -std=c11 */

#include "oci/flatten.h"
#include "oci/stargz.h"
#include "oci/tar.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "cvmfs/catalog/catalog_write.h"   /* cvmfs_xattr_unpack/_count */

#define FL_WH_PREFIX   ".brix.wh."         /* == BRIX_OV_WH_PREFIX  */
#define FL_OPQ_NAME    ".brix.opq"         /* == BRIX_OV_OPQ_NAME   */
#define FL_TMP_PREFIX  ".brix.tmp."        /* == BRIX_OV_TMP_PREFIX */
#define FL_TMP_NAME    ".brix.tmp.flatten" /* single-writer scratch name */

#define OCI_WH_PREFIX  ".wh."
#define OCI_OPQ_NAME   ".wh..wh..opq"

#define FL_MAX_COMPS       2048
#define FL_DEFAULT_ENTRIES (1024 * 1024)

typedef struct {
    const brix_flatten_opts_t *o;
    brix_flatten_stats_t      *st;
    int                        root;      /* O_DIRECTORY fd on upper_dir */
    brix_tar_t                *tar;
    int64_t                    entries;   /* this layer's entry count */
    char                      *err;
    size_t                     errlen;
    unsigned char              copybuf[64 * 1024];
} fl_ctx_t;

static int fl_fail(fl_ctx_t *fx, const char *fmt, const char *a, const char *b) {
    snprintf(fx->err, fx->errlen, fmt, a, b);
    return -1;
}

/* The overlay grammar's reserved-name predicate (brix_ov_name_reserved's
 * spelling, kept in lockstep by the D7 grammar tests). */
static int fl_reserved(const char *name) {
    if (strncmp(name, FL_WH_PREFIX, sizeof(FL_WH_PREFIX) - 1) == 0)   return 1;
    if (strncmp(name, FL_TMP_PREFIX, sizeof(FL_TMP_PREFIX) - 1) == 0) return 1;
    if (strcmp(name, FL_OPQ_NAME) == 0)                               return 1;
    return 0;
}

/* Split an archive path into validated components. "." and empty components
 * are dropped (layers spell "./usr/bin"); ".." and reserved marker names are
 * refused before any syscall. Returns the component count (0 = the layer
 * root itself) or -1. Component pointers alias `buf`, which must outlive
 * them and receives a copy of `path`. */
static int fl_components(fl_ctx_t *fx, const char *path,
                         char *buf, size_t bufsz,
                         const char **comps, size_t max) {
    size_t n = 0;
    char  *save = NULL, *tok;

    if (strlen(path) >= bufsz)
        return fl_fail(fx, "path too long: %.100s%s", path, "…");
    strcpy(buf, path);
    for (tok = strtok_r(buf, "/", &save); tok != NULL;
         tok = strtok_r(NULL, "/", &save)) {
        if (strcmp(tok, ".") == 0)
            continue;
        if (strcmp(tok, "..") == 0)
            return fl_fail(fx, "refusing '..' in layer path %s%s", path, "");
        if (strlen(tok) > 255)
            return fl_fail(fx, "component over 255 bytes in %s%s", path, "");
        if (fl_reserved(tok))
            return fl_fail(fx, "layer smuggles reserved marker name '%s' "
                           "in %s", tok, path);
        if (n >= max)
            return fl_fail(fx, "more than %s path components in %s",
                           "2048", path);
        comps[n++] = tok;
    }
    return (int) n;
}

/* Descend to the directory holding components[0..n-1], creating missing
 * intermediates (mode 0755). Every hop is openat(O_NOFOLLOW|O_DIRECTORY):
 * a symlink planted at any component is ELOOP — the containment wall.
 * Returns an owned fd or -1. */
static int fl_descend(fl_ctx_t *fx, const char *const *comps, size_t n) {
    int    cur = dup(fx->root);
    size_t i;

    if (cur < 0)
        return fl_fail(fx, "dup(upper) failed%s%s", "", "");
    for (i = 0; i < n; i++) {
        int next = openat(cur, comps[i],
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int saved;

        if (next < 0 && errno == ENOENT) {
            if (mkdirat(cur, comps[i], 0755) != 0 && errno != EEXIST) {
                saved = errno;
                close(cur);
                return fl_fail(fx, "cannot create parent '%s': %s",
                               comps[i], strerror(saved));
            }
            next = openat(cur, comps[i],
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        saved = errno;
        close(cur);
        if (next < 0) {
            errno = saved;
            if (errno == ELOOP || errno == ENOTDIR)
                return fl_fail(fx, "containment: '%s' is not a real "
                               "directory (symlink escape refused)", comps[i],
                               "");
            return fl_fail(fx, "cannot descend into '%s': %s", comps[i],
                           strerror(errno));
        }
        cur = next;
    }
    return cur;
}

/* Remove parent/name whatever it is (recursive for directories). 0 ok
 * (ENOENT counts as ok), -1 error. Recursion depth is bounded by the
 * component budget that built the tree in the first place. */
static int fl_rm(fl_ctx_t *fx, int parent, const char *name) {
    int            dfd;
    DIR           *d;
    struct dirent *de;

    if (unlinkat(parent, name, 0) == 0 || errno == ENOENT)
        return 0;
    if (errno != EISDIR && errno != EPERM)
        return fl_fail(fx, "cannot remove '%s': %s", name, strerror(errno));

    dfd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0)
        return fl_fail(fx, "cannot open '%s' for removal: %s", name,
                       strerror(errno));
    d = fdopendir(dfd);
    if (d == NULL) {
        close(dfd);
        return fl_fail(fx, "fdopendir '%s' failed%s", name, "");
    }
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (fl_rm(fx, dirfd(d), de->d_name) != 0) {
            closedir(d);
            return -1;
        }
    }
    closedir(d);
    if (unlinkat(parent, name, AT_REMOVEDIR) != 0)
        return fl_fail(fx, "cannot rmdir '%s': %s", name, strerror(errno));
    return 0;
}

/* Apply ownership/mtime onto parent/name (never following symlinks).
 * Ownership is best-effort: rootless ingest cannot chown to foreign uids
 * (EPERM/EINVAL swallowed — the Z-4 rootless reality; --squash-owner is the
 * deterministic path). */
static void fl_meta(fl_ctx_t *fx, int parent, const char *name,
                    const brix_tar_entry_t *e) {
    struct timespec ts[2];
    uid_t uid = fx->o->squash ? fx->o->squash_uid : e->uid;
    gid_t gid = fx->o->squash ? fx->o->squash_gid : e->gid;

    int crc = fchownat(parent, name, uid, gid, AT_SYMLINK_NOFOLLOW);
    (void) crc;                      /* unprivileged chown is best-effort */
    ts[0].tv_sec = ts[1].tv_sec = (time_t) e->mtime;
    ts[0].tv_nsec = ts[1].tv_nsec = 0;
    (void) utimensat(parent, name, ts, AT_SYMLINK_NOFOLLOW);
}

/* Apply the entry's user.* xattrs to an open fd. Non-user namespaces
 * (security.*, trusted.*) are skipped: the publish plane only carries
 * user.* (changeset.c's capture), and rootless ingest could not set them
 * anyway. ENOTSUP (filesystem without xattrs) is tolerated. */
static int fl_xattrs(fl_ctx_t *fx, int fd, const brix_tar_entry_t *e) {
    int i, n;

    if (e->xattr == NULL)
        return 0;
    n = cvmfs_xattr_count((const unsigned char *) e->xattr, e->xattr_len);
    if (n < 0)
        return fl_fail(fx, "malformed xattr blob on %s%s", e->path, "");
    for (i = 0; i < n; i++) {
        const char          *key;
        const unsigned char *val;
        size_t               keylen, vallen;
        char                 kbuf[256];

        if (cvmfs_xattr_unpack((const unsigned char *) e->xattr, e->xattr_len,
                               (size_t) i, &key, &keylen, &val, &vallen) != 0)
            return fl_fail(fx, "malformed xattr entry on %s%s", e->path, "");
        if (keylen >= sizeof(kbuf))
            continue;
        memcpy(kbuf, key, keylen);
        kbuf[keylen] = '\0';
        if (strncmp(kbuf, "user.", 5) != 0)
            continue;
        if (fsetxattr(fd, kbuf, val, vallen, 0) != 0 && errno != ENOTSUP)
            return fl_fail(fx, "cannot set xattr %s: %s", kbuf,
                           strerror(errno));
    }
    return 0;
}

/* Regular file: stream body → temp → rename, byte budget enforced on actual
 * bytes written (the decompression-bomb defense — claims don't count, output
 * does). */
#include "flatten_entries.c"

int brix_flatten_layer(const brix_flatten_opts_t *o, int layer_fd,
                       brix_flatten_stats_t *st, char *err, size_t errlen) {
    fl_ctx_t *fx = calloc(1, sizeof(*fx));
    int64_t   max_entries = o->max_entries > 0 ? o->max_entries
                                               : FL_DEFAULT_ENTRIES;
    int       rc = -1;

    if (fx == NULL) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    err[0]     = '\0';
    fx->o      = o;
    fx->st     = st;
    fx->err    = err;
    fx->errlen = errlen;
    fx->root   = open(o->upper_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fx->root < 0) {
        snprintf(err, errlen, "cannot open upper dir %s: %s", o->upper_dir,
                 strerror(errno));
        free(fx);
        return -1;
    }
    fx->tar = brix_tar_open_fd(layer_fd, err, errlen);
    if (fx->tar == NULL) {
        close(fx->root);
        free(fx);
        return -1;
    }
    if (o->diffid_hex != NULL && brix_tar_digest_enable(fx->tar) != 0) {
        snprintf(err, errlen, "%s", brix_tar_error(fx->tar));
        brix_tar_close(fx->tar);
        close(fx->root);
        free(fx);
        return -1;
    }

    for (;;) {
        brix_tar_entry_t e;
        int              got = brix_tar_next(fx->tar, &e);

        if (got < 0) {
            snprintf(err, errlen, "malformed layer: %s",
                     brix_tar_error(fx->tar));
            break;
        }
        if (got == 0) {
            rc = 0;
            break;
        }
        if (++fx->entries > max_entries) {
            snprintf(err, errlen, "entry budget (%lld) exhausted",
                     (long long) max_entries);
            break;
        }
        if (fl_entry(fx, &e) != 0)
            break;
    }

    if (rc == 0 && o->diffid_hex != NULL
        && brix_tar_digest_finish(fx->tar, o->diffid_hex,
                                  o->diffid_hexlen) != 0) {
        snprintf(err, errlen, "%s", brix_tar_error(fx->tar));
        rc = -1;
    }

    brix_tar_close(fx->tar);
    close(fx->root);
    free(fx);
    return rc;
}
