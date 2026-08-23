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
static int fl_reg(fl_ctx_t *fx, int parent, const char *name,
                  const brix_tar_entry_t *e) {
    int fd;

    if (fl_rm(fx, parent, name) != 0)      /* dir→file replacement */
        return -1;
    fd = openat(parent, FL_TMP_NAME,
                O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return fl_fail(fx, "cannot create temp for '%s': %s", name,
                       strerror(errno));
    for (;;) {
        int got = brix_tar_read(fx->tar, fx->copybuf, sizeof(fx->copybuf));

        if (got < 0) {
            close(fd);
            unlinkat(parent, FL_TMP_NAME, 0);
            return fl_fail(fx, "read of '%s' failed: %s", name,
                           brix_tar_error(fx->tar));
        }
        if (got == 0)
            break;
        fx->st->bytes += got;
        if (fx->o->max_total_bytes > 0 &&
            fx->st->bytes > fx->o->max_total_bytes) {
            close(fd);
            unlinkat(parent, FL_TMP_NAME, 0);
            return fl_fail(fx, "byte budget exhausted at '%s'%s", name, "");
        }
        if (write(fd, fx->copybuf, (size_t) got) != (ssize_t) got) {
            close(fd);
            unlinkat(parent, FL_TMP_NAME, 0);
            return fl_fail(fx, "write of '%s' failed: %s", name,
                           strerror(errno));
        }
    }
    if (fchmod(fd, e->mode) != 0 || fl_xattrs(fx, fd, e) != 0) {
        close(fd);
        unlinkat(parent, FL_TMP_NAME, 0);
        return fx->err[0] ? -1
                          : fl_fail(fx, "chmod '%s' failed%s", name, "");
    }
    close(fd);
    if (renameat(parent, FL_TMP_NAME, parent, name) != 0)
        return fl_fail(fx, "rename into '%s' failed: %s", name,
                       strerror(errno));
    fl_meta(fx, parent, name, e);
    fx->st->files++;
    return 0;
}

/* Directory: mkdir-or-merge; later layers win the metadata. */
static int fl_dir(fl_ctx_t *fx, int parent, const char *name,
                  const brix_tar_entry_t *e) {
    struct stat sb;
    int         dfd;

    if (fstatat(parent, name, &sb, AT_SYMLINK_NOFOLLOW) == 0 &&
        !S_ISDIR(sb.st_mode)) {
        if (fl_rm(fx, parent, name) != 0)   /* file→dir replacement */
            return -1;
    }
    if (mkdirat(parent, name, 0755) != 0 && errno != EEXIST)
        return fl_fail(fx, "mkdir '%s' failed: %s", name, strerror(errno));
    dfd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0)
        return fl_fail(fx, "cannot open new dir '%s': %s", name,
                       strerror(errno));
    if (fchmod(dfd, e->mode) != 0 || fl_xattrs(fx, dfd, e) != 0) {
        close(dfd);
        return fx->err[0] ? -1
                          : fl_fail(fx, "chmod dir '%s' failed%s", name, "");
    }
    close(dfd);
    fl_meta(fx, parent, name, e);
    fx->st->dirs++;
    return 0;
}

/*
 * WHAT: Copy a hardlink target when the filesystem refuses linkat.
 * WHY:  Cross-device targets remain representable without leaving partial files.
 * HOW:  Open source before destination, stream bytes, and remove failed output.
 */
static int fl_hardlink_copy(fl_ctx_t *fx, int target_parent,
                            const char *target, int parent, const char *name) {
    int     source = openat(target_parent, target,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int     destination = source < 0 ? -1 :
                          openat(parent, name, O_WRONLY | O_CREAT | O_TRUNC |
                                 O_NOFOLLOW | O_CLOEXEC, 0600);
    int     rc = -1;
    ssize_t got = 0;

    if (source >= 0 && destination >= 0) {
        rc = 0;
        while ((got = read(source, fx->copybuf, sizeof(fx->copybuf))) > 0) {
            if (write(destination, fx->copybuf, (size_t) got) != got) {
                rc = -1;
                break;
            }
            fx->st->bytes += got;
        }
        if (got < 0)
            rc = -1;
    }
    if (source >= 0)
        close(source);
    if (destination >= 0)
        close(destination);
    if (rc != 0 && destination >= 0)
        (void) fl_rm(fx, parent, name);
    return rc;
}

/* Hardlink: resolve the target through the same confined descent, then
 * linkat. A target that cannot be linked degrades to a byte copy. */
static int fl_hardlink(fl_ctx_t *fx, int parent, const char *name,
                       const brix_tar_entry_t *e) {
    char        tbuf[4096];
    const char *tcomps[FL_MAX_COMPS];
    int         tn, tparent;
    int         rc;

    tn = fl_components(fx, e->linkname, tbuf, sizeof(tbuf), tcomps,
                       FL_MAX_COMPS);
    if (tn <= 0)
        return tn == 0 ? fl_fail(fx, "hardlink '%s' targets the root%s",
                                 e->path, "") : -1;
    tparent = fl_descend(fx, tcomps, (size_t) tn - 1);
    if (tparent < 0)
        return -1;
    if (fl_rm(fx, parent, name) != 0) {
        close(tparent);
        return -1;
    }
    rc = linkat(tparent, tcomps[tn - 1], parent, name, 0) == 0 ? 0 :
         fl_hardlink_copy(fx, tparent, tcomps[tn - 1], parent, name);
    if (rc != 0)
        fl_fail(fx, "hardlink '%s' → '%s': target unlinkable and copy failed",
                e->path, e->linkname);
    close(tparent);
    if (rc == 0) {
        int mrc = fchmodat(parent, name, e->mode, 0);
        (void) mrc;                                  /* copy path lands 0600 */
        fl_meta(fx, parent, name, e);
        fx->st->links++;
    }
    return rc;
}

/*
 * WHAT: Materialize a non-whiteout tar entry in its already resolved parent.
 * WHY:  Entry routing and individual filesystem mutations are separate concerns.
 * HOW:  Dispatch regular, directory, symlink, hardlink, and special-file types.
 */
static int fl_materialize(fl_ctx_t *fx, int parent, const char *name,
                          const brix_tar_entry_t *entry) {
    int rc;

    switch (entry->type) {
    case BRIX_TAR_REG:
        return fl_reg(fx, parent, name, entry);
    case BRIX_TAR_DIR:
        return fl_dir(fx, parent, name, entry);
    case BRIX_TAR_SYMLINK:
        rc = fl_rm(fx, parent, name);
        if (rc == 0 && symlinkat(entry->linkname, parent, name) != 0)
            rc = fl_fail(fx, "symlink '%s' failed: %s", name,
                         strerror(errno));
        if (rc == 0) {
            fl_meta(fx, parent, name, entry);
            fx->st->links++;
        }
        return rc;
    case BRIX_TAR_HARDLINK:
        return fl_hardlink(fx, parent, name, entry);
    default:
        if (fx->o->strict)
            return fl_fail(fx, "special file '%s' refused under --strict%s",
                           entry->path, "");
        fx->st->skipped_special++;
        return brix_tar_skip(fx->tar);
    }
}

static int fl_whiteout(fl_ctx_t *fx, int parent, const char *target);
static int fl_opaque(fl_ctx_t *fx, int parent);

/*
 * WHAT: Apply an OCI whiteout, opaque marker, or ordinary materialized entry.
 * WHY:  Overlay control names take precedence over tar entry type semantics.
 * HOW:  Match reserved basenames, skip their bodies, otherwise dispatch type.
 */
static int fl_named_entry(fl_ctx_t *fx, int parent, const char *name,
                          const brix_tar_entry_t *entry) {
    int rc;

    if (strcmp(name, OCI_OPQ_NAME) == 0) {
        rc = fl_opaque(fx, parent);
        return rc == 0 ? brix_tar_skip(fx->tar) : rc;
    }
    if (strncmp(name, OCI_WH_PREFIX, sizeof(OCI_WH_PREFIX) - 1) == 0) {
        rc = fl_whiteout(fx, parent, name + sizeof(OCI_WH_PREFIX) - 1);
        return rc == 0 ? brix_tar_skip(fx->tar) : rc;
    }
    return fl_materialize(fx, parent, name, entry);
}

/* Whiteout: remove the named entry and drop the overlay marker so the
 * DELETE survives into a re-ingest changeset against a published base. */
static int fl_whiteout(fl_ctx_t *fx, int parent, const char *target) {
    char mark[300];
    int  fd, n;

    if (target[0] == '\0' || strcmp(target, ".") == 0 ||
        strcmp(target, "..") == 0 || fl_reserved(target))
        return fl_fail(fx, "refusing whiteout of '%s'%s", target, "");
    n = snprintf(mark, sizeof(mark), FL_WH_PREFIX "%s", target);
    if (n < 0 || (size_t) n >= sizeof(mark) || n > 255)
        return fl_fail(fx, "whiteout marker name too long for '%s'%s",
                       target, "");
    if (fl_rm(fx, parent, target) != 0)
        return -1;
    fd = openat(parent, mark, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                0644);
    if (fd < 0)
        return fl_fail(fx, "cannot drop whiteout marker '%s': %s", mark,
                       strerror(errno));
    close(fd);
    fx->st->whiteouts++;
    return 0;
}

/* Opaque: clear the directory (markers included — the opaque supersedes
 * them) and drop the opaque marker. */
static int fl_opaque(fl_ctx_t *fx, int parent) {
    int            dupfd = dup(parent);
    DIR           *d;
    struct dirent *de;
    int            fd;

    if (dupfd < 0 || (d = fdopendir(dupfd)) == NULL) {
        if (dupfd >= 0)
            close(dupfd);
        return fl_fail(fx, "cannot enumerate opaque dir%s%s", "", "");
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
    fd = openat(parent, FL_OPQ_NAME, O_WRONLY | O_CREAT | O_NOFOLLOW |
                O_CLOEXEC, 0644);
    if (fd < 0)
        return fl_fail(fx, "cannot drop opaque marker: %s%s",
                       strerror(errno), "");
    close(fd);
    fx->st->opaques++;
    return 0;
}

/* One tar entry through the D7.1 translation table. */
static int fl_entry(fl_ctx_t *fx, const brix_tar_entry_t *e) {
    char        buf[4096];
    const char *comps[FL_MAX_COMPS];
    const char *name;
    int         n, parent, rc;

    n = fl_components(fx, e->path, buf, sizeof(buf), comps, FL_MAX_COMPS);
    if (n < 0)
        return -1;
    if (n == 0)             /* the layer root ("./"): nothing to write */
        return brix_tar_skip(fx->tar);

    name = comps[n - 1];
    /* eStargz's own bookkeeping entries, which the format reserves at the
     * archive root only. A lazy-pull snapshotter consumes them and hides
     * them; a publisher that materializes the whole rootfs must drop them,
     * or an eStargz layer flattens to a rootfs its non-stargz original does
     * not have. Dropping them cannot change the layer's diff_id — that is
     * hashed over the decompressed stream before any entry is interpreted.
     * The names come from the TU that WRITES them (stargz.h, D15.8), so the
     * reader and the writer cannot drift on what is reserved. */
    if (n == 1 && brix_stargz_is_meta(name)) {
        fx->st->skipped_toc++;
        return brix_tar_skip(fx->tar);
    }

    parent = fl_descend(fx, comps, (size_t) n - 1);
    if (parent < 0)
        return -1;

    rc = fl_named_entry(fx, parent, name, e);
    close(parent);
    return rc;
}

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
