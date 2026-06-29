#ifndef XROOTD_PATH_BENEATH_H
#define XROOTD_PATH_BENEATH_H

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <stddef.h>

/*
 * Kernel-enforced path confinement API.
 *
 * Every function takes a persistent rootfd (O_PATH fd opened once per worker
 * on the export root) and a client-supplied reqpath. The kernel's
 * RESOLVE_BENEATH flag ensures no path can escape the root directory tree —
 * symlinks, ".." traversal, and magic-links are all blocked atomically.
 *
 * EXDEV from any of these functions means an escape attempt was blocked;
 * callers must map this to kXR_NotAuthorized (see xrootd_kxr_from_errno).
 */

/*
 * Open an O_PATH directory fd on root_canon to anchor the beneath API.
 *
 * Prefer a *persistent* rootfd (stream conf->rootfd / HTTP conf->common.rootfd,
 * opened once per worker) on hot or per-request paths. This per-call opener is
 * only for the infrequent shared-namespace-mutation helpers (compat/) that
 * receive a root_canon string but not a conf — it matches the cost of the legacy
 * xrootd_*_confined_canon() functions it replaces (which also opened a rootfd
 * per call). Returns an fd >= 0 (close with close()) or -1 (errno set).
 */
int xrootd_beneath_open_root(const char *root_canon);

/* Open a file under kernel confinement.
 * flags: O_RDONLY / O_WRONLY / O_RDWR / O_CREAT / O_PATH etc.
 * mode:  permission bits; only meaningful when O_CREAT is set. */
int xrootd_open_beneath(int rootfd, const char *reqpath, int flags, mode_t mode);

/* Stat a file via a temporary O_PATH open (follows a trailing symlink, confined). */
int xrootd_stat_beneath(int rootfd, const char *reqpath, struct stat *st);
/* lstat: O_PATH | O_NOFOLLOW — does NOT follow a trailing symlink, so the result
 * describes the link itself. Used by kXR_stat with the kXR_statNoFollow option. */
int xrootd_lstat_beneath(int rootfd, const char *reqpath, struct stat *st);

/* Open a directory stream under kernel confinement (RESOLVE_IN_ROOT): a trailing
 * in-export symlink is followed chroot-style, an escaping one is rejected
 * (EXDEV/ENOENT), unlike a bare opendir() which follows an outward link out of
 * the root. Returns a DIR* (caller closedir()s it) or NULL with errno set. */
DIR *xrootd_opendir_beneath(int rootfd, const char *reqpath);

/* Remove a file (is_dir=0) or empty directory (is_dir=1). */
int xrootd_unlink_beneath(int rootfd, const char *reqpath, int is_dir);

/* Create a directory. */
int xrootd_mkdir_beneath(int rootfd, const char *reqpath, mode_t mode);

/* Rename src to dst within the same root. */
int xrootd_rename_beneath(int rootfd, const char *src, const char *dst);

/* Atomic create-if-absent rename: renameat2(RENAME_NOREPLACE).  Returns -1 with
 * errno==EEXIST when dst already exists; falls back to a non-atomic rename
 * (logged once) on kernels/filesystems lacking RENAME_NOREPLACE. */
int xrootd_rename_beneath_excl(int rootfd, const char *src, const char *dst);

/* Hard-link src to dst within the same root. */
int xrootd_link_beneath(int rootfd, const char *src, const char *dst);

/* Strip all leading '/' from a client path, returning a relative path.
 * Returns "" for root paths like "/", "//", "///"; callers that pass
 * the result to openat2 must substitute "." (see do_openat2 in beneath.c). */
static inline const char *
xrootd_beneath_rel(const char *reqpath)
{
    while (reqpath[0] == '/') { reqpath++; }
    return reqpath;
}

/*
 * xrootd_beneath_strip_root — turn an absolute, already-canonical path that
 * lives under root_canon into the root-relative tail the beneath API expects.
 *
 * This is the bridge for migrating the legacy xrootd_*_confined_canon(root_canon,
 * abspath) callers to xrootd_*_beneath(rootfd, rel): those functions already
 * stripped root_canon internally before openat2, so doing it here is
 * behaviour-preserving. It ALSO re-implements their within-root guard — a
 * NULL return means abspath is not under root_canon (the old code's
 * xrootd_path_within_root() rejection), and the caller must treat it as an
 * escape (errno=EXDEV) and NOT fall through to a raw syscall.
 *
 * Returns a pointer into abspath (starting at the '/' after root_canon, or the
 * terminating NUL when abspath == root_canon), or NULL if abspath is not within
 * root_canon. The trailing-character check rejects a sibling like "/rootX" that
 * merely shares the "/root" string prefix.
 */
static inline const char *
xrootd_beneath_strip_root(const char *root_canon, const char *abspath)
{
    size_t rlen = strlen(root_canon);

    if (strncmp(abspath, root_canon, rlen) != 0) {
        return (const char *) 0;
    }
    if (abspath[rlen] == '\0' || abspath[rlen] == '/') {
        return abspath + rlen;   /* == root, or a real path boundary under root */
    }
    return (const char *) 0;     /* prefix match but not a '/' boundary */
}

/* Build the full filesystem path for auth_gate: root_canon + "/" + reqpath_rel.
 * Replaces realpath()-derived 'resolved' for ACL prefix matching.
 * Returns number of bytes written (excluding NUL); buf is valid when < (int)bufsz. */
static inline int
xrootd_beneath_full_path(const char *root_canon, const char *reqpath,
                          char *buf, size_t bufsz)
{
    const char *rel  = xrootd_beneath_rel(reqpath);
    size_t      rlen = strlen(root_canon);
    size_t      plen = (rel[0] != '\0') ? strlen(rel) : 0;
    size_t      need = rlen + (plen ? 1 + plen : 0);

    if (need + 1 > bufsz) {
        if (bufsz > 0) buf[0] = '\0';
        return (int) need;
    }

    memcpy(buf, root_canon, rlen);
    if (plen) {
        buf[rlen] = '/';
        memcpy(buf + rlen + 1, rel, plen + 1);
    } else {
        buf[rlen] = '\0';
    }
    return (int) need;
}

#endif /* XROOTD_PATH_BENEATH_H */
