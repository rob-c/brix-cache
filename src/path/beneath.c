/*
 * beneath.c — kernel-enforced path-confinement primitives (openat2/RESOLVE_BENEATH).
 *
 * WHAT: Implements the "beneath" API declared in beneath.h: a small set of
 *       filesystem primitives (open/stat/unlink/mkdir/rename/link) that operate
 *       on a client-supplied reqpath but are GUARANTEED never to escape a
 *       per-worker O_PATH rootfd anchored on the export root. The core wrapper
 *       do_openat2() drives the openat2(2) syscall with RESOLVE_BENEATH |
 *       RESOLVE_NO_MAGICLINKS; xrootd_open_beneath()/xrootd_stat_beneath() use it
 *       directly, while the path-MUTATING ops route through beneath_open_parent().
 *
 * WHY:  This layer IS the confinement boundary (see op_path.c: the lexical
 *       'resolved' string is for ACL/logging only — it is NOT the security
 *       boundary). XRootD/WebDAV/S3 clients send arbitrary paths; the kernel,
 *       not nginx code, must refuse any traversal out of the export root.
 *       RESOLVE_BENEATH rejects absolute paths, "..", and symlinks that would
 *       leave the rootfd subtree, atomically and without TOCTOU races.
 *       RESOLVE_NO_MAGICLINKS additionally blocks /proc/<pid>/fd-style escapes.
 *       An escape attempt surfaces to callers as EXDEV/ELOOP, which the error
 *       mapper turns into kXR_NotAuthorized / HTTP 403.
 *
 * HOW:  openat2(2) is a hard build requirement (the #error guards below fail the
 *       compile on kernels/headers < 5.6). do_openat2() masks O_CREAT mode bits
 *       to 07777 because openat2() — unlike open(2) — rejects S_IFMT type bits.
 *       The crucial subtlety: RESOLVE_BENEATH protects ONLY the openat2() call
 *       itself; the legacy *at() syscalls (mkdirat/unlinkat/renameat/linkat) do
 *       NOT honour it, so a symlink in an intermediate component could be
 *       followed out of the root. beneath_open_parent() closes that hole by
 *       resolving the PARENT directory under RESOLVE_BENEATH and then performing
 *       the *at() op on the final component name only (which those syscalls do
 *       not dereference as a symlink for delete/rename/create).
 */
#include "../ngx_xrootd_module.h"
#include "beneath.h"
#include "../impersonate/impersonate.h"

#include <sys/syscall.h>
#include <linux/openat2.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

/*
 * IMPERSONATION SEAM (phase 40).
 *
 * When `xrootd_impersonation map` is active and a per-request principal is set,
 * xrootd_imp_client_active() returns true and the confined helpers below delegate
 * the open/metadata syscall to the privileged broker, which performs it as the
 * mapped UNIX user under its OWN rootfd (the kernel enforces RESOLVE_BENEATH
 * there too).  In that mode the worker's local `rootfd` argument is unused — the
 * broker is the confinement authority — but the helper signatures are unchanged,
 * so no caller is touched.  When impersonation is off (the default) or no
 * principal is set, xrootd_imp_client_active() is false and the original local
 * openat2 path below runs exactly as before.
 */

#ifndef RESOLVE_BENEATH
#error "openat2(2) with RESOLVE_BENEATH required — kernel headers too old (need >= 5.6)"
#endif

#ifndef SYS_openat2
#error "SYS_openat2 not defined — kernel headers too old (need >= 5.6)"
#endif

/*
 * Open an O_PATH directory fd on root_canon to anchor every beneath() call.
 * O_PATH gives a traversal-only handle (no read/write to the dir itself),
 * O_DIRECTORY enforces it is a directory, O_CLOEXEC stops fd leaks across exec.
 * Returns fd >= 0 (caller closes) or -1 with errno set. Hot paths should reuse
 * a persistent per-worker rootfd rather than calling this per request.
 */
int
xrootd_beneath_open_root(const char *root_canon)
{
    return open(root_canon, O_PATH | O_DIRECTORY | O_CLOEXEC);
}

/*
 * do_openat2 — the single chokepoint through which every confined open passes.
 * `rel` is a root-RELATIVE path (no leading '/'); RESOLVE_BENEATH treats rootfd
 * as the top of the tree and refuses to follow anything — "..", absolute paths,
 * or symlinks — that would resolve outside it, returning EXDEV/ELOOP instead.
 * RESOLVE_NO_MAGICLINKS additionally blocks /proc/<pid>/fd magic symlinks.
 * NOTE: this guarantee applies ONLY to the open performed here; mutating *at()
 * ops must pre-resolve their parent via beneath_open_parent() (see below).
 */
static int
do_openat2(int rootfd, const char *rel, int flags, mode_t mode)
{
    struct open_how how;
    /* empty rel means root dir itself; "." opens the rootfd directory */
    if (rel[0] == '\0') { rel = "."; }
    ngx_memzero(&how, sizeof(how));
    how.flags   = (uint64_t)(flags | O_CLOEXEC);
    /* RESOLVE_BENEATH: kernel confines resolution to the rootfd subtree.
     * RESOLVE_NO_MAGICLINKS: refuse /proc/PID/fd and other magic-link escapes. */
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    /*
     * openat2() is stricter than open()/openat(): it rejects (EINVAL) any
     * how.mode bit outside 07777.  Callers legitimately pass a full struct
     * stat st_mode (e.g. staged_file copying a source's permissions), which
     * carries the S_IFMT type bits.  Mask to the permission bits, exactly as
     * open(2) does by ignoring the type bits, so a struct-stat mode is accepted.
     */
    if (flags & O_CREAT) { how.mode = (uint64_t)(mode & 07777); }
    return (int)syscall(SYS_openat2, rootfd, rel, &how, sizeof(how));
}

int
xrootd_open_beneath(int rootfd, const char *reqpath, int flags, mode_t mode)
{
    if (xrootd_imp_client_active()) {
        return xrootd_imp_open(reqpath, flags, mode);
    }
    return do_openat2(rootfd, xrootd_beneath_rel(reqpath), flags, mode);
}

int
xrootd_stat_beneath(int rootfd, const char *reqpath, struct stat *st)
{
    int fd, rc;

    if (xrootd_imp_client_active()) {
        return xrootd_imp_stat(reqpath, st, 0 /* follow */);
    }
    /* O_PATH without O_NOFOLLOW: follow symlinks, but RESOLVE_BENEATH blocks
     * any attempt to escape the root — escapes return EXDEV. */
    fd = do_openat2(rootfd, xrootd_beneath_rel(reqpath), O_PATH, 0);
    if (fd < 0) { return -1; }
    rc = fstat(fd, st);
    close(fd);
    return rc;
}

int
xrootd_lstat_beneath(int rootfd, const char *reqpath, struct stat *st)
{
    int fd, rc;

    if (xrootd_imp_client_active()) {
        return xrootd_imp_stat(reqpath, st, 1 /* nofollow */);
    }
    /* O_PATH | O_NOFOLLOW: do NOT follow a trailing symlink, so fstat() reports
     * the link itself (lstat semantics). RESOLVE_BENEATH still confines the path;
     * intermediate symlinks are resolved/blocked exactly as in stat_beneath. */
    fd = do_openat2(rootfd, xrootd_beneath_rel(reqpath), O_PATH | O_NOFOLLOW, 0);
    if (fd < 0) { return -1; }
    rc = fstat(fd, st);
    close(fd);
    return rc;
}

/*
 * SECURITY: the *at() family (mkdirat / unlinkat / renameat / linkat) does NOT
 * honour RESOLVE_BENEATH — only openat2() does.  Handing them a multi-component
 * relative path lets a symlink in an INTERMEDIATE component (e.g. /link -> /etc,
 * then "/link/x") be followed straight out of the export root.  openat2()'s
 * RESOLVE_BENEATH only guards the open itself, so for every path-MUTATING op we
 * must resolve the PARENT directory ourselves under RESOLVE_BENEATH and then
 * operate on the final component name only.  The final component is safe for
 * these ops: unlinkat/renameat never follow a trailing symlink, and mkdir/link
 * create a fresh name.
 *
 * beneath_open_parent() returns an O_PATH fd on the confined parent of reqpath
 * (caller closes) and points *base at the final component (into reqpath).
 * pbuf must be >= PATH_MAX.  Returns -1 (errno: EXDEV/ELOOP on escape).
 */
static int
beneath_open_parent(int rootfd, const char *reqpath,
                    char *pbuf, size_t pbufsz, const char **base)
{
    const char *rel = xrootd_beneath_rel(reqpath);   /* strip leading '/'s */
    const char *slash = strrchr(rel, '/');
    size_t      plen;

    if (slash == NULL || slash == rel) {
        /* single component, or only a leading-slash remnant → parent is root */
        *base = (slash == NULL) ? rel : slash + 1;
        return do_openat2(rootfd, ".", O_PATH | O_DIRECTORY, 0);
    }

    *base = slash + 1;
    plen  = (size_t) (slash - rel);
    if (plen >= pbufsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(pbuf, rel, plen);
    pbuf[plen] = '\0';
    return do_openat2(rootfd, pbuf, O_PATH | O_DIRECTORY, 0);
}

int
xrootd_unlink_beneath(int rootfd, const char *reqpath, int is_dir)
{
    char         pbuf[PATH_MAX];
    const char  *base;
    int          pfd, rc, e;

    if (xrootd_imp_client_active()) {
        return xrootd_imp_unlink(reqpath, is_dir);
    }

    pfd = beneath_open_parent(rootfd, reqpath, pbuf, sizeof(pbuf), &base);
    if (pfd < 0) { return -1; }
    if (base[0] == '\0') { close(pfd); errno = EINVAL; return -1; }
    rc = unlinkat(pfd, base, is_dir ? AT_REMOVEDIR : 0);
    e = errno; close(pfd); errno = e;
    return rc;
}

int
xrootd_mkdir_beneath(int rootfd, const char *reqpath, mode_t mode)
{
    char         pbuf[PATH_MAX];
    const char  *base;
    int          pfd, rc, e;

    if (xrootd_imp_client_active()) {
        return xrootd_imp_mkdir(reqpath, mode);
    }

    pfd = beneath_open_parent(rootfd, reqpath, pbuf, sizeof(pbuf), &base);
    if (pfd < 0) { return -1; }
    if (base[0] == '\0') { close(pfd); errno = EINVAL; return -1; }
    rc = mkdirat(pfd, base, mode);
    e = errno; close(pfd); errno = e;
    return rc;
}

int
xrootd_rename_beneath(int rootfd, const char *src, const char *dst)
{
    char         sbuf[PATH_MAX], dbuf[PATH_MAX];
    const char  *sbase, *dbase;
    int          sfd, dfd, rc, e;

    if (xrootd_imp_client_active()) {
        return xrootd_imp_rename(src, dst);
    }

    sfd = beneath_open_parent(rootfd, src, sbuf, sizeof(sbuf), &sbase);
    if (sfd < 0) { return -1; }
    dfd = beneath_open_parent(rootfd, dst, dbuf, sizeof(dbuf), &dbase);
    if (dfd < 0) { e = errno; close(sfd); errno = e; return -1; }
    if (sbase[0] == '\0' || dbase[0] == '\0') {
        close(sfd); close(dfd); errno = EINVAL; return -1;
    }
    rc = renameat(sfd, sbase, dfd, dbase);
    e = errno; close(sfd); close(dfd); errno = e;
    return rc;
}

int
xrootd_link_beneath(int rootfd, const char *src, const char *dst)
{
    char         sbuf[PATH_MAX], dbuf[PATH_MAX];
    const char  *sbase, *dbase;
    int          sfd, dfd, rc, e;

    if (xrootd_imp_client_active()) {
        return xrootd_imp_link(src, dst);
    }

    sfd = beneath_open_parent(rootfd, src, sbuf, sizeof(sbuf), &sbase);
    if (sfd < 0) { return -1; }
    dfd = beneath_open_parent(rootfd, dst, dbuf, sizeof(dbuf), &dbase);
    if (dfd < 0) { e = errno; close(sfd); errno = e; return -1; }
    if (sbase[0] == '\0' || dbase[0] == '\0') {
        close(sfd); close(dfd); errno = EINVAL; return -1;
    }
    rc = linkat(sfd, sbase, dfd, dbase, 0);
    e = errno; close(sfd); close(dfd); errno = e;
    return rc;
}
