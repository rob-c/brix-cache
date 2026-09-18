/*
 * src/platform/darwin/path_wrapper.c - Darwin path primitives beneath the VFS seam
 *
 * WHAT: The openat2(2) emulation (a userspace walk), the confined stat,
 *       renameatx_np and the birth time declared in platform_api_posix.h.
 * WHY:  Darwin has no openat2/renameat2/statx; before the PAL owned this the
 *       Darwin arm of brix_open_beneath was a bare openat and "../secret"
 *       escaped every export. The walk gives the Linux verdicts.
 * HOW:  darwin_openat_resolve walks `rel` one component at a time from rootfd
 *       on an fd stack, opening every step O_NOFOLLOW so the kernel never
 *       follows a link on its own; ".." pops (never above rootfd), a symlink
 *       is expanded by readlinkat and re-walked from its directory. BENEATH:
 *       ".." at the root and an absolute target are EXDEV. IN_ROOT: ".." at
 *       the root stays there and an absolute target restarts at rootfd.
 *       NO_SYMLINKS: any link is ELOOP. NO_MAGICLINKS is a no-op (no /proc).
 *       With `st_out` the walk is a confined stat: the final component is
 *       fstatat()ed (no fd, no permission needed on the object, so a 0000-mode
 *       file stats as under Linux O_PATH). Bounded: 40 link hops (the kernel
 *       limit) and a fixed fd-stack depth; no goto, early-return only.
 */

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_PLATFORM_DARWIN

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stdio.h>      /* renameatx_np, RENAME_EXCL / RENAME_SWAP */
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * darwin_openat_resolve — userspace emulation of the openat2(2) resolve
 * semantics on a host without the syscall (macOS).
 *
 * WHAT: Walks `rel` one component at a time from rootfd, keeping the chain of
 *       directory fds as a stack, and opens the final component with O_NOFOLLOW
 *       so no step ever trusts the kernel's own symlink following.  ".." pops
 *       the stack (never above rootfd); a symlink is expanded by readlinkat()
 *       and re-walked from the directory it was found in.
 * WHY:  The previous Darwin branch was a bare openat(2): "../secret" and an
 *       absolute symlink target escaped the export (test_dashboard_files
 *       traversal, every VFS confinement contract).  The emulation gives the
 *       same verdicts as RESOLVE_BENEATH / RESOLVE_IN_ROOT / RESOLVE_NO_SYMLINKS
 *       (EXDEV / ELOOP) so callers and tests need no platform branches.
 * HOW:  BENEATH: ".." at the root and an absolute link target are EXDEV.
 *       IN_ROOT: ".." at the root stays at the root and an absolute link target
 *       restarts from rootfd (chroot-style).  NO_SYMLINKS: any link is ELOOP.
 *       NO_MAGICLINKS has no Darwin counterpart (no /proc) and is accepted as a
 *       no-op.  With `st_out` the walk is a confined stat: the final component
 *       is fstatat()ed (no fd, no permission needed on the object itself, so a
 *       0000-mode file stats as it does under Linux O_PATH) and, unless
 *       O_NOFOLLOW asks for the link itself, a trailing symlink is expanded like
 *       any other.  Bounded: 40 link hops (the kernel's limit) and a fixed
 *       fd-stack depth; no goto, early-return only.
 */
#define DARWIN_RESOLVE_MAX_HOPS   40
#define DARWIN_RESOLVE_MAX_DEPTH  128

/* Walk state: the fd stack (stack[0] is the borrowed rootfd), the caller's
 * request, and the cursor into the unresolved remainder of `path`. */
typedef struct {
    int          stack[DARWIN_RESOLVE_MAX_DEPTH];
    int          sp;
    int          hops;
    int          flags;
    mode_t       mode;
    uint64_t     resolve;
    struct stat *st_out;
    char         path[PATH_MAX];
    char         comp[NAME_MAX + 1];
    const char  *p;            /* unresolved remainder */
    const char  *raw;          /* remainder after comp, incl. its slashes */
    const char  *rest;         /* remainder after comp's slashes */
    int          slash_after;  /* "name/": the object must be a directory */
    int          result;       /* the walk's answer once a step returns WALK_DONE */
} darwin_walk_t;

enum { WALK_NEXT, WALK_FOLLOW, WALK_DONE };

/* Close every fd the walk opened, restore the caller-facing errno and record
 * -1: the single failure exit. */
static int
walk_fail(darwin_walk_t *w, int err)
{
    while (w->sp > 0) {
        close(w->stack[w->sp]);
        w->sp--;
    }
    errno = err;
    w->result = -1;
    return WALK_DONE;
}

/* Close the walk's fds but keep `fd` (the result) open. */
static int
walk_done(darwin_walk_t *w, int fd)
{
    int err = errno;

    while (w->sp > 0) {
        close(w->stack[w->sp]);
        w->sp--;
    }
    errno = err;
    w->result = fd;
    return WALK_DONE;
}

/* Splice a symlink target in front of the unresolved remainder of the path:
 * path = target "/" rest.  ENAMETOOLONG if it does not fit. */
static int
darwin_resolve_splice(int dirfd, const char *comp, const char *rest,
    char *path, size_t cap)
{
    char    target[PATH_MAX];
    char    scratch[PATH_MAX];
    ssize_t n;
    size_t  rest_len;

    n = readlinkat(dirfd, comp, target, sizeof(target) - 1); /* vfs-seam-allow: SEAM_CORRECT - PAL confinement walk beneath brix_open_beneath */
    if (n < 0) {
        return -1;
    }
    target[n] = '\0';
    rest_len = strlen(rest);
    if ((size_t) n + 1 + rest_len + 1 > cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    /* rest may alias the tail of path: assemble in a scratch buffer first.
     * A TRAILING link has no remainder: splice the bare target, never
     * "target/" — the slash would demand a directory (ENOTDIR for a link to
     * a regular file, which stat/open must follow like stock). */
    memcpy(scratch, target, (size_t) n);
    if (rest_len == 0) {
        scratch[n] = '\0';
        memcpy(path, scratch, (size_t) n + 1);
        return 0;
    }
    scratch[n] = '/';
    memcpy(scratch + n + 1, rest, rest_len + 1);
    memcpy(path, scratch, (size_t) n + 1 + rest_len + 1);
    return 0;
}

/* The path named a directory already on the stack: open or stat it. */
static int
walk_end(darwin_walk_t *w)
{
    int fd;

    if (w->st_out != NULL) {
        fd = fstat(w->stack[w->sp], w->st_out); /* vfs-seam-allow: SEAM_CORRECT - PAL confinement walk beneath brix_open_beneath */
        return walk_done(w, fd);
    }
    fd = openat(w->stack[w->sp], ".", w->flags | O_CLOEXEC, w->mode); /* vfs-seam-allow: SEAM_CORRECT - PAL confinement walk beneath brix_open_beneath */
    return walk_done(w, fd);
}

/* Cut the next component out of the remainder into w->comp. */
static int
walk_take_component(darwin_walk_t *w)
{
    size_t len = strcspn(w->p, "/");

    if (len > NAME_MAX) {
        return walk_fail(w, ENAMETOOLONG);
    }
    memcpy(w->comp, w->p, len);
    w->comp[len] = '\0';
    w->raw = w->p + len;
    w->slash_after = (*w->raw == '/');
    w->rest = w->raw;
    while (*w->rest == '/') {
        w->rest++;
    }
    return WALK_NEXT;
}

/* "." is skipped; ".." pops the stack and is EXDEV at the root unless the
 * caller asked for chroot-style RESOLVE_IN_ROOT. Returns 0 when comp is a
 * real name the caller must resolve. */
static int
walk_dots(darwin_walk_t *w, int *step)
{
    if (w->comp[0] != '.') {
        return 0;
    }
    if (w->comp[1] == '\0') {
        w->p = w->rest;
        *step = WALK_NEXT;
        return 1;
    }
    if (w->comp[1] != '.' || w->comp[2] != '\0') {
        return 0;
    }
    if (w->sp > 0) {
        close(w->stack[w->sp]);
        w->sp--;
    } else if (!(w->resolve & RESOLVE_IN_ROOT)) {
        *step = walk_fail(w, EXDEV);
        return 1;
    }
    w->p = w->rest;
    *step = WALK_NEXT;
    return 1;
}

/* Confined stat of the final component: the object itself is never opened.
 * "name/" follows a link even under O_NOFOLLOW (as lstat(2) does) and then
 * insists on a directory, matching openat2 / stock. */
static int
walk_final_stat(darwin_walk_t *w)
{
    if (fstatat(w->stack[w->sp], w->comp, w->st_out, AT_SYMLINK_NOFOLLOW) != 0) { /* vfs-seam-allow: SEAM_CORRECT - PAL confinement walk beneath brix_open_beneath */
        return walk_fail(w, errno);
    }
    if (S_ISLNK(w->st_out->st_mode)
        && (!(w->flags & O_NOFOLLOW) || w->slash_after))
    {
        return WALK_FOLLOW;   /* a trailing symlink the caller wants followed */
    }
    if (w->slash_after && !S_ISDIR(w->st_out->st_mode)) {
        return walk_fail(w, ENOTDIR);
    }
    return walk_done(w, 0);
}

static int walk_refusal_is_link(darwin_walk_t *w, int err);

/* Open the final component; never let the kernel follow a trailing link. */
static int
walk_final_open(darwin_walk_t *w)
{
    int fd = openat(w->stack[w->sp], w->comp, /* vfs-seam-allow: SEAM_CORRECT - PAL confinement walk beneath brix_open_beneath */
                    w->flags | O_NOFOLLOW | O_CLOEXEC
                    | (w->slash_after ? O_DIRECTORY : 0), w->mode);
    int err = errno;

    if (fd >= 0 || !walk_refusal_is_link(w, err)) {
        errno = err;
        return walk_done(w, fd);
    }
    if ((w->flags & O_NOFOLLOW) && !w->slash_after) {
        return walk_fail(w, ELOOP);
    }
    return WALK_FOLLOW;
}

/* Descend into an intermediate directory, pushing its fd on the stack. */
/* Whether the component just refused with `err` is really a symlink that the
 * walk should expand.  Linux says ELOOP for an O_NOFOLLOW open of a link;
 * Darwin says ELOOP without O_DIRECTORY but ENOTDIR with it, so the errno
 * alone cannot tell a link from a plain file — lstat the component. */
static int
walk_refusal_is_link(darwin_walk_t *w, int err)
{
    struct stat st;

    if (err != ELOOP && err != ENOTDIR) {
        return 0;
    }
    return fstatat(w->stack[w->sp], w->comp, &st, AT_SYMLINK_NOFOLLOW) == 0 /* vfs-seam-allow: SEAM_CORRECT - PAL confinement walk beneath brix_open_beneath */
           && S_ISLNK(st.st_mode);
}

static int
walk_descend(darwin_walk_t *w)
{
    int fd = openat(w->stack[w->sp], w->comp, /* vfs-seam-allow: SEAM_CORRECT - PAL confinement walk beneath brix_open_beneath */
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int err;

    if (fd < 0) {
        err = errno;
        return walk_refusal_is_link(w, err) ? WALK_FOLLOW : walk_fail(w, err);
    }
    if (w->sp + 1 >= DARWIN_RESOLVE_MAX_DEPTH) {
        close(fd);
        return walk_fail(w, ENAMETOOLONG);
    }
    w->stack[++w->sp] = fd;
    w->p = w->rest;
    return WALK_NEXT;
}

/* `comp` is a symlink the caller allows us to follow: splice its target in
 * front of the remainder and re-walk from the directory it was found in.
 * BENEATH: an absolute target is EXDEV; IN_ROOT: it restarts at the root. */
static int
walk_follow_link(darwin_walk_t *w)
{
    if (w->resolve & RESOLVE_NO_SYMLINKS) {
        return walk_fail(w, ELOOP);
    }
    if (++w->hops > DARWIN_RESOLVE_MAX_HOPS) {
        return walk_fail(w, ELOOP);
    }
    if (darwin_resolve_splice(w->stack[w->sp], w->comp, w->raw, w->path,
                              sizeof(w->path)) != 0)
    {
        return walk_fail(w, errno);
    }
    w->p = w->path;
    if (w->path[0] != '/') {
        return WALK_NEXT;
    }
    if (!(w->resolve & RESOLVE_IN_ROOT)) {
        return walk_fail(w, EXDEV);
    }
    while (w->sp > 0) {   /* chroot-style: an absolute target restarts at the root */
        close(w->stack[w->sp]);
        w->sp--;
    }
    return WALK_NEXT;
}

/* One component: resolve it, or report that it is a link to follow. */
static int
walk_component(darwin_walk_t *w)
{
    int step;

    step = walk_take_component(w);
    if (step != WALK_NEXT) {
        return step;
    }
    if (walk_dots(w, &step)) {
        return step;
    }
    if (*w->rest != '\0') {
        return walk_descend(w);
    }
    return (w->st_out != NULL) ? walk_final_stat(w) : walk_final_open(w);
}

static int
darwin_openat_resolve(int rootfd, const char *rel, int flags, mode_t mode,
    uint64_t resolve, struct stat *st_out)
{
    darwin_walk_t w;
    int           step;

    if (strlen(rel) >= sizeof(w.path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memset(&w, 0, sizeof(w));
    memcpy(w.path, rel, strlen(rel) + 1);
    w.stack[0] = rootfd;
    w.flags    = flags;
    w.mode     = mode;
    w.resolve  = resolve;
    w.st_out   = st_out;
    w.p        = w.path;

    for ( ;; ) {
        while (*w.p == '/') {
            w.p++;
        }
        step = (*w.p == '\0') ? walk_end(&w) : walk_component(&w);
        if (step == WALK_FOLLOW) {
            step = walk_follow_link(&w);
        }
        if (step == WALK_DONE) {
            return w.result;
        }
    }
}

int
brix_plat_openat2(int rootfd, const char *rel, int flags, mode_t mode,
    uint64_t resolve)
{
    if (flags & O_CREAT) {
        mode &= 07777;
    }
    return darwin_openat_resolve(rootfd, rel[0] == '\0' ? "." : rel,
                                 flags | O_CLOEXEC, mode, resolve, NULL);
}

int
brix_plat_openat2_available(void)
{
    return 1;   /* the walk is always present */
}

int
brix_plat_stat_resolve(int rootfd, const char *rel, int nofollow,
    uint64_t resolve, struct stat *st)
{
    return darwin_openat_resolve(rootfd, rel[0] == '\0' ? "." : rel,
                                 nofollow ? O_NOFOLLOW : 0, 0, resolve, st);
}

/* Darwin's unlinkat(2) rejects a directory (no AT_REMOVEDIR) with EPERM
 * where Linux answers EISDIR; callers key their "unlink a file, rmdir a
 * directory" fallback on EISDIR, so restore it when the name is a dir. */
int
brix_plat_unlinkat(int dirfd, const char *name, int flags)
{
    struct stat st;
    int         saved;

    if (unlinkat(dirfd, name, flags) == 0) { /* vfs-seam-allow: SEAM_CORRECT - PAL unlink primitive beneath the VFS */
        return 0;
    }
    if (errno != EPERM || (flags & AT_REMOVEDIR)) {
        return -1;
    }
    saved = errno;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 /* vfs-seam-allow: SEAM_CORRECT - PAL unlink primitive beneath the VFS */
        && S_ISDIR(st.st_mode))
    {
        errno = EISDIR;
        return -1;
    }
    errno = saved;
    return -1;
}

int
brix_plat_renameat2(int sfd, const char *sbase, int dfd, const char *dbase,
    unsigned int flags)
{
    unsigned int nflags = 0;

    if (flags & BRIX_RENAME_NOREPLACE) {
        nflags |= RENAME_EXCL;
    }
    if (flags & BRIX_RENAME_EXCHANGE) {
        nflags |= RENAME_SWAP;
    }
    if (renameatx_np(sfd, sbase, dfd, dbase, nflags) == 0) { /* vfs-seam-allow: SEAM_CORRECT - PAL rename primitive beneath the VFS */
        return 0;
    }
    if (errno == ENOTSUP || errno == EINVAL) {
        errno = ENOTSUP;
    }
    return -1;
}

int
brix_plat_fstatat_btime(int dirfd, const char *name, int flags,
    struct stat *st, time_t *btime)
{
    if (fstatat(dirfd, name, st, flags) != 0) { /* vfs-seam-allow: SEAM_CORRECT - PAL metadata primitive beneath the VFS */
        return -1;
    }
    *btime = st->st_birthtimespec.tv_sec;
    return 0;
}

#endif /* BRIX_PLATFORM_DARWIN */
