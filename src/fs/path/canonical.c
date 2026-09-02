#include "core/ngx_brix_module.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

/* Resolve `root` to its canonical absolute path (realpath) into the caller's
 * buffer.  Returns NGX_OK, or NGX_ERROR (emerg-logged) on failure. */
int
brix_get_canonical_root(ngx_log_t *log, const ngx_str_t *root,
                          char *root_canon, size_t root_canon_sz)
{
    char root_buf[PATH_MAX];

    if (root == NULL || root->len == 0 || root->len >= sizeof(root_buf)) {
        return 0;
    }

    ngx_memcpy(root_buf, root->data, root->len);
    root_buf[root->len] = '\0';

    if (realpath(root_buf, root_canon) == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "brix: cannot canonicalize root \"%s\"", root_buf);
        return 0;
    }

    if (ngx_strnlen((u_char *) root_canon, root_canon_sz) >= root_canon_sz) {
        return 0;
    }

    return 1;
}

/*
 * brix_realpath_existing — realpath(3) semantics for an existing path,
 * priced for the miss.
 *
 * glibc realpath() readlink-walks every component, so a caller probing a
 * path that usually does NOT exist (the stat handler's symlink-follow
 * fallback) pays ~one readlink per directory level just to learn ENOENT.
 * open(O_PATH) makes the kernel do the whole resolution in one syscall —
 * a miss costs exactly that failing open — and the canonical result is
 * read back through /proc/self/fd.  Falls back to realpath(3) when /proc
 * is not mounted.  Returns `resolved` (a PATH_MAX buffer) or NULL with
 * errno describing the failing resolution.
 */
char *
brix_realpath_existing(const char *path, char *resolved)
{
    char    proc[48];
    ssize_t n;
    int     fd, e;

    fd = open(path, O_PATH | O_CLOEXEC);   /* vfs-seam-allow: SEAM_CORRECT — canonicaliser core: kernel-side path resolution, no data plane */
    if (fd < 0) {
        return NULL;
    }

    (void) snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    n = readlink(proc, resolved, PATH_MAX - 1);
    e = errno;
    close(fd);

    if (n <= 0 || resolved[0] != '/') {
        if (n >= 0 || e == ENOENT) {
            /* /proc absent (or gave a non-path) — resolve the slow way. */
            return realpath(path, resolved);
        }
        errno = e;
        return NULL;
    }

    resolved[n] = '\0';
    return resolved;
}
