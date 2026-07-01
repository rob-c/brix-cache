/*
 * gsi_upstream.c — Phase-4b GSI delegation: secure-temp writer (Task 2).
 *
 * The threaded blocking GSI client (Task 3) reuses the cache origin client, which
 * reads the proxy credential from a FILE path; so the in-memory delegated proxy
 * PEM is first written to an owner-only temp here. mkstemp(3) creates the file
 * O_EXCL with mode 0600 on Linux; we fchmod 0600 again defensively and write the
 * bytes fully. Pure libc so the path/perms logic is unit-testable standalone.
 */

#include "gsi_upstream.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int
xrootd_proxy_gsi_write_pem_temp(const unsigned char *pem, size_t len,
    char *out, size_t cap)
{
    char    tmpl[] = "/tmp/xrd-deleg-XXXXXX";
    int     fd;
    size_t  off;

    if (pem == NULL || len == 0 || out == NULL || cap <= sizeof(tmpl)) {
        errno = EINVAL;
        return -1;
    }

    fd = mkstemp(tmpl);
    if (fd < 0) {
        return -1;
    }
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {   /* vfs-seam-allow: config-domain delegated GSI proxy credential temp (not export storage) */
        int saved = errno;
        close(fd);
        unlink(tmpl);                           /* vfs-seam-allow: config-domain delegated GSI proxy credential temp (not export storage) */
        errno = saved;
        return -1;
    }

    off = 0;
    while (off < len) {
        ssize_t w = write(fd, pem + off, len - off);
        if (w < 0) {
            int saved = errno;
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            unlink(tmpl);                        /* vfs-seam-allow: config-domain delegated GSI proxy credential temp (not export storage) */
            errno = saved;
            return -1;
        }
        off += (size_t) w;
    }

    if (close(fd) != 0) {
        int saved = errno;
        unlink(tmpl);                           /* vfs-seam-allow: config-domain delegated GSI proxy credential temp (not export storage) */
        errno = saved;
        return -1;
    }

    memcpy(out, tmpl, sizeof(tmpl));
    return 0;
}
