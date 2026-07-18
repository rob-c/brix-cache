/*
 * cred_stage.c — private staging area for short-lived credential material.
 * See cred_stage.h for the rationale (CWE-377 co-tenant race, fail-closed).
 *
 * Pure libc so it links into both the stream module (native TPC, GSI proxy) and
 * the HTTP module (WebDAV TPC) and is unit-testable without nginx.
 */

#include "cred_stage.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>          /* mkstemp */
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Per-uid staging root on tmpfs.  /dev/shm is 1777 (sticky, world-writable), so
 * every uid can create its OWN 0700 subdirectory here that no other uid can enter
 * or delete; the security boundary is that dir's mode + ownership, checked below.
 * Per-uid naming keeps distinct workers/users from tripping over each other's dir
 * ownership on a shared host. */
#define BRIX_CRED_STAGE_BASE "/dev/shm/brix-creds"

int
brix_cred_stage_dir(char *out, size_t outsz)
{
    struct stat st;
    char        dir[64];
    int         n;

    n = snprintf(dir, sizeof(dir), "%s.%u",
                 BRIX_CRED_STAGE_BASE, (unsigned) geteuid());
    if (n < 0 || (size_t) n >= sizeof(dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        return -1;
    }

    /* REQUIRE a real directory, owned by us, with no group/other access. A
     * pre-existing path that fails any of these (a foreign squatter, a loosened
     * mode, a symlink) is unsafe — fail closed rather than trust it. */
    if (lstat(dir, &st) != 0) {
        return -1;
    }
    if (!S_ISDIR(st.st_mode)
        || st.st_uid != geteuid()
        || (st.st_mode & 0077) != 0)
    {
        errno = EPERM;
        return -1;
    }

    if ((size_t) n + 1 > outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, dir, (size_t) n + 1);
    return 0;
}

int
brix_cred_stage_write(const char *prefix, const void *bytes, size_t len,
                      char *path_out, size_t path_outsz)
{
    char                  dir[64];
    char                  tmpl[128];
    const unsigned char  *p = bytes;
    size_t                off;
    size_t                plen;
    int                   fd;
    int                   n;

    if (prefix == NULL || bytes == NULL || path_out == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (brix_cred_stage_dir(dir, sizeof(dir)) != 0) {
        return -1;                          /* fail closed — never /tmp */
    }

    n = snprintf(tmpl, sizeof(tmpl), "%s/%sXXXXXX", dir, prefix);
    if (n < 0 || (size_t) n >= sizeof(tmpl)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    fd = mkstemp(tmpl);                      /* O_EXCL create, 0600 on Linux */
    if (fd < 0) {
        return -1;
    }
    /* Defensive: pin 0600 regardless of umask/platform mkstemp behaviour. */
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        int saved = errno;
        close(fd);
        unlink(tmpl);
        errno = saved;
        return -1;
    }

    off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0) {
            int saved = errno;
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            unlink(tmpl);
            errno = saved;
            return -1;
        }
        off += (size_t) w;
    }

    if (close(fd) != 0) {
        int saved = errno;
        unlink(tmpl);
        errno = saved;
        return -1;
    }

    plen = strlen(tmpl) + 1;
    if (plen > path_outsz) {
        unlink(tmpl);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(path_out, tmpl, plen);
    return 0;
}
