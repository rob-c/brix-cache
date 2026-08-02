/* platform.c — OS feature shim. See platform.h. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1            /* memfd_create, O_TMPFILE */
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1        /* mkstemp under strict -std=c11 */
#endif

#include "cvmfs/platform/platform.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/mman.h>

int brix_plat_anon_fd(const char *label, const char *spill_dir) {
#if defined(__linux__)
    int mfd = memfd_create(label != NULL ? label : "brix-anon", MFD_CLOEXEC);
    if (mfd >= 0) return mfd;
#else
    (void) label;
#endif
#if defined(O_TMPFILE)
    if (spill_dir != NULL && spill_dir[0] != '\0') {
        int tfd = open(spill_dir, O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
        if (tfd >= 0) return tfd;
    }
#endif
    char tmpl[576];
    snprintf(tmpl, sizeof(tmpl), "%s/.brix-anon.XXXXXX",
             (spill_dir != NULL && spill_dir[0] != '\0') ? spill_dir : "/tmp");
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    unlink(tmpl);
    return fd;
}

int brix_plat_fsync_data(int fd) {
#if defined(__APPLE__)
    if (fcntl(fd, F_FULLFSYNC) == 0) return 0;
    return fsync(fd);
#elif defined(__linux__)
    return fdatasync(fd);
#else
    return fsync(fd);
#endif
}

void *brix_plat_map_ro(int fd, unsigned long len) {
    if (len == 0) { errno = EINVAL; return NULL; }
    void *p = mmap(NULL, (size_t) len, PROT_READ, MAP_SHARED, fd, 0);
    return p == MAP_FAILED ? NULL : p;
}

void brix_plat_unmap(void *p, unsigned long len) {
    if (p != NULL && len != 0) munmap(p, (size_t) len);
}
