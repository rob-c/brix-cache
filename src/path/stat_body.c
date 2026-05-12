#include "../ngx_xrootd_module.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void
xrootd_make_stat_body(const struct stat *st, ngx_flag_t is_vfs,
                      int extra_flags, char *out, size_t outsz)
{
    int flags = extra_flags;

    if (is_vfs) {
        snprintf(out, outsz, "0 %lld %d %ld",
                 (long long) st->st_blocks * 512,
                 kXR_readable,
                 (long) st->st_mtime);
        return;
    }

    if (S_ISDIR(st->st_mode)) {
        flags |= kXR_isDir;
    } else if (!S_ISREG(st->st_mode)) {
        flags |= kXR_other;
    }

    if (st->st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
        flags |= kXR_readable;
    }

    snprintf(out, outsz, "%llu %lld %d %ld",
             (unsigned long long) st->st_ino,
             (long long) st->st_size,
             flags,
             (long) st->st_mtime);
}
