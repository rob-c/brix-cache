#include "../ngx_xrootd_module.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ---- Function: xrootd_make_stat_body() ----
 *
 * WHAT: Formats filesystem metadata into XRootD wire protocol stat response body string. Converts struct stat fields (inode, size, mode, timestamps) into the 4-field space-separated format expected by kXR_stat/kXR_statx opcodes. Two output modes: VFS mode produces simplified block count + readable flag; non-VFS mode includes inode number and full permission flags.
 *
 * WHY: The XRootD protocol requires specific field ordering and encoding for stat responses — this helper ensures consistent wire format across all stat implementations (read/stat.c, read/statx.c). VFS mode is used when the server operates in virtual filesystem abstraction where real block counts are not meaningful; non-VFS mode uses actual inode+block data from the underlying filesystem. Thread safety: pure function with no shared state — safe for concurrent use on any thread. */

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
