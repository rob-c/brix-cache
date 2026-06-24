#include "../ngx_xrootd_module.h"
#include "../protocol/stat_line.h"    /* shared stat-line grammar (encode side) */
#include "../protocol/stat_flags.h"   /* shared stat `flags` semantics (encode side) */

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
    int flags;

    /* VFS mode hides the real inode/blocks: id 0, size = block bytes, readable. */
    if (is_vfs) {
        xrootd_statline_format(out, outsz, 0ULL,
                               (long long) st->st_blocks * 512,
                               kXR_readable,
                               (long) st->st_mtime);
        return;
    }

    /* The stat `flags` field bits come from the shared semantics header,
     * mirroring the reference StatGen: readable/writable/xset are derived from
     * the file's permission bits checked against the server's own (effective)
     * uid/gid — whom the confined export is accessed as — plus dir/other type. */
    flags = xrootd_stat_flags_from_stat(st, geteuid(), getegid(), extra_flags);

    /* Unique id ("devid", chunks[0] of the stat line) — mirror the reference
     * StatGen exactly so XrdCl/gfal parse an identical value.  StatGen builds it
     * via `union {long long uuid; struct {int hi; int lo;} id;}` with
     * `id.lo = st_ino; id.hi = st_dev`.  On the LP64/little-endian platform this
     * runs on, the `id.lo` int sits in the low-address (least-significant) word,
     * so the composed 64-bit value is (st_ino << 32) | (uint32_t)st_dev — the
     * inode in the high word, device in the low word (verified against stock:
     * `stock_id >> 32 == st_ino`).  uuid is zero only when both are zero, which
     * is the reference's `!Dev.uuid` offline trigger — preserved here. */
    xrootd_statline_format(out, outsz,
                           ((unsigned long long) st->st_ino << 32)
                               | (unsigned long long) (uint32_t) st->st_dev,
                           (long long) st->st_size,
                           flags,
                           (long) st->st_mtime);
}
