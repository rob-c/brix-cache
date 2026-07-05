/*
 * posix_map.c — backend-agnostic XRootD↔POSIX translation (see posix_map.h).
 *
 * Lifted verbatim from the two FUSE drivers' identical helpers so both (and the
 * preload shim) share one implementation. No connection model, no FUSE types.
 */
#include "posix_map.h"
#include "protocols/root/protocol/stat_flags.h"   /* shared stat `flags` semantics (decode side) */
#include "protocols/root/protocol/qspace.h"       /* shared oss.* space-report grammar (parse side) */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

void
brix_statinfo_to_stat(const brix_statinfo *si, int allow_symlink,
                      struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(*stbuf));

    /* File-type + permission bits come from the shared stat-flags semantics, the
     * inverse-by-spec of the server's st_mode -> kXR flags encode. The FUSE-facing
     * link count / size policy stays here: a directory advertises nlink 2 and no
     * size; a symlink (lstat) or regular file advertises nlink 1 and the wire
     * size (for a symlink that is the target length, which drives readlink). */
    stbuf->st_mode = brix_stat_mode_from_flags(si->flags, allow_symlink);
    if (S_ISDIR(stbuf->st_mode)) {
        stbuf->st_nlink = 2;
    } else {
        stbuf->st_nlink = 1;
        stbuf->st_size = (off_t) si->size;
    }
    stbuf->st_mtime = (time_t) si->mtime;
    stbuf->st_atime = stbuf->st_mtime;
    stbuf->st_ctime = stbuf->st_mtime;
    /* Stable inode from the server's file id so inode-tracking tools (find
     * -samefile, rsync, tar) see a consistent identity across calls. */
    stbuf->st_ino = (ino_t) si->id;
    stbuf->st_blksize = 1024 * 1024;   /* hint a large I/O unit for cp/dd */
    stbuf->st_blocks = (blkcnt_t) ((stbuf->st_size + 511) / 512);
}

void
brix_parse_qspace(const char *text, unsigned long long *total,
                  unsigned long long *freeb)
{
    /* oss.* token grammar is shared with the server's emitter (protocol/qspace.h). */
    brix_qspace_parse(text, total, freeb);
}

int
brix_fattr_listxattr_xlate(const char *raw, size_t rawlen, char *list, size_t size)
{
    size_t total = 0, i = 0;

    while (i < rawlen) {
        const char *nm   = raw + i;
        size_t      nl   = strnlen(nm, rawlen - i);
        const char *body = nm;
        size_t      blen = nl;
        size_t      need;

        if (nl == 0) {
            i += 1;
            continue;
        }
        if (blen >= 2 && body[0] == 'U' && body[1] == '.') {
            body += 2;
            blen -= 2;
        }
        need = 5 + blen + 1;     /* "user." + body + NUL */
        if (size > 0) {
            if (total + need > size) {
                return -ERANGE;
            }
            memcpy(list + total, "user.", 5);
            memcpy(list + total + 5, body, blen);
            list[total + 5 + blen] = '\0';
        }
        total += need;
        i += nl + 1;             /* advance past the name and its NUL */
    }
    return (int) total;
}
