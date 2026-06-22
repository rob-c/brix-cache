/*
 * posix_map.c — backend-agnostic XRootD↔POSIX translation (see posix_map.h).
 *
 * Lifted verbatim from the two FUSE drivers' identical helpers so both (and the
 * preload shim) share one implementation. No connection model, no FUSE types.
 */
#include "posix_map.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

void
xrdc_statinfo_to_stat(const xrdc_statinfo *si, int allow_symlink,
                      struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(*stbuf));
    if (si->flags & kXR_isDir) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else if (allow_symlink && (si->flags & kXR_other)) {
        /* Non-regular/non-dir from an lstat: present as a symlink with size =
         * target length so the kernel follows up with readlink. */
        stbuf->st_mode = S_IFLNK | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = (off_t) si->size;
    } else {
        stbuf->st_mode = S_IFREG | ((si->flags & kXR_xset) ? 0755 : 0644);
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
xrdc_parse_qspace(const char *text, unsigned long long *total,
                  unsigned long long *freeb)
{
    const char *p;

    if (total != NULL) { *total = 0; }
    if (freeb != NULL) { *freeb = 0; }
    if (text == NULL) {
        return;
    }
    p = strstr(text, "oss.space=");
    if (p != NULL && total != NULL) { *total = strtoull(p + 10, NULL, 10); }
    p = strstr(text, "oss.free=");
    if (p != NULL && freeb != NULL) { *freeb = strtoull(p + 9, NULL, 10); }
}

int
xrdc_fattr_listxattr_xlate(const char *raw, size_t rawlen, char *list, size_t size)
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
