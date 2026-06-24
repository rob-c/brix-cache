/*
 * stat_flags.h — XRootD stat `flags` field semantics (single source of truth).
 *
 * WHAT: the meaning of the bits in the `flags` field of a kXR_stat reply
 *       (kXR_isDir / kXR_other / kXR_readable / kXR_xset / ...), expressed once
 *       for both halves of the boundary:
 *         - xrootd_stat_flags_from_mode: struct-stat mode -> kXR flags (server encode)
 *         - xrootd_stat_mode_from_flags: kXR flags -> POSIX file-type+perm bits (client decode)
 * WHY:  this is the companion to stat_line.h — that header owns the LINE shape
 *       ("<id> <size> <flags> <mtime>"); this one owns what the `flags` integer in
 *       that line MEANS. The server set the bits (src/path/stat_body.c) and the
 *       client turned them back into an st_mode (client/lib/posix_map.c) with the
 *       bit meanings written out independently on each side — so the dir/other/
 *       readable/xset semantics were duplicated and free to drift.
 * HOW:  header-only static inlines over <sys/stat.h> + the kXR_* bit constants —
 *       no ngx/alloc/OpenSSL — so the same code compiles into the nginx module and
 *       the ngx-free client. FUSE-specific policy (st_nlink, st_size, st_ino,
 *       st_blksize) stays in the client; only the file-type + permission bits,
 *       which the flag spec actually dictates, live here.
 *
 * The two functions are NOT strict inverses: the decoder handles every bit a
 * peer xrootd server might send, while the encoder emits the file-type +
 * permission bits the reference StatGen sets. They share the bit *definitions*,
 * not a round trip.
 *
 * Clean-room: bit meanings from src/protocol/flags.h (vs XProtocol stat flags).
 */
#ifndef XROOTD_PROTOCOL_STAT_FLAGS_H
#define XROOTD_PROTOCOL_STAT_FLAGS_H

#include <sys/stat.h>

#include "flags.h"   /* kXR_isDir / kXR_other / kXR_readable / kXR_xset / ... */

/*
 * Encode the kXR stat `flags` field from a POSIX mode (server side). `extra_flags`
 * carries any caller-supplied bits (e.g. kXR_offline for a tape-resident file).
 * Mirrors the historical derivation exactly: directory -> kXR_isDir; non-regular
 * non-dir -> kXR_other; any read permission bit -> kXR_readable.
 */
static inline int
xrootd_stat_flags_from_mode(mode_t st_mode, int extra_flags)
{
    int flags = extra_flags;

    if (S_ISDIR(st_mode)) {
        flags |= kXR_isDir;
    } else if (!S_ISREG(st_mode)) {
        flags |= kXR_other;
    }

    if (st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
        flags |= kXR_readable;
    }

    return flags;
}

/*
 * Encode the kXR stat `flags` field from a full struct stat (server side),
 * mirroring the reference XrdXrootdProtocol::StatGen exactly. Unlike the
 * mode-only helper above, this sets kXR_writable and kXR_xset in addition to
 * kXR_readable, applying the owner/group/other permission check against the
 * server's own (effective) uid/gid — which is whom the export is read/written
 * as. `extra_flags` carries caller-supplied bits (e.g. kXR_offline/kXR_cachersp).
 *
 *   read  bit set & (owner&uid match | group&gid match | other) -> kXR_readable
 *   write bit set & (... same ...)                              -> kXR_writable
 *   exec  bit set & (... same ...)                              -> kXR_xset
 *   directory -> kXR_isDir ; non-dir non-regular -> kXR_other
 */
static inline int
xrootd_stat_flags_from_stat(const struct stat *st, uid_t myuid, gid_t mygid,
                            int extra_flags)
{
    int    flags = extra_flags;
    mode_t m     = st->st_mode;

    if ((m & (S_IRUSR | S_IRGRP | S_IROTH))
        && (((m & S_IRUSR) && myuid == st->st_uid)
            || ((m & S_IRGRP) && mygid == st->st_gid)
            ||  (m & S_IROTH))) {
        flags |= kXR_readable;
    }
    if ((m & (S_IWUSR | S_IWGRP | S_IWOTH))
        && (((m & S_IWUSR) && myuid == st->st_uid)
            || ((m & S_IWGRP) && mygid == st->st_gid)
            ||  (m & S_IWOTH))) {
        flags |= kXR_writable;
    }
    if ((m & (S_IXUSR | S_IXGRP | S_IXOTH))
        && (((m & S_IXUSR) && myuid == st->st_uid)
            || ((m & S_IXGRP) && mygid == st->st_gid)
            ||  (m & S_IXOTH))) {
        flags |= kXR_xset;
    }

    if (S_ISDIR(m)) {
        flags |= kXR_isDir;
    } else if (!S_ISREG(m)) {
        flags |= kXR_other;
    }

    return flags;
}

/*
 * Decode the kXR stat `flags` field into a POSIX file-type + permission mode
 * (client side). `allow_symlink` is set by callers that issued an lstat and want a
 * non-regular/non-dir entry surfaced as a symlink (size = target length, so the
 * kernel follows up with readlink); a plain stat passes 0 and gets a regular file.
 *   kXR_isDir              -> S_IFDIR | 0755
 *   kXR_other (lstat only) -> S_IFLNK | 0777
 *   otherwise              -> S_IFREG | (kXR_xset ? 0755 : 0644)
 */
static inline mode_t
xrootd_stat_mode_from_flags(int flags, int allow_symlink)
{
    if (flags & kXR_isDir) {
        return (mode_t) (S_IFDIR | 0755);
    }
    if (allow_symlink && (flags & kXR_other)) {
        return (mode_t) (S_IFLNK | 0777);
    }
    return (mode_t) (S_IFREG | ((flags & kXR_xset) ? 0755 : 0644));
}

#endif /* XROOTD_PROTOCOL_STAT_FLAGS_H */
