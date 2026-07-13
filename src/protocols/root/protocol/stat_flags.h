/*
 * stat_flags.h — XRootD stat `flags` field semantics (single source of truth).
 *
 * WHAT: the meaning of the bits in the `flags` field of a kXR_stat reply
 *       (kXR_isDir / kXR_other / kXR_readable / kXR_xset / ...), expressed once
 *       for both halves of the boundary:
 *         - brix_stat_flags_from_mode: struct-stat mode -> kXR flags (server encode)
 *         - brix_stat_mode_from_flags: kXR flags -> POSIX file-type+perm bits (client decode)
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
#ifndef BRIX_PROTOCOL_STAT_FLAGS_H
#define BRIX_PROTOCOL_STAT_FLAGS_H

#include <sys/stat.h>

#include "flags.h"   /* kXR_isDir / kXR_other / kXR_readable / kXR_xset / ... */

/*
 * Encode the kXR stat `flags` field from a POSIX mode (server side). `extra_flags`
 * carries any caller-supplied bits (e.g. kXR_offline for a tape-resident file).
 * Mirrors the historical derivation exactly: directory -> kXR_isDir; non-regular
 * non-dir -> kXR_other; any read permission bit -> kXR_readable.
 */
static inline int
brix_stat_flags_from_mode(mode_t st_mode, int extra_flags)
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
 * WHAT: does a POSIX permission triad (owner/group/other bits) grant access to
 *       the caller's effective uid/gid?
 * WHY:  StatGen's readable/writable/xset tests are the SAME predicate applied to
 *       three different bit triples; factoring it keeps the three flag decisions
 *       identical by construction (no drift between read/write/exec) and drops the
 *       encoder's branch count.
 * HOW:  pure bit test — owner bit set AND uid matches, OR group bit set AND gid
 *       matches, OR the other bit set — over the mode already read from stat.
 *       Byte-identical to the inlined predicate it replaces.
 */
static inline int
brix_stat_perm_granted(mode_t m, mode_t ubit, mode_t gbit, mode_t obit,
                       uid_t myuid, gid_t mygid, uid_t fuid, gid_t fgid)
{
    if (!(m & (ubit | gbit | obit))) {
        return 0;
    }
    if ((m & ubit) && myuid == fuid) {
        return 1;
    }
    if ((m & gbit) && mygid == fgid) {
        return 1;
    }
    return (m & obit) ? 1 : 0;
}

/*
 * WHAT: file-type flag (kXR_isDir / kXR_other / none) for a POSIX mode.
 * WHY:  the directory-vs-other classification is a self-contained sub-decision;
 *       naming it removes a branch from the encoder and documents the "regular
 *       files carry no type flag" rule in one place.
 * HOW:  directory -> kXR_isDir; any non-regular non-dir -> kXR_other; regular
 *       file -> 0. Identical to the historical if/else-if ladder.
 */
static inline int
brix_stat_type_flag(mode_t m)
{
    if (S_ISDIR(m)) {
        return kXR_isDir;
    }
    if (!S_ISREG(m)) {
        return kXR_other;
    }
    return 0;
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
brix_stat_flags_from_stat(const struct stat *st, uid_t myuid, gid_t mygid,
                            int extra_flags)
{
    int    flags = extra_flags;
    mode_t m     = st->st_mode;
    uid_t  fuid  = st->st_uid;
    gid_t  fgid  = st->st_gid;

    if (brix_stat_perm_granted(m, S_IRUSR, S_IRGRP, S_IROTH,
                               myuid, mygid, fuid, fgid)) {
        flags |= kXR_readable;
    }
    if (brix_stat_perm_granted(m, S_IWUSR, S_IWGRP, S_IWOTH,
                               myuid, mygid, fuid, fgid)) {
        flags |= kXR_writable;
    }
    if (brix_stat_perm_granted(m, S_IXUSR, S_IXGRP, S_IXOTH,
                               myuid, mygid, fuid, fgid)) {
        flags |= kXR_xset;
    }

    flags |= brix_stat_type_flag(m);

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
brix_stat_mode_from_flags(int flags, int allow_symlink)
{
    if (flags & kXR_isDir) {
        return (mode_t) (S_IFDIR | 0755);
    }
    if (allow_symlink && (flags & kXR_other)) {
        return (mode_t) (S_IFLNK | 0777);
    }
    return (mode_t) (S_IFREG | ((flags & kXR_xset) ? 0755 : 0644));
}

#endif /* BRIX_PROTOCOL_STAT_FLAGS_H */
