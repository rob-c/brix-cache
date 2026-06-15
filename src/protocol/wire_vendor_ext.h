#ifndef XROOTD_WIRE_VENDOR_EXT_H
#define XROOTD_WIRE_VENDOR_EXT_H

/*
 * wire_vendor_ext.h — request structures for the nginx-xrootd vendor extension
 * opcodes (kXR_setattr / kXR_symlink / kXR_readlink / kXR_link, opcodes.h).
 *
 * WHAT: 24-byte ClientRequestHdr-shaped structs for the POSIX-completeness ops
 *       the base XRootD protocol lacks. All are capability-negotiated (the server
 *       advertises "xrdfs.ext" via kXR_Qconfig; the native client only emits these
 *       when advertised), so a stock server never sees them.
 * WHY:  Lets a FUSE mount honour `cp -p` / `touch -d` (mtime), chown, and
 *       `ln`/`ln -s` (hard/symbolic links) against this gateway.
 * HOW:  Same framing as every other request — 2B streamid + 2B requestid + 16B
 *       opcode body + 4B dlen (big-endian), then a payload. These structs use the
 *       project's natural-alignment convention (no #pragma pack): every field sits
 *       on its natural boundary so each struct is exactly 24 bytes with no padding,
 *       matching ClientRmRequest / ClientMvRequest. The variable attribute data for
 *       setattr lives entirely in the PAYLOAD (parsed field-by-field with
 *       be64toh/ntohl) so no misaligned int64 appears in a struct.
 *
 * Included by wire.h (after types.h, so the kXR_* type aliases are in scope).
 */

#pragma pack(push, 1)

/* ---- kXR_setattr (3500) — set modification/access times and/or owner ----
 *
 * WHAT: Set a path's timestamps (utimens) and/or owner (chown). kXR_chmod already
 *       covers mode, so this opcode deliberately does NOT carry mode.
 *
 * Payload layout (big-endian fixed prefix, then a NUL-terminated path):
 *   off  0: int32 flags        (kXR_sa_times | kXR_sa_owner)
 *   off  4: int64 atime_sec
 *   off 12: int64 atime_nsec   (UTIME_OMIT / UTIME_NOW honoured per utimensat(2))
 *   off 20: int64 mtime_sec
 *   off 28: int64 mtime_nsec
 *   off 36: int32 uid          (-1 = leave unchanged)
 *   off 40: int32 gid          (-1 = leave unchanged)
 *   off 44: path[]             (NUL-terminated; dlen - 44 bytes)
 */
#define XROOTD_SETATTR_PREFIX_LEN  44   /* fixed binary prefix before the path */
#define kXR_sa_times  0x01             /* apply atime/mtime via utimensat */
#define kXR_sa_owner  0x02             /* apply uid/gid via fchownat       */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_setattr */
    kXR_char   reserved[16];
    kXR_int32  dlen;         /* XROOTD_SETATTR_PREFIX_LEN + path length */
    /* payload: 44-byte big-endian attribute prefix + null-terminated path */
} ClientSetattrRequest;      /* 24 bytes */

/* ---- kXR_symlink (3501) — create a symbolic link ----
 *
 * WHAT: Create a symlink named <linkpath> whose target is the literal string
 *       <target>. The target is stored verbatim (never resolved here); traversal
 *       safety is enforced at open time by the confined-open (RESOLVE_BENEATH).
 *
 * Wire (mirrors kXR_mv): payload = target + ' ' + linkpath; arg1len = strlen(target).
 *   Only <linkpath> is path-resolved + confined (where the link is created).
 */
typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_symlink */
    kXR_char   reserved[14];
    kXR_int16  arg1len;      /* byte length of <target> in the payload */
    kXR_int32  dlen;         /* total payload length (target + ' ' + linkpath) */
} ClientSymlinkRequest;      /* 24 bytes */

/* ---- kXR_readlink (3502) — read a symbolic link's target ----
 *
 * WHAT: Return the target string of the symlink at <path>. Read-side op (no write
 *       gate). Response body = the link target (not NUL-terminated; dlen bytes).
 */
typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_readlink */
    kXR_char   reserved[16];
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientReadlinkRequest;     /* 24 bytes */

/* ---- kXR_link (3503) — create a hard link ----
 *
 * Wire (mirrors kXR_mv): payload = oldpath + ' ' + newpath; arg1len = strlen(oldpath).
 *   Both paths are resolved + confined under the export root.
 */
typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_link */
    kXR_char   reserved[14];
    kXR_int16  arg1len;      /* byte length of <oldpath> in the payload */
    kXR_int32  dlen;         /* total payload length (oldpath + ' ' + newpath) */
} ClientLinkRequest;         /* 24 bytes */

#pragma pack(pop)

#endif /* XROOTD_WIRE_VENDOR_EXT_H */
