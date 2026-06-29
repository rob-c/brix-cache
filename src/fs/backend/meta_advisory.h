#ifndef XROOTD_META_ADVISORY_H
#define XROOTD_META_ADVISORY_H

/*
 * meta_advisory.h — shared "advisory" unix-metadata codec for object-store backends.
 *
 * WHAT: A tiny, pure (libc-only, no nginx, no sd.h) codec for a reserved metadata
 *       string that carries POSIX mode/uid/gid/mtime across a backend that has no
 *       native concept of them.
 *
 * WHY:  XrdCeph/RADOS fakes mode and returns ENOTSUP for chmod; S3 has no POSIX
 *       attrs. To let chmod/utime "stick" and round-trip (the approved *advisory*
 *       model), every such backend stores this one string in a reserved slot
 *       (xattr `user.xrd.unixattr` on RADOS; `x-amz-meta-xrd-unixattr` on S3) and
 *       overlays it on stat. The codec is shared so the format is identical across
 *       backends and the client VFS — a mode set over one access method reads back
 *       over another.
 *
 * HOW:  Format `v1 mode=0640 uid=1000 gid=2000 mtime=<sec> mtime_ns=<ns>`, only the
 *       present fields after the version token. Decode is forward-compatible: it
 *       skips an unknown version and any unknown `key=val` token. Kept dependency-
 *       free so it unit-tests standalone and links into both the module and
 *       libxrdproto. The overlay-onto-`xrootd_sd_stat_t` happens at the call site
 *       (it owns both the decoded struct and the backend's base stat).
 */

#include <sys/types.h>   /* mode_t, uid_t, gid_t, time_t */
#include <stddef.h>      /* size_t */

/* Reserved slot names (RADOS xattr / S3 user-metadata header suffix). */
#define XROOTD_META_ADVISORY_XATTR  "user.xrd.unixattr"
#define XROOTD_META_ADVISORY_S3META "xrd-unixattr"      /* → x-amz-meta-xrd-unixattr */

typedef struct {
    mode_t   mode;
    uid_t    uid;
    gid_t    gid;
    time_t   mtime;
    long     mtime_ns;
    unsigned have_mode:1;
    unsigned have_owner:1;   /* uid AND gid present */
    unsigned have_mtime:1;
} xrootd_meta_advisory_t;

/* Encode the present fields of *m into out[cap] (NUL-terminated). Returns the
 * string length (excl. NUL), or -1 on bad args / truncation. */
int xrootd_meta_advisory_encode(const xrootd_meta_advisory_t *m,
                                char *out, size_t cap);

/* Decode `blob` (len bytes, need NOT be NUL-terminated) into *m (zeroed first).
 * Tolerates an empty blob, missing fields, an unknown version, and unknown
 * tokens (forward-compat). Returns 0, or -1 only on a NULL *m. */
int xrootd_meta_advisory_decode(const char *blob, size_t len,
                                xrootd_meta_advisory_t *m);

/* Read-modify-write: decode the current NUL-terminated `blob` (may be empty),
 * overlay the present fields of *delta, and re-encode into blob[cap]. For a
 * setattr that touches only some fields. Returns the new length, or -1. */
int xrootd_meta_advisory_patch(char *blob, size_t cap,
                               const xrootd_meta_advisory_t *delta);

#endif /* XROOTD_META_ADVISORY_H */
