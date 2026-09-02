/*
 * lock_record.h — the persisted resource-lock record (phase-107 C7).
 *
 * WHAT: The on-disk format of a WebDAV lock — one pipe-delimited xattr value
 *       on the locked resource — as a protocol-neutral type: the xattr key,
 *       the record struct, encode/decode, and the ancestor-walk path helper.
 *
 * WHY:  Phase-107 C7 makes lock coverage a VFS question
 *       (brix_vfs_require_unlocked): a lock taken over WebDAV must refuse an
 *       XRootD, GridFTP or S3 write. The VFS cannot include a protocol header,
 *       so the record format moved here from src/protocols/webdav (webdav.h /
 *       prop_xattr.c) byte-for-byte; WebDAV keeps its names as aliases and
 *       still owns the lock STATE MACHINE (LOCK/UNLOCK, refresh, discovery,
 *       reaping) — this unit owns only the format.
 *
 * HOW:  Encoding is schema v2: `v=2|token=...|owner=...|expires=<wallclock
 *       seconds>|scope=exclusive|shared|depth=infinity|0|null=0|1`. The
 *       decoder forces a non-v2 record to expires=0 (already expired) so a
 *       legacy monotonic-msec deadline is released, never honoured.
 */

#ifndef NGX_BRIX_LOCK_RECORD_H
#define NGX_BRIX_LOCK_RECORD_H

#include <ngx_config.h>
#include <ngx_core.h>

#define BRIX_LOCK_XATTR_KEY     "user.nginx_xrootd.lock"
#define BRIX_LOCK_XATTR_MAXLEN  512

typedef struct {
    char        token[64];           /* full opaquelocktoken:UUID string */
    char        owner[256];          /* DN or free-form owner */
    int64_t     expires;             /* absolute expiry, Unix WALL-CLOCK seconds
                                      * (ngx_time()-based, NOT the monotonic
                                      * ngx_current_msec): a persisted lock must
                                      * keep meaningful expiry across a machine
                                      * reboot, where the monotonic clock resets. */
    unsigned    exclusive:1;
    unsigned    depth_infinity:1;
    unsigned    is_null:1;           /* lock-null: the lock created a zero-byte
                                      * placeholder on a non-existent resource
                                      * (RFC 4918 §9.10.1); reaped on UNLOCK/expiry
                                      * while the resource is still empty. */
} brix_lock_record_t;

/* Serialise a lock record to the pipe-delimited xattr value form in
 * out[outsz]. NGX_OK, or NGX_ERROR if it would not fit. */
ngx_int_t brix_lock_record_encode(const brix_lock_record_t *e,
    char *out, size_t outsz);

/* Parse a stored lock value raw[rawlen] back into *e. NGX_OK; NGX_DECLINED if
 * empty/oversized or no token field was found (not a valid lock record). */
ngx_int_t brix_lock_record_decode(const char *raw, size_t rawlen,
    brix_lock_record_t *e);

/* Strip the last component from `check` (of length check_len) in place,
 * advancing an ancestor walk one level toward the export root. Returns 1 when
 * a shorter parent path remains in `check`, 0 when the path can no longer be
 * shortened (no interior slash) so the caller stops. */
int brix_lock_path_ascend(char *check, size_t check_len);

#endif /* NGX_BRIX_LOCK_RECORD_H */
