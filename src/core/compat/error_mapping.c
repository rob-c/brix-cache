/*
 * error_mapping.c — unified errno → protocol status mapping service.
 *
 * WHAT: Consolidates three complementary error-mapping domains into one file:
 *   1. POSIX errno → XRootD kXR error codes (kxr_errno.c)
 *   2. POSIX errno → HTTP status codes (http_errno.c)
 *   3. Namespace service status → HTTP status codes (result_mapper.c)
 *
 * WHY: All three modules serve the same purpose — translating filesystem errors
 *      into protocol-specific response codes. Centralising here ensures consistency,
 *      eliminates duplication between http_errno.h and result_mapper.h, and reduces
 *      the compat directory's file count by three files with zero functional change.
 *
 * HOW: Each domain lives in its own section with WHAT/WHY/HOW documentation blocks.
 *      No cross-dependencies between sections — each function is self-contained.
 */

#include "error_mapping.h"
#include <errno.h>
#include <stddef.h>

/*
 * Section 1: errno → kXR (XRootD wire protocol error codes)
 * */

/*
 * WHAT: Maps a single POSIX errno to the kXR error code used in wire responses.
 *
 * WHY: write-side opcodes (rm, chmod, mv, rmdir, truncate) each had their own
 *      inline chain; centralising here ensures consistent error codes across
 *      all handlers and makes future adjustments apply everywhere at once.
 */

uint16_t
brix_kxr_from_errno(int err)
{
    switch (err) {
    case ENOENT:
        return kXR_NotFound;

    case EACCES:
    case EPERM:
    case EXDEV:    /* openat2 RESOLVE_BENEATH ".." path-escape */
    case ELOOP:    /* RESOLVE_BENEATH/NO_MAGICLINKS rejecting an escaping symlink */
        return kXR_NotAuthorized;

    case ENOTEMPTY:
    case EEXIST:
        /* Reference mapError() returns kXR_ItExists for BOTH EEXIST and
         * ENOTEMPTY (XProtocol.hh: a non-empty directory removal reports
         * kXR_ItExists "until the next major release", not a generic FS error).
         * Stock `xrdfs rm/rmdir` of a populated directory returns 3018 — match. */
        return kXR_ItExists;

    case ENOTDIR:
        /* A non-directory in a path prefix (e.g. stat "/file/under/it") — the
         * reference maps ENOTDIR to kXR_FSError ("Unable to locate ...; not a
         * directory"), NOT kXR_NotFile.  Match it for stat/statx/rmdir parity. */
        return kXR_FSError;

    case ENOMEM:
        return kXR_NoMemory;

    case ENOSPC:
        return kXR_NoSpace;

    case EINVAL:
        return kXR_ArgInvalid;

    default:
        return kXR_IOError;
    }
}

/*
 * WHAT: Maps a kXR wire error code back to a POSIX errno — the inverse of
 *   brix_kxr_from_errno(), co-located so the project's canonical errno↔kXR
 *   table (CLAUDE.md invariant) lives in ONE shared, ngx-free place rather than
 *   the forward direction here and the reverse direction in the native client.
 *   Returns a POSITIVE errno, or 0 when the code is not a recognised kXR error
 *   (the caller chooses the fallback — e.g. the client's POSIX layers negate the
 *   result for the kernel and substitute a captured sys_errno on 0).
 *
 * WHY: the native client's FUSE/preload layers must hand the kernel a -errno for
 *   a server kXR_error; keeping this beside errno→kXR prevents the two directions
 *   drifting out of sync as error codes are added.
 */
/*
 * WHAT: static kXR-code -> POSIX-errno lookup table backing brix_errno_from_kxr().
 *
 * WHY: a flat data table keeps the canonical reverse mapping in one auditable
 *   place and collapses what was a long branch ladder into a trivial scan — the
 *   pairs (and the "unrecognised => 0" fallback) are the ONLY behavioural
 *   contract, unchanged from the former switch.
 */
typedef struct {
    uint16_t kxr;   /* XRootD wire error code */
    int      err;   /* positive POSIX errno */
} brix_kxr_errno_entry_t;

static const brix_kxr_errno_entry_t brix_kxr_errno_table[] = {
    { kXR_NotFound,       ENOENT },
    { kXR_NotAuthorized,  EACCES },
    { kXR_AuthFailed,     EACCES },
    { kXR_isDirectory,    EISDIR },
    { kXR_NotFile,        EISDIR },
    { kXR_FSError,        EEXIST },
    { kXR_ItExists,       EEXIST },
    { kXR_Conflict,       EEXIST },
    { kXR_NoSpace,        ENOSPC },
    { kXR_overQuota,      EDQUOT },
    { kXR_Unsupported,    ENOSYS },
    { kXR_fsReadOnly,     EROFS },
    { kXR_FileLocked,     EAGAIN },
    { kXR_inProgress,     EINPROGRESS },
    { kXR_ArgInvalid,     EINVAL },
    { kXR_ArgMissing,     EINVAL },
    { kXR_ArgTooLong,     ENAMETOOLONG },
    { kXR_InvalidRequest, EINVAL },
    { kXR_FileNotOpen,    EBADF },
    { kXR_NoMemory,       ENOMEM },
    { kXR_ChkSumErr,      EIO },
    { kXR_IOError,        EIO },
    { kXR_AttrNotFound,   ENODATA },
    { kXR_TLSRequired,    EACCES },
    { kXR_Overloaded,     EBUSY },
    { kXR_noserver,       EHOSTUNREACH },
};

int
brix_errno_from_kxr(uint16_t kxr)
{
    size_t i;

    for (i = 0; i < sizeof(brix_kxr_errno_table) / sizeof(brix_kxr_errno_table[0]); i++) {
        if (brix_kxr_errno_table[i].kxr == kxr) {
            return brix_kxr_errno_table[i].err;
        }
    }

    return 0;   /* not a recognised kXR error code */
}

/*
 * WHAT: Maps an brix_ns_status_t to a kXR error code for stream protocol
 * responses.  BRIX_NS_IO_ERROR delegates to brix_kxr_from_errno(sys_errno).
 */
uint16_t
brix_kxr_map_ns_status(brix_ns_status_t status, int sys_errno)
{
    switch (status) {
    case BRIX_NS_OK:        return kXR_ok;
    case BRIX_NS_NOT_FOUND: return kXR_NotFound;
    case BRIX_NS_DENIED:    return kXR_NotAuthorized;
    case BRIX_NS_EXISTS:    return kXR_FSError;
    case BRIX_NS_CONFLICT:  return kXR_FSError;
    case BRIX_NS_NOT_EMPTY: return kXR_ItExists;   /* ENOTEMPTY → 3018 (mapError) */
    case BRIX_NS_NO_SPACE:  return kXR_NoSpace;    /* ENOSPC → 3017, not NoMemory */
    case BRIX_NS_TOO_LONG:  return kXR_ArgTooLong;
    case BRIX_NS_IO_ERROR:  return brix_kxr_from_errno(sys_errno);
    }
    return kXR_IOError;
}

/*
 * Section 2: errno → HTTP status codes
 * */

/*
 * WHAT: Converts filesystem errors (ENOENT, EACCES, ENOSPC, etc.) into standard
 *       HTTP 4xx/5xx status codes. Returns 404 for not-found, 403 for permission,
 *       507 for storage-full, 409 for conflict, 414 for path-too-long, 500 default.
 *
 * WHY: WebDAV and S3 modules both receive errno from POSIX syscalls but need HTTP
 *       status codes for nginx response dispatch. This centralised map ensures both
 *       modules return identical codes for the same error (fixes ENOSPC→507,
 *       ENAMETOOLONG→414 divergences documented in file comment).
 *
 * HOW: Direct switch-case mapping per AGENTS.md errno→HTTP table. EDQUOT grouped
 *       with ENOSPC under 507 (storage quota exceeded). Default case returns 500.
 */

int
brix_http_errno_to_status(int err)
{
    switch (err) {
    case ENOENT:
    case ENOTDIR:
        return 404;

    case EACCES:
    case EPERM:
    case EROFS:
    case EXDEV:    /* openat2 RESOLVE_BENEATH path-escape via ".." out of the
                    * export root. */
    case ELOOP:    /* RESOLVE_BENEATH/RESOLVE_NO_MAGICLINKS rejecting a symlink
                    * (or magic-link) that would escape the export root. */
        /*
         * Both reach here now that confinement is enforced by the kernel at the
         * op instead of by an upstream realpath() that used to fail earlier.  A
         * blocked traversal is forbidden, not a server fault — never a 500.
         */
        return 403;

    case ENOSPC:
#ifdef EDQUOT
    case EDQUOT:
#endif
        return 507;

    case EEXIST:
    case ENOTEMPTY:
        return 409;

    case ENAMETOOLONG:
        return 414;

    default:
        return 500;
    }
}

/*
 * Section 3: namespace status → HTTP status codes
 *
 * ngx-only: returns ngx_int_t for NGX_HTTP_* comparisons. Excluded from the
 * standalone libxrdproto core (-DXRDPROTO_NO_NGX); Sections 1-2 above are pure.
 * */
#ifndef XRDPROTO_NO_NGX

/*
 * WHAT: Maps XRootD namespace service result codes to HTTP status.
 *
 * WHY: namespace_ops.c returns brix_ns_status_t for mkdir/rename/delete operations;
 *      WebDAV handlers need the corresponding HTTP status code for response dispatch.
 *      This mapping ensures namespace errors produce consistent HTTP responses.
 */

ngx_int_t
brix_http_map_ns_status(brix_ns_status_t status)
{
    switch (status) {
    case BRIX_NS_OK:
        return 200;

    case BRIX_NS_NOT_FOUND:
        return 404;

    case BRIX_NS_DENIED:
        return 403;

    case BRIX_NS_EXISTS:
    case BRIX_NS_CONFLICT:
    case BRIX_NS_NOT_EMPTY:
        return 409;

    case BRIX_NS_TOO_LONG:
        return 414;

    case BRIX_NS_NO_SPACE:
        return 507;

    case BRIX_NS_IO_ERROR:
    default:
        return 500;
    }
}

/*
 * WHAT: Thin wrapper over brix_http_errno_to_status() that returns ngx_int_t.
 *
 * WHY: WebDAV handlers expect ngx_int_t for HTTP status comparisons against
 *      NGX_HTTP_* constants. This wrapper provides the type conversion without
 *      duplicating the mapping logic.
 */

ngx_int_t
brix_http_map_errno(int err)
{
    return (ngx_int_t) brix_http_errno_to_status(err);
}

#endif /* !XRDPROTO_NO_NGX */
