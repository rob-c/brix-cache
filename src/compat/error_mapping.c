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

/* --------------------------------------------------------------------------
 * Section 1: errno → kXR (XRootD wire protocol error codes)
 * -------------------------------------------------------------------------- */

/*
 * WHAT: Maps a single POSIX errno to the kXR error code used in wire responses.
 *
 * WHY: write-side opcodes (rm, chmod, mv, rmdir, truncate) each had their own
 *      inline chain; centralising here ensures consistent error codes across
 *      all handlers and makes future adjustments apply everywhere at once.
 */

uint16_t
xrootd_kxr_from_errno(int err)
{
    switch (err) {
    case ENOENT:
        return kXR_NotFound;

    case EACCES:
    case EPERM:
        return kXR_NotAuthorized;

    case ENOTEMPTY:
    case EEXIST:
        return kXR_FSError;

    case ENOTDIR:
        return kXR_NotFile;

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

/* --------------------------------------------------------------------------
 * Section 2: errno → HTTP status codes
 * -------------------------------------------------------------------------- */

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
xrootd_http_errno_to_status(int err)
{
    switch (err) {
    case ENOENT:
    case ENOTDIR:
        return 404;

    case EACCES:
    case EPERM:
    case EROFS:
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

/* --------------------------------------------------------------------------
 * Section 3: namespace status → HTTP status codes
 * -------------------------------------------------------------------------- */

/*
 * WHAT: Maps XRootD namespace service result codes to HTTP status.
 *
 * WHY: namespace_ops.c returns xrootd_ns_status_t for mkdir/rename/delete operations;
 *      WebDAV handlers need the corresponding HTTP status code for response dispatch.
 *      This mapping ensures namespace errors produce consistent HTTP responses.
 */

ngx_int_t
xrootd_http_map_ns_status(xrootd_ns_status_t status)
{
    switch (status) {
    case XROOTD_NS_OK:
        return NGX_HTTP_OK;

    case XROOTD_NS_NOT_FOUND:
        return NGX_HTTP_NOT_FOUND;

    case XROOTD_NS_DENIED:
        return NGX_HTTP_FORBIDDEN;

    case XROOTD_NS_EXISTS:
    case XROOTD_NS_CONFLICT:
    case XROOTD_NS_NOT_EMPTY:
        return NGX_HTTP_CONFLICT;

    case XROOTD_NS_TOO_LONG:
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;

    case XROOTD_NS_NO_SPACE:
        return NGX_HTTP_INSUFFICIENT_STORAGE;

    case XROOTD_NS_IO_ERROR:
    default:
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

/*
 * WHAT: Thin wrapper over xrootd_http_errno_to_status() that returns ngx_int_t.
 *
 * WHY: WebDAV handlers expect ngx_int_t for HTTP status comparisons against
 *      NGX_HTTP_* constants. This wrapper provides the type conversion without
 *      duplicating the mapping logic.
 */

ngx_int_t
xrootd_http_map_errno(int err)
{
    return (ngx_int_t) xrootd_http_errno_to_status(err);
}
