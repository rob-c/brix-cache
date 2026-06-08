/*
 * path.c — HTTP/S3 URI-to-filesystem path resolver adapter.
 *
 * WebDAV and S3 keep their historical HTTP-style return codes, but the actual
 * path validation, canonicalization, missing-parent handling, and confinement
 * checks now live in src/path/unified.c alongside the stream resolver.
 */

#include "path.h"
#include "../path/unified.h"

int
xrootd_http_resolve_path(const char *root_canon, const char *decoded_path,
    char *out, size_t outsz)
{
    xrootd_path_opts_t     opts;
    xrootd_path_status_t   rc;

    opts = (xrootd_path_opts_t) { 0 };
    opts.allow_missing_parents = 1;
    opts.allow_root = 1;

    rc = xrootd_path_resolve_cstr(NULL, root_canon, decoded_path, opts,
                                  out, outsz, NULL);
    switch (rc) {
    case XROOTD_PATH_STATUS_OK:
        return 0;
    case XROOTD_PATH_STATUS_INVALID:
        return 403;
    case XROOTD_PATH_STATUS_NOT_FOUND:
        return 404;
    case XROOTD_PATH_STATUS_TOO_LONG:
        return 414;
    default:
        return 500;
    }
}
