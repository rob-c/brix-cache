/*
 * path.c — HTTP/S3 URI-to-filesystem path resolver adapter.
 *
 * Phase 8: this no longer calls realpath().  WebDAV and S3 use the returned
 * path only to drive their own confined operations (xrootd_*_confined_canon /
 * xrootd_*_beneath / the VFS layer), all of which re-resolve under the export
 * root with openat2(RESOLVE_BENEATH).  So confinement is enforced at the actual
 * filesystem op, and this adapter only has to (1) reject the same malformed
 * inputs the old resolver did — depth and "." / ".." components — and
 * (2) produce the lexical root_canon + decoded_path join for ACL matching and
 * logging.  It deliberately performs NO existence check: the HTTP semantics
 * allowed missing parents (PUT/MKCOL create), and the real operation surfaces
 * ENOENT itself.
 */

#include "path.h"
#include "../path/beneath.h"
#include "../path/op_path.h"

int
xrootd_http_resolve_path(const char *root_canon, const char *decoded_path,
    char *out, size_t outsz)
{
    if (decoded_path == NULL || root_canon == NULL) {
        return 403;
    }

    /* Validation equivalent to the retired xrootd_validate_components_cstr():
     * depth limit + reject any "." / ".." component.  An escaping ".." is also
     * blocked by RESOLVE_BENEATH at the op, but rejecting it up front keeps the
     * 403 contract and avoids handing a traversal string to ACL/logging. */
    if (xrootd_count_path_depth(decoded_path) != NGX_OK
        || xrootd_op_path_forbidden_component(decoded_path))
    {
        return 403;
    }

    /* Lexical confined join (no symlink resolution here — the kernel does that
     * under RESOLVE_BENEATH when the op runs). */
    if (xrootd_beneath_full_path(root_canon, decoded_path, out, outsz)
        >= (int) outsz)
    {
        return 414;
    }

    return 0;
}
