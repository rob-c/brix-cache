/*
 * path.c — HTTP/S3 URI-to-filesystem path resolver adapter.
 *
 * Phase 8: this no longer calls realpath().  WebDAV and S3 use the returned
 * path only to drive their own confined operations (brix_*_confined_canon /
 * brix_*_beneath / the VFS layer), all of which re-resolve under the export
 * root with openat2(RESOLVE_BENEATH).  So confinement is enforced at the actual
 * filesystem op, and this adapter only has to (1) reject the same malformed
 * inputs the old resolver did — depth and "." / ".." components — and
 * (2) produce the lexical root_canon + decoded_path join for ACL matching and
 * logging.  It deliberately performs NO existence check: the HTTP semantics
 * allowed missing parents (PUT/MKCOL create), and the real operation surfaces
 * ENOENT itself.
 */

#include "path.h"
#include "fs/path/beneath.h"
#include "fs/path/reserved_names.h"   /* brix_is_internal_name */
#include "protocols/root/path/op_path.h"

int
brix_http_resolve_path(const char *root_canon, const char *decoded_path,
    char *out, size_t outsz)
{
    if (decoded_path == NULL || root_canon == NULL) {
        return 403;
    }

    /* Validation equivalent to the retired brix_validate_components_cstr():
     * depth limit + reject any "." / ".." component.  An escaping ".." is also
     * blocked by RESOLVE_BENEATH at the op, but rejecting it up front keeps the
     * 403 contract and avoids handing a traversal string to ACL/logging. */
    if (brix_count_path_depth(decoded_path) != NGX_OK
        || brix_op_path_forbidden_component(decoded_path))
    {
        return 403;
    }

    /* Internal metadata/staging artifacts (cache sidecars, stage markers,
     * in-flight upload temps) are invisible to clients: a request that names one
     * is answered as if the path does not exist (404) — never served, and never
     * created (a PUT/MOVE onto such a name would collide with the cache's own
     * sidecar naming). 404 (not 403) so the response does not distinguish an
     * internal name from a genuinely absent one. Covers WebDAV + S3 (both route
     * client URIs through here); the server's own sidecar/temp I/O uses the
     * confined-open primitives directly and never passes through this resolver. */
    if (brix_is_internal_name(decoded_path)) {
        return 404;
    }

    /* Lexical confined join (no symlink resolution here — the kernel does that
     * under RESOLVE_BENEATH when the op runs). */
    if (brix_beneath_full_path(root_canon, decoded_path, out, outsz)
        >= (int) outsz)
    {
        return 414;
    }

    return 0;
}
