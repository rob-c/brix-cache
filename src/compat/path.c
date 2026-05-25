/*
 * path.c — URI-to-filesystem path resolver shared by WebDAV and S3.
 *
 * WHAT: Resolves a decoded URI path against a canonical root directory to produce
 *       a confined, canonical filesystem path. Used by the WebDAV GET/PUT handler
 *       and the S3 PUT handler for all file-path operations.
 *
 * WHY: Both protocols need the same resolution logic — realpath-based canonicalization,
 *      dot/dotdot rejection, root confinement verification, and an ENOENT-parent strategy
 *      for paths that do not yet exist (PUT/MKCOL/COPY destinations). Centralising it here
 *      avoids duplication between WebDAV and S3 code.
 *
 * HOW: Three-phase process. Phase 1 — reject "." or ".." components via has_forbidden_components().
 *       Phase 2 — build candidate = root_canon + decoded_path, call realpath() to canonicalize.
 *       If realpath returns ENOENT (target does not exist), walk up the path finding the deepest
 *       existing ancestor within root_canon and append the non-existent suffix. Phase 3 — verify
 *       the resolved path is confined under root_canon (strncmp + boundary check). Return 0 on
 *       success, 403 if outside root, 414 if overflow, 500 for other errors.
 */

#include "path.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * WHAT: Scans a URI path for "." and ".." components that would escape the root.
 *
 * HOW: Walks character-by-character through the path, skipping leading slashes.
 *       For each segment (delimited by '/'), checks if seg_len == 1 && p[0] == '.'
 *       or seg_len == 2 && p[0] == '.' && p[1] == '..'. Returns 1 on first match,
 *       0 if no forbidden components found. Skips trailing slashes after the last
 *       segment to avoid false matches.
 */

static int
has_forbidden_components(const char *path)
{
    const char *p = path;

    while (*p == '/')
        p++;

    while (*p != '\0') {
        const char *seg_end;
        size_t      seg_len;

        while (*p == '/')
            p++;
        if (*p == '\0')
            break;

        seg_end = strchr(p, '/');
        seg_len = seg_end ? (size_t)(seg_end - p) : strlen(p);

        if ((seg_len == 1 && p[0] == '.')
            || (seg_len == 2 && p[0] == '.' && p[1] == '.'))
            return 1;

        if (seg_end == NULL)
            break;
        p = seg_end + 1;
    }
    return 0;
}

/*
 * WHAT: Resolves a decoded URI path against a canonical root to produce a confined
 *       filesystem path. Returns 0 (success), 403 (outside root), 414 (overflow),
 *       or 500 (other error).
 *
 * HOW: Phase 1 — reject "." or ".." components via has_forbidden_components() → 403.
 *       Phase 2 — snprintf(root_canon + decoded_path) into candidate, check overflow → 414.
 *       Call realpath(candidate) to canonicalize the path.
 *
 *       If realpath succeeds: verify confinement (strncmp against root_canon + boundary
 *       check) → 403 if outside root. Copy resolved into out buffer, check size → 414.
 *
 *       If realpath fails with ENOENT (target does not exist — PUT/COPY/MKCOL destination):
 *         Walk up candidate via strrchr('/') to find the deepest existing ancestor within
 *         root_canon. Verify that ancestor is confined. Reconstruct resolved =
 *         ancestor_canon + non-existent suffix from candidate.
 *
 *       If realpath fails with any other errno → 500.
 *
 * WHY: WebDAV and S3 PUT handlers both need canonicalization, dot/dotdot rejection,
 *      root confinement, and ENOENT-parent handling for new-file paths. Centralising
 *      this logic avoids duplication and ensures consistent behaviour across protocols.
 */

int
xrootd_http_resolve_path(const char *root_canon, const char *decoded_path,
    char *out, size_t outsz)
{
    char   candidate[PATH_MAX];
    char   resolved[PATH_MAX];
    size_t root_len;
    int    n;

    if (has_forbidden_components(decoded_path))
        return 403;

    n = snprintf(candidate, sizeof(candidate), "%s%s", root_canon, decoded_path);
    if (n < 0 || (size_t) n >= sizeof(candidate))
        return 414;

    if (realpath(candidate, resolved) == NULL) {
        if (errno == ENOENT) {
            /*
             * Target does not exist yet (PUT/COPY destination, or path
             * with multiple non-existent components, e.g. S3 PUT to a new
             * subdirectory).  Walk up the candidate path to find the deepest
             * existing ancestor within root_canon, then append the
             * non-existent suffix.
             */
            char   ancestor[PATH_MAX];
            char   ancestor_canon[PATH_MAX];
            size_t candidate_len;
            char  *slash;

            candidate_len = strlen(candidate);
            if (candidate_len >= sizeof(ancestor))
                return 414;
            memcpy(ancestor, candidate, candidate_len + 1);

            do {
                slash = strrchr(ancestor, '/');
                if (slash == NULL || slash == ancestor)
                    return 404;   /* walked past root without finding anything */
                *slash = '\0';

                if (realpath(ancestor, ancestor_canon) != NULL)
                    break;        /* found an existing ancestor */
                if (errno != ENOENT)
                    return 500;
            } while (1);

            root_len = strlen(root_canon);
            if (strncmp(ancestor_canon, root_canon, root_len) != 0
                || (ancestor_canon[root_len] != '\0'
                    && ancestor_canon[root_len] != '/'))
                return 403;

            /* Reconstruct: ancestor_canon + suffix from candidate. */
            n = snprintf(resolved, sizeof(resolved), "%s%s",
                         ancestor_canon, candidate + strlen(ancestor));
            if (n < 0 || (size_t) n >= sizeof(resolved))
                return 414;
        } else {
            return 500;
        }
    }

    root_len = strlen(root_canon);
    if (strncmp(resolved, root_canon, root_len) != 0
        || (resolved[root_len] != '\0' && resolved[root_len] != '/'))
        return 403;

    {
        size_t rlen = strlen(resolved);
        if (rlen >= outsz)
            return 414;
        memcpy(out, resolved, rlen + 1);
    }

    return 0;
}
