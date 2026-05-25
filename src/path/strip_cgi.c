#include <string.h>

/*
 * WHAT: Strip query-string suffix from an XRootD wire protocol path.
 *
 * Clients may send paths like "/data/atlas/run3/AOD.pool.root?checksum=md5"
 * containing opaque query parameters. The filesystem resolver only needs the
 * POSIX path component — everything after '?' must be discarded before any
 * subsequent canonical or confined path resolution.
 */

/* WHY: Wire protocol safety invariant.
 *
 * AGENTS.md INVARIANT #4 mandates "All wire paths → resolve_path() before open()".
 * If a query-string is left in the path string, resolve_path() would attempt to
 * find a directory named "...AOD.pool.root?checksum=md5" on disk — guaranteed
 * ENOENT. This function operates at the earliest possible point in the pipeline
 * (wire payload extraction) to prevent downstream confusion.
 */

/* HOW: Simple pointer arithmetic on strchr result.
 *
 * 1. Find first '?' character position via strchr().
 * 2. Compute substring length: distance from start to '?'.
 *    If no '?' exists, use strlen(in) for full path.
 * 3. Bound by output buffer size — truncate if path exceeds outsz.
 * 4. memcpy the computed-length prefix and NUL-terminate.
 */

void
xrootd_strip_cgi(const char *in, char *out, size_t outsz)
{
    const char *q = strchr(in, '?');
    size_t      len;

    if (q != NULL) {
        len = (size_t) (q - in);
    } else {
        len = strlen(in);
    }

    if (len >= outsz) {
        len = outsz - 1;
    }

    memcpy(out, in, len);
    out[len] = '\0';
}
