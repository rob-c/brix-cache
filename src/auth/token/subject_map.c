/*
 * token/subject_map.c — subject→username map lookup (see header).
 *
 * WHAT: Reads a small JSON map file { "<subject>": "<user>", ... } and returns
 *       the local username for a given token subject. WHY: the `mapping`
 *       authorization strategy turns an external token subject into a local
 *       identity whose filesystem/ACL permissions then apply. HOW: bounded file
 *       read into a heap buffer, then json_get_string() keyed by the literal
 *       subject. Pure C (no nginx runtime) so it is unit-testable standalone.
 */

#include "subject_map.h"
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Maps are tiny (subject→user lines); cap the read so a bad path can't OOM. */
#define XROOTD_SUBJECT_MAP_MAX  (256 * 1024)

int
xrootd_subject_mapfile_lookup(const char *path, const char *subject,
    char *out, size_t outsz)
{
    FILE   *f;
    char   *buf;
    size_t  got;
    ssize_t n;

    if (path == NULL || path[0] == '\0' || subject == NULL) {
        return -1;
    }

    f = fopen(path, "re");                  /* 'e' = O_CLOEXEC */
    if (f == NULL) {
        return -1;
    }

    buf = malloc(XROOTD_SUBJECT_MAP_MAX);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }

    got = fread(buf, 1, XROOTD_SUBJECT_MAP_MAX - 1, f);
    fclose(f);
    buf[got] = '\0';

    n = json_get_string(buf, got, subject, out, outsz);
    free(buf);

    return (n >= 0) ? 0 : -1;
}
