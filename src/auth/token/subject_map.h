#ifndef BRIX_TOKEN_SUBJECT_MAP_H
#define BRIX_TOKEN_SUBJECT_MAP_H

#include <stddef.h>

/*
 * token/subject_map.h — SciTokens subject→local-username mapping (phase-59 W1b).
 *
 * Resolves a token subject (or a configured username_claim value) to a local
 * username via a JSON map file: { "<subject>": "<username>", ... }. Used by the
 * `mapping` authorization strategy.
 */

/*
 * Look up `subject` in the JSON map file at `path`. On a hit copies the mapped
 * username into out (bounded by outsz) and returns 0; on miss / parse error /
 * unreadable file returns -1. Pure (no nginx runtime) — unit-testable.
 */
int brix_subject_mapfile_lookup(const char *path, const char *subject,
    char *out, size_t outsz);

#endif /* BRIX_TOKEN_SUBJECT_MAP_H */
