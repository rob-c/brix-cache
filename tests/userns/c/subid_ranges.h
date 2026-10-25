/* Test-only discovery of the caller's actual subordinate-id allocation.
 * Requires: libc stdio, pwd and unistd; no nginx or host-privilege changes.
 * Both namespace drivers map 65536 ids, but the outer start is host policy,
 * not the historical hard-coded 100000 used by a particular developer.
 */
#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>

/* ---- Parse one subordinate-id allocation ----
 * WHAT: Return 1 and its start only for an owned, sufficient, valid range.
 * WHY: An unrelated user's range or malformed entry must never be selected.
 * HOW: 1. Parse the complete row. 2. Match name or numeric uid. 3. Bound ids.
 */
static inline int
brix_test_subid_parse(const char *line, const char *name, uid_t uid,
    uint32_t *start)
{
    char owner[256], numeric[32], extra;
    unsigned long long first, count;

    if (sscanf(line, "%255[^:]:%llu:%llu %c", owner, &first, &count,
               &extra) != 3) {
        return 0;
    }
    snprintf(numeric, sizeof(numeric), "%u", (unsigned) uid);
    if (strcmp(owner, name) != 0 && strcmp(owner, numeric) != 0) {
        return 0;
    }
    if (first == 0 || count < 65536 || count > UINT32_MAX
        || first > UINT32_MAX - count) {
        return 0;
    }
    *start = (uint32_t) first;
    return 1;
}

/* ---- Discover an allocated range without modifying host policy ----
 * WHAT: Format the caller's owned range start, returning 0 or -1 if absent.
 * WHY: uid and gid allocations can differ; read each authoritative file.
 * HOW: 1. Resolve the outer caller. 2. Scan rows. 3. Close and free resources.
 */
static inline int
brix_test_subid_start(const char *path, char *output, size_t capacity)
{
    struct passwd *caller = getpwuid(getuid());
    FILE *source;
    char *line = NULL;
    size_t allocated = 0;
    uint32_t start;
    int found = -1;

    if (caller == NULL || capacity < 11) {
        return -1;
    }
    source = fopen(path, "r");
    if (source == NULL) {
        return -1;
    }
    while (getline(&line, &allocated, source) >= 0) {
        if (brix_test_subid_parse(line, caller->pw_name, getuid(), &start)) {
            snprintf(output, capacity, "%u", start);
            found = 0;
            break;
        }
    }
    free(line);
    fclose(source);
    return found;
}
