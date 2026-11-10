/* Finite driver for the production raw-query scanners. Output-buffer canaries
 * are checked independently of the returned status, including refused input. */
#include "core/http/http_query.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* WHAT: Dispatch one public scanner call, including invalid-argument probes.
 * WHY: Refusals and policy classification must use the real implementation.
 * HOW: 1. Select null arguments explicitly. 2. Invoke the requested API. */
static int
scan(const char *operation, ngx_str_t query, const char *key, char *output,
    size_t capacity, unsigned flags)
{
    if (strcmp(operation, "null-key") == 0) {
        return brix_http_query_get(query, NULL, output, capacity, flags);
    }
    if (strcmp(operation, "null-output") == 0) {
        return brix_http_query_get(query, key, NULL, capacity, flags);
    }
    if (strcmp(operation, "has") == 0) {
        return brix_http_query_has(query, key, flags);
    }
    if (strcmp(operation, "has-null-key") == 0) {
        return brix_http_query_has(query, NULL, flags);
    }
    if (strcmp(operation, "decoded") == 0) {
        return brix_http_query_has_decoded_name(query, key, flags);
    }
    if (strcmp(operation, "decoded-null-key") == 0) {
        return brix_http_query_has_decoded_name(query, NULL, flags);
    }
    if (strcmp(operation, "decoded-null-query") == 0) {
        query.data = NULL;
        return brix_http_query_has_decoded_name(query, key, flags);
    }
    assert(strcmp(operation, "get") == 0);
    return brix_http_query_get(query, key, output, capacity, flags);
}

/* WHAT: Run one bounded query and report status plus successful output bytes.
 * WHY: A successful decode must never write beyond its advertised capacity.
 * HOW: 1. Prepare canaries. 2. Scan. 3. Verify the boundary and emit hex bytes. */
int
main(int argc, char **argv)
{
    unsigned char storage[1040];
    size_t capacity, i;
    ngx_str_t query;
    int result;

    assert(argc == 6);
    capacity = strtoul(argv[4], NULL, 10);
    assert(capacity <= 1024);
    memset(storage, 0xa5, sizeof(storage));
    if (capacity > 0) {
        storage[0] = 0;
    }
    query.data = (u_char *) argv[2];
    query.len = strlen(argv[2]);
    result = scan(argv[1], query, argv[3], (char *) storage, capacity,
                  (unsigned) strtoul(argv[5], NULL, 10));
    for (i = capacity; i < sizeof(storage); i++) {
        assert(storage[i] == 0xa5);
    }
    printf("%d:", result);
    if (result == 1 && strcmp(argv[1], "get") == 0) {
        assert(memchr(storage, 0, capacity) != NULL);
        for (i = 0; i < capacity && storage[i] != 0; i++) {
            printf("%02x", storage[i]);
        }
    }
    puts("");
    return 0;
}
