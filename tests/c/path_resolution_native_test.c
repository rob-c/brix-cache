/* Real canonical resolver: preserve absent leaf names and confinement. */
#include "fs/path/unified_internal.h"
#include <assert.h>

/* WHAT: Resolve one caller-controlled path. WHY: Verify bounded outputs and failure publication. HOW: Invoke production stages with canary-backed storage. */
int main(int argc, char **argv)
{
    assert(argc == 7);
    unsigned options = (unsigned) atoi(argv[4]);
    size_t capacity = (size_t) atoi(argv[5]); assert(capacity <= PATH_MAX);
    unsigned char output[PATH_MAX + 16]; memset(output, 0xa5, sizeof(output));
    brix_path_result_t result = {0};
    brix_path_opts_t opts = {.allow_missing_tail = !!(options & 1),
        .allow_missing_parents = !!(options & 2), .require_directory = !!(options & 4),
        .allow_root = !!(options & 8), .is_write_operation = !!(options & 3)};
    brix_resolve_ctx_t ctx = {.root_canon = argv[2], .resolved = (char *) output,
        .resolvsz = capacity, .result = &result, .depth = 1};
    if (!strcmp(argv[6], "no-result")) { ctx.result = NULL; }
    brix_path_status_t rc;
    if (!strcmp(argv[1], "tail")) { rc = brix_resolve_missing_tail(&ctx, argv[3]); }
    else if (!strcmp(argv[1], "parents")) { rc = brix_resolve_missing_parents(&ctx, argv[3]); }
    else if (!strcmp(argv[1], "finish")) { rc = brix_finish_resolved(&ctx, argv[3], opts); }
    else {
        rc = brix_path_resolve_cstr(NULL, argv[2], argv[3], opts,
            (char *) output, capacity, ctx.result);
    }
    for (size_t n = capacity; n < sizeof(output); ++n) { assert(output[n] == 0xa5); }
    printf("status=%d confined=%u type=%ld\n", rc, result.is_confined, (long) result.type);
    if (rc == BRIX_PATH_STATUS_OK) { printf("%s\n", output); }
    return 0;
}
