/* Real subject-map parsing and audit formatting with bounded allocation faults. */
#include "core/ngx_brix_module.h"
#include "auth/token/subject_map.h"
#include <assert.h>

typedef struct { ngx_cycle_t cycle; const char *mode; } fixture;

/* WHAT: Select a process-local fault. WHY: Production code stays unchanged.
 * HOW: Read the fixture attached to the nginx cycle. */
static int mode(const char *name)
{
    return ngx_cycle && !strcmp(((fixture *) ngx_cycle)->mode, name);
}

void *__real_malloc(size_t size);
/* WHAT: Refuse the subject-map buffer. WHY: Failure must not return an identity.
 * HOW: Match its bounded allocation; delegate all other heap operations. */
void *__wrap_malloc(size_t size)
{
    return mode("allocation") && size == 256 * 1024 ? NULL : __real_malloc(size);
}

void *__real_ngx_pnalloc(ngx_pool_t *pool, size_t size);
/* WHAT: Refuse audit-string allocation. WHY: OOM must expose an empty result.
 * HOW: Fail only the explicitly selected case. */
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    return mode("allocation") ? NULL : __real_ngx_pnalloc(pool, size);
}

/* WHAT: Query one real map file. WHY: Bounds and null identity are fail-closed.
 * HOW: Surround the caller buffer with canaries, invoke, verify, and emit. */
static void mapping(char **args)
{
    unsigned char bytes[272]; memset(bytes, 0xa5, sizeof(bytes));
    size_t capacity = strtoul(args[5], NULL, 10); assert(capacity <= 256);
    const char *path = !strcmp(args[3], "<null>") ? NULL : args[3];
    const char *subject = !strcmp(args[4], "<null>") ? NULL : args[4];
    char *output = (char *) bytes + 8;
    int rc = brix_subject_mapfile_lookup(path, subject, output, capacity);
    for (size_t i = 0; i < 8; i++) {
        assert(bytes[i] == 0xa5 && bytes[8 + capacity + i] == 0xa5);
    }
    printf("%d\n", rc);
    if (!rc) {
        size_t length = strnlen(output, capacity); assert(length < capacity);
        assert(fwrite(output, 1, length, stdout) == length);
    }
}

/* WHAT: Describe an identity without mutating it. WHY: Audit views borrow state.
 * HOW: Fill bounded C-string views, assert failure ownership, print exact bytes. */
static void describe(char **args)
{
    ngx_log_t log = {0}; ngx_pool_t *pool = ngx_create_pool(4096, &log); assert(pool);
    brix_identity_t identity = {0};
    identity.dn = (ngx_str_t) {strlen(args[3]), (u_char *) args[3]};
    identity.subject = (ngx_str_t) {strlen(args[4]), (u_char *) args[4]};
    identity.auth_method = strtoul(args[5], NULL, 10);
    brix_identity_t before = identity;
    ngx_str_t output = brix_identity_describe(mode("null-id") ? NULL : &identity,
                                             mode("null-pool") ? NULL : pool);
    assert(!memcmp(&before, &identity, sizeof(identity)));
    if (mode("null-pool") || mode("allocation")) { assert(!output.data && !output.len); }
    else { assert(output.data && fwrite(output.data, 1, output.len, stdout) == output.len); }
    ngx_destroy_pool(pool);
}

/* WHAT: Select a public identity operation. WHY: Each fault has isolated state.
 * HOW: Bind one fixture and dispatch to a bounded contract. */
int main(int argc, char **argv)
{
    assert(argc == 6); fixture f = {0}; f.mode = argv[2]; ngx_cycle = &f.cycle;
    if (!strcmp(argv[1], "map")) { mapping(argv); }
    else { assert(!strcmp(argv[1], "describe")); describe(argv); }
    ngx_cycle = NULL;
    return 0;
}
