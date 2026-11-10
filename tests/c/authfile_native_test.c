/* Parse an actual authorization database and evaluate a canonical request. */
#include "auth/authz/acc/acc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct { unsigned calls; unsigned fail_at; } allocation_fault_t;
void *__real_ngx_pnalloc(ngx_pool_t *pool, size_t size);

/* WHAT: Refuse one pool allocation while parsing an explicitly owned file.
 * WHY: A truncated token stream must never become an accepted generation.
 * HOW: Count only this fixture's parser allocations through its log context. */
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    allocation_fault_t *state = pool->log->data;
    if (state != NULL && ++state->calls == state->fail_at) { return NULL; }
    return __real_ngx_pnalloc(pool, size);
}

/* WHAT: Represent an absent identity attribute explicitly.
 * WHY: Missing attributes must not match compound constraints.
 * HOW: Only the fixture sentinel becomes NULL. */
static const char *attribute(const char *value)
{
    return strcmp(value, "-") == 0 ? NULL : value;
}

/* WHAT: Drive the parser, entity builder, canonicalizer and authorization engine.
 * WHY: A successfully loaded rule must grant only the intended identity/path.
 * HOW: Keep all tables and request strings owned until after the decision. */
int main(int argc, char **argv)
{
    assert(argc == 11);
    allocation_fault_t fault = {.fail_at = (unsigned)atoi(argv[10])};
    ngx_log_t log = {.data = &fault};
    ngx_time_init();
    brix_acc_tables_t *tables = brix_acc_authfile_parse(&log, argv[1],
                                argv[2][0], atoi(argv[3]));
    log.data = NULL;
    if (tables == NULL) { puts("-1 0 0"); return 0; }
    ngx_pool_t *pool = ngx_create_pool(4096, &log);
    assert(pool != NULL);
    brix_acc_entity_t *entity = brix_acc_entity_build(pool, attribute(argv[4]),
        attribute(argv[5]), strcmp(argv[4], "*") != 0, attribute(argv[6]),
        attribute(argv[7]), attribute(argv[8]));
    assert(entity != NULL);
    const char *path = brix_acc_canon_path(pool, argv[9]);
    assert(path != NULL);
    brix_acc_privs_t privileges = brix_acc_access(tables, entity, path, BRIX_AOP_ANY);
    printf("0 %u %lu\n", (unsigned)privileges, (unsigned long)tables->rule_count);
    ngx_destroy_pool(pool);
    brix_acc_tables_free(tables);
    brix_acc_tables_free(NULL);
    return 0;
}
