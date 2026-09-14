/* Exercise the production swarm registration and HTTP fill registries without
 * starting workers or making network requests. No production APIs are stubbed. */
#include "protocols/cvmfs/swarm_internal.h"
#include "protocols/shared/http_cache_fill_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* WHAT: Allocate an unpublished fill fixture. WHY: Keep credential padding zero.
 * HOW: 1. Allocate zeroed storage. 2. Set its instance, key and caller identity. */
static brix_http_cache_fill_ctx_t *
new_fill(brix_sd_instance_t *instance, const char *key, const char *principal)
{
    brix_http_cache_fill_ctx_t *fill = calloc(1, sizeof(*fill));
    assert(fill != NULL);
    fill->inst = instance;
    snprintf(fill->key, sizeof(fill->key), "%s", key);
    snprintf(fill->cred.principal, sizeof(fill->cred.principal), "%s", principal);
    return fill;
}

/* WHAT: Verify normal registration and coalescing lifecycle.
 * WHY: Moving state must preserve in-place updates and exact-list removal.
 * HOW: 1. Register/update an export. 2. Publish two fills. 3. Remove tail/head. */
static void
test_success(void)
{
    brix_sd_instance_t instance = {0};
    brix_http_cache_fill_ctx_t *first = new_fill(&instance, "first", "alice");
    brix_http_cache_fill_ctx_t *second = new_fill(&instance, "second", "alice");
    const cvmfs_swarm_reg_t *registration;

    brix_cvmfs_swarm_regs_reset();
    brix_cvmfs_swarm_register("/export", 10, NULL, NULL);
    assert(cvmfs_swarm_reg_count() == 1);
    registration = cvmfs_swarm_reg_at(0);
    assert(registration != NULL && registration->interval == 10);
    brix_cvmfs_swarm_register("/export", 20, NULL, NULL);
    assert(cvmfs_swarm_reg_count() == 1);
    assert(cvmfs_swarm_reg_at(0) == registration && registration->interval == 20);

    brix_http_fill_publish(first);
    brix_http_fill_publish(second);
    assert(brix_http_fill_find(&instance, "first", &first->cred) == first);
    assert(brix_http_fill_find(&instance, "second", &second->cred) == second);
    brix_http_fill_unpublish(first);
    assert(brix_http_fill_find(&instance, "first", &first->cred) == NULL);
    assert(brix_http_fill_find(&instance, "second", &second->cred) == second);
    brix_http_fill_unpublish(second);
    assert(brix_http_fill_find(&instance, "second", &second->cred) == NULL);
    free(first);
    free(second);
}

/* WHAT: Check registry capacity and idempotent removal errors.
 * WHY: Refused work must not corrupt existing registration or in-flight state.
 * HOW: 1. Fill registration capacity. 2. Refuse overflow. 3. Remove absent fills. */
static void
test_errors(void)
{
    brix_sd_instance_t instance = {0};
    brix_http_cache_fill_ctx_t *present = new_fill(&instance, "key", "alice");
    brix_http_cache_fill_ctx_t *absent = new_fill(&instance, "key", "alice");
    ngx_uint_t index;
    char root[32];

    brix_cvmfs_swarm_regs_reset();
    assert(cvmfs_swarm_reg_at(0) == NULL);
    for (index = 0; index < CVMFS_SWARM_MAX_EXPORTS; index++) {
        snprintf(root, sizeof(root), "/export-%lu", (unsigned long) index);
        brix_cvmfs_swarm_register(root, 10, NULL, NULL);
    }
    brix_cvmfs_swarm_register("/overflow", 10, NULL, NULL);
    assert(cvmfs_swarm_reg_count() == CVMFS_SWARM_MAX_EXPORTS);
    assert(cvmfs_swarm_reg_at(CVMFS_SWARM_MAX_EXPORTS) == NULL);

    brix_http_fill_publish(present);
    brix_http_fill_unpublish(absent);
    assert(brix_http_fill_find(&instance, "key", &present->cred) == present);
    brix_http_fill_unpublish(present);
    brix_http_fill_unpublish(present);
    assert(brix_http_fill_find(&instance, "key", &present->cred) == NULL);
    free(present);
    free(absent);
}

/* WHAT: Check reload visibility, bounded registration and credential isolation.
 * WHY: Removed exports and another caller's fill must never become selectable.
 * HOW: 1. Reset registration visibility. 2. Reject a long root. 3. Match credentials. */
static void
test_isolation(void)
{
    brix_sd_instance_t instance = {0};
    brix_sd_instance_t other_instance = {0};
    brix_http_cache_fill_ctx_t *alice = new_fill(&instance, "key", "alice");
    brix_http_cache_fill_ctx_t *bob = new_fill(&instance, "key", "bob");
    brix_http_fill_cred_t anonymous = {0};
    char long_root[257];

    brix_cvmfs_swarm_regs_reset();
    brix_cvmfs_swarm_register("/retired", 10, NULL, NULL);
    brix_cvmfs_swarm_regs_reset();
    assert(cvmfs_swarm_reg_count() == 0 && cvmfs_swarm_reg_at(0) == NULL);
    memset(long_root, 'x', sizeof(long_root) - 1);
    long_root[sizeof(long_root) - 1] = '\0';
    brix_cvmfs_swarm_register(long_root, 10, NULL, NULL);
    assert(cvmfs_swarm_reg_count() == 0);

    brix_http_fill_publish(alice);
    brix_http_fill_publish(bob);
    assert(brix_http_fill_find(&instance, "key", &alice->cred) == alice);
    assert(brix_http_fill_find(&instance, "key", &bob->cred) == bob);
    assert(brix_http_fill_find(&instance, "key", &anonymous) == NULL);
    assert(brix_http_fill_find(&other_instance, "key", &alice->cred) == NULL);
    brix_http_fill_unpublish(bob);
    brix_http_fill_unpublish(alice);
    free(alice);
    free(bob);
}

/* WHAT: Run one independent regression group. WHY: Report useful pytest cases.
 * HOW: 1. Dispatch by group name. 2. Return only after assertions pass. */
int
main(int argc, char **argv)
{
    assert(argc == 2);
    if (strcmp(argv[1], "success") == 0) {
        test_success();
        return 0;
    }
    if (strcmp(argv[1], "error") == 0) {
        test_errors();
        return 0;
    }
    assert(strcmp(argv[1], "isolation") == 0);
    test_isolation();
    return 0;
}
