/* Real driver descriptors, selectively degraded at their advertised interface. */
#include "fs/tier/tier.h"
#include "fs/backend/frm/sd_frm.h"
#include <assert.h>
#include <string.h>

/* WHAT: Remove a named byte-I/O or staging slot from a private descriptor.
 * WHY: Every required slot must independently prevent readiness when absent.
 * HOW: Assign typed NULL values without changing any real driver globally. */
static void remove_io(brix_sd_driver_t *driver, const char *name)
{
#define REMOVE(field) if (!strcmp(name, #field)) { driver->field = NULL; }
    REMOVE(open); REMOVE(pread); REMOVE(stat); REMOVE(fstat);
    REMOVE(staged_open); REMOVE(staged_write); REMOVE(staged_commit); REMOVE(staged_abort);
#undef REMOVE
}

/* WHAT: Remove a named namespace/recall slot or advertised capability.
 * WHY: Byte I/O alone cannot fulfill the cache, stage or nearline contracts.
 * HOW: Mutate only the selected descriptor field or capability bit. */
static void remove_namespace(brix_sd_driver_t *driver, const char *name)
{
#define REMOVE(field) if (!strcmp(name, #field)) { driver->field = NULL; }
    REMOVE(unlink); REMOVE(opendir); REMOVE(readdir); REMOVE(closedir);
    REMOVE(getxattr); REMOVE(setxattr); REMOVE(recall);
#undef REMOVE
#define REMOVE_CAP(bit) if (!strcmp(name, #bit)) { driver->caps &= ~BRIX_SD_CAP_##bit; }
    REMOVE_CAP(RANGE_READ); REMOVE_CAP(RANDOM_WRITE); REMOVE_CAP(DIRS);
    REMOVE_CAP(XATTR); REMOVE_CAP(NEARLINE);
#undef REMOVE_CAP
}

/* WHAT: Compare the public readiness report to the selected missing contract.
 * WHY: A stale or misclassified report can activate a driver lacking operations.
 * HOW: Supply the chosen nullable input and check status, slot/cap and project. */
static void check_gap(const brix_tier_gap_t *result, const brix_tier_cfg_t *config,
                       const char *gap)
{
    int absent = !strncmp(gap, "null-", 5);
    const char *expected = absent ? "open" : gap;
    int cap = expected[0] >= 'A' && expected[0] <= 'Z';
    assert(!strcmp(cap ? result->cap : result->slot, expected));
    assert((cap ? result->slot : result->cap)[0] == '\0');
    const char *project = "SP3";
    if (!strcmp(config->driver, "pblock") || !strcmp(config->driver, "xroot")) {
        project = "SP2";
    }
    if (!strcmp(config->driver, "tape")) { project = "SP5"; }
    assert(!strcmp(result->sp_item, absent ? "SP1" : project));
}

/* WHAT: Check nullable readiness inputs and clearing of stale diagnostic fields.
 * WHY: Missing configurations must fail closed, and complete contracts must reset gaps.
 * HOW: Invoke the public API once, then inspect the selected outcome. */
static void check_status(brix_tier_cfg_t *config, brix_sd_instance_t *probe,
                          const char *gap)
{
    brix_tier_gap_t result;
    memset(&result, 0xa5, sizeof(result));
    if (!strcmp(gap, "null-driver")) { probe->driver = NULL; }
    brix_tier_status_t status = brix_tier_status(
        !strcmp(gap, "null-config") ? NULL : config,
        !strcmp(gap, "null-probe") ? NULL : probe,
        !strcmp(gap, "null-gap") ? NULL : &result);
    if (!strcmp(gap, "null-gap")) { assert(status == BRIX_TIER_READY); return; }
    if (!strcmp(gap, "ready")) {
        brix_tier_gap_t empty = {0};
        assert(status == BRIX_TIER_READY && !memcmp(&result, &empty, sizeof(result)));
        return;
    }
    assert(status == BRIX_TIER_NEEDS_DEV);
    check_gap(&result, config, gap);
}

/* WHAT: Probe complete and deliberately incomplete real driver descriptors.
 * WHY: No fake operation implementation should define the readiness oracle.
 * HOW: Copy POSIX or an actual stub-tape descriptor, remove one promise, check. */
int main(int argc, char **argv)
{
    assert(argc == 5);
    ngx_log_t log = {0};
    ngx_cycle_t cycle = {0};
    cycle.log = &log; ngx_cycle = &cycle; ngx_os_argv = argv;
    ngx_time_init(); assert(ngx_os_init(&log) == NGX_OK);
    brix_tier_cfg_t config = {0};
    strcpy(config.driver, argv[3]);
    config.role = BRIX_TIER_BACKEND;
    if (!strcmp(argv[1], "cache")) { config.role = BRIX_TIER_CACHE; }
    if (!strcmp(argv[1], "stage")) { config.role = BRIX_TIER_STAGE; }
    config.nearline = !strcmp(argv[1], "nearline");
    brix_sd_instance_t *tape = NULL;
    brix_sd_driver_t driver = brix_sd_posix_driver;
    if (config.nearline) {
        tape = brix_sd_frm_create("stub", argv[4], &log);
        assert(tape != NULL);
        driver = *tape->driver;
    }
    remove_io(&driver, argv[2]); remove_namespace(&driver, argv[2]);
    brix_sd_instance_t probe = {.driver = &driver};
    check_status(&config, &probe, argv[2]);
    if (tape != NULL) { brix_sd_frm_destroy(tape); }
    return 0;
}
