/* Exercise the production per-uid registry with observable transport factories.
 * The wrapped factories own typed records so identity lifetime, cleanup, and
 * connection parameters can be checked without requiring a mounted filesystem.
 */
#include "apps/fs/xrootdfs_internal.h"
#include <assert.h>
#include <limits.h>
#include <unistd.h>

typedef struct {
    const brix_opts *options;
    char name[64];
    int manager;
} transport_record;

typedef struct {
    pthread_barrier_t *barrier;
    uid_t uid;
    brix_pool *pool;
    brix_mgr *manager;
    int result;
} identity_request;

void *__real_calloc(size_t count, size_t size);

/* WHAT: Inject only the explicitly requested allocation refusal.
 * WHY: Initialization must fail before any identity can be served.
 * HOW: 1) Check the test-only switch. 2) Otherwise call the real allocator. */
void *__wrap_calloc(size_t count, size_t size)
{
    if (getenv("BRIX_IDENTITY_INIT_FAIL") != NULL) { return NULL; }
    return __real_calloc(count, size);
}

/* WHAT: Build one observable transport with its retained identity template.
 * WHY: A cached identity must never point at another caller's mutable options.
 * HOW: 1) Check the cloned options. 2) Save its name and pointer. */
static transport_record *transport_create(const brix_opts *options, int manager)
{
    transport_record *record = calloc(1, sizeof(*record));
    assert(record != NULL && options != &g_opts);
    assert(options->sss_user != NULL);
    assert(strcmp(g_opts.sss_user, "mount-owner") == 0);
    assert(options->max_stall_ms == g_opts.max_stall_ms);
    record->options = options;
    record->manager = manager;
    snprintf(record->name, sizeof(record->name), "%s", options->sss_user);
    return record;
}

/* WHAT: Record the metadata pool request or refuse it at the transport seam.
 * WHY: Authentication failure must remain attached to the requesting uid.
 * HOW: 1) Validate parameters. 2) Delay for contention. 3) Allocate or fail. */
brix_pool *__wrap_brix_pool_create(const brix_url *url, const brix_opts *options,
                                   int count, brix_status *status)
{
    assert(url == &g_url && count == g_ident_conns);
    printf("pool %s %d\n", options->sss_user, count);
    usleep(20000);
    if (getenv("BRIX_IDENTITY_POOL_FAIL") != NULL) {
        brix_status_set(status, XRDC_EAUTH, 0, "identity pool refusal");
        return NULL;
    }
    return (brix_pool *)transport_create(options, 0);
}

/* WHAT: Record the data manager request or refuse its construction.
 * WHY: The manager must carry the same uid and resilience settings as the pool.
 * HOW: 1) Check all parameters. 2) Allocate the observable transport or fail. */
brix_mgr *__wrap_brix_mgr_create(const brix_url *url, const brix_opts *options,
    int count, int eager, int stall, int keepalive, int retries, brix_status *status)
{
    assert(url == &g_url && count == g_ident_streams && eager == count);
    assert(stall == g_max_stall && keepalive == g_keepalive);
    assert(retries == g_max_retries);
    printf("manager %s %d\n", options->sss_user, count);
    if (getenv("BRIX_IDENTITY_MANAGER_FAIL") != NULL) {
        brix_status_set(status, XRDC_EAUTH, 0, "identity manager refusal");
        return NULL;
    }
    return (brix_mgr *)transport_create(options, 1);
}

/* WHAT: Check retained identity storage before releasing a transport.
 * WHY: Shutdown and failed-manager cleanup must free exactly their own records.
 * HOW: 1) Verify kind and still-live name. 2) Report and release ownership. */
static void transport_destroy(transport_record *record, int manager)
{
    assert(record != NULL && record->manager == manager);
    assert(strcmp(record->name, record->options->sss_user) == 0);
    printf("destroy-%s %s\n", manager ? "manager" : "pool", record->name);
    free(record);
}

/* WHAT: Close the metadata seam. WHY: Check ownership. HOW: Validate and free. */
void __wrap_brix_pool_destroy(brix_pool *pool)
{
    transport_destroy((transport_record *)pool, 0);
}

/* WHAT: Close the data seam. WHY: Check ownership. HOW: Validate and free. */
void __wrap_brix_mgr_destroy(brix_mgr *manager)
{
    transport_destroy((transport_record *)manager, 1);
}

/* WHAT: Issue a simultaneous registry lookup.
 * WHY: One uid must create one connection set even with concurrent requests.
 * HOW: 1) Wait for the start barrier. 2) Preserve the result and both pointers. */
static void *identity_worker(void *argument)
{
    identity_request *request = argument;
    pthread_barrier_wait(request->barrier);
    request->result = xfs_ident_get(request->uid, &request->pool, &request->manager);
    return NULL;
}

/* WHAT: Check the mount-wide fallback only when identity mode is disabled.
 * WHY: Disabling the feature intentionally preserves its compatibility path.
 * HOW: 1) Supply distinct sentinels. 2) Check optional outputs and shutdown. */
static void check_disabled(void)
{
    brix_pool *pool = NULL;
    brix_mgr *manager = NULL;
    g_sss_ident = 0;
    g_pool = (brix_pool *)&g_opts;
    g_mgr = (brix_mgr *)&g_url;
    assert(xfs_ident_init() == 0);
    assert(xfs_ident_get(0, &pool, &manager) == 0);
    assert(pool == g_pool && manager == g_mgr);
    assert(xfs_ident_get(1, NULL, NULL) == 0);
    xfs_ident_shutdown();
}

/* WHAT: Check cache reuse, uid separation, and the hard capacity refusal.
 * WHY: No new user may inherit a mount owner's or previous user's connection.
 * HOW: 1) Fill two slots. 2) Repeat optional lookups. 3) Refuse a third uid. */
static void check_capacity(void)
{
    brix_pool *first = NULL, *second = NULL, *again = NULL;
    brix_mgr *manager = NULL, *other = NULL;
    assert(xfs_ident_get(0, &first, &manager) == 0);
    assert(xfs_ident_get((uid_t)UINT_MAX - 1, &second, &other) == 0);
    assert(first != second && manager != other);
    assert(xfs_ident_get(0, &again, NULL) == 0 && again == first);
    assert(xfs_ident_get(0, NULL, NULL) == 0);
    assert(xfs_ident_get(0, NULL, &other) == 0 && other == manager);
    again = first;
    assert(xfs_ident_get(1, &again, &other) == -EMFILE);
    assert(again == first && other == manager);
}

/* WHAT: Check that failed creation is cached and never falls back.
 * WHY: Serving an authentication failure under the mount uid is unsafe.
 * HOW: 1) Fail twice for one uid. 2) Remove the injection. 3) Use a new uid. */
static void check_failed(void)
{
    brix_pool *pool = NULL;
    brix_mgr *manager = NULL;
    assert(xfs_ident_get(0, &pool, &manager) == -EACCES);
    assert(pool == NULL && manager == NULL);
    unsetenv("BRIX_IDENTITY_POOL_FAIL");
    unsetenv("BRIX_IDENTITY_MANAGER_FAIL");
    assert(xfs_ident_get(0, &pool, &manager) == -EACCES);
    assert(pool == NULL && manager == NULL);
    assert(xfs_ident_get((uid_t)UINT_MAX - 1, &pool, &manager) == 0);
    assert(pool != NULL && manager != NULL);
}

/* WHAT: Check concurrent callers share one published result per uid.
 * WHY: Waiters must see a complete transport pair or a consistent refusal.
 * HOW: 1) Start sixteen callers together. 2) Join. 3) Compare their results. */
static void check_concurrent(int failed)
{
    pthread_barrier_t barrier;
    pthread_t threads[16];
    identity_request requests[16] = {0};
    assert(pthread_barrier_init(&barrier, NULL, 16) == 0);
    for (int index = 0; index < 16; index++) {
        requests[index].barrier = &barrier;
        assert(pthread_create(&threads[index], NULL, identity_worker,
                              &requests[index]) == 0);
    }
    for (int index = 0; index < 16; index++) {
        assert(pthread_join(threads[index], NULL) == 0);
        assert(requests[index].result == (failed ? -EACCES : 0));
        assert(requests[index].pool == requests[0].pool);
        assert(requests[index].manager == requests[0].manager);
    }
    pthread_barrier_destroy(&barrier);
}

/* WHAT: Run one registry contract in a fresh process.
 * WHY: Process ownership bounds production globals and shutdown lifetime.
 * HOW: 1) Configure explicit values. 2) Run the selected contract. 3) Shut down. */
int main(int argc, char **argv)
{
    assert(argc == 2);
    g_opts.sss_user = "mount-owner";
    g_opts.max_stall_ms = 137;
    g_sss_ident = 1;
    g_ident_max = 2;
    g_ident_conns = 3;
    g_ident_streams = 2;
    g_max_stall = 1234;
    g_keepalive = 321;
    g_max_retries = 7;
    if (strcmp(argv[1], "disabled") == 0) { check_disabled(); return 0; }
    if (strcmp(argv[1], "low-limit") == 0) { g_ident_max = -4; }
    if (strcmp(argv[1], "high-limit") == 0) { g_ident_max = 2000; }
    int result = xfs_ident_init();
    if (strcmp(argv[1], "allocation") == 0) {
        assert(result == -1);
        unsetenv("BRIX_IDENTITY_INIT_FAIL");
        assert(xfs_ident_init() == 0);
    } else { assert(result == 0); }
    if (strcmp(argv[1], "capacity") == 0) { check_capacity(); }
    if (strcmp(argv[1], "failed") == 0) { check_failed(); }
    if (strcmp(argv[1], "concurrent") == 0) { check_concurrent(0); }
    if (strcmp(argv[1], "concurrent-failed") == 0) { check_concurrent(1); }
    if (strcmp(argv[1], "low-limit") == 0) { assert(g_ident_max == 1); }
    if (strcmp(argv[1], "high-limit") == 0) { assert(g_ident_max == 1024); }
    xfs_ident_shutdown();
    xfs_ident_shutdown();
    puts("identity-contract-ok");
    return 0;
}
