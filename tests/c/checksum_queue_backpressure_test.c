/* WHAT: Exercise the real path/handle checksum-post functions.
 * WHY: A full worker queue must not turn a checksum into event-loop work.
 * HOW: Inject only allocation, VFS ownership, metric and response boundaries;
 *      production function bodies and the write-policy constructor follow below.
 */
#include "protocols/root/query/checksum_qcksum_internal.h"
#include "core/aio/aio.h"
#include "protocols/root/response/response.h"
#include "fs/path/path.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ngx_pool_t pool;
    ngx_thread_task_t *allocation;
    int busy;
    int allocation_failure;
    int posts;
    int allocations;
    int cleanup_records;
    int closes;
    int waits;
    int errors;
    int access_records;
    brix_vfs_mutation_policy_t expected_policy;
} queue_fixture;

static ngx_int_t brix_qcksum_handle_try_async(brix_qcksum_req_t *request,
    int index, const char *resolved, ngx_flag_t *handled);
static ngx_int_t brix_qcksum_try_async(brix_qcksum_req_t *request,
    brix_vfs_file_t *handle, int descriptor, ngx_flag_t *handled);

/* WHAT: Keep metric plumbing outside the scheduling/ownership unit.
 * WHY: The test counts the protocol response, not an exporter implementation.
 * HOW: Retain expression evaluation without linking shared metric storage. */
#undef BRIX_OP_ERR
#define BRIX_OP_ERR(context, operation) ((void) (context), (void) (operation))

/* WHAT: Inject only the heap-allocation edge, retaining real ownership code.
 * WHY: Repeated retry requests must share one bounded allocation.
 * HOW: Fail on demand or record a real malloc block for the production slot. */
void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    queue_fixture *fixture = (queue_fixture *) log;
    if (fixture->allocation_failure) {
        return NULL;
    }
    fixture->allocation = malloc(size);
    assert(fixture->allocation != NULL);
    fixture->allocations++;
    return fixture->allocation;
}

/* WHAT: Model nginx's cleanup registration with real heap-backed records.
 * WHY: The production concern must register only one owner per connection.
 * HOW: Attach an allocated record and payload to the actual SDK pool list. */
ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *pool, size_t size)
{
    queue_fixture *fixture = (queue_fixture *) pool;
    ngx_pool_cleanup_t *cleanup = calloc(1, sizeof(*cleanup));
    assert(cleanup != NULL);
    cleanup->data = calloc(1, size);
    assert(cleanup->data != NULL);
    cleanup->next = pool->cleanup;
    pool->cleanup = cleanup;
    fixture->cleanup_records++;
    return cleanup;
}

/* WHAT: Copy the fixture's short diagnostic strings through the SDK signature.
 * WHY: Keep nginx string object linkage outside this scheduling unit.
 * HOW: Use the standard bounded formatter and return its terminator. */
u_char *
ngx_cpystrn(u_char *destination, u_char *source, size_t capacity)
{
    int length = snprintf((char *) destination, capacity, "%s", source);
    assert(length >= 0 && (size_t) length < capacity);
    return destination + length;
}

/* WHAT: Inject accepted/busy queue results without running another thread.
 * WHY: The full-queue branch must be deterministic, not timing-dependent.
 * HOW: Preserve the helper's posted flag and record the submitted context. */
ngx_int_t
brix_aio_post_task(brix_ctx_t *context, ngx_connection_t *connection,
    ngx_thread_pool_t *pool, ngx_thread_task_t *task,
    const char *message, ngx_flag_t *posted)
{
    queue_fixture *fixture = connection->data;
    (void) context;
    (void) message;
    assert(pool != NULL && task == fixture->allocation);
    brix_cksum_aio_t *query = task->ctx;
    assert(query->mutation_policy == fixture->expected_policy);
    fixture->posts++;
    *posted = !fixture->busy;
    task->event.active = *posted;
    return NGX_OK;
}

/* WHAT: Supply the expected storage object without opening a real export.
 * WHY: Only whether the caller retains/closes its handle is under test.
 * HOW: Require a path-owned handle and produce an empty opaque object. */
void
brix_vfs_file_sd_obj(const brix_vfs_file_t *handle, brix_sd_obj_t *object)
{
    assert(handle != NULL);
    memset(object, 0, sizeof(*object));
}

/* WHAT: Observe path-owned VFS handle release.
 * WHY: A busy path request must close its temporary handle exactly once.
 * HOW: Resolve the fixture from its log pointer and count the close. */
ngx_int_t
brix_vfs_close(brix_vfs_file_t *handle, ngx_log_t *log)
{
    queue_fixture *fixture = (queue_fixture *) log;
    assert(handle != NULL);
    fixture->closes++;
    return NGX_OK;
}

/* WHAT: Observe the explicit retry response.
 * WHY: Busy must not become either successful compute or a hard I/O error.
 * HOW: Require a one-second retry and leave a distinct return marker. */
ngx_int_t
brix_send_wait(brix_ctx_t *context, ngx_connection_t *connection, uint32_t seconds)
{
    queue_fixture *fixture = connection->data;
    (void) context;
    assert(seconds == 1);
    fixture->waits++;
    return NGX_DONE;
}

/* WHAT: Preserve an allocator failure as a hard no-memory response.
 * WHY: Backpressure must not hide allocation errors.
 * HOW: Check the wire error and count exactly one error reply. */
ngx_int_t
brix_send_error(brix_ctx_t *context, ngx_connection_t *connection,
    uint16_t error, const char *message)
{
    queue_fixture *fixture = connection->data;
    (void) context;
    (void) message;
    assert(error == kXR_NoMemory);
    fixture->errors++;
    return NGX_DONE;
}

/* WHAT: Count diagnostic access records without depending on a log file.
 * WHY: Refusals must remain operator-visible.
 * HOW: Retain the production boundary's exact SDK signature. */
void
brix_log_access(brix_ctx_t *context, ngx_connection_t *connection,
    const char *verb, const char *path, const char *detail,
    ngx_uint_t ok, uint16_t error, const char *message, size_t bytes)
{
    queue_fixture *fixture = connection->data;
    (void) context; (void) verb; (void) path; (void) detail;
    (void) ok; (void) error; (void) message; (void) bytes;
    fixture->access_records++;
}

/* WHAT: Bind inert task callbacks for scheduling tests.
 * WHY: No compute/completion code should run inside the queue selector.
 * HOW: Abort if either callback is unexpectedly executed inline. */
void brix_cksum_aio_thread(void *data, ngx_log_t *log)
{ (void) data; (void) log; abort(); }
void brix_cksum_aio_done(ngx_event_t *event)
{ (void) event; abort(); }

/* WHAT: Invoke the real registered owner after simulated completions retire.
 * WHY: Sanitizers must see the complete allocation/cleanup lifecycle.
 * HOW: Call each registered handler, then release the fixture's record storage. */
static void
finish_fixture(queue_fixture *fixture)
{
    ngx_pool_cleanup_t *cleanup = fixture->pool.cleanup;
    while (cleanup != NULL) {
        ngx_pool_cleanup_t *next = cleanup->next;
        assert(cleanup->handler != NULL);
        cleanup->handler(cleanup->data);
        free(cleanup->data);
        free(cleanup);
        cleanup = next;
    }
}

/* WHAT: Check cache growth, overlap refusal and repeated reuse independently.
 * WHY: An inactive task may grow; an active worker must retain exact storage.
 * HOW: Exercise real slot functions with heap failure and lifetime boundaries. */
static int
check_slot(const char *scenario)
{
    queue_fixture fixture = {0};
    ngx_connection_t connection = {0};
    connection.pool = &fixture.pool;
    connection.log = (ngx_log_t *) &fixture;
    ngx_thread_task_t *original = brix_query_checksum_task(&connection, 128);
    assert(original != NULL && fixture.allocations == 1);
    memset(original->ctx, 0x42, 128);
    if (strcmp(scenario, "active") == 0) {
        original->event.active = 1;
        assert(brix_query_checksum_task(&connection, 256) == NULL);
        assert(original->event.active && ((unsigned char *) original->ctx)[0] == 0x42);
        original->event.active = 0;
    } else if (strcmp(scenario, "overflow") == 0) {
        assert(brix_query_checksum_task(&connection, SIZE_MAX) == NULL);
        assert(((unsigned char *) original->ctx)[0] == 0x42);
    } else if (strcmp(scenario, "resize-oom") == 0) {
        fixture.allocation_failure = 1;
        assert(brix_query_checksum_task(&connection, 256) == NULL);
        assert(((unsigned char *) original->ctx)[0] == 0x42);
        fixture.allocation_failure = 0;
        assert(brix_query_checksum_task(&connection, 256) != NULL);
        assert(fixture.allocations == 2);
    } else {
        assert(strcmp(scenario, "reuse") == 0);
        for (int attempt = 0; attempt < 128; attempt++) {
            assert(brix_query_checksum_task(&connection, 128) == original);
            assert(((unsigned char *) original->ctx)[0] == 0);
        }
        assert(fixture.allocations == 1);
    }
    assert(fixture.cleanup_records == 1);
    finish_fixture(&fixture);
    return 0;
}

/* WHAT: Verify one path/handle admission outcome.
 * WHY: Both entry forms must retain policy and handle ownership consistently.
 * HOW: Configure one queue edge, invoke the real body and inspect its result. */
int
main(int argc, char **argv)
{
    assert(argc == 3);
    if (strcmp(argv[1], "slot") == 0) {
        return check_slot(argv[2]);
    }
    queue_fixture fixture = {0};
    brix_ctx_t context = {0};
    ngx_connection_t connection = {0};
    ngx_stream_brix_srv_conf_t configuration = {0};
    brix_qcksum_req_t request = {0};
    int by_path = strcmp(argv[1], "path") == 0;
    int posted = strncmp(argv[2], "posted", 6) == 0;
    int no_pool = strcmp(argv[2], "no-pool") == 0;
    int repetitions = strcmp(argv[2], "repeat-busy") == 0 ? 128 : 1;
    ngx_flag_t handled = -1;

    fixture.busy = strstr(argv[2], "busy") != NULL;
    fixture.allocation_failure = strcmp(argv[2], "oom") == 0;
    configuration.common.allow_write = strstr(argv[2], "readonly") == NULL;
    if (strcmp(argv[2], "posted-unset") == 0) {
        configuration.common.allow_write = NGX_CONF_UNSET;
    }
    fixture.expected_policy = brix_vfs_policy_from_write_enable(
        configuration.common.allow_write);
    configuration.common.thread_pool = no_pool ? NULL : (void *) (uintptr_t) 1;
    connection.pool = &fixture.pool;
    connection.log = (ngx_log_t *) &fixture;
    connection.data = &fixture;
    context.files = calloc(1, sizeof(*context.files));
    assert(context.files != NULL);
    context.files[0].fd = 17;
    request.ctx = &context;
    request.c = &connection;
    request.conf = &configuration;
    strcpy(request.algo, "adler32");
    strcpy(request.full_path, "/fixture/object");
    ngx_int_t result = NGX_ERROR;
    for (int attempt = 0; attempt < repetitions; attempt++) {
        result = by_path
            ? brix_qcksum_try_async(&request, (void *) (uintptr_t) 1, 17, &handled)
            : brix_qcksum_handle_try_async(&request, 0, request.full_path, &handled);
    }

    if (posted) {
        assert(result == NGX_OK && handled == 1 && fixture.posts == 1);
        assert(fixture.waits == 0 && fixture.closes == 0 && fixture.allocations == 1);
        brix_cksum_aio_t *task = fixture.allocation->ctx;
        assert(task->fd == 17 && task->close_fd == by_path);
        assert(task->mutation_policy == fixture.expected_policy);
        fixture.allocation->event.active = 0;
    } else if (fixture.busy) {
        assert(result == NGX_DONE && handled == 1 && fixture.posts == repetitions);
        assert(fixture.waits == repetitions && fixture.errors == 0 && fixture.allocations == 1);
        assert(fixture.closes == by_path * repetitions && fixture.access_records == 0);
    } else if (no_pool) {
        assert(result == NGX_OK && handled == 0 && fixture.posts == 0);
        assert(fixture.waits == 0 && fixture.closes == 0 && fixture.allocations == 0);
    } else {
        assert(fixture.allocation_failure && result == NGX_DONE && handled == 1);
        assert(fixture.errors == 1 && fixture.waits == 0 && fixture.posts == 0);
        assert(fixture.closes == by_path);
        assert(fixture.access_records == 1);
    }
    assert(fixture.cleanup_records == !no_pool);
    finish_fixture(&fixture);
    free(context.files);
    return 0;
}
