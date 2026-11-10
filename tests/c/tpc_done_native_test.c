/* TPC completion with real VFS cleanup and metadata; only reply transport is observed. */
#include "tpc/engine/tpc_internal.h"
#include "fs/path/beneath.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    brix_ctx_t context;
    ngx_connection_t connection;
    ngx_stream_session_t session;
    ngx_stream_brix_srv_conf_t config;
    brix_tpc_pull_t task;
    ngx_log_t log;
    ngx_cycle_t cycle;
    void *configs[1];
    int ok, error, queued, resumed;
    char trailer[256];
} completion_fixture_t;

int __real_close(int fd);

/* WHAT: Detect a duplicate close of the transfer descriptor.
 * WHY: A driver-owned descriptor must be reclaimed by its driver exactly once.
 * HOW: Require each close of that descriptor number to still name an open fd;
 *      legitimate descriptor-number reuse during VFS cleanup remains allowed. */
int __wrap_close(int fd)
{
    const char *tracked = getenv("BRIX_TPC_COMPLETION_FD");
    if (tracked != NULL && fd == atoi(tracked)) { assert(fcntl(fd, F_GETFD) >= 0); }
    return __real_close(fd);
}

/* WHAT: Observe an empty sync success. WHY: The deferred request receives one reply.
 * HOW: Require the actual context and stream identity restored by completion. */
ngx_int_t __wrap_brix_send_ok(brix_ctx_t *ctx, ngx_connection_t *connection,
                              const void *body, uint32_t size)
{
    completion_fixture_t *f = connection->data;
    assert(ctx == &f->context && body == NULL && size == 0);
    assert(ctx->recv.cur_streamid[0] == 0x31); f->ok++; return NGX_OK;
}

/* WHAT: Observe the real failure verdict. WHY: Failed transfers cannot get success.
 * HOW: Capture the wire code while requiring a nonempty diagnostic. */
ngx_int_t __wrap_brix_send_error(brix_ctx_t *ctx, ngx_connection_t *connection,
                                 uint16_t error, const char *message)
{
    completion_fixture_t *f = connection->data;
    assert(ctx == &f->context && message != NULL && message[0]);
    f->error = error; return NGX_OK;
}

/* WHAT: Inspect a complete open response. WHY: Trailer and length must match the wire.
 * HOW: Check the canonical header and retain the bounded optional ASCII trailer. */
ngx_int_t __wrap_brix_queue_response(brix_ctx_t *ctx, ngx_connection_t *connection,
                                     u_char *body, size_t size)
{
    completion_fixture_t *f = connection->data;
    assert(ctx == &f->context && size >= XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody));
    assert(body[0] == 0x31 && body[1] == 0x92);
    assert(xrdw_get_u32(body + 4) == size - XRD_RESPONSE_HDR_LEN);
    size_t prefix = XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody);
    if (size > prefix) {
        assert(size - prefix <= sizeof(f->trailer) && body[size - 1] == '\0');
        memcpy(f->trailer, body + prefix, size - prefix);
    }
    f->queued++; return NGX_OK;
}

/* WHAT: Count event-loop continuations. WHY: Abandoned clients must not resume.
 * HOW: Keep continuation state on the caller-owned connection fixture. */
void __wrap_brix_aio_resume(ngx_connection_t *connection)
{
    completion_fixture_t *f = connection->data; f->resumed++;
}

/* WHAT: Build a normal live session and destination handle.
 * WHY: Real teardown, stat refresh and logging need the configured session graph.
 * HOW: Allocate real pools, bind the module config, and seed a private destination. */
static void setup(completion_fixture_t *f, char **argv)
{
    ngx_os_argv = argv; ngx_cycle = &f->cycle; f->cycle.log = &f->log;
    ngx_time_init(); assert(ngx_os_init(&f->log) == NGX_OK);
    ngx_stream_brix_module.ctx_index = 0;
    f->connection.log = &f->log; f->connection.data = f;
    f->connection.pool = ngx_create_pool(16384, &f->log); assert(f->connection.pool);
    f->configs[0] = &f->config; f->session.srv_conf = f->configs;
    f->session.connection = &f->connection; f->context.session = &f->session;
    f->config.access_log_fd = NGX_INVALID_FILE;
    snprintf(f->config.common.root_canon, sizeof(f->config.common.root_canon),
             "%s", argv[3]);
    f->config.common.allow_write = 1;
    f->config.rootfd = brix_beneath_open_root(argv[3]); assert(f->config.rootfd >= 0);
    f->context.files = calloc(3, sizeof(*f->context.files)); assert(f->context.files);
    brix_tpc_pull_t *task = &f->task;
    task->c = &f->connection; task->ctx = &f->context; task->conf = &f->config;
    task->streamid[0] = 0x31; task->streamid[1] = 0x92; task->fhandle_idx = 1;
    task->reply_kind = !strcmp(argv[1], "sync") ? BRIX_TPC_REPLY_SYNC : BRIX_TPC_REPLY_OPEN;
    task->result = NGX_OK; task->bytes_written = 7;
    snprintf(task->dst_path, sizeof(task->dst_path), "%s/destination", argv[3]);
    task->dst_fd = open(task->dst_path, O_RDWR | O_CREAT | O_EXCL, 0640);
    assert(task->dst_fd >= 0 && write(task->dst_fd, "payload", 7) == 7);
    f->context.files[1].fd = task->dst_fd;
    f->context.files[1].path = strdup(task->dst_path); assert(f->context.files[1].path);
    if (!strcmp(argv[4], "driver")) {
        brix_sd_posix_wrap(&f->context.files[1].sd_obj, task->dst_fd);
    }
    char descriptor[32]; snprintf(descriptor, sizeof(descriptor), "%d", task->dst_fd);
    assert(setenv("BRIX_TPC_COMPLETION_FD", descriptor, 1) == 0);
}

/* WHAT: Select one completion condition. WHY: Lifetime and reply shape are independent.
 * HOW: Change only the relevant task/session input after valid setup. */
static int select_mode(completion_fixture_t *f, const char *mode)
{
    brix_tpc_pull_t *task = &f->task;
    int abandoned = !strcmp(mode, "destroyed") || !strncmp(mode, "orphan-", 7);
    if (strstr(mode, "fail") || abandoned || !strcmp(mode, "invalid-slot")) {
        task->result = NGX_ERROR;
    }
    task->is_push = !strcmp(mode, "push-fail");
    if (!strcmp(mode, "read-only-fail")) { f->config.common.allow_write = 0; }
    if (!strcmp(mode, "destroyed")) { f->context.destroyed = 1; }
    if (!strcmp(mode, "orphan-context")) { task->ctx = NULL; }
    if (!strcmp(mode, "orphan-connection")) { task->c = NULL; }
    if (!strcmp(mode, "invalid-slot")) { task->fhandle_idx = -1; }
    if (strstr(mode, "key")) { strcpy(task->tpc_key, "transfer-key"); }
    if (!strncmp(mode, "stat", 4)) { task->options = kXR_retstat; }
    return abandoned;
}

/* WHAT: Assert failure cleanup and preservation policy.
 * WHY: A failed pull removes its partial, while push sources and read-only files survive.
 * HOW: Inspect the original descriptor and destination pathname after completion. */
static void failure_result(completion_fixture_t *f, int original, const char *mode,
                            int abandoned)
{
    assert(fcntl(original, F_GETFD) == -1 && errno == EBADF);
    int retained = !strcmp(mode, "push-fail") || !strcmp(mode, "read-only-fail");
    assert((access(f->task.dst_path, F_OK) == 0) == retained);
    assert(f->resumed == !abandoned && f->ok == 0 && f->queued == 0);
    assert(f->error == (abandoned ? 0 : kXR_ServerError));
}

/* WHAT: Assert successful handle retention and exact reply disposition.
 * WHY: Sync leaves the handle live; open includes only the requested trailer fields.
 * HOW: Inspect stored bytes, descriptor liveness and observed reply counters. */
static void success_result(completion_fixture_t *f, int original, const char *mode)
{
    assert(fcntl(original, F_GETFD) >= 0 && access(f->task.dst_path, F_OK) == 0);
    assert(f->resumed == 1 && f->error == 0);
    if (f->task.reply_kind == BRIX_TPC_REPLY_SYNC) {
        assert(f->ok == 1 && f->queued == 0 && f->context.files[1].tpc_done);
        assert(f->context.files[1].bytes_written == 7);
        return;
    }
    assert(f->queued == 1 && f->ok == 0);
    if (strstr(mode, "key")) { assert(strstr(f->trailer, "tpc.key=transfer-key")); }
    if (!strncmp(mode, "stat", 4)) { assert(strstr(f->trailer, " 7 ")); }
}

/* WHAT: Drive one actual event-thread completion.
 * WHY: The event owns a task context but must retain or dispose resources correctly.
 * HOW: Run the callback, assert its contract, and release only fixture-owned state. */
int main(int argc, char **argv)
{
    assert(argc == 5);
    completion_fixture_t *f = calloc(1, sizeof(*f)); assert(f);
    setup(f, argv); int original = f->task.dst_fd;
    int abandoned = select_mode(f, argv[2]);
    ngx_thread_task_t task = {.ctx = &f->task}; ngx_event_t event = {.data = &task};
    brix_tpc_pull_done(&event);
    if (f->task.result == NGX_OK) { success_result(f, original, argv[2]); close(original); }
    else { failure_result(f, original, argv[2], abandoned); }
    free(f->context.files[1].path); free(f->context.files);
    close(f->config.rootfd); ngx_destroy_pool(f->connection.pool); free(f);
    return 0;
}
