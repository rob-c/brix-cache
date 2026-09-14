/* Real pipelined completion and stream restoration bodies are appended by the
 * Python compiler fixture. Replies, accounting and event scheduling are owned
 * callbacks; the test never opens a file or a connection. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "core/ngx_brix_module.h"

/* Metrics do not participate in receiving-frame or response-ID ownership. */
#undef BRIX_OP_OK
#undef BRIX_OP_ERR
#define BRIX_OP_OK(ctx, op) ((void) 0)
#define BRIX_OP_ERR(ctx, op) ((void) 0)
#define brix_aio_metric_done(start, op) ((void) 0)

typedef struct {
    int ok;
    int xrd_error;
    const char *errmsg;
    size_t nbytes;
} brix_write_aio_logrec_t;

typedef struct {
    brix_ctx_t *ctx;
    unsigned replies;
    unsigned errors;
    unsigned resumes;
    unsigned teardowns;
    unsigned commits;
    int send_failure;
} ack_fixture_t;

static void brix_write_aio_done_pipelined(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, brix_write_aio_t *task, ngx_int_t op);

/* WHAT: Own callback counters. WHY: Keep state inside the isolated test process.
 * HOW: 1. Return the single fixture, initialized before invoking production. */
static ack_fixture_t *
fixture(void)
{
    static ack_fixture_t state;
    return &state;
}

/* WHAT: Check the unfinished request. WHY: Its payload continues after this ack.
 * HOW: 1. Assert its ID, opcode, header and payload positions remain intact. */
static void
check_receiving_frame(brix_ctx_t *ctx)
{
    assert(ctx->recv.cur_streamid[0] == 2 && ctx->recv.cur_streamid[1] == 9);
    assert(ctx->state == XRD_ST_REQ_PAYLOAD && ctx->recv.cur_reqid == kXR_write);
    assert(ctx->recv.hdr_pos == 24 && ctx->recv.payload_pos == 512);
}

/* WHAT: Observe the completed task's reply. WHY: Restoring the receiver early
 * would send the ack to the wrong request. HOW: 1. Require completed ID and
 * async framing. 2. Return the configured response-queue outcome. */
static ngx_int_t
record_reply(brix_ctx_t *ctx)
{
    ack_fixture_t *state = fixture();
    assert(ctx == state->ctx);
    assert(ctx->recv.cur_streamid[0] == 1 && ctx->recv.cur_streamid[1] == 7);
    assert(ctx->out.resp_async == 1);
    state->replies++;
    return state->send_failure ? NGX_ERROR : NGX_OK;
}

/* WHAT: Capture an ordinary successful write ack. WHY: Inspect its ID without
 * emitting bytes. HOW: 1. Check the empty body. 2. Delegate ID ownership checks. */
ngx_int_t
brix_send_ok(brix_ctx_t *ctx, ngx_connection_t *connection,
    const void *body, uint32_t length)
{
    (void) connection;
    assert(body == NULL && length == 0);
    return record_reply(ctx);
}

/* WHAT: Capture the write error ack. WHY: Error exits must preserve both IDs too.
 * HOW: 1. Check error semantics. 2. Count it and inspect completed-task identity. */
ngx_int_t
brix_send_error(brix_ctx_t *ctx, ngx_connection_t *connection,
    uint16_t code, const char *message)
{
    (void) connection;
    assert(code == kXR_IOError && message != NULL);
    fixture()->errors++;
    return record_reply(ctx);
}

/* WHAT: Observe rescheduling. WHY: The receiving ID must be restored beforehand.
 * HOW: 1. Check the unchanged receiving frame and cleared async flag. 2. Count. */
ngx_int_t
brix_schedule_read_resume(ngx_connection_t *connection)
{
    (void) connection;
    check_receiving_frame(fixture()->ctx);
    assert(fixture()->ctx->out.resp_async == 0);
    fixture()->resumes++;
    return NGX_OK;
}

/* WHAT: Retire the destroyed fixture. WHY: ASan must catch any post-retirement
 * access. HOW: 1. Check ownership. 2. Free it and clear the fixture's pointer. */
void
brix_run_deferred_teardown(brix_ctx_t *ctx, ngx_connection_t *connection)
{
    (void) connection;
    assert(ctx == fixture()->ctx && ctx->destroyed);
    free(ctx);
    fixture()->ctx = NULL;
    fixture()->teardowns++;
}

/* WHAT: Observe success accounting. WHY: Error branches must never commit bytes.
 * HOW: 1. Require a full write and count the isolated accounting callback. */
static void
brix_write_aio_commit(brix_ctx_t *ctx, brix_write_aio_t *task)
{
    assert(ctx == fixture()->ctx && task->nwritten == (ssize_t) task->len);
    fixture()->commits++;
}

/* WHAT: Accept the existing access-log record. WHY: Keep the actual callback's
 * outcome path intact without a log file. HOW: 1. Check fixture and record. */
static void
brix_write_aio_log(brix_ctx_t *ctx, ngx_connection_t *connection,
    ngx_stream_brix_srv_conf_t *config, brix_write_aio_t *task,
    const brix_write_aio_logrec_t *record)
{
    (void) connection; (void) config; (void) task;
    assert(ctx == fixture()->ctx && record != NULL);
}

/* WHAT: Set up one unfinished frame and an older completed task. WHY: Model the
 * ordinary interleaving. HOW: 1. Give them distinct IDs. 2. Configure the outcome. */
static void
prepare_fixture(const char *mode, brix_write_aio_t *task)
{
    ack_fixture_t *state = fixture();
    state->ctx = calloc(1, sizeof(*state->ctx));
    assert(state->ctx != NULL);
    state->ctx->state = XRD_ST_REQ_PAYLOAD;
    state->ctx->recv.cur_streamid[0] = 2;
    state->ctx->recv.cur_streamid[1] = 9;
    state->ctx->recv.cur_reqid = kXR_write;
    state->ctx->recv.hdr_pos = 24;
    state->ctx->recv.payload_pos = 512;
    task->streamid[0] = 1;
    task->streamid[1] = 7;
    task->len = 1024;
    task->nwritten = 1024;
    task->io_errno = EIO;
    if (strcmp(mode, "io-error") == 0) task->nwritten = -1;
    if (strcmp(mode, "short-write") == 0) task->nwritten = 512;
    state->send_failure = strcmp(mode, "send-failure") == 0;
    if (strncmp(mode, "destroyed", 9) == 0) {
        state->ctx->destroyed = 1;
        state->ctx->out.finalize_pending = 1;
        state->ctx->out.wr_inflight = strcmp(mode, "destroyed-pending") == 0;
    }
}

/* WHAT: Verify a lifetime exit. WHY: Destroyed connections cannot reply/resume.
 * HOW: 1. Check zero live callbacks. 2. Require final teardown or retained owner. */
static void
check_destroyed(const char *mode)
{
    ack_fixture_t *state = fixture();
    assert(state->replies == 0 && state->resumes == 0 && state->commits == 0);
    if (strcmp(mode, "destroyed") == 0) {
        assert(state->ctx == NULL && state->teardowns == 1);
        return;
    }
    assert(state->teardowns == 0 && state->ctx != NULL);
    check_receiving_frame(state->ctx);
    free(state->ctx);
}

/* WHAT: Execute one real callback case. WHY: Cover successful and failed replies
 * plus safe early exits. HOW: 1. Prepare. 2. Complete. 3. Check both identities. */
int
main(int argc, char **argv)
{
    ngx_connection_t connection = {0};
    ngx_stream_brix_srv_conf_t config = {0};
    brix_write_aio_t task = {0};
    ack_fixture_t *state = fixture();

    assert(argc == 2);
    prepare_fixture(argv[1], &task);
    brix_write_aio_done_pipelined(state->ctx, &connection, &config, &task, BRIX_OP_WRITE);
    if (strncmp(argv[1], "destroyed", 9) == 0) {
        check_destroyed(argv[1]);
        return 0;
    }
    check_receiving_frame(state->ctx);
    assert(state->replies == 1 && state->resumes == 1 && state->teardowns == 0);
    assert(state->errors == (task.nwritten != (ssize_t) task.len));
    assert(state->commits == (task.nwritten == (ssize_t) task.len));
    free(state->ctx);
    return 0;
}
