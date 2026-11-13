/* Real VFS reads, wire-chain construction and read-pool ownership at AIO completion. */
#include "core/ngx_brix_module.h"
#include "protocols/root/protocol/readv_seg.h"
#include <assert.h>

typedef struct {
    brix_ctx_t ctx;
    ngx_connection_t connection;
    ngx_log_t log;
    brix_readv_aio_t read;
    int queues, resumes, error, wait, parked, chain_failure;
} readv_fixture_t;

/* WHAT: Observe a real generated wire chain at its transport boundary.
 * WHY: A completion must preserve its stream ID and transfer the correct buffer.
 * HOW: Check header/body bytes, then model inline completion or queued ownership. */
ngx_int_t __wrap_brix_queue_response_chain(brix_ctx_t *ctx, ngx_connection_t *c,
                                          ngx_chain_t *chain, u_char *owned)
{
    readv_fixture_t *f = c->data;
    assert(ctx == &f->ctx && owned == f->read.response_buffer);
    assert(chain != NULL && chain->next != NULL && chain->next->next == NULL);
    assert(chain->buf->memory && !chain->buf->in_file);
    assert(chain->buf->pos[0] == 0x31 && chain->buf->pos[1] == 0x92);
    assert(xrd_get_u32_be(chain->buf->pos + 4) == f->read.response_bytes);
    assert(chain->next->buf->pos == owned);
    assert((size_t)(chain->next->buf->last - owned) == f->read.response_bytes);
    f->queues++;
    if (f->parked) { ctx->out.count++; }
    return NGX_OK;
}

/* WHAT: Observe the event-loop continuation without admitting another request.
 * WHY: Teardown must not resume, while a consumed completion resumes exactly once.
 * HOW: Count calls on the fixture carried by the connection. */
void __wrap_brix_aio_resume(ngx_connection_t *c)
{
    readv_fixture_t *f = c->data; f->resumes++;
}

/* WHAT: Record an ordinary protocol error emitted by the real completion.
 * WHY: Failed reads cannot be reported as successful payloads.
 * HOW: Require a diagnostic and retain its wire error code. */
ngx_int_t __wrap_brix_send_error(brix_ctx_t *ctx, ngx_connection_t *c,
                                uint16_t error, const char *message)
{
    readv_fixture_t *f = c->data;
    assert(ctx == &f->ctx && message[0]); f->error = error;
    return NGX_OK;
}

/* WHAT: Observe the special serve-while-filling retry disposition.
 * WHY: A temporary frontier is a wait response rather than a permanent I/O error.
 * HOW: Require EAGAIN and keep the ordinary-error counter unchanged. */
ngx_int_t __wrap_brix_read_io_error(brix_ctx_t *ctx, ngx_connection_t *c, int error)
{
    readv_fixture_t *f = c->data;
    assert(ctx == &f->ctx && error == EAGAIN); f->wait++;
    return NGX_OK;
}

ngx_chain_t *__real_brix_build_chunked_chain(brix_ctx_t *, ngx_connection_t *,
                                            u_char *, size_t);

/* WHAT: Refuse chain construction in one completion, otherwise use the real builder.
 * WHY: Allocation failure must return the read buffer without queueing it.
 * HOW: Select the fault from the connection-local test state. */
ngx_chain_t *__wrap_brix_build_chunked_chain(brix_ctx_t *ctx, ngx_connection_t *c,
                                            u_char *data, size_t size)
{
    readv_fixture_t *f = c->data;
    if (f->chain_failure) { return NULL; }
    return __real_brix_build_chunked_chain(ctx, c, data, size);
}

/* WHAT: Build two real range descriptors and a final interleaved response buffer.
 * WHY: The worker must fill the exact storage the completion later sends.
 * HOW: Pack canonical segment headers and bind each segment to the source fd. */
static void plan(readv_fixture_t *f, int fd, const char *mode)
{
    brix_readv_aio_t *read = &f->read;
    read->ctx = &f->ctx; read->c = &f->connection;
    read->streamid[0] = 0x31; read->streamid[1] = 0x92;
    read->segments = calloc(2, sizeof(*read->segments));
    read->response_buffer = calloc(1, 64); read->segment_count = 2;
    assert(read->segments != NULL && read->response_buffer != NULL);
    size_t cursor = 0;
    for (size_t i = 0; i < 2; ++i) {
        brix_readv_seg_desc_t *seg = &read->segments[i];
        seg->fd = fd; seg->handle_index = i + 1;
        seg->offset = i * (!strcmp(mode, "scattered") ? 8 : 4);
        seg->read_length = i == 0 && !strcmp(mode, "empty-segment") ? 0 : 4;
        u_char handle[4] = {(u_char)(i + 1), 0, 0, 0};
        brix_readv_seg_pack(read->response_buffer + cursor, handle,
                            seg->read_length, seg->offset);
        seg->header_read_length_ptr = read->response_buffer + cursor + 4;
        seg->payload_ptr = read->response_buffer + cursor + BRIX_READV_SEGSIZE;
        cursor += BRIX_READV_SEGSIZE + seg->read_length;
    }
    f->ctx.out.pipeline_depth = 1;
    f->ctx.rd.pool = calloc(1, sizeof(*f->ctx.rd.pool));
    f->ctx.out.ring = calloc(1, sizeof(*f->ctx.out.ring));
    f->ctx.files = calloc(3, sizeof(*f->ctx.files));
    assert(f->ctx.rd.pool != NULL && f->ctx.out.ring != NULL && f->ctx.files != NULL);
    f->ctx.rd.pool[0].buf = read->response_buffer;
    f->ctx.rd.pool[0].in_use = 1; f->ctx.rd.inflight = 1;
}

/* WHAT: Exercise worker refusals without altering the public worker implementation.
 * WHY: Corrupt descriptors, absent input and I/O failure must not publish bytes.
 * HOW: Change one plan field, then call the real VFS-backed worker. */
static void execute(readv_fixture_t *f, const char *mode)
{
    brix_readv_seg_desc_t *first = &f->read.segments[0];
    if (!strcmp(mode, "bad-fd")) { first->fd = -1; }
    if (!strcmp(mode, "past-eof")) { first->offset = 16; }
    if (!strcmp(mode, "negative-offset")) { first->offset = -1; }
    if (!strcmp(mode, "overflow")) { first->offset = INT64_MAX; }
    if (!strcmp(mode, "empty-plan")) { f->read.segment_count = 0; }
    brix_readv_aio_thread(&f->read, &f->log);
    if (!strcmp(mode, "wait")) {
        f->read.io_error = 1; f->read.io_errno = EAGAIN;
    }
    if (f->read.io_error) { return; }
    size_t expected = !strcmp(mode, "empty-segment") ? 4 : 8;
    assert(f->read.bytes_read_total == expected);
    assert(f->read.response_bytes == 2 * BRIX_READV_SEGSIZE + expected);
    const char *source = "abcdefghijklmnop";
    for (size_t i = 0; i < 2; ++i) {
        brix_readv_seg_desc_t *seg = &f->read.segments[i];
        assert(!memcmp(seg->payload_ptr, source + seg->offset, seg->read_length));
        assert(xrd_get_u32_be(seg->header_read_length_ptr) == seg->read_length);
    }
}

/* WHAT: Verify completion counters, restored request state and buffer ownership.
 * WHY: Stale XRD_ST_SENDING must not cause leaks or release a queued response early.
 * HOW: Run the actual done callback, then compare observable state and finish cleanup. */
static void complete(readv_fixture_t *f, const char *mode)
{
    f->ctx.destroyed = !strcmp(mode, "destroyed");
    f->parked = !strcmp(mode, "queued");
    f->chain_failure = !strcmp(mode, "chain-failure");
    f->ctx.state = XRD_ST_SENDING; f->ctx.recv.hdr_pos = 17;
    ngx_thread_task_t task = {.ctx = &f->read};
    ngx_event_t event = {.data = &task};
    brix_readv_aio_done(&event);
    assert(f->resumes == !f->ctx.destroyed);
    assert(f->ctx.rd.pool[0].in_use == f->parked);
    assert(f->ctx.rd.inflight == (ngx_uint_t)f->parked);
    if (f->ctx.destroyed) { assert(f->queues == 0); return; }
    assert(f->ctx.recv.cur_streamid[0] == 0x31 && f->ctx.recv.cur_streamid[1] == 0x92);
    assert(f->ctx.recv.hdr_pos == 0);
    if (f->read.io_error) {
        assert(f->queues == 0 && f->ctx.totals.bytes == 0);
        assert(f->error == (f->read.io_errno == EAGAIN ? 0 : kXR_IOError));
        assert(f->wait == (f->read.io_errno == EAGAIN)); return;
    }
    assert(f->queues == !f->chain_failure);
    assert(f->ctx.totals.bytes == f->read.bytes_read_total);
    assert(f->ctx.files[1].bytes_read + f->ctx.files[2].bytes_read
           == f->read.bytes_read_total);
    brix_release_read_buffer(&f->ctx, &f->connection, f->read.response_buffer);
    assert(f->ctx.rd.inflight == 0);
}

/* WHAT: Run one independent AIO readv worker/completion lifecycle.
 * WHY: Each process owns its descriptor, read pool and fault observations.
 * HOW: Initialize nginx, build and execute a plan, complete it, release resources. */
int main(int argc, char **argv)
{
    assert(argc == 3);
    readv_fixture_t *f = calloc(1, sizeof(*f)); assert(f != NULL);
    ngx_cycle_t cycle = {.log = &f->log};
    ngx_time_init(); ngx_pid = getpid(); ngx_os_argv = argv; ngx_cycle = &cycle;
    assert(ngx_os_init(&f->log) == NGX_OK);
    f->connection.data = f; f->connection.log = &f->log;
    f->connection.pool = ngx_create_pool(4096, &f->log); assert(f->connection.pool);
    int fd = open(argv[2], O_RDONLY); assert(fd >= 0);
    plan(f, fd, argv[1]); execute(f, argv[1]); complete(f, argv[1]);
    close(fd); free(f->read.response_buffer);
    free(f->ctx.rd.pool); free(f->ctx.out.ring);
    free(f->ctx.files);
    ngx_destroy_pool(f->connection.pool); free(f);
    return 0;
}
