/* Real pgread worker and completion, with observable transport ownership. */
#include "core/ngx_brix_module.h"
#include "protocols/root/connection/disconnect.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_stream_session_t session;
    ngx_stream_brix_srv_conf_t conf;
    ngx_connection_t connection[2];
    brix_ctx_t context[2];
    brix_pgread_aio_t read;
    const char *mode;
    u_char *buffer;
    int queues, resumes, errors, waits, chunks, parks, arms, teardowns[2], releases;
} fixture;

/* WHAT: Recover the current fixture. WHY: Keep globals out of the test seam.
 * HOW: The actual nginx cycle is the enclosing fixture's first member. */
static fixture *state(void) { return (fixture *) ngx_cycle; }

/* WHAT: Select one transition. WHY: Faults must remain independent.
 * HOW: Match a command-line mode owned for this process lifetime. */
static int mode(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Validate a generated status frame. WHY: PGREAD cannot use kXR_ok.
 * HOW: Check stream, status and page payload size in the real wire header. */
static void frame(const u_char *bytes, size_t length)
{
    fixture *f = state();
    assert(length == sizeof(ServerStatusResponse_pgRead));
    assert(bytes[0] == 0x31 && bytes[1] == 0x92);
    assert(xrdw_get_u16(bytes + 2) == kXR_status);
    assert(xrdw_get_u32(bytes + 4) == 24);
    assert(xrdw_get_u32(bytes + 20) == f->read.out_size);
}

/* WHAT: Observe a primary response. WHY: The real builder must retain pages.
 * HOW: Inspect header, borrowed payload and inline versus queued ownership. */
ngx_int_t __wrap_brix_queue_response_chain(brix_ctx_t *ctx, ngx_connection_t *c,
                                          ngx_chain_t *chain, u_char *owned)
{
    fixture *f = state(); assert(ctx == &f->context[0] && c == &f->connection[0]);
    frame(chain->buf->pos, (size_t)(chain->buf->last - chain->buf->pos));
    assert(chain->next && !chain->next->next && owned == f->buffer);
    assert(chain->next->buf->pos == f->read.scratch);
    assert((size_t)(chain->next->buf->last - chain->next->buf->pos) == f->read.out_size);
    assert(chain->buf->memory && chain->next->buf->memory);
    f->queues++; if (mode("queued")) { ctx->out.count++; } return NGX_OK;
}

/* WHAT: Observe a secondary response. WHY: Header and data share its read slot.
 * HOW: Validate the contiguous frame and retain ownership only when queued. */
ngx_int_t __wrap_brix_queue_response_base(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *bytes, size_t length, u_char *owned)
{
    fixture *f = state(); assert(ctx == &f->context[1] && c == &f->connection[1]);
    assert(bytes == owned && owned == f->buffer);
    frame(bytes, length - f->read.out_size);
    f->queues++; if (mode("queued")) { ctx->out.count++; } return NGX_OK;
}

/* WHAT: Observe EOF. WHY: Empty reads use a status response without pages.
 * HOW: Check the exact request offset and the AIO response disposition. */
ngx_int_t __wrap_brix_send_empty_pgread(brix_ctx_t *ctx, ngx_connection_t *c,
                                       int64_t offset, ngx_flag_t ready)
{
    fixture *f = state(); assert(ctx == &f->context[0] && c == &f->connection[0]);
    assert(offset == f->read.offset && ready == 1); f->queues++; return NGX_OK;
}

/* WHAT: Record resume. WHY: A dead primary must never accept another request.
 * HOW: Require the primary and count one event-loop continuation. */
void __wrap_brix_aio_resume(ngx_connection_t *c)
{
    assert(c == &state()->connection[0]); state()->resumes++;
}

/* WHAT: Record a failed I/O. WHY: EAGAIN remains a retry rather than a hard error.
 * HOW: Distinguish the real completion's errno at the response boundary. */
ngx_int_t __wrap_brix_read_io_error(brix_ctx_t *ctx, ngx_connection_t *c, int error)
{
    fixture *f = state(); assert(ctx == &f->context[0] && c == &f->connection[0]);
    assert(error == EIO || error == EAGAIN);
    if (error == EAGAIN) { f->waits++; } else { f->errors++; } return NGX_OK;
}

/* WHAT: Record loss of the secondary. WHY: The control stream gets that failure.
 * HOW: Check the destination and the canonical wire I/O error. */
ngx_int_t __wrap_brix_send_error(brix_ctx_t *ctx, ngx_connection_t *c,
                                uint16_t code, const char *message)
{
    fixture *f = state(); assert(ctx == &f->context[0] && c == &f->connection[0]);
    assert(code == kXR_IOError && message[0]); f->errors++; return NGX_OK;
}

/* WHAT: Record a chunk failure. WHY: A started reply must finish on its channel.
 * HOW: Require the secondary and original sid instead of current recv state. */
ngx_int_t __wrap_brix_send_error_sid(brix_ctx_t *ctx, ngx_connection_t *c,
    const u_char sid[2], uint16_t code, const char *message)
{
    fixture *f = state(); assert(ctx == &f->context[1] && c == &f->connection[1]);
    assert(code == kXR_IOError && message[0] && sid[0] == 0x31 && sid[1] == 0x92);
    f->chunks++; return NGX_OK;
}

/* WHAT: Observe parked tail ownership. WHY: Partial wire images precede new frames.
 * HOW: Check the unsent slice and that the send token is still held while parking. */
ngx_int_t __wrap_brix_park_front_buf(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *bytes, size_t length, u_char *owned)
{
    fixture *f = state(); assert(ctx == &f->context[1] && c == &f->connection[1]);
    assert(owned == f->buffer && bytes == owned + 7 && length == f->read.pool_image_len - 7);
    assert(ctx->out.send_token == 1); ctx->out.count++; f->parks++; return NGX_OK;
}

/* WHAT: Observe queued work wakeup. WHY: Completed pool-send releases the writer.
 * HOW: Require pending secondary frames and count one registration. */
ngx_int_t __wrap_brix_ensure_write_event(ngx_connection_t *c)
{
    assert(c == &state()->connection[1] && state()->context[1].out.count);
    state()->arms++; return NGX_OK;
}

/* WHAT: Observe deferred teardown. WHY: The last completion owns each side separately.
 * HOW: Require no pending I/O and record the matching connection index. */
void __wrap_brix_run_deferred_teardown(brix_ctx_t *ctx, ngx_connection_t *c)
{
    fixture *f = state(); int side = c == &f->connection[1];
    assert(ctx == &f->context[side] && !ctx->rd.aio_inflight && !ctx->out.wr_inflight);
    f->teardowns[side]++;
}

void __real_brix_release_read_buffer(brix_ctx_t *, ngx_connection_t *, u_char *);
/* WHAT: Observe read slot release. WHY: The secondary owns an offloaded frame.
 * HOW: Assert owner/base, then execute the actual read-pool release helper. */
void __wrap_brix_release_read_buffer(brix_ctx_t *ctx, ngx_connection_t *c, u_char *bytes)
{
    fixture *f = state(); int side = f->read.sec_c != NULL;
    assert(ctx == &f->context[side] && c == &f->connection[side] && bytes == f->buffer);
    f->releases++; __real_brix_release_read_buffer(ctx, c, bytes);
}

ngx_chain_t *__real_brix_build_pgread_chain(brix_ctx_t *, ngx_connection_t *, int64_t, u_char *, uint32_t);
/* WHAT: Refuse one response allocation. WHY: A failed chain cannot retain its slot.
 * HOW: The ordinary branch runs the unchanged production builder. */
ngx_chain_t *__wrap_brix_build_pgread_chain(brix_ctx_t *ctx, ngx_connection_t *c,
    int64_t offset, u_char *bytes, uint32_t size)
{
    return mode("chain-failure") ? NULL : __real_brix_build_pgread_chain(ctx, c, offset, bytes, size);
}

/* WHAT: Build actual session and read slots. WHY: Accounting uses nginx srv_conf.
 * HOW: Two connections share one configured session but own separate read pools. */
static void setup(fixture *f, int secondary, int fd)
{
    ngx_cycle = &f->cycle; f->cycle.log = &f->log; ngx_time_init();
    ngx_stream_brix_module.ctx_index = 0;
    f->conf.access_log_fd = NGX_INVALID_FILE;
    f->session.srv_conf = calloc(ngx_stream_brix_module.ctx_index + 1, sizeof(void *));
    assert(f->session.srv_conf); f->session.srv_conf[ngx_stream_brix_module.ctx_index] = &f->conf;
    for (int i = 0; i < 2; i++) {
        ngx_connection_t *c = &f->connection[i]; brix_ctx_t *ctx = &f->context[i];
        c->data = &f->session; c->log = &f->log; c->pool = ngx_create_pool(4096, &f->log);
        ctx->out.pipeline_depth = 1; ctx->rd.pool = calloc(1, sizeof(*ctx->rd.pool));
        ctx->files = calloc(1, sizeof(*ctx->files)); assert(c->pool && ctx->rd.pool && ctx->files);
        ctx->rd.aio_inflight = 1; ctx->state = XRD_ST_AIO; ctx->recv.hdr_pos = 17;
    }
    f->buffer = calloc(1, 128); assert(f->buffer);
    f->context[secondary].rd.pool[0].buf = f->buffer;
    f->context[secondary].rd.pool[0].in_use = 1; f->context[secondary].rd.inflight = 1;
    brix_pgread_aio_t *t = &f->read;
    t->ctx = &f->context[0]; t->c = &f->connection[0]; t->fd = fd; t->offset = 1; t->rlen = 8;
    t->scratch = f->buffer + secondary * sizeof(ServerStatusResponse_pgRead);
    t->streamid[0] = 0x31; t->streamid[1] = 0x92; t->counted = 1;
    if (secondary) { t->sec_ctx = &f->context[1]; t->sec_c = &f->connection[1]; t->sec_counted = 1; }
    brix_pgread_aio_thread(t, &f->log);
    assert(t->nread == 8 && t->out_size == 12 && !memcmp(t->scratch + 4, "bcdefghi", 8));
}

/* WHAT: Model independent connection liveness. WHY: Each side has its own lifetime.
 * HOW: Exercise destroyed owners, deferred work and a receive loop already active. */
static void liveness(fixture *f)
{
    brix_ctx_t *p = &f->context[0], *s = &f->context[1];
    p->destroyed = mode("primary-dead") || mode("both-dead") || mode("primary-busy")
                   || mode("sent-primary-dead") || mode("token-primary-dead");
    s->destroyed = mode("secondary-dead") || mode("both-dead")
                   || mode("sent-secondary-dead") || mode("token-secondary-dead");
    p->out.finalize_pending = p->destroyed; s->out.finalize_pending = s->destroyed;
    if (mode("primary-busy")) { p->rd.aio_inflight = 2; }
    if (mode("receiving")) { p->state = XRD_ST_REQ_HEADER; }
    if (mode("uncounted")) { f->read.counted = f->read.sec_counted = 0; }
}

/* WHAT: Supply worker outcomes. WHY: Completion must distinguish data and wire failures.
 * HOW: Use valid pool-send states with the already encoded real page payload. */
static void outcome(fixture *f)
{
    brix_pgread_aio_t *t = &f->read;
    if (mode("error") || mode("wait")) { t->nread = -1; t->io_errno = mode("wait") ? EAGAIN : EIO; }
    if (mode("eof")) { t->nread = 0; t->out_size = 0; }
    if (!strncmp(f->mode, "sent", 4)) { t->pool_sent_all = 1; t->pool_sent = 44; t->pool_frames = 1; }
    if (!strncmp(f->mode, "token", 5)) {
        t->pool_token_held = 1; t->pool_sent = 7; t->pool_image_len = 44;
        f->context[1].out.send_token = 1;
    }
    if (mode("send-error")) { t->pool_send_errno = EPIPE; t->pool_sent = 7; }
    if (!strncmp(f->mode, "chunk", 5)) { t->chunk_error = 1; t->io_errno = mode("chunk-errno") ? EIO : 0; }
    t->pool_send = t->pool_sent_all || t->pool_token_held || t->pool_send_errno || t->chunk_error;
    if (mode("sent-queued")) { f->context[1].out.count = 1; }
}

/* WHAT: Execute one completion and expose state. WHY: Python asserts outcome tables.
 * HOW: Run real worker/done, then release only fixture-owned allocations. */
int main(int argc, char **argv)
{
    assert(argc == 4); fixture *f = calloc(1, sizeof(*f)); assert(f);
    f->mode = argv[1]; int secondary = atoi(argv[2]); int fd = open(argv[3], O_RDONLY); assert(fd >= 0);
    setup(f, secondary, fd); liveness(f); outcome(f);
    ngx_thread_task_t task = {.ctx = &f->read}; ngx_event_t event = {.data = &task};
    brix_pgread_aio_done(&event);
    printf("queues=%d resume=%d error=%d wait=%d chunks=%d parks=%d arms=%d teardown=%d,%d "
           "release=%d held=%u bytes=%zu pending=%lu,%lu token=%lu sent=%lld hdr=%zu\n",
        f->queues, f->resumes, f->errors, f->waits, f->chunks, f->parks, f->arms,
        f->teardowns[0], f->teardowns[1], f->releases, f->context[secondary].rd.pool[0].in_use,
        (size_t)f->context[0].totals.bytes, (unsigned long)f->context[0].rd.aio_inflight,
        (unsigned long)f->context[1].rd.aio_inflight, (unsigned long)f->context[1].out.send_token,
        (long long)f->connection[1].sent, (size_t)f->context[0].recv.hdr_pos);
    assert(f->context[0].files[0].bytes_read == f->context[0].totals.bytes);
    for (int i = 0; i < 2; i++) {
        free(f->context[i].rd.pool); free(f->context[i].files); ngx_destroy_pool(f->connection[i].pool);
    }
    free(f->session.srv_conf); free(f->buffer); close(fd); free(f); return 0;
}
