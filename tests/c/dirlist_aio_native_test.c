/* Real confined directory worker with observable completion ownership. */
#include "core/ngx_brix_module.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_stream_session_t session;
    ngx_stream_brix_srv_conf_t conf;
    ngx_connection_t connection;
    brix_ctx_t context;
    brix_dirlist_aio_t read;
    const char *mode;
    u_char *allocation;
    int queues, resumes, released, error;
} fixture;

/* WHAT: Recover this process's observer. WHY: Production APIs remain unchanged.
 * HOW: The nginx cycle is the first fixture member. */
static fixture *state(void) { return (fixture *) ngx_cycle; }

/* WHAT: Observe a completed wire train. WHY: Empty final frames and ownership matter.
 * HOW: Decode every real frame, require final kXR_ok, retain only queued output. */
ngx_int_t __wrap_brix_queue_response_base(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *bytes, size_t length, u_char *owned)
{
    fixture *f = state(); size_t cursor = 0; uint16_t status = 0;
    assert(ctx == &f->context && c == &f->connection && bytes == owned && owned == f->allocation);
    while (cursor < length) {
        assert(length - cursor >= 8 && bytes[cursor] == 0x42 && bytes[cursor + 1] == 0x19);
        status = xrdw_get_u16(bytes + cursor + 2);
        assert(status == kXR_ok || status == kXR_oksofar);
        size_t size = xrdw_get_u32(bytes + cursor + 4);
        assert(size <= length - cursor - 8); cursor += 8 + size;
        assert(status != kXR_ok || cursor == length);
    }
    assert(status == kXR_ok && length >= 8);
    f->queues++; if (!strcmp(f->mode, "queued")) { ctx->out.count++; }
    printf("wire="); for (size_t i = 0; i < length; i++) { printf("%02x", bytes[i]); } puts("");
    return NGX_OK;
}

/* WHAT: Observe slot release. WHY: Inline/error releases and parked ownership differ.
 * HOW: Verify exact allocation and execute nginx's real pfree helper. */
void __real_brix_release_read_buffer(brix_ctx_t *, ngx_connection_t *, u_char *);
void __wrap_brix_release_read_buffer(brix_ctx_t *ctx, ngx_connection_t *c, u_char *bytes)
{
    fixture *f = state(); assert(ctx == &f->context && c == &f->connection && bytes == f->allocation);
    f->released++; __real_brix_release_read_buffer(ctx, c, bytes);
}

/* WHAT: Record a wire error. WHY: The completion maps the worker errno exactly.
 * HOW: Require the restored stream and a useful bounded diagnostic. */
ngx_int_t __wrap_brix_send_error(brix_ctx_t *ctx, ngx_connection_t *c,
    uint16_t code, const char *message)
{
    fixture *f = state(); assert(ctx == &f->context && c == &f->connection);
    assert(ctx->recv.cur_streamid[0] == 0x42 && ctx->recv.cur_streamid[1] == 0x19);
    assert(!strncmp(message, "dirlist: ", 9) && strlen(message) < 128);
    f->error = code; return NGX_OK;
}

/* WHAT: Observe continuation. WHY: Dead requests must not restart the receive loop.
 * HOW: Count a primary connection resume without running unrelated events. */
void __wrap_brix_aio_resume(ngx_connection_t *c)
{
    assert(c == &state()->connection); state()->resumes++;
}

/* WHAT: Build worker-owned inputs. WHY: Thread execution must avoid session state.
 * HOW: Confined preopened directory, bounded response, copied stream and checksum. */
static void setup(fixture *f, const char *path, const char *algorithm)
{
    ngx_cycle = &f->cycle; f->cycle.log = &f->log; ngx_time_init();
    ngx_stream_brix_module.ctx_index = 0; f->conf.access_log_fd = NGX_INVALID_FILE;
    f->session.srv_conf = calloc(1, sizeof(void *)); assert(f->session.srv_conf);
    f->session.srv_conf[0] = &f->conf; f->connection.data = &f->session;
    f->context.session = &f->session;
    f->connection.log = &f->log; f->connection.pool = ngx_create_pool(4096, &f->log);
    assert(f->connection.pool); f->context.state = XRD_ST_SENDING; f->context.recv.hdr_pos = 17;
    brix_dirlist_aio_t *t = &f->read;
    t->ctx = &f->context; t->c = &f->connection; t->conf = &f->conf;
    t->streamid[0] = 0x42; t->streamid[1] = 0x19;
    snprintf(t->resolved, sizeof(t->resolved), "%s", path);
    snprintf(t->cksum_algo, sizeof(t->cksum_algo), "%s", algorithm);
    t->want_stat = strcmp(algorithm, "names") != 0;
    t->want_cksum = t->want_stat && strcmp(algorithm, "stat") != 0;
    t->response_cap = !strcmp(f->mode, "overflow") ? 8 : 65544;
    t->response = ngx_palloc(f->connection.pool, t->response_cap); assert(t->response);
    f->allocation = t->response; t->dirfd = open(path, O_RDONLY); assert(t->dirfd >= 0);
    if (!strcmp(f->mode, "bad-fd")) { close(t->dirfd); t->dirfd = -1; }
}

/* WHAT: Run worker and event-loop completion. WHY: Validate FD and response lifetimes.
 * HOW: Verify worker closure, then expose exact queue/release/error outcomes. */
int main(int argc, char **argv)
{
    assert(argc == 4); fixture *f = calloc(1, sizeof(*f)); assert(f);
    f->mode = argv[1]; setup(f, argv[2], argv[3]); int fd = f->read.dirfd;
    ngx_thread_task_t task = {.ctx = &f->read}; ngx_event_t event = {.data = &task};
    brix_dirlist_aio_thread(&task, &f->log);
    assert(f->read.dirfd == -1);
    if (fd >= 0) { assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF); }
    if (!strcmp(f->mode, "fallback-message")) { f->read.io_errno = EACCES; f->read.err_msg[0] = 0; }
    if (!strcmp(f->mode, "custom-message")) {
        f->read.io_errno = ENOENT; snprintf(f->read.err_msg, sizeof(f->read.err_msg), "finite missing entry");
    }
    f->context.destroyed = !strcmp(f->mode, "destroyed");
    brix_dirlist_aio_done(&event);
    if (!f->context.destroyed) { assert(f->context.recv.hdr_pos == 0); }
    printf("queues=%d resumes=%d released=%d error=%d errno=%d null=%d\n",
        f->queues, f->resumes, f->released, f->error, f->read.io_errno, f->read.response == NULL);
    ngx_destroy_pool(f->connection.pool); free(f->session.srv_conf); free(f); return 0;
}
