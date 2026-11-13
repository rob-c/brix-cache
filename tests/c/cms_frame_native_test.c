/* CMS frame routing, login retarget and recycled pending-client ownership. */
#include "core/ngx_brix_module.h"
#include "net/cms/cms_internal.h"
#include "net/cms/recv_internal.h"
#include "net/manager/pending.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_brix_cms_ctx_t cms;
    ngx_stream_brix_srv_conf_t conf;
    ngx_connection_t connection;
    ngx_connection_t *files[8];
    ngx_event_t read;
    ngx_stream_session_t session;
    void *contexts[1], *configs[1];
    brix_ctx_t client;
    brix_pending_locate_t pending;
    ngx_addr_t original;
    const char *mode, *host;
    unsigned unlocks, removes, answers, resumes, disconnects, schedules, forwards, fans, prepares;
    int armed;
} fixture;

static fixture *state(void) { return (fixture *)ngx_cycle; }

/* WHAT: Fail retarget allocations only. WHY: A failed retarget must retain the
 * configured manager. HOW: Arm after constructing the real pool and timer. */
void *__real_ngx_pcalloc(ngx_pool_t *, size_t);
void *__wrap_ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    if (state()->armed && !strcmp(state()->mode, "calloc")) { return NULL; }
    return __real_ngx_pcalloc(pool, size);
}
void *__real_ngx_pnalloc(ngx_pool_t *, size_t);
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    if (state()->armed && !strcmp(state()->mode, "nalloc")) { return NULL; }
    return __real_ngx_pnalloc(pool, size);
}

/* WHAT: Supply one correlated pending entry. WHY: The real wake routine must
 * release its table lock before connection lookup. HOW: Count unlock/removal. */
brix_pending_locate_t *__wrap_brix_pending_lookup(uint32_t sid, ngx_pid_t pid)
{
    assert(sid == 42 && pid == ngx_pid);
    return !strcmp(state()->mode, "missing") ? NULL : &state()->pending;
}
void __wrap_brix_pending_unlock(void) { state()->unlocks++; }
void __wrap_brix_pending_remove(uint32_t sid, ngx_pid_t pid)
{
    assert(sid == 42 && pid == ngx_pid && state()->unlocks == 1); state()->removes++;
}

/* WHAT: Observe a safe selected answer. WHY: Host validation, generation and
 * state checks must precede it. HOW: Require restored stream and removed timer. */
ngx_int_t __wrap_brix_cms_answer_selected(brix_ctx_t *ctx, ngx_connection_t *conn,
    ngx_stream_brix_srv_conf_t *conf, const char *host, uint16_t port)
{
    fixture *f = state(); assert(ctx == &f->client && conn == &f->connection && conf == &f->conf);
    assert(!strcmp(host, f->host) && port == 1234 && !f->read.timer_set);
    assert(ctx->state == XRD_ST_REQ_HEADER && ctx->recv.cur_streamid[0] == 0x12
           && ctx->recv.cur_streamid[1] == 0x34);
    f->answers++; return !strcmp(f->mode, "answer-fail") ? NGX_ERROR : NGX_OK;
}
void __wrap_brix_schedule_read_resume(ngx_connection_t *connection)
{
    assert(connection == &state()->connection); state()->resumes++;
}

/* WHAT: Observe login retarget/reconnect. WHY: No real network is required.
 * HOW: Retain the context so its address and original-manager fields are checked. */
void __wrap_ngx_brix_cms_disconnect(ngx_brix_cms_ctx_t *ctx)
{
    assert(ctx == &state()->cms); state()->disconnects++;
}
void __wrap_ngx_brix_cms_schedule(ngx_brix_cms_ctx_t *ctx, ngx_msec_t delay)
{
    assert(ctx == &state()->cms && delay == 10); state()->schedules++;
}
void __wrap_ngx_brix_cms_schedule_retry(ngx_brix_cms_ctx_t *ctx)
{
    assert(ctx == &state()->cms); state()->schedules++;
}

/* WHAT: Observe role-based namespace/staging routing. WHY: Restricted parent
 * roles must not mutate a child export. HOW: Count exact opcode payload dispatch. */
ngx_int_t __wrap_cms_node_exec_forward(ngx_brix_cms_ctx_t *ctx, u_char code,
    uint32_t sid, const u_char *payload, size_t size)
{
    assert(ctx == &state()->cms && code == CMS_RR_RM && sid == 42 && size == 0);
    assert(payload == ctx->inbuf + NGX_BRIX_CMS_HDR_LEN); state()->forwards++; return NGX_OK;
}
ngx_int_t __wrap_cms_super_fan_down(ngx_brix_cms_ctx_t *ctx, u_char code,
    const u_char *payload, size_t size)
{
    assert(ctx == &state()->cms && code == CMS_RR_RM && size == 0);
    assert(payload == ctx->inbuf + NGX_BRIX_CMS_HDR_LEN); state()->fans++; return NGX_OK;
}
ngx_int_t __wrap_cms_node_exec_prepare(ngx_brix_cms_ctx_t *ctx, u_char code,
    uint32_t sid, const u_char *payload, size_t size)
{
    assert(ctx == &state()->cms && code == CMS_RR_PREPDEL && sid == 42 && size == 0);
    assert(payload == ctx->inbuf + NGX_BRIX_CMS_HDR_LEN); state()->prepares++; return NGX_OK;
}

/* WHAT: Construct a waiting client with a real nginx timer. WHY: Wake owns
 * timer cancellation and fd recycling. HOW: Install both index lookup routes. */
static void setup(fixture *f)
{
    ngx_cycle = &f->cycle; f->cycle.log = &f->log; ngx_time_init();
    f->cycle.pool = ngx_create_pool(8192, &f->log); assert(f->cycle.pool);
    ngx_stream_brix_module.ctx_index = 0;
    assert(ngx_event_timer_init(&f->log) == NGX_OK);
    f->read.log = &f->log; ngx_add_timer(&f->read, 1000);
    f->connection = (ngx_connection_t){.fd=3, .number=9, .read=&f->read, .data=&f->session};
    f->cycle.connections = &f->connection; f->cycle.connection_n = 1;
    f->files[3] = &f->connection; f->cycle.files = f->files; f->cycle.files_n = 8;
    f->session.ctx = f->contexts; f->contexts[0] = &f->client;
    f->session.srv_conf = f->configs; f->configs[0] = &f->conf;
    f->client.state = XRD_ST_WAITING_CMS;
    f->pending = (brix_pending_locate_t){.conn_fd=3, .conn_number=9, .client_streamid={0x12,0x34}};
    f->cms.cycle = &f->cycle; f->cms.conf = &f->conf; f->cms.mgr_addr = &f->original;
    ngx_str_set(&f->cms.mgr_name, "configured");
}

/* WHAT: Model stale pending owners. WHY: Valid sid alone cannot authorize a
 * reply to a recycled descriptor. HOW: Alter exactly one lifetime field. */
static void pending_mode(fixture *f)
{
    if (!strcmp(f->mode, "linear")) { f->cycle.files = NULL; }
    if (!strcmp(f->mode, "negative")) { f->pending.conn_fd = -1; }
    if (!strcmp(f->mode, "absent-fd")) { f->pending.conn_fd = 7; }
    if (!strcmp(f->mode, "linear-miss")) { f->cycle.files = NULL; f->pending.conn_fd = 7; }
    if (!strcmp(f->mode, "recycled")) { f->connection.number++; }
    if (!strcmp(f->mode, "no-session")) { f->connection.data = NULL; }
    if (!strcmp(f->mode, "no-context")) { f->contexts[0] = NULL; }
    if (!strcmp(f->mode, "wrong-state")) { f->client.state = XRD_ST_REQ_HEADER; }
}

/* WHAT: Feed the actual frame table. WHY: Retargeting and role filtering belong
 * to the frame boundary. HOW: Construct headers and bounded redirect payloads. */
static ngx_int_t frame(fixture *f, const char *operation, int argument)
{
    uint32_t sid = 42; u_char code = 254;
    if (!strcmp(operation, "retarget")) { code = CMS_RR_TRY; sid = 0; }
    if (!strcmp(operation, "forward")) { code = CMS_RR_RM; f->conf.cms.role = argument; }
    if (!strcmp(operation, "prepare")) { code = CMS_RR_PREPDEL; }
    if (!strcmp(operation, "status")) { code = CMS_RR_STATUS; f->conf.cms.suspended = 1; }
    if (!strcmp(operation, "disconnect")) { code = CMS_RR_DISC; }
    f->cms.inbuf[3] = (u_char)sid; f->cms.inbuf[4] = code; f->cms.inbuf[5] = (u_char)argument;
    f->cms.in_need = NGX_BRIX_CMS_HDR_LEN;
    if (code == CMS_RR_TRY) {
        size_t n = strlen(f->host); u_char *payload = f->cms.inbuf + NGX_BRIX_CMS_HDR_LEN;
        memcpy(payload, f->host, n + 1); payload[n+1] = 0x04; payload[n+2] = 0xd2;
        f->cms.in_need += n + 3; f->cms.retarget_depth = argument;
        if (!strcmp(f->mode, "short")) { f->cms.in_need = NGX_BRIX_CMS_HDR_LEN + 2; }
        if (!strcmp(f->mode, "truncated")) { f->cms.in_need--; }
        if (!strcmp(f->mode, "already")) {
            f->cms.retargeted = 1; f->cms.orig_addr = &f->original;
        }
    }
    return ngx_brix_cms_process_frame(&f->cms);
}

int main(int argc, char **argv)
{
    assert(argc == 5); fixture f = {0}; f.mode = argv[2]; f.host = argv[3]; setup(&f);
    pending_mode(&f); f.armed = 1;
    ngx_int_t result = !strcmp(argv[1], "wake")
        ? brix_cms_wake_pending_session(&f.log, 42, f.host, 1234)
        : frame(&f, argv[1], atoi(argv[4]));
    if (f.cms.retargeted) { assert(f.cms.orig_addr == &f.original); }
    printf("result=%ld unlocks=%u removes=%u answers=%u resumes=%u disconnects=%u schedules=%u "
           "depth=%u changed=%d forwards=%u fans=%u prepares=%u suspended=%lu\n",
        (long)result, f.unlocks, f.removes, f.answers, f.resumes, f.disconnects, f.schedules,
        (unsigned)f.cms.retarget_depth, f.cms.mgr_addr != &f.original,
        f.forwards, f.fans, f.prepares, (unsigned long)f.conf.cms.suspended);
    if (f.read.timer_set) { ngx_del_timer(&f.read); }
    ngx_destroy_pool(f.cycle.pool); return 0;
}
