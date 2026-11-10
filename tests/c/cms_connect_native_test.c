/* CMS connection lifecycle using the real nginx timer tree and finite I/O. */
#include "net/cms/cms_internal.h"
#include "observability/sesslog/sesslog_ngx.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_brix_cms_ctx_t ctx;
    ngx_stream_brix_srv_conf_t conf;
    ngx_connection_t connection;
    ngx_event_t read, write;
    ngx_addr_t address, original;
    const char *mode;
    unsigned dials, closes, login, status, load, dns, dropped;
    brix_sess_end_t reason;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Complete or refuse one manager dial.
 * WHY: Both immediate and readiness failures must retain bounded retry policy.
 * HOW: Return a fixture-owned connection; all CMS orchestration remains real. */
ngx_int_t __wrap_ngx_event_connect_peer(ngx_peer_connection_t *peer)
{
    fixture *f = state(); f->dials++; assert(peer->socklen == sizeof(struct sockaddr));
    if (mode("dial-error")) { return NGX_ERROR; }
    if (mode("dial-declined")) { return NGX_DECLINED; }
    if (mode("dial-empty")) { return NGX_OK; }
    f->connection.fd = open("/dev/null", O_RDONLY); assert(f->connection.fd >= 0);
    peer->connection = &f->connection;
    return mode("immediate") ? NGX_OK : NGX_AGAIN;
}
void __wrap_ngx_close_connection(ngx_connection_t *connection)
{
    assert(connection == &state()->connection && connection->fd >= 0);
    assert(!close(connection->fd)); connection->fd = -1; state()->closes++;
}
void __wrap_brix_dns_target_note_failure(brix_dns_target_t *target)
{ assert(target == state()->ctx.mgr_dns); state()->dns++; }
void __wrap_brix_cms_state_relay_drop_ctx(ngx_brix_cms_ctx_t *ctx)
{ assert(ctx == &state()->ctx); state()->dropped++; }
void __wrap_brix_sess_end(brix_sess_t *session, brix_sess_end_t why)
{ assert(session == NULL); state()->reason = why; }

/* WHAT: Fail one initial frame or event registration.
 * WHY: A link may become registered only after its required initialization.
 * HOW: Count exact dispatch and select a single explicit seam failure. */
ngx_int_t __wrap_ngx_brix_cms_send_login(ngx_brix_cms_ctx_t *ctx)
{ assert(ctx == &state()->ctx); state()->login++; return mode("login") ? NGX_ERROR : NGX_OK; }
ngx_int_t __wrap_ngx_brix_cms_send_status(ngx_brix_cms_ctx_t *ctx)
{ assert(ctx == &state()->ctx); state()->status++; return mode("status") ? NGX_ERROR : NGX_OK; }
ngx_int_t __wrap_ngx_brix_cms_send_load(ngx_brix_cms_ctx_t *ctx)
{ assert(ctx == &state()->ctx); state()->load++; return mode("load") ? NGX_ERROR : NGX_OK; }
ngx_int_t __wrap_ngx_handle_read_event(ngx_event_t *event, ngx_uint_t flags)
{ assert(event == &state()->read && flags == 0); return mode("read-event") ? NGX_ERROR : NGX_OK; }
static ngx_int_t delete_event(ngx_event_t *event, ngx_int_t kind, ngx_uint_t flags)
{
    assert(event == &state()->write && kind == NGX_WRITE_EVENT && flags == NGX_DISABLE_EVENT);
    if (mode("delete-event")) { return NGX_ERROR; }
    event->active = 0; return NGX_OK;
}

/* WHAT: Exercise the dial and one-shot writable transition.
 * WHY: Failed handshakes must cancel every owned timer and reconnect once.
 * HOW: Fire the callback installed by the production connection owner. */
static void dial(void)
{
    fixture *f = state(); ngx_brix_cms_ctx_t *ctx = &f->ctx;
    if (mode("unresolved")) { f->address.socklen = 0; }
    if (mode("custom-timeout")) { f->conf.cms.send_timeout = 73; }
    ngx_brix_cms_timer(&ctx->timer);
    if (!ctx->connection) {
        assert(ctx->timer.timer_set && !f->closes);
        assert(f->dials == (unsigned) !mode("unresolved"));
        assert(f->dns == f->dials); return;
    }
    if (!mode("immediate")) {
        assert(f->write.timer_set);
        ngx_msec_t delay = mode("custom-timeout") ? 73 : NGX_BRIX_CMS_CONNECT_TIMEOUT;
        assert(f->write.timer.key == ngx_current_msec + delay);
        f->write.active = 1;
        if (mode("timeout")) { f->write.timedout = 1; }
        f->write.handler(&f->write);
    }
    if (mode("login") || mode("status") || mode("load") || mode("read-event")
        || mode("delete-event") || mode("timeout")) {
        assert(!ctx->connection && f->closes == 1 && ctx->timer.timer_set);
        assert(!f->read.timer_set && !f->write.timer_set && f->dropped == 1);
        assert(f->reason == (mode("timeout") ? BRIX_SESS_END_TIMEOUT : BRIX_SESS_END_ERROR));
        return;
    }
    assert(ctx->logged_in && ctx->ever_logged_in && f->login == 1 && f->status == 1 && f->load == 1);
    assert(ctx->timer.timer_set && f->read.timer_set && !f->write.timer_set);
    assert(ctx->backoff == 1000 && ctx->fast_deadline == 0);
    ngx_brix_cms_timer(&ctx->timer); assert(f->load == 2 && f->login == 1);
    ngx_brix_cms_disconnect(ctx); assert(f->closes == 1 && f->dropped == 1);
}

/* WHAT: Tear down each possible session-end state.
 * WHY: The first explicit hint wins and draining workers never reconnect.
 * HOW: Arm actual timers, set one cause, then inspect the recorded end reason. */
static void disconnect_case(void)
{
    fixture *f = state(); ngx_brix_cms_ctx_t *ctx = &f->ctx;
    ctx->connection = &f->connection; f->connection.fd = open("/dev/null", O_RDONLY);
    assert(f->connection.fd >= 0); ctx->logged_in = 1;
    ngx_add_timer(&f->read, 100); ngx_add_timer(&f->write, 100);
    ngx_add_timer(&ctx->read_resume, 100);
    brix_sess_end_t expected = BRIX_SESS_END_ERROR;
    if (mode("read-timeout")) { f->read.timedout = 1; expected = BRIX_SESS_END_TIMEOUT; }
    if (mode("write-timeout")) { f->write.timedout = 1; expected = BRIX_SESS_END_TIMEOUT; }
    if (mode("connection-error")) { f->connection.error = 1; }
    if (mode("hint")) {
        ngx_brix_cms_set_end_hint(NULL, BRIX_SESS_END_ERROR);
        ngx_brix_cms_set_end_hint(ctx, BRIX_SESS_END_TIMEOUT);
        ngx_brix_cms_set_end_hint(ctx, BRIX_SESS_END_ERROR); expected = BRIX_SESS_END_TIMEOUT;
    }
    if (mode("exiting")) { ngx_exiting = 1; expected = BRIX_SESS_END_SHUTDOWN; }
    if (mode("terminate")) { ngx_terminate = 1; expected = BRIX_SESS_END_SHUTDOWN; }
    if (mode("load")) {
        ngx_brix_cms_timer(&ctx->timer); assert(ctx->timer.timer_set);
    } else if (mode("exiting")) {
        ngx_brix_cms_timer(&ctx->timer); ngx_brix_cms_schedule_retry(ctx); assert(!ctx->timer.timer_set);
    } else { ngx_brix_cms_disconnect(ctx); }
    assert(f->reason == expected && f->closes == 1 && f->dropped == 1);
    assert(!f->read.timer_set && !f->write.timer_set && !ctx->read_resume.timer_set);
    assert(!ctx->connection && !ctx->logged_in && ctx->in_need == NGX_BRIX_CMS_HDR_LEN);
    ngx_brix_cms_disconnect(ctx); assert(f->closes == 1);
}

/* WHAT: Verify bounded backoff and restoration of the configured manager.
 * WHY: Redirect failures must not strand a node on a dead supervisor.
 * HOW: Drive three retries through the actual timer and retarget state machine. */
static void retry(void)
{
    fixture *f = state(); ngx_brix_cms_ctx_t *ctx = &f->ctx;
    ctx->backoff = 6000; ctx->retargeted = 1; ctx->retarget_depth = 2;
    ctx->orig_addr = &f->original; ctx->orig_name = (ngx_str_t) ngx_string("original:1094");
    for (unsigned i = 0; i < 3; i++) {
        ngx_brix_cms_schedule_retry(ctx); assert(ctx->timer.timer_set);
        if (i < 2) { assert(ctx->retargeted && ctx->retarget_fails == i + 1); }
    }
    assert(!ctx->retargeted && !ctx->retarget_depth && !ctx->retarget_fails);
    assert(ctx->mgr_addr == &f->original && ctx->mgr_name.data == ctx->orig_name.data);
    assert(ctx->backoff == 10000);
}

int main(int argc, char **argv)
{
    assert(argc == 3); fixture f = {0}; f.mode = argv[2]; ngx_cycle = &f.cycle;
    ngx_open_file_t file = {.fd = STDERR_FILENO};
    ngx_log_t log = {.log_level = NGX_LOG_ERR, .file = &file}; f.cycle.log = &log;
    ngx_time_init(); assert(ngx_event_timer_init(&log) == NGX_OK); ngx_current_msec = 1000;
    f.ctx.cycle = &f.cycle; f.ctx.conf = &f.conf; f.ctx.mgr_addr = &f.address;
    f.ctx.mgr_name = (ngx_str_t) ngx_string("manager:1094"); f.address.name = f.ctx.mgr_name;
    struct sockaddr address = {.sa_family = AF_INET};
    f.address.sockaddr = &address; f.address.socklen = sizeof(address);
    f.conf.cms.interval = 1; f.conf.cms.read_timeout = 100; f.conf.access_log_fd = NGX_INVALID_FILE;
    f.ctx.backoff = 10; f.ctx.timer.data = &f.ctx; f.ctx.timer.log = &log; f.ctx.read_resume.log = &log;
    f.connection.data = &f.ctx; f.connection.read = &f.read; f.connection.write = &f.write;
    f.connection.log = &log; f.read.log = f.write.log = &log;
    f.read.data = f.write.data = &f.connection; ngx_event_actions.del = delete_event;
    if (!strcmp(argv[1], "dial")) { dial(); }
    else if (!strcmp(argv[1], "retry")) { retry(); }
    else { disconnect_case(); }
    if (f.ctx.timer.timer_set) { ngx_del_timer(&f.ctx.timer); }
    ngx_exiting = 0; ngx_terminate = 0; ngx_cycle = NULL; return 0;
}
