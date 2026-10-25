"""Completed CMS connects must not leave an idle writable event spinning."""

from pathlib import Path
import re
import shutil
import subprocess

import pytest


def _compile_callback(tmp_path_factory, symbol, boundaries, cases):
    """Compile the production callback, substituting only its dependencies."""
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler required for CMS event contracts")
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/net/cms/connect.c").read_text()
    handler = re.search(r'static void\n' + symbol + r'\([^{}]+\n\{.*?\n\}',
                        source, re.S)
    assert handler, "compile the actual production callback"
    directory = tmp_path_factory.mktemp(symbol)
    program = directory / "handler.c"
    program.write_text(boundaries + handler[0] + cases)
    binary = directory / "handler"
    built = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(program), "-o", str(binary)],
                           capture_output=True, text=True, timeout=30)
    assert built.returncode == 0, built.stdout + built.stderr
    return binary


@pytest.fixture(scope="module")
def connect_handler(tmp_path_factory):
    return _compile_callback(tmp_path_factory, 'ngx_brix_cms_write_handler',
                             _BOUNDARIES, _CASES)


@pytest.fixture(scope="module")
def connect_entry(tmp_path_factory):
    return _compile_callback(tmp_path_factory, 'ngx_brix_cms_connect',
                             _CONNECT_BOUNDARIES, _CONNECT_CASES)


@pytest.mark.parametrize("case", ["ready", "inactive", "remove-error",
                                  "timeout", "login-error", "load-error"])
def test_connect_writable_event_is_retired_or_connection_closed(connect_handler, case):
    """Success retires readiness; event/send errors never certify a live link."""
    subprocess.run([str(connect_handler), case], check=True, timeout=5)


@pytest.mark.parametrize('case', ['cold-start', 'previously-live', 'no-fast-window'])
def test_immediate_refusal_retains_retry_accounting_and_warning_policy(connect_entry, case):
    """Quiet cold starts still count failures; outages/disabled windows warn."""
    subprocess.run([str(connect_entry), case], check=True, timeout=5)


_BOUNDARIES = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef unsigned long ngx_msec_t;
typedef struct { void *log; } cycle_t;
typedef struct { struct { unsigned interval; } cms; int manager_mode; } conf_t;
typedef struct event_s ngx_event_t;
typedef struct {
    conf_t *conf;
    cycle_t *cycle;
    unsigned logged_in, retarget_fails, ever_logged_in;
    ngx_msec_t backoff, fast_deadline;
    uint64_t start_ns;
    ngx_event_t *write_event;
} ngx_brix_cms_ctx_t;
struct event_s {
    void *data, *log;
    int timedout, timer_set, active, disabled, pending_change;
};
typedef struct { void *data; ngx_event_t *read, *write; } ngx_connection_t;
enum { NGX_OK, NGX_ERROR, NGX_WRITE_EVENT = 4, NGX_DISABLE_EVENT = 8,
       BRIX_SESS_END_TIMEOUT, BRIX_SESS_END_ERROR };
#define BRIX_LOG_DEBUG(...) ((void)0)
#define BRIX_LOG(...) ((void)0)
#define BRIX_RESIL_METRIC_INC(...) ((void)0)
#define NGX_BRIX_CMS_MS_PER_SEC 1000UL
#define NGX_BRIX_CMS_BACKOFF_INITIAL 1000UL
#define ngx_min(a,b) ((a) < (b) ? (a) : (b))
static int removes, closed, retries, logins, loads, schedules, reads;
static int reject_remove, reject_login, reject_load;
static void ngx_del_timer(ngx_event_t *event) { event->timer_set = 0; }
static int ngx_del_event(ngx_event_t *event, int type, int flags) {
    assert(event->active && type == NGX_WRITE_EVENT && flags == NGX_DISABLE_EVENT);
    removes++;
    if (reject_remove) return NGX_ERROR;
    event->active = 0;
    event->disabled = 1;
    event->pending_change = 1;
    return NGX_OK;
}
static void ngx_brix_cms_set_end_hint(ngx_brix_cms_ctx_t *ctx, int reason) {
    (void)ctx;
    assert(reason == BRIX_SESS_END_ERROR || reason == BRIX_SESS_END_TIMEOUT);
}
static void ngx_brix_cms_disconnect(ngx_brix_cms_ctx_t *ctx) {
    ngx_event_t *event = ctx->write_event;
    /* Model nginx's close contract: only active/disabled filters participate
       in cancellation of a kqueue change not yet submitted to the kernel. */
    if (event->active || event->disabled) event->pending_change = 0;
    event->active = event->disabled = 0;
    assert(!event->pending_change);
    ctx->logged_in = 0; closed++;
}
static void ngx_brix_cms_schedule_retry(ngx_brix_cms_ctx_t *ctx) {
    (void)ctx; retries++;
}
static int ngx_brix_cms_send_login(ngx_brix_cms_ctx_t *ctx) {
    (void)ctx; logins++; return reject_login ? NGX_ERROR : NGX_OK;
}
static int ngx_brix_cms_send_status(ngx_brix_cms_ctx_t *ctx) {
    (void)ctx; return NGX_OK;
}
#define brix_cms_log_action(...) ((void)0)
static void ngx_brix_cms_log_registration(ngx_brix_cms_ctx_t *ctx) { (void)ctx; }
static void ngx_brix_cms_arm_read_deadline(ngx_brix_cms_ctx_t *ctx) { (void)ctx; }
static int ngx_brix_cms_send_load(ngx_brix_cms_ctx_t *ctx) {
    (void)ctx; loads++; return reject_load ? NGX_ERROR : NGX_OK;
}
static int ngx_handle_read_event(ngx_event_t *event, int flags) {
    (void)event; assert(flags == 0); reads++; return NGX_OK;
}
static void ngx_brix_cms_schedule(ngx_brix_cms_ctx_t *ctx, ngx_msec_t delay) {
    assert(delay == ctx->conf->cms.interval * 1000UL); schedules++;
}
'''

_CASES = r'''
int main(int argc, char **argv) {
    assert(argc == 2);
    conf_t conf = {{3}, 0};
    cycle_t cycle = {NULL};
    ngx_brix_cms_ctx_t ctx = {.conf = &conf, .cycle = &cycle};
    ngx_event_t read_event = {0}, write_event = {.active = 1, .timer_set = 1};
    ngx_connection_t connection = {&ctx, &read_event, &write_event};
    ctx.write_event = &write_event;
    write_event.data = &connection;
    write_event.active = strcmp(argv[1], "inactive") != 0;
    write_event.timedout = strcmp(argv[1], "timeout") == 0;
    reject_remove = strcmp(argv[1], "remove-error") == 0;
    reject_login = strcmp(argv[1], "login-error") == 0;
    reject_load = strcmp(argv[1], "load-error") == 0;
    ngx_brix_cms_write_handler(&write_event);
    if (write_event.timedout || reject_remove || reject_login || reject_load) {
        assert(closed == 1 && retries == 1 && schedules == 0);
        assert(ctx.logged_in == 0);
        if (write_event.timedout || reject_remove) assert(logins == 0 && loads == 0);
        return 0;
    }
    assert(!write_event.active && !write_event.timer_set);
    assert(removes == (strcmp(argv[1], "inactive") != 0));
    assert(closed == 0 && retries == 0 && ctx.logged_in);
    assert(logins == 1 && loads == 1 && schedules == 1 && reads == 1);
    ngx_brix_cms_disconnect(&ctx);
    assert(!write_event.pending_change && !write_event.disabled);
    return 0;
}
'''


_CONNECT_BOUNDARIES = r'''
#include <assert.h>
#include <stddef.h>
#include <string.h>
typedef int ngx_int_t;
typedef unsigned long ngx_msec_t;
typedef struct event_s { void (*handler)(struct event_s *); } ngx_event_t;
typedef struct { void *data; ngx_event_t *read, *write; int fd; } ngx_connection_t;
typedef struct { unsigned socklen; void *sockaddr; int name; } address_t;
typedef struct { void *log; } cycle_t;
typedef struct { struct { unsigned tcp_keepalive, tcp_user_timeout, send_timeout; } cms; } conf_t;
typedef struct {
    void *sockaddr, *name, *log;
    unsigned socklen;
    int (*get)(void);
    int log_error;
    ngx_connection_t *connection;
} peer_t;
typedef struct {
    unsigned connect_attempts, ever_logged_in, fast_window, logged_in, in_pos, in_need;
    int mgr_name;
    void *mgr_dns;
    address_t *mgr_addr;
    cycle_t *cycle;
    conf_t *conf;
    peer_t peer;
    ngx_connection_t *connection;
} ngx_brix_cms_ctx_t;
enum { NGX_OK, NGX_ERROR, NGX_DECLINED, NGX_AGAIN, NGX_ERROR_ERR };
#define NGX_LOG_INFO 0
#define NGX_BRIX_CMS_HDR_LEN 8
#define NGX_BRIX_CMS_CONNECT_TIMEOUT 5000
#define ngx_memzero(p,n) memset(p,0,n)
#define BRIX_LOG(...) ((void)0)
#define BRIX_DIAG_WARN(...) (++warnings)
#define BRIX_RESIL_METRIC_INC(...) (++failures)
static unsigned warnings, failures, retries, dns_failures;
static int ngx_event_get_peer(void) { return NGX_OK; }
static int ngx_event_connect_peer(peer_t *peer) {
    assert(peer->socklen && peer->get);
    return NGX_DECLINED;
}
static void ngx_brix_cms_schedule_retry(ngx_brix_cms_ctx_t *ctx) {
    assert(!ctx->connection); retries++;
}
static void brix_dns_target_note_failure(void *target) {
    assert(target); dns_failures++;
}
static void ngx_brix_cms_read_handler(ngx_event_t *event) { (void)event; assert(0); }
static void ngx_brix_cms_write_handler(ngx_event_t *event) { (void)event; assert(0); }
static void ngx_brix_cms_sess_begin(ngx_brix_cms_ctx_t *ctx) { (void)ctx; assert(0); }
static void brix_apply_tcp_deadpeer_opts(int fd, unsigned keep, unsigned timeout) {
    (void)fd; (void)keep; (void)timeout; assert(0);
}
static void ngx_add_timer(ngx_event_t *event, ngx_msec_t timeout) {
    (void)event; (void)timeout; assert(0);
}
'''


_CONNECT_CASES = r'''
int main(int argc, char **argv) {
    assert(argc == 2);
    address_t address = {.socklen = 1};
    cycle_t cycle = {0};
    conf_t conf = {0};
    ngx_brix_cms_ctx_t ctx = {.mgr_addr = &address, .mgr_dns = &address,
        .cycle = &cycle, .conf = &conf, .fast_window = 2000};
    ctx.ever_logged_in = strcmp(argv[1], "previously-live") == 0;
    if (strcmp(argv[1], "no-fast-window") == 0) ctx.fast_window = 0;
    ngx_brix_cms_connect(&ctx);
    assert(ctx.connect_attempts == 1 && !ctx.connection && !ctx.logged_in);
    assert(failures == 1 && dns_failures == 1 && retries == 1);
    assert(warnings == (unsigned)(strcmp(argv[1], "cold-start") != 0));
    return 0;
}
'''
