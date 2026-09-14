"""Exercise real stream-proxy health ownership and endpoint selection in C.

The production pool owner, its getter and the selection kernel are compiled
together with configured nginx flags. Only allocation, logging and nginx's
cached clock/cycle are supplied by the harness; no sockets or fleet are used.
Run with BRIX_NGINX_BUILD_DIR=build/alma9-merged and pytest --noconftest.
"""

import subprocess

import pytest

from test_platform_linux_native import native_compile  # shared SDK fixture


@pytest.fixture(scope='module')
def health_binary(native_compile):
    """Link real failure tracking and its actual round-robin consumer."""
    return native_compile('proxy-health', r'''
#include <assert.h>
#include <stdlib.h>
#include "net/proxy/pool.c"
#include "net/proxy/connect_upstream_select.c"

volatile ngx_cycle_t *ngx_cycle;
volatile ngx_time_t *ngx_cached_time;

/* Preserve the independent pool-capacity contract during this compile. */
_Static_assert(BRIX_PROXY_MAX_IDLE_CONNECTIONS == 32,
               "idle capacity must not alias the 512-byte proxy buffer size");

void *ngx_alloc(size_t size, ngx_log_t *log) {
    (void)log;
    return malloc(size);
}
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
                       const char *format, ...) {
    (void)level; (void)log; (void)error; (void)format;
}

static void mark_down(brix_proxy_ctx_t *proxy, int index) {
    proxy->upstream_idx = index;
    for (ngx_uint_t attempt = 0; attempt < BRIX_PROXY_MAX_FAILS; attempt++) {
        brix_proxy_up_mark_failed(proxy);
    }
    assert(brix_proxy_up_status_get()[index].down == 1);
}

static void check_unallocated(ngx_stream_brix_srv_conf_t *conf,
                              brix_proxy_ctx_t *proxy) {
    assert(brix_proxy_up_status_get() == NULL);
    brix_proxy_up_mark_failed(proxy);
    brix_proxy_up_mark_ok(proxy);
    assert(brix_proxy_up_status_get() == NULL);
    for (ngx_uint_t turn = 0; turn < 6; turn++) {
        ngx_uint_t selected = 99;
        assert(pc_pick_healthy_upstream(conf, &selected) == NGX_OK);
        assert(selected == turn % 3);
    }
}

static void check_failed(ngx_stream_brix_srv_conf_t *conf,
                         brix_proxy_ctx_t *proxy, ngx_time_t *clock,
                         int retry_expired) {
    brix_proxy_up_status_init(conf);
    assert(brix_proxy_up_status_get() != NULL);
    for (int index = 0; index < 3; index++) { mark_down(proxy, index); }
    ngx_uint_t selected = 99;
    assert(pc_pick_healthy_upstream(conf, &selected) == NGX_ERROR);
    assert(selected == 99);
    if (retry_expired) {
        clock->sec += BRIX_PROXY_FAIL_TIMEOUT;
        mark_down(proxy, 1);
        mark_down(proxy, 2);
        assert(pc_pick_healthy_upstream(conf, &selected) == NGX_OK);
        assert(selected == 0);
        proxy->upstream_idx = 0;
        brix_proxy_up_mark_ok(proxy);
        assert(brix_proxy_up_status_get()[0].down == 0);
        assert(brix_proxy_up_status_get()[0].fails == 0);
    }
    free(proxy_up_state.status);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    ngx_time_t clock = {.sec = 1000};
    ngx_log_t log = {.log_level = NGX_LOG_ERR};
    ngx_cycle_t cycle = {.log = &log};
    ngx_connection_t client = {.log = &log};
    ngx_array_t upstreams = {.nelts = 3};
    ngx_stream_brix_srv_conf_t conf;
    brix_proxy_ctx_t proxy;
    memset(&conf, 0, sizeof(conf));
    memset(&proxy, 0, sizeof(proxy));
    conf.proxy.upstreams = &upstreams;
    proxy.client_conn = &client;
    ngx_cycle = &cycle;
    ngx_cached_time = &clock;
    if (strcmp(argv[1], "unallocated") == 0) {
        check_unallocated(&conf, &proxy);
    } else {
        check_failed(&conf, &proxy, &clock, strcmp(argv[1], "expired") == 0);
    }
    return 0;
}
''', extra=['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'])


@pytest.mark.parametrize('case', ['unallocated', 'all-down', 'expired'])
def test_proxy_health_selection(health_binary, case):
    """Round-robin healthy endpoints, refuse all-down sets and retry on expiry."""
    result = subprocess.run([str(health_binary), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
