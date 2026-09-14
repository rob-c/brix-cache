"""Check CMS event setup and descriptor ownership without network or children.

The real alternate-DS and perf-feed orchestrators use private pipe descriptors.
Only nginx connection/event boundaries and socket/connect/spawn are substituted;
the production setup, cleanup and nginx timer tree execute in the native test.
"""

import os
from pathlib import Path
import subprocess

import pytest

from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def cms_event_binary(native_compile):
    """Build both production owners against the configured nginx headers."""
    root = Path(__file__).resolve().parents[1]
    build = Path(os.environ.get("BRIX_NGINX_BUILD_DIR", root / "build/alma9-merged"))
    timer_tree = build.resolve() / "nginx-src/src/core/ngx_rbtree.c"
    return native_compile("cms-event-ownership", _NATIVE_SOURCE, [timer_tree], [
        "-DNGX_DEBUG=1", "-ffunction-sections", "-fdata-sections",
        "-Wl,--gc-sections", "-Wl,--wrap=socket", "-Wl,--wrap=connect",
        "-Wl,--wrap=pipe2", "-Wl,--wrap=posix_spawn", "-Wl,--wrap=kill",
        "-Wl,--wrap=waitpid",
    ])


@pytest.mark.parametrize("feature", ["altds", "perf"])
@pytest.mark.parametrize("case", ["accepted", "registration-error", "allocation-refused"])
def test_cms_event_registration_owns_logs_and_descriptors(cms_event_binary, feature, case):
    """Register complete events, release rejected work, and handle pool refusal."""
    result = subprocess.run([str(cms_event_binary), feature, case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


_NATIVE_SOURCE = r'''
#include <assert.h>
#include "net/cms/altds.c"
#include "net/cms/perf_pgm.c"

ngx_uint_t ngx_exiting;
volatile ngx_msec_t ngx_current_msec = 1000;
ngx_rbtree_t ngx_event_timer_rbtree;

static struct {
    ngx_connection_t connection;
    ngx_event_t read_event;
    ngx_event_t write_event;
    ngx_log_t *log;
    int owned_fd;
    int registrations;
    int releases;
    int spawns;
    int child_signals;
    int child_waits;
    int reject_registration;
    int reject_allocation;
} observed;

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
                       const char *format, ...) {
    (void)level; (void)error; (void)format;
    assert(log == observed.log);
}

ngx_connection_t *ngx_get_connection(ngx_socket_t fd, ngx_log_t *log) {
    assert(fd == observed.owned_fd && log == observed.log);
    if (observed.reject_allocation) { return NULL; }
    ngx_connection_t *connection = &observed.connection;
    memset(connection, 0, sizeof(*connection));
    memset(&observed.read_event, 0, sizeof(observed.read_event));
    memset(&observed.write_event, 0, sizeof(observed.write_event));
    connection->fd = fd;
    connection->log = log;
    connection->read = &observed.read_event;
    connection->write = &observed.write_event;
    connection->read->data = connection;
    connection->write->data = connection;
    return connection;
}

void ngx_close_connection(ngx_connection_t *connection) {
    assert(connection == &observed.connection && observed.releases == 0);
    if (connection->write->timer_set) { ngx_del_timer(connection->write); }
    assert(close(connection->fd) == 0);
    connection->fd = -1;
    observed.releases++;
}

static ngx_int_t register_event(ngx_event_t *event) {
    ngx_connection_t *connection = event->data;
    assert(connection == &observed.connection);
    assert(connection->read->log == observed.log);
    assert(connection->write->log == observed.log);
    assert(event->handler != NULL);
    observed.registrations++;
    return observed.reject_registration ? NGX_ERROR : NGX_OK;
}

ngx_int_t ngx_handle_read_event(ngx_event_t *event, ngx_uint_t flags) {
    assert(flags == 0);
    return register_event(event);
}

ngx_int_t ngx_handle_write_event(ngx_event_t *event, size_t lowat) {
    assert(lowat == 0);
    return register_event(event);
}

int __real_pipe2(int descriptors[2], int flags);
int __wrap_pipe2(int descriptors[2], int flags) {
    int result = __real_pipe2(descriptors, flags);
    assert(result == 0);
    observed.owned_fd = descriptors[0];
    return result;
}

int __wrap_socket(int domain, int type, int protocol) {
    assert(domain == AF_INET && (type & SOCK_STREAM) && protocol == 0);
    int descriptors[2];
    assert(pipe(descriptors) == 0);
    assert(close(descriptors[1]) == 0);
    observed.owned_fd = descriptors[0];
    return descriptors[0];
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length) {
    assert(fd == observed.owned_fd && length == sizeof(struct sockaddr_in));
    assert(address->sa_family == AF_INET);
    errno = EINPROGRESS;
    return -1;
}

int __wrap_posix_spawn(pid_t *pid, const char *path,
                      const posix_spawn_file_actions_t *actions,
                      const posix_spawnattr_t *attributes,
                      char *const argv[], char *const environment[]) {
    (void)environment;
    assert(strcmp(path, "/bin/sh") == 0 && actions != NULL);
    assert(attributes == NULL && strcmp(argv[1], "-c") == 0);
    *pid = 123456;
    observed.spawns++;
    return 0;
}

int __wrap_kill(pid_t pid, int selected) {
    assert(pid == 123456 && selected == SIGTERM);
    observed.child_signals++;
    return 0;
}

pid_t __wrap_waitpid(pid_t pid, int *status, int options) {
    assert(pid == 123456 && status == NULL && options == WNOHANG);
    observed.child_waits++;
    return pid;
}

ngx_int_t brix_cms_send_frame(ngx_connection_t *connection, uint32_t streamid,
        u_char code, u_char modifier, const u_char *payload, size_t length) {
    (void)connection; (void)streamid; (void)code; (void)modifier;
    (void)payload; (void)length;
    assert(0 && "initialization never sends a manager frame");
    return NGX_ERROR;
}

static void check_altds(ngx_cycle_t *cycle, int accepted) {
    ngx_stream_brix_srv_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    conf.cms.altds_port = 1;
    conf.cms.altds_interval = 300;
    brix_cms_altds_t monitor = {.cycle = cycle, .conf = &conf};
    monitor.tick.data = &monitor;
    monitor.tick.log = cycle->log;
    altds_tick(&monitor.tick);
    assert(monitor.tick.timer_set);
    if (accepted) {
        assert(monitor.probe == &observed.connection);
        assert(monitor.probe->write->timer_set);
        assert(observed.releases == 0);
        altds_probe_close(&monitor);
    }
    assert(monitor.probe == NULL);
    assert(observed.spawns == 0 && observed.child_signals == 0);
    ngx_del_timer(&monitor.tick);
}

static void check_perf(ngx_cycle_t *cycle, int accepted) {
    brix_cms_perf_t feed = {.cycle = cycle, .child = -1};
    feed.pgm.data = (u_char *)"private-test-feed";
    feed.pgm.len = strlen((char *)feed.pgm.data);
    feed.respawn.data = &feed;
    feed.respawn.log = cycle->log;
    perf_spawn(&feed);
    if (accepted) {
        assert(feed.conn == &observed.connection);
        assert(!feed.respawn.timer_set && observed.child_signals == 0);
        perf_teardown(&feed);
    }
    assert(feed.conn == NULL && feed.child == -1);
    assert(feed.respawn.timer_set);
    assert(observed.spawns == 1 && observed.child_signals == 1);
    assert(observed.child_waits == 1);
    perf_teardown(&feed);
    assert(observed.child_signals == 1 && observed.child_waits == 1);
    ngx_del_timer(&feed.respawn);
}

int main(int argc, char **argv) {
    assert(argc == 3);
    ngx_log_t log = {.log_level = NGX_LOG_DEBUG_ALL};
    ngx_cycle_t cycle = {.log = &log};
    ngx_rbtree_node_t sentinel;
    ngx_rbtree_init(&ngx_event_timer_rbtree, &sentinel,
                    ngx_rbtree_insert_timer_value);
    observed.log = &log;
    observed.owned_fd = -1;
    observed.reject_registration = strcmp(argv[2], "registration-error") == 0;
    observed.reject_allocation = strcmp(argv[2], "allocation-refused") == 0;
    int accepted = strcmp(argv[2], "accepted") == 0;
    if (strcmp(argv[1], "altds") == 0) { check_altds(&cycle, accepted); }
    else { check_perf(&cycle, accepted); }
    assert(observed.registrations == (observed.reject_allocation ? 0 : 1));
    assert(observed.releases == (observed.reject_allocation ? 0 : 1));
    assert(observed.owned_fd >= 0);
    assert(fcntl(observed.owned_fd, F_GETFD) == -1 && errno == EBADF);
    assert(ngx_event_timer_rbtree.root == ngx_event_timer_rbtree.sentinel);
    return 0;
}
'''
