"""Filesystem-safe I/O selection, preserving native buffer and request isolation."""
from pathlib import Path
import subprocess

import pytest

from cmdscripts.compile_run import compile_binary
from csource_scan import function_body
from test_platform_linux_native import native_compile


ROOT = Path(__file__).resolve().parents[1]


def _function(path, declaration, name):
    """Compile the unchanged production body with explicit test boundaries."""
    return declaration + function_body((ROOT / path).read_text(), name)


@pytest.fixture(scope='module')
def filesystem_policy_binary(tmp_path_factory):
    """Inject only fstatfs results; the actual FreeBSD decision is unchanged."""
    directory = tmp_path_factory.mktemp('sendfile-filesystem')
    source = directory / 'policy.c'
    source.write_text(r'''
#include <assert.h>
#include <errno.h>
#include <string.h>
struct statfs { char f_fstypename[16]; };
static int fstatfs(int fd, struct statfs *out) {
    memset(out, 0, sizeof(*out));
    if (fd < 0) { errno = EBADF; return -1; }
    if (fd == 1) { strcpy(out->f_fstypename, "ufs"); }
    if (fd == 2) { strcpy(out->f_fstypename, "zfs"); }
    return 0;
}
''' + _function('src/platform/freebsd/storage_wrapper.c',
                'int brix_plat_file_sendfile_safe(int fd)',
                'brix_plat_file_sendfile_safe') + r'''
int main(void) {
    errno = EACCES;
    assert(brix_plat_file_sendfile_safe(1) == 1 && errno == EACCES);
    assert(brix_plat_file_sendfile_safe(2) == 0 && errno == EACCES);
    assert(brix_plat_file_sendfile_safe(-1) == 0 && errno == EACCES);
    assert(brix_plat_file_sendfile_safe(3) == 0 && errno == EACCES);
    return 0;
}
''')
    binary = directory / 'policy'
    result = compile_binary(binary, ['-std=c11', '-Wall', '-Wextra', '-Werror', str(source)])
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def test_freebsd_filesystem_policy_preserves_errno_and_refuses_unknown_metadata(
        filesystem_policy_binary):
    """UFS keeps sendfile; ZFS, failed inspection and unknown types do not."""
    subprocess.run([str(filesystem_policy_binary)], check=True, timeout=10)


_BOUNDARIES = r'''
#include "core/http/http_file_response.h"
#include "protocols/root/read/read_internal.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
ngx_module_t ngx_http_copy_filter_module = { .ctx_index = 0 };
typedef struct {
    ngx_output_chain_ctx_t copy;
    unsigned primes, outputs;
    int initialization;
} policy_state_t;
int brix_plat_file_sendfile_safe(int fd) { return fd == 200; }
static ngx_flag_t brix_ktls_send_active(ngx_connection_t *connection) {
    (void) connection; return 0;
}
ngx_int_t ngx_http_output_filter(ngx_http_request_t *request, ngx_chain_t *chain) {
    policy_state_t *state = request->ctx[1];
    if (chain == NULL) {
        state->primes++;
        if (state->initialization == 1) { return NGX_ERROR; }
        if (state->initialization != 2) { request->ctx[0] = &state->copy; }
        return NGX_AGAIN; /* queued headers do not permit unsafe body output */
    }
    state->outputs++;
    for (ngx_chain_t *link = chain; link != NULL; link = link->next) {
        if (link->buf->in_file && link->buf->file->fd != 200) {
            assert(request->ctx[0] == &state->copy);
            assert(state->copy.sendfile == 0 && state->copy.need_in_memory == 1);
        }
    }
    return NGX_AGAIN;
}
static ngx_fd_t driver_fd(brix_sd_obj_t *object, off_t offset, size_t length,
                          unsigned zero_copy) {
    (void) offset; (void) length; assert(zero_copy == 1); return object->fd;
}
'''


_HTTP_MAIN = r'''
static void check_http(const char *name) {
    ngx_connection_t connection = {0};
    ngx_http_request_t request = {0}, other = {0};
    ngx_output_chain_ctx_t other_copy = {0};
    policy_state_t state = {0};
    void *contexts[2] = {NULL, &state}, *other_contexts[2] = {&other_copy, NULL};
    ngx_file_t file = {.fd = 201}, safe = {.fd = 200};
    ngx_buf_t body = {.in_file = 1, .file = &file};
    ngx_buf_t first = {.in_file = 1, .file = &safe};
    ngx_chain_t chain = {.buf = &body}, mixed = {.buf = &first, .next = &chain};
    ngx_chain_t *input = &chain;
    connection.sendfile = 1;
    request.connection = &connection; request.ctx = contexts;
    other.connection = &connection; other.ctx = other_contexts;
    other_copy.sendfile = 1;
    state.copy.sendfile = 1;
    if (strcmp(name, "safe") == 0) { file.fd = 200; }
    if (strcmp(name, "existing") == 0) { request.ctx[0] = &state.copy; }
    if (strcmp(name, "init-error") == 0) { state.initialization = 1; }
    if (strcmp(name, "init-missing") == 0) { state.initialization = 2; }
    if (strcmp(name, "malformed") == 0) { body.file = NULL; }
    if (strcmp(name, "mixed") == 0) { input = &mixed; }
    ngx_int_t result = brix_http_output_file_chain(&request, input);
    int refused = state.initialization != 0 || body.file == NULL;
    assert(result == (refused ? NGX_ERROR : NGX_AGAIN));
    assert(state.outputs == (unsigned) !refused);
    assert(connection.sendfile == 1);
    assert(other.ctx[0] == &other_copy && other_copy.sendfile == 1);
    if (strcmp(name, "safe") == 0) {
        assert(request.ctx[0] == NULL && state.primes == 0 && state.copy.sendfile == 1);
    } else if (strcmp(name, "existing") == 0) {
        assert(state.primes == 0);
    } else if (body.file != NULL) {
        assert(state.primes == 1);
    }
}
'''


_ROOT_MAIN = r'''
static void check_root(const char *name) {
    brix_ctx_t *context = calloc(1, sizeof(*context));
    ngx_connection_t connection = {0};
    brix_read_io_t io = {.idx = 0, .fd = 200, .rlen = BRIX_READ_SENDFILE_MIN};
    brix_sd_driver_t driver = {.read_sendfile_fd = driver_fd};
    assert(context != NULL);
    context->files = calloc(1, sizeof(*context->files));
    assert(context->files != NULL);
    context->files[0].is_regular = 1;
    ngx_fd_t expected = 200;
    if (strstr(name, "driver") != NULL) {
        context->files[0].sd_obj.driver = &driver;
        context->files[0].sd_obj.fd = 200;
        io.fd = 201; /* the backend's actual fd, not this alias, determines safety */
    }
    if (strstr(name, "unsafe") != NULL) {
        io.fd = 201; context->files[0].sd_obj.fd = 201; expected = NGX_INVALID_FILE;
    }
    if (strcmp(name, "root-driver-missing") == 0) {
        driver.read_sendfile_fd = NULL; expected = NGX_INVALID_FILE;
    }
    if (strcmp(name, "root-tls") == 0) {
        connection.ssl = (ngx_ssl_connection_t *) 1; expected = NGX_INVALID_FILE;
    }
    if (strcmp(name, "root-small") == 0) { io.rlen = 0; expected = NGX_INVALID_FILE; }
    assert(read_sendfile_serve_fd(context, &connection, &io) == expected);
    free(context->files);
    free(context);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    if (strncmp(argv[1], "root-", 5) == 0) { check_root(argv[1]); }
    else { check_http(argv[1]); }
    return 0;
}
'''


@pytest.fixture(scope='module')
def transfer_policy_binary(native_compile):
    """Use real SDK types; inject only filesystem verdicts and downstream filters."""
    http = 'src/core/http/http_file_response.c'
    code = _BOUNDARIES + '\n'.join([
        _function(http, 'static ngx_int_t brix_http_require_buffered_file(ngx_http_request_t *r)',
                  'brix_http_require_buffered_file'),
        _function(http, 'ngx_int_t brix_http_output_file_chain(ngx_http_request_t *r, ngx_chain_t *chain)',
                  'brix_http_output_file_chain'),
        _function('src/protocols/root/read/read_sendfile.c',
                  'ngx_fd_t read_sendfile_serve_fd(brix_ctx_t *ctx, ngx_connection_t *c, const brix_read_io_t *io)',
                  'read_sendfile_serve_fd'),
    ]) + _HTTP_MAIN + _ROOT_MAIN
    return native_compile('sendfile-policy', code, (),
                          ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])


@pytest.mark.parametrize('case', ['unsafe', 'safe', 'existing', 'mixed',
                                'init-error', 'init-missing', 'malformed'])
def test_http_file_policy_is_request_local_and_fail_closed(transfer_policy_binary, case):
    """Unsafe/unknown files are buffered; failed setup never emits file bytes."""
    subprocess.run([str(transfer_policy_binary), case], check=True, timeout=10)


@pytest.mark.parametrize('case', ['root-bare-safe', 'root-bare-unsafe',
    'root-driver-safe', 'root-driver-unsafe', 'root-driver-missing', 'root-tls', 'root-small'])
def test_root_gate_checks_the_elected_fd_without_relaxing_other_gates(
        transfer_policy_binary, case):
    """Both fd ownership forms obey the PAL, TLS and small-read contracts."""
    subprocess.run([str(transfer_policy_binary), case], check=True, timeout=10)
