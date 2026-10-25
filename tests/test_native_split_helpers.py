"""Execute the extracted open-option and physical-xattr helpers, not copies."""

from pathlib import Path
import subprocess

import pytest

from cmdscripts.compile_run import openssl_compile_args
from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def split_driver(native_compile):
    """Link pure production helpers against the configured native nginx SDK."""
    root = Path(__file__).resolve().parents[1]
    return native_compile("split-helpers", (root / "tests/c/native_split_helpers.c").read_text(), [
        "src/protocols/root/read/open_request_options.c",
        "src/protocols/root/read/open_overview.c",
        "src/protocols/root/path/opaque_validate.c",
        "src/protocols/root/fattr/storage_keys.c",
        "src/core/compat/crypto.c", "src/core/compat/hex.c",
    ], openssl_compile_args(["-lcrypto"]))


@pytest.mark.parametrize("case", ["success", "error", "negative"])
def test_open_and_physical_key_contracts(split_driver, case):
    """Preserve valid hints, typed errors and hostile-input boundaries."""
    result = subprocess.run([str(split_driver), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


VARIABLE_REGISTRATION = r'''
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_stream.h>
#include <assert.h>
#include <string.h>
typedef struct {
    BRIX_TEST_VARIABLE_TYPE registered[3];
    unsigned calls;
    unsigned fail_at;
} registration_state;
static ngx_int_t getter(BRIX_TEST_REQUEST_TYPE *request,
    BRIX_TEST_VALUE_TYPE *value, uintptr_t data)
{
    (void) request; (void) value; (void) data;
    return NGX_OK;
}
static BRIX_TEST_VARIABLE_TYPE *add_variable(ngx_conf_t *cf,
    ngx_str_t *name, ngx_uint_t flags)
{
    registration_state *state = cf->ctx;
    BRIX_TEST_VARIABLE_TYPE *target;
    state->calls++;
    if (state->calls == state->fail_at) { return NULL; }
    assert(state->calls <= 3);
    target = &state->registered[state->calls - 1];
    target->name = *name;
    target->flags = flags;
    return target;
}
#define BRIX_VARIABLE_TYPE BRIX_TEST_VARIABLE_TYPE
#define BRIX_VARIABLE_ADD add_variable
#define BRIX_VARIABLE_REGISTER register_descriptors
#define BRIX_VARIABLE_LINKAGE static
#include "core/compat/register_variables.inc"
int main(int argc, char **argv)
{
    BRIX_TEST_VARIABLE_TYPE descriptors[] = {
        { ngx_string("first"), NULL, getter, 0xabc, 1, 0 },
        { ngx_string("second"), NULL, getter, 0xdef, 2, 0 },
        { ngx_null_string, NULL, NULL, 0, 0, 0 }
    };
    registration_state state;
    ngx_conf_t cf;
    assert(argc == 2);
    memset(&state, 0, sizeof(state));
    memset(&cf, 0, sizeof(cf));
    cf.ctx = &state;
    if (strcmp(argv[1], "error") == 0) {
        state.fail_at = 2;
        assert(register_descriptors(&cf, descriptors) == NGX_ERROR);
        assert(state.calls == 2 && state.registered[1].get_handler == NULL);
    } else if (strcmp(argv[1], "negative") == 0) {
        descriptors[0].name.len = 0;
        assert(register_descriptors(&cf, descriptors) == NGX_OK);
        assert(state.calls == 0);
    } else {
        assert(strcmp(argv[1], "success") == 0);
        assert(register_descriptors(&cf, descriptors) == NGX_OK);
        assert(state.calls == 2);
        assert(state.registered[1].flags == 2);
        assert(state.registered[1].get_handler == getter);
        assert(state.registered[1].data == 0xdef);
    }
    return 0;
}
'''


@pytest.fixture(scope='module', params=['http', 'stream'])
def variable_registration_driver(native_compile, request):
    """The same production template compiles with both real nginx type families."""
    plane = request.param
    request_type = 'ngx_http_request_t' if plane == 'http' else 'ngx_stream_session_t'
    return native_compile('variable-registration-' + plane, VARIABLE_REGISTRATION,
        extra=['-DBRIX_TEST_VARIABLE_TYPE=ngx_' + plane + '_variable_t',
               '-DBRIX_TEST_REQUEST_TYPE=' + request_type,
               '-DBRIX_TEST_VALUE_TYPE=ngx_' + plane + '_variable_value_t'])


@pytest.mark.parametrize('case', ['success', 'error', 'negative'])
def test_shared_typed_variable_registration(variable_registration_driver, case):
    """Preserve getter/data, propagate registration failure, and honor the sentinel."""
    result = subprocess.run([str(variable_registration_driver), case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


VARIABLE_COPY = r'''
#include "core/http/http_variables.h"
#include <assert.h>
#include <string.h>
/* Fault-inject only allocation; execute the production copy helper verbatim. */
void *ngx_pnalloc(ngx_pool_t *pool, size_t length)
{
    if (pool == NULL || length > (size_t) (pool->d.end - pool->d.last)) {
        return NULL;
    }
    return pool->d.last;
}
int main(int argc, char **argv)
{
    ngx_http_request_t request;
    ngx_http_variable_value_t value;
    ngx_pool_t pool;
    unsigned char storage[8];
    char text[] = "value";
    assert(argc == 2);
    memset(&request, 0, sizeof(request));
    memset(&value, 0, sizeof(value));
    memset(&pool, 0, sizeof(pool));
    memset(storage, 0xaa, sizeof(storage));
    pool.d.last = storage;
    pool.d.end = storage + sizeof(storage);
    if (strcmp(argv[1], "error") == 0) {
        assert(brix_http_variable_copy(&request, &value, text) == NGX_ERROR);
        assert(value.data == NULL && value.valid == 0);
    } else {
        request.pool = &pool;
        assert(brix_http_variable_copy(&request, &value, text) == NGX_OK);
        assert(value.len == 5 && value.valid && !value.not_found && !value.no_cacheable);
        if (strcmp(argv[1], "negative") == 0) { memset(text, 'X', 5); }
        else { assert(strcmp(argv[1], "success") == 0); }
        assert(memcmp(value.data, "value", 5) == 0);
        assert(storage[5] == 0xaa && storage[7] == 0xaa);
    }
    return 0;
}
'''


@pytest.fixture(scope='module')
def variable_copy_driver(native_compile):
    """Only allocation is fault-injected; no variable-value implementation copy."""
    return native_compile('variable-copy', VARIABLE_COPY)


@pytest.mark.parametrize('case', ['success', 'error', 'negative'])
def test_runtime_variable_copy_owns_its_lifetime(variable_copy_driver, case):
    """Preserve exact values, allocator refusals and independence from mutable input."""
    result = subprocess.run([str(variable_copy_driver), case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


AUTH_TRACKING = r'''
#include <ngx_config.h>
#include <ngx_core.h>
#include "observability/metrics/metrics.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv)
{
    ngx_brix_metrics_t *metrics = calloc(1, sizeof(*metrics));
    const char vo[] = "atlas", identity[] = "authenticated-subject";
    char malformed[4] = { 'X', 'X', 'X', 'X' };
    assert(argc == 2 && metrics != NULL);
    if (strcmp(argv[1], "success") == 0) {
        brix_track_auth_identity(metrics, vo, sizeof(vo), identity, sizeof(identity));
        brix_track_auth_identity(metrics, vo, sizeof(vo), identity, sizeof(identity));
        assert(metrics->vo_global.slots[0].requests_total == 4);
        assert(metrics->user_tracking.unique_count == 1);
        assert(metrics->user_tracking.slots[0].sessions_total == 2);
    } else if (strcmp(argv[1], "error") == 0) {
        brix_track_auth_identity(NULL, vo, sizeof(vo), identity, sizeof(identity));
        brix_track_auth_identity(metrics, NULL, 0, NULL, 0);
        assert(metrics->vo_global.slot_count == 0 && metrics->user_tracking.unique_count == 0);
    } else {
        assert(strcmp(argv[1], "negative") == 0);
        brix_track_auth_identity(metrics, malformed, sizeof(malformed), malformed, sizeof(malformed));
        assert(metrics->vo_global.slot_count == 0 && metrics->user_tracking.unique_count == 0);
    }
    free(metrics);
    return 0;
}
'''


@pytest.fixture(scope='module')
def auth_tracking_driver(native_compile):
    """Link actual SHM tracking routines, with no substitute metrics kernel."""
    return native_compile('auth-tracking', AUTH_TRACKING,
                          ['src/observability/metrics/tracking.c'])


@pytest.mark.parametrize('case', ['success', 'error', 'negative'])
def test_auth_tracking_has_one_bounded_implementation(auth_tracking_driver, case):
    """Preserve counters, tolerate absent SHM, and refuse unterminated identities."""
    result = subprocess.run([str(auth_tracking_driver), case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


MIRROR_CONFIGURATION = r'''
#include "protocols/shared/mirror_common.h"
#include <assert.h>
#include <string.h>
static ngx_int_t handler(ngx_http_request_t *r) { (void) r; return NGX_OK; }
int main(int argc, char **argv)
{
    ngx_conf_t cf;
    ngx_array_t arguments;
    ngx_http_core_loc_conf_t location;
    ngx_str_t values[] = { ngx_string("mirror"), ngx_string("https://origin.invalid/") };
    ngx_str_t url = ngx_null_string;
    ngx_flag_t enabled = NGX_CONF_UNSET;
    char *result;
    assert(argc == 2);
    memset(&cf, 0, sizeof(cf));
    memset(&location, 0, sizeof(location));
    memset(&arguments, 0, sizeof(arguments));
    arguments.elts = values;
    arguments.nelts = 2;
    cf.args = &arguments;
    if (strcmp(argv[1], "error") == 0) { enabled = 1; }
    if (strcmp(argv[1], "negative") == 0) { arguments.nelts = 1; }
    result = brix_http_mirror_configure(&cf, &location, &enabled, &url, handler);
    if (strcmp(argv[1], "success") == 0) {
        assert(result == NGX_CONF_OK && enabled == 1);
        assert(url.data == values[1].data && url.len == values[1].len);
        assert(location.handler == handler);
    } else {
        assert(location.handler == NULL && url.len == 0);
        if (strcmp(argv[1], "error") == 0) {
            assert(result != NULL && result != NGX_CONF_ERROR);
            assert(strcmp(result, "is duplicate") == 0);
        } else {
            assert(result == NGX_CONF_ERROR && enabled == NGX_CONF_UNSET);
        }
    }
    return 0;
}
'''


@pytest.fixture(scope='module')
def mirror_configuration_driver(native_compile):
    """Exercise the real setter without nginx-core configuration globals."""
    return native_compile('mirror-configure', MIRROR_CONFIGURATION)


@pytest.mark.parametrize('case', ['success', 'error', 'negative'])
def test_mirror_setter_never_partially_publishes_invalid_input(mirror_configuration_driver, case):
    """Bind valid mirrors, preserve duplicate refusal, and reject incomplete arguments."""
    result = subprocess.run([str(mirror_configuration_driver), case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


READ_OFFLOAD = r'''
#include "protocols/root/read/read_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
ngx_int_t brix_queue_response_base(brix_ctx_t *ctx, ngx_connection_t *connection,
    u_char *buffer, size_t length, u_char *owned)
{
    (void) connection;
    assert(buffer == owned && length == 16);
    return ctx->out.count == 2 ? NGX_ERROR : NGX_OK;
}
void brix_metric_offload(brix_proto_t proto)
{
    assert(proto == BRIX_PROTO_ROOT);
    puts("metric");
}
void brix_release_read_buffer(brix_ctx_t *ctx, ngx_connection_t *connection, u_char *buffer)
{
    (void) ctx; (void) connection; (void) buffer;
    puts("release");
}
int main(int argc, char **argv)
{
    brix_ctx_t *ctx = calloc(1, sizeof(*ctx));
    ngx_connection_t connection;
    unsigned char buffer[16] = { 0 };
    ngx_int_t result;
    assert(argc == 2 && ctx != NULL);
    memset(&connection, 0, sizeof(connection));
    ctx->out.count = strcmp(argv[1], "parked") == 0 ? 1
                   : strcmp(argv[1], "error") == 0 ? 2 : 0;
    result = brix_read_offload_queue(ctx, &connection, buffer, sizeof(buffer));
    assert(result == (ctx->out.count == 2 ? NGX_ERROR : NGX_OK));
    free(ctx);
    return 0;
}
'''


@pytest.fixture(scope='module')
def read_offload_driver(native_compile):
    """Fault-inject only queue disposition; run the real ownership orchestrator."""
    return native_compile('read-offload-queue', READ_OFFLOAD)


@pytest.mark.parametrize('case,events', [
    ('parked', ['metric']), ('inline', ['metric', 'release']), ('error', ['release'])])
def test_read_secondary_ownership_and_metrics(read_offload_driver, case, events):
    """Do not free parked data, leak failed sends, or count rejected offloads."""
    result = subprocess.run([str(read_offload_driver), case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == events


CODING_INPUT = r'''
#include "protocols/cvmfs/coding.h"
#include <assert.h>
#include <string.h>
struct brix_vfs_file_s {
    const char *bytes;
    size_t physical, reported;
    unsigned reads;
    int error, directory;
};
void *ngx_pnalloc(ngx_pool_t *pool, size_t length)
{
    void *answer = pool->d.last;
    if (length > (size_t) (pool->d.end - pool->d.last)) { return NULL; }
    pool->d.last += length;
    return answer;
}
ngx_int_t brix_vfs_file_stat(const brix_vfs_file_t *file, brix_vfs_stat_t *metadata)
{
    memset(metadata, 0, sizeof(*metadata));
    metadata->size = file->reported;
    metadata->is_directory = file->directory;
    return NGX_OK;
}
ssize_t brix_vfs_file_pread(brix_vfs_file_t *file, void *buffer, size_t length, off_t offset)
{
    size_t count;
    file->reads++;
    if (file->error) { return -1; }
    if ((size_t) offset >= file->physical) { return 0; }
    count = file->physical - (size_t) offset;
    if (count > length) { count = length; }
    if (count > 2) { count = 2; }
    memcpy(buffer, file->bytes + offset, count);
    return (ssize_t) count;
}
int main(int argc, char **argv)
{
    brix_vfs_file_t file = { "abcdefgh", 8, 8, 0, 0, 0 };
    ngx_http_request_t request;
    ngx_pool_t pool;
    brix_vfs_stat_t metadata;
    unsigned char storage[32], *input = NULL, *output = NULL;
    size_t length = 777;
    int result;
    assert(argc == 2);
    memset(&request, 0, sizeof(request));
    memset(&pool, 0, sizeof(pool));
    memset(storage, 0xcc, sizeof(storage));
    pool.d.last = storage;
    pool.d.end = storage + sizeof(storage);
    request.pool = &pool;
    if (strcmp(argv[1], "error") == 0) { file.error = 1; }
    if (strcmp(argv[1], "oversize") == 0) { file.reported = 17; }
    if (strcmp(argv[1], "short") == 0) { file.physical = 4; }
    if (strcmp(argv[1], "oom") == 0) { pool.d.end = storage; }
    if (strcmp(argv[1], "directory") == 0) { file.directory = 1; }
    if (strcmp(argv[1], "empty") == 0) { file.reported = 0; }
    result = brix_cvmfs_coding_load(&request, &file, &metadata, 16, &length, &input, &output);
    if (strcmp(argv[1], "success") == 0) {
        assert(result == 0 && length == 8 && file.reads == 4);
        assert(memcmp(input, file.bytes, 8) == 0 && output == storage + 8);
        assert(storage[16] == 0xcc);
    } else {
        assert(result == -1 && length == 777);
        if (file.reported == 0 || file.reported > 16 || file.directory) {
            assert(file.reads == 0 && pool.d.last == storage);
        }
    }
    return 0;
}
'''


@pytest.fixture(scope='module')
def coding_input_driver(native_compile):
    """Keep production coding code; inject only bounded VFS reads/allocation."""
    return native_compile('cvmfs-coding-input', CODING_INPUT,
        ['src/protocols/cvmfs/coding.c'],
        ['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'])


@pytest.mark.parametrize('case', ['success', 'error', 'oversize', 'short', 'oom', 'directory', 'empty'])
def test_coding_input_is_exact_bounded_and_metadata_authoritative(coding_input_driver, case):
    """Short/error reads cannot become coded responses; bounds precede any read."""
    result = subprocess.run([str(coding_input_driver), case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
