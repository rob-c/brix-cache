"""One bounded production CMS login codec serves both handshake directions."""

import subprocess

import pytest

from test_platform_linux_native import native_compile
from _test_cms_wire_pup_conformance_helpers import _decode_login
from cmdscripts.object_unit_layout import NGX_SRC


@pytest.fixture(scope="module")
def login_codec(native_compile):
    """Compile the actual wire implementation, dropping unrelated stats code."""
    return native_compile("cms-login-codec", _DRIVER, ["src/net/cms/wire.c"],
                          ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"])


@pytest.mark.parametrize("case", ["success", "error", "negative"])
def test_production_login_codec(login_codec, case):
    """Valid fields round-trip; insufficient or hostile spans leave output intact."""
    result = subprocess.run([str(login_codec), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    if case == "success":
        payload = bytes.fromhex(result.stdout.strip())
        decoded = _decode_login(payload)
        assert decoded == {
            "version": 3, "mode": 8, "holdtime": 1234, "tspace": 100,
            "fspace": 5000, "mspace": 100, "fsnum": 1, "fsutil": 7,
            "dport": 12345, "sport": 0, "sid": b"testnode:1",
            "paths": b"r /", "iflist": b"", "envcgi": b"vnid=fixture",
            "_tail_pos": len(payload),
        }


@pytest.fixture(scope="module")
def login_ack_sender(native_compile):
    """Capture the real sender's framed payload, keeping nginx's real formatter."""
    return native_compile("cms-login-ack", _ACK_DRIVER,
                          ["src/net/cms/wire.c", "src/net/cms/server_send.c",
                           str(NGX_SRC / "src/core/ngx_string.c")],
                          ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"])


@pytest.mark.parametrize("case", ["success", "error", "negative"])
def test_production_manager_login_ack(login_ack_sender, case):
    """Correctly identify the manager; missing sockets or failed sends stay errors."""
    result = subprocess.run([str(login_ack_sender), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    if case == "success":
        payload = bytes.fromhex(result.stdout.strip())
        decoded = _decode_login(payload)
        assert decoded["version"] == 3 and decoded["mode"] == 0
        assert decoded["sid"] == b"brix-manager@fixture-host:1234"
        assert decoded["_tail_pos"] == len(payload)
        assert all(decoded[key] == b"" for key in ("paths", "iflist", "envcgi"))
        assert all(decoded[key] == 0 for key in (
            "holdtime", "tspace", "fspace", "mspace", "fsnum", "fsutil", "dport", "sport"))


@pytest.fixture(scope="module")
def login_parser(native_compile):
    """Compile the real accept-side parser against the same production encoder."""
    return native_compile("cms-login-parser", _PARSER_DRIVER,
                          ["src/net/cms/wire.c", "src/net/cms/server_recv_parse.c"],
                          ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"])


@pytest.mark.parametrize("case", ["success", "error", "negative"])
def test_production_login_admission_parser(login_parser, case):
    """Complete supported LOGINs pass; truncated and malformed mandatory data fail."""
    result = subprocess.run([str(login_parser), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope="module")
def login_auth_state(native_compile):
    """Compile the real authentication guard with observable terminal callbacks."""
    return native_compile("cms-login-auth-state", _STATE_DRIVER,
                          ["src/net/cms/server_auth.c"],
                          ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"])


@pytest.mark.parametrize("case", ["success", "error", "negative"])
def test_login_authentication_state_guard(login_auth_state, case):
    """Permit valid states, reject a pending challenge and fail closed on corruption."""
    result = subprocess.run([str(login_auth_state), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope="module")
def node_login_paths(native_compile):
    """Compile the real node sender's pure path formatter, not a test copy."""
    return native_compile("cms-node-login-paths", _PATH_DRIVER, [],
                          ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"])


@pytest.mark.parametrize("case", ["success", "error", "negative"])
def test_node_login_path_formatting(node_login_paths, case):
    """Preserve export types, empty-entry handling and bounded output writes."""
    result = subprocess.run([str(node_login_paths), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


_PATH_DRIVER = r'''
#include "net/cms/send.c"
#include <assert.h>

int main(int argc, char **argv)
{
    assert(argc == 2);
    u_char output[64], before[64];
    memset(output, 0xa5, sizeof(output));
    memcpy(before, output, sizeof(output));
    ngx_str_t paths = ngx_string("/data:/atlas");
    if (strcmp(argv[1], "success") == 0) {
        const char *expected = "w /data\nw /atlas";
        size_t length = cms_login_format_paths(paths, 1, output, sizeof(output));
        assert(length == strlen(expected));
        assert(memcmp(output, expected, length) == 0 && output[length] == 0xa5);
    } else if (strcmp(argv[1], "error") == 0) {
        ngx_str_set(&paths, ":/data::/atlas:");
        const char *expected = "r /data\nr /atlas";
        size_t length = cms_login_format_paths(paths, 0, output, sizeof(output));
        assert(length == strlen(expected) && memcmp(output, expected, length) == 0);
        paths.data = NULL;
        assert(cms_login_format_paths(paths, 0, output, sizeof(output)) == 0);
    } else {
        assert(strcmp(argv[1], "negative") == 0);
        assert(cms_login_format_paths(paths, 1, output + 1, 4) == 0);
        assert(memcmp(output, before, sizeof(output)) == 0);
        assert(cms_login_format_paths(paths, 1, NULL, sizeof(output)) == 0);
    }
    return 0;
}
'''


_DRIVER = r'''
#include "net/cms/login_wire.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    brix_cms_login_fields_t fields = {0};
    u_char output[256], original[256];
    size_t length;
    assert(argc == 2);
    memset(output, 0xa5, sizeof(output));
    memcpy(original, output, sizeof(output));
    if (strcmp(argv[1], "success") == 0) {
        fields.mode = 8; fields.hold_time = 1234; fields.total_gb = 100;
        fields.free_mb = 5000; fields.min_free_mb = 100;
        fields.fs_num = 1; fields.fs_util = 7; fields.data_port = 12345;
        ngx_str_set(&fields.sid, "testnode:1");
        ngx_str_set(&fields.paths, "r /");
        ngx_str_set(&fields.environment, "vnid=fixture");
        length = brix_cms_login_encode(output, sizeof(output), &fields);
        assert(length > 48 && length < sizeof(output));
        for (size_t index = 0; index < length; index++) printf("%02x", output[index]);
        putchar('\n');
    } else if (strcmp(argv[1], "error") == 0) {
        assert(brix_cms_login_encode(output, 47, &fields) == 0);
        ngx_str_set(&fields.sid, "testnode:1");
        assert(brix_cms_login_encode(output, 48, &fields) == 0);
        assert(brix_cms_login_encode(NULL, sizeof(output), &fields) == 0);
        assert(brix_cms_login_encode(output, sizeof(output), NULL) == 0);
        assert(memcmp(output, original, sizeof(output)) == 0);
    } else {
        assert(strcmp(argv[1], "negative") == 0);
        fields.sid.data = (u_char *) "x"; fields.sid.len = SIZE_MAX;
        assert(brix_cms_login_encode(output, sizeof(output), &fields) == 0);
        fields.sid.len = UINT16_MAX;
        assert(brix_cms_login_encode(output, sizeof(output), &fields) == 0);
        fields.sid.data = NULL; fields.sid.len = 1;
        assert(brix_cms_login_encode(output, sizeof(output), &fields) == 0);
        assert(memcmp(output, original, sizeof(output)) == 0);
    }
    return 0;
}
'''


_ACK_DRIVER = r'''
#include "net/cms/server.h"
#include "net/cms/frame_io.h"
#include "core/compat/host_identity.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    unsigned sends;
    ngx_int_t send_status;
    u_char body[512];
    size_t length;
} capture_t;

const char *brix_host_identity(void) { return "fixture-host"; }
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s, ngx_uint_t port) {
    (void)s; (void)port;
    return c->local_sockaddr != NULL ? NGX_OK : NGX_ERROR;
}
in_port_t ngx_inet_get_port(struct sockaddr *address) {
    return ntohs(((struct sockaddr_in *) address)->sin_port);
}
ngx_int_t brix_cms_send_frame(ngx_connection_t *c, uint32_t streamid, u_char code,
    u_char modifier, const u_char *payload, size_t length) {
    capture_t *capture = c->data;
    assert(streamid == 0 && code == CMS_RR_LOGIN && modifier == 0);
    assert(length <= sizeof(capture->body));
    capture->sends++;
    memcpy(capture->body, payload, length); capture->length = length;
    return capture->send_status;
}
int main(int argc, char **argv) {
    capture_t capture = {0};
    ngx_connection_t connection = {0};
    brix_cms_srv_ctx_t ctx = {0};
    struct sockaddr_in address = {0};
    assert(argc == 2);
    address.sin_family = AF_INET; address.sin_port = htons(1234);
    connection.local_sockaddr = (struct sockaddr *)&address;
    connection.data = &capture; ctx.c = &connection;
    if (strcmp(argv[1], "success") == 0) {
        assert(brix_cms_srv_send_login_ack(&ctx) == NGX_OK);
        assert(capture.sends == 1);
        for (size_t index = 0; index < capture.length; index++) printf("%02x", capture.body[index]);
        putchar('\n');
    } else if (strcmp(argv[1], "error") == 0) {
        ctx.c = NULL;
        assert(brix_cms_srv_send_login_ack(&ctx) == NGX_ERROR);
        ctx.c = &connection; connection.local_sockaddr = NULL;
        assert(brix_cms_srv_send_login_ack(&ctx) == NGX_ERROR);
        assert(capture.sends == 0);
    } else {
        assert(strcmp(argv[1], "negative") == 0);
        capture.send_status = NGX_AGAIN;
        assert(brix_cms_srv_send_login_ack(&ctx) != NGX_OK);
        capture.send_status = NGX_ERROR;
        assert(brix_cms_srv_send_login_ack(&ctx) == NGX_ERROR);
    }
    return 0;
}
'''


_PARSER_DRIVER = r'''
#include "net/cms/server_recv_internal.h"
#include "net/cms/login_wire.h"
#include <assert.h>
#include <string.h>

int main(int argc, char **argv) {
    brix_cms_login_fields_t fields = {0};
    brix_cms_srv_ctx_t ctx = {0};
    u_char payload[256], malformed[256];
    size_t length;
    assert(argc == 2);
    fields.mode = 8; fields.free_mb = 5000; fields.fs_num = 1;
    fields.fs_util = 7; fields.data_port = 12345;
    ngx_str_set(&fields.sid, "testnode:1");
    ngx_str_set(&fields.paths, "r /fixture");
    length = brix_cms_login_encode(payload, sizeof(payload), &fields);
    assert(length > 48);
    if (strcmp(argv[1], "success") == 0) {
        assert(cms_srv_parse_login(&ctx, payload, length) == 1);
        assert(ctx.port == 12345 && ctx.free_mb == 5000 && ctx.util_pct == 7);
        assert(strcmp(ctx.paths, "/fixture") == 0 && strcmp(ctx.node_role, "S") == 0);
        /* The historical optional interface/environment tail remains optional. */
        assert(cms_srv_parse_login(&ctx, payload, length - 4) == 1);
    } else if (strcmp(argv[1], "error") == 0) {
        for (size_t cut = 0; cut < length - 4; cut++)
            assert(cms_srv_parse_login(&ctx, payload, cut) == 0);
        assert(cms_srv_parse_login(&ctx, NULL, 0) == 0);
    } else {
        assert(strcmp(argv[1], "negative") == 0);
        memcpy(malformed, payload, length); malformed[0] = 0xa0;
        assert(cms_srv_parse_login(&ctx, malformed, length) == 0);
        memcpy(malformed, payload, length); malformed[2] = 99;
        assert(cms_srv_parse_login(&ctx, malformed, length) == 0);
        memcpy(malformed, payload, length); malformed[40] = 0xff; malformed[41] = 0xff;
        assert(cms_srv_parse_login(&ctx, malformed, length) == 0);
        memcpy(malformed, payload, length); malformed[42 + fields.sid.len] = 'X';
        assert(cms_srv_parse_login(&ctx, malformed, length) == 0);
    }
    return 0;
}
'''


_STATE_DRIVER = r'''
#include "net/cms/server_recv_internal.h"
#include <assert.h>
#include <string.h>

void cms_srv_log_auth_fail(brix_cms_srv_ctx_t *ctx, const char *reason) {
    assert(strcmp(reason, "login-during-auth") == 0);
    ctx->sess_attempt_logged++;
}
void cms_srv_fail_close(brix_cms_srv_ctx_t *ctx, brix_sess_end_t why) {
    assert(why == BRIX_SESS_END_ERROR);
    ctx->c = NULL;
}
int main(int argc, char **argv) {
    brix_cms_srv_ctx_t ctx = {0};
    ngx_connection_t connection = {0};
    assert(argc == 2);
    ctx.c = &connection;
    if (strcmp(argv[1], "success") == 0) {
        brix_cms_auth_state_t states[] = {CMS_AUTH_NONE, CMS_AUTH_REQUESTED, CMS_AUTH_DONE};
        for (size_t index = 0; index < sizeof(states)/sizeof(states[0]); index++) {
            ctx.auth_state = states[index];
            assert(brix_cms_srv_require_login_state(&ctx) == NGX_OK);
            assert(ctx.c == &connection && ctx.sess_attempt_logged == 0);
        }
    } else {
        assert(strcmp(argv[1], "error") == 0 || strcmp(argv[1], "negative") == 0);
        ctx.auth_state = strcmp(argv[1], "error") == 0 ? CMS_AUTH_CHALLENGED
                                                     : (brix_cms_auth_state_t)255;
        assert(brix_cms_srv_require_login_state(&ctx) == NGX_ERROR);
        assert(ctx.c == NULL && ctx.sess_attempt_logged == 1 && ctx.logged_in == 0);
    }
    return 0;
}
'''
