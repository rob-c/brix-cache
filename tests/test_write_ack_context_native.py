"""Preserve the receiving frame while a real pipelined write callback replies."""

from pathlib import Path
import subprocess

import pytest

from csource_scan import function_body
from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def write_ack_binary(native_compile):
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/core/aio/write.c").read_text()
    resume = (root / "src/core/aio/resume.c").read_text()
    declarations = (
        "ngx_flag_t brix_aio_restore_stream(brix_ctx_t *ctx, const u_char streamid[2])",
        "static void brix_write_aio_done_pipelined(brix_ctx_t *ctx, "
        "ngx_connection_t *c, ngx_stream_brix_srv_conf_t *rconf, "
        "brix_write_aio_t *t, ngx_int_t op)",
    )
    bodies = declarations[0] + function_body(resume, "brix_aio_restore_stream")
    bodies += declarations[1] + function_body(source, "brix_write_aio_done_pipelined")
    fixture = (root / "tests/c/write_ack_context_test.c").read_text()
    return native_compile(
        "write-ack-context", fixture + bodies,
        extra=["-fsanitize=address,undefined", "-fno-sanitize-recover=all"],
    )


@pytest.mark.parametrize("case", ["success", "io-error", "short-write",
                                 "send-failure", "destroyed", "destroyed-pending"])
def test_write_ack_preserves_receiving_frame(write_ack_binary, case):
    result = subprocess.run([str(write_ack_binary), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
