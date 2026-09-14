"""Check the admin listener's event contract without opening a real socket.

The three production listener function bodies use the configured nginx types.
Socket calls are local stubs; registration checks the bare-connection event
logs that Alma's debug-enabled nginx reads before returning to the caller.
"""

from pathlib import Path
import subprocess

import pytest

from csource_scan import function_body
from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def admin_listener_binary(native_compile):
    root = Path(__file__).resolve().parents[1]
    production = (root / "src/net/admin/admin_unix.c").read_text()
    signatures = (
        "static int admin_unix_worker_path(char *out, size_t cap, const char *path)",
        "static ngx_socket_t admin_unix_bind(const char *path, size_t plen, ngx_log_t *log)",
        "void brix_admin_unix_listen(ngx_cycle_t *cycle, const char *path, "
        "const brix_admin_unix_t *srv)",
    )
    names = ("admin_unix_worker_path", "admin_unix_bind", "brix_admin_unix_listen")
    bodies = "\n".join(signature + function_body(production, name)
                       for signature, name in zip(signatures, names))
    shim = (root / "tests/c/admin_listener_test.c").read_text()
    return native_compile("admin-listener", shim + bodies,
                          extra=["-fsanitize=address,undefined",
                                 "-fno-sanitize-recover=all"])


@pytest.mark.parametrize("case", ["success", "registration-failure", "path-too-long"])
def test_admin_listener_contract(admin_listener_binary, case):
    result = subprocess.run([str(admin_listener_binary), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
