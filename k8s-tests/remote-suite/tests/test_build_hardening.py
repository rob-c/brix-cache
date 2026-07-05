# tests/test_build_hardening.py
"""Asserts the build emits position-independent, RELRO+BIND_NOW, non-exec-stack
artifacts. Security regression guard for the link-hardening defaults."""
import subprocess, pathlib, pytest, glob

REPO = pathlib.Path(__file__).resolve().parent.parent
CLIENT_BIN = REPO / "client" / "bin" / "xrdcp"


def _readelf(path):
    return subprocess.run(["readelf", "-Wl", "-d", "-h", str(path)],
                          capture_output=True, text=True, check=True).stdout


def _find_module_so():
    # nginx builds the dynamic module under the nginx source objs/ tree.
    for base in ("/tmp/nginx-1.28.3/objs", "/tmp/nginx*/objs"):
        for p in glob.glob(base + "/*xrootd*.so"):
            return p
    return None


def test_module_so_is_relro_now():
    so = _find_module_so()
    if not so:
        pytest.skip("module .so not built")
    out = _readelf(so)
    assert "GNU_RELRO" in out, "module .so missing RELRO"
    assert "BIND_NOW" in out or "NOW" in out, "module .so missing BIND_NOW"


@pytest.mark.skipif(not CLIENT_BIN.exists(), reason="client not built")
def test_client_binary_is_pie_relro_now_noexecstack():
    out = _readelf(CLIENT_BIN)
    assert "Type:" in out and "DYN (" in out, "binary is not PIE (Type should be DYN)"
    assert "GNU_RELRO" in out, "missing RELRO segment"
    assert "BIND_NOW" in out or "FLAGS_1" in out and "NOW" in out, "missing BIND_NOW"
    assert "GNU_STACK" in out, "missing GNU_STACK"
    stack_line = [l for l in out.splitlines() if "GNU_STACK" in l]
    assert stack_line and " E " not in stack_line[0], "stack is executable"
