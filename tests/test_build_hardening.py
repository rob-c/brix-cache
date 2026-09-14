# tests/test_build_hardening.py
"""Asserts the build emits position-independent, RELRO+BIND_NOW, non-exec-stack
artifacts. Security regression guard for the link-hardening defaults."""
import glob
import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
CLIENT_BIN = REPO / "client" / "bin" / "xrdcp"


def _readelf(path):
    return subprocess.run(["readelf", "-Wl", "-d", "-h", str(path)],
                          capture_output=True, text=True, check=True).stdout


def _is_brix_module(path):
    """Recognize current and legacy project modules, excluding nginx's core."""
    return path.match("ngx_*brix*.so") or path.match("ngx_*xrootd*.so")


def _module_build_directories():
    """Prefer an explicitly selected build over unrelated local artifacts."""
    source = os.environ.get("NGX_SRC") or os.environ.get("NGINX_SRC")
    if source:
        return [pathlib.Path(source) / "objs"]
    legacy = [pathlib.Path(path) for path in sorted(glob.glob("/tmp/nginx*/objs"))]
    return [REPO / "build/modules", REPO / "build/nginx-src/objs", *legacy]


def _find_module_sos():
    """Inspect every selected BriX module, retaining missing paths as failures."""
    from cmdscripts.live_common import _configured_nginx_modules

    configured = _configured_nginx_modules()
    if configured:
        return [pathlib.Path(path) for path in configured
                if _is_brix_module(pathlib.Path(path))]
    for directory in _module_build_directories():
        modules = sorted(path for path in directory.glob("*.so")
                         if _is_brix_module(path))
        if modules:
            return modules
    return []


def test_module_so_is_relro_now():
    """Both loaded BriX modules must carry the required ELF link hardening."""
    modules = _find_module_sos()
    if not modules:
        pytest.skip("module .so not built")
    for so in modules:
        _check_module_hardening(so)


def _check_module_hardening(so):
    """A selected missing or unhardened module must fail the build guard."""
    assert so.is_file(), f"selected module is missing: {so}"
    out = _readelf(so)
    assert "GNU_RELRO" in out, f"{so} missing RELRO"
    assert _has_bind_now(out), f"{so} missing BIND_NOW"


@pytest.mark.skipif(not CLIENT_BIN.exists(), reason="client not built")
def test_client_binary_is_pie_relro_now_noexecstack():
    out = _readelf(CLIENT_BIN)
    assert "Type:" in out, "ELF type is missing"
    assert "DYN (" in out, "binary is not PIE (Type should be DYN)"
    assert "GNU_RELRO" in out, "missing RELRO segment"
    assert _has_bind_now(out), "missing BIND_NOW"
    assert "GNU_STACK" in out, "missing GNU_STACK"
    stack_line = [l for l in out.splitlines() if "GNU_STACK" in l]
    assert stack_line, "GNU_STACK line is missing"
    assert " E " not in stack_line[0], "stack is executable"


def _has_bind_now(output):
    if "BIND_NOW" in output:
        return True
    return "FLAGS_1" in output and "NOW" in output
