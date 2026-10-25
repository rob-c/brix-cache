"""Standalone runtime-validator regression tests; no nginx or fleet required.

Run: python -m pytest --noconftest tests/test_nginx_compat_smoke.py -v
"""

from __future__ import annotations

import http.server
import importlib.util
import sys
import threading
from types import SimpleNamespace
from pathlib import Path

import pytest

from ephemeral_port import free_port
from settings import HOST


@pytest.fixture
def smoke():
    path = Path(__file__).resolve().parents[1] / "tools/ci/nginx_compat_smoke.py"
    spec = importlib.util.spec_from_file_location("nginx_compat_smoke", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def subject(tmp_path):
    """A real HTTP peer lets tests model faulty status, bytes and mutations."""
    data = tmp_path / "data"
    data.mkdir()
    payload = b"compatibility regression payload"
    (data / "seed.bin").write_bytes(payload)
    behavior = {"payload": payload, "missing": 404, "mutate": False}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/seed.bin":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(behavior["payload"])
                return
            self.send_response(behavior["missing"])
            self.end_headers()

        def deny(self):
            # Drain the request before closing: Darwin otherwise RSTs unread
            # PUT bytes and hides the deliberately forged 403 from the client.
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if behavior["mutate"]:
                (data / "seed.bin").write_bytes(b"modified despite denial")
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_PUT = deny
        do_DELETE = deny
        do_MKCOL = deny

    server = http.server.HTTPServer((HOST, free_port()), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, data, payload, behavior
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_readonly_http_export_passes(smoke, subject):
    """Success requires exact bytes, missing 404, and unchanged read-only data."""
    port, data, payload, _ = subject
    smoke._check_http(port, data, payload)
    assert (data / "seed.bin").read_bytes() == payload, "seed changed after successful smoke"


@pytest.mark.parametrize("fault, value, expected", [
    ("payload", b"corrupt", "byte-exact"),
    ("missing", 200, "expected 404"),
])
def test_bad_http_result_fails(smoke, subject, fault, value, expected):
    """HTTP success codes cannot conceal corrupt bytes or a missing-object bug."""
    port, data, payload, behavior = subject
    behavior[fault] = value
    with pytest.raises(RuntimeError, match=expected):
        smoke._check_http(port, data, payload)


def test_denied_request_cannot_mutate_storage(smoke, subject):
    """Security-negative: HTTP 403 alone cannot conceal an export mutation."""
    port, data, payload, behavior = subject
    behavior["mutate"] = True
    with pytest.raises(RuntimeError, match="changed the export"):
        smoke._check_http(port, data, payload)


def test_absent_modules_fail_before_starting_nginx(smoke, tmp_path, capsys):
    """An absent build artifact must fail the CLI, with no silent skip path."""
    result = smoke.main([
        "--nginx", sys.executable, "--module-dir", str(tmp_path / "absent"),
        "--work-dir", str(tmp_path / "work"),
    ])
    assert result == 1, "missing modules unexpectedly passed"
    assert "required dynamic module is missing" in capsys.readouterr().err
    assert not (tmp_path / "work").exists(), "runtime setup preceded artifact validation"


def test_failed_probe_reaps_its_private_process(smoke, tmp_path):
    """A failed request must still terminate and reap the private server."""
    command = [sys.executable, "-c", "import time; time.sleep(60)"]
    with pytest.raises(RuntimeError, match="probe failure"):
        with smoke._running_nginx(command, tmp_path) as process:
            raise RuntimeError("probe failure")
    assert process.poll() is not None, "the private server leaked after failure"


def _module_arguments(tmp_path):
    """Only the two BriX modules are common to built-in/dynamic stream builds."""
    for name in ("ngx_stream_brix_module.so", "ngx_http_brix_xrdhttp_filter_module.so"):
        (tmp_path / name).touch()
    return SimpleNamespace(nginx=Path(sys.executable), module_dir=tmp_path,
                           stream_module=None)


def test_builtin_stream_does_not_require_a_nonexistent_shared_core(smoke, tmp_path, monkeypatch):
    """Success: Homebrew's built-in stream core needs only the two BriX DSOs."""
    arguments = _module_arguments(tmp_path)
    monkeypatch.setattr(smoke, "_builtin_stream", lambda binary: True)
    assert len(smoke._modules(arguments)) == 2


def test_dynamic_stream_still_requires_its_core_module(smoke, tmp_path, monkeypatch):
    """Error: a dynamic stream build cannot silently omit its core DSO."""
    arguments = _module_arguments(tmp_path)
    monkeypatch.setattr(smoke, "_builtin_stream", lambda binary: False)
    with pytest.raises(RuntimeError, match="ngx_stream_module.so"):
        smoke._modules(arguments)


def test_explicit_missing_stream_override_cannot_fall_back(smoke, tmp_path, monkeypatch):
    """Negative: an authoritative broken override remains a hard error."""
    arguments = _module_arguments(tmp_path)
    arguments.stream_module = tmp_path / "explicit-missing.so"
    monkeypatch.setattr(smoke, "_builtin_stream", lambda binary: True)
    with pytest.raises(RuntimeError, match="explicit-missing.so"):
        smoke._modules(arguments)


@pytest.mark.parametrize("flag,expected", [
    ("--with-stream", True), ("--with-stream=dynamic", False),
    ("--with-stream_ssl_module", False),
])
def test_builtin_stream_requires_an_exact_configure_flag(smoke, monkeypatch, flag, expected):
    """A prefix match must not mistake an external/absent stream core for built-in."""
    import subprocess
    monkeypatch.setattr(smoke.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args, 0, "", "configure arguments: " + flag))
    assert smoke._builtin_stream(sys.executable) is expected
