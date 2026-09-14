"""Standalone runtime-validator regression tests; no nginx or fleet required.

Run: python -m pytest --noconftest tests/test_nginx_compat_smoke.py -v
"""

from __future__ import annotations

import http.server
import importlib.util
import sys
import threading
from pathlib import Path

import pytest


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
            if behavior["mutate"]:
                (data / "seed.bin").write_bytes(b"modified despite denial")
            self.send_response(403)
            self.end_headers()

        do_PUT = deny
        do_DELETE = deny
        do_MKCOL = deny

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
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
