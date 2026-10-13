"""Phase-118 HTTP error semantics and request-confusion fixtures."""
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from ephemeral_port import free_port
from settings import HOST


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
PAYLOAD = bytes((index * 37 + 9) & 0xFF for index in range(4096))


class _ErrorHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status, body=b"", headers=()):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _normalized_path(self):
        if self.path.startswith(("http://", "https://")):
            return urlsplit(self.path).path
        return self.path

    def do_HEAD(self):
        if self._normalized_path() == "/fixture":
            self._reply(200, PAYLOAD)
        else:
            self._reply(404)

    def do_GET(self):
        absolute_form = self.path.startswith(("http://", "https://"))
        path = self._normalized_path()
        lower = path.lower()
        line_length = len(self.requestline.encode("ascii")) + 2
        if self._reject_long_line(line_length):
            self._reply(414)
            return
        if "%0d%0a" in lower:
            self._crlf_reply()
            return
        if "../" in path or "%2e%2e%2f" in lower:
            self._traversal_reply(lower)
            return
        if path == "/fixture":
            self._fixture_reply(absolute_form)
            return
        if self.server.behaviour == "leak":
            self._reply(404, b"open /etc/brix/private-token: denied")
            return
        self._reply(404, b"not found")

    def _reject_long_line(self, line_length):
        return (line_length >= self.server.request_line_limit
                and self.server.behaviour != "line-ok")

    def _crlf_reply(self):
        if self.server.behaviour == "crlf-ok":
            self._reply(200, PAYLOAD, headers=(("X-Brix", "injected"),))
            return
        self._reply(400)

    def _traversal_reply(self, lower):
        split = (self.server.behaviour == "traversal-split"
                 and "%2e%2e%2f" in lower)
        self._reply(404 if split else 403)

    def _fixture_reply(self, absolute_form):
        diverged = absolute_form and self.server.behaviour == "absolute-split"
        self._reply(200, b"absolute-form-diverged" if diverged else PAYLOAD)

    def do_PUT(self):
        ambiguous = len(self.headers.get_all("Content-Length", [])) > 1 \
            or self.headers.get("Transfer-Encoding") is not None
        if ambiguous and self.server.behaviour != "smuggle":
            self._reply(400)
        else:
            self._reply(201)

    def do_BRIXCONFORM(self):
        if self.server.behaviour == "method-500":
            self._reply(500)
        else:
            self._reply(405, headers=(("Allow", "GET, HEAD, PUT"),))

    def log_message(self, _format, *_args):
        return


class ErrorOrigin:
    def __init__(self, behaviour="ok"):
        port = free_port(HOST)
        self.server = ThreadingHTTPServer((HOST, port), _ErrorHandler)
        self.server.behaviour = behaviour
        self.server.request_line_limit = 4096
        self.port = port
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _require_xrd():
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")


def _extend_http_error_command(command, request_line_limit, verify_negative):
    if request_line_limit:
        command.extend(("--http-request-line-limit", "4096"))
    if verify_negative is not None:
        command.extend(("--verify-negative", verify_negative))


def _run(tmp_path, behaviour, request_line_limit=True, verify_negative=None):
    _require_xrd()
    output = tmp_path / behaviour
    with ErrorOrigin(behaviour) as origin:
        target = f"http://{HOST}:{origin.port}/fixture"
        command = [
            str(XRD), "conform", "accept", target,
            "--profile", "http", "--families", "HTE",
            "--budget", "boundary", "--fail-on", "divergent",
            "--wall-seconds", "10", "--request-limit", "32",
            "--byte-limit", "1048576", "--out", str(output),
        ]
        _extend_http_error_command(
            command, request_line_limit, verify_negative,
        )
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def test_http_error_and_confusion_success_paths(tmp_path):
    result, rows = _run(tmp_path, "ok")
    assert result.returncode == 0, result.stderr + result.stdout
    for clause in ("HTE-002", "HTE-003", "HTE-004", "HTE-005", "HTE-006",
                   "HTE-007", "HTE-008"):
        assert rows[clause]["verdict"] == "conformant", rows[clause]
    assert rows["HTE-001"]["reason"] == \
        "fixture-required:complete-http-errno-matrix"


def test_error_body_filesystem_disclosure_is_reported(tmp_path):
    result, rows = _run(tmp_path, "leak", verify_negative="HTE-002")
    assert result.returncode == 1
    assert rows["HTE-002"]["verdict"] == "divergent"


def test_accepted_ambiguous_request_framing_is_reported(tmp_path):
    result, rows = _run(tmp_path, "smuggle", verify_negative="HTE-006")
    assert result.returncode == 1
    assert rows["HTE-006"]["verdict"] == "divergent"


def test_accepted_overlimit_request_line_is_reported(tmp_path):
    result, rows = _run(tmp_path, "line-ok", verify_negative="HTE-005")
    assert result.returncode == 1
    assert rows["HTE-005"]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("method-500", "HTE-003"),
    ("crlf-ok", "HTE-004"),
    ("absolute-split", "HTE-007"),
    ("traversal-split", "HTE-008"),
])
def test_hostile_http_error_semantics_are_reported(
        tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, verify_negative=owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_unspecified_request_line_limit_is_explicitly_skipped(tmp_path):
    result, rows = _run(tmp_path, "ok", request_line_limit=False)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTE-005"]["verdict"] == "skipped"
    assert rows["HTE-005"]["reason"] == \
        "fixture-required:request-line-limit-boundary"
