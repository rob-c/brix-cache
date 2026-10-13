"""Phase-118 HTTP validator success, error, and stale-body negatives."""
import json
import gzip
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ephemeral_port import free_port
from settings import HOST


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
PAYLOAD = bytes((index * 29 + 7) & 0xFF for index in range(8192))
ETAG = '"brix-conform-current"'


class _ValidatorHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status, body=b"", content_range=None,
               content_encoding=None):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", ETAG)
        if content_range is not None:
            self.send_header("Content-Range", content_range)
        if content_encoding is not None:
            self.send_header("Content-Encoding", content_encoding)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def do_HEAD(self):
        self._reply(200, PAYLOAD)

    def _serve_encoding(self):
        if self.headers.get("Accept-Encoding") != "gzip":
            return False
        bodies = {
            "gzip_ok": (gzip.compress(PAYLOAD), "gzip"),
            "bad_gzip": (b"not-a-gzip-stream", "gzip"),
        }
        body, encoding = bodies.get(self.server.behaviour, (PAYLOAD, None))
        self._reply(200, body, content_encoding=encoding)
        return True

    def _serve_validator(self):
        if self.headers.get("If-None-Match") != ETAG:
            return False
        if self.server.behaviour == "bad_not_modified":
            self._reply(200, PAYLOAD)
        else:
            self._reply(304)
        return True

    def _serve_multi_range(self, value):
        if "," not in value:
            return False
        excessive = value.count(",") >= 256
        if self.server.behaviour == "range_limit_416" and excessive:
            self._reply(416)
        elif self.server.behaviour == "bad_range_limit" and excessive:
            self._reply(206, PAYLOAD[:1], f"bytes 0-0/{len(PAYLOAD)}")
        else:
            self._reply(200, PAYLOAD)
        return True

    def _serve_if_range(self, value):
        if not value or not self.headers.get("If-Range"):
            return False
        if self.server.behaviour == "bad_if_range":
            self._reply(206, PAYLOAD[:1], f"bytes 0-0/{len(PAYLOAD)}")
        else:
            self._reply(200, PAYLOAD)
        return True

    def _serve_single_range(self, value):
        if value is None or value == "bytes=abc-def":
            self._reply(200, PAYLOAD)
            return
        if value in ("bytes=-0", f"bytes={len(PAYLOAD)}-", "bytes=2-1"):
            self._reply(416)
            return
        if value == "bytes=-1":
            start = len(PAYLOAD) - 1
            end = start
        else:
            first, last = value[6:].split("-", 1)
            start = int(first)
            end = len(PAYLOAD) - 1 if last == "" \
                else min(int(last), len(PAYLOAD) - 1)
        body = PAYLOAD[start:end + 1]
        self._reply(206, body, f"bytes {start}-{end}/{len(PAYLOAD)}")

    def do_GET(self):
        if self._serve_encoding() or self._serve_validator():
            return
        value = self.headers.get("Range")
        if self._serve_multi_range(value or "") or self._serve_if_range(value):
            return
        self._serve_single_range(value)

    def log_message(self, _format, *_args):
        return


class ValidatorOrigin:
    def __init__(self, behaviour="ok"):
        self.port = free_port(HOST)
        self.server = ThreadingHTTPServer((HOST, self.port), _ValidatorHandler)
        self.server.behaviour = behaviour
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _run(tmp_path, behaviour="ok", verify_negative=None):
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    output = tmp_path / behaviour
    with ValidatorOrigin(behaviour) as origin:
        command = [str(XRD), "conform", "accept",
             f"http://{HOST}:{origin.port}/fixture", "--profile", "http",
             "--families", "HTR", "--fail-on", "divergent",
             "--wall-seconds", "10", "--request-limit", "64",
             "--byte-limit", "4194304", "--out", str(output)]
        if verify_negative is not None:
            command.extend(["--verify-negative", verify_negative])
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def test_current_and_stale_validators_are_honoured(tmp_path):
    result, rows = _run(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTR-018"]["verdict"] == "conformant"
    assert rows["HTR-019"]["verdict"] == "conformant"
    assert rows["HTR-020"]["verdict"] == "conformant"
    assert rows["HTR-012"]["verdict"] == "conformant"


def test_current_etag_cannot_be_ignored(tmp_path):
    result, rows = _run(tmp_path, "bad_not_modified", "HTR-018")
    assert result.returncode == 1
    assert rows["HTR-018"]["verdict"] == "divergent"


def test_stale_if_range_cannot_return_a_partial_body(tmp_path):
    result, rows = _run(tmp_path, "bad_if_range", "HTR-019")
    assert result.returncode == 1
    assert rows["HTR-019"]["verdict"] == "divergent"


def test_gzip_response_decompresses_to_the_adopted_body(tmp_path):
    result, rows = _run(tmp_path, "gzip_ok")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTR-020"]["verdict"] == "conformant"


def test_malformed_gzip_response_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "bad_gzip", "HTR-020")
    assert result.returncode == 1
    assert rows["HTR-020"]["verdict"] == "divergent"


def test_excessive_range_set_may_be_refused(tmp_path):
    result, rows = _run(tmp_path, "range_limit_416")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTR-012"]["verdict"] == "conformant"


def test_excessive_range_set_cannot_be_truncated_to_one_part(tmp_path):
    result, rows = _run(tmp_path, "bad_range_limit", "HTR-012")
    assert result.returncode == 1
    assert rows["HTR-012"]["verdict"] == "divergent"
