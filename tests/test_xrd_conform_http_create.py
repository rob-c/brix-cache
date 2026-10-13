"""Phase-118 scratch-confined HTTP creation fixtures."""
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ephemeral_port import free_port
from settings import HOST


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
PAYLOAD = bytes((index * 43 + 17) & 0xFF for index in range(4096))


class _CreateHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def do_HEAD(self):
        self._reply(200, PAYLOAD)

    def do_GET(self):
        if self.path == "/fixture":
            self._reply(200, PAYLOAD)
        elif self.path in self.server.objects:
            self._reply(200, self.server.objects[self.path])
        else:
            self._reply(404)

    def _read_chunked(self):
        body = bytearray()
        while True:
            line = self.rfile.readline(128)
            if not line.endswith(b"\r\n"):
                return bytes(body), False
            try:
                length = int(line[:-2].split(b";", 1)[0], 16)
            except ValueError:
                return bytes(body), False
            if length == 0:
                return bytes(body), self.rfile.readline(128) == b"\r\n"
            chunk = self.rfile.read(length)
            body.extend(chunk)
            if len(chunk) != length or self.rfile.read(2) != b"\r\n":
                return bytes(body), False

    def _request_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            return self._read_chunked()
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        return body, len(body) == length

    def do_PUT(self):
        body, complete = self._request_body()
        if not complete:
            if self.server.behaviour in {"partial-cl", "partial-chunk"}:
                self.server.objects[self.path] = body
                self._reply(201)
                return
            self._reply(400)
            return
        if self.server.behaviour == "phantom":
            self._reply(201)
            return
        if self.server.behaviour == "substitute" and not body:
            body = b"not-empty"
        self.server.objects[self.path] = body
        self._reply(201)

    def do_DELETE(self):
        self.server.deleted.append(self.path)
        self.server.objects.pop(self.path, None)
        self._reply(204)

    def log_message(self, _format, *_args):
        return


class CreateOrigin:
    def __init__(self, behaviour):
        self.port = free_port(HOST)
        self.server = ThreadingHTTPServer((HOST, self.port), _CreateHandler)
        self.server.behaviour = behaviour
        self.server.objects = {}
        self.server.deleted = []
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _run(tmp_path, behaviour, verify_negative=None):
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    output = tmp_path / behaviour
    with CreateOrigin(behaviour) as origin:
        command = [str(XRD), "conform", "accept",
             f"http://{HOST}:{origin.port}/fixture", "--profile", "http",
             "--families", "HTC", "--allow-mutate", "--scratch", "/scratch",
             "--fail-on", "divergent", "--wall-seconds", "10",
             "--request-limit", "32", "--byte-limit", "1048576",
             "--out", str(output)]
        if verify_negative is not None:
            command.extend(["--verify-negative", verify_negative])
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
        )
        deleted = list(origin.server.deleted)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}, deleted


def test_zero_length_put_creates_and_cleans_empty_object(tmp_path):
    result, rows, deleted = _run(tmp_path, "ok")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTC-003"]["verdict"] == "conformant"
    assert rows["HTC-004"]["verdict"] == "conformant"
    assert rows["HTC-005"]["verdict"] == "conformant"
    assert rows["HTC-001"]["verdict"] == "skipped"
    assert rows["HTC-002"]["verdict"] == "skipped"
    assert deleted == [
        "/scratch/brix-conform-http-zero",
        "/scratch/brix-conform-http-short",
        "/scratch/brix-conform-http-chunk",
    ]


def test_successful_put_without_created_object_is_reported(tmp_path):
    result, rows, deleted = _run(tmp_path, "phantom", "HTC-003")
    assert result.returncode == 1
    assert rows["HTC-003"]["verdict"] == "divergent"
    assert deleted == [
        "/scratch/brix-conform-http-zero",
        "/scratch/brix-conform-http-short",
        "/scratch/brix-conform-http-chunk",
    ]


def test_empty_put_content_substitution_is_reported(tmp_path):
    result, rows, _deleted = _run(tmp_path, "substitute", "HTC-003")
    assert result.returncode == 1
    assert rows["HTC-003"]["verdict"] == "divergent"


def test_short_content_length_partial_commit_is_reported(tmp_path):
    result, rows, _deleted = _run(tmp_path, "partial-cl", "HTC-004")
    assert result.returncode == 1
    assert rows["HTC-004"]["verdict"] == "divergent"


def test_malformed_chunk_partial_commit_is_reported(tmp_path):
    result, rows, _deleted = _run(tmp_path, "partial-chunk", "HTC-005")
    assert result.returncode == 1
    assert rows["HTC-005"]["verdict"] == "divergent"
