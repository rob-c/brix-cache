"""Controlled GridFTP/OCI adoption fixtures for Phase-118 XPR-001/002."""
import json
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ephemeral_port import free_port
from settings import HOST


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
PAYLOAD = bytes((index * 29 + 17) & 0xFF for index in range(8192))


class _ObjectHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _body(self):
        if self.path == "/fixture":
            return self.server.payload, "application/octet-stream"
        if self.path == "/v2/lab/app/manifests/v1":
            return self.server.payload, "application/vnd.oci.image.manifest.v1+json"
        return None, "application/octet-stream"

    def _reply(self, send_body):
        body, content_type = self._body()
        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def do_HEAD(self):
        self._reply(False)

    def do_GET(self):
        self._reply(True)

    def log_message(self, _format, *_args):
        return


class ObjectOrigin:
    def __init__(self, payload):
        self.port = free_port(HOST)
        self.server = ThreadingHTTPServer((HOST, self.port), _ObjectHandler)
        self.server.payload = payload
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class FtpOrigin:
    """Small anonymous RFC-959 fixture serving exactly one object."""

    def __init__(self, payload, advertised_size=None):
        self.payload = payload
        self.advertised_size = (len(payload) if advertised_size is None
                                else advertised_size)
        self.port = free_port(HOST)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((HOST, self.port))
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    @staticmethod
    def _send(control, message):
        control.sendall(message.encode("ascii") + b"\r\n")

    def _cmd_user(self, control, data_listener):
        self._send(control, "331 password required")
        return data_listener, False

    def _cmd_pass(self, control, data_listener):
        self._send(control, "230 logged in")
        return data_listener, False

    def _cmd_type(self, control, data_listener):
        self._send(control, "200 binary")
        return data_listener, False

    def _cmd_size(self, control, data_listener):
        self._send(control, f"213 {self.advertised_size}")
        return data_listener, False

    def _cmd_mdtm(self, control, data_listener):
        self._send(control, "213 20261006000000")
        return data_listener, False

    def _cmd_epsv(self, control, data_listener):
        if data_listener is not None:
            data_listener.close()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        data_port = free_port(HOST)
        listener.bind((HOST, data_port))
        listener.listen(1)
        listener.settimeout(5)
        self._send(control,
                   f"229 Entering Extended Passive Mode (|||{data_port}|)")
        return listener, False

    def _cmd_retr(self, control, data_listener):
        if data_listener is None:
            self._send(control, "425 use EPSV first")
            return None, False
        self._send(control, "150 opening data connection")
        data, _peer = data_listener.accept()
        with data:
            data.sendall(self.payload)
        data_listener.close()
        self._send(control, "226 transfer complete")
        return None, False

    def _cmd_quit(self, control, data_listener):
        self._send(control, "221 goodbye")
        return data_listener, True

    def _cmd_unsupported(self, control, data_listener):
        self._send(control, "500 unsupported command")
        return data_listener, False

    def _handle_command(self, control, verb, data_listener):
        handler = getattr(self, f"_cmd_{verb.lower()}", self._cmd_unsupported)
        return handler(control, data_listener)

    def _serve_session(self, control):
        data_listener = None
        control.settimeout(5)
        stream = control.makefile("rb")
        self._send(control, "220 controlled FTP fixture")
        try:
            for raw in stream:
                command = raw.decode("ascii", "strict").rstrip("\r\n")
                verb, _, _argument = command.partition(" ")
                data_listener, stop = self._handle_command(
                    control, verb, data_listener,
                )
                if stop:
                    return
        except (ConnectionError, OSError, UnicodeError):
            return
        finally:
            if data_listener is not None:
                data_listener.close()
            stream.close()

    def _serve(self):
        while not self.stopping.is_set():
            try:
                control, _peer = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with control:
                self._serve_session(control)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=2)


def _run(tmp_path, ftp_payload, advertised_size=None, verify=False):
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    output = tmp_path / "report"
    with ObjectOrigin(PAYLOAD) as objects:
        with FtpOrigin(ftp_payload, advertised_size) as ftp:
            command = [
                str(XRD), "conform", "full",
                f"http://{HOST}:{objects.port}/fixture",
                "--profile", "full", "--only", "XPR-002",
                "--also", f"ftp://{HOST}:{ftp.port}/fixture",
                "--also", f"oci+http://{HOST}:{objects.port}/lab/app:v1",
                "--wall-seconds", "15", "--request-limit", "16",
                "--byte-limit", "1048576", "--fail-on", "divergent",
                "--out", str(output),
            ]
            if verify:
                command.extend(["--verify-negative", "XPR-002"])
            result = subprocess.run(command, text=True, capture_output=True,
                                    timeout=20, check=False)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in report["results"]}
    return result, rows


def test_ftp_and_oci_bytes_join_cross_plane_oracle(tmp_path):
    """HTTP, FTP and OCI production clients adopt the same exact bytes."""
    result, rows = _run(tmp_path, PAYLOAD)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-002"]["verdict"] == "conformant"


def test_ftp_byte_mismatch_is_divergent(tmp_path):
    """Equal sizes cannot hide different FTP data-channel bytes."""
    altered = PAYLOAD[:-1] + bytes([PAYLOAD[-1] ^ 0xFF])
    result, rows = _run(tmp_path, altered, verify=True)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["XPR-002"]["verdict"] == "divergent"


def test_ftp_retr_cannot_exceed_advertised_size(tmp_path):
    """A lying FTP SIZE response aborts adoption without overflowing the sink."""
    result, rows = _run(tmp_path, PAYLOAD, advertised_size=len(PAYLOAD) - 1)
    assert result.returncode == 3, result.stderr + result.stdout
    assert rows["XPR-002"]["verdict"] == "conformant"
