"""GridFTP passive data sockets remain children of their control peer.

The live cases queue an off-peer loopback connector before the legitimate data
socket.  A vulnerable first-accept implementation consumes that attacker socket;
the hardened event engine closes it before VFS access, preserves the listener,
and completes the legitimate MODE S or MODE E upload byte-exactly.

Run with::

    PYTHONPATH=tests pytest tests/test_gridftp_passive_peer_binding.py -v -p no:xdist
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess

import pytest
from ephemeral_port import free_port

from settings import BIND_HOST, NGINX_BIN
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec


ROOT = Path(__file__).resolve().parents[1]
LEGITIMATE_PEER = BIND_HOST
RACING_PEER = "127.0.0.2"
EB_EOF = 0x40
EB_EOD = 0x08

pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(180),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-gridftp-ev"),
]


class _Gateway:
    """Registry-owned clear event gateway used by the live race regressions."""

    def __init__(self):
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name="gridftp-plain-ev",
            template="nginx_gridftp_plain_ev.conf",
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST},
        ))
        self.port = endpoint.port
        self.export = Path(endpoint.data_root)

    def close(self):
        """Stop only this fixture's registry-owned processes."""
        self.harness.close()


class _Control:
    """Minimal FTP control client with an explicitly bound transport peer."""

    def __init__(self, host, port):
        self.socket = socket.create_connection(
            (host, port), timeout=20,
            source_address=(LEGITIMATE_PEER, free_port()),
        )
        self.socket.settimeout(20)
        self.reader = self.socket.makefile("rb")
        assert self.reply().startswith("220 "), "missing GridFTP greeting"
        assert self.command("USER anonymous").startswith("331 ")
        assert self.command("PASS peer-binding").startswith("230 ")

    def send(self, command):
        """Write one CRLF-framed command without awaiting its reply."""
        self.socket.sendall(command.encode("ascii") + b"\r\n")

    def reply(self):
        """Read exactly one RFC 959 single- or multi-line reply."""
        first = self.reader.readline()
        assert first, "control connection closed before a reply"
        text = first.decode("ascii", errors="replace").rstrip("\r\n")
        assert len(text) >= 4 and text[:3].isdigit(), text
        if text[3] != "-":
            return text
        terminal = text[:3] + " "
        lines = [text]
        while True:
            line = self.reader.readline()
            assert line, "control connection closed inside a multi-line reply"
            decoded = line.decode("ascii", errors="replace").rstrip("\r\n")
            lines.append(decoded)
            if decoded.startswith(terminal):
                return "\n".join(lines)

    def command(self, command):
        """Send one command and return exactly its next complete reply."""
        self.send(command)
        return self.reply()

    def close(self):
        """Release the file wrapper and transport without sending another verb."""
        self.reader.close()
        self.socket.close()


@pytest.fixture(scope="module")
def gateway():
    """Start one local event gateway after checking live prerequisites."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    try:
        destination = socket.gethostbyname(BIND_HOST)
    except OSError as error:
        pytest.skip(f"local GridFTP bind host is unavailable: {error}")
    if not destination.startswith("127."):
        pytest.skip("peer-race regression requires the local IPv4 loopback range")

    _require_racing_peer()

    instance = _Gateway()
    yield instance
    instance.close()


def _require_racing_peer():
    """Require the secondary loopback address before starting the gateway."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((RACING_PEER, free_port()))
    except OSError as error:
        pytest.skip(f"secondary loopback source address unavailable: {error}")
    finally:
        probe.close()


def _pasv_endpoint(control):
    """Return the IPv4 host and port advertised by one PASV reply."""
    response = control.command("PASV")
    match = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", response)
    assert match, response
    fields = [int(value) for value in match.groups()]
    assert all(0 <= value <= 255 for value in fields), response
    return ".".join(map(str, fields[:4])), (fields[4] << 8) | fields[5]


def _connect_data(endpoint, source):
    """Connect one data socket from a selected loopback transport identity."""
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(20)
    connection.bind((source, free_port()))
    connection.connect(endpoint)
    return connection


def _assert_closed_without_server_data(connection):
    """Require a rejected racer to receive no byte from the protected transfer."""
    try:
        received = connection.recv(1)
    except (ConnectionResetError, BrokenPipeError):
        received = b""
    assert received == b"", f"rejected data peer received {received!r}"


def _eblock(descriptor, payload_count, offset):
    """Encode one GFD.020 MODE E header in network byte order."""
    return struct.pack("!BQQ", descriptor, payload_count, offset)


def test_peer_address_predicate_canonicalizes_and_fails_closed(tmp_path):
    """Native address unit covers mapped IPv4, IPv6 scope, and malformed input."""
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler unavailable")
    executable = tmp_path / "gridftp-peer-addr"
    command = [
        compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-I", str(ROOT / "src"),
        str(ROOT / "tests/c/gridftp_peer_addr_test.c"),
        "-o", str(executable),
    ]
    built = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert built.returncode == 0, built.stdout + built.stderr
    ran = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
    assert ran.returncode == 0, ran.stdout + ran.stderr


def test_offpeer_stream_upload_is_dropped_without_consuming_listener(gateway):
    """A MODE S racer injects no byte and the queued same-peer STOR still wins."""
    target = gateway.export / "peer-bound-stream.bin"
    target.unlink(missing_ok=True)
    payload = b"legitimate stream payload\x00" + os.urandom(8192)
    attacker_payload = b"ATTACKER-CONTENT-MUST-NOT-LAND"
    control = _Control(LEGITIMATE_PEER, gateway.port)
    attacker = legitimate = None
    try:
        endpoint = _pasv_endpoint(control)
        attacker = _connect_data(endpoint, RACING_PEER)
        attacker.sendall(attacker_payload)
        attacker.shutdown(socket.SHUT_WR)
        legitimate = _connect_data(endpoint, LEGITIMATE_PEER)
        legitimate.sendall(payload)
        legitimate.shutdown(socket.SHUT_WR)

        control.send("STOR /peer-bound-stream.bin")
        assert control.reply().startswith("150 "), "missing transfer-start reply"
        assert control.reply().startswith("226 "), "legitimate upload did not finish"
        _assert_closed_without_server_data(attacker)
        assert target.read_bytes() == payload, "off-peer bytes crossed the VFS boundary"
    finally:
        if attacker is not None:
            attacker.close()
        if legitimate is not None:
            legitimate.close()
        control.close()


def test_offpeer_mode_e_child_cannot_open_or_write_destination(gateway):
    """A MODE E racer consumes no slot/block and a same-peer child commits exactly."""
    target = gateway.export / "peer-bound-mode-e.bin"
    target.unlink(missing_ok=True)
    payload = b"legitimate extended-block payload\x00" + os.urandom(12000)
    attacker_payload = b"ATTACKER-EBLOCK-MUST-NOT-LAND"
    attacker_frame = (
        _eblock(0, len(attacker_payload), 0) + attacker_payload
        + _eblock(EB_EOF | EB_EOD, 0, 1)
    )
    legitimate_frame = (
        _eblock(0, len(payload), 0) + payload
        + _eblock(EB_EOF | EB_EOD, 0, 1)
    )
    control = _Control(LEGITIMATE_PEER, gateway.port)
    attacker = legitimate = None
    try:
        assert control.command("TYPE I").startswith("200 ")
        assert control.command("MODE E").startswith("200 ")
        endpoint = _pasv_endpoint(control)
        attacker = _connect_data(endpoint, RACING_PEER)
        attacker.sendall(attacker_frame)
        attacker.shutdown(socket.SHUT_WR)
        legitimate = _connect_data(endpoint, LEGITIMATE_PEER)
        legitimate.sendall(legitimate_frame)
        legitimate.shutdown(socket.SHUT_WR)

        control.send("STOR /peer-bound-mode-e.bin")
        assert control.reply().startswith("150 "), "missing MODE E start reply"
        assert control.reply().startswith("226 "), "legitimate MODE E upload failed"
        _assert_closed_without_server_data(attacker)
        assert target.read_bytes() == payload, "off-peer MODE E block was committed"
    finally:
        if attacker is not None:
            attacker.close()
        if legitimate is not None:
            legitimate.close()
        control.close()


def test_dcau_a_cannot_reach_a_clear_transfer_sink():
    """The pre-transfer policy rejects DCAU A unless PROT P will verify identity."""
    source = (ROOT / "src/protocols/gridftp/ev/ftp_ev_xfer.c").read_text()
    guard = re.search(
        r"static ngx_int_t\s+ev_xfer_guards\([^)]*\)\s*\{(?P<body>.*?)\n\}",
        source,
        re.DOTALL,
    )
    assert guard, "could not locate the transfer-policy boundary"
    body = guard.group("body")
    assert "fc->dcau_a && fc->prot != 'P'" in body
    assert "534 DCAU A requires PROT P data protection" in body
