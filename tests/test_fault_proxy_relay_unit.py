"""Byte-exact finite sessions through the production fault-proxy relay engine."""

import json
import socket
import subprocess

import pytest

from _test_brix_fault_proxy_helpers import _StreamEcho
from settings import HOST
from test_fault_proxy_control_unit import build_fault_unit


@pytest.fixture(scope="module")
def relay_unit(tmp_path_factory):
    """Link the real relay and its complete dependency closure."""
    return build_fault_unit(tmp_path_factory, "relay")


@pytest.fixture(scope="module")
def echo():
    """Reuse the existing streaming loopback upstream fixture."""
    upstream = _StreamEcho()
    yield upstream
    upstream.close()


def receive_bytes(peer, length):
    """Receive the expected length or an earlier observable stream close."""
    received = bytearray()
    while len(received) < length:
        chunk = peer.recv(length - len(received))
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received)


def relay_session(binary, port, payload, expected_length, *commands):
    """Drive one actual relay and wait for normal connection cleanup."""
    peer, accepted = socket.socketpair()
    with peer, accepted:
        peer.settimeout(3)
        peer.sendall(payload)
        argv = [str(binary), str(accepted.fileno()), HOST, str(port), *commands]
        with subprocess.Popen(argv, pass_fds=(accepted.fileno(),),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            accepted.close()
            try:
                received = receive_bytes(peer, expected_length)
            finally:
                peer.close()
            output, errors = process.communicate(timeout=5)
            assert process.returncode == 0, errors.decode()
    return received, json.loads(output)


@pytest.mark.parametrize("commands", [
    (), ("chunk 3",), ("drip 5 1",), ("latency 1",),
    ("jitter 1",), ("latency-dist normal 1 1",), ("reorder 100 1",),
    ("rate 1024",), ("rate 1024", "burst 1024"),
    ("connect-delay 1",), ("mss 512", "rcvbuf 2048", "sndbuf 2048"),
    ("global-rate 1024",), ("toxicity 0", "corrupt 100"),
    ("toxic add latency latency 1 up", "toxic add pace rate 1024 down"),
])
def test_relay_preserves_bytes_under_pacing(relay_unit, echo, commands):
    """Timing and segmentation controls leave every payload byte intact."""
    payload = bytes(range(128))
    received, counters = relay_session(relay_unit, echo.port, payload, len(payload), *commands)
    assert received == payload
    assert counters["up_bytes"] == counters["down_bytes"] == len(payload)
    assert counters["active"] == 0


@pytest.mark.parametrize("command,payload,expected", [
    ("replace str:needle str:target up", b"needle", b"target"),
    ("replace str:needle str:target down", b"needle", b"target"),
    ("inject str:prefix- up", b"payload", b"prefix-payload"),
    ("inject str:prefix- down", b"payload", b"prefix-payload"),
    ("mangle-len up 0 set 7", b"\0\0\0\x01data", b"\0\0\0\x07data"),
    ("mangle-len down 0 add 3", b"\0\0\0\x01data", b"\0\0\0\x04data"),
    ("mangle-len both 0 sub 1", b"\0\0\0\x04data", b"\0\0\0\x02data"),
])
def test_relay_applies_exact_byte_transform(relay_unit, echo, command, payload, expected):
    """Payload mutation is exact and confined to the configured direction."""
    received, counters = relay_session(relay_unit, echo.port, payload, len(expected), command)
    assert received == expected
    assert counters["active"] == 0


@pytest.mark.parametrize("direction", ["up", "down"])
def test_relay_corruption_cannot_pass_as_original(relay_unit, echo, direction):
    """A 100-percent corruption fault changes every byte and counts each change."""
    payload = bytes(range(128))
    received, counters = relay_session(relay_unit, echo.port, payload, len(payload),
                                       f"corrupt 100 {direction}")
    assert len(received) == len(payload)
    assert all(left != right for left, right in zip(received, payload))
    assert counters["corrupt"] == len(payload)


@pytest.mark.parametrize("command,payload", [
    ("lossy 100 up", b"secret"), ("fail-nth 1", b""),
])
def test_relay_fault_closes_and_counts_sever(relay_unit, echo, command, payload):
    """A byte-loss fault or pre-dial refusal closes the session and counts once."""
    # Pre-dial refusal needs no client bytes. Closing an unread Unix socket
    # reports RST on Linux and EOF on macOS, which is a kernel contract outside
    # this test; an idle accepted socket makes the refusal itself deterministic.
    received, counters = relay_session(relay_unit, echo.port, payload, 1, command)
    assert received == b""
    assert counters["severs"] == 1
    assert counters["active"] == 0


@pytest.mark.parametrize("command,expected", [
    ("tls set-type 23 up", b"\x17\x03\x03\x00\x04data"),
    ("tls set-type 23 down", b"\x17\x03\x03\x00\x04data"),
    ("tls set-version 3 1 up", b"\x16\x03\x01\x00\x04data"),
    ("tls inflate 3 up", b"\x16\x03\x03\x00\x07data"),
    ("tls fragment 2 up", b"\x16\x03\x03\x00\x02da\x16\x03\x03\x00\x02ta"),
])
def test_tls_record_transforms_are_byte_exact(relay_unit, echo, command, expected):
    """The real relay changes only the requested TLS record fields or framing."""
    received, counters = relay_session(relay_unit, echo.port,
        b"\x16\x03\x03\x00\x04data", len(expected), command)
    assert received == expected
    assert counters["tls_rewrites"] == 1


@pytest.mark.parametrize("direction", ["up", "down"])
def test_http_line_transform_preserves_body(relay_unit, echo, direction):
    """HTTP header rewriting keeps the application body byte-exact."""
    request = b"POST /test HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\n\r\ndata"
    expected = request.replace(b"\r\n", b"\n")
    received, counters = relay_session(relay_unit, echo.port, request, len(expected),
                                       f"http naked-lf {direction}")
    assert received == expected
    assert counters["http_rewrites"] == 1


def test_trigger_arms_only_the_response_fault(relay_unit, echo):
    """A content trigger passes the request and corrupts the selected response."""
    payload = b"trigger-me"
    received, counters = relay_session(relay_unit, echo.port, payload, len(payload),
        "trigger-once up str:trigger-me corrupt 100 down")
    assert len(received) == len(payload)
    assert all(left != right for left, right in zip(received, payload))
    assert counters["triggered"] == 1
    assert counters["corrupt"] == len(payload)


def test_recorded_response_replays_without_an_upstream(relay_unit, echo, tmp_path):
    """A finite captured session reproduces its bytes with the origin absent."""
    capture = tmp_path / "session.bfpr"
    payload = b"recorded-response"
    recorded, counters = relay_session(relay_unit, echo.port, payload, len(payload),
                                       f"record {capture}")
    assert recorded == payload
    assert counters["recorded"] == 2 * len(payload)
    # Port zero cannot host an upstream; replay must answer from the capture.
    replayed, counters = relay_session(relay_unit, 0, b"", len(payload), f"replay {capture}")
    assert replayed == payload
    assert counters["replayed"] == len(payload)
    assert counters["active"] == 0


def events_of_type(path, kind):
    """Select one event family from the real JSONL telemetry stream."""
    rows = map(json.loads, path.read_text().splitlines())
    return [row for row in rows if row["event"] == kind]


def test_fault_event_counts_never_contain_payload(relay_unit, echo, tmp_path):
    """Fault telemetry reports the mutation count without logging secret bytes."""
    events = tmp_path / "events.jsonl"
    payload = b"private-client-payload"
    received, counters = relay_session(relay_unit, echo.port, payload, len(payload),
        f"event-log {events}", "corrupt 100 up")
    assert received != payload
    mutations = events_of_type(events, "corrupt")
    assert sum(row["count"] for row in mutations) == counters["corrupt"] == len(payload)
    assert payload not in events.read_bytes()
