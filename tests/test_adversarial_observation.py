"""Adversarial controls must observe complete replies and the real TLS metrics."""

import hashlib
import struct
from types import SimpleNamespace

import pytest

import _test_evil_actor_v3_helpers as helpers
import _test_proxy_mode_helpers as wire
import test_evil_actor_v3_b as chaos


class Reply:
    """Fragmented socket-shaped input; no daemon, network or copied decoder."""

    def __init__(self, frames):
        self.data = b"".join(struct.pack(">2sHI", sid, status, len(body)) + body
                             for sid, status, body in frames)
        self.sent = []
        self.closed = False

    def recv(self, length):
        length = min(length, 137)
        chunk, self.data = self.data[:length], self.data[length:]
        return chunk

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


@pytest.mark.parametrize("parts", [[65536], [32768, 32768], [1, 32767, 32768]],
                         ids=["single", "two-window", "fragmented"])
def test_control_read_collects_all_continuation_frames(monkeypatch, parts):
    """A fragmented but byte-exact reply must not be called corruption."""
    body = bytes(range(256)) * 256
    cursor, frames = 0, []
    for index, size in enumerate(parts):
        status = wire.kXR_ok if index == len(parts) - 1 else wire.kXR_oksofar
        frames.append((b"\x00\x0c", status, body[cursor:cursor + size]))
        cursor += size
    stream = Reply(frames)
    _control(monkeypatch, stream, hashlib.md5(body).hexdigest(), [])


def _control(monkeypatch, stream, digest, expected):
    """Drive the real chaos observer, not a replacement integrity predicate."""
    monkeypatch.setattr(chaos, "_session", lambda _port: (stream, None))
    monkeypatch.setattr(chaos, "_open", lambda *_args, **_kwargs:
                        (b"\x00\x02", wire.kXR_ok, b"hand"))
    errors = []
    chaos._control_root_round(SimpleNamespace(root_port=12345), digest, errors)
    assert errors == expected
    assert stream.closed and len(stream.sent) == 1


@pytest.mark.parametrize("body", [b"", b"short", b"x" * 65536],
                         ids=["empty", "short", "modified"])
def test_control_read_rejects_short_or_corrupt_success(monkeypatch, body):
    """A terminal success does not excuse missing or modified bytes."""
    stream = Reply([(b"\x00\x0c", wire.kXR_ok, body)])
    digest = hashlib.md5(b"y" * 65536).hexdigest()
    _control(monkeypatch, stream, digest, ["control_root corrupt"])


@pytest.mark.parametrize("sid,body", [(b"xx", b"y" * 65536),
                                      (b"\x00\x0c", b"y" * 65537)],
                         ids=["foreign-stream", "oversized"])
def test_control_read_refuses_foreign_or_oversized_frames(monkeypatch, sid, body):
    """Foreign stream IDs and excess bytes cannot bless a control read."""
    stream = Reply([(sid, wire.kXR_ok, body)])
    _control(monkeypatch, stream, hashlib.md5(body).hexdigest(),
             ["control_root invalid framing"])
    assert stream.data, "hostile payload was consumed before its header was checked"


def test_multiframe_error_keeps_the_terminal_error():
    """Data preceding a terminal error must not turn that error into success."""
    stream = Reply([(b"id", wire.kXR_oksofar, b"partial"),
                    (b"id", wire.kXR_error, b"failure")])
    assert wire._read_resp_all(stream, expected_sid=b"id", max_bytes=32) == (
        wire.kXR_error, b"partialfailure")


@pytest.mark.parametrize("status,body,expected", [
    (200, b"brix_frm_requests_total 0\n", True),
    (200, b"brix_requests_total 0\n", False),
    (400, b"brix_frm_requests_total 0\n", False),
    (None, b"", False),
])
def test_frm_probe_uses_the_actual_tls_observer(monkeypatch, status, body, expected):
    """A valid TLS scrape enables FRM; errors or unrelated metrics do not."""
    calls = []
    def observe(port, path, **options):
        calls.append((port, path, options))
        return status, body
    monkeypatch.setitem(helpers._frm_available.__globals__, "_https_get", observe)
    assert helpers._frm_available(SimpleNamespace(have_xattr=True), 12345) is expected
    assert calls == [(12345, "/metrics", {"timeout": 5})]


def test_frm_probe_does_not_fabricate_xattr_support(monkeypatch):
    """Absent native residency support must not be replaced by metric presence."""
    def forbidden(*_args, **_kwargs):
        raise AssertionError("xattr-negative probe contacted the server")
    monkeypatch.setitem(helpers._frm_available.__globals__, "_https_get", forbidden)
    assert helpers._frm_available(SimpleNamespace(have_xattr=False), 12345) is False


def test_frm_fixture_configures_the_durable_registry():
    """The transfer journal alone does not enable durable request ownership."""
    block = helpers._frm_block(dict(have_xattr=True, queue="/fixture/queue",
                                    control="/fixture/control", copycmd="/fixture/copy"))
    assert "brix_frm_queue_path /fixture/queue;" in block
    assert "brix_frm_control_dir /fixture/control;" in block


def test_frm_fixture_without_xattrs_enables_no_staging():
    """An unavailable residency capability must not get a synthetic registry."""
    assert helpers._frm_block(dict(have_xattr=False)) == ""


@pytest.mark.parametrize("status,reply", [(wire.kXR_ok, "0"),
                                        (wire.kXR_error, "denied")])
def test_missing_durable_request_is_a_failure_not_a_skip(monkeypatch, status, reply):
    """A configured but broken stager must stay red, not reduce coverage."""
    owner = Reply([])
    monkeypatch.setattr(chaos, "_session", lambda _port: (owner, None))
    monkeypatch.setattr(chaos, "_prepare_stage", lambda *_args: (status, reply))
    with pytest.raises(pytest.fail.Exception, match="no durable reqid"):
        chaos._stage_durable_reqid(SimpleNamespace(root_port=12345))
    assert owner.closed
