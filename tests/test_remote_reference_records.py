"""Large oracle requests stay exact, bounded, ordered and fail-closed."""
import base64
import io
import json
import socket
import threading
from types import SimpleNamespace

import pytest

from tools.ci import remote_reference_records as records
from tools.ci import remote_reference_transport as transport


def _input_frames(data):
    """Use the real transport encoder, including its unchanged frame cap."""
    stream = io.BytesIO()
    lock = threading.Lock()
    for frame in records.input_frames(data):
        transport.send(stream, frame, lock)
    transport.send(stream, dict(kind='eof'), lock)
    stream.seek(0)
    return stream


def _process():
    """Observe the child boundary without launching reference implementations."""
    writes, closed, stopped = [], [], []
    stdin = SimpleNamespace(write=writes.append, flush=lambda: None,
                            close=lambda: closed.append(True))
    return SimpleNamespace(stdin=stdin, terminate=lambda: stopped.append(True)), writes, closed, stopped


def test_twelve_mib_write_reaches_the_worker_as_one_exact_operation(monkeypatch, tmp_path):
    """The original payload and 64-bit offset survive bounded transport frames."""
    payload = bytes(range(256)) * (12 * 1024 * 1024 // 256)
    request = dict(id=19, op='file_call', h=7, method='write',
                   kwargs=dict(offset=2**40 + 13, buffer=base64.b64encode(payload).decode()))
    data = json.dumps(request).encode() + b'\n'
    stream = io.BytesIO()
    shutdown = []
    monkeypatch.setattr(transport, '_stdin_chunks',
        lambda _stopped: (data[index:index + 65536] for index in range(0, len(data), 65536)))
    args = SimpleNamespace(kind='worker', fixture_root=tmp_path, shared_credentials=False)
    peer = SimpleNamespace(shutdown=shutdown.append)
    transport._client_input(stream, threading.Lock(), args, peer, threading.Event())
    assert shutdown == []
    stream.seek(0)
    process, writes, closed, stopped = _process()
    errors = []
    transport._input(stream, process, args, tmp_path, None, 'worker', errors)
    assert errors == stopped == [] and closed == [True]
    assert len(writes) == 1 and json.loads(writes[0]) == request
    assert base64.b64decode(json.loads(writes[0])['kwargs']['buffer'], validate=True) == payload


@pytest.mark.parametrize('length', [0, 8 * 1024 * 1024, 64 * 1024 * 1024])
def test_logical_request_cap_is_separate_from_the_frame_cap(length):
    """The approved 64 MiB logical bound includes ordinary 8 MiB requests."""
    records.check_worker_length(length)
    with pytest.raises(ValueError, match='input exceeds 64 MiB'):
        records.check_worker_length(64 * 1024 * 1024 + 1)


def test_transport_frame_send_cap_remains_eight_mib():
    """Fragmentation does not relax the existing transport security boundary."""
    stream = io.BytesIO()
    with pytest.raises(ValueError, match='frame exceeds 8 MiB'):
        transport.send(stream, dict(kind='input', data='x' * (8 * 1024 * 1024)), threading.Lock())
    assert stream.getvalue() == b''


@pytest.mark.parametrize('data', [b'{"op":"ping"}', b'{"op":', b'{bad json}\n'])
def test_truncated_or_malformed_request_never_reaches_the_child(data, tmp_path):
    """Wire EOF requires a complete newline-delimited request, not a JSON prefix."""
    process, writes, closed, stopped = _process()
    errors = []
    transport._input(_input_frames(data), process, SimpleNamespace(), tmp_path, None, 'worker', errors)
    assert writes == [] and closed == stopped == [True]
    assert errors == ['JSONDecodeError' if data.endswith(b'\n') else 'ValueError']


def test_reassembly_cannot_borrow_another_connections_prefix():
    """Partial requests and completed-record state belong to their own connection."""
    first, second = records.WorkerRecords(), records.WorkerRecords()
    assert list(first.feed(b'{"op":')) == []
    assert list(second.feed(b'{"op":"ping"}\n')) == [b'{"op":"ping"}\n']
    assert list(first.feed(b'"next"}\n')) == [b'{"op":"next"}\n']
    assert first.finish() == second.finish() == b''


def test_record_order_and_incomplete_tail_are_not_transport_frame_boundaries():
    """One fragment may finish one request and begin another without dispatching it."""
    accumulator = records.WorkerRecords()
    assert list(accumulator.feed(b'first\nse')) == [b'first\n']
    assert list(accumulator.feed(b'cond\nthi')) == [b'second\n']
    with pytest.raises(ValueError, match='truncated'):
        accumulator.finish()


def test_limit_is_checked_before_appending_or_dispatching(monkeypatch):
    """A rejected fragment cannot extend the pending buffer or invoke a child."""
    def bounded(length):
        if length > 32:
            raise ValueError('controlled logical limit')
    monkeypatch.setattr(records, 'check_worker_length', bounded)
    accumulator = records.WorkerRecords()
    assert list(accumulator.feed(b'x' * 32)) == []
    with pytest.raises(ValueError, match='logical limit'):
        list(accumulator.feed(b'overflow\n'))
    assert accumulator.pending == b'x' * 32


def test_credential_expansion_is_bounded_again_before_any_fragment(monkeypatch, tmp_path):
    """A small native request cannot bypass the cap by expanding its metadata."""
    monkeypatch.setattr(transport, '_stdin_chunks', lambda _stopped: [b'{"op":"ping"}\n'])
    monkeypatch.setattr(transport, '_client_request', lambda *_args: b'x' * (64 * 1024 * 1024 + 1))
    stream, shutdown = io.BytesIO(), []
    args = SimpleNamespace(kind='worker', fixture_root=tmp_path, shared_credentials=False)
    transport._client_input(stream, threading.Lock(), args,
                            SimpleNamespace(shutdown=shutdown.append), threading.Event())
    assert stream.getvalue() == b'' and shutdown == [socket.SHUT_RDWR]


def test_fragmented_open_still_rejects_a_foreign_destination(tmp_path):
    """Reassembly does not bypass the reference's independent URL authorization."""
    request = dict(op='file_call', method='open', args=['root://192.0.2.1:1094/private'])
    process, writes, closed, stopped = _process()
    errors = []
    transport._input(_input_frames(json.dumps(request).encode() + b'\n'), process,
                     SimpleNamespace(), tmp_path, lambda *_args: pytest.fail('foreign forward'),
                     'worker', errors)
    assert errors == ['ValueError'] and writes == [] and closed == stopped == [True]
