"""Real socket-control framing and timeline scripts with finite thread cleanup."""

from contextlib import contextmanager
import json
import os
import socket
import subprocess

import pytest

from settings import BIND_HOST, HOST
from _test_brix_fault_proxy_helpers import _free_port
from test_fault_proxy_control_unit import control_unit  # noqa: F401
from test_fault_privileged_finite import command


@contextmanager
def socket_control(binary):
    port = _free_port()
    process = subprocess.Popen([str(binary), '--control-fixture', str(port)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, 'BRIX_FAULT_TEST_BIND': BIND_HOST})
    try:
        assert process.stdout.readline() == b'ready\n'
        yield process, port
    finally:
        process.stdin.close()
        try:
            status = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise
        error = process.stderr.read().decode()
        process.stdout.close()
        process.stderr.close()
        assert status == 0, error


def connect(port):
    return socket.create_connection((HOST, port), timeout=3)


def framed_session(port, splits):
    with connect(port) as peer, peer.makefile('rb') as responses:
        data = b'\r\nlatency 17 up\r\nrate 9 down\n{"cmd":"status"}\nquit\n'
        for index in range(0, len(data), splits):
            peer.sendall(data[index:index + splits])
        assert responses.readline() == b'ok\n'
        assert responses.readline() == b'ok\n'
        snapshot = json.loads(responses.readline())
        assert snapshot['up']['latency_ms'] == 17
        assert snapshot['down']['rate_kbps'] == 9
        assert responses.read() == b''


@pytest.mark.parametrize('splits', [1, 2, 5, 2048])
def test_socket_control_split_frames_and_reconnect(control_unit, splits):
    with socket_control(control_unit) as (process, port):
        framed_session(port, splits)
        with connect(port) as peer, peer.makefile('rb') as responses:
            peer.sendall(b'clear\nquit\n')
            assert responses.read() == b'ok\n'
        assert json.loads(command(process, '{"cmd":"status"}'))['up']['latency_ms'] == 0


def test_oversized_line_is_refused_and_next_connection_survives(control_unit):
    with socket_control(control_unit) as (process, port):
        with connect(port) as peer, peer.makefile('rb') as responses:
            peer.sendall(b'x' * 5000)
            peer.shutdown(socket.SHUT_WR)
            assert responses.read() == b'err: line too long\n'
        with connect(port) as peer, peer.makefile('rb') as responses:
            peer.sendall(b'status json\nquit\n')
            assert json.loads(responses.readline())['blocked'] == 0
        assert json.loads(command(process, 'status json'))['blocked'] == 0


@pytest.mark.parametrize('payload', [b'block', b'latency 9\0block\n', b'quit\nblock\n'])
def test_partial_nul_or_post_quit_data_cannot_inject_block(control_unit, payload):
    with socket_control(control_unit) as (process, port):
        with connect(port) as peer, peer.makefile('rb') as responses:
            peer.sendall(payload)
            peer.shutdown(socket.SHUT_WR)
            responses.read()
        assert json.loads(command(process, 'status json'))['blocked'] == 0


def run_script(binary, path):
    result = subprocess.run([str(binary), '--script-fixture', str(path)],
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout.endswith(b'\0')
    return json.loads(result.stdout[:-1]), result.stderr.decode()


def test_timeline_applies_ordered_commands_and_skips_invalid_lines(control_unit, tmp_path):
    path = tmp_path / 'timeline'
    path.write_text('  # comment\n\ninvalid\n\t0 latency 17 up\n'
                    '0.02 rate 9 down\n0.01 latency 3 up\n')
    status, error = run_script(control_unit, path)
    assert not error
    assert status['up']['latency_ms'] == 3
    assert status['down']['rate_kbps'] == 9


def test_missing_script_reports_error_without_changing_levers(control_unit, tmp_path):
    status, error = run_script(control_unit, tmp_path / 'missing')
    assert 'cannot open --script' in error
    assert status['up']['latency_ms'] == 0


def test_script_oracle_cannot_execute_without_opt_in(control_unit, tmp_path):
    marker = tmp_path / 'not-created'
    path = tmp_path / 'timeline'
    path.write_text(f'0 bisect latency 0 1 100 touch {marker}\n')
    status, _error = run_script(control_unit, path)
    assert not status['flags']['blocked']
    assert not marker.exists()
