"""Finite real UDP relay tests preserve production counters after worker join."""

from contextlib import contextmanager
import json
import os
import socket
import subprocess
import time

import pytest

from settings import BIND_HOST, HOST
from ephemeral_port import free_port

from test_fault_proxy_control_unit import control_unit  # noqa: F401
from test_fault_proxy_udp import _UdpEcho
from test_fault_privileged_finite import command


@contextmanager
def udp_driver(binary, host, port):
    listen = free_port(BIND_HOST)
    process = subprocess.Popen([str(binary), '--udp-fixture', str(listen), host,
                                str(port)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={**os.environ, 'BRIX_FAULT_TEST_BIND': BIND_HOST})
    try:
        assert json.loads(command(process, 'status json'))['udp_in'] == 0
        yield process, listen
    finally:
        process.stdin.close()
        try:
            status = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise
        errors = process.stderr.read().decode()
        process.stdout.close()
        process.stderr.close()
        assert status == 0, errors


@pytest.fixture(scope='module')
def udp_echo():
    echo = _UdpEcho()
    yield echo
    echo.close()


@contextmanager
def udp_client(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        sock.connect((HOST, port))
        yield sock


def relay(sock, data=b'datagram'):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        sock.send(data)
        try:
            assert sock.recv(65536) == data
            return
        except (TimeoutError, ConnectionRefusedError):
            time.sleep(0.02)
    pytest.fail('UDP listener did not echo the datagram')


def wait_counter(process, name, minimum):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status = json.loads(command(process, 'status json'))
        if status[name] >= minimum:
            return status
        time.sleep(0.01)
    pytest.fail(f'UDP counter {name} did not reach {minimum}')


@pytest.mark.parametrize('size', [1, 64, 1400, 60000])
def test_udp_datagram_boundaries_and_existing_flow(control_unit, udp_echo, size):
    with udp_driver(control_unit, HOST, udp_echo.port) as (process, port):
        with udp_client(port) as sock:
            relay(sock, b'a' * size)
            relay(sock, b'b' * size)
        status = wait_counter(process, 'udp_out', 2)
        assert status['udp_dropped'] == 0


def test_udp_drop_clear_and_idle_flow_reaping(control_unit, udp_echo):
    with udp_driver(control_unit, HOST, udp_echo.port) as (process, port):
        with udp_client(port) as sock:
            relay(sock)
            assert command(process, 'udp-drop 1000000') == 'ok\n'
            sock.send(b'must-drop')
            with pytest.raises(TimeoutError):
                sock.recv(1024)
            assert wait_counter(process, 'udp_dropped', 1)['udp_out'] == 1
            assert command(process, 'clear') == 'ok\n'
            relay(sock, b'recovered')
            assert command(process, 'udp-reap 10') == 'ok\n'
            wait_counter(process, 'udp_reaped', 1)
            relay(sock, b'new-flow')


@pytest.mark.parametrize('setting,delay', [('udp-hold-until-tcp 50', 0.04),
                                         ('udp-reorder 1000000 30', 0.05)])
def test_udp_timing_levers_delay_real_datagrams(control_unit, udp_echo, setting, delay):
    with udp_driver(control_unit, HOST, udp_echo.port) as (process, port):
        with udp_client(port) as sock:
            assert command(process, setting) == 'ok\n'
            started = time.monotonic()
            relay(sock)
            assert time.monotonic() - started >= delay
            assert command(process, 'clear') == 'ok\n'
            relay(sock, b'after-clear')


def test_invalid_upstream_never_echoes_untrusted_bytes(control_unit):
    with udp_driver(control_unit, '256.256.256.256', 9) as (process, port):
        with udp_client(port) as sock:
            time.sleep(0.05)
            sock.send(b'cannot-resolve')
            with pytest.raises(TimeoutError):
                sock.recv(1024)
        status = wait_counter(process, 'udp_in', 1)
        assert status['udp_out'] == 0
