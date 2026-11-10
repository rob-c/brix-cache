"""Real dynamic listeners, relay bytes and route lifecycle with finite cleanup."""

from contextlib import contextmanager
import json
import os
import socket
import subprocess
import time

import pytest

from settings import BIND_HOST, HOST

from _test_brix_fault_proxy_helpers import _free_port, _StreamEcho
from test_fault_proxy_control_unit import control_unit  # noqa: F401
from test_fault_privileged_finite import command
from test_fault_proxy_relay_unit import receive_bytes


@contextmanager
def network_driver(binary, enable_exec=False):
    options = ['--enable-exec'] if enable_exec else []
    process = subprocess.Popen([str(binary), '--network-fixture', *options, '--stdin'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, 'BRIX_FAULT_TEST_BIND': BIND_HOST})
    try:
        yield process
    finally:
        finish_network(process)


def finish_network(process):
    """Release relays, finish the consumer and verify its real exit status."""
    assert command(process, 'clear').startswith('ok')
    for row in routes(process):
        if row['name'] != 'default':
            assert command(process, 'route del ' + row['name']).startswith('ok:')
    wait_idle(process)
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


def routes(process):
    return json.loads(command(process, 'route list json'))['routes']


def wait_idle(process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if json.loads(command(process, 'status json'))['active'] == 0:
            return
        time.sleep(0.01)
    pytest.fail('route relay did not release its connection')


@pytest.fixture(scope='module')
def route_echo():
    upstream = _StreamEcho()
    yield upstream
    upstream.close()


def echo_through(port, payload):
    with socket.create_connection((HOST, port), timeout=3) as peer:
        peer.sendall(payload)
        assert receive_bytes(peer, len(payload)) == payload


def test_route_relay_restart_preserves_counters(control_unit, route_echo):
    port = _free_port()
    add = f'route add cache {port} {HOST}:{route_echo.port}'
    with network_driver(control_unit) as process:
        assert command(process, add).startswith('ok:')
        echo_through(port, b'first-transfer')
        wait_idle(process)
        first = routes(process)[1]
        assert first['conns'] == 1
        assert first['up_bytes'] == first['down_bytes'] == 14
        assert 'already exists' in command(process, add)
        assert command(process, 'route del cache').startswith('ok:')
        assert len(routes(process)) == 1
        assert command(process, add).startswith('ok:')
        echo_through(port, b'again')
        wait_idle(process)
        second = routes(process)[1]
        assert second['conns'] == 2
        assert second['up_bytes'] == second['down_bytes'] == 19
        assert 'route cache port=' in command(process, 'route list')


def test_route_fails_over_to_second_target(control_unit, route_echo):
    port, unavailable = _free_port(), _free_port()
    with network_driver(control_unit) as process:
        response = command(process, f'route add retry {port} '
                           f'{HOST}:{unavailable},{HOST}:{route_echo.port}')
        assert response.startswith('ok:')
        for payload in [b'one', b'two', b'three']:
            echo_through(port, payload)
        wait_idle(process)
        assert routes(process)[1]['conns'] == 3


@pytest.mark.parametrize('targets', ['missing-port', ':1234', 'host:',
    'host:0', 'host:65536', ',,,', ','.join(['host:1234'] * 9)])
def test_invalid_target_pool_never_creates_route(control_unit, targets):
    with network_driver(control_unit) as process:
        assert 'bad target list' in command(process,
            f'route add invalid {_free_port()} {targets}')
        assert len(routes(process)) == 1


@pytest.mark.parametrize('text', ['route add default 24002 host:1234',
    'route del default', 'route del absent', 'route del',
    'route add invalid 0 host:1234', 'route add invalid 65536 host:1234',
    'route add', 'route unknown'])
def test_reserved_or_invalid_mutations_preserve_default(control_unit, text):
    with network_driver(control_unit) as process:
        assert command(process, text).startswith('err:')
        assert [row['name'] for row in routes(process)] == ['default']


def test_bind_collision_releases_new_route_slot(control_unit, route_echo):
    with network_driver(control_unit) as process:
        refused = command(process, f'route add collision {route_echo.port} '
                          f'{HOST}:{route_echo.port}')
        assert 'cannot bind' in refused
        assert len(routes(process)) == 1
        accepted = command(process, f'route add collision {_free_port()} '
                           f'{HOST}:{route_echo.port}')
        assert accepted.startswith('ok:')


def test_route_identity_capacity_is_bounded(control_unit, route_echo):
    with network_driver(control_unit) as process:
        for index in range(15):
            assert command(process, f'route add r{index} {_free_port()} '
                           f'{HOST}:{route_echo.port}').startswith('ok:')
        assert len(routes(process)) == 16
        assert 'table full' in command(process, f'route add overflow {_free_port()} '
                                     f'{HOST}:{route_echo.port}')
