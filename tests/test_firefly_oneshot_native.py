"""Short-lived transfers emit paired SciTags reports with bounded metadata."""

from contextlib import ExitStack
import json
import socket
import subprocess

import pytest

from settings import HOST, HOST6
from ephemeral_port import free_port

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def firefly_oneshot(server_native_compile):
    return server_native_compile('firefly-oneshot', 'tests/c/firefly_oneshot_native_test.c')


def connected_sockets(stack, family):
    """Keep both TCP endpoints and a bound UDP receiver alive across exec."""
    host = HOST if family == socket.AF_INET else HOST6
    listener = stack.enter_context(socket.socket(family, socket.SOCK_STREAM))
    listener.bind((host, free_port(host))); listener.listen(1)
    client = stack.enter_context(socket.socket(family, socket.SOCK_STREAM))
    client.connect(listener.getsockname())
    server = stack.enter_context(listener.accept()[0])
    collector = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
    collector.bind((host, free_port(host))); collector.settimeout(0.1)
    return client, server, collector


def invoke(binary, mode, direction, app, family):
    with ExitStack() as stack:
        client, server, collector = connected_sockets(stack, family)
        result = subprocess.run([str(binary), mode, str(server.fileno()),
            str(collector.fileno()), str(direction), app],
            pass_fds=(server.fileno(), collector.fileno()), capture_output=True,
            text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        documents = []
        while True:
            try:
                wire = collector.recv(8192).decode()
            except TimeoutError:
                break
            assert wire.startswith('<134>1 - fixture xrootd - firefly-json - ')
            documents.append(json.loads(wire[wire.index('{'):]))
        return documents, client.getsockname(), server.getsockname()


def expected_fields(peer, local, direction, family, app):
    """Describe supplier orientation and the bounded application independently."""
    source, destination = (peer, local) if direction else (local, peer)
    expected_app = '' if app == '<null>' else app[:31]
    address_family = {socket.AF_INET: 'ipv4', socket.AF_INET6: 'ipv6'}[family]
    return ({'experiment-id': 17, 'activity-id': 3, 'application': expected_app},
            {'afi': address_family, 'src-ip': source[0], 'dst-ip': destination[0],
             'protocol': 'tcp', 'src-port': source[1], 'dst-port': destination[1]})


@pytest.mark.parametrize('family', [socket.AF_INET, socket.AF_INET6])
@pytest.mark.parametrize('direction', [0, 1])
@pytest.mark.parametrize('app', ['copy', '', '<null>', 'a' * 512])
def test_report_pair_preserves_direction_and_bounds_application(firefly_oneshot, family, direction, app):
    documents, peer, local = invoke(firefly_oneshot, 'normal', direction, app, family)
    assert [item['flow-lifecycle']['state'] for item in documents] == ['start', 'end']
    assert 'end-time' not in documents[0]['flow-lifecycle']
    assert 'end-time' in documents[1]['flow-lifecycle']
    context, flow = expected_fields(peer, local, direction, family, app)
    for item in documents:
        assert item['context'] == context
        assert item['flow-id'] == flow


@pytest.mark.parametrize('mode', ['disabled', 'negative-fd', 'null-conf', 'bad-family',
                                 'bad-address', 'no-collector'])
def test_disabled_or_invalid_report_destination_cannot_emit(firefly_oneshot, mode):
    documents, _, _ = invoke(firefly_oneshot, mode, 0, 'copy', socket.AF_INET)
    assert documents == []
