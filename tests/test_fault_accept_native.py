"""Fault proxy admission owns descriptors and rolls back failed worker gauges."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def acceptance(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('fault-accept')
    binary = output / 'brix-fault-proxy'
    plan = client_make(root / 'client', '-n', 'brix-fault-proxy', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout.replace('\\\n', ' '), binary)
    command += ['-Dmain=brix_fault_unused_main', str(root / 'tests/c/fault_accept_native_test.c')]
    command += ['-Wl,--wrap=' + name for name in ('malloc', 'calloc', 'fp_route_alive',
        'poll', 'accept', 'usleep', 'pthread_create', 'pthread_detach', 'listen_sa',
        'fp_priv_enable', 'fp_priv_teardown')]
    if '--coverage' in command:
        command.append('-O0')
    built = client_run(root / 'client', command, cwd=root / 'client',
                       capture_output=True, text=True, timeout=120)
    assert built.returncode == 0, built.stdout + built.stderr
    return binary


def invoke(binary, operation, mode):
    result = subprocess.run([str(binary), operation, mode], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout.splitlines()[-1])


@pytest.mark.parametrize('mode', ['normal', 'pause', 'poll-timeout', 'poll-interrupted'])
def test_admitted_socket_moves_to_exactly_one_worker(acceptance, mode):
    body = invoke(acceptance, 'admission', mode)
    assert body == dict(open=0, active=0, conns=1, refused=0, syn=0,
                       creates=1, detached=1, relays=1, sleeps=2 * (mode == 'pause'))


@pytest.mark.parametrize('mode', ['blocked', 'refused', 'seeded', 'syn-dropped', 'capped'])
def test_refused_socket_cannot_start_a_worker_or_leak_a_slot(acceptance, mode):
    body = invoke(acceptance, 'admission', mode)
    assert body == dict(open=0, active=int(mode == 'capped'), conns=0,
        refused=int(mode != 'syn-dropped'), syn=int(mode == 'syn-dropped'),
        creates=0, detached=0, relays=0, sleeps=0)


@pytest.mark.parametrize('mode,conns', [('allocation-error', 0), ('create-error', 1)])
def test_resource_failure_closes_fd_and_restores_active_gauge(acceptance, mode, conns):
    body = invoke(acceptance, 'admission', mode)
    assert body == dict(open=0, active=0, conns=conns, refused=0, syn=0,
                       creates=conns, detached=0, relays=0, sleeps=0)


@pytest.mark.parametrize('mode', ['accept-error', 'accept-interrupted'])
def test_accept_failure_never_transfers_unaccepted_descriptor(acceptance, mode):
    body = invoke(acceptance, 'admission', mode)
    assert body == dict(open=1, active=0, conns=0, refused=0, syn=0,
                       creates=0, detached=0, relays=0, sleeps=0)


@pytest.mark.parametrize('mode,created,detached', [('normal', 3, 2), ('quiet', 3, 2),
    ('bad-udp', 2, 1), ('udp-allocation-error', 2, 1), ('startup-create-error', 3, 0)])
def test_optional_jobs_preserve_exact_configuration_and_failure_is_best_effort(acceptance, mode, created, detached):
    body = invoke(acceptance, 'startup', mode)
    assert body == dict(rc=0, creates=created, detached=detached, listens=2, priv=0)


@pytest.mark.parametrize('mode,rc,listens,priv', [('unsafe-bind', 2, 0, 0),
    ('event-error', 1, 0, 0), ('listen-error', 1, 2, 0),
    ('priv-without-enable', 2, 0, 0), ('priv-error', 2, 0, 1)])
def test_failed_startup_does_not_spawn_workers(acceptance, mode, rc, listens, priv):
    body = invoke(acceptance, 'startup', mode)
    assert body == dict(rc=rc, creates=0, detached=0, listens=listens, priv=priv)


def test_privileged_setup_receives_only_selected_ports(acceptance):
    body = invoke(acceptance, 'startup', 'priv-success')
    assert body == dict(rc=0, creates=1, detached=0, listens=2, priv=1)
