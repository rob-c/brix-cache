"""EOS manager discovery keeps authenticated enumeration bounded and cleans up failures."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping and object instrumentation')


def private_diag_entry(root, output):
    """Preserve the CLI's report helpers while replacing only its main symbol."""
    entry = output / 'xrddiag-entry.o'
    result = client_run(root / 'client', ['objcopy', '--redefine-sym',
        'main=brix_test_diag_main', 'apps/diag/xrddiag.o', str(entry)],
        cwd=root / 'client', capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return entry


@pytest.fixture(scope='module')
def eos_probe(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('eos-discovery'); binary = output / 'xrddiag'
    plan = client_make(root / 'client', '-n', 'xrddiag', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    index = command.index('apps/diag/xrddiag.o')
    command[index:index + 1] = [str(private_diag_entry(root, output)),
                               str(root / 'tests/c/eos_discovery_native_test.c')]
    command += ['-I.', *['-Wl,--wrap=' + name for name in ('realloc', 'brix_connect',
        'brix_close', 'brix_file_open_opaque', 'brix_file_read', 'brix_file_close',
        'doctor_eos_discover_fileinfo')]]
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def invoke(binary, mode='normal', capacity=4, operation='map', version=None, admin=None):
    version = version if version is not None else 'mgm.proc.stdout=EOS_INSTANCE=fixture EOS_SERVER_VERSION=1&mgm.proc.retc=0'
    admin = admin if admin is not None else 'mgm.proc.stdout=host=first.invalid\nhostport=second.invalid:2048\n&mgm.proc.retc=0'
    env = dict(os.environ, BRIX_EOS_MODE=mode, BRIX_EOS_VERSION=version, BRIX_EOS_ADMIN=admin)
    result = subprocess.run([str(binary), operation, str(capacity)], env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.splitlines()


@pytest.mark.parametrize('capacity,count,truncated', [(2, 2, 1), (3, 3, 1), (4, 3, 0)])
@pytest.mark.parametrize('mode', ['normal', 'custom-timeout'])
def test_admin_inventory_replaces_self_node_with_bounded_farm(eos_probe, capacity, count, truncated, mode):
    output = invoke(eos_probe, mode, capacity)
    assert output[0] == f'truncated={truncated} count={count} fst={count - 1} gated=0 sampled=0'
    assert json.loads(output[1])['eos']['instance'] == 'fixture'


@pytest.mark.parametrize('mode', ['admin-denied', 'normal'])
@pytest.mark.parametrize('capacity', [2, 4])
def test_denied_or_failed_admin_command_uses_bounded_unprivileged_sample(eos_probe, mode, capacity):
    output = invoke(eos_probe, mode, capacity, admin='mgm.proc.retc=13')
    expected = {2: 'truncated=1 count=2 fst=1 gated=1 sampled=1',
                4: 'truncated=0 count=3 fst=2 gated=1 sampled=1'}
    assert output[0] == expected[capacity]


def test_empty_sample_does_not_claim_complete_inventory(eos_probe):
    output = invoke(eos_probe, 'sample-empty')
    assert output[0] == 'truncated=0 count=2 fst=0 gated=1 sampled=0'
    assert json.loads(output[1])['eos']['gated'] is True


@pytest.mark.parametrize('mode', ['disabled', 'bad-url', 'connect-error',
    'open-error', 'read-error', 'allocation-error'])
def test_failed_or_disabled_discovery_keeps_existing_mesh(eos_probe, mode):
    output = invoke(eos_probe, mode)
    assert output[0] == 'truncated=0 count=2 fst=0 gated=0 sampled=0'
    assert 'eos' not in json.loads(output[1])


@pytest.mark.parametrize('version', ['', 'not-eos', 'mgm.proc.stdout=&mgm.proc.retc=0',
                                   'mgm.proc.stdout=OTHER=service&mgm.proc.retc=0'])
def test_non_eos_service_is_not_misclassified(eos_probe, version):
    assert 'eos' not in json.loads(invoke(eos_probe, version=version)[1])


@pytest.mark.parametrize('admin', ['mgm.proc.retc=0', 'mgm.proc.stdout=&mgm.proc.retc=0'])
def test_empty_or_missing_admin_envelope_does_not_invent_nodes(eos_probe, admin):
    output = invoke(eos_probe, admin=admin)
    assert json.loads(output[1])['eos']['fst_count'] == 0


@pytest.mark.parametrize('mode,expected', [('large-body', '0 200000'),
    ('open-error', '-1 0'), ('read-error', '-1 0'), ('allocation-error', '-1 0')])
def test_proc_grow_read_handles_large_reply_and_closes_every_failure(eos_probe, mode, expected):
    assert invoke(eos_probe, mode, operation='proc') == [expected]
