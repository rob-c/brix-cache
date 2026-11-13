"""Per-uid transport ownership, failure caching, and publication under contention."""

from collections import Counter
import os
from pathlib import Path
import pwd
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = [pytest.mark.serial,
              pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')]


@pytest.fixture(scope='module')
def identity_binary(tmp_path_factory):
    """Reuse the complete configured FUSE link closure with a private test main."""
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('identity-native')
    binary = output / 'xrootdfs'
    wrapped = ['brix_pool_create', 'brix_pool_destroy', 'brix_mgr_create',
               'brix_mgr_destroy', 'calloc']
    flags = ['--coverage', *['-Wl,--wrap=' + name for name in wrapped]]
    result = client_make(root / 'client', '-n', 'xrootdfs', f'BINDIR={output}',
                        'LDFLAGS=' + ' '.join(flags), capture_output=True,
                        text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    command = private_link_command(result.stdout, binary)
    driver = root / 'tests/c/xrootdfs_identity_native_test.c'
    command[command.index('apps/fs/xrootdfs_main.o')] = str(driver)
    command += ['-I.', '-Ilib', '-Werror']
    linked = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert linked.returncode == 0, linked.stdout + linked.stderr
    return binary


def identity_case(binary, mode, **switches):
    """Require the native assertions and return observable factory events."""
    environment = {**os.environ, **{'BRIX_IDENTITY_' + key: value
                                   for key, value in switches.items()}}
    result = subprocess.run([str(binary), mode], env=environment,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    return Counter(result.stdout.splitlines())


def test_disabled_identity_preserves_mount_connections(identity_binary):
    assert not identity_case(identity_binary, 'disabled')


def test_capacity_and_unknown_user_never_share_identity(identity_binary):
    events = identity_case(identity_binary, 'capacity')
    for name in [pwd.getpwuid(0).pw_name, '4294967294']:
        assert events['pool ' + name + ' 3'] == 1
        assert events['manager ' + name + ' 2'] == 1
        assert events['destroy-manager ' + name] == 1
        assert events['destroy-pool ' + name] == 1


@pytest.mark.parametrize('failure', ['POOL_FAIL', 'MANAGER_FAIL'])
def test_creation_failure_stays_with_its_uid(identity_binary, failure):
    events = identity_case(identity_binary, 'failed', **{failure: '1'})
    owner = pwd.getpwuid(0).pw_name
    assert events['pool ' + owner + ' 3'] == 1
    assert events['destroy-manager ' + owner] == 0
    assert events['destroy-pool ' + owner] == (failure == 'MANAGER_FAIL')
    assert events['manager 4294967294 2'] == 1
    assert events['destroy-manager 4294967294'] == 1
    assert events['destroy-pool 4294967294'] == 1


def test_concurrent_same_uid_publishes_exactly_once(identity_binary):
    events = identity_case(identity_binary, 'concurrent')
    owner = pwd.getpwuid(0).pw_name
    assert events['pool ' + owner + ' 3'] == 1
    assert events['manager ' + owner + ' 2'] == 1
    assert events['destroy-manager ' + owner] == 1
    assert events['destroy-pool ' + owner] == 1


@pytest.mark.parametrize('failure', ['POOL_FAIL', 'MANAGER_FAIL'])
def test_concurrent_failure_refuses_every_waiter(identity_binary, failure):
    events = identity_case(identity_binary, 'concurrent-failed', **{failure: '1'})
    owner = pwd.getpwuid(0).pw_name
    assert events['pool ' + owner + ' 3'] == 1
    assert events['destroy-manager ' + owner] == 0
    assert events['destroy-pool ' + owner] == (failure == 'MANAGER_FAIL')


@pytest.mark.parametrize('mode', ['low-limit', 'high-limit'])
def test_identity_capacity_is_bounded(identity_binary, mode):
    assert identity_case(identity_binary, mode) == {'identity-contract-ok': 1}


def test_allocation_failure_can_be_retried_before_serving(identity_binary):
    events = identity_case(identity_binary, 'allocation', INIT_FAIL='1')
    assert events == {'identity-contract-ok': 1}
