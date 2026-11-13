"""FUSE metadata never borrows another identity or hides a permanent denial."""

import errno
from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def metadata_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('metadata-native')
    binary = output / 'xrootdfs'
    wrapped = ['xfs_ident_get', 'brix_pool_checkout', 'brix_pool_checkin',
               'brix_backoff_sleep_fast', 'brix_mono_ns', 'brix_readlink',
               'brix_lstat', 'brix_web_stat_pooled']
    flags = ['--coverage', *['-Wl,--wrap=' + name for name in wrapped]]
    plan = client_make(root / 'client', '-n', 'xrootdfs', f'BINDIR={output}',
                       'LDFLAGS=' + ' '.join(flags), capture_output=True,
                       text=True, timeout=180)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    command[command.index('apps/fs/xrootdfs_main.o')] = str(
        root / 'tests/c/xrootdfs_metadata_native_test.c')
    command += ['-I.', '-Ilib', '-Werror']
    linked = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert linked.returncode == 0, linked.stdout + linked.stderr
    return binary


def metadata_case(binary, operation, case):
    result = subprocess.run([str(binary), operation, case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return tuple(map(int, result.stdout.split()))


@pytest.mark.parametrize('case,expected', [
    ('success', (0, 1, 1, 1, 1, 0)), ('retry', (0, 1, 2, 2, 2, 1)),
    ('checkout-retry', (0, 1, 2, 1, 1, 1)),
    ('checkout-denied', (-errno.EACCES, 1, 1, 0, 0, 0)),
    ('denied', (-errno.EACCES, 1, 1, 1, 1, 0)),
    ('identity', (-errno.EACCES, 1, 0, 0, 0, 0)),
    ('count', (-errno.EIO, 1, 3, 3, 3, 2)),
    ('timeout', (-errno.EIO, 1, 3, 3, 3, 2)),
    ('disabled', (-errno.ENOTSUP, 0, 0, 0, 0, 0)),
    ('empty', (-errno.ENOTSUP, 0, 0, 0, 0, 0)),
    ('web', (-errno.EINVAL, 0, 0, 0, 0, 0)),
])
def test_readlink_retry_budget_and_identity(metadata_binary, case, expected):
    assert metadata_case(metadata_binary, 'readlink', case) == expected


@pytest.mark.parametrize('case,expected', [
    ('success', (0, 1, 1, 1, 1, 0)), ('root', (0, 0, 0, 0, 0, 0)),
    ('writer-missing', (0, 1, 1, 1, 1, 0)),
    ('reader-missing', (-errno.ENOENT, 1, 1, 1, 1, 0)),
    ('null-missing', (-errno.ENOENT, 1, 1, 1, 1, 0)),
    ('empty-missing', (-errno.ENOENT, 1, 1, 1, 1, 0)),
    ('writer-denied', (-errno.EACCES, 1, 1, 1, 1, 0)),
    ('identity', (-errno.EACCES, 1, 0, 0, 0, 0)),
    ('web-success', (0, 0, 0, 0, 1, 0)),
    ('web-denied', (-errno.EACCES, 0, 0, 0, 1, 0)),
    ('web-missing', (-errno.ENOENT, 0, 0, 0, 1, 0)),
])
def test_staged_metadata_fallback_is_only_for_owned_writer(metadata_binary, case, expected):
    assert metadata_case(metadata_binary, 'getattr', case) == expected


def test_web_mount_mutations_never_checkout_root_connection(metadata_binary):
    assert metadata_case(metadata_binary, 'web', 'readonly') == (0, 0, 0, 0, 0, 0)
