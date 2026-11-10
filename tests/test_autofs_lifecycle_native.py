"""Automount lifecycle ownership without host mounts or child processes."""

from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def autofs_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('autofs-lifecycle')
    binary = output / 'brixMount'
    plan = client_make(root / 'client', '-n', 'brixMount', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    command[command.index('apps/fs/brixmount.o')] = str(root / 'tests/c/autofs_lifecycle_native_test.c')
    command += ['-I.', '-I/usr/include/fuse3']
    wrappers = ['fuse_new', 'fuse_mount', 'fuse_daemonize', 'fuse_unmount', 'fuse_destroy',
                'fuse_exit', 'fuse_loop_mt_31', 'pipe', 'pthread_create', 'pthread_join',
                'af_umount_path', 'af_is_mounted', 'brix_plat_umount_expire',
                'waitpid', 'kill', 'nanosleep']
    command += ['-Wl,--wrap=' + name for name in wrappers]
    linked = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert linked.returncode == 0, linked.stdout + linked.stderr
    return binary


@pytest.fixture
def automount(autofs_binary, tmp_path):
    etc = tmp_path / 'etc'
    config = etc / 'config.d'
    config.mkdir(parents=True)
    (config / 'repo.example.conf').write_text('')
    (config / 'invalid.conf').write_text('')
    (config / 'ignored.txt').write_text('')
    mount = tmp_path / 'umbrella'
    farm = tmp_path / 'farm'
    def invoke(mode='', options='', strict='no', repositories='repo.example', idle=0):
        (etc / 'default.conf').write_text(
            f'CVMFS_STRICT_MOUNT={strict}\nCVMFS_REPOSITORIES={repositories}\n')
        result = subprocess.run([str(autofs_binary), mode, 'autofs', str(etc), str(mount) + '/',
            '-f', '-o', f'mntbase={farm},idle={idle},timeout=7', '-o' + options],
            capture_output=True, text=True, timeout=10)
        return result
    return invoke


@pytest.mark.parametrize('mode,counts', [
    ('new', 'mounts=0 unmounts=0 destroys=0 joins=0'),
    ('mount', 'mounts=1 unmounts=0 destroys=1 joins=0'),
    ('daemon', 'mounts=1 unmounts=1 destroys=1 joins=0'),
    ('pipe', 'mounts=1 unmounts=1 destroys=1 joins=0'),
    ('controller', 'mounts=1 unmounts=1 destroys=1 joins=0'),
    ('loop', 'mounts=1 unmounts=1 destroys=1 joins=1'),
])
def test_startup_and_loop_errors_release_owned_resources(automount, mode, counts):
    result = automount(mode)
    assert result.returncode == 1, result.stdout + result.stderr
    assert counts in result.stdout


@pytest.mark.parametrize('mode', ['', 'reap', 'reap-unmounted', 'terminate', 'hung-child'])
def test_shutdown_releases_children_threads_and_both_pipe_ends(automount, mode):
    result = automount(mode)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'destroys=1 joins=1' in result.stdout
    if mode == 'hung-child':
        assert 'kills=1' in result.stdout


@pytest.mark.parametrize('mode', ['idle-thread', 'expire', 'expire-denied'])
def test_idle_expiry_failure_and_success_preserve_teardown(automount, mode):
    result = automount(mode, idle=1)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'destroys=1' in result.stdout
    if mode == 'idle-thread':
        assert 'cannot start idle expiry' in result.stderr
    else:
        assert 'expires=1' in result.stdout


@pytest.mark.parametrize('strict', ['yes', 'on', '1'])
def test_repository_config_and_fuse_options_keep_their_boundaries(automount, strict):
    result = automount('new', strict=strict,
                       options='repos=other.example,allow_other,ro,default_permissions')
    assert result.returncode == 1
    assert 'strict=1 repos=other.example ghosts=1 timeout=7 idle=0' in result.stdout
    assert 'subtype=cvmfs,allow_other,ro,default_permissions' in result.stdout


def test_strict_empty_repository_list_warns_before_serving(automount):
    result = automount('new', strict='yes', repositories='')
    assert result.returncode == 1
    assert 'every mount will be refused' in result.stderr
