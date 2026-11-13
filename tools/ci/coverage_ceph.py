"""Run the existing native Ceph contracts against an owned disposable Docker lab.

Only the reference cluster runs in Docker. Production drivers and migration
tools compile and execute in the instrumented host build, retaining counters.
The reverse migration group starts only after the MDS journal is flushed and
the owned container's metadata daemon has stopped.
"""

import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid


def _command(arguments, **options):
    """Keep setup errors fatal and bound every native or Docker command."""
    try:
        return subprocess.run(list(map(str, arguments)), check=True,
                              capture_output=True, text=True, timeout=180, **options)
    except subprocess.CalledProcessError as error:
        from tools.logging_support import diagnostic
        diagnostic('ERROR', 'tools/ci/coverage_ceph.py', '_command',
                   error.stderr[-4096:], file=sys.stderr)
        raise


def _ceph(container, *arguments):
    """Use only the owned reference cluster, never a host's default config."""
    return _command(['docker', 'exec', container, 'ceph', *arguments]).stdout


def _environment(directory, environment):
    """Allocate private credentials and unique resources without external reuse."""
    return {**environment,
            'CEPH_CONTAINER': 'brix-coverage-ceph-' + uuid.uuid4().hex[:12],
            'CEPH_DIR': str(directory), 'CEPH_CONF': str(directory / 'ceph.conf'),
            'CEPH_KEYRING': str(directory / 'ceph.client.admin.keyring'),
            'CEPH_IMAGE': environment.get('COVERAGE_CEPH_IMAGE',
                                           'quay.io/ceph/demo:latest-reef'),
            'CEPH_DEMO_DAEMONS': 'mon,mgr,osd,mds',
            'TEST_CEPH': '1', 'TEST_CEPHFS': '1', 'TEST_CEPHFS_QUIESCED': '0',
            'CEPH_POOL': 'brix-coverage', 'CEPH_RECOVERY_POOL': 'brix-recovery',
            'CEPH_STRIPER_POOL': 'brix-striper', 'CEPH_REVERSE_POOL': 'brix-reverse',
            'CEPH_MIGRATION_ROOT': '/brix-coverage-migration',
            'CEPH_BOB_KEYRING': str(directory / 'ceph.client.bob.keyring'),
            'CEPH_READONLY_KEYRING': str(directory / 'ceph.client.readonly.keyring'),
            'CEPH_UN_KEYRING_DIR': str(directory)}


def _pools(container):
    """Make this single-OSD lab writable before any live assertion can run."""
    _ceph(container, 'config', 'set', 'global', 'mon_allow_pool_size_one', 'true')
    for name in ('brix-coverage', 'brix-recovery', 'brix-striper', 'brix-reverse'):
        _ceph(container, 'osd', 'pool', 'create', name, '8', '8')
        _ceph(container, 'osd', 'pool', 'application', 'enable', name, 'rados')
    for name in _ceph(container, 'osd', 'pool', 'ls').splitlines():
        _ceph(container, 'osd', 'pool', 'set', name, 'size', '1',
              '--yes-i-really-mean-it')
        _ceph(container, 'osd', 'pool', 'set', name, 'min_size', '1')
    _wait_clean(container)


def _wait_clean(container):
    """Require real writable placement groups within a finite startup budget."""
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        state = json.loads(_ceph(container, 'status', '--format=json'))['pgmap']
        groups = state.get('pgs_by_state', [])
        if groups and all({'active', 'clean'} <= set(row['state_name'].split('+'))
                          for row in groups):
            return
        time.sleep(2)
    raise RuntimeError('disposable Ceph placement groups did not become active and clean')


def _credentials(container, directory):
    """Use actual CephX read-only and per-user authority for denied-write tests."""
    for name in ('bob', 'readonly', *(f'u{number}' for number in range(10))):
        remote = f'/tmp/brix-coverage-{name}.keyring'
        access = 'rwx' if name == 'bob' else 'r'
        _ceph(container, 'auth', 'get-or-create', f'client.{name}',
              'mon', 'allow r', 'osd', f'allow {access} pool=brix-coverage',
              '-o', remote)
        local = directory / f'ceph.client.{name}.keyring'
        _command(['docker', 'cp', f'{container}:{remote}', local])
        local.chmod(0o600)
    keyring = directory / 'ceph.client.admin.keyring'
    keyring.chmod(0o600)
    with (directory / 'ceph.conf').open('a') as stream:
        stream.write(f'\n[client]\nkeyring = {keyring}\n')


def _require_zero(result, message):
    """Retain the public CephFS API's error code in setup failures."""
    if result != 0:
        raise RuntimeError(f'{message} ({result})')


def _migration_root(configuration):
    """Own the private CephFS migration directory as the actual test identity."""
    library = ctypes.CDLL('libcephfs.so.2')
    pointer = ctypes.c_void_p
    arguments = {'ceph_create': [ctypes.POINTER(pointer), ctypes.c_char_p],
                 'ceph_conf_read_file': [pointer, ctypes.c_char_p],
                 'ceph_mount': [pointer, ctypes.c_char_p],
                 'ceph_mkdirs': [pointer, ctypes.c_char_p, ctypes.c_uint],
                 'ceph_chown': [pointer, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint],
                 'ceph_unmount': [pointer], 'ceph_release': [pointer]}
    for name, types in arguments.items():
        getattr(library, name).argtypes = types
    mount = pointer()
    _require_zero(library.ceph_create(ctypes.byref(mount), b'admin'),
                  'could not create the private CephFS client')
    try:
        _require_zero(library.ceph_conf_read_file(mount, os.fsencode(configuration)),
                      'could not load the private CephFS configuration')
        _require_zero(library.ceph_mount(mount, b'/'),
                      'could not mount the private CephFS client')
        try:
            path = b'/brix-coverage-migration'
            _require_zero(library.ceph_mkdirs(mount, path, 0o700),
                          'could not create the private CephFS migration root')
            _require_zero(library.ceph_chown(mount, path, os.getuid(), os.getgid()),
                          'could not own the private CephFS migration root')
        finally:
            _require_zero(library.ceph_unmount(mount),
                          'could not unmount the private CephFS client')
    finally:
        library.ceph_release(mount)


def _seed(root, directory, container):
    """Reuse the existing byte/xattr/symlink fixture and flush its real metadata."""
    for name in ('cephfs_seed', 'cephfs_seed2'):
        binary = directory / name
        _command(['gcc', '-D_FILE_OFFSET_BITS=64', root / 'tests/ceph' / f'{name}.c',
                  '-lcephfs', '-o', binary])
        result = _command([binary])
        print(result.stdout, end='', flush=True)
    _migration_root(directory / 'ceph.conf')
    _ceph(container, 'tell', 'mds.*', 'flush', 'journal')


def _tests(root, names):
    """Keep all native success, error and security assertions and their verdict."""
    command = [sys.executable, '-m', 'pytest', '--noconftest', '-n0',
               '-o', 'addopts=', '-p', 'no:randomly', '-p', 'no:rerunfailures',
               '-ra', '-q', '--tb=short', *(str(root / 'tests' / name) for name in names)]
    return subprocess.run(command, cwd=root, check=False).returncode


def run(root, report):
    """Own the complete lab lifetime and retain a failed test or setup result."""
    sys.path.insert(0, str(root / 'tests'))
    from cmdscripts import ceph_harness

    directory = Path(tempfile.mkdtemp(prefix='ceph-lab-', dir=report))
    os.environ.update(_environment(directory, os.environ))
    container = os.environ['CEPH_CONTAINER']
    try:
        if ceph_harness.cmd_start() != 0:
            raise RuntimeError('could not start the disposable Ceph reference cluster')
        _pools(container)
        _credentials(container, directory)
        _seed(root, directory, container)
        result = _tests(root, ['test_ceph_native_live.py', 'test_ceph_recovery_live.py',
                              'test_ceph_migration_native.py', 'test_ceph_migrate_version.py'])
        if result:
            return result
        _ceph(container, 'tell', 'mds.*', 'flush', 'journal')
        _command(['docker', 'exec', container, 'pkill', '-TERM', '-x', 'ceph-mds'])
        _command(['docker', 'exec', container, 'sh', '-c',
                  'for attempt in $(seq 1 30); do '
                  'pgrep -x ceph-mds >/dev/null || exit 0; sleep 1; done; exit 1'])
        os.environ['TEST_CEPHFS_QUIESCED'] = '1'
        return _tests(root, ['test_ceph_reverse_migration_native.py'])
    finally:
        ceph_harness.cmd_stop()


def main():
    """Refuse accidental lab provisioning outside an enabled Linux measurement."""
    if sys.platform != 'linux' or os.environ.get('COVERAGE_CEPH') != '1':
        raise RuntimeError('live Ceph coverage requires explicit Linux opt-in')
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    return run(root, Path(os.environ['COVERAGE_OUT']))


if __name__ == '__main__':
    sys.exit(main())
