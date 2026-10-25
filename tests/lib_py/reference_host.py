"""Reference-fixture policy and bounded observations; never changes BriX auth."""
import os
import sys
import ipaddress
import uuid
import json
import hashlib
import base64
import subprocess
import stat
from types import SimpleNamespace
from pathlib import Path
from contextlib import contextmanager


def _fixture_route(path, variable):
    """Only explicitly selected shared paths may use an oracle-side operation."""
    selected = os.environ.get(variable)
    if selected is None:
        return None
    root = Path(os.environ['TEST_REFERENCE_SHARED_ROOT'])
    # BriX's independent native export must keep its native inspection path.
    if not Path(path).is_relative_to(root):
        return None
    from brix_suite.clients.xrdcl.worker_link import _validate_remote_command

    command = json.loads(selected)
    _validate_remote_command(command)
    return command


def _fixture_result(command, arguments):
    """Bound and validate the result; a selected route never falls back silently."""
    result = subprocess.run([*command, *arguments], capture_output=True,
                            timeout=15, check=True)
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError('remote fixture metadata exceeds 2 MiB')
    values = json.loads(result.stdout)
    if not isinstance(values, dict) or len(values) > 1024:
        raise ValueError('invalid remote fixture metadata')
    return values


def reference_disk_xattrs(path):
    """Read oracle-owned metadata remotely only in the explicit shared-fixture lane."""
    command = _fixture_route(path, 'TEST_REFERENCE_FIXTURE_COMMAND')
    if command is None:
        return None
    values = _fixture_result(command, [str(path)])
    return {name: base64.b64decode(value, validate=True)
            for name, value in values.items()}


def reference_disk_stat(path):
    """Use real backing metadata, retaining ordinary native stat outside the lab."""
    command = _fixture_route(path, 'TEST_REFERENCE_FIXTURE_COMMAND')
    if command is None:
        return os.stat(path)
    values = _fixture_result(command, ['stat', str(path)])
    if set(values) != {'st_mode', 'st_size', 'st_blocks'} or not all(
            type(value) is int and 0 <= value < 2**63 for value in values.values()):
        raise ValueError('invalid remote fixture stat fields')
    return SimpleNamespace(**values)


def reference_mkfifo(path, mode):
    """Create reference FIFOs natively when SFTP cannot represent that operation."""
    command = _fixture_route(path, 'TEST_REFERENCE_FIFO_COMMAND')
    if command is None:
        os.mkfifo(path, mode)
        return
    result = _fixture_result(command, [str(path), str(mode)])
    if set(result) != {'created'} or result['created'] is not True:
        raise ValueError('reference FIFO creation did not confirm success')


def assert_backing_size_parity(pair, path, ours, reference):
    """Equal file sizes; differing directory sizes must match each actual FS."""
    assert ours is not None and reference is not None, f'missing stat size: {path}'
    relative = Path(path.lstrip('/'))
    if '..' in relative.parts:
        raise ValueError('backing size observation requires a confined fixture path')
    if int(ours) == int(reference):
        return
    for key, reported in (('our_data', ours), ('off_data', reference)):
        info = reference_disk_stat(Path(pair[key]) / relative)
        assert stat.S_ISDIR(info.st_mode), f'file size divergence: {path}: {ours} != {reference}'
        assert int(reported) == info.st_size, (
            f'{key} directory {path}: wire size {reported} != backing size {info.st_size}')


def reference_platform():
    """Use pinned actual oracle provenance, never the test runner's guessed OS."""
    selected = os.environ.get('TEST_REFERENCE_PROVENANCE')
    if selected is None:
        return sys.platform
    path = Path(selected)
    if path.stat().st_size > 65536:
        raise ValueError('reference provenance exceeds 64 KiB')
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != os.environ.get('TEST_REFERENCE_PROVENANCE_SHA256'):
        raise ValueError('reference provenance digest mismatch')
    record = json.loads(content)
    return {'Darwin': 'darwin', 'Linux': 'linux', 'FreeBSD': 'freebsd'}[record['system']]


def reference_brix_data_root(path, shared_root):
    """Keep BriX on native storage while only the external oracle uses NFS.

    Opt-in lab mapping preserves each fixture's relative namespace. Native
    filesystem features must not become NFS false failures in the remote lane.
    Ordinary native runs retain their exact existing paths.
    """
    selected = os.environ.get('TEST_REFERENCE_BRIX_DATA_ROOT')
    if selected is None:
        return path
    base = Path(selected)
    scope = Path(os.environ.get('TEST_REFERENCE_SHARED_ROOT', shared_root))
    _native_export_identity(base, scope)
    Path(path).resolve().relative_to(Path(shared_root).resolve(strict=True))
    relative = Path(path).resolve().relative_to(scope.resolve(strict=True))
    result = base / relative
    result.resolve().relative_to(base.resolve(strict=True))
    return str(result)


def _native_export_identity(base, shared_root):
    """A private marker binds one fresh native export root to this exact lab."""
    if not base.is_absolute() or base.is_symlink():
        raise ValueError('native reference export must be an absolute plain directory')
    info = base.stat()
    if not base.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('native reference export must be owner-private')
    _native_export_marker(base, shared_root)


def _native_export_marker(base, shared_root):
    """A marker for another run cannot repurpose an existing private directory."""
    marker = base / '.brix-reference-native-export.json'
    if marker.is_symlink() or marker.stat().st_size > 4096:
        raise ValueError('invalid native reference export marker')
    record = json.loads(marker.read_text())
    if record != dict(schema_version=1, shared_root=str(Path(shared_root).resolve(strict=True))):
        raise ValueError('native reference export belongs to another fixture lane')


def reference_listener_args(host):
    """Match a numeric fixture endpoint without resolving names at import time."""
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return []
    return ["-I", f"v{address.version}"]


def reference_listener_ready(process, host, port, timeout):
    """An installed dependency needs both its owned process and TCP listener."""
    from lib_py.util import wait_tcp

    if process.poll() is not None:
        return False
    return wait_tcp(host, port, timeout=timeout) and process.poll() is None


def _reference_transport_options(host, disable_async):
    """Preserve explicit async-disable while applying only the host workaround."""
    options = ['off'] if disable_async else []
    if host.startswith('freebsd'):
        options.append('nosf')
    return options


def reference_transport_directives(host=None, *, disable_async=False):
    """Keep the FreeBSD package's broken sendfile path out of protocol oracles.

    The installed native daemon disconnects large reads with 'sendfile failure';
    its configured buffered path passes the same byte-exact transfer. This is a
    reference-package workaround, not evidence that its offload was certified.
    """
    selected = sys.platform if host is None else host
    options = _reference_transport_options(selected, disable_async)
    return 'xrootd.async ' + ' '.join(options) + '\n' if options else ''


def fixture_read_bytes(path, *, limit=128 * 1024 * 1024):
    """Fail on oversized or changing fixtures before allocating unbounded data.

    A broken native reference can turn a small write into a petabyte sparse
    file. That remains a test failure, not permission to exhaust the VM while
    collecting evidence. These byte-comparison corpora fit within 128 MiB.
    """
    with open(path, 'rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        if not 0 <= size <= limit:
            raise AssertionError(f'fixture size {size} exceeds read budget {limit}: {path}')
        content = stream.read(size + 1)
        assert len(content) == size, f'fixture changed during bounded read: {path}'
        return content


def reference_read_bytes(stream, expected_size, *, limit=128 * 1024 * 1024):
    """Read a known-size reference fixture without trusting its reported extent.

    Both a malformed write offset and a corrupt stat response remain failures.
    The extra byte detects growth, including an originally empty fixture, while
    every request stays bounded by the caller's independent expected size.
    The caller owns opening and closing the reference handle.
    """
    if not 0 <= expected_size <= limit:
        raise AssertionError('expected fixture size exceeds read budget')
    status, info = stream.stat()
    assert status.ok, f'fixture stat failed: {status.message}'
    assert info.size == expected_size, (
        f'fixture size {info.size} differs from expected {expected_size}')
    status, content = stream.read(offset=0, size=expected_size + 1)
    assert status.ok, f'fixture read failed: {status.message}'
    assert len(content) == expected_size, 'fixture changed during bounded reference read'
    return content


@contextmanager
def reference_write_target(filesystem):
    """Retire exactly one private remote name, even if its writer fails.

    Cleanup uses the same selected endpoint rather than assuming that the
    fixture's export is mounted locally. Only the wire's path-not-found error
    (3011) is harmless; a refused or failed cleanup remains visible.
    """
    name = 'aio-write-' + uuid.uuid4().hex + '.bin'
    try:
        yield name
    finally:
        status, _ = filesystem.rm('/' + name, timeout=5)
        assert status.ok or status.errno == 3011, (
            f'private reference fixture cleanup failed: {status.message}')
