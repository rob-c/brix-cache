"""Finite real broker sessions: mapped ownership, DAC and wire framing."""

from contextlib import contextmanager
import mmap
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys

import pytest

from test_platform_linux_native import native_compile  # noqa: F401
from impersonation_gridmap_helpers import acct, provision_accounts, reap_accounts


pytestmark = [pytest.mark.privileged, pytest.mark.skipif(
    sys.platform != 'linux' or os.geteuid() != 0,
    reason='real broker credential transitions require Linux root')]


@pytest.fixture(scope='module')
def mapped_account():
    """Use the existing dedicated test-account provisioning and cleanup."""
    provision_accounts()
    try:
        yield acct('alice')
    finally:
        reap_accounts()


@pytest.fixture(scope='module')
def broker_binary(native_compile):
    """Compile the shipped broker, client, mapper and host PAL unchanged."""
    root = Path(__file__).resolve().parents[1]
    names = ('impersonate_state', 'broker', 'broker_creds', 'broker_ops',
             'broker_ops_ns', 'client', 'client_ops', 'idmap', 'idmap_gridmap',
             'idmap_denylist')
    sources = [f'src/auth/impersonate/{name}.c' for name in names]
    sources += [f'src/platform/linux/{name}.c' for name in (
        'process_wrapper', 'priv_wrapper', 'path_wrapper', 'posix_wrapper')]
    sources += ['src/fs/backend/posix/lock_store.c',
                'src/core/seccomp/seccomp_core.c']
    # Link nginx's real bounded string implementation used by the transport.
    sources.append(str(Path(os.environ['TEST_NGINX_SRC']) / 'src/core/ngx_string.c'))
    return native_compile('impersonation-finite',
        (root / 'tests/c/impersonation_finite_test.c').read_text(), sources,
        ['-lcrypt', '-lseccomp', '-ffunction-sections', '-fdata-sections',
         '-Wl,--gc-sections'])


@contextmanager
def _server(binary, directory):
    """Own the listener, export fd, stop flag and server child through shutdown."""
    export = directory / 'export'
    export.mkdir(mode=0o777)
    export.chmod(0o777)
    (export / 'private').mkdir(mode=0o700)
    (export / 'escape').symlink_to('/etc/passwd')
    endpoint = directory / 'broker.sock'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(endpoint))
        listener.listen(8)
        with (directory / 'stop').open('w+b') as stopfile:
            stopfile.write(bytes(4))
            stopfile.flush()
            with mmap.mmap(stopfile.fileno(), 4) as stop:
                with _running_broker(binary, export, listener, stopfile, stop):
                    yield str(endpoint)


@contextmanager
def _running_broker(binary, export, listener, stopfile, stop):
    """Request normal termination even when an assertion in the client fails."""
    rootfd = os.open(export, os.O_PATH | os.O_DIRECTORY)
    try:
        descriptors = (listener.fileno(), rootfd, stopfile.fileno())
        with subprocess.Popen([str(binary), 'server', *map(str, descriptors)],
                              pass_fds=descriptors, stderr=subprocess.PIPE,
                              text=True) as process:
            try:
                yield
            finally:
                stop[:] = struct.pack('=i', 1)
                _, error = _finish_server(process)
                assert process.returncode == 0, error
    finally:
        os.close(rootfd)


def _finish_server(process):
    """Bound failed shutdown and reap only the owned server process."""
    try:
        return process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise


@pytest.mark.parametrize('case', ['namespace', 'metadata', 'xattr', 'refusal'])
def test_broker_finite_contract(broker_binary, mapped_account, tmp_path, case):
    """Check observable production results and a clean server shutdown."""
    with _server(broker_binary, tmp_path) as endpoint:
        result = subprocess.run([str(broker_binary), case, endpoint],
                                capture_output=True, text=True, timeout=15,
                                env={**os.environ, 'BRIX_FINITE_ACCOUNT': mapped_account})
        assert result.returncode == 0, result.stdout + result.stderr
