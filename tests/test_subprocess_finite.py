"""Real bounded helper processes cover success, setup failure and isolation."""

import errno
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from cmdscripts.compile_run import PLATFORM_HOST_FLAGS, pal_host_sources

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU syscall wrapping')


def process_sources(root):
    """Keep the existing subprocess PAL closure explicit and shared."""
    sources = ['tests/c/subprocess_finite_test.c', 'src/core/compat/subprocess.c',
               *pal_host_sources('storage_wrapper', 'process_wrapper')]
    return [str(root / source) for source in sources]


def process_link_flags():
    """Wrap syscall boundaries; force the optional gcov dump only in coverage."""
    flags = ['-Wl,--wrap=' + name for name in
             ('_exit', 'execvp', 'fork', 'pipe2', 'socketpair')]
    if os.environ.get('BRIX_COVERAGE_COUNTERS'):
        flags.extend(['-Wl,-u,__gcov_dump', '-Wl,-u,__gcov_reset'])
    return flags


@pytest.fixture(scope='module')
def finite_process(tmp_path_factory):
    """Use the production helper and PAL, retaining child counters in coverage runs."""
    compiler = shutil.which('gcc')
    if compiler is None:
        pytest.skip('GCC is required for the finite subprocess consumer')
    root = Path(__file__).resolve().parents[1]
    binary = tmp_path_factory.mktemp('finite-process') / 'probe'
    result = subprocess.run([compiler, '-O1', '-g', '-Wall', '-Wextra', '-Werror',
        '-pthread', *PLATFORM_HOST_FLAGS, '-I' + str(root / 'src'),
        *process_sources(root), *process_link_flags(), '-o', str(binary)],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def run_helper(binary, mode, program):
    result = subprocess.run([str(binary), mode, sys.executable, program],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    rc, status, error, length, encoded = result.stdout.strip().split(':')
    payload = bytes.fromhex(encoded)
    assert len(payload) == int(length)
    return int(rc), int(status), int(error), payload


@pytest.mark.parametrize('program,status,payload', [
    ('print("hello", end="")', 0, b'hello'),
    ('import sys; print("failure", end=""); sys.exit(17)', 17, b'failure'),
    ('print("x" * 200, end="")', 0, b'x' * 15),
    ('pass', 0, b''),
])
def test_child_bytes_and_exit_status_are_independent(finite_process, program,
                                                    status, payload):
    rc, actual, _error, data = run_helper(finite_process, 'capture', program)
    assert (rc, actual, data) == (0, status, payload)


@pytest.mark.parametrize('mode', ['fork-1', 'fork-2', 'fork-3',
                                  'pipe-failure', 'socket-failure', 'invalid'])
def test_setup_failure_never_fabricates_success(finite_process, mode):
    rc, status, _error, payload = run_helper(finite_process, mode, 'raise SystemExit(0)')
    assert (rc, status, payload) == (-1, -1, b'')


def test_command_not_found_has_real_127_status(finite_process):
    rc, status, _error, payload = run_helper(finite_process, 'missing', 'pass')
    assert (rc, status, payload) == (0, 127, b'')


def test_signalled_child_is_an_error(finite_process):
    code = 'import os, signal; os.kill(os.getpid(), signal.SIGKILL)'
    rc, status, _error, payload = run_helper(finite_process, 'capture', code)
    assert (rc, status, payload) == (-1, -1, b'')


def test_deadline_kills_helper_process_group(finite_process):
    code = ('import subprocess, time; child = subprocess.Popen(["sleep", "10"]); '
            'print(child.pid, flush=True); time.sleep(10)')
    rc, status, error, payload = run_helper(finite_process, 'timeout', code)
    assert (rc, status, error) == (-1, -1, errno.ETIMEDOUT)
    child = Path('/proc') / str(int(payload)) / 'stat'
    assert not child.exists() or child.read_text().split(') ', 1)[1].startswith('Z ')


@pytest.mark.parametrize('mode', ['capture', 'inherit'])
def test_operator_helper_never_inherits_parent_socket(finite_process, mode):
    code = 'import os; assert not os.path.exists("/proc/self/fd/400")'
    rc, status, _error, payload = run_helper(finite_process, mode, code)
    assert (rc, status, payload) == (0, 0, b'')
