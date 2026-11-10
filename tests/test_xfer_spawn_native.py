"""External transfer helpers preserve status, descriptor isolation and signals."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def xfer_spawn(server_native_compile):
    wrappers = ('fork', 'socketpair', 'read', 'write', 'waitpid', 'brix_plat_execvpe', '_exit')
    flags = ['-Wl,--wrap=' + name for name in wrappers]
    flags += ['--coverage', '-Wl,-u,__gcov_dump', '-Wl,-u,__gcov_reset']
    return server_native_compile('xfer-spawn', 'tests/c/xfer_spawn_native_test.c', flags)


@pytest.mark.parametrize('mode,expected', [('normal', 17), ('path', 17), ('partial', 17),
    ('read-eintr', 17), ('write-eintr', 17), ('wait-eintr', 17), ('security', 0),
    ('signal', 128), ('missing', 127), ('null', -1), ('null-element', -1),
    ('socketpair', -1), ('fork-parent', -1), ('fork-agent', -1), ('fork-command', 127),
    ('read-error', -1), ('write-error', -1)])
def test_reparented_command_and_result_channel_contract(xfer_spawn, mode, expected):
    result = subprocess.run([str(xfer_spawn), mode, str(expected)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
