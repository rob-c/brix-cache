"""Double-fork transfer isolation, replies, respawn and admission failures."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def agent_binary(server_native_compile):
    return server_native_compile('xfer-agent', 'tests/c/xfer_agent_native_test.c',
        ['-Wl,--wrap=malloc', '-Wl,--wrap=fork', '-Wl,--wrap=socketpair'])


@pytest.mark.parametrize('case', ['roundtrip', 'no-drain', 'respawn', 'callback-exit',
                                  'backpressure', 'alloc',
                                  'fork', 'socketpair', 'connections'])
def test_transfer_agent_contract(agent_binary, case):
    result = subprocess.run([str(agent_binary), case], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
