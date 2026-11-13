"""Real shared recall waiters retain ownership across reload and fd reuse."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def waiter_binary(server_native_compile):
    return server_native_compile('stage-waiter', 'tests/c/stage_waiter_native_test.c')


def run_waiter(binary, case, capacity):
    result = subprocess.run([str(binary), case, str(capacity)], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('capacity', [0, 2, 32, 4097])
@pytest.mark.parametrize('case', ['lifetime', 'reload', 'expire-poll', 'cross-worker'])
def test_waiter_capacity_expiry_reload_and_process_ownership(waiter_binary, case, capacity):
    run_waiter(waiter_binary, case, capacity)


@pytest.mark.parametrize('case', ['recycled', 'destroyed', 'no-session', 'no-context',
    'dead-context', 'wrong-state', 'missing-fd', 'files-recycled'])
def test_delayed_reply_never_reaches_stale_connection(waiter_binary, case):
    run_waiter(waiter_binary, case, 1)
