"""Worker transition policy refuses unverified identities and retained capabilities."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def identity_binary(server_native_compile):
    names = ['getuid', 'geteuid', 'getpwnam', 'getpwuid', 'getgroups', 'setgroups', 'setgid', 'setuid',
        'brix_plat_getresuid', 'brix_plat_getresgid', 'brix_plat_setresuid', 'brix_plat_setresgid',
        'brix_plat_getgrouplist', 'brix_imp_cap_held', 'brix_plat_prctl', 'brix_imp_worker_drop_bounds',
        'brix_plat_capset', 'brix_plat_capget', 'malloc']
    return server_native_compile('worker-identity', 'tests/c/worker_identity_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


def invoke(binary, operation, mode):
    result = subprocess.run([str(binary), operation, mode], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return tuple(map(int, result.stdout.split()))


@pytest.mark.parametrize('operation,counts', [('current', (0, 1, 0, 0, 0)),
    ('transition', (0, 1, 1, 1, 1)), ('normalize', (0, 1, 1, 1, 1)), ('harden', (0, 1, 0, 0, 0))])
def test_success_reaches_verified_terminal_identity_before_serving(identity_binary, operation, counts):
    assert invoke(identity_binary, operation, 'normal') == counts


@pytest.mark.parametrize('mode', ['missing', 'root-target', 'group-count', 'group-read',
    'group-resolve', 'allocation', 'cap-write', 'cap-read', 'cap-retained', 'single'])
def test_current_target_refuses_missing_identity_or_incomplete_attestation(identity_binary, mode):
    counts = invoke(identity_binary, 'current', mode)
    assert counts[0] == -1 and counts[2:] == (0, 0, 0)


@pytest.mark.parametrize('mode', ['group-write', 'gid-write', 'uid-write', 'uid-unstuck',
    'group-unstuck', 'cap-write', 'cap-read', 'cap-retained'])
def test_failed_transition_cannot_start_request_processing(identity_binary, mode):
    assert invoke(identity_binary, 'transition', mode)[0] == -1


@pytest.mark.parametrize('mode', ['no-cap', 'group-write', 'gid-write', 'uid-write', 'uid-unstuck',
    'group-unstuck', 'group-count', 'group-read'])
def test_saved_or_group_identity_cannot_remain_privileged(identity_binary, mode):
    assert invoke(identity_binary, 'normalize', mode)[0] == -1


@pytest.mark.parametrize('mode', ['no-new-privs', 'bounds', 'cap-write'])
def test_preparation_failure_prevents_serving(identity_binary, mode):
    assert invoke(identity_binary, 'harden', mode)[0] == -1


@pytest.mark.parametrize('mode,result', [('default', 0), ('default-missing', -1), ('default-unsafe', -1)])
def test_implicit_target_preserves_only_a_verified_unprivileged_service_account(identity_binary, mode, result):
    assert invoke(identity_binary, 'current', mode) == (result, 1, 0, 0, 0)
