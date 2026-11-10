"""Broker privilege transitions fail closed at every kernel boundary."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def credentials(server_native_compile):
    boundaries = ['getuid', 'geteuid', 'syscall', 'brix_plat_prctl', 'brix_plat_capset',
        'brix_plat_setresgid', 'brix_plat_setresuid', 'brix_plat_getresgid', 'brix_plat_getresuid',
        'brix_seccomp_broker_apply']
    return server_native_compile('broker-credentials', 'tests/c/broker_credentials_native_test.c',
        [f'-Wl,--wrap={name}' for name in boundaries])


def invoke(binary, action='drop', mode='normal', log=1):
    result = subprocess.run([str(binary), action, mode, str(log)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return {key: int(value) for key, value in
            (line.split('=', 1) for line in result.stdout.splitlines())}


@pytest.mark.parametrize('mode', ['normal', 'default-gid'])
@pytest.mark.parametrize('log', [0, 1])
def test_service_drop_has_ordered_groups_gid_uid_and_verified_identity(credentials, mode, log):
    result = invoke(credentials, mode=mode, log=log)
    assert result == dict(rc=0, stage=4, bounding=0, capsets=1, filters=0)


@pytest.mark.parametrize('mode,rc', [('unset', 0), ('nonroot', 0), ('root-user', -1)])
def test_unconfigured_or_unsafe_service_identity_does_not_change_credentials(credentials, mode, rc):
    result = invoke(credentials, mode=mode)
    assert result == dict(rc=rc, stage=0, bounding=0, capsets=0, filters=0)


@pytest.mark.parametrize('mode,stage', [('keepcaps', 0), ('groups', 1), ('setgid', 2), ('setuid', 3),
    ('capset', 4), ('getuid', 4), ('getgid', 4), ('real-uid', 4), ('effective-uid', 4), ('saved-uid', 4),
    ('real-gid', 4), ('effective-gid', 4), ('saved-gid', 4)])
@pytest.mark.parametrize('log', [0, 1])
def test_failed_or_partial_drop_is_never_accepted(credentials, mode, stage, log):
    result = invoke(credentials, mode=mode, log=log)
    assert result['rc'] == -1 and result['stage'] == stage and result['filters'] == 0


@pytest.mark.parametrize('mode', ['normal', 'permitted-only'])
def test_capability_set_contains_only_setuid_and_setgid(credentials, mode):
    assert invoke(credentials, 'capset', mode)['rc'] == 0


@pytest.mark.parametrize('mode', ['normal', 'unknown-cap', 'seccomp', 'unset'])
def test_full_hardening_retains_capability_floor_with_optional_filter(credentials, mode):
    result = invoke(credentials, 'all', mode)
    assert result['rc'] == 0 and result['bounding'] > 30 and result['filters'] == 1
    assert result['capsets'] == (1 if mode == 'unset' else 2)


@pytest.mark.parametrize('mode', ['no-new-privs', 'bounding', 'capset', 'reraise', 'root-user'])
def test_capability_floor_failure_stops_before_filter_installation(credentials, mode):
    result = invoke(credentials, 'all', mode)
    assert result['rc'] == -1 and result['filters'] == 0
