"""Group overflow must inspect the complete membership before issuing capped credentials."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def groups_binary(server_native_compile):
    names = ['getpwnam', 'getgrnam', 'brix_plat_getgrouplist', 'brix_idmap_get_min_uid',
             'brix_idmap_get_primary_only', 'malloc']
    return server_native_compile('idmap-groups', 'tests/c/idmap_groups_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


def invoke(binary, operation, mode):
    result = subprocess.run([str(binary), operation, mode], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.split()


@pytest.mark.parametrize('mode,lookups,count', [('normal', 1, 3), ('primary', 0, 1),
    ('empty', 1, 1), ('overflow', 2, 32)])
def test_clean_group_sets_preserve_identity_and_cap_only_after_validation(groups_binary, mode, lookups, count):
    assert list(map(int, invoke(groups_binary, 'resolve', mode))) == [0, lookups, count, 1]


@pytest.mark.parametrize('mode,rc,lookups', [('missing', -1, 0), ('allocation', -1, 1),
    ('grows-again', -1, 2), ('root-tail', -2, 2), ('reserved-tail', -2, 2), ('forbidden-tail', -2, 2)])
def test_unresolved_or_forbidden_tail_membership_cannot_become_credentials(groups_binary, mode, rc, lookups):
    assert list(map(int, invoke(groups_binary, 'resolve', mode))) == [rc, lookups, 0, 0]


@pytest.mark.parametrize('kind,denied,identity,category', [('normal', 0, 777, '-'),
    ('null', 1, 0, 'n'), ('negative', 1, 2**32 - 1, 'n'), ('overflow', 1, 33, 'n'),
    ('uid', 1, 0, 'u'), ('gid', 1, 999, 'g'), ('supplementary', 1, 0, 's')])
def test_broker_guard_reports_the_exact_rejected_credential(groups_binary, kind, denied, identity, category):
    assert invoke(groups_binary, 'reserved', kind) == [str(denied), str(identity), category]
