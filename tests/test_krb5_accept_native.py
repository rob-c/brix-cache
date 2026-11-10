"""Ticket rejection cannot register a session or leak Kerberos authentication owners."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def accept_binary(server_native_compile):
    names = ('krb5_auth_con_init', 'krb5_auth_con_free', 'krb5_auth_con_setaddrs',
        'krb5_rd_req', 'krb5_free_ticket', 'krb5_aname_to_localname', 'krb5_unparse_name',
        'brix_send_error', 'brix_send_ok', 'brix_metric_auth', 'brix_log_access',
        'brix_session_register', 'brix_metrics_get_shm_zone', 'brix_track_unique_user',
        'brix_krb5_deleg_park', 'brix_krb5_send_fwdtgt', 'brix_krb5_deleg_capture')
    return server_native_compile('krb5-accept', 'tests/c/krb5_accept_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


@pytest.fixture
def accept(accept_binary):
    def run(mode='normal', family=4, delegation=0):
        result = subprocess.run([str(accept_binary), mode, str(family), str(delegation)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return tuple(map(int, result.stdout.split()))
    return run


@pytest.mark.parametrize('family', [0, 4, 6])
@pytest.mark.parametrize('mode', ['normal', 'nul-prefix', 'principal-name', 'no-identity', 'no-metrics', 'empty-name'])
def test_verified_ticket_has_one_grant_and_exact_identity(accept, family, mode):
    assert accept(mode, family) == (1, 0, 1, int(family != 0), 1,
                                   int(mode not in {'no-metrics', 'empty-name'}), 1, 1, 0)


@pytest.mark.parametrize('mode', ['no-context', 'no-principal', 'no-keytab', 'null-payload',
    'short-payload', 'wrong-prefix', 'context-error', 'no-peer', 'bind-error', 'verify-error',
    'null-ticket', 'no-enc-part', 'no-client', 'name-error', 'null-name'])
def test_failed_authentication_cannot_grant_or_register(accept, mode):
    result = accept(mode)
    assert result[0] == 0 and result[1] != 0 and result[4:] == (0, 0, 1, 0, 0)


def test_unsupported_peer_family_is_rejected_before_ticket_verification(accept):
    assert accept(family=1) == (0, 3010, 0, 0, 0, 0, 1, 0, 0)


@pytest.mark.parametrize('family', [0, 4, 6])
def test_delegation_challenge_parks_owner_without_granting(accept, family):
    assert accept(family=family, delegation=1) == (0, 0, 1, int(family != 0), 0, 0, 0, 0, 1)


@pytest.mark.parametrize('mode', ['park-error', 'no-client', 'name-error'])
def test_delegation_setup_refusal_releases_ticket_and_context(accept, mode):
    result = accept(mode, delegation=1)
    assert result[0] == 0 and result[1] != 0 and result[4:] == (0, 0, 1, 0, 0)


def test_forwarded_credential_is_verified_before_second_round_grant(accept):
    assert accept(delegation=2) == (1, 0, 0, 0, 1, 1, 1, 1, 0)
    assert accept('capture-error', delegation=2) == (0, 3010, 0, 0, 0, 0, 1, 0, 0)
