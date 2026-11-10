"""Stream audit variables retain identity meaning through missing contexts and allocation faults."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def variables_binary(server_native_compile):
    return server_native_compile('stream-variables', 'tests/c/stream_variables_native_test.c',
        ['-Wl,--wrap=ngx_stream_add_variable', '-Wl,--wrap=ngx_pnalloc'])


def invoke(binary, mode, field):
    result = subprocess.run([str(binary), mode, 'brix_' + field], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize('field,expected', [('dn', 'identity-dn'), ('sub', 'identity-subject'),
    ('issuer', 'issuer'), ('user', 'mapped'), ('vo', '/vo/Role=one,/vo/Role=two'),
    ('fqan', '/vo/Role=one'), ('origin', '/origin'), ('tier', 'posix'),
    ('cache_status', 'HIT'), ('path', '/data/file'), ('bytes_served', '12345'),
    ('bytes_received', '678'), ('ops', '17'), ('backend_time', '1.234'), ('duration', '0.000')])
def test_registered_values_describe_the_session_exactly(variables_binary, field, expected):
    assert invoke(variables_binary, 'normal', field) == expected


@pytest.mark.parametrize('field,expected', [('dn', 'login-dn'), ('sub', 'login-dn'),
    ('vo', '/fallback'), ('fqan', '/fallback'), ('user', '-'), ('issuer', '-')])
@pytest.mark.parametrize('mode', ['legacy', 'empty-id'])
def test_absent_identity_fields_fall_back_only_to_the_matching_login_field(variables_binary, field, expected, mode):
    assert invoke(variables_binary, mode, field) == expected


@pytest.mark.parametrize('field', ['dn', 'issuer', 'user', 'backend_time', 'bytes_served', 'ops', 'path'])
def test_early_disconnect_has_an_explicit_missing_value(variables_binary, field):
    assert invoke(variables_binary, 'no-context', field) == '-'


@pytest.mark.parametrize('field', ['dn', 'fqan', 'backend_time', 'bytes_served', 'ops', 'duration'])
def test_allocation_failure_cannot_publish_uninitialized_log_bytes(variables_binary, field):
    assert invoke(variables_binary, 'allocation', field) == '-'


@pytest.mark.parametrize('mode,field,expected', [('first-allocation', 'fqan', '/vo/Role=one,/vo/Role=two'),
    ('single-vo', 'fqan', '/single'), ('unmapped', 'user', '-'),
    ('no-config', 'origin', '-'), ('no-config', 'tier', '-'), ('empty-monitor', 'path', '-'),
    ('empty-monitor', 'cache_status', '-'), ('tls', 'tls', 'on'), ('no-context', 'tls', 'off')])
def test_optional_session_sources_have_explicit_fallbacks(variables_binary, mode, field, expected):
    assert invoke(variables_binary, mode, field) == expected


def test_registration_failure_is_returned_before_installing_remaining_getters(variables_binary):
    assert invoke(variables_binary, 'register-error', 'dn') == 'refused\n'
