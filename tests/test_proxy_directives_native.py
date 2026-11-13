"""Proxy configuration preserves identity modes and rejects malformed endpoints."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def directives(server_native_compile):
    names = ('ngx_pnalloc', 'ngx_array_create', 'ngx_array_push', 'brix_dns_backend_prepare')
    return server_native_compile('proxy-directives', 'tests/c/proxy_directives_native_test.c',
                                 ['-Wl,--wrap=' + name for name in names])


def invoke(binary, operation, value, extra='', mode=''):
    result = subprocess.run([str(binary), operation, value, extra, mode],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return dict(line.split('=', 1) for line in result.stdout.splitlines())


@pytest.mark.parametrize('endpoint,host,port', [('origin.invalid', 'origin.invalid', 1094),
    ('127.0.0.1:1', '127.0.0.1', 1), ('origin.invalid:65535', 'origin.invalid', 65535),  # net-literal-allow: parser input/output, no connection
    ('[::1]:1094', '::1', 1094)])  # net-literal-allow: IPv6 parser input/output, no connection
@pytest.mark.parametrize('policy,key', [('', ''), ('anonymous', ''), ('forward', ''),
                                      ('sss', ''), ('sss:caller', 'caller')])
def test_upstreams_preserve_address_key_and_first_legacy_endpoint(directives, endpoint, host, port, policy, key):
    result = invoke(directives, 'upstream', endpoint, policy)
    assert result['rc'] == '0' and result['dns'] == '1'
    assert (result['host'], result['port'], result['key']) == (host, str(port), key)
    expected = {'': -1, 'anonymous': 0, 'forward': 1, 'sss': 2, 'sss:caller': 2}
    assert result['policy'] == str(expected[policy])


@pytest.mark.parametrize('endpoint', ['[::1', '[::1]', '[::1]1094', '[::1]:0',  # net-literal-allow: malformed IPv6 parser inputs, no connection
    '[::1]:65536', 'host:0', 'host:-1', 'host:65536', 'host:12garbage', 'host:'])  # net-literal-allow: invalid IPv6 port parser input, no connection
def test_malformed_endpoint_cannot_prepare_dns(directives, endpoint):
    result = invoke(directives, 'upstream', endpoint)
    assert result['rc'] == '-1' and result['dns'] == '0'


@pytest.mark.parametrize('policy', ['unknown', 'sss:' + 'x' * 256])
def test_invalid_auth_or_oversized_key_cannot_prepare_dns(directives, policy):
    result = invoke(directives, 'upstream', 'host:1094', policy)
    assert result['rc'] == '-1' and result['dns'] == '0'


@pytest.mark.parametrize('endpoint,mode', [('host:1094', '1'), ('host:1094', '2'),
    ('[::1]:1094', '2'), ('host', 'array'), ('host', 'push'), ('host', 'dns')])  # net-literal-allow: IPv6 parser allocation-failure input, no connection
def test_allocation_and_backend_initialization_failures_are_fatal(directives, endpoint, mode):
    result = invoke(directives, 'upstream', endpoint, mode=mode)
    assert result['rc'] == '-1' and result['dns'] == str(int(mode == 'dns'))


@pytest.mark.parametrize('operation,value,field,expected', [
    ('auth', 'anonymous', 'auth', 0), ('auth', 'forward', 'auth', 1),
    ('auth', 'sss', 'auth', 2), ('auth', 'gsi', 'auth', 3),
    ('login', 'anonymous', 'login', 0), ('login', 'passthrough', 'login', 1),
    ('login', 'fixed:a', 'login', 2), ('login', 'fixed:12345678', 'login', 2),
    ('identity', 'keytab', 'identity', 0), ('identity', 'client', 'identity', 1)])
def test_identity_configuration_retains_exact_enum_and_name(directives, operation, value, field, expected):
    result = invoke(directives, operation, value)
    assert result['rc'] == '0' and result[field] == str(expected)
    if value.startswith('fixed:'):
        assert result['user'] == value[6:]


@pytest.mark.parametrize('operation,value,field', [('auth', 'invalid', 'auth'),
    ('login', 'invalid', 'login'), ('login', 'fixed:', 'login'),
    ('login', 'fixed:123456789', 'login'), ('identity', 'invalid', 'identity')])
def test_invalid_identity_policy_preserves_unset_value(directives, operation, value, field):
    result = invoke(directives, operation, value)
    assert result['rc'] == '-1' and result[field] == '99'


@pytest.mark.parametrize('prefix', ['', '/source', '/space and bytes'])
def test_path_rewrite_retains_length_delimited_arguments(directives, prefix):
    assert invoke(directives, 'rewrite', prefix, '/dest')['rc'] == '0'
