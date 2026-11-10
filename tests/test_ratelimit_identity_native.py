"""Anonymous fallback and bounded subject hashing agree across stream and HTTP."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def ratelimit_identity(server_native_compile):
    binary = server_native_compile('ratelimit-identity', 'tests/c/ratelimit_identity_native_test.c')

    def run(plane, kind, identity, capacity=128, path='/store/object'):
        result = subprocess.run([str(binary), plane, str(kind), identity, str(capacity), path],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        status, key = result.stdout.split('\n', 1)
        return int(status), key
    return run


@pytest.mark.parametrize('plane', ['http', 'stream'])
@pytest.mark.parametrize('kind', [0, 1, 2, 3, 5])
@pytest.mark.parametrize('identity', ['none', 'empty'])
@pytest.mark.parametrize('capacity', [1, 8, 128])
def test_anonymous_clients_cannot_escape_ip_bucket(ratelimit_identity, plane, kind, identity, capacity):
    assert ratelimit_identity(plane, kind, identity, capacity) == (0, 'ip:192.0.2.17'[:capacity - 1])


@pytest.mark.parametrize('plane', ['http', 'stream'])
@pytest.mark.parametrize('kind,expected', [(0, 'vo:atlas'), (1, 'iss:https://issuer.invalid'),
                                         (2, 'ip:192.0.2.17')])
def test_present_identity_dimension_selects_correct_bucket(ratelimit_identity, plane, kind, expected):
    assert ratelimit_identity(plane, kind, 'full') == (0, expected)


@pytest.mark.parametrize('kind,prefix', [(3, 'dn:'), (5, 'sub:')])
def test_private_principals_hash_identically_across_planes(ratelimit_identity, kind, prefix):
    stream = ratelimit_identity('stream', kind, 'full')
    http = ratelimit_identity('http', kind, 'full')
    assert stream == http
    assert stream[0] == 0 and stream[1].startswith(prefix)
    assert len(stream[1]) == len(prefix) + 8
    assert all(byte in '0123456789ABCDEFabcdef' for byte in stream[1][len(prefix):])
    assert 'private' not in stream[1] and '@' not in stream[1]


def test_http_certificate_dn_fallback_matches_structured_identity(ratelimit_identity):
    assert ratelimit_identity('http', 3, 'cert') == ratelimit_identity('stream', 3, 'full')


@pytest.mark.parametrize('plane', ['http', 'stream'])
@pytest.mark.parametrize('path,expected', [('/store/object', (0, 'vol:/store/')),
    ('/elsewhere', (-5, '')), ('<null>', (-5, ''))])
def test_volume_rule_applies_only_to_selected_prefix(ratelimit_identity, plane, path, expected):
    assert ratelimit_identity(plane, 4, 'none', path=path) == expected


@pytest.mark.parametrize('plane', ['http', 'stream'])
def test_unknown_dimension_cannot_emit_a_bucket(ratelimit_identity, plane):
    assert ratelimit_identity(plane, 99, 'full') == (-1, '')
