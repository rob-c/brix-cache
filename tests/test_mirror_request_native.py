"""Mirror requests retain resource paths, credential policy and body ownership."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def mirror(server_native_compile):
    return server_native_compile('mirror-request', 'tests/c/mirror_request_native_test.c',
        ['-Wl,--wrap=ngx_create_temp_buf', '-Wl,--wrap=ngx_alloc_chain_link',
         '-Wl,--wrap=brix_metrics_get_shm_zone', '-Wl,--wrap=brix_dns_target_note_failure'])


def invoke(binary, method='COPY', auth='strip', destination='none', fault='normal'):
    result = subprocess.run([str(binary), method, auth, destination, fault],
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    status, wire = result.stdout.split(b'\n', 1)
    return int(status.removeprefix(b'rc=')), wire


@pytest.mark.parametrize('method', ['COPY', 'MOVE'])
@pytest.mark.parametrize('destination,expected', [
    ('https://public.example/dav/a%2fb?x=1', 'http://shadow.example:8443/dav/a%2fb?x=1'),
    ('http://public.example/dav/leaf', 'http://shadow.example:8443/dav/leaf'),
    ('HTTPS://public.example/dav/leaf', 'http://shadow.example:8443/dav/leaf'),
    ('http://[2001:db8::1]:8443/dav/leaf', 'http://shadow.example:8443/dav/leaf'),
    ('http://public.example', 'http://shadow.example:8443'),
    ('/dav/relative', '/dav/relative'), ('odd', 'odd'),
])
def test_destination_replaces_authority_and_retains_resource(mirror, method, destination, expected):
    rc, wire = invoke(mirror, method, destination=destination)
    assert rc == 0 and b'Destination: ' + expected.encode() + b'\r\n' in wire
    assert b'Depth: infinity\r\nOverwrite: F\r\n' in wire


@pytest.mark.parametrize('auth,expected', [('strip', []),
    ('forward', [b'Authorization: Bearer client-secret']),
    ('inject', [b'Authorization: Bearer shadow-token'])])
def test_credentials_follow_explicit_shadow_policy(mirror, auth, expected):
    rc, wire = invoke(mirror, auth=auth)
    values = [line for line in wire.split(b'\r\n') if line.startswith(b'Authorization:')]
    assert (rc, values) == (0, expected)
    assert wire.startswith(b'COPY /dav/source?opaque=%2f HTTP/1.1\r\n')
    assert wire.endswith(b'\r\n\r\n') and b'X-Xrootd-Mirror: 1\r\n' in wire


def test_put_body_cursors_are_private_and_length_matches_preserved_parent(mirror):
    rc, wire = invoke(mirror, 'PUT')
    assert rc == 0 and b'Content-Length: 7\r\n' in wire
    assert b'Destination:' not in wire and b'Depth:' not in wire


@pytest.mark.parametrize('method', ['COPY', 'PUT'])
@pytest.mark.parametrize('fault', ['header-oom', 'chain-oom', 'no-context', 'no-target'])
def test_incomplete_request_is_refused_without_publishing_a_partial_chain(mirror, method, fault):
    assert invoke(mirror, method, fault=fault) == (-1, b'')


def response(binary, wire, mode='normal', fault='normal'):
    result = subprocess.run([str(binary), 'RESPONSE', mode, wire, fault],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return {key: int(value) for key, value in (field.split('=') for field in result.stdout.split())}


@pytest.mark.parametrize('status,divergence', [(200, 0), (204, 0), (404, 1), (503, 1)])
def test_shadow_response_status_and_divergence_are_recorded(mirror, status, divergence):
    fields = response(mirror, f'HTTP/1.1 {status} Result\r\nX-Test: value\r\n\r\n')
    assert fields == {'ok': 1, 'again': 0, 'invalid': 0, 'error': 0, 'status': status,
                      'total': 1, 'errors': 0, 'divergence': divergence, 'dns': 0}


@pytest.mark.parametrize('mode', ['no-primary', 'no-parent-context', 'no-parent'])
def test_unavailable_primary_status_cannot_create_false_divergence(mirror, mode):
    fields = response(mirror, 'HTTP/1.1 500 Failed\r\n\r\n', mode)
    assert fields['ok'] == 1 and fields['divergence'] == 0 and fields['total'] == 1


@pytest.mark.parametrize('wire,status', [('HTTP/1.1 2', 0),
    ('HTTP/1.1 200 OK\r\nX-Test: incomplete', 200)])
def test_fragmented_response_waits_for_more_bytes(mirror, wire, status):
    fields = response(mirror, wire)
    assert fields['again'] == 1 and fields['status'] == status and fields['ok'] == 0


@pytest.mark.parametrize('wire', ['invalid status\r\n', 'HTTP/1.1 200 OK\r\nBad\x00Header: x\r\n\r\n'])
def test_malformed_shadow_response_is_not_accepted(mirror, wire):
    # argv cannot carry NUL; a control byte exercises the same parser refusal.
    fields = response(mirror, wire.replace('\x00', '\x01'))
    assert fields['invalid'] == 1 and fields['ok'] == 0


def test_missing_context_refuses_response_and_reports_unreachable_target(mirror):
    fields = response(mirror, 'HTTP/1.1 200 OK\r\n\r\n', fault='no-context')
    assert fields['error'] == 1 and fields['status'] == 0
    assert fields['errors'] == fields['dns'] == 1 and fields['total'] == 0
