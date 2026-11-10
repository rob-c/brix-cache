"""Real AWS-style and MinIO-style STS exchanges preserve bounded credentials."""

from contextlib import contextmanager
import http.server
import subprocess
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from settings import BIND_HOST
from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def sts_exchange(server_native_compile):
    return server_native_compile('sts-exchange', 'tests/c/sts_exchange_native_test.c',
        ['-Wl,--wrap=' + name for name in ('ngx_pnalloc', 'curl_easy_init', 'gmtime_r')])


class STSHandler(http.server.BaseHTTPRequestHandler):
    """Record the actual signed request before returning a finite XML response."""

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.reply(urlsplit(self.path).query)

    def do_POST(self):
        self.reply(self.rfile.read(int(self.headers['Content-Length'])).decode())

    def reply(self, query):
        self.server.requests.append((self.command, parse_qs(query), dict(self.headers)))
        self.send_response(self.server.status)
        self.send_header('Content-Length', str(len(self.server.payload)))
        self.send_header('Location', 'file:///etc/passwd')
        self.end_headers()
        try:
            self.wfile.write(self.server.payload)
        except (BrokenPipeError, ConnectionResetError):
            pass


def credentials(session=True):
    token = '<SessionToken>FIXTURE_TOKEN</SessionToken>' if session else ''
    return ('<AssumeRoleResponse><AssumeRoleResult><Credentials>'
            '<AccessKeyId>TEMP_AK</AccessKeyId><SecretAccessKey>TEMP_SK</SecretAccessKey>'
            + token + '</Credentials></AssumeRoleResult></AssumeRoleResponse>').encode()


@contextmanager
def endpoint(payload, status=200):
    server = http.server.ThreadingHTTPServer((BIND_HOST, 0), STSHandler)
    server.payload = payload; server.status = status; server.requests = []
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
    thread.start()
    try:
        yield f'http://{BIND_HOST}:{server.server_port}/', server.requests
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)
        assert not thread.is_alive()


def invoke(binary, url, mode='normal', dialect=0, ttl=3600, role='role:test', subject='alice', expected=0):
    result = subprocess.run([str(binary), url, mode, str(dialect), str(ttl), role,
                             subject, str(expected)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'FIXTURE_SERVICE_SECRET' not in result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize('dialect', [0, 1])
@pytest.mark.parametrize('ttl,want', [(-1, 3600), (1, 900), (3600, 3600), (99999, 43200)])
@pytest.mark.parametrize('role', ['', 'role:test'])
def test_signed_request_clamps_ttl_and_returns_exact_credentials(sts_exchange, dialect, ttl, want, role):
    with endpoint(credentials()) as (url, requests):
        assert invoke(sts_exchange, url, dialect=dialect, ttl=ttl, role=role) == 'TEMP_AK\nTEMP_SK\nFIXTURE_TOKEN\n'
    assert len(requests) == 1
    method, query, headers = requests[0]
    assert method == ('POST' if dialect else 'GET')
    assert query['DurationSeconds'] == [str(want)]
    assert query['Action'] == ['AssumeRole' if role or dialect else 'GetSessionToken']
    assert 'FIXTURE_SERVICE_SECRET' not in repr(requests)
    if dialect:
        assert headers['Authorization'].startswith('AWS4-HMAC-SHA256 Credential=FIXTURE_AK/')
    else:
        assert len(query['X-Amz-Signature'][0]) == 64


@pytest.mark.parametrize('mode,subject,want', [('normal', 'alice \"&x', 'alice___x'),
    ('dn', '/CN=Alice Smith', '/CN=Alice_Smith'), ('null-id', 'ignored', 'anonymous'),
    ('normal', 'a' * 100, 'a' * 64), ('normal', '', 'anonymous')])
def test_identity_is_bounded_before_signed_query(sts_exchange, mode, subject, want):
    with endpoint(credentials(False)) as (url, requests):
        assert invoke(sts_exchange, url, mode, subject=subject) == 'TEMP_AK\nTEMP_SK\n\n'
    assert requests[0][1]['RoleSessionName'] == [want]


@pytest.mark.parametrize('mode', ['empty-endpoint', 'empty-region', 'empty-ak', 'empty-sk',
    'empty-host', 'long-credential', 'host-allocation', 'body-allocation', 'curl-init',
    'clock', 'null-pool', 'null-config'])
def test_setup_errors_never_send_a_request_or_return_credentials(sts_exchange, mode):
    with endpoint(credentials()) as (url, requests):
        assert invoke(sts_exchange, url, mode, expected=-1) == ''
    assert requests == []


@pytest.mark.parametrize('dialect', [0, 1])
@pytest.mark.parametrize('payload,status', [(credentials(), 403), (credentials(), 302),
    (b'<broken', 200), (b'<Credentials/>', 200), (b'x' * 65537, 200)])
def test_remote_errors_redirects_and_oversized_xml_never_return_credentials(sts_exchange, dialect, payload, status):
    with endpoint(payload, status) as (url, requests):
        assert invoke(sts_exchange, url, dialect=dialect, expected=-1) == ''
    assert len(requests) == 1
