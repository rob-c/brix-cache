"""Drive the real storage scanner through a finite, authenticated HTTP peer."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from brix_suite.client_build import client_snapshot
from settings import BIND_HOST, HOST, url_host


@pytest.fixture(scope='module')
def scanner(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    binary = root / 'client/bin/xrdstorascan'
    assert binary.is_file(), 'build the native client before running this contract'
    return client_snapshot(root / 'client', binary,
                           tmp_path_factory.mktemp('scanner-http') / binary.name)


def run_scan(scanner, arguments, password=None):
    environment = dict(os.environ)
    environment.pop('XRDSTORASCAN_PASSWORD', None)
    if password is not None:
        environment['XRDSTORASCAN_PASSWORD'] = password
    return subprocess.run([str(scanner), *arguments], env=environment,
                          capture_output=True, text=True, timeout=15)


class ScanPeer(BaseHTTPRequestHandler):
    """Record request boundaries and return the scenario's bounded response."""

    def log_message(self, *_arguments):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.server.requests.append(('POST', self.path, dict(self.headers), body))
        self.send_response(self.server.login_status)
        if self.server.cookie is not None:
            self.send_header('Set-Cookie', self.server.cookie)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        self.server.requests.append(('GET', self.path, dict(self.headers), b''))
        if self.server.disconnect:
            self.close_connection = True
            return
        self.send_response(self.server.scan_status)
        self.send_header('Content-Length', str(len(self.server.body)))
        self.end_headers()
        self.wfile.write(self.server.body)


@contextmanager
def scan_peer(records=(), login_status=200, cookie='session=fixture; HttpOnly',
              scan_status=200, disconnect=False):
    peer = ThreadingHTTPServer((BIND_HOST, 0), ScanPeer)
    peer.requests = []
    peer.login_status = login_status
    peer.cookie = cookie
    peer.scan_status = scan_status
    peer.disconnect = disconnect
    peer.body = '\n'.join(json.dumps(row, separators=(',', ':'))
                          for row in records).encode()
    thread = threading.Thread(target=peer.serve_forever, daemon=True)
    thread.start()
    try:
        yield peer, f'http://{url_host(HOST)}:{peer.server_port}/dashboard'
    finally:
        peer.shutdown()
        peer.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.parametrize('mode', ['dump', 'fill', 'compare', 'verify', 'inspect',
                                 'health', 'inventory', 'drift'])
@pytest.mark.parametrize('login_status', [200, 302])
def test_authenticated_query_preserves_values(scanner, mode, login_status):
    records = [{'t': 'summary', 'files': 2, 'ok': 2, 'mismatch': 0}]
    path = '/Z.a_~-9/a b+&?é'
    with scan_peer(records, login_status=login_status) as (peer, url):
        result = run_scan(scanner, [mode, url, '--path', path, '--algo', 'sha+256',
                                    '--password', 'override', '--insecure', '--json'],
                          password='ignored')
    assert result.returncode == 0, result.stderr
    assert [json.loads(line) for line in result.stdout.splitlines()] == records
    post, get = peer.requests
    assert post[0:2] == ('POST', '/brix/login')
    assert post[3] == b'password=override'
    assert post[2]['Content-Type'] == 'application/x-www-form-urlencoded'
    assert get[0] == 'GET' and get[2]['Cookie'] == 'session=fixture'
    parsed = urlsplit(get[1])
    assert parsed.path == '/brix/api/v1/scan'
    assert parse_qs(parsed.query) == {'mode': [mode], 'path': [path], 'alg': ['sha+256']}


@pytest.mark.parametrize('row,expected', [
    ({'t': 'inspect', 'backend': 'rados', 'size': 8, 'path': '/data',
      'stored_src': 'xattr', 'namespace_consistent': True},
     'rados    8            /data\tstored_src=xattr consistent=true'),
    ({'t': 'health', 'backend': 'posix', 'total_bytes': 64, 'used_bytes': 8,
      'free_bytes': 56}, 'backend=posix total=64 used=8 free=56'),
    ({'t': 'object', 'size': 5, 'key': 'orphan-key', 'orphan': True},
     '5            (orphan)\tkey=orphan-key orphan=true'),
    ({'t': 'object', 'size': 5, 'path': '/file', 'key': 'key', 'orphan': False},
     '5            /file\tkey=key orphan=false'),
    ({'t': 'drift', 'class': 'missing', 'size': 7, 'key': 'key', 'path': '/gone'},
     'missing        7            key=key path=/gone'),
    ({'t': 'file', 'status': 'ok', 'size': 4, 'path': '/a"b', 'stored': 'abcd',
      'computed': 'abcd'}, 'ok         4            /a"b\tstored=abcd computed=abcd'),
    ({'t': 'file'}, '-          0            \tstored=- computed=-'),
    ({'t': 'summary'}, '# files=0 ok=0 mismatch=0 missing=0 unreadable=0'),
])
def test_record_rendering_and_defaults(scanner, row, expected):
    with scan_peer([{'ignored': 1}, row]) as (peer, url):
        result = run_scan(scanner, ['dump', url], password='from-environment')
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected + '\n'
    assert peer.requests[0][3] == b'password=from-environment'


@pytest.mark.parametrize('mode,expected', [('verify', 1), ('compare', 1), ('dump', 0)])
@pytest.mark.parametrize('flags', [[], ['--json'], ['--summary'], ['--json', '--summary']])
def test_mismatch_exit_and_summary_filter(scanner, mode, expected, flags):
    row = {'t': 'file', 'status': 'mismatch', 'path': '/bad'}
    summary = {'t': 'summary', 'files': 1, 'mismatch': 1}
    with scan_peer([row, summary]) as (_peer, url):
        result = run_scan(scanner, [mode, url, *flags], password='fixture')
    assert result.returncode == expected, result.stderr
    if '--summary' in flags:
        assert json.loads(result.stdout) == summary
    elif '--json' in flags:
        assert [json.loads(line) for line in result.stdout.splitlines()] == [row, summary]
    else:
        assert '/bad' in result.stdout and '# files=1 ok=0 mismatch=1' in result.stdout


@pytest.mark.parametrize('status,cookie', [(403, 'session=denied'), (500, 'session=bad'),
                                         (200, None), (302, ''), (200, '; HttpOnly')])
def test_login_refusal_never_sends_scan_request(scanner, status, cookie):
    with scan_peer(login_status=status, cookie=cookie) as (peer, url):
        result = run_scan(scanner, ['dump', url], password='fixture')
    assert result.returncode != 0
    assert 'login failed' in result.stderr
    assert len(peer.requests) == 1 and peer.requests[0][0] == 'POST'
    assert result.stdout == ''


@pytest.mark.parametrize('status,hint', [(401, 'check password'),
                                       (404, 'brix_scan_root'), (500, 'HTTP 500')])
def test_scan_http_errors_are_not_reported_as_success(scanner, status, hint):
    with scan_peer(scan_status=status) as (_peer, url):
        result = run_scan(scanner, ['health', url], password='fixture')
    assert result.returncode == 3 and result.stdout == ''
    assert hint in result.stderr


def test_dropped_response_is_a_transport_error(scanner):
    with scan_peer(disconnect=True) as (_peer, url):
        result = run_scan(scanner, ['dump', url], password='fixture')
    assert result.returncode != 0 and result.stdout == ''
    assert 'dump:' in result.stderr


@pytest.mark.parametrize('arguments', [[], ['--unknown'], ['--path'],
    ['http://host', 'extra'], ['ftp://host'], ['http://'], ['http://host:0'],
    ['http://host:-1'], ['http://' + 'a' * 256], ['http://host']])
def test_bad_invocations_fail_before_network(scanner, arguments):
    result = run_scan(scanner, ['dump', *arguments])
    assert result.returncode == 64 and result.stdout == ''


def test_mode_help_requires_no_credentials(scanner):
    result = run_scan(scanner, ['health', '--help'])
    assert result.returncode == 0
    assert 'health <dashboard-url>' in result.stdout


def test_empty_body_is_an_empty_successful_scan(scanner):
    with scan_peer() as (_peer, url):
        result = run_scan(scanner, ['dump', url], password='fixture')
    assert result.returncode == 0 and result.stdout == ''
