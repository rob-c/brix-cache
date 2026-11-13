"""Real diagnostic requests against a bounded, deliberately adversarial peer."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading

import pytest

from brix_suite.client_build import client_snapshot
from settings import BIND_HOST, HOST, url_host


@pytest.fixture(scope='module')
def doctor(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    binary = root / 'client/bin/xrddiag'
    assert binary.is_file(), 'build the native client before this contract'
    return client_snapshot(root / 'client', binary,
                           tmp_path_factory.mktemp('doctor-http') / binary.name)


class DoctorPeer(BaseHTTPRequestHandler):
    """Record actual methods, headers and targets; never forward requests."""

    def log_message(self, *_arguments):
        pass

    def respond(self):
        signed = 'Authorization' in self.headers
        self.server.requests.append((self.command, self.path, dict(self.headers)))
        self.server.bodies.append(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        key = 'SIGNED' if signed else self.command
        response = self.server.responses.get(key, (200, {}, b''))
        if response == 'reset':
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       struct.pack('ii', 1, 0))
            self.close_connection = True
            return
        if response is None:
            self.close_connection = True
            return
        status, headers, body = response
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    do_HEAD = respond
    do_GET = respond
    do_OPTIONS = respond
    do_PROPFIND = respond
    do_POST = respond


class DoctorServer(ThreadingHTTPServer):
    """Honor an injected reset without the default graceful shutdown first."""

    def shutdown_request(self, request):
        linger = request.getsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 8)
        if linger == struct.pack('ii', 1, 0):
            self.close_request(request)
        else:
            super().shutdown_request(request)


@contextmanager
def doctor_peer(responses):
    peer = DoctorServer((BIND_HOST, 0), DoctorPeer)
    peer.responses, peer.requests = responses, []
    peer.bodies = []
    thread = threading.Thread(target=peer.serve_forever, daemon=True)
    thread.start()
    try:
        yield peer, f'{url_host(HOST)}:{peer.server_port}/bucket/private-object'
    finally:
        peer.shutdown()
        peer.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def doctor_environment(credentials):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('AWS_')}
    environment.update(credentials or {})
    return environment


def run_doctor(doctor, url, credentials=None):
    result = subprocess.run([str(doctor), 'remote-doctor', url, '--json',
                             '--probe-timeout', '1000'], env=doctor_environment(credentials),
                            capture_output=True, text=True, timeout=10)
    document = json.loads(result.stdout)['remote_doctor']
    endpoint, = document['endpoints']
    assert document['cross_endpoint_analysis']['hops'] == 0
    findings = {item['probe']: item for item in endpoint['diagnosis']}
    assert 'private-object' not in result.stdout
    return result, endpoint, findings


@pytest.mark.parametrize('status,verdict,code', [
    (200, 'ok', 0), (204, 'ok', 0), (206, 'ok', 0), (301, 'warn', 0),
    (307, 'warn', 0), (401, 'warn', 0), (403, 'warn', 0), (404, 'warn', 0),
    (410, 'warn', 0), (418, 'warn', 0), (500, 'fail', 1), (503, 'fail', 1),
])
def test_http_status_and_transfer_capabilities(doctor, status, verdict, code):
    headers = {'Accept-Ranges': 'bytes', 'Digest': 'sha-256=fixture',
               'Location': 'http://must-not-contact.invalid/secret'}
    with doctor_peer({'HEAD': (status, headers, b'')}) as (peer, authority):
        result, endpoint, findings = run_doctor(doctor, 'http://' + authority)
    assert result.returncode == code, result.stderr
    assert endpoint['connected'] and endpoint['facts']['tls'] == 'none'
    assert findings['http']['verdict'] == verdict
    assert findings['http']['kxr'] == status
    for probe in ('ranges', 'checksum', 'content-length'):
        assert findings[probe]['verdict'] == 'ok'
    assert [(method, path) for method, path, _ in peer.requests] == [
        ('HEAD', '/bucket/private-object')]
    assert 'must-not-contact' not in result.stdout


@pytest.mark.parametrize('headers', [{}, {'Accept-Ranges': 'none'},
                                   {'Digest': 'malformed'}])
def test_absent_or_malformed_capabilities_warn(doctor, headers):
    with doctor_peer({'HEAD': (200, headers, b'')}) as (_peer, authority):
        result, endpoint, findings = run_doctor(doctor, 'http://' + authority)
    assert result.returncode == 0 and endpoint['status'] == 'YELLOW'
    assert findings['ranges']['verdict'] == 'warn'
    assert findings['checksum']['verdict'] == 'warn'


def test_failed_head_uses_one_bounded_range_request(doctor):
    with doctor_peer({'HEAD': 'reset', 'GET': (206, {}, b'X')}) as (peer, authority):
        result, endpoint, findings = run_doctor(doctor, 'http://' + authority)
    assert result.returncode == 0 and endpoint['connected']
    assert findings['http']['kxr'] == 206
    head, get = peer.requests
    assert head[0] == 'HEAD' and get[0] == 'GET'
    assert get[2]['Range'] == 'bytes=0-0'


@pytest.mark.parametrize('scheme,methods', [('http', ['HEAD', 'GET']),
                                         ('s3', ['GET'])])
def test_disconnected_peer_is_failed_and_stops_probing(doctor, scheme, methods):
    with doctor_peer({'HEAD': 'reset', 'GET': 'reset'}) as (peer, authority):
        result, endpoint, findings = run_doctor(doctor, scheme + '://' + authority)
    assert result.returncode == 1 and endpoint['status'] == 'RED'
    assert not endpoint['connected']
    assert findings['reachability']['verdict'] == 'fail'
    assert [request[0] for request in peer.requests] == methods
    assert 's3-sigv4' not in findings


def dav_headers(dav, allow):
    return {key: value for key, value in [('DAV', dav), ('Allow', allow)]
            if value is not None}


@pytest.mark.parametrize('dav,allow,listing', [
    ('1, 2', 'GET, COPY, PROPFIND', 207), ('1', 'GET', 401),
    (None, 'GET', 403), (None, None, 404), ('1', None, 500),
])
def test_webdav_discovery_and_listing_classification(doctor, dav, allow, listing):
    responses = {'OPTIONS': (200, dav_headers(dav, allow), b''),
                 'PROPFIND': (listing, {}, b'<multistatus/>')}
    with doctor_peer(responses) as (peer, authority):
        result, _endpoint, findings = run_doctor(doctor, 'dav://' + authority)
    assert result.returncode == 0
    assert findings['davs-class']['verdict'] == ('ok' if dav else 'warn')
    assert ('davs-tpc' in findings) == (allow is not None and 'COPY' in allow)
    assert findings['davs-listing']['kxr'] == listing
    assert findings['davs-listing']['verdict'] == ('ok' if listing == 207 else 'warn')
    assert [request[0] for request in peer.requests] == ['HEAD', 'OPTIONS', 'PROPFIND']
    assert peer.requests[-1][2]['Depth'] == '1'


def test_webdav_transport_failures_do_not_claim_capabilities(doctor):
    with doctor_peer({'OPTIONS': 'reset', 'PROPFIND': 'reset'}) as (_peer, authority):
        result, _endpoint, findings = run_doctor(doctor, 'dav://' + authority)
    assert result.returncode == 0
    assert findings['davs-class']['verdict'] == 'warn'
    assert 'davs-tpc' not in findings and 'davs-listing' not in findings


@pytest.mark.parametrize('status,probe,verdict,code', [
    (200, 's3-auth', 'warn', 0), (206, 's3-auth', 'warn', 0),
    (403, 's3-auth', 'ok', 0), (404, 's3-bucket', 'warn', 0),
    (301, 's3-req', 'warn', 0), (500, 's3-req', 'fail', 1),
])
def test_s3_anonymous_posture(doctor, status, probe, verdict, code):
    with doctor_peer({'GET': (status, {}, b'private-body')}) as (peer, authority):
        result, endpoint, findings = run_doctor(doctor, 's3://' + authority)
    assert result.returncode == code and endpoint['connected']
    assert findings[probe]['verdict'] == verdict
    assert findings[probe]['kxr'] == status
    assert 'skipped' in findings['s3-sigv4']['cause']
    request, = peer.requests
    assert request[0] == 'GET' and 'Authorization' not in request[2]
    assert 'private-body' not in result.stdout


@pytest.mark.parametrize('response,verdict,code', [
    ((200, {}, b'private-body'), 'ok', 0),
    ((403, {}, b'<Code>SignatureDoesNotMatch</Code>'), 'fail', 1),
    ((403, {}, b'<Code>AccessDenied</Code><Message>SignatureDoesNotMatch</Message>'),
     'warn', 0),
    ((403, {}, b''), 'warn', 0), ((404, {}, b''), 'warn', 0),
    ((500, {}, b''), 'fail', 1), ('reset', 'warn', 0), (None, 'fail', 1),
])
@pytest.mark.parametrize('region', ['', 'eu-test-1'])
def test_s3_signed_probe_and_redacted_diagnosis(doctor, response, verdict, code, region):
    credentials = {'AWS_ACCESS_KEY_ID': 'coverage-only-access',
                   'AWS_SECRET_ACCESS_KEY': 'coverage-only-secret',
                   'AWS_DEFAULT_REGION': region}
    with doctor_peer({'GET': (403, {}, b''), 'SIGNED': response}) as (peer, authority):
        result, _endpoint, findings = run_doctor(doctor, 's3://' + authority, credentials)
    assert result.returncode == code, result.stderr
    assert findings['s3-sigv4']['verdict'] == verdict
    anonymous, signed = peer.requests
    assert 'Authorization' not in anonymous[2]
    authorization = signed[2]['Authorization']
    assert authorization.startswith('AWS4-HMAC-SHA256 Credential=coverage-only-access/')
    assert '/' + (region or 'us-east-1') + '/s3/aws4_request' in authorization
    assert 'host' in authorization and signed[2]['Host'] == authority.split('/')[0]
    assert 'coverage-only' not in result.stdout + result.stderr
    assert 'private-body' not in result.stdout


@pytest.mark.parametrize('credentials', [
    {'AWS_ACCESS_KEY_ID': 'incomplete'}, {'AWS_SECRET_ACCESS_KEY': 'incomplete'},
    {'AWS_ACCESS_KEY_ID': '', 'AWS_SECRET_ACCESS_KEY': 'incomplete'},
])
def test_partial_credentials_never_send_signed_request(doctor, credentials):
    with doctor_peer({'GET': (403, {}, b'')}) as (peer, authority):
        result, _endpoint, findings = run_doctor(doctor, 's3://' + authority, credentials)
    assert result.returncode == 0 and len(peer.requests) == 1
    assert 'skipped' in findings['s3-sigv4']['cause']


@pytest.mark.parametrize('scheme,probe', [('http', 'http'), ('s3', 's3-req')])
def test_empty_http_response_is_never_reported_successful(doctor, scheme, probe):
    with doctor_peer({'HEAD': None, 'GET': None}) as (_peer, authority):
        result, endpoint, findings = run_doctor(doctor, scheme + '://' + authority)
    assert result.returncode == 1 and endpoint['status'] == 'RED'
    assert findings[probe]['verdict'] == 'fail' and findings[probe]['kxr'] == 0
    assert 'malformed/partial' in findings[probe]['cause']
