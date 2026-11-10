"""A local TLS director validates signed cache registration and refusal paths."""

import base64
import http.server
import ipaddress
import json
import ssl
import subprocess
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import pytest

from settings import BIND_HOST, HOST

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def pelican_binary(server_native_compile):
    return server_native_compile('pelican-register',
                                'tests/c/pelican_register_native_test.c')


def director_san():
    try:
        return 'IP:' + str(ipaddress.ip_address(HOST))
    except ValueError:
        return 'DNS:' + HOST


@pytest.fixture(scope='module')
def director_pki(tmp_path_factory):
    root = tmp_path_factory.mktemp('director-pki')
    ca = root / 'ca'
    ca.mkdir()
    key, cert = root / 'key.pem', ca / 'cert.pem'
    command = ['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
        'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', f'/CN={HOST}',
        '-addext', 'subjectAltName=' + director_san(), '-keyout', str(key), '-out', str(cert)]
    subprocess.run(command, check=True, capture_output=True, timeout=10)
    subprocess.run(['openssl', 'rehash', str(ca)], check=True,
                   capture_output=True, timeout=10)
    public = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout'],
                            check=True, capture_output=True, timeout=10).stdout
    return ca, key, cert, public


class DirectorHandler(http.server.BaseHTTPRequestHandler):
    """Serve only the local test's discovery document and registration endpoint."""

    def log_message(self, *_args):
        pass

    def respond(self, code, body=b'', location=None):
        self.send_response(code)
        self.send_header('Content-Length', str(len(body)))
        if location:
            self.send_header('Location', location)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        mode = self.server.mode
        if mode == 'get-error':
            self.respond(503)
            return
        if mode == 'redirect-discovery' and self.path.startswith('/.well-known'):
            self.respond(302, b'not-json', self.server.url + '/discovery')
            return
        documents = {'invalid-json': b'{', 'missing-director': b'{}',
            'wrong-type': b'{"director_endpoint":3}', 'oversized': b' ' * 100000,
            'duplicate-key': b'{"director_endpoint":"x","director_endpoint":"y"}',
            'long-director': json.dumps({'director_endpoint': 'x' * 600}).encode()}
        body = documents.get(mode, json.dumps({'director_endpoint': self.server.url}).encode())
        self.respond(200, body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        self.server.posts.append((self.path, self.headers.get('Authorization'), body))
        if self.server.mode == 'post-error':
            self.respond(403)
        elif self.server.mode == 'cross-origin':
            self.respond(307, location=f'https://{HOST}:1/must-not-receive-token')
        else:
            self.respond(204)


@pytest.fixture
def director(director_pki):
    _root, key, cert, _public = director_pki
    server = http.server.ThreadingHTTPServer((BIND_HOST, 0), DirectorHandler)
    server.mode, server.posts = 'success', []
    server.url = f'https://{HOST}:{server.server_port}'
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def register(binary, director, pki, mode='normal', key=None, ca=None):
    root, signing_key, _cert, _public = pki
    result = subprocess.run([str(binary), str(director.server_port),
        str(ca or root), str(key or signing_key), mode, HOST],
        capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def verify_token(token, public_key, audience):
    header, payload, signature = token.split('.')
    raw = base64.urlsafe_b64decode(signature + '=' * (-len(signature) % 4))
    assert len(raw) == 64
    encoded = utils.encode_dss_signature(int.from_bytes(raw[:32], 'big'),
                                         int.from_bytes(raw[32:], 'big'))
    key = serialization.load_pem_public_key(public_key)
    key.verify(encoded, (header + '.' + payload).encode(), ec.ECDSA(hashes.SHA256()))
    assert json.loads(base64.urlsafe_b64decode(header + '=' * (-len(header) % 4))) == {
        'alg': 'ES256', 'typ': 'JWT'}
    claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    assert claims['aud'] == audience and claims['iss'] == 'https://cache.example.test/data'
    assert claims['nbf'] <= time.time() <= claims['exp']
    return claims


@pytest.mark.parametrize('mode', ['success', 'redirect-discovery'])
def test_signed_registration_and_timer_generation(pelican_binary, director, director_pki, mode):
    director.mode = mode
    output = register(pelican_binary, director, director_pki)
    assert 'result=0 generation=2' in output
    assert len(director.posts) == 2
    for generation, (path, authorization, body) in enumerate(director.posts, start=1):
        assert path == '/api/v1.0/director/registerCache'
        assert authorization.startswith('Bearer ')
        claims = verify_token(authorization[7:], director_pki[3], director.url)
        assert claims['scope'] == 'pelican.advertise'
        assert claims['exp'] - claims['iat'] == 60
        ad = json.loads(body)
        assert ad['generationID'] == generation
        assert ad['data-url'] == claims['sub']
        assert ad['capabilities']['Write'] is False


@pytest.mark.parametrize('mode', ['get-error', 'invalid-json', 'missing-director',
    'wrong-type', 'oversized', 'duplicate-key', 'long-director'])
def test_invalid_discovery_never_sends_credentials(pelican_binary, director, director_pki, mode):
    director.mode = mode
    assert 'result=-1' in register(pelican_binary, director, director_pki)
    assert director.posts == []


@pytest.mark.parametrize('mode', ['post-error', 'cross-origin'])
def test_refused_registration_is_reported(pelican_binary, director, director_pki, mode):
    director.mode = mode
    assert 'result=-1' in register(pelican_binary, director, director_pki)
    assert len(director.posts) == 2


@pytest.mark.parametrize('mode', ['disabled', 'no-data'])
def test_incomplete_configuration_never_advertises(pelican_binary, director, director_pki, mode):
    assert 'result=-1' in register(pelican_binary, director, director_pki, mode)
    assert director.posts == []


def test_untrusted_director_and_missing_key_fail_closed(pelican_binary, director,
                                                       director_pki, tmp_path):
    assert 'result=-1' in register(pelican_binary, director, director_pki, ca=tmp_path)
    assert 'result=-1' in register(pelican_binary, director, director_pki,
                                   key=tmp_path / 'missing')
    assert director.posts == []
