"""TPC TLS publishes verified state only for a trusted peer and its owning fd."""

import ipaddress
import os
import socket
import ssl
import subprocess
import threading

import pytest
from cryptography import x509

from test_nginx_native_contract import server_native_compile  # noqa: F401
from x509forge import make_ca, make_eec


@pytest.fixture(scope='module')
def tpc_tls(server_native_compile):
    wrappers = ('SSL_CTX_new', 'SSL_new', 'SSL_set_fd', 'SSL_CTX_set_default_verify_paths',
                'X509_VERIFY_PARAM_set1_host', 'SSL_ctrl', 'SSL_get_verify_result')
    return server_native_compile('tpc-tls', 'tests/c/tpc_tls_native_test.c',
                                 ['-Wl,--wrap=' + name for name in wrappers])


@pytest.fixture(scope='module')
def tls_material(tmp_path_factory):
    root = tmp_path_factory.mktemp('tpc-tls-certificates')
    authority = make_ca('/CN=TPC TLS authority', key_type='ec')
    leaf = make_eec(authority, '/CN=TPC source', key_type='ec',
                    eku=[x509.ExtendedKeyUsageOID.SERVER_AUTH.dotted_string],
                    extra_ext=[(x509.SubjectAlternativeName([
                        x509.IPAddress(ipaddress.ip_address('127.0.0.1')),  # net-literal-allow: certificate SAN bytes under test
                        x509.DNSName('source.example')]), False)])
    for name, data in [('trust.pem', authority.pem), ('server.pem', leaf.pem),
                       ('server.key', leaf.key_pem), ('other.pem',
                        make_ca('/CN=Unrelated TPC authority', key_type='ec').pem)]:
        (root / name).write_bytes(data)
    return root


def exercise(binary, root, mode, *, hostname='source.example', trust='trust.pem', success=False):
    """Use one bounded TLS socketpair; a refused handshake must send no payload."""
    client, peer = socket.socketpair()
    peer.settimeout(5)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / 'server.pem', root / 'server.key')
    received = []

    def serve():
        try:
            with context.wrap_socket(peer, server_side=True) as connection:
                received.append(connection.recv(64))
        except (ssl.SSLError, ConnectionError):
            pass

    thread = threading.Thread(target=serve)
    thread.start()
    environment = dict(os.environ, SSL_CERT_FILE=str(root / 'trust.pem'),
                       SSL_CERT_DIR=str(root / 'no-default-directory'))
    try:
        result = subprocess.run([str(binary), mode, str(client.fileno()),
                                 str(root / trust) if trust else '', hostname, str(int(success))],
                                pass_fds=(client.fileno(),), capture_output=True,
                                text=True, timeout=10, env=environment)
    finally:
        client.close()
        thread.join(timeout=6)
        peer.close()
    assert not thread.is_alive()
    assert result.returncode == 0, result.stdout + result.stderr
    assert b''.join(received) == (b'verified' if success else b'')


@pytest.mark.parametrize('mode', ['primary', 'substream'])
@pytest.mark.parametrize('hostname', ['source.example', '127.0.0.1', '::ffff:127.0.0.1'])  # net-literal-allow: IPv4 and mapped-IPv6 certificate identity inputs
@pytest.mark.parametrize('trust', ['trust.pem', ''])
def test_verified_socket_is_published_and_teardown_is_idempotent(tpc_tls, tls_material,
                                                               mode, hostname, trust):
    exercise(tpc_tls, tls_material, mode, hostname=hostname, trust=trust, success=True)


@pytest.mark.parametrize('mode,hostname,trust', [
    ('unowned', 'source.example', 'trust.pem'),
    ('primary', 'other.example', 'trust.pem'),
    ('primary', 'source.example', 'other.pem'),
    ('primary', '', 'trust.pem'),
    ('invalid-path', 'source.example', 'trust.pem'),
])
def test_untrusted_or_unowned_socket_never_receives_credentials(tpc_tls, tls_material,
                                                               mode, hostname, trust):
    exercise(tpc_tls, tls_material, mode, hostname=hostname, trust=trust)


@pytest.mark.parametrize('mode', ['context-failure', 'session-failure', 'descriptor-failure',
                                'name-failure', 'sni-failure', 'post-verify-failure',
                                'default-failure'])
def test_tls_setup_failures_leave_no_authenticated_socket(tpc_tls, tls_material, mode):
    exercise(tpc_tls, tls_material, mode, trust='' if mode == 'default-failure' else 'trust.pem')
