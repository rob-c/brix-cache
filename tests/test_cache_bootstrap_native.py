"""Real origin bootstrap frames retain TLS ordering and caller identity."""

import socket
import struct
import subprocess

import pytest

from test_cache_origin_wire_native import read_request, send_response
from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def bootstrap(server_native_compile):
    names = ('brix_cache_io_send', 'brix_cache_origin_tls_upgrade',
        'brix_cache_origin_auth_ztn', 'brix_cache_origin_auth_gsi',
        'brix_cache_origin_auth_sss', 'brix_cache_origin_auth_krb5_raw')
    return server_native_compile('cache-bootstrap', 'tests/c/cache_bootstrap_native_test.c',
                                 ['-Wl,--wrap=' + name for name in names])


def invoke(binary, *, user='', service='', advert=b'', login=0, tls=False,
           flags=0, fault='', failed_phase=None, raw=None):
    client, peer = socket.socketpair()
    with client, peer:
        peer.settimeout(10)
        for phase, body in enumerate((b'', struct.pack('!II', 0x511, flags), bytes(16) + advert)):
            status = login if phase == 2 else 0
            if failed_phase == phase:
                send_response(peer, raw, 4003, b'refused')
                break
            send_response(peer, None, status, body)
        peer.shutdown(socket.SHUT_WR)
        result = subprocess.run([str(binary), str(client.fileno()), user, service,
            str(int(tls)), fault], pass_fds=(client.fileno(),), capture_output=True,
            text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        client.close()
        wire = bytes(read_request(peer))
    return dict(line.split('=', 1) for line in result.stdout.splitlines()), wire


@pytest.mark.parametrize('tls,flags', [(False, 0), (True, 0), (True, 0x40000000)])
def test_bootstrap_orders_handshake_protocol_tls_and_login(bootstrap, tls, flags):
    result, wire = invoke(bootstrap, tls=tls, flags=flags)
    assert result['rc'] == '0' and result['auth_count'] == '0'
    assert result['tls'] == str(int(bool(flags))) and result['flags'] == str(flags)
    assert len(wire) == 68
    assert wire[:20] == struct.pack('!IIIII', 0, 0, 0, 4, 2012)
    assert struct.unpack_from('!H', wire, 22)[0] == 3006
    assert struct.unpack_from('!H', wire, 46)[0] == 3007
    assert wire[52:55] == b'xrd'


@pytest.mark.parametrize('user,service,advert,kind,value,extra', [
    ('gsi-ztn-sss-krb5', 'gsi-ztn-sss', b'&P=gsi,v:10600&P=ztn,token', 'gsi', 'caller.proxy', 'v:10600'),
    ('krb5-ztn-sss', 'gsi-ztn-sss', b'&P=krb5,root/origin@REALM&P=ztn,token', 'krb5', 'caller.ccache', 'root/origin@REALM'),
    ('krb5', '', b'&P=krb5', 'krb5', 'caller.ccache', 'root/carried@REALM'),
    ('krb5-no-spn', '', b'&P=krb5', 'krb5', 'caller.ccache', ''),
    ('ztn-sss', 'gsi-ztn-sss', b'&P=ztn,token&P=sss,key', 'ztn', 'caller.token', ''),
    ('sss', 'gsi-ztn-sss', b'&P=sss,key&P=ztn,token', 'sss', 'caller.keytab', 'alice'),
    ('', 'gsi-ztn-sss', b'&P=ztn,token&P=gsi,v:1&P=sss,key', 'ztn', 'service.token', ''),
    ('', 'gsi-sss', b'&P=gsi,v:2&P=sss,key', 'gsi', 'service.proxy', 'v:2'),
    ('', 'sss', b'&P=sss,key', 'sss', 'service.keytab', ''),
    ('gsi', '', b'&P=gsi,' + b'a' * 300, 'gsi', 'caller.proxy', 'a' * 255),
    ('krb5', '', b'&P=krb5,' + b'a' * 600, 'krb5', 'caller.ccache', 'a' * 511),
])
@pytest.mark.parametrize('login', [0, 4002])
def test_selected_credential_and_bounded_advert_are_exact(bootstrap, user, service,
                                                        advert, kind, value, extra, login):
    result, _wire = invoke(bootstrap, user=user, service=service, advert=advert, login=login)
    assert result['rc'] == '0' and result['auth_count'] == '1'
    assert (result['auth'], result['value'], result['extra']) == (kind, value, extra)


@pytest.mark.parametrize('user', ['gsi', 'krb5', 'ztn', 'sss'])
@pytest.mark.parametrize('advert,login', [(b'&P=unknown,1', 0), (b'', 4002)])
def test_caller_never_falls_back_to_service_identity(bootstrap, user, advert, login):
    result, _wire = invoke(bootstrap, user=user, service='gsi-ztn-sss', advert=advert, login=login)
    assert result['rc'] == '-1' and result['error'] == '3030'
    assert result['auth_count'] == '0'


@pytest.mark.parametrize('service', ['', 'gsi', 'sss'])
def test_advertless_authmore_cannot_use_nonbearer_service_keys(bootstrap, service):
    result, _wire = invoke(bootstrap, service=service, login=4002)
    assert result['rc'] == '-1' and result['error'] == '3030'
    assert result['auth_count'] == '0'


def test_advertless_authmore_selects_static_bearer(bootstrap):
    result, _wire = invoke(bootstrap, service='ztn', login=4002)
    assert result['rc'] == '0' and result['value'] == 'service.token'


@pytest.mark.parametrize('service', ['', 'gsi-ztn-sss'])
def test_unusable_advert_distinguishes_missing_and_incompatible_credentials(bootstrap, service):
    result, _wire = invoke(bootstrap, service=service, advert=b'&P=unknown,1')
    assert result['error'] == '3030' and result['auth_count'] == '0'
    assert ('offers no protocol' if service else 'NO credential') in result['message']


@pytest.mark.parametrize('phase', [0, 1, 2])
@pytest.mark.parametrize('raw', [None, b'\0', struct.pack('!HHI', 1, 0, 40960)])
def test_failed_or_truncated_bootstrap_phase_stops_progress(bootstrap, phase, raw):
    result, _wire = invoke(bootstrap, failed_phase=phase, raw=raw)
    assert result['rc'] == '-1' and result['error'] == '3012'
    assert result['sends'] == str(phase + 1) and result['auth_count'] == '0'


@pytest.mark.parametrize('phase', [1, 2, 3])
def test_failed_send_never_advances_to_next_phase(bootstrap, phase):
    result, wire = invoke(bootstrap, fault=str(phase))
    assert result['rc'] == '-1' and result['error'] == '3012'
    assert result['sends'] == str(phase) and len(wire) == [0, 20, 44][phase - 1]


@pytest.mark.parametrize('tls,fault,upgrades', [(False, '', '0'), (True, 'tls', '1')])
def test_required_tls_or_bad_certificate_prevents_login(bootstrap, tls, fault, upgrades):
    result, wire = invoke(bootstrap, tls=tls, flags=0x40000000, fault=fault)
    assert result['rc'] == '-1' and result['error'] == '3028'
    assert result['tls'] == upgrades and len(wire) == 44


@pytest.mark.parametrize('user,advert', [('gsi', b'&P=gsi,v:1'), ('ztn', b'&P=ztn,1'),
                                       ('sss', b'&P=sss,1'), ('krb5', b'&P=krb5')])
def test_provider_refusal_is_terminal_even_with_service_keys(bootstrap, user, advert):
    result, _wire = invoke(bootstrap, user=user, service='gsi-ztn-sss', advert=advert, fault='auth')
    assert result['rc'] == '-1' and result['auth_count'] == '1'
    assert result['error'] == '3030' and result['message'] == 'provider refused'
