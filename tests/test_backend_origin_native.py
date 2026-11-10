"""Configured origin grammars retain exact routing and fail closed on bad input."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def backend_origin(server_native_compile):
    return server_native_compile('backend-origin', 'tests/c/backend_origin_native_test.c')


def invoke(binary, family, value, *, root='normal', expected=0):
    result = subprocess.run([str(binary), family, value, root, str(expected)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return dict(line.split('=', 1) for line in result.stdout.splitlines())


@pytest.mark.parametrize('family,value,fields', [
    ('ceph', 'ceph:objects', {'backend': 'ceph', 'pool': 'objects', 'conf': '/etc/ceph/ceph.conf'}),
    ('ceph', 'ceph:objects@/cluster.conf?tenant/', {'pool': 'objects', 'conf': '/cluster.conf', 'prefix': 'tenant/'}),
    ('ceph', 'ceph:objects?tenant/', {'pool': 'objects', 'prefix': 'tenant/'}),
    ('rados', 'rados://objects', {'backend': 'ceph', 'pool': 'objects', 'prefix': ''}),
    ('rados', 'rados://objects/tenant/sub', {'pool': 'objects', 'prefix': 'tenant/sub'}),
    ('cephfs', 'cephfsro:metadata+data?assume_quiesced=1',
     {'backend': 'cephfsro', 'pool': 'metadata', 'data_pool': 'data', 'quiesced': '1', 'live': '0'}),
    ('cephfs', 'cephfsro:metadata+data@/cluster.conf?live=1',
     {'conf': '/cluster.conf', 'quiesced': '0', 'live': '1'}),
    ('cephfs', 'cephfsro:metadata+data?live=1&assume_quiesced=1', {'quiesced': '1', 'live': '1'}),
    ('tape', 'tape://stub/archive', {'backend': 'tape', 'host': 'stub', 'path': '/archive', 'arc': '0'}),
    ('tape', 'frm:///archive?arc=8', {'host': '', 'path': '/archive', 'arc': '8'}),
    ('s3', 's3://origin.invalid/bucket', {'backend': 's3', 'host': 'origin.invalid', 'port': '7480', 'path': 'bucket'}),
    ('s3', 's3://origin.invalid:9000///bucket?nearline=1&restore_days=7&put_checksum=1',
     {'port': '9000', 'path': 'bucket', 'nearline': '1', 'restore_days': '7', 'checksum': '1'}),
    ('ftp', 'ftp://origin.invalid', {'backend': 'gsiftp', 'host': 'origin.invalid', 'path': '/', 'tls': '0'}),
    ('ftp', 'gsiftp://origin.invalid:2811/archive', {'port': '2811', 'path': '/archive', 'tls': '1'}),
    ('root', 'root://origin.invalid:1094', {'backend': 'xroot', 'host': 'origin.invalid', 'port': '1094', 'tls': '0'}),
    ('root', 'roots+tape://origin.invalid:1095', {'port': '1095', 'tls': '1', 'nearline': '1'}),
    ('root', 'root+tape://origin.invalid:1094', {'tls': '0', 'nearline': '1'}),
    ('root', 'roots://origin.invalid:1094', {'tls': '1', 'nearline': '0'}),
    ('forward', 'forward://root', {'backend': 'xroot_fwd', 'root': '1', 'roots': '0', 'host': '', 'path': '/'}),
    ('forward', 'forward://roots', {'root': '0', 'roots': '1'}),
    ('forward', 'forward://roots,root', {'root': '1', 'roots': '1'}),
])
def test_origin_registration_preserves_declared_route(backend_origin, family, value, fields):
    observed = invoke(backend_origin, family, value)
    assert observed['registered'] == '1'
    assert fields.items() <= observed.items()


@pytest.mark.parametrize('family,value', [
    ('ceph', 'ceph:@/cluster.conf'), ('ceph', 'ceph:?prefix'),
    ('rados', 'rados://'), ('rados', 'rados:///tenant'),
    ('rados', 'rados://' + 'a' * 512),
    ('cephfs', 'cephfsro:metadata'), ('cephfs', 'cephfsro:+data?live=1'),
    ('cephfs', 'cephfsro:metadata+?live=1'), ('cephfs', 'cephfsro:metadata+data'),
    ('cephfs', 'cephfsro:metadata+data?live=0'),
    ('tape', 'tape://stub'), ('tape', 'frm://stub/archive?arc=0'),
    ('tape', 'frm://stub/archive?arc=9'), ('tape', 'tape://stub/archive?unknown=1'),
    ('s3', 's3://origin.invalid'), ('s3', 's3:///bucket'), ('s3', 's3://origin.invalid/'),
    ('s3', 's3://origin.invalid:0/bucket'), ('s3', 's3://origin.invalid:65536/bucket'),
    ('s3', 's3://origin.invalid:bad/bucket'),
    ('ftp', 'ftp:///base'), ('ftp', 'ftp://origin.invalid:0/base'),
    ('ftp', 'ftp://origin.invalid/base/../secret'), ('ftp', 'gsiftp://origin.invalid/./secret'),
    ('ftp', 'gsiftp://origin.invalid/base?injected=1'), ('ftp', 'ftp://origin.invalid/base#fragment'),
    ('ftp', 'ftp://origin.invalid/base\\secret'), ('ftp', 'ftp://origin.invalid/base\x7f'),
    ('root', 'root://origin.invalid'), ('root', 'root://:1094'),
    ('root', 'roots://origin.invalid:0'), ('root', 'roots://origin.invalid:65536'),
    ('root', 'roots://origin.invalid:bad'), ('root', 'unknown://origin.invalid'),
    ('forward', 'forward://'), ('forward', 'forward://http'), ('forward', 'forward://root,'),
    ('forward', 'forward://,roots'), ('forward', 'forward://root,,roots'),
])
def test_invalid_origin_cannot_register_an_export(backend_origin, family, value):
    assert invoke(backend_origin, family, value, expected=-1) == {'registered': '0'}


@pytest.mark.parametrize('family', ['ceph', 'rados', 'cephfs', 'tape', 's3', 'ftp', 'forward'])
def test_unrelated_scheme_remains_unclaimed(backend_origin, family):
    assert invoke(backend_origin, family, 'unrelated:value', expected=-5) == {'registered': '0'}


@pytest.mark.parametrize('family,value', [
    ('ceph', 'ceph:objects'), ('rados', 'rados://objects'),
    ('cephfs', 'cephfsro:meta+data?live=1'), ('tape', 'tape://stub/archive'),
    ('s3', 's3://origin.invalid/bucket'), ('ftp', 'ftp://origin.invalid/base'),
    ('root', 'root://origin.invalid:1094'), ('forward', 'forward://root'),
])
@pytest.mark.parametrize('root', ['empty', 'full'])
def test_missing_anchor_or_full_registry_cannot_alias_existing_exports(backend_origin, family, value, root):
    result = invoke(backend_origin, family, value, root=root,
                    expected=-1 if family == 'forward' else 0)
    assert result == {'registered': '0'}
