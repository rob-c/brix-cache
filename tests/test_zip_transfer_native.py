"""ZIP transfer ownership and failure contracts, using independently built archives."""

from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def zip_transfer(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    binary = compile_client_contract(root, tmp_path_factory.mktemp('zip-transfer'),
        'tests/c/zip_transfer_native_test.c', ('brix_connect', 'brix_close', 'brix_stat',
        'brix_file_open_read', 'brix_file_open_write', 'brix_file_open_update',
        'brix_file_read', 'brix_file_write', 'brix_file_close', 'open_download_temp',
        'write', 'rename'))
    def invoke(operation, source, dest, mode='', force=False, append=False,
               expected=0, member='payload'):
        result = subprocess.run([str(binary), operation, str(source), str(dest), mode,
            str(int(force)), str(int(append)), str(expected), member],
            capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        return result
    return invoke


def make_archive(path, compression=zipfile.ZIP_STORED, data=b'archive payload\x00\xff' * 100):
    with zipfile.ZipFile(path, 'w', compression=compression) as archive:
        archive.writestr('payload', data)
    return data


def assert_no_partial(dest):
    assert not list(dest.parent.glob(dest.name + '.xrdcp-tmp.*'))


@pytest.mark.parametrize('compression', [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
@pytest.mark.parametrize('mode', ['', 'sink-intr', 'sink-short', 'stdout'])
def test_extraction_preserves_exact_bytes_and_closes_resources(zip_transfer, tmp_path, compression, mode):
    source, dest = tmp_path / 'source.zip', tmp_path / 'dest'
    data = make_archive(source, compression)
    result = zip_transfer('unzip', source, dest, mode)
    output = result.stdout if mode == 'stdout' else dest.read_bytes()
    assert output == data
    assert_no_partial(dest)


@pytest.mark.parametrize('mode,hint', [('connect', 'connect refused'), ('stat', 'stat refused'),
    ('open', 'open refused'), ('read', 'ZIP open failed'), ('sink-error', 'extract failed'),
    ('rename', 'rename to')])
def test_extraction_failure_preserves_previous_destination(zip_transfer, tmp_path, mode, hint):
    source, dest = tmp_path / 'source.zip', tmp_path / 'dest'
    make_archive(source)
    dest.write_bytes(b'previous data')
    result = zip_transfer('unzip', source, dest, mode, force=True, expected=-1)
    assert hint in result.stderr.decode()
    assert dest.read_bytes() == b'previous data'
    assert_no_partial(dest)


@pytest.mark.parametrize('malformed,hint', [('absent', 'member not found'),
    ('garbage', 'ZIP open failed'), ('crc', 'extract failed'), ('truncated', 'ZIP open failed')])
def test_untrusted_archive_never_publishes_partial_output(zip_transfer, tmp_path, malformed, hint):
    source, dest = tmp_path / 'source.zip', tmp_path / 'dest'
    data = make_archive(source)
    archive = source.read_bytes()
    replacements = {'garbage': b'not a ZIP', 'crc': archive.replace(data, b'X' + data[1:]),
                    'truncated': archive[:-10]}
    source.write_bytes(replacements.get(malformed, archive))
    member = 'missing' if malformed == 'absent' else 'payload'
    result = zip_transfer('unzip', source, dest, expected=-1, member=member)
    assert hint in result.stderr.decode() and not dest.exists()
    assert_no_partial(dest)


def test_existing_destination_requires_force(zip_transfer, tmp_path):
    source, dest = tmp_path / 'source.zip', tmp_path / 'dest'
    make_archive(source)
    dest.write_bytes(b'keep')
    result = zip_transfer('unzip', source, dest, expected=-1)
    assert 'destination exists' in result.stderr.decode() and dest.read_bytes() == b'keep'
    assert_no_partial(dest)


def test_temp_creation_failure_releases_remote_handle(zip_transfer, tmp_path):
    source, dest = tmp_path / 'source.zip', tmp_path / 'missing/dest'
    make_archive(source)
    result = zip_transfer('unzip', source, dest, expected=-1)
    assert 'open=read' in result.stderr.decode() and not dest.exists()


@pytest.mark.parametrize('operation', ['store', 'remote'])
@pytest.mark.parametrize('append,existing', [(False, False), (True, False), (True, True)])
def test_create_and_append_preserve_members(zip_transfer, tmp_path, operation, append, existing):
    source, dest = tmp_path / 'new-member', tmp_path / 'dest.zip'
    source.write_bytes(b'new data' * 10000)
    if existing:
        make_archive(dest)
    result = zip_transfer(operation, source, dest, append=append)
    with zipfile.ZipFile(dest) as archive:
        assert archive.testzip() is None
        assert archive.read(source.name) == source.read_bytes()
        assert len(archive.namelist()) == 1 + int(existing)
    assert 'result=0' in result.stderr.decode()


@pytest.mark.parametrize('append', [False, True])
@pytest.mark.parametrize('mode,hint', [('connect', 'connect refused'), ('open', 'open refused'),
    ('write', 'zip write failed'), ('close', 'close refused'), ('write-close', 'zip write failed')])
def test_remote_failure_closes_every_owned_resource(zip_transfer, tmp_path, append, mode, hint):
    source, dest = tmp_path / 'new-member', tmp_path / 'dest.zip'
    source.write_bytes(b'payload')
    if append:
        make_archive(dest)
    result = zip_transfer('remote', source, dest, mode, append=append, expected=-1)
    assert hint in result.stderr.decode()


@pytest.mark.parametrize('operation', ['store', 'remote'])
def test_invalid_append_archive_is_not_overwritten(zip_transfer, tmp_path, operation):
    source, dest = tmp_path / 'new-member', tmp_path / 'dest.zip'
    source.write_bytes(b'payload')
    dest.write_bytes(b'not an archive')
    result = zip_transfer(operation, source, dest, append=True, expected=-1)
    assert 'not a valid ZIP' in result.stderr.decode() and dest.read_bytes() == b'not an archive'


@pytest.mark.parametrize('operation', ['store', 'remote'])
@pytest.mark.parametrize('mode', ['stdin', 'missing-source'])
def test_invalid_source_is_rejected_before_destination_open(zip_transfer, tmp_path, operation, mode):
    source, dest = tmp_path / 'missing', tmp_path / 'dest.zip'
    result = zip_transfer(operation, source, dest, mode, expected=-1)
    assert 'connect=0' in result.stderr.decode() and not dest.exists()


def test_missing_local_destination_parent_is_reported(zip_transfer, tmp_path):
    source, dest = tmp_path / 'member', tmp_path / 'missing/dest.zip'
    source.write_bytes(b'payload')
    result = zip_transfer('store', source, dest, expected=-1)
    assert 'open ' in result.stderr.decode() and not dest.exists()
