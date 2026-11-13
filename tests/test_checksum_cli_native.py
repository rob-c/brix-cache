"""Checksum manifest trust boundaries, remote refusals, and metadata TLV records."""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import zlib

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def checksum_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('checksum-cli')
    binary = output / 'xrdcksum'
    plan = client_make(root / 'client', '-n', 'xrdcksum', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    command[command.index('apps/cksum/xrdcksum.o')] = str(root / 'tests/c/checksum_cli_native_test.c')
    wrappers = ['brix_connect', 'brix_close', 'brix_query_cksum', 'brix_tree_walk',
                'brix_cksum_fd', 'open', 'fseek', 'ftell', 'fread', 'malloc']
    command += ['-Wl,--wrap=' + name for name in wrappers]
    linked = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert linked.returncode == 0, linked.stdout + linked.stderr
    return binary


@pytest.fixture
def checksum(checksum_binary):
    def invoke(*arguments, fault='', digest='abcdef12', walk=None):
        environment = dict(os.environ, BRIX_CHECKSUM_FAULT=fault, BRIX_CHECKSUM_DIGEST=digest)
        if walk is not None:
            environment['BRIX_CHECKSUM_WALK_PATH'] = walk
        return subprocess.run([str(checksum_binary), *map(str, arguments)], env=environment,
                              capture_output=True, text=True, timeout=10)
    return invoke


@pytest.mark.parametrize('scheme', ['root', 'roots'])
@pytest.mark.parametrize('root', ['/base', '/base/', '/'])
def test_remote_tree_preserves_relative_names_and_skips_directories(checksum, scheme, root):
    result = checksum('tree', scheme + '://fixture.invalid' + root)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'abcdef12  sub/file\n'
    assert result.stderr.count('QUERY ') == 1


@pytest.mark.parametrize('path', ['/outside/file', '/base-sibling/file', '/base',
                                 '/base/forged\nrecord', '/base/forged\rrecord'])
def test_remote_walker_cannot_forge_or_escape_manifest(checksum, path):
    result = checksum('tree', 'root://fixture.invalid/base', walk=path)
    assert result.returncode == 2 and result.stdout == ''
    assert 'QUERY ' not in result.stderr


@pytest.mark.parametrize('fault', ['query', 'query-empty', 'walk'])
def test_remote_tree_failures_cannot_look_like_empty_success(checksum, fault):
    result = checksum('tree', 'root://fixture.invalid/base', fault=fault)
    assert result.returncode == 2 and result.stdout == ''


@pytest.mark.parametrize('digest,algorithm', [('ABCDEF12', 'adler32'),
    ('a' * 16, 'crc64'), ('b' * 32, 'md5')])
def test_remote_check_infers_algorithm_and_compares_case_insensitively(checksum, tmp_path,
                                                                    digest, algorithm):
    manifest = tmp_path / 'manifest'
    manifest.write_text(digest + '  nested/data\n')
    result = checksum('check', manifest, 'root://fixture.invalid/base', digest=digest.lower())
    assert result.returncode == 0 and result.stdout == 'OK nested/data\n'
    assert f'QUERY {algorithm} /base/nested/data' in result.stderr


@pytest.mark.parametrize('algorithm', ['crc32c', 'crc64nvme', 'zcrc32'])
def test_explicit_algorithm_is_forwarded_unchanged(checksum, tmp_path, algorithm):
    manifest = tmp_path / 'manifest'
    manifest.write_text('abcdef12  data\n')
    result = checksum('check', manifest, 'roots://fixture.invalid/base', '--algo', algorithm)
    assert result.returncode == 0 and f'QUERY {algorithm} ' in result.stderr


@pytest.mark.parametrize('record', ['abcdef12  ../outside', 'abcdef12  /absolute',
    'not-a-manifest', '001122  data', 'abcdef12  nested/../../outside'])
def test_untrusted_manifest_is_rejected_before_remote_query(checksum, tmp_path, record):
    manifest = tmp_path / 'manifest'
    manifest.write_text(record + '\r\n')
    result = checksum('check', manifest, 'root://fixture.invalid/base')
    assert result.returncode == 2 and result.stdout == ''
    assert 'QUERY ' not in result.stderr


@pytest.mark.parametrize('fault', ['query', 'query-empty'])
def test_remote_check_refusal_is_an_error_not_a_mismatch(checksum, tmp_path, fault):
    manifest = tmp_path / 'manifest'
    manifest.write_text('abcdef12  data\n')
    result = checksum('check', manifest, 'root://fixture.invalid/base', fault=fault)
    assert result.returncode == 2 and result.stdout == ''


def test_manifest_errors_take_precedence_and_do_not_stop_later_lines(checksum, tmp_path):
    manifest = tmp_path / 'manifest'
    manifest.write_text('00000000  mismatch\nbad-record\nabcdef12  good\n')
    result = checksum('check', manifest, 'root://fixture.invalid/base')
    assert result.returncode == 2
    assert result.stdout.splitlines() == ['FAILED mismatch', 'OK good']


@pytest.mark.parametrize('verb', ['tree', 'check'])
@pytest.mark.parametrize('url,fault', [('root://', ''), ('http://fixture.invalid/base', ''),
                                    ('root://fixture.invalid/base', 'connect')])
def test_preflight_errors_close_output_and_manifest(checksum, tmp_path, verb, url, fault):
    manifest = tmp_path / 'manifest'
    manifest.write_text('abcdef12  data\n')
    arguments = [url, '-o', str(tmp_path / 'output')]
    if verb == 'check':
        arguments = [str(manifest), url]
    result = checksum(verb, *arguments, fault=fault)
    assert result.returncode != 0 and result.stdout == ''


@pytest.mark.parametrize('verb', ['tree', 'check'])
@pytest.mark.parametrize('fault', ['open', 'checksum', 'checksum-empty'])
def test_local_io_errors_close_descriptors(checksum, tmp_path, verb, fault):
    data = tmp_path / 'data'
    data.mkdir()
    (data / 'file').write_bytes(b'payload')
    manifest = tmp_path / 'manifest'
    manifest.write_text('abcdef12  file\n')
    arguments = [str(data)] if verb == 'tree' else [str(manifest), str(data)]
    result = checksum(verb, *arguments, fault=fault)
    assert result.returncode == 2 and result.stdout == ''


def test_local_tree_omits_symlink_escape_and_replays_real_digest(checksum, tmp_path):
    data = tmp_path / 'data'
    data.mkdir()
    (data / 'file').write_bytes(b'payload')
    (data / 'escape').symlink_to('/etc/passwd')
    manifest = tmp_path / 'manifest'
    result = checksum('tree', str(data) + '/', '-o', manifest)
    assert result.returncode == 0 and result.stdout == ''
    assert manifest.read_text() == f'{zlib.adler32(b"payload"):08x}  file\n'
    checked = checksum('check', manifest, data)
    assert checked.returncode == 0 and checked.stdout == 'OK file\n'


@pytest.mark.parametrize('arguments', [('tree',), ('tree', '--algo'), ('tree', '-o'),
    ('tree', '--invalid'), ('tree', 'a', 'b'), ('tree', 'a', '--algo', 'invalid'),
    ('check',), ('check', 'm', 'r', '--algo'), ('check', 'm', 'r', '--algo', 'invalid'),
    ('check', 'm', 'r', 'extra')])
def test_cli_usage_refusals(checksum, arguments):
    result = checksum(*arguments)
    assert result.returncode != 0 and result.stdout == ''


@pytest.mark.parametrize('arguments', [('tree', '--help'), ('check', 'm', 'r', '--help')])
def test_cli_help_does_not_open_paths(checksum, arguments):
    result = checksum(*arguments)
    assert result.returncode == 0 and 'usage:' in result.stderr


def metadata_record(sections=(), size=12, block=4, bitmap=5, unverified=1):
    header = bytearray(56)
    struct.pack_into('<iqq', header, 0, 4, block, size)
    struct.pack_into('<q', header, 28, unverified)
    body = bytes(header) + bytes([bitmap]) + b'\0' * 4
    extension = b'XCX1' + struct.pack('<HH', 1, len(sections))
    for kind, payload in sections:
        extension += struct.pack('<HHI', kind, 0, len(payload)) + payload + b'\0' * 4
    return body + extension


def test_metadata_extensions_report_state_crc_and_escaped_digests(checksum, tmp_path):
    state = bytearray(80)
    struct.pack_into('<QQQQ', state, 0, 42, 4, 9, 7)
    struct.pack_into('<II', state, 72, 0o640, 1)
    crcs = struct.pack('<IIQIII', 4, 0, 3, 123, 0, 456)
    value = b'a"\\\x01\xff'
    digests = struct.pack('<HH', 1, len(value)) + value + struct.pack('<HH', 2, 2) + b'ff'
    path = tmp_path / 'record'
    path.write_bytes(metadata_record([(1, state), (3, crcs), (2, digests), (99, b'ignored')]))
    result = checksum('info', path)
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    assert record['present_blocks'] == [0, 2] and not record['complete']
    assert record['origin_mtime'] == 42 and record['flush_gen'] == 7 and record['mode'] == 0o640
    assert record['flags'] == ['PARTIAL', 'DIRTY', 'VERIFIED', 'UNVERIFIED_BLOCKS']
    assert record['blockcrc'] == {'granule': 4, 'nblocks': 3, 'computed': 2}
    assert record['digests'] == [{'alg': 1, 'value': value.decode('latin1')}, {'alg': 2, 'value': 'ff'}]


@pytest.mark.parametrize('sections', [[(1, b'short')], [(3, b'short')],
    [(2, struct.pack('<HH', 1, 50) + b'cut')], [(99, b'unknown')]])
def test_short_and_unknown_extensions_preserve_valid_geometry(checksum, tmp_path, sections):
    path = tmp_path / 'record'
    path.write_bytes(metadata_record(sections))
    result = checksum('info', path)
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    assert record['size'] == 12 and record['present_blocks'] == [0, 2]
    assert record['mode'] == 0 and 'blockcrc' not in record


@pytest.mark.parametrize('fault', ['seek', 'tell', 'short-read', 'allocation'])
def test_metadata_io_failures_release_file_and_buffer(checksum, tmp_path, fault):
    path = tmp_path / 'record'
    path.write_bytes(metadata_record())
    result = checksum('info', path, fault=fault)
    assert result.returncode == 3 and json.loads(result.stdout) == {'absent': True}


@pytest.mark.parametrize('offset,encoding,value', [(4, '<q', 0), (12, '<q', -1),
                                                 (48, '<i', -1)])
def test_invalid_geometry_cannot_be_rendered_as_valid(checksum, tmp_path, offset, encoding, value):
    record = bytearray(metadata_record())
    struct.pack_into(encoding, record, offset, value)
    path = tmp_path / 'record'
    path.write_bytes(record)
    result = checksum('info', path)
    assert result.returncode == 2 and json.loads(result.stdout) == {'error': 'bad_magic'}
