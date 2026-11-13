"""Catalog-native scans must report real bytes without modifying stored metadata."""

import hashlib
import json
import subprocess
import zlib

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def scan_binary(server_native_compile):
    return server_native_compile('scan-catalog', 'tests/c/scan_catalog_native_test.c',
                                 ['-Wl,--wrap=ngx_alloc'])


def scan(binary, root, mode, case='normal', algorithm='adler32', count=3):
    result = subprocess.run([str(binary), str(root), mode, case, algorithm, str(count)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


@pytest.mark.parametrize('count', [0, 1, 400])
def test_inventory_lists_only_files_and_escapes_paths(scan_binary, tmp_path, count):
    records = scan(scan_binary, tmp_path, 'inventory', count=count)
    assert len(records) == count
    for index, record in enumerate(records):
        name = f'/nested/file-{index:04d}"\\\n'
        assert record['t'] == 'object' and record['size'] == 5
        assert record['path'] == name and record['key'] == name
        assert record['orphan'] is False


@pytest.mark.parametrize('algorithm,checksum', [
    ('adler32', f'{zlib.adler32(b"hello"):08x}'),
    ('md5', hashlib.md5(b'hello').hexdigest()),
    ('sha256', hashlib.sha256(b'hello').hexdigest())])
def test_verify_computes_bytes_without_writing_checksum_cache(scan_binary, tmp_path,
                                                             algorithm, checksum):
    records = scan(scan_binary, tmp_path, 'verify', algorithm=algorithm)
    assert len(records) == 3
    for record in records:
        assert record['status'] == 'missing' and record['stored'] is None
        assert record['computed'] == checksum and record['size'] == 5


@pytest.mark.parametrize('case,algorithm', [('lost', 'adler32'), ('normal', 'unknown')])
def test_unreadable_objects_do_not_abort_catalog_walk(scan_binary, tmp_path, case, algorithm):
    records = scan(scan_binary, tmp_path, 'verify', case, algorithm)
    assert len(records) == 3
    assert all(record['status'] == 'unreadable' for record in records)


@pytest.mark.parametrize('mode', ['inventory', 'verify'])
@pytest.mark.parametrize('case', ['oom', 'unsupported', 'catalog-error'])
def test_failed_scans_preserve_existing_objects(scan_binary, tmp_path, mode, case):
    assert scan(scan_binary, tmp_path, mode, case) == []
