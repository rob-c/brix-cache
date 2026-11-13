"""Existing native contracts run against the configured server dependency graph."""

import subprocess
import zipfile

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.mark.parametrize('name,driver', [
    ('ssi-provider', 'src/protocols/ssi/provider_unittest.c'),
    ('vfs-core', 'src/fs/core/vfs_core_unittest.c'),
    ('crc64', 'tests/unit/test_crc64.c'),
    ('crc32c', 'tests/unit/test_crc32c.c'),
    ('token-base64', 'tests/unit/test_b64url.c'),
    ('token-json', 'tests/unit/test_json.c'),
    ('token-scopes', 'tests/unit/test_scopes.c'),
    ('xml', 'tests/unit/test_xml_compat.c'),
])
def test_existing_server_unit(server_native_compile, tmp_path, name, driver):
    binary = server_native_compile(name, driver)
    result = subprocess.run([str(binary)], cwd=tmp_path, capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


def test_existing_zip_directory_unit(server_native_compile, tmp_path):
    """Run stored/deflated/ZIP64 reads, missing-member and directory-limit refusals."""
    binary = server_native_compile('zip-directory',
                                  'src/protocols/root/zip/zip_dir_unittest.c')
    archive = tmp_path / 'members.zip'
    with zipfile.ZipFile(archive, 'w') as output:
        output.writestr('stored.txt', b'hello stored member\n')
        output.writestr('sub/defl.bin', bytes((i * 31 + 7) & 255 for i in range(100000)),
                        compress_type=zipfile.ZIP_DEFLATED)
        with output.open('big64.txt', 'w', force_zip64=True) as member:
            member.write(b'zip64 forced member\n')
    result = subprocess.run([str(binary), str(archive)], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'UNITTEST PASSED' in result.stdout
