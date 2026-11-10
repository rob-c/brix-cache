"""Transformed blocks retain exact logical bytes and reject damaged physical records."""

import errno
import struct
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def xform_binary(server_native_compile):
    names = ('malloc', 'pread64', 'write', 'ftruncate64', 'ZSTD_compress')
    return server_native_compile('pblock-xform', 'tests/c/pblock_xform_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


def invoke(binary, operation, path, codec='crypt', mode='normal'):
    result = subprocess.run([str(binary), operation, mode, codec, str(path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = result.stdout.splitlines()
    return tuple(map(int, rows[0].split())), bytes.fromhex(rows[1]) if len(rows) > 1 else b''


@pytest.mark.parametrize('codec', ['crypt', 'zstd'])
@pytest.mark.parametrize('store_mode,load_mode', [('normal', 'normal'),
    ('write-interrupt', 'read-interrupt'), ('short-write', 'short-read')])
def test_transform_roundtrip_preserves_logical_length_and_zero_tail(xform_binary, tmp_path, codec, store_mode, load_mode):
    path = tmp_path / 'block'
    assert invoke(xform_binary, 'store', path, codec, store_mode)[0][0] == 0
    counts, payload = invoke(xform_binary, 'load', path, codec, load_mode)
    assert counts[:3] == (0, 0, 37)
    assert payload == bytes(index % 7 for index in range(37)) + bytes(27)


@pytest.mark.parametrize('operation,mode,error', [('store', 'allocate', errno.ENOMEM),
    ('store', 'write-error', errno.ENOSPC), ('store', 'body-write', errno.ENOSPC),
    ('store', 'truncate', errno.EIO), ('store', 'compress', errno.EIO),
    ('load', 'allocate', errno.ENOMEM), ('load', 'read-error', errno.EIO), ('load', 'body-error', errno.EIO)])
def test_transform_io_failures_cannot_report_completed_bytes(xform_binary, tmp_path, operation, mode, error):
    path = tmp_path / 'block'
    assert invoke(xform_binary, 'store', path, 'zstd')[0][0] == 0
    assert invoke(xform_binary, operation, path, 'zstd', mode)[0][:3] == (-1, error, 0)


@pytest.mark.parametrize('record', [b'123', struct.pack('<II', 65, 1) + b'x',
    struct.pack('<II', 1, 585), struct.pack('<II', 7, 7) + b'abc',
    struct.pack('<II', 7, 6) + b'abcdef'])
@pytest.mark.parametrize('codec', ['crypt', 'zstd'])
def test_corrupt_headers_or_short_payloads_are_refused(xform_binary, tmp_path, record, codec):
    path = tmp_path / 'block'; path.write_bytes(record)
    assert invoke(xform_binary, 'load', path, codec)[0][:3] == (-1, errno.EIO, 0)


@pytest.mark.parametrize('present', [False, True])
def test_missing_and_fresh_empty_blocks_are_zero_filled_holes(xform_binary, tmp_path, present):
    path = tmp_path / 'block'
    if present:
        path.touch()
    counts, payload = invoke(xform_binary, 'load', path)
    assert counts[:3] == (0, 0, 0) and payload == bytes(64)


def test_unknown_transform_cannot_store_or_decode_a_record(xform_binary, tmp_path):
    path = tmp_path / 'block'
    assert invoke(xform_binary, 'store', path, 'unknown')[0][:2] == (-1, errno.ENOTSUP)
    assert not path.exists()
    path.write_bytes(struct.pack('<II', 1, 1) + b'x')
    assert invoke(xform_binary, 'load', path, 'unknown')[0][:2] == (-1, errno.ENOTSUP)


@pytest.mark.parametrize('spec,error,kind', [('<null>', 0, 0), ('', 0, 0), ('zstd', 0, 2),
    ('crypt:', errno.EINVAL, 0), ('unknown', errno.EINVAL, 0),
    ('crypt:' + 'a' * 4096, errno.EINVAL, 0)])
def test_transform_configuration_is_bounded_and_explicit(xform_binary, tmp_path, spec, error, kind):
    assert invoke(xform_binary, 'config', tmp_path / 'unused', spec)[0] == (-int(bool(error)), error, 0, kind)


@pytest.mark.parametrize('content,error', [(b'', errno.EINVAL), (b'key material', 0)])
def test_keyfile_must_have_readable_nonempty_material(xform_binary, tmp_path, content, error):
    path = tmp_path / 'key'; path.write_bytes(content)
    counts, _ = invoke(xform_binary, 'config', path, 'crypt:' + str(path))
    assert counts[:2] == (-int(bool(error)), error)


@pytest.mark.parametrize('operation', ['load', 'store'])
def test_directory_is_never_accepted_as_a_block(xform_binary, tmp_path, operation):
    assert invoke(xform_binary, operation, tmp_path)[0][0] == -1
