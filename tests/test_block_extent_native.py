"""The production block driver confines reads and writes to each fixed extent."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def block_extent(server_native_compile):
    return server_native_compile('block-extent', 'tests/c/block_extent_native_test.c',
        ['-Wl,--wrap=ngx_pcalloc,--wrap=ngx_pnalloc,--wrap=ngx_calloc'])


def invoke(binary, tmp_path, op, key='/1', value=0, expected=0, *, extent=512, remove=False):
    device = tmp_path / 'device'
    original = prepare_device(device, op)
    result = subprocess.run([str(binary), str(device), str(extent), op, key, str(value),
        str(expected), 'remove' if remove else 'keep'], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    return result.stdout, device, original


def prepare_device(device, op):
    original = bytes(index % 251 for index in range(1025))
    if op != 'init-missing':
        device.write_bytes(b'' if op == 'init-empty' else original)
    return original


@pytest.mark.parametrize('key,expected', [('/', '1:0'), ('', '1:0'), ('<null>', '1:0'),
    ('0', '0:512'), ('/1', '0:512'), ('/2', '0:1')])
def test_metadata_reports_logical_extent_geometry(block_extent, tmp_path, key, expected):
    output, _device, _original = invoke(block_extent, tmp_path, 'stat', key)
    assert output.decode() == expected


@pytest.mark.parametrize('key', ['/', '', '<null>'])
@pytest.mark.parametrize('extent,listing', [(0, b'0\n'), (512, b'0\n1\n2\n'), (4096, b'0\n')])
def test_directory_lists_exactly_the_fixed_extent_set(block_extent, tmp_path, key, extent, listing):
    output, _device, _original = invoke(block_extent, tmp_path, 'list', key, extent=extent)
    assert output == listing


@pytest.mark.parametrize('key', ['/3', '/-1', '/2147483648', '/99999999999999999999',
    '/1/2', '/../1', '//1', '/1x'])
@pytest.mark.parametrize('op', ['stat', 'open'])
def test_non_extent_paths_cannot_access_device_bytes(block_extent, tmp_path, key, op):
    _output, device, original = invoke(block_extent, tmp_path, op, key, expected=errno.ENOENT)
    assert device.read_bytes() == original


@pytest.mark.parametrize('key', ['/', '', '<null>'])
def test_root_cannot_be_opened_as_a_file(block_extent, tmp_path, key):
    invoke(block_extent, tmp_path, 'open', key, expected=errno.EISDIR)


@pytest.mark.parametrize('key', ['/0', '/missing', '/../'])
def test_objects_and_escape_paths_are_not_directories(block_extent, tmp_path, key):
    invoke(block_extent, tmp_path, 'list', key, expected=errno.ENOTDIR)


@pytest.mark.parametrize('op,width', [('read', 16), ('vector', 64), ('vector2', 64)])
@pytest.mark.parametrize('offset', [-1, 0, 505, 511, 512, 513])
def test_reads_stop_at_the_extent_boundary(block_extent, tmp_path, op, width, offset):
    output, device, original = invoke(block_extent, tmp_path, op, value=offset)
    expected = original[512 + offset:512 + min(512, offset + width)] if 0 <= offset < 512 else b''
    assert output == expected
    assert device.read_bytes() == original


@pytest.mark.parametrize('offset', [-1, 497, 511, 512])
def test_cross_extent_writes_fail_without_modifying_neighbors(block_extent, tmp_path, offset):
    _output, device, original = invoke(block_extent, tmp_path, 'write', value=offset, expected=errno.ENOSPC)
    assert device.read_bytes() == original


@pytest.mark.parametrize('offset', [0, 496])
def test_in_bounds_writes_change_only_the_addressed_extent(block_extent, tmp_path, offset):
    _output, device, original = invoke(block_extent, tmp_path, 'write', value=offset)
    expected = bytearray(original)
    expected[512 + offset:528 + offset] = b'0123456789abcdef'
    assert device.read_bytes() == expected


@pytest.mark.parametrize('key,size,expected', [('/1', 512, 0), ('/1', 513, errno.ENOSPC),
    ('/2', 1, 0), ('/2', 2, errno.ENOSPC)])
def test_reservation_cannot_grow_a_fixed_extent(block_extent, tmp_path, key, size, expected):
    invoke(block_extent, tmp_path, 'reserve', key, size, expected)


@pytest.mark.parametrize('op', ['init-alloc', 'open-alloc', 'list-alloc'])
@pytest.mark.parametrize('allocation', [1, 2])
def test_allocation_failure_preserves_device_contents(block_extent, tmp_path, op, allocation):
    _output, device, original = invoke(block_extent, tmp_path, op, '/' if op == 'list-alloc' else '/1',
                                       allocation, errno.ENOMEM)
    assert device.read_bytes() == original


@pytest.mark.parametrize('op,expected', [('init-null', errno.EINVAL), ('init-empty-name', errno.EINVAL),
    ('init-empty', errno.ENODEV), ('init-missing', errno.ENOENT), ('vector-invalid', errno.EINVAL),
    ('bad-fd', 0)])
def test_invalid_configuration_and_io_errors_are_reported(block_extent, tmp_path, op, expected):
    invoke(block_extent, tmp_path, op, expected=expected)


def test_removed_device_is_never_recreated_by_open_flags(block_extent, tmp_path):
    _output, device, _original = invoke(block_extent, tmp_path, 'open', expected=errno.ENOENT, remove=True)
    assert not device.exists()
