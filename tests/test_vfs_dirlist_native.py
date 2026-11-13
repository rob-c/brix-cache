"""Worker directory listings preserve framing, fd confinement and read-only data."""

import errno
import hashlib
import os
import struct
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def dirlist_binary(server_native_compile):
    return server_native_compile('vfs-dirlist', 'tests/c/vfs_dirlist_native_test.c',
                                 ['-Wl,--wrap=readdir64', '-Wl,--wrap=fstatat64'])


def listing(binary, directory, mode='names', capacity=262176, fault=''):
    """Decode every frame independently and reject trailing or truncated bytes."""
    environment = dict(os.environ, BRIX_DIRLIST_FAULT=fault)
    result = subprocess.run([str(binary), str(directory), str(capacity), mode],
                            env=environment, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    summary, wire = result.stdout.split(b'\n', 1)
    status, error, size = map(int, summary.split())
    assert size == len(wire)
    return status, error, decode_frames(wire)


def decode_frames(wire):
    """The repository wire spec requires stream IDs, bounded chunks and final ok."""
    frames = []
    while wire:
        stream, status, size = struct.unpack('!2sHI', wire[:8])
        assert stream == b'\x17\x39'
        assert size <= 65536
        body, wire = wire[8:8 + size], wire[8 + size:]
        assert len(body) == size
        assert status == (4000 if wire else 0)
        frames.append(body)
    return frames


def names_from(frames):
    return set(b''.join(frames).rstrip(b'\0').splitlines())


def seed_names(directory, count):
    names = {f'{index:05d}-' + 'x' * 110 for index in range(count)}
    for name in names:
        (directory / name).touch()
    return set(map(str.encode, names))


@pytest.mark.parametrize('count,frame_count', [(0, 1), (1, 1), (17, 1), (700, 2)])
def test_directory_chunks_preserve_all_names(dirlist_binary, tmp_path, count,
                                              frame_count):
    names = seed_names(tmp_path, count)
    status, error, frames = listing(dirlist_binary, tmp_path)
    assert (status, error) == (0, 0)
    assert names_from(frames) == names
    assert len(frames) == frame_count


@pytest.mark.parametrize('fault,capacity,error', [
    ('invalid-fd', 65544, errno.EINVAL), ('null-buffer', 65544, errno.EINVAL),
    ('closed-fd', 65544, errno.EBADF), ('', 65543, errno.ENOMEM),
    ('readdir', 65544, errno.EIO),
])
def test_invalid_or_failed_scan_returns_no_partial_response(dirlist_binary,
                                                          tmp_path, fault,
                                                          capacity, error):
    assert listing(dirlist_binary, tmp_path, capacity=capacity,
                   fault=fault) == (-1, error, [])


def test_regular_file_is_not_a_directory(dirlist_binary, tmp_path):
    path = tmp_path / 'file'
    path.write_bytes(b'unchanged')
    assert listing(dirlist_binary, path) == (-1, errno.ENOTDIR, [])
    assert path.read_bytes() == b'unchanged'


def test_buffer_exhaustion_does_not_publish_partial_listing(dirlist_binary, tmp_path):
    for index in range(700):
        (tmp_path / (str(index) + 'x' * 110)).touch()
    assert listing(dirlist_binary, tmp_path, capacity=65544) == (-1, errno.E2BIG, [])


def test_control_names_cannot_inject_wire_records(dirlist_binary, tmp_path):
    for name in ['safe', '.allowed', '.nginx-xrootd', '.nginx-xrootd.private',
                 'line\nbreak', 'tab\tname', 'del\x7f', 'ctrl\x01']:
        (tmp_path / name).touch()
    status, error, frames = listing(dirlist_binary, tmp_path)
    assert (status, error) == (0, 0)
    assert names_from(frames) == {b'safe', b'.allowed'}


@pytest.mark.parametrize('fault', ['stat-vanished', 'stat-denied'])
def test_unstattable_entries_are_omitted(dirlist_binary, tmp_path, fault):
    (tmp_path / 'file').touch()
    status, error, frames = listing(dirlist_binary, tmp_path, 'stat', fault=fault)
    assert (status, error) == (0, 0)
    assert b''.join(frames) == b'.\n0 0 0 0\0'


def test_stat_reports_file_and_symlink_metadata(dirlist_binary, tmp_path):
    (tmp_path / 'file').write_bytes(b'payload')
    (tmp_path / 'link').symlink_to('outside-does-not-exist')
    status, error, frames = listing(dirlist_binary, tmp_path, 'stat')
    assert (status, error) == (0, 0)
    rows = b''.join(frames).rstrip(b'\0').splitlines()
    assert rows[:2] == [b'.', b'0 0 0 0']
    entries = dict(zip(rows[2::2], rows[3::2]))
    assert int(entries[b'file'].split()[1]) == 7
    assert int(entries[b'link'].split()[1]) == len('outside-does-not-exist')


@pytest.mark.parametrize('algorithm', ['md5', 'sha1', 'sha256', 'sha512'])
def test_checksum_reads_data_without_persisting_xattrs(dirlist_binary, tmp_path,
                                                      algorithm):
    path = tmp_path / 'file'
    path.write_bytes(b'123456789')
    (tmp_path / 'directory').mkdir()
    (tmp_path / 'link').symlink_to(path)
    before = os.listxattr(path)
    status, error, frames = listing(dirlist_binary, tmp_path, algorithm)
    assert (status, error) == (0, 0)
    rows = b''.join(frames).rstrip(b'\0').splitlines()
    entries = dict(zip(rows[2::2], rows[3::2]))
    digest = hashlib.new(algorithm, b'123456789').hexdigest()
    assert entries[b'file'].endswith(f'[ {algorithm}:{digest} ]'.encode())
    for name in (b'link', b'directory'):
        assert entries[name].endswith(f'[ {algorithm}:none ]'.encode())
    assert os.listxattr(path) == before
    assert path.read_bytes() == b'123456789'


@pytest.mark.parametrize('algorithm,fault', [('unknown', ''), ('md5', 'long-path')])
def test_unavailable_checksum_is_explicit_none(dirlist_binary, tmp_path,
                                              algorithm, fault):
    (tmp_path / 'file').write_bytes(b'123456789')
    status, error, frames = listing(dirlist_binary, tmp_path, algorithm, fault=fault)
    assert (status, error) == (0, 0)
    assert b''.join(frames).endswith(f'[ {algorithm}:none ]\0'.encode())
