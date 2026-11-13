"""Directory listing frames retain metadata and never publish partial allocation results."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def metadata_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('dirlist-metadata'),
        'tests/c/dirlist_metadata_native_test.c',
        ['brix_roundtrip', 'brix_recv', 'brix_resilient_window_ms', 'realloc'])


def invoke(binary, tmp_path, data, operation='checksum', mode='normal', chunk=65536, allocation=0):
    path = tmp_path / 'reply'; path.write_bytes(data)
    result = subprocess.run([str(binary), operation, mode, str(path), str(chunk), str(allocation)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = result.stdout.splitlines()
    return tuple(map(int, rows[0].split())), rows[1:]


@pytest.mark.parametrize('chunk', [1, 2, 7, 13, 65536])
def test_checksum_listing_keeps_exact_metadata_across_frame_boundaries(metadata_binary, tmp_path, chunk):
    data = b'.\n0 0 0 0\nfile\n12 123 0 4 [  sha256 abcd  ]\nempty\n13 0 0 4 [ ]\n'
    counts, rows = invoke(metadata_binary, tmp_path, data, chunk=chunk)
    assert counts[:3] == (0, 0, 2)
    assert counts[3] == (len(data) + chunk - 1) // chunk
    assert rows == ['file|1|123|sha256 abcd', 'empty|1|0|']


@pytest.mark.parametrize('suffix,expected', [('', ''), ('[unterminated', ''),
    (' ] before [ no close', ''), ('[abc]', 'abc'), ('[' + 'x' * 200 + ']', 'x' * 143)])
def test_checksum_parser_requires_a_closed_bounded_field(metadata_binary, tmp_path, suffix, expected):
    counts, rows = invoke(metadata_binary, tmp_path, ('file\n1 7 0 4 ' + suffix + '\n').encode())
    assert counts[:3] == (0, 0, 1) and rows == ['file|1|7|' + expected]


@pytest.mark.parametrize('mode', ['null-path', 'null-algo', 'query-path', 'long-path'])
def test_ambiguous_or_oversize_checksum_request_sends_nothing(metadata_binary, tmp_path, mode):
    counts, rows = invoke(metadata_binary, tmp_path, b'', mode=mode)
    assert counts[0] == -1 and counts[1] != 0 and counts[2:] == (0, 0, 0) and not rows


@pytest.mark.parametrize('mode,receives', [('send-error', 1), ('recv-error', 2)])
def test_transport_failure_cannot_publish_a_partial_listing(metadata_binary, tmp_path, mode, receives):
    counts, rows = invoke(metadata_binary, tmp_path, b'file\n1 7 0 4\n', mode=mode, chunk=2)
    assert counts[0] == -1 and counts[1] != 0 and counts[2:4] == (0, receives) and not rows


@pytest.mark.parametrize('allocation', [1, 2, 3])
def test_growing_entry_array_is_atomic_on_allocation_failure(metadata_binary, tmp_path, allocation):
    data = ''.join(f'file-{i}\n{i} {i + 10} 0 4 [sum]\n' for i in range(70)).encode()
    counts, rows = invoke(metadata_binary, tmp_path, data, allocation=allocation)
    assert counts[0] == -1 and counts[1] != 0 and counts[2] == 0 and not rows


def test_growing_entry_array_keeps_every_entry(metadata_binary, tmp_path):
    data = ''.join(f'file-{i}\n{i} {i + 10} 0 4 [sum]\n' for i in range(70)).encode()
    counts, rows = invoke(metadata_binary, tmp_path, data)
    assert counts[:3] == (0, 0, 70)
    assert rows == [f'file-{i}|1|{i + 10}|sum' for i in range(70)]


@pytest.mark.parametrize('allocation', [0, 2])
def test_growing_response_buffer_retains_every_frame_or_refuses(metadata_binary, tmp_path, allocation):
    data = b'a\n' * 40000
    counts, rows = invoke(metadata_binary, tmp_path, data, operation='names', allocation=allocation)
    if allocation:
        assert counts[0] == -1 and counts[2] == 0 and not rows
    else:
        assert counts == (0, 0, 40000, 2, 1) and rows == ['a|0|0|'] * 40000


@pytest.mark.parametrize('data,rows', [(b'', []), (b'\nignored', []),
    (b'a\x00ignored', ['a|0|0|']), (b'a\nb', ['a|0|0|', 'b|0|0|'])])
def test_name_only_terminators_do_not_create_phantom_entries(metadata_binary, tmp_path, data, rows):
    counts, actual = invoke(metadata_binary, tmp_path, data, operation='names')
    assert counts[:3] == (0, 0, len(rows)) and actual == rows
