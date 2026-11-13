"""Real request-body storage and decompression retain bounds and exact bytes."""

import bz2
import gzip
import lzma
import re
import subprocess
import zlib

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def body_binary(server_native_compile):
    wrappers = ('malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc', 'ngx_pnalloc', 'ngx_alloc',
                'brix_vfs_staged_write', 'brix_vfs_writer_write', 'brix_vfs_writer_write_fd', 'pread64')
    return server_native_compile('http-body', 'tests/c/http_body_native_test.c',
                                 ['-Wl,--wrap=' + name for name in wrappers])


@pytest.fixture
def body(body_binary, tmp_path):
    def run(data=b'body payload', layout='mixed', operation='read', mode='normal', codec=0, limit=1000000):
        source, target = tmp_path / 'source', tmp_path / 'target'
        source.write_bytes(data)
        process = subprocess.run([str(body_binary), str(source), str(target), layout, operation,
            mode, str(codec), str(limit)], capture_output=True, text=True, timeout=10)
        assert process.returncode == 0, process.stdout + process.stderr
        result = re.search(r'RESULT rc=(-?\d+) status=(\d+)', process.stdout)
        assert result, process.stdout
        return int(result[1]), int(result[2]), target.read_bytes(), process.stdout
    return run


@pytest.mark.parametrize('layout', ['memory', 'file', 'mixed'])
@pytest.mark.parametrize('operation', ['read', 'write', 'write-at'])
@pytest.mark.parametrize('size', [0, 17, 150000])
def test_body_preserves_bytes_across_memory_and_spooled_chains(body, layout, operation, size):
    data = (bytes(range(256)) * (size // 256 + 1))[:size]
    rc, _, stored, _ = body(data=data, layout=layout, operation=operation)
    assert rc == 0 and stored == (b'\0' * 7 if operation == 'write-at' and size else b'') + data


@pytest.mark.parametrize('operation', ['read', 'write', 'write-at', 'decode', 'summary'])
@pytest.mark.parametrize('mode', ['bad-fd', 'missing-file', 'reverse-file'])
def test_invalid_spooled_metadata_prevents_processing(body, operation, mode):
    rc, _, stored, _ = body(operation=operation, mode=mode)
    assert rc == -1 and stored == b''


@pytest.mark.parametrize('operation', ['read', 'decode'])
@pytest.mark.parametrize('mode', ['short-file', 'closed-file'])
def test_spooled_read_failure_cannot_claim_success(body, operation, mode):
    assert body(operation=operation, mode=mode)[0] == -1


@pytest.mark.parametrize('operation', ['write', 'write-at', 'decode'])
def test_output_failure_is_propagated(body, operation):
    assert body(operation=operation, mode='closed-output')[0] == -1


@pytest.mark.parametrize('operation', ['read', 'write', 'write-at', 'decode', 'summary'])
@pytest.mark.parametrize('mode', ['no-body', 'no-chain'])
def test_absent_body_is_empty_success(body, operation, mode):
    rc, _, stored, _ = body(operation=operation, mode=mode)
    assert rc == 0 and stored == b''


@pytest.mark.parametrize('operation', ['summary', 'write', 'write-at', 'decode'])
def test_nullable_request_is_empty_success(body, operation):
    assert body(operation=operation, mode='null-request')[0] == 0


@pytest.mark.parametrize('mode', ['null-out', 'null-length', 'pool-oom'])
def test_read_requires_result_storage_and_allocation(body, mode):
    assert body(mode=mode)[0] == -1


def test_read_limit_rejects_before_materializing_body(body):
    assert body(limit=3)[:3] == (-5, 0, b'')


@pytest.mark.parametrize('operation', ['read', 'decode', 'summary'])
def test_null_chain_buffer_is_ignored(body, operation):
    assert body(operation=operation, mode='null-buffer')[0] == 0


@pytest.mark.parametrize('codec,compress', [(0, bytes), (1, gzip.compress), (2, zlib.compress),
                                        (5, lzma.compress), (6, bz2.compress)])
@pytest.mark.parametrize('layout', ['memory', 'file', 'mixed'])
def test_decoding_preserves_plaintext_across_chain_boundaries(body, codec, compress, layout):
    data = bytes(range(256)) * 1000
    rc, _, stored, _ = body(data=compress(data), layout=layout, operation='decode', codec=codec)
    assert rc == 0 and stored == data


@pytest.mark.parametrize('codec,compress', [(1, gzip.compress), (2, zlib.compress),
                                        (5, lzma.compress), (6, bz2.compress)])
def test_decoded_output_cap_rejects_expansion(body, codec, compress):
    rc, status, _, _ = body(data=compress(b'x' * 10000), operation='decode', codec=codec, limit=100)
    assert rc == -1 and status == 413


@pytest.mark.parametrize('codec', [1, 2, 5, 6])
def test_corrupt_stream_maps_to_bad_request(body, codec):
    assert body(data=b'invalid stream', operation='decode', codec=codec)[:2] == (-1, 400)


@pytest.mark.parametrize('skip', [0, 1])
def test_decode_scratch_allocation_failure_is_internal_error(body, skip):
    assert body(operation='decode', mode=f'decode-oom{skip}')[:2] == (-1, 500)


def test_unknown_codec_is_refused(body):
    assert body(operation='decode', codec=999)[:2] == (-1, 415)


@pytest.mark.parametrize('operation', ['staged', 'writer'])
@pytest.mark.parametrize('layout', ['memory', 'file', 'mixed'])
@pytest.mark.parametrize('size', [0, 17, 65537, 150000])
def test_driver_sink_receives_exact_bytes_and_contiguous_offsets(body, operation, layout, size):
    data = (bytes(range(256)) * (size // 256 + 1))[:size]
    rc, _, stored, _ = body(data=data, layout=layout, operation=operation)
    assert rc == 0 and stored == data


@pytest.mark.parametrize('operation', ['staged', 'writer'])
@pytest.mark.parametrize('mode', ['null-request', 'null-sink', 'bad-fd', 'missing-file',
                                 'reverse-file', 'short-file', 'closed-file', 'closed-output', 'sink-fail'])
def test_driver_sink_failure_cannot_report_a_complete_body(body, operation, mode):
    rc, _, stored, _ = body(operation=operation, layout='file', mode=mode)
    assert rc == -1
    assert stored == (b'body payload' if mode == 'short-file' else b'')


@pytest.mark.parametrize('operation', ['staged', 'writer'])
@pytest.mark.parametrize('mode', ['no-body', 'no-chain', 'null-buffer'])
def test_driver_sink_handles_absent_body_and_null_chain_entries(body, operation, mode):
    rc, _, stored, _ = body(operation=operation, mode=mode)
    assert rc == 0 and stored == (b'body payload' if mode == 'null-buffer' else b'')


def test_spooled_staging_retries_interrupted_read_without_losing_bytes(body):
    data = bytes(range(256)) * 600
    rc, _, stored, _ = body(data=data, operation='staged', layout='file', mode='interrupted')
    assert rc == 0 and stored == data


@pytest.mark.parametrize('operation', ['staged', 'writer'])
def test_memory_sink_failure_stops_the_chain(body, operation):
    assert body(operation=operation, layout='memory', mode='sink-fail')[:3] == (-1, 0, b'')
