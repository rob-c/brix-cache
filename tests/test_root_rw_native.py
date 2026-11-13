"""Native inline compression and vector response boundaries at the wire seam."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def root_rw(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    binary = compile_client_contract(root, tmp_path_factory.mktemp('root-rw'),
        'tests/c/root_rw_native_test.c', ('brix_send', 'brix_send_ext', 'brix_recv',
        'malloc', 'realloc', 'brix_io_stall_arm', 'brix_io_stall_disarm', 'brix_codec_step'))
    def invoke(operation, mode='', codec=0, length=16, expected=0, flag=0, partials=0):
        result = subprocess.run([str(binary), operation, mode, str(codec), str(length),
            str(expected), str(flag), str(partials)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return invoke


@pytest.mark.parametrize('codec', [0, 1])
@pytest.mark.parametrize('length', [0, 16, 100000])
def test_plain_and_compressed_reads_preserve_bytes_and_whole_read_guard(root_rw, codec, length):
    output = root_rw('read', codec=codec, length=length, expected=length,
                     partials=int(length == 100000))
    assert 'sends=1' in output


@pytest.mark.parametrize('codec', [0, 1, 2, 3, 4, 5, 6, 7])
@pytest.mark.parametrize('length', [0, 16])
def test_write_wire_payload_roundtrips_each_negotiated_codec(root_rw, codec, length):
    assert 'sends=1 receives=1' in root_rw('write', codec=codec, length=length)


@pytest.mark.parametrize('operation', ['read', 'write', 'readv', 'writev'])
@pytest.mark.parametrize('mode', ['send', 'receive'])
def test_transport_errors_propagate_without_false_success(root_rw, operation, mode):
    assert 'refused' in root_rw(operation, mode, expected=-1)


@pytest.mark.parametrize('codec,mode,hint', [(0, 'oversized', 'more than requested'),
    (1, 'oversized', 'too large'), (1, 'corrupt', 'corrupt'), (255, '', 'unavailable'),
    (1, 'reallocation', 'out of memory'), (1, 'codec-stall', 'corrupt'),
    (1, 'codec-error', 'corrupt')])
def test_untrusted_read_frames_cannot_exceed_requested_buffer(root_rw, codec, mode, hint):
    assert hint in root_rw('read', mode, codec=codec, expected=-1)


@pytest.mark.parametrize('mode,hint', [('second-reallocation', 'out of memory'),
                                    ('receive-second', 'receive refused')])
def test_compressed_accumulation_failure_discards_partial_frame(root_rw, mode, hint):
    assert hint in root_rw('read', mode, codec=1, length=100000, expected=-1, partials=1)


@pytest.mark.parametrize('mode,hint', [('allocation', 'out of memory'),
                                    ('codec-stall', 'compress failed'), ('codec-error', 'compress failed')])
def test_compression_failure_never_sends_payload(root_rw, mode, hint):
    output = root_rw('write', mode, codec=1, expected=-1)
    assert hint in output and 'sends=0' in output


def test_unsupported_write_codec_is_refused(root_rw):
    assert 'unavailable' in root_rw('write', codec=255, expected=-1)


@pytest.mark.parametrize('multi', [0, 1])
@pytest.mark.parametrize('mode,partials', [('', 0), ('fragment', 13)])
def test_readv_scatter_retains_segment_handle_and_order(root_rw, multi, mode, partials):
    root_rw('readv', mode, expected=8, flag=multi, partials=partials)


@pytest.mark.parametrize('mode,hint', [('short-header', 'truncated segment header'),
    ('short-body', 'truncated segment data'), ('segment-overrun', 'exceeds requested'),
    ('vector-cap', 'response too large'), ('allocation', 'out of memory'),
    ('reallocation', 'out of memory')])
def test_readv_rejects_bad_sizes_and_allocation_failure(root_rw, mode, hint):
    assert hint in root_rw('readv', mode, expected=-1)


@pytest.mark.parametrize('operation', ['readv', 'writev'])
@pytest.mark.parametrize('mode', ['count-zero', 'count-large'])
def test_invalid_vector_count_stops_before_transport(root_rw, operation, mode):
    output = root_rw(operation, mode, expected=-1)
    assert 'bad segment count' in output and 'sends=0' in output


@pytest.mark.parametrize('sync', [0, 1])
def test_writev_frames_descriptors_separately_from_data(root_rw, sync):
    root_rw('writev', flag=sync)


@pytest.mark.parametrize('mode,hint', [('single-cap', 'payload exceeds'),
                                    ('sum-cap', 'payload exceeds'), ('allocation', 'out of memory')])
def test_writev_size_and_allocation_refusals_never_send(root_rw, mode, hint):
    output = root_rw('writev', mode, expected=-1)
    assert hint in output and 'sends=0' in output
