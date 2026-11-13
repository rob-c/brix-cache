"""ZIP output must stay parseable on success and latch failed writes."""

from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def zip_writer(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    binary = compile_client_contract(root, tmp_path_factory.mktemp('zip-writer-fault'),
        'tests/c/zip_writer_fault_native_test.c', ('calloc', 'realloc', 'pread'))
    return binary


def write_archive(binary, temporary, mode='', base=0, failure=0, expected=0):
    source, dest = temporary / 'source', temporary / 'output.zip'
    source.write_bytes(b'complete source bytes\x00\xff')
    result = subprocess.run([str(binary), str(source), str(dest), mode, str(base),
        str(failure), str(expected)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return source, dest, result.stderr


@pytest.mark.parametrize('base', [0, 2**32 + 128])
@pytest.mark.parametrize('mode', ['', 'crc-intr', 'data-intr', 'crc-shrink'])
def test_writer_records_match_emitted_data_even_with_retry_and_large_offsets(zip_writer, tmp_path, base, mode):
    source, dest, _observed = write_archive(zip_writer, tmp_path, mode, base)
    with zipfile.ZipFile(dest) as archive:
        assert archive.testzip() is None
        expected = b'' if mode == 'crc-shrink' else source.read_bytes()
        assert archive.read('payload') == expected
        assert archive.getinfo('payload').header_offset == base


@pytest.mark.parametrize('base,failures', [(0, 5), (2**32 + 128, 8)])
def test_every_sink_failure_latches_and_blocks_later_writes(zip_writer, tmp_path, base, failures):
    for failure in range(1, failures + 1):
        _source, _dest, observed = write_archive(zip_writer, tmp_path, base=base,
                                               failure=failure, expected=-3)
        assert f'emits={failure}' in observed


@pytest.mark.parametrize('mode,expected', [('calloc', -4), ('null-sink', -4),
    ('realloc', -4), ('seed-realloc', -4), ('name-empty', -2), ('name-long', -2),
    ('name-null', -2), ('fd-invalid', -3), ('crc-error', -3), ('data-error', -3),
    ('data-shrink', -3)])
def test_invalid_input_and_resource_failures_cannot_report_success(zip_writer, tmp_path, mode, expected):
    write_archive(zip_writer, tmp_path, mode, expected=expected)
