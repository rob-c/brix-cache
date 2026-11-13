"""Page-write CSE repair preserves offsets, checksums and finite retry budgets."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def pgwrite(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    binary = compile_client_contract(root, tmp_path_factory.mktemp('pgwrite-native'),
        'tests/c/pgwrite_retry_native_test.c',
        ('brix_send', 'read_status_frame', 'brix_read_full', 'malloc'))
    def run(mode, offset=3, length=8200, result=0, status=0, sends=1):
        completed = subprocess.run([str(binary), mode, str(offset), str(length),
            str(result), str(status), str(sends)], capture_output=True, text=True, timeout=10)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        return completed.stdout
    return run


@pytest.mark.parametrize('offset', [0, 3, 4095])
@pytest.mark.parametrize('length', [1, 100, 4096, 8200])
def test_clean_write_checks_every_page_payload(pgwrite, offset, length):
    pgwrite('clean', offset=offset, length=length)


@pytest.mark.parametrize('offset', [0, 3, 4095])
@pytest.mark.parametrize('length', [1, 100, 4096, 8200])
def test_corrupt_pages_are_repaired_using_original_bytes(pgwrite, offset, length):
    pages = (offset % 4096 + length + 4095) // 4096
    output = pgwrite('repair', offset=offset, length=length, sends=1 + pages)
    starts = [int(line.split()[1]) for line in output.splitlines() if line.startswith('SEND ')][1:]
    assert starts == [offset, *range((offset // 4096 + 1) * 4096, offset + length, 4096)]


@pytest.mark.parametrize('mode,status,sends', [
    ('allocation', -2, 0), ('cse-allocation', -2, 1), ('send-error', -1, 1),
    ('frame-error', -1, 1), ('body-error', -1, 1), ('offset', -2, 1),
    ('retry-send-error', -1, 2), ('retry-frame-error', -1, 2), ('retry-offset', -2, 2),
    ('before-base', -2, 1), ('after-end', -2, 1)])
def test_failure_stops_at_first_uncorrected_page(pgwrite, mode, status, sends):
    pgwrite(mode, result=-1, status=status, sends=sends)


@pytest.mark.parametrize('size', [1, 7, 9, 15, 17, 23, 31])
def test_malformed_cse_never_generates_retry(pgwrite, size):
    output = pgwrite(f'malformed{size}', result=-1, status=-2)
    assert 'malformed pgwrite CSE trailer' in output


def test_empty_error_list_requires_no_retry(pgwrite):
    assert 'bodies=1' in pgwrite('empty-cse')


def test_repeated_corruption_stops_at_three_retries(pgwrite):
    output = pgwrite('uncorrectable', result=-1, status=-5, sends=4)
    assert 'uncorrectable after 3 retries' in output and 'bodies=4' in output


def test_third_retry_can_repair_page(pgwrite):
    output = pgwrite('twice-bad', sends=6)
    assert output.count('SEND 3 4093') == 3 and 'bodies=3' in output
