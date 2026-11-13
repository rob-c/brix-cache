"""Paged client reads enforce CRC retries, frame order and bounded failure handling."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def pgread_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('pgread-native'),
        'tests/c/pgread_native_test.c',
        ('brix_send', 'read_status_frame', 'brix_read_full', 'malloc'))


@pytest.mark.parametrize('strict', [0, 1])
@pytest.mark.parametrize('mode', ['success', 'partial', 'empty', 'send-error',
    'frame-error', 'body-error', 'offset', 'type', 'malformed', 'allocation',
    'corrupt', 'retry-fail', 'retry-transport'])
def test_paged_read_frame_and_retry_contract(pgread_binary, mode, strict):
    result = subprocess.run([str(pgread_binary), mode, str(strict)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


def test_invalid_optional_argument_request_is_not_sent(pgread_binary):
    result = subprocess.run([str(pgread_binary), 'invalid', '1'],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
