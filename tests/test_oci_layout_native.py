"""Native OCI layout durability, integrity and failed-allocation contracts."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def layout_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('oci-layout-native')
    return compile_client_contract(root, output, 'tests/c/oci_layout_native_test.c',
        ('malloc', 'calloc', 'realloc', 'read', 'write', 'fsync', 'fchmod', 'rename'))


@pytest.mark.parametrize('mode', [
    'roundtrip', 'invalid', 'index', 'index-invalid',
    'load-malloc', 'load-read', 'load-short', 'verify-read',
    'put-write', 'put-fsync', 'put-fchmod', 'put-rename',
    'index-realloc', 'index-write', 'index-fsync', 'index-rename',
    'list-calloc', 'list-realloc', 'commit-missing', 'stage-missing',
])
def test_layout_integrity_and_failure_contracts(layout_binary, tmp_path, mode):
    result = subprocess.run([str(layout_binary), mode, str(tmp_path / 'layout')],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
