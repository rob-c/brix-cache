"""Execute the configured client's operation pipeline under bounded failures."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU allocation wrapping')


@pytest.fixture(scope='module')
def operation_pipeline(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('operation-pipeline'),
                                   'tests/c/operation_pipeline_native_test.c', ('calloc', 'realloc'))


@pytest.mark.parametrize('count,failure', [(0, -1), (1, -1), (8, -1), (9, -1),
    (129, -1), (256, -1), (1, 0), (20, 0), (20, 8), (20, 19), (256, 255)])
def test_pipeline_bounds_preserve_order_failure_index_and_reusability(operation_pipeline, count, failure):
    result = subprocess.run([str(operation_pipeline), str(count), str(failure)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
