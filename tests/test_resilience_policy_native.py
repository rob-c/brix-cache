"""Connection, metadata and file-open retries honor replay safety and bounds."""

from pathlib import Path
import errno
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def resilience_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('resilience-policy-native')
    return compile_client_contract(root, output, 'tests/c/resilience_policy_native_test.c',
        ('brix_mono_ns', 'brix_backoff_sleep_fast', 'brix_connect', 'brix_reconnect',
         'brix_roundtrip', 'brix_file_open_read', 'brix_file_open_write', 'brix_file_open_opaque',
         'brix_pool_checkout', 'brix_pool_checkin'))


def run_policy(binary, operation, mode, kind=0, window=20, expected=0, calls=1, home=1):
    result = subprocess.run([str(binary), operation, mode, str(kind), str(window),
        str(expected), str(calls), str(home)], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize('operation', ['connect', 'operation', 'roundtrip', 'read', 'write', 'opaque'])
@pytest.mark.parametrize('home', [0, 1])
def test_initial_success_needs_no_reconnect(resilience_binary, operation, home):
    assert 'reconnects=0' in run_policy(resilience_binary, operation, 'success', home=home)


@pytest.mark.parametrize('operation', ['connect', 'operation', 'roundtrip', 'read', 'write', 'opaque'])
@pytest.mark.parametrize('home', [0, 1])
def test_transient_failure_replays_original_request(resilience_binary, operation, home):
    run_policy(resilience_binary, operation, 'retry', calls=2, home=home)


@pytest.mark.parametrize('operation', ['connect', 'operation', 'roundtrip', 'read', 'write', 'opaque'])
def test_auth_failure_is_never_retried(resilience_binary, operation):
    assert 'reconnects=0' in run_policy(resilience_binary, operation, 'auth', expected=-1)


@pytest.mark.parametrize('operation', ['connect', 'operation', 'roundtrip', 'read', 'write', 'opaque'])
@pytest.mark.parametrize('window', [0, -1])
def test_disabled_resilience_keeps_first_failure(resilience_binary, operation, window):
    assert 'reconnects=0' in run_policy(resilience_binary, operation, 'retry', window=window, expected=-1)


@pytest.mark.parametrize('operation', ['operation', 'roundtrip'])
def test_unsafe_operation_is_never_replayed(resilience_binary, operation):
    assert 'reconnects=0' in run_policy(resilience_binary, operation, 'retry', kind=3, expected=-1)


@pytest.mark.parametrize('operation', ['operation', 'roundtrip'])
@pytest.mark.parametrize('kind', [0, 1])
def test_idempotent_replay_survives_one_failed_reconnect(resilience_binary, operation, kind):
    output = run_policy(resilience_binary, operation, 'reconnect-retry', kind=kind, calls=2)
    assert 'reconnects=2' in output


@pytest.mark.parametrize('operation', ['operation', 'roundtrip'])
def test_reconnect_auth_failure_prevents_reissue(resilience_binary, operation):
    output = run_policy(resilience_binary, operation, 'reconnect-auth', expected=-1)
    assert 'reconnects=1' in output


@pytest.mark.parametrize('operation', ['operation', 'roundtrip'])
@pytest.mark.parametrize('mode,expected', [('normalize', 0), ('retry', 0), ('late-auth', -1), ('permanent', -1)])
def test_mutation_reissued_only_once_and_benign_result_normalized(resilience_binary, operation, mode, expected):
    output = run_policy(resilience_binary, operation, mode, kind=2, expected=expected, calls=2)
    assert 'reconnects=1' in output


def test_refused_connection_fails_without_backoff(resilience_binary):
    run_policy(resilience_binary, 'connect', 'refused', expected=-1)


@pytest.mark.parametrize('operation', ['operation', 'roundtrip', 'read', 'write', 'opaque'])
def test_deadline_exhaustion_stops_before_replay(resilience_binary, operation):
    run_policy(resilience_binary, operation, 'permanent', window=1, expected=-1)


@pytest.mark.parametrize('operation', ['operation', 'roundtrip', 'fuse'])
@pytest.mark.parametrize('mode', ['normalize', 'normalize-missing'])
def test_replayed_mutation_accepts_only_matching_positive_errno(resilience_binary, operation, mode):
    run_policy(resilience_binary, operation, mode, kind=2, calls=2)


@pytest.mark.parametrize('operation', ['operation', 'roundtrip', 'fuse'])
@pytest.mark.parametrize('mode', ['normalize-zero', 'normalize-negative', 'normalize-mismatch'])
def test_disabled_or_mismatched_normalization_keeps_failure(resilience_binary, operation, mode):
    expected = -errno.EEXIST if operation == 'fuse' else -1
    run_policy(resilience_binary, operation, mode, kind=2, calls=2, expected=expected)


@pytest.mark.parametrize('operation', ['operation', 'roundtrip', 'fuse'])
def test_initial_already_exists_is_an_error(resilience_binary, operation):
    expected = -errno.EEXIST if operation == 'fuse' else -1
    run_policy(resilience_binary, operation, 'first-benign', kind=2, expected=expected)


@pytest.mark.parametrize('operation', ['operation', 'roundtrip'])
@pytest.mark.parametrize('kind', [0, 1])
def test_readonly_and_idempotent_classes_do_not_normalize(resilience_binary, operation, kind):
    run_policy(resilience_binary, operation, 'normalize', kind=kind, expected=-1, calls=2)


@pytest.mark.parametrize('mode,expected,calls', [
    ('success', 0, 1), ('retry', 0, 2), ('auth', -errno.EACCES, 1),
    ('late-auth', -errno.EACCES, 2),
])
def test_pooled_metadata_returns_connections_and_preserves_auth_errors(resilience_binary, mode, expected, calls):
    run_policy(resilience_binary, 'fuse', mode, expected=expected, calls=calls)
