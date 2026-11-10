"""Upload ownership, commit retries and checksum policy across transport faults."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def upload_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('upload-commit-native'),
        'tests/c/upload_commit_native_test.c', ('brix_mono_ns', 'brix_backoff_sleep_fast',
        'brix_copy_quit_requested', 'brix_connect_resilient', 'brix_close',
        'brix_file_open_write', 'brix_file_open_opaque', 'csctx_reopen_home',
        'brix_streams_open', 'brix_streams_close', 'pump_sink_remote', 'brix_file_close',
        'pump_sink_reopen', 'brix_stat', 'cksum_verify', 'brix_vfs_fstat'))


@pytest.fixture
def upload(upload_binary, tmp_path):
    source = tmp_path / 'source'
    source.write_text('upload contents\n')
    def run(mode='success', expected=0, silent=0, path=None):
        if mode.startswith('stdin'):
            path = '-'
        result = subprocess.run([str(upload_binary), str(path or source), mode,
            str(expected), str(silent)], input='upload contents\n',
            capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return parse_counters(result.stdout)
    return run


def parse_counters(output):
    counters = dict(line.split('=', 1) for line in output.splitlines()
                    if line.startswith('UPLOAD_'))
    return {key.removeprefix('UPLOAD_'): int(value) for key, value in counters.items()}


@pytest.mark.parametrize('mode', ['success', 'paged', 'compressed', 'stdin', 'unknown-size'])
@pytest.mark.parametrize('silent', [0, 1])
def test_success_commits_once_and_releases_all_owners(upload, mode, silent):
    counters = upload(mode, silent=silent)
    assert counters['COMMITS'] == counters['DISCONNECTS'] == counters['STREAM_CLOSES'] == 1
    assert counters['WRITES'] == counters['CHECKSUMS'] == 1
    assert counters['STREAMS'] == (0 if mode == 'compressed' else 1)
    assert counters['OPAQUE'] == (1 if mode == 'compressed' else 0)


@pytest.mark.parametrize('mode,disconnected,opened', [('connect', 0, 0), ('open-auth', 1, 1)])
def test_initial_failure_never_writes_or_commits(upload, mode, disconnected, opened):
    counters = upload(mode, expected=-1)
    assert counters['OPENS'] == opened and counters['DISCONNECTS'] == disconnected
    assert counters['WRITES'] == counters['COMMITS'] == counters['CHECKSUMS'] == 0


def test_failed_transfer_abandons_posc_handle(upload):
    counters = upload('pump', expected=-1)
    assert counters['COMMITS'] == counters['CHECKSUMS'] == 0
    assert counters['WRITES'] == counters['DISCONNECTS'] == counters['STREAM_CLOSES'] == 1


def test_retryable_open_reconnects_before_sending_bytes(upload):
    counters = upload('open-retry')
    assert counters['OPENS'] == 2 and counters['RECONNECTS'] == 1
    assert counters['WRITES'] == counters['COMMITS'] == 1


def test_lost_commit_reply_reopens_in_place(upload):
    counters = upload('close-retry')
    assert counters['COMMITS'] == 2 and counters['REOPENS'] == 1
    assert counters['WRITES'] == 1 and counters['STATS'] == 0


def test_already_committed_size_confirms_lost_reply(upload):
    counters = upload('close-confirmed')
    assert counters['COMMITS'] == counters['REOPENS'] == counters['STATS'] == 1
    assert counters['CHECKSUMS'] == counters['DISCONNECTS'] == 1


@pytest.mark.parametrize('mode', ['close-wrong-size', 'close-stat-error', 'close-transient', 'cancel'])
def test_unconfirmed_commit_or_cancellation_remains_failure(upload, mode):
    counters = upload(mode, expected=-1)
    assert counters['CHECKSUMS'] == 0 and counters['DISCONNECTS'] == 1
    assert counters['COMMITS'] >= 1


@pytest.mark.parametrize('mode,expected', [('mismatch', -1), ('unverified', 0),
                                         ('unverified-strict', -1), ('stdin-strict', -1)])
@pytest.mark.parametrize('silent', [0, 1])
def test_checksum_policy_runs_only_after_persisting(upload, mode, expected, silent):
    counters = upload(mode, expected=expected, silent=silent)
    assert counters['COMMITS'] == counters['DISCONNECTS'] == 1
    assert counters['CHECKSUMS'] == (0 if mode == 'stdin-strict' else 1)


def test_missing_local_source_never_connects(upload, tmp_path):
    counters = upload(expected=-1, path=tmp_path / 'missing')
    assert counters['CONNECTS'] == counters['WRITES'] == counters['COMMITS'] == 0
