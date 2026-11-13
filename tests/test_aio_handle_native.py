"""Async file recovery preserves wire identity and never repeats a destructive open."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def handle_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('aio-handle'),
        'tests/c/aio_handle_native_test.c', ('calloc', 'malloc', 'brix_codec_available',
        'brix_deflate_frame', 'brix_mono_ns', 'brix_backoff_sleep_fast',
        'brix_aio_call_ex', 'brix_aio_call'))


@pytest.fixture
def handle(handle_binary):
    def run(operation='read', mode='normal', force=1, posc=0, codec=0):
        result = subprocess.run([str(handle_binary), operation, mode, str(force), str(posc), str(codec)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        label, *values = result.stdout.split()
        return label, tuple(map(int, values))
    return run


@pytest.mark.parametrize('operation', ['read', 'write', 'stat'])
@pytest.mark.parametrize('mode', ['normal', 'transient', 'stale', 'reopen-once'])
@pytest.mark.parametrize('force,posc', [(0, 0), (1, 1), (2, 0)])
def test_reconnect_preserves_handle_operation_and_create_policy(handle, operation, mode, force, posc):
    label, values = handle(operation, mode, force, posc)
    assert label == 'RESULT' and values[0] == (7 if operation == 'read' else 0)
    assert values[2] == {'normal': 1, 'transient': 2, 'stale': 2, 'reopen-once': 3}[mode]
    assert values[3] == (1 if mode == 'normal' else 2)
    assert values[5:] == (0, 0, 1, 1)


@pytest.mark.parametrize('operation', ['read', 'write', 'stat'])
@pytest.mark.parametrize('mode', ['permanent', 'deadline', 'reopen-deadline', 'reopen-permanent'])
def test_permanent_refusals_and_patience_expiry_are_finite(handle, operation, mode):
    _, values = handle(operation, mode)
    assert values[0] == -1 and values[1] != 0 and values[2] <= 7 and values[4] <= 5
    if mode == 'permanent':
        assert values[2:5] == (1, 1, 0)
    if mode == 'reopen-permanent':
        assert values[5:] == (-1, 0, 0, 0)
    else:
        assert values[5:] == (0, 0, 1, 1)


@pytest.mark.parametrize('mode', ['owner-oom', 'payload-oom', 'open-error', 'short-open', 'unavailable'])
def test_failed_open_never_exposes_a_partial_owner(handle, mode):
    label, values = handle(mode=mode, codec=1)
    assert label == 'OPEN-REFUSED' and values[0] != 0
    assert values[1] == (0 if mode in {'owner-oom', 'payload-oom'} else 1)


@pytest.mark.parametrize('operation', ['read', 'write'])
@pytest.mark.parametrize('codec', [1, 2, 3, 4, 5, 6, 7])
def test_negotiated_codecs_round_trip_payload_and_plaintext_offset(handle, operation, codec):
    _, values = handle(operation=operation, codec=codec)
    assert values[0] == (7 if operation == 'read' else 0) and values[2:5] == (1, 1, 0)


@pytest.mark.parametrize('operation,mode,codec', [('read', 'corrupt-frame', 1),
    ('write', 'compress-error', 1)])
def test_malformed_content_and_local_codec_failure_are_not_retried(handle, operation, mode, codec):
    _, values = handle(operation=operation, mode=mode, codec=codec)
    assert values[0] == -1 and values[1] != 0 and values[2] == 1 and values[4] == 0
    assert values[3] == (0 if mode == 'compress-error' else 1)


@pytest.mark.parametrize('mode', ['bad-stat', 'long-stat', 'empty-stat'])
def test_malformed_stat_recovery_obeys_protocol_desync_patience(handle, mode):
    # The shared status policy permits reconnecting on EPROTO to resync framing.
    _, values = handle(operation='stat', mode=mode)
    assert values[0:2] == (-1, -2)
    assert 1 < values[2] == values[3] <= 5 and values[4] == values[2] - 1
    assert values[5:] == (0, 0, 1, 1)


@pytest.mark.parametrize('operation', ['read', 'write'])
def test_legacy_codec_byte_without_magic_remains_plaintext(handle, operation):
    _, values = handle(operation=operation, mode='legacy-codec', codec=1)
    assert values[0] == (7 if operation == 'read' else 0)


def test_empty_range_is_eof_and_sync_refusal_is_not_retried(handle):
    assert handle(mode='empty-read')[1][0] == 0
    assert handle(mode='sync-error')[1][5:] == (-1, -1, 1, 1)
