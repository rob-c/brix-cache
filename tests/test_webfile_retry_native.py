"""Persistent HTTP reads resume at exact offsets and bound stalls."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def web_retry(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('webfile-retry-native')
    wrappers = ('calloc', 'brix_web_stat', 'brix_tcp_connect', 'brix_write_full',
                'brix_xrdrc_default_ms', 'brix_mono_ns', 'brix_backoff_sleep_fast')
    binary = compile_client_contract(root, output, 'tests/c/webfile_retry_native_test.c', wrappers)

    def run(mode='normal', offset=0, length=10, expected=10, requests=1,
            window='5', config=None, optional=0, timeout=20):
        env = dict(os.environ)
        env.pop('XRDC_MAX_STALL_MS', None)
        env.pop('BRIX_WEB_CONFIG_WINDOW', None)
        if window is not None:
            env['XRDC_MAX_STALL_MS'] = window
        if config is not None:
            env['BRIX_WEB_CONFIG_WINDOW'] = config
        result = subprocess.run([str(binary), mode, str(offset), str(length),
            str(expected), str(optional), str(timeout), str(requests)],
            env=env, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('optional', [0, 1])
@pytest.mark.parametrize('timeout', [20, 0, -1])
def test_open_preserves_metadata_and_optional_credentials(web_retry, optional, timeout):
    assert 'RESULT 10' in web_retry(optional=optional, timeout=timeout)


@pytest.mark.parametrize('mode,message', [('stat-error', 'stat denied'),
    ('directory', 'is a directory'), ('allocation', 'out of memory')])
def test_open_failure_never_dials(web_retry, mode, message):
    output = web_retry(mode=mode, requests=0)
    assert 'OPEN-ERROR ' + message in output and 'RANGE ' not in output


@pytest.mark.parametrize('offset,length,expected,requests', [
    (8, 10, 2, 1), (10, 10, 0, 0), (12, 4, 0, 0), (0, 0, 0, 0)])
def test_past_eof_and_tail_clamping(web_retry, offset, length, expected, requests):
    web_retry(offset=offset, length=length, expected=expected, requests=requests)


@pytest.mark.parametrize('mode,requests', [('short', 5), ('progress', 10)])
@pytest.mark.parametrize('window', ['0', '5'])
def test_partial_progress_resumes_without_duplication(web_retry, mode, requests, window):
    output = web_retry(mode=mode, requests=requests, window=window)
    starts = [int(line.split()[1]) for line in output.splitlines() if line.startswith('RANGE ')]
    assert starts == list(range(0, 10, 10 // requests))
    assert 'BACKOFF' not in output


def test_connection_failure_retries_within_deadline(web_retry):
    assert 'BACKOFF 0' in web_retry(mode='retry-once')


@pytest.mark.parametrize('window', ['0', '-1'])
def test_disabled_retry_returns_connection_error_immediately(web_retry, window):
    output = web_retry(mode='connect-error', window=window, expected=-1, requests=0)
    assert 'BACKOFF' not in output


def test_no_progress_stops_at_deadline(web_retry):
    output = web_retry(mode='deadline', expected=-1, requests=0)
    assert output.splitlines() == ['BACKOFF 0', 'BACKOFF 1', 'RESULT -1']


@pytest.mark.parametrize('mode', ['partial-auth', 'partial-eof', 'partial-error'])
def test_partial_bytes_survive_terminal_response(web_retry, mode):
    output = web_retry(mode=mode, window='0', requests=2, expected=2)
    assert 'RANGE 2 9' in output and 'BACKOFF' not in output


@pytest.mark.parametrize('window,config,expected', [
    ('19', '37', 19), ('0', '37', 0), ('-2', '37', 0), ('invalid', '37', 0),
    ('', '37', 37), (None, '37', 37), (None, '0', 0), (None, None, 30000)])
def test_retry_window_environment_then_config_then_default(web_retry, window, config, expected):
    assert web_retry(mode='window', window=window, config=config) == f'WINDOW {expected}\n'
