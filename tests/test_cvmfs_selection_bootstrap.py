"""Parse the real CVMFS selection fixture without opening any listener."""

import os
from pathlib import Path
import re

import pytest

from cmdscripts.cvmfs_live_ext import _selection_log_config
from cmdscripts.live_common import LiveRun
from settings import HOST, NGINX_BIN


@pytest.fixture
def selection_config(tmp_path):
    """Use only LiveRun's file writer and command boundary, never its lifecycle."""
    run = LiveRun.__new__(LiveRun)
    run.root = tmp_path
    run.nginx = Path(os.environ.get('TEST_NGINX_BIN', NGINX_BIN))
    if not os.access(run.nginx, os.X_OK):
        pytest.skip(f'nginx not executable: {run.nginx}')
    cache, logs = run.mkdir('cache'), run.mkdir('logs')
    error_log = logs / 'e.log'
    config = _selection_log_config(run, cache, error_log, (1, 2, 19001))
    return run, config, error_log


@pytest.mark.parametrize('mode', ['private-default', 'stderr', 'invalid-geo'])
def test_selection_report_bootstrap_destination(selection_config, mode):
    """Keep rankings observable and reject incomplete geo configuration."""
    run, config, error_log = selection_config
    command = [run.nginx, '-t', '-c', config, '-p', run.root]
    if mode != 'private-default':
        command += ['-e', 'stderr']
    if mode == 'invalid-geo':
        text = config.read_text().replace('brix_cvmfs_here 51.57:-1.31;', '')
        config.write_text(text)
    result = run.call(command, check=False)
    _assert_no_master_pid(run.root)
    assert f'error_log {error_log} info;' in config.read_text()
    _assert_selection_result(run, result, mode)


def _assert_no_master_pid(prefix):
    """nginx -t checks pidfile permissions without writing a master PID."""
    for pidfile in prefix.glob('nginx.pid'):
        assert pidfile.stat().st_size == 0


def _assert_selection_result(run, result, mode):
    if mode == 'invalid-geo':
        assert result.returncode != 0
        assert 'brix_cvmfs_origin_select geo requires brix_cvmfs_here' in result.stderr
        return
    assert result.returncode == 0, result.stderr
    body = result.stderr
    if mode == 'private-default':
        body = (run.root / 'logs/bootstrap.log').read_text()
    assert re.search(rf'selection report.*{re.escape(HOST)}:1 .*rank 0 \(preferred', body)
    assert re.search(rf'selection report.*{re.escape(HOST)}:2 .*rank 1', body)
