"""Ceph coverage must own its reference cluster and preserve setup failures."""

import ctypes.util
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tools.ci import coverage_ceph


def test_lab_environment_preserves_native_counter_collection(tmp_path):
    """Host-side production tests must retain the active measurement's paths."""
    original = {'BRIX_COVERAGE_COUNTERS': '/owned/counters', 'PATH': '/owned/bin',
                'COVERAGE_CEPH_IMAGE': 'explicit-reference-image'}
    selected = coverage_ceph._environment(tmp_path, original)
    assert selected['BRIX_COVERAGE_COUNTERS'] == '/owned/counters'
    assert selected['PATH'] == '/owned/bin'
    assert selected['CEPH_IMAGE'] == 'explicit-reference-image'
    assert selected['TEST_CEPH'] == selected['TEST_CEPHFS'] == '1'
    assert selected['TEST_CEPHFS_QUIESCED'] == '0'


def test_lab_cannot_reuse_external_configuration_or_container(tmp_path):
    """Ambient production settings cannot become fixture cleanup targets."""
    foreign = tmp_path / 'production.conf'
    foreign.write_text('must remain untouched')
    original = {'CEPH_CONTAINER': 'production', 'CEPH_CONF': str(foreign),
                'CEPH_POOL': 'production', 'CEPH_DIR': '/production'}
    first = coverage_ceph._environment(tmp_path / 'first', original)
    second = coverage_ceph._environment(tmp_path / 'second', original)
    assert first['CEPH_CONTAINER'] != second['CEPH_CONTAINER'] != 'production'
    assert first['CEPH_CONF'] == str(tmp_path / 'first/ceph.conf')
    assert first['CEPH_POOL'] == 'brix-coverage'
    assert original['CEPH_CONTAINER'] == 'production'
    assert foreign.read_text() == 'must remain untouched'


def test_failed_setup_command_keeps_exit_status_and_diagnostics():
    """A real setup subprocess failure must never produce a passing phase."""
    with pytest.raises(subprocess.CalledProcessError) as caught:
        coverage_ceph._command([sys.executable, '-c',
                                'import sys; print("setup failed", file=sys.stderr); sys.exit(7)'])
    assert caught.value.returncode == 7
    assert caught.value.stderr == 'setup failed\n'


def test_lab_cli_refuses_missing_explicit_opt_in(monkeypatch):
    """A normal import or incidental CLI invocation cannot provision resources."""
    monkeypatch.delenv('COVERAGE_CEPH', raising=False)
    with pytest.raises(RuntimeError, match='requires explicit Linux opt-in'):
        coverage_ceph.main()


@pytest.mark.skipif(sys.platform != 'linux' or not ctypes.util.find_library('cephfs'),
                    reason='requires the real Linux CephFS SDK')
def test_missing_private_cephfs_config_fails_before_connecting(tmp_path, monkeypatch):
    """A missing fixture config cannot fall back to ambient cluster settings."""
    monkeypatch.setenv('CEPH_CONF', '/must-not-be-used')
    with pytest.raises(RuntimeError, match='could not load the private CephFS configuration'):
        coverage_ceph._migration_root(tmp_path / 'missing.conf')
    assert os.environ['CEPH_CONF'] == '/must-not-be-used'


@pytest.mark.parametrize('state', ['', 'Z\n', 'Z\nZl\n'])
def test_mds_without_executing_tasks_is_quiesced(monkeypatch, state):
    monkeypatch.setattr(coverage_ceph, '_command',
                        lambda _arguments: SimpleNamespace(stdout=state, stderr=''))
    coverage_ceph._wait_stopped_mds('owned-reference')


def test_mds_inspection_error_cannot_authorize_reverse_migration(monkeypatch):
    monkeypatch.setattr(coverage_ceph, '_command',
                        lambda _arguments: SimpleNamespace(stdout='', stderr='permission denied'))
    with pytest.raises(RuntimeError, match='could not inspect the owned MDS'):
        coverage_ceph._wait_stopped_mds('owned-reference')


def test_executing_mds_cannot_authorize_reverse_migration(monkeypatch):
    times = iter([0, 0, 31])
    monkeypatch.setattr(coverage_ceph, 'time',
                        SimpleNamespace(monotonic=lambda: next(times), sleep=lambda _seconds: None))
    monkeypatch.setattr(coverage_ceph, '_command',
                        lambda _arguments: SimpleNamespace(stdout='Sl\n', stderr=''))
    with pytest.raises(RuntimeError, match='still has executing processes: Sl'):
        coverage_ceph._wait_stopped_mds('owned-reference')
