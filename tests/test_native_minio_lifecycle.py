"""Native MinIO fixture ownership, readiness and explicit dependency selection."""
from types import SimpleNamespace

import pytest


def test_native_minio_owns_private_data_listener_and_child(monkeypatch, tmp_path):
    """Success: private paths, explicit binary and exact owned-child teardown."""
    import test_sts_minio_live as lab

    calls, started = [], []
    child = SimpleNamespace(terminate=lambda: calls.append('terminate'),
                            wait=lambda timeout: calls.append(('wait', timeout)))

    def start(command, **options):
        started.append((command, options))
        return child

    monkeypatch.setattr(lab, '_port_released', lambda host, port: True)
    monkeypatch.setattr(lab.subprocess, 'Popen', start)
    with lab._native_minio('/selected/minio', tmp_path) as owned:
        assert owned is child
        command, options = started[0]
        assert command[:4] == ['/selected/minio', 'server', '--address',
                               f'{lab.HOST}:{lab.PORT}']
        assert command[-1] == str(tmp_path / 'data')
        assert {'--certs-dir', '--anonymous'} <= set(command)
        assert options['env']['MINIO_BROWSER'] == 'off'
        assert options['stdout'] is options['stderr']
    assert calls == ['terminate', ('wait', 5)]


def test_native_minio_refuses_foreign_listener_without_signalling(monkeypatch, tmp_path):
    """Security-negative: an occupied port grants no process ownership."""
    import test_sts_minio_live as lab

    monkeypatch.setattr(lab, '_port_released', lambda host, port: False)
    monkeypatch.setattr(lab.subprocess, 'Popen',
                        lambda *args, **options: pytest.fail('must not start or signal a child'))
    with pytest.raises(RuntimeError, match='already occupied'), lab._native_minio('minio', tmp_path):
        pytest.fail('foreign listener cannot be adopted')
    assert not (tmp_path / 'data').exists()


def test_native_minio_dead_child_cannot_borrow_health_from_another_service(monkeypatch):
    """A dead child cannot inherit readiness from an unrelated HTTP listener."""
    import test_sts_minio_live as lab

    monkeypatch.setattr(lab, '_http', lambda *args: pytest.fail('dead process has no health proof'))
    with pytest.raises(RuntimeError, match='exited during readiness'):
        lab._wait_minio(SimpleNamespace(poll=lambda: 1))


def test_native_minio_bad_explicit_binary_never_falls_back(monkeypatch):
    """Error: a bad explicit dependency never silently selects another binary."""
    import test_sts_minio_live as lab

    monkeypatch.setenv('BRIX_MINIO_BIN', '/missing/selected-minio')
    checked = []
    monkeypatch.setattr(lab.shutil, 'which', lambda name: checked.append(name))
    with pytest.raises(RuntimeError, match='not an executable'):
        lab._native_minio_binary()
    assert checked == ['/missing/selected-minio']


def test_native_minio_conflicting_selections_are_an_error(monkeypatch, tmp_path):
    """Ambiguous explicit backend selections refuse before launching anything."""
    import test_sts_minio_live as lab

    monkeypatch.setenv('BRIX_MINIO_BIN', '/selected/minio')
    monkeypatch.setenv('BRIX_MINIO_IMAGE', 'selected/image:fixed')
    with pytest.raises(RuntimeError, match='not both'), lab._minio_service(tmp_path):
        pytest.fail('conflicting explicit selections cannot launch anything')


def test_native_minio_forced_stop_reaps_only_owned_child(monkeypatch, tmp_path):
    """Escalation waits for and reaps only the child created by this fixture."""
    import test_sts_minio_live as lab
    import subprocess

    calls = []

    def wait(timeout):
        calls.append('wait')
        if len(calls) == 2:
            raise subprocess.TimeoutExpired('owned minio', timeout)

    child = SimpleNamespace(terminate=lambda: calls.append('terminate'), wait=wait,
                            kill=lambda: calls.append('kill'))
    monkeypatch.setattr(lab, '_port_released', lambda host, port: True)
    monkeypatch.setattr(lab.subprocess, 'Popen', lambda *args, **options: child)
    with lab._native_minio('/selected/minio', tmp_path):
        pass
    assert calls == ['terminate', 'wait', 'kill', 'wait']
