"""Varnish baselines own their foreground manager, never argv-match daemons."""
from types import SimpleNamespace

import pytest

from cmdscripts import cvmfs_matrix as subject


@pytest.fixture
def baseline(tmp_path, monkeypatch):
    work = tmp_path / 'baseline'
    work.mkdir()
    spawned, stopped, commands = [], [], []
    manager = SimpleNamespace(terminate=lambda: stopped.append('owned-manager'))

    def spawn(argv):
        spawned.append(argv)
        return manager

    def write(path, content):
        path.write_text(content)
        return path

    run = SimpleNamespace(root=tmp_path, write=write, spawn=spawn,
                          mkdir=lambda name: work,
                          call=lambda argv, **kwargs: commands.append(argv))
    monkeypatch.setattr(subject.shutil, 'which', lambda name: '/tools/' + name)
    return run, work, spawned, stopped, commands


def test_varnish_startup_and_shutdown_target_only_owned_manager(baseline):
    run, work, spawned, stopped, commands = baseline
    stop, url, env = subject._start_varnish(run, 12345, 'origin.invalid', '12344', work)
    assert len(spawned) == 1 and '-F' in spawned[0]
    assert spawned[0][spawned[0].index('-n') + 1] == work / 'vn'
    assert url.endswith(':12345') and env == {}
    stop()
    assert stopped == ['owned-manager'] and commands == []


@pytest.mark.parametrize('exception', [False, True])
def test_harness_failure_stops_owned_process_without_matching_foreign_titles(
    baseline, monkeypatch, exception,
):
    run, work, _spawned, stopped, commands = baseline
    monkeypatch.setattr(subject, 'wait_tcp', lambda *args: True)

    def fail_harness(argv, **kwargs):
        commands.append(argv)
        if exception:
            raise RuntimeError('injected harness exception')
        return SimpleNamespace(returncode=1, stderr='injected harness failure', stdout='')

    run.call = fail_harness
    if exception:
        with pytest.raises(RuntimeError, match='injected harness exception'):
            subject.run_baseline(run, 'varnish', 12345, 'origin.invalid:12344', work)
    else:
        ok, message = subject.run_baseline(run, 'varnish', 12345, 'origin.invalid:12344', work)
        assert not ok and 'injected harness failure' in message
    assert stopped == ['owned-manager']
    assert len(commands) == 1 and commands[0][0] == subject.sys.executable
