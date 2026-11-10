"""A mesh's port band never authorizes stopping another test root's fleet."""

import importlib

import pytest

from settings import HOST


@pytest.fixture(params=("cms_mesh_lib", "hybrid_mesh_lib"))
def mesh(request):
    """Exercise both orchestrators through their real listener parsers."""
    return importlib.import_module("brix_suite.mesh." + request.param)


def _listener(port, pid):
    """Build the portable listener seam's normal ss-compatible row."""
    return f'LISTEN 0 128 {HOST}:{port} *:* users:(("nginx",pid={pid},fd=5))'


def _sweep(mesh, monkeypatch, rows):
    """Feed the same socket snapshot to either mesh's cleanup entry point."""
    if hasattr(mesh, "_kill_mesh_listeners"):
        monkeypatch.setattr(mesh, "_list_listeners", lambda: rows)
        mesh._kill_mesh_listeners()
        return
    mesh._kill_bound_processes("\n".join(rows))


def test_mesh_sweep_reaps_only_owned_processes_in_its_band(mesh, monkeypatch):
    """Success: retain the sweep for owned survivors, respecting its port band."""
    calls, roots = [], []

    def owned(root):
        roots.append(root)
        return [(711, "owned listener"), (713, "owned other service")]

    monkeypatch.setattr(mesh, "find_orphans", owned)
    monkeypatch.setattr(mesh.subprocess, "run", lambda argv, **kw: calls.append(argv))
    _sweep(mesh, monkeypatch, [_listener(mesh.PORT_MIN, 711),
                              _listener(mesh.PORT_MIN + 1, 712),
                              _listener(mesh.PORT_MAX + 1, 713)])
    assert roots == [mesh.MESH_DIR]
    assert calls == [["kill", "-9", "711"]]


def test_mesh_sweep_preserves_foreign_listeners_in_its_band(mesh, monkeypatch):
    """Security-negative: a matching port without ownership grants no kill."""
    calls = []
    monkeypatch.setattr(mesh, "find_orphans", lambda root: [])
    monkeypatch.setattr(mesh.subprocess, "run", lambda argv, **kw: calls.append(argv))
    _sweep(mesh, monkeypatch, [_listener(mesh.PORT_MIN, 711)])
    assert calls == []


def test_mesh_sweep_inspection_failure_cannot_authorize_a_kill(mesh, monkeypatch):
    """Error: unavailable ownership evidence propagates before any signal."""
    calls = []
    error = OSError("process inspection failed")

    def unavailable(root):
        raise error

    monkeypatch.setattr(mesh, "find_orphans", unavailable)
    monkeypatch.setattr(mesh.subprocess, "run", lambda argv, **kw: calls.append(argv))
    with pytest.raises(OSError) as caught:
        _sweep(mesh, monkeypatch, [_listener(mesh.PORT_MIN, 711)])
    assert caught.value is error
    assert calls == []


def test_empty_mesh_root_neither_stops_nor_waits_for_foreign_ports(mesh, monkeypatch):
    """An empty child root must return before any stop command or port wait."""
    monkeypatch.setattr(mesh, "find_orphans", lambda root: [])

    def unexpected(*args, **kwargs):
        pytest.fail("an unowned mesh must not run cleanup or wait for ports")

    monkeypatch.setattr(mesh.subprocess, "run", unexpected)
    monkeypatch.setattr(mesh.time, "sleep", unexpected)
    mesh.stop_all()


def test_mesh_cleanup_reaps_workers_before_removing_pidfiles(mesh, tmp_path, monkeypatch):
    """Success: collect parent-based ownership before any master can disappear."""
    pidfile = tmp_path / 'node/run/nginx.pid'
    pidfile.parent.mkdir(parents=True)
    pidfile.write_text('711\n')
    monkeypatch.setattr(mesh, 'MESH_DIR', str(tmp_path))
    monkeypatch.setattr(mesh, 'find_orphans', lambda root: [(711, 'master'), (712, 'worker')])
    calls = []

    def reap(root):
        assert pidfile.exists()
        calls.append(root)
        return []

    monkeypatch.setattr(mesh, 'kill_orphans', reap)
    wait = '_wait_manager_ports_closed' if hasattr(mesh, '_wait_manager_ports_closed') else '_wait_ports_closed'
    monkeypatch.setattr(mesh, wait, lambda: calls.append('wait'))
    mesh.stop_all()
    assert calls == [str(tmp_path), 'wait']
    assert not pidfile.exists()


def test_mesh_cleanup_survivor_is_not_reported_as_stopped(mesh, monkeypatch):
    """Error: a surviving owned worker must keep teardown visibly failed."""
    monkeypatch.setattr(mesh, 'find_orphans', lambda root: [(712, 'worker')])
    monkeypatch.setattr(mesh, 'kill_orphans', lambda root: [(712, 'worker')])
    with pytest.raises(RuntimeError, match='survived cleanup'):
        mesh.stop_all()


def test_mesh_cleanup_foreign_lane_refusal_propagates(mesh, monkeypatch):
    """Security-negative: the common reaper's lane guard remains authoritative."""
    monkeypatch.setattr(mesh, 'find_orphans', lambda root: [(711, 'master')])
    refusal = RuntimeError('another active harness owns this lane')

    def refuse(root):
        raise refusal

    monkeypatch.setattr(mesh, 'kill_orphans', refuse)
    with pytest.raises(RuntimeError) as caught:
        mesh.stop_all()
    assert caught.value is refusal
