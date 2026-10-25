"""Hermetic checks for stale fleet-listener ownership recovery."""

import pytest

from brix_suite import orphans


@pytest.fixture(autouse=True)
def kernel_socket_seam(monkeypatch):
    """These synthetic inode cases exercise procfs on every test host."""
    monkeypatch.setattr(orphans, "_HAVE_PROCFS", True)


def test_listener_owned_when_exact_root_process_holds_socket(monkeypatch):
    monkeypatch.setattr(orphans, "_listening_socket_inodes",
                        lambda port: {"41001"})
    monkeypatch.setattr(orphans, "find_orphans",
                        lambda root, exes: [(101, "nginx -p /lane/main")])
    monkeypatch.setattr(orphans, "_process_socket_inodes",
                        lambda pid: {"41001", "41002"})

    assert orphans.listener_owned_by_test_root("/lane", 10005)


def test_listener_without_kernel_socket_is_not_owned(monkeypatch):
    monkeypatch.setattr(orphans, "_listening_socket_inodes", lambda port: set())
    monkeypatch.setattr(orphans, "find_orphans",
                        lambda root, exes: [(101, "nginx -p /lane/main")])

    assert not orphans.listener_owned_by_test_root("/lane", 10005)


def test_foreign_listener_cannot_borrow_stale_owned_process(monkeypatch):
    """Security-negative: argv ownership must intersect the listener inode."""
    monkeypatch.setattr(orphans, "_listening_socket_inodes",
                        lambda port: {"foreign"})
    monkeypatch.setattr(orphans, "find_orphans",
                        lambda root, exes: [(101, "nginx -p /lane/main")])
    monkeypatch.setattr(orphans, "_process_socket_inodes",
                        lambda pid: {"owned-but-not-listening"})

    assert not orphans.listener_owned_by_test_root("/lane", 10005)


@pytest.mark.parametrize('listeners,owned,expected', [
    ({12345: {101, 102}}, [(101, 'owned worker')], {101}),
    ({}, [(101, 'owned worker')], set()),
    ({12345: {102}}, [(101, 'owned worker')], set()),
])
def test_registry_reaper_requires_listener_and_lane_ownership(
        monkeypatch, listeners, owned, expected):
    from brix_suite.launcher import control_operations

    monkeypatch.setattr(orphans, 'find_orphans', lambda root: owned)
    result = control_operations._candidate_pids(object(), lambda spec: [12345], listeners)
    assert result == expected


def test_disk_stop_cannot_kill_another_lanes_listener(monkeypatch):
    from types import SimpleNamespace
    from brix_suite.launcher import internal_operations

    killed = []
    monkeypatch.setattr('lib_py.util.pids_on_port', lambda port: [101, 102])
    monkeypatch.setattr(orphans, 'find_orphans', lambda root: [(101, 'owned helper')])
    monkeypatch.setattr(internal_operations.os, 'kill', lambda pid, sig: killed.append(pid))
    internal_operations._kill_port_processes(SimpleNamespace(port=12345))
    assert killed == [101]


def test_absent_instance_never_waits_for_a_foreign_fleet_to_stop(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from brix_suite.launcher import control_operations

    monkeypatch.setattr(control_operations, '_candidate_pids', lambda *args: set())
    launcher = SimpleNamespace(_read_pid=lambda path: None)
    endpoint = SimpleNamespace(pidfile=str(tmp_path / 'missing'), prefix=str(tmp_path))
    control_operations._stop_nginx(launcher, object(), endpoint)
