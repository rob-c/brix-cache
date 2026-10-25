"""Actual private Alma lease files and offline Windows lock boundaries.

No sockets are opened. Windows byte-range locking follows the stdlib contract:
https://docs.python.org/3/library/msvcrt.html#msvcrt.locking
"""

import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

import ephemeral_port as ports


@pytest.mark.parametrize("scenario,error,expected,body_entered", [
    ("success", None, [(1, 1, 0), (0, 1, 0)], [True]),
    ("body-error", ValueError, [(1, 1, 0), (0, 1, 0)], [True]),
    ("lock-error", OSError, [(1, 1, 0)], []),
])
def test_windows_lock_owns_byte_zero_until_cleanup(
        tmp_path, monkeypatch, scenario, error, expected, body_entered):
    calls = []
    entered = []

    def locking(fd, mode, size):
        calls.append((mode, size, os.lseek(fd, 0, os.SEEK_CUR)))
        if scenario == "lock-error" and mode == 1:
            raise OSError("lock unavailable")

    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(
        locking=locking, LK_LOCK=1, LK_UNLCK=0))
    monkeypatch.setattr(ports, "os", SimpleNamespace(name="nt"))
    with (tmp_path / "registry").open("w+") as registry:
        registry.write("old")
        registry.flush()

        def critical_section():
            with ports._registry_lock(registry):
                entered.append(True)
                registry.seek(0, os.SEEK_END)
                registry.write("-new")
                if scenario == "body-error":
                    raise ValueError("body failed")

        if error is None:
            critical_section()
        else:
            with pytest.raises(error):
                critical_section()
        assert entered == body_entered
        assert calls == expected


def test_private_lease_registry_serializes_processes(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_ROOT", str(tmp_path))
    tests = str(Path(__file__).parent)
    command = [sys.executable, "-c", "import json; from ephemeral_port import free_ports; "
               "print(json.dumps(free_ports(12)))"]
    children = [subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=dict(os.environ, PYTHONPATH=tests, PYTEST_CURRENT_TEST=f"lease-child-{i}"))
        for i in range(2)]
    assigned = []
    for child in children:
        output, error = child.communicate(timeout=15)
        assert child.returncode == 0, error
        assigned.extend(json.loads(output))
    recorded = json.loads((tmp_path / "mock-port-leases.json").read_text())
    assert len(assigned) == len(set(assigned)) == len(recorded) == 24
    assert sorted(assigned) == list(range(ports.MOCK_PORT_FIRST, ports.MOCK_PORT_FIRST + 24))


def test_private_leases_distinguish_processes_with_same_test_identity(
        tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_ROOT", str(tmp_path))
    tests = str(Path(__file__).parent)
    command = [sys.executable, "-c",
               "from ephemeral_port import free_port; print(free_port())"]
    env = dict(os.environ, PYTHONPATH=tests,
               PYTEST_CURRENT_TEST="shared-fixture-setup")
    children = [subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=env) for _ in range(2)]
    assigned = []
    for child in children:
        output, error = child.communicate(timeout=15)
        assert child.returncode == 0, error
        assigned.append(int(output))
    assert len(set(assigned)) == 2


def test_exhausted_registry_preserves_existing_leases(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_ROOT", str(tmp_path))
    monkeypatch.setattr(ports, "MOCK_PORT_LAST", ports.MOCK_PORT_FIRST)
    path = tmp_path / "mock-port-leases.json"
    original = json.dumps({"already-owned": ports.MOCK_PORT_FIRST})
    path.write_text(original)
    with pytest.raises(RuntimeError, match="test mock-port range exhausted"):
        ports.free_port()
    assert path.read_text() == original


def test_bind_port_returns_the_successful_lease(monkeypatch):
    monkeypatch.setattr(ports, "free_port", lambda _host: 41001)
    assert ports.bind_port(lambda port: f"listener-{port}") == \
        (41001, "listener-41001")


def test_bind_port_retries_one_ephemeral_collision(monkeypatch):
    leases = iter((41001, 41002))
    monkeypatch.setattr(ports, "free_port", lambda _host: next(leases))

    def factory(port):
        if port == 41001:
            raise OSError("address already in use")
        return "listener"

    assert ports.bind_port(factory) == (41002, "listener")


def test_bind_port_fails_closed_after_its_bound(monkeypatch):
    calls = []
    monkeypatch.setattr(ports, "free_port", lambda _host: 41001 + len(calls))

    def collision(port):
        calls.append(port)
        raise OSError("address already in use")

    with pytest.raises(OSError, match="address already in use"):
        ports.bind_port(collision, attempts=3)
    assert calls == [41001, 41002, 41003]


def test_unix_lock_excludes_a_second_process_until_release(tmp_path):
    pytest.importorskip("fcntl")
    path = tmp_path / "registry"
    script = (
        "import fcntl, sys\n"
        "with open(sys.argv[1], 'a+') as registry:\n"
        "    try:\n"
        "        fcntl.flock(registry.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
        "    except BlockingIOError:\n"
        "        raise SystemExit(23)\n"
    )
    command = [sys.executable, "-c", script, str(path)]
    with path.open("a+") as registry:
        with ports._registry_lock(registry):
            blocked = subprocess.run(command, capture_output=True, timeout=15)
            assert blocked.returncode == 23, blocked.stderr
    released = subprocess.run(command, capture_output=True, timeout=15)
    assert released.returncode == 0, released.stderr
