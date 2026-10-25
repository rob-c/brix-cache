"""Session-owned, range-assigned ports for non-registry test listeners.

``free_port`` remains only as a compatibility name.  It no longer binds port
zero or asks the kernel for a random ephemeral port: every value is leased from
the ``TEST_PORT_START`` mock range declared in :mod:`port_ladder`.  The lease
registry is shared by xdist workers, so mocks, stock-xrootd upstreams and lab
proxies receive distinct infrastructure-assigned ports just like fleet servers.
"""

from __future__ import annotations

from contextlib import contextmanager
from functools import partial
import inspect
import json
import os
from pathlib import Path

from port_ladder import MOCK_PORT_FIRST, MOCK_PORT_LAST


_CALLS: dict[str, int] = {}


def _managed_lane(port):
    """Return whether *port* belongs to this run's fixed test-port ladder."""
    from port_ladder import PORT_FIRST

    return PORT_FIRST <= port <= MOCK_PORT_LAST


def _caller_key() -> str:
    """Return the current test/call-site identity for one port lease."""
    frame = inspect.currentframe()
    assert frame is not None
    caller = frame.f_back
    while caller and Path(caller.f_code.co_filename).name == Path(__file__).name:
        caller = caller.f_back
    if caller is None:
        site = "unknown"
    else:
        site = f"{caller.f_code.co_filename}:{caller.f_lineno}"
    test = os.environ.get("PYTEST_CURRENT_TEST")
    if not test:
        test = f"pid-{os.getpid()}"
    # Long-lived fixture subprocesses inherit the same PYTEST_CURRENT_TEST as
    # their parent and keep independent in-memory ordinal counters.  Include
    # the process identity so two such fixtures cannot be handed the same
    # supposedly session-unique listener port.
    key = f"{test}|pid-{os.getpid()}|{site}"
    ordinal = _CALLS.get(key, 0)
    _CALLS[key] = ordinal + 1
    return f"{key}|{ordinal}"


def _lease_path() -> Path:
    """Return the TEST_ROOT-scoped lease registry path."""
    root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))
    root.mkdir(parents=True, exist_ok=True)
    return root / "mock-port-leases.json"


@contextmanager
def _registry_lock(registry):
    """Serialize the same lease file on Unix and Windows.

    msvcrt locks from the current offset, including beyond EOF for a new
    registry. LK_LOCK bounds acquisition to ten attempts; a failed acquisition
    never enters the critical section or tries to unlock an unowned region.
    """
    fd = registry.fileno()
    registry.seek(0)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        unlock = partial(msvcrt.locking, fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        unlock = partial(fcntl.flock, fd, fcntl.LOCK_UN)
    try:
        yield
    finally:
        try:
            registry.flush()
        finally:
            registry.seek(0)
            unlock()


def _assigned_port() -> int:
    """Lease one unused fixed mock slot from the shared test infrastructure."""
    if MOCK_PORT_FIRST > MOCK_PORT_LAST:
        raise RuntimeError("mock-port allocation disabled for this partial lane")
    path = _lease_path()
    key = _caller_key()
    with path.open("a+", encoding="utf-8") as registry, _registry_lock(registry):
        registry.seek(0)
        try:
            leases = json.load(registry)
        except json.JSONDecodeError:
            leases = {}
        if key not in leases:
            port = MOCK_PORT_FIRST + len(leases)
            if port > MOCK_PORT_LAST:
                raise RuntimeError(
                    "test mock-port range exhausted; increase MOCK_PORT_WIDTH "
                    "in tests/port_ladder.py"
                )
            leases[key] = port
            registry.seek(0)
            registry.truncate()
            json.dump(leases, registry, sort_keys=True)
            registry.flush()
        return int(leases[key])


def free_port(host="127.0.0.1"):
    """Return one infrastructure-assigned port from the mock range.

    ``host`` remains for call-site compatibility; allocation is host-agnostic
    because the range is globally unique within a test session.
    """
    del host
    return _assigned_port()


def free_ports(n, host="127.0.0.1"):
    """Return ``n`` distinct infrastructure-assigned mock ports."""
    del host
    return [_assigned_port() for _ in range(n)]


def bind_port(factory, host="127.0.0.1", attempts=5):
    """Create a listener on a leased port, retrying bounded bind collisions.

    The fixed mock window can overlap the host's ephemeral client range.  A
    lease prevents two test fixtures choosing the same slot, but cannot prevent
    the kernel briefly assigning that slot to an outbound connection between
    allocation and bind.  ``factory`` owns cleanup when its bind fails.
    """
    if attempts < 1:
        raise ValueError("attempts must be positive")
    for attempt in range(attempts):
        port = free_port(host)
        try:
            return port, factory(port)
        except OSError:
            if attempt == attempts - 1:
                raise
    raise AssertionError("unreachable leased-port retry state")
