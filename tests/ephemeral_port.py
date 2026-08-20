"""Session-owned, range-assigned ports for non-registry test listeners.

``free_port`` remains only as a compatibility name.  It no longer binds port
zero or asks the kernel for a random ephemeral port: every value is leased from
the ``TEST_PORT_START`` mock range declared in :mod:`port_ladder`.  The lease
registry is shared by xdist workers, so mocks, stock-xrootd upstreams and lab
proxies receive distinct infrastructure-assigned ports just like fleet servers.
"""

from __future__ import annotations

import fcntl
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
    key = f"{test}|{site}"
    ordinal = _CALLS.get(key, 0)
    _CALLS[key] = ordinal + 1
    return f"{key}|{ordinal}"


def _lease_path() -> Path:
    """Return the TEST_ROOT-scoped lease registry path."""
    root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))
    root.mkdir(parents=True, exist_ok=True)
    return root / "mock-port-leases.json"


def _assigned_port() -> int:
    """Lease one unused fixed mock slot from the shared test infrastructure."""
    path = _lease_path()
    key = _caller_key()
    with path.open("a+", encoding="utf-8") as registry:
        fcntl.flock(registry.fileno(), fcntl.LOCK_EX)
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
