"""``lib_py.util.pids_on_port``: EVERY process holding a listener, not one.

Callers reap a leaked server by killing what this returns.  A pre-forking
server shares its listening socket with its children, so a list naming only a
child frees nothing: the parent respawns it and the port stays bound.  That is
exactly what Darwin's netstat reports (one owner per socket), which is why the
lookup uses lsof there.
"""
import json
import os
import signal
import subprocess
import sys

import pytest

from ephemeral_port import free_port
from lib_py.util import pids_on_port
from settings import HOST

#: A stand-in for a pre-forking server: bind a listener, fork, and report both
#: pids.  Run as a SUBPROCESS — forking inside pytest inherits its capture and
#: plugin state, which deadlocks.
#:
#: Host and port are formatted in by the parent rather than asked of the kernel:
#: this listener lives for the whole case, and an unledgered ephemeral one can
#: land on a managed fleet port (``test_fleet_port_uniqueness``).
_SERVER = """
import json, os, socket, sys, time
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(({host!r}, {port}))
srv.listen(4)
port = srv.getsockname()[1]
child = os.fork()
if child == 0:
    time.sleep(120)
    os._exit(0)
print(json.dumps({{"port": port, "parent": os.getpid(), "child": child}}), flush=True)
time.sleep(120)
"""


@pytest.fixture
def shared_listener():
    source = _SERVER.format(host=HOST, port=free_port())
    # Own session, and tear down the whole GROUP: the helper's whole point is a
    # forked child holding the same listening socket, and proc.kill() reaps only
    # the parent — the child keeps the port bound for its full sleep.  Invisible
    # while the port was kernel-assigned (each run drew a fresh one); with a
    # stable per-call-site lease the orphan collides with the next case, which
    # then fails as EADDRINUSE in the helper rather than as anything real.
    proc = subprocess.Popen([sys.executable, "-c", source],
                            stdout=subprocess.PIPE, text=True,
                            start_new_session=True)
    try:
        line = proc.stdout.readline()
        assert line, "listener helper produced no handshake"
        info = json.loads(line)
        yield info["port"], info["parent"], info["child"]
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            proc.kill()
        proc.wait()


def test_every_holder_is_reported(shared_listener):
    """success: the parent AND the child that inherited the socket."""
    port, parent, child = shared_listener
    found = set(pids_on_port(port))
    assert parent in found, (parent, found)
    assert child in found, (child, found)


def test_a_free_port_reports_nobody():
    """error path: a port nothing listens on yields an empty list, so a caller
    reaping it kills nothing."""
    # A mock-range lease: owned by this session, so nothing in the lane holds
    # it — which is exactly the precondition the case needs — and unlike a
    # kernel-assigned port it stays visible to the test-port ledger.
    assert pids_on_port(free_port()) == []


def test_the_parent_is_never_omitted(shared_listener):
    """security-negative: naming only the child is the defect this pins — a
    reaper that killed just the child would watch the parent respawn it while
    the port stayed bound."""
    port, parent, _child = shared_listener
    assert parent in set(pids_on_port(port))
