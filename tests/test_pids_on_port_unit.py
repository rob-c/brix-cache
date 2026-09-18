"""``lib_py.util.pids_on_port``: EVERY process holding a listener, not one.

Callers reap a leaked server by killing what this returns.  A pre-forking
server shares its listening socket with its children, so a list naming only a
child frees nothing: the parent respawns it and the port stays bound.  That is
exactly what Darwin's netstat reports (one owner per socket), which is why the
lookup uses lsof there.
"""
import json
import socket
import subprocess
import sys

import pytest

from lib_py.util import pids_on_port

#: A stand-in for a pre-forking server: bind a listener, fork, and report both
#: pids.  Run as a SUBPROCESS — forking inside pytest inherits its capture and
#: plugin state, which deadlocks.
_SERVER = """
import json, os, socket, sys, time
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(4)
port = srv.getsockname()[1]
child = os.fork()
if child == 0:
    time.sleep(120)
    os._exit(0)
print(json.dumps({"port": port, "parent": os.getpid(), "child": child}), flush=True)
time.sleep(120)
"""


@pytest.fixture
def shared_listener():
    proc = subprocess.Popen([sys.executable, "-c", _SERVER],
                            stdout=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline()
        assert line, "listener helper produced no handshake"
        info = json.loads(line)
        yield info["port"], info["parent"], info["child"]
    finally:
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
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))   # net-literal-allow: the loopback probe is the subject
    free = probe.getsockname()[1]
    probe.close()
    assert pids_on_port(free) == []


def test_the_parent_is_never_omitted(shared_listener):
    """security-negative: naming only the child is the defect this pins — a
    reaper that killed just the child would watch the parent respawn it while
    the port stayed bound."""
    port, parent, _child = shared_listener
    assert parent in set(pids_on_port(port))
