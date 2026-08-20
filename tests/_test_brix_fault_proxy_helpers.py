"""
test_brix_fault_proxy.py — CLI + behaviour tests for the first-class
`brix-fault-proxy` tool (client/apps/diag/brix_fault_proxy.c).

The 3-test ritual for the new command-line surface:

* SUCCESS  — `--version`/`--help` print the house strings, and a live relay in
             front of a loopback echo server forwards bytes byte-exact while the
             control port reports and mutates the fault levers.
* ERROR    — malformed / incomplete invocations exit 2 with a usage diagnostic
             (missing required endpoints, a colon-less `--target`, and a mix of
             positional + named forms).
* SECURITY — the *unauthenticated* control port must bind to loopback by default;
             a non-loopback `--bind` is refused unless `--insecure-bind` is also
             given.

Self-contained: builds the tool via `make -C client brix-fault-proxy` and drives
it against its own throwaway echo server on ephemeral ports. No fleet server, so
no registry-server declaration is needed.
"""

import os
import socket
import subprocess
import threading
import time

import pytest

from settings import BIND_HOST, HOST

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
BFP = os.path.join(CLIENT_DIR, "bin", "brix-fault-proxy")


@pytest.fixture(scope="module")
def bfp():
    """Path to a freshly built brix-fault-proxy (skip if it can't be built)."""
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "brix-fault-proxy"],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 or not os.path.exists(BFP):
        pytest.skip(f"brix-fault-proxy build failed:\n{proc.stdout}\n{proc.stderr}")
    return BFP


def _free_port():
    from ephemeral_port import free_port
    return free_port(BIND_HOST)


def _wait_port(port, deadline=5.0):
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection((HOST, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.02)
    return False


class _Echo:
    """A trivial upstream: prefixes every received blob with b'echo:'."""

    def __init__(self):
        self.port = _free_port()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((BIND_HOST, self.port))
        self._srv.listen(8)
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        self._srv.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                continue
            try:
                data = conn.recv(4096)
                if data:
                    conn.sendall(b"echo:" + data)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self):
        self._stop = True
        self._srv.close()


class _StreamEcho:
    """A streaming upstream: echoes every byte it receives, in a loop, so large
    payloads flow back through the proxy where byte-level levers apply."""

    def __init__(self):
        self.port = _free_port()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((BIND_HOST, self.port))
        self._srv.listen(8)
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        self._srv.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        conn.settimeout(2.0)
        try:
            while not self._stop:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self._stop = True
        self._srv.close()


def _drain(sock, want, deadline=3.0):
    """Read up to `want` bytes until the peer closes or the deadline passes."""
    sock.settimeout(0.5)
    end = time.time() + deadline
    out = b""
    while len(out) < want and time.time() < end:
        try:
            d = sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            break
        if not d:
            break
        out += d
    return out


def _spawn(bfp, echo_port, extra=None):
    """Start a proxy in front of `echo_port`; return (proc, listen, ctl)."""
    listen, ctl = _free_port(), _free_port()
    argv = [bfp, "--listen", str(listen), "--target", f"{HOST}:{echo_port}",
            "--control", str(ctl), "--quiet"] + (extra or [])
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert _wait_port(ctl), "control port never came up"
    assert _wait_port(listen), "listen port never came up"
    # _wait_port(listen) proves that the socket is bound, but its probe can
    # still be queued for accept when the caller starts exercising admission
    # controls.  Drain that probe before returning so max-conns and fail-nth
    # tests never race the proxy's accept loop.
    deadline = time.time() + 2.0
    while time.time() < deadline:
        if _stat_int(ctl, "conns") >= 1 and _stat_int(ctl, "active") == 0:
            break
        time.sleep(0.02)
    return proc, listen, ctl


def _ctl(port, cmd):
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(4096).decode()


def _stat_int(ctl, key):
    """Pull an integer `key=NNN` field out of the status line."""
    for tok in _ctl(ctl, "status").replace("]", " ").replace("[", " ").split():
        if tok.startswith(key + "="):
            return int(tok.split("=", 1)[1].rstrip("B"))
    raise AssertionError(f"{key} not in status")


# --------------------------------------------------------------------------- #
# SUCCESS                                                                      #
# --------------------------------------------------------------------------- #
