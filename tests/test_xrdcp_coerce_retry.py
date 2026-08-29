"""xrdcp -F/--coerce + --retry-policy (parity-audit §7.13, final residuals).

Stock semantics pinned live from 5.6.9 --help: ``-F | --coerce`` "coerces the
copy by ignoring file locking semantics" — the kXR_force (0x0004) open bit on
the remote destination; ``--retry-policy <force|continue>`` chooses whether a
RETRY restarts from scratch or resumes at the partial — "continue" simply
arms the §7.6 byte-offset engine, so each retry picks up where the failed
attempt stopped.

  * success   — -F rides kXR_force on the wire (decoded from the client's own
                --capture bundle) and the upload still succeeds; a severed
                first attempt under --retry-policy continue resumes: the
                retry's connection moves LESS than the file
  * error     — --retry-policy force refetches from zero (the control half of
                the differential); a bogus policy value is exit 50
  * security  — without -F the force bit is ABSENT (the flag cannot leak into
                default opens)

Run:
    PYTHONPATH=tests pytest tests/test_xrdcp_coerce_retry.py -v
"""

import os
import socket
import struct
import subprocess
import threading
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST
from ephemeral_port import free_port

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

kXR_open = 3010
kXR_force = 0x0004

# xdist_group: this module stages its fixture data under the SHARED
# DATA_ROOT in a module-scoped fixture.  Ungrouped cells spread across
# workers under --dist loadgroup, so each worker runs its own copy of
# that fixture and the first teardown deletes the file out from under
# the workers still using it ("NotFound").  One group == one worker.
pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(180),
    pytest.mark.skipif(not os.path.exists(XRDCP),
                       reason="brix-xrdcp not built (client/bin/xrdcp)"),
    pytest.mark.xdist_group("xrdcp-coerce-retry"),
]


def _open_frames(capture_path):
    """Yield the options word of every kXR_open REQUEST in an .xrdcap bundle."""
    blob = open(capture_path, "rb").read()
    assert blob[:8] == b"XRDCAP1\n", "not an xrdcap bundle"
    cur, opts = 8, []
    while cur < len(blob):
        tag = blob[cur:cur + 1]
        cur += 1
        if tag == b"M":
            klen = blob[cur]
            cur += 1 + klen
            vlen = struct.unpack(">H", blob[cur:cur + 2])[0]
            cur += 2 + vlen
        elif tag == b"F":
            is_req = blob[cur + 1]
            code = struct.unpack(">H", blob[cur + 4:cur + 6])[0]
            wl = struct.unpack(">I", blob[cur + 6:cur + 10])[0]
            wire = blob[cur + 10:cur + 10 + wl]
            cur += 10 + wl
            if is_req and code == kXR_open and len(wire) >= 8:
                opts.append(struct.unpack(">H", wire[6:8])[0])
        else:
            break
    return opts


def _close_all(*socks):
    """Best-effort close of every socket; already-closed ones are fine."""
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


class _SeverShim(threading.Thread):
    """MITM that severs connection #1 after `sever_at` downstream bytes, then
    REFUSES new connections for `hold` seconds (so the in-attempt resilient
    reopen exhausts a short --max-stall and the attempt FAILS), then passes
    everything cleanly.  Per-connection downstream byte counts are recorded —
    the resume-vs-restart differential reads them."""

    def __init__(self, backend, sever_at, hold=2.0):
        super().__init__(daemon=True)
        self._backend = backend
        self._sever_at = sever_at
        self._hold = hold
        self._sever_time = None
        self.downstream = []          # bytes forwarded per accepted conn
        self._stop = threading.Event()
        self._lsock = socket.socket()
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind(("127.0.0.1", free_port()))  # net-literal-allow: loopback mock shim; leased mock-range port (never kernel-assigned)
        self._lsock.listen(8)
        self._lsock.settimeout(0.2)
        self.port = self._lsock.getsockname()[1]

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if (self._sever_time is not None
                    and time.monotonic() < self._sever_time + self._hold):
                conn.close()          # refusal window after the sever
                continue
            idx = len(self.downstream)
            self.downstream.append(0)
            threading.Thread(target=self._serve, args=(conn, idx),
                             daemon=True).start()
        self._lsock.close()

    def _serve(self, conn, idx):
        try:
            back = socket.create_connection(self._backend, timeout=10)
        except OSError:
            conn.close()
            return
        threading.Thread(target=self._up, args=(conn, back), daemon=True).start()
        sever = (idx == 0)
        try:
            self._pump_sever(conn, back, idx) if sever else self._relay(conn, back, idx)
        except OSError:
            pass
        if sever:
            self._sever_time = time.monotonic()
        _close_all(conn, back)

    def _relay(self, conn, back, idx):
        """Faithfully relay backend->client until EOF (the non-severing leg),
        counting forwarded bytes — the resume-vs-restart differential reads
        per-connection downstream totals, retry legs included."""
        while True:
            data = back.recv(65536)
            if not data:
                break
            conn.sendall(data)
            self.downstream[idx] += len(data)

    def _sever_slice(self, data, idx):
        """The prefix of `data` that still fits under the sever budget, or None
        once the budget is exhausted (the caller then stops relaying)."""
        room = self._sever_at - self.downstream[idx]
        return None if room <= 0 else data[:room]

    def _pump_sever(self, conn, back, idx):
        """Relay backend->client but truncate the stream once the configured
        byte budget is reached, then stop (the severing leg)."""
        while True:
            data = back.recv(65536)
            if not data:
                break
            data = self._sever_slice(data, idx)
            if data is None:
                break
            conn.sendall(data)
            self.downstream[idx] += len(data)
            if self.downstream[idx] >= self._sever_at:
                break

    @staticmethod
    def _up(conn, back):
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                back.sendall(data)
        except OSError:
            pass

    def stop(self):
        self._stop.set()


CONTENT = bytes((i * 29 + 5) % 251 for i in range(4 * 1024 * 1024))
NAME = "retrypolicy-src.bin"


@pytest.fixture(scope="module", autouse=True)
def staged():
    os.makedirs(DATA_ROOT, exist_ok=True)
    with open(os.path.join(DATA_ROOT, NAME), "wb") as f:
        f.write(CONTENT)
    yield
    try:
        os.remove(os.path.join(DATA_ROOT, NAME))
    except FileNotFoundError:
        pass


def _severed_copy(policy, tmp_path):
    """One severed-then-clean copy under the given retry policy; returns
    (returncode, dest_bytes, per_connection_downstream)."""
    shim = _SeverShim((SERVER_HOST, NGINX_ANON_PORT),
                      sever_at=2 * 1024 * 1024)
    shim.start()
    try:
        dst = tmp_path / "out.bin"
        args = [XRDCP, "--retry", "3", "--max-stall", "700"]
        if policy:
            args += ["--retry-policy", policy]
        args += [f"root://127.0.0.1:{shim.port}//{NAME}", str(dst)]  # net-literal-allow: URL targets the loopback mock shim
        res = subprocess.run(args, capture_output=True, text=True,
                             timeout=150)
        data = dst.read_bytes() if dst.exists() else b""
        return res.returncode, data, list(shim.downstream)
    finally:
        shim.stop()


class TestCoerce:

    def test_coerce_rides_kxr_force(self, tmp_path):
        """(success + security-neg) -F sets kXR_force on the destination open;
        without -F the bit is absent."""
        src = tmp_path / "src.bin"
        src.write_bytes(b"coerce probe\n")
        for flag, want in ((["-F"], True), ([], False)):
            cap = tmp_path / f"cap{want}.xrdcap"
            res = subprocess.run(
                [XRDCP, *flag, "-f", "--capture", str(cap), str(src),
                 f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//coerce-t.bin"],
                capture_output=True, text=True, timeout=60)
            assert res.returncode == 0, res.stderr
            opts = _open_frames(str(cap))
            assert opts, "no kXR_open captured"
            got = any(o & kXR_force for o in opts)
            assert got == want, (flag, [hex(o) for o in opts])
        os.remove(os.path.join(DATA_ROOT, "coerce-t.bin"))


# serial: the resume-vs-restart differential is read from WIRE BYTES moved by
# each retry leg through a severing MITM shim — a loaded parallel lane changes
# the timing the sever and the reconnect race against, which is the measurement
# itself.  Reliable on its own; flaked in the bulk lane.
@pytest.mark.serial
class TestRetryPolicy:

    def test_continue_policy_resumes(self, tmp_path):
        """(success) severed first attempt + --retry-policy continue: the
        retry moves LESS than the file (it resumed) and the result is
        byte-exact."""
        rc, data, per_conn = _severed_copy("continue", tmp_path)
        assert rc == 0, f"copy failed: {per_conn}"
        assert data == CONTENT
        assert len(per_conn) >= 2, per_conn
        # A genuine resume skips at least the completed chunks of attempt 1
        # (≥ 1 MiB of the 2 MiB the shim forwarded; one in-flight chunk is
        # legitimately lost). per_conn counts WIRE bytes, so allow framing
        # overhead: anything ≥ 256 KiB under a full refetch proves the resume;
        # a force-restart measures ≥ len(CONTENT) + overhead.
        resumed = sum(per_conn[1:])
        assert resumed <= len(CONTENT) - 256 * 1024, (
            f"retry refetched the whole file — no resume: {per_conn}")

    def test_force_policy_restarts(self, tmp_path):
        """(error-shape control) the same sever under --retry-policy force
        refetches the WHOLE file on the retry."""
        rc, data, per_conn = _severed_copy("force", tmp_path)
        assert rc == 0, f"copy failed: {per_conn}"
        assert data == CONTENT
        assert len(per_conn) >= 2, per_conn
        assert max(per_conn[1:]) >= len(CONTENT) * 9 // 10, (
            f"force policy did not restart from zero: {per_conn}")

    def test_bogus_policy_usage_error(self, tmp_path):
        res = subprocess.run(
            [XRDCP, "--retry-policy", "sideways",
             f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//{NAME}",
             str(tmp_path / "o")],
            capture_output=True, text=True, timeout=30)
        assert res.returncode == 50
        assert "retry-policy" in res.stderr
