"""
test_fault_proxy_counters.py — the fault proxy's own counters are the witness
that a fault test was not vacuous.

WHAT: pins `FaultProxy.counters()`: the parse of the proxy's `metrics` reply
      into ints, that `corrupt_total` moves only when the corruption lever is
      armed, and that a torn-down proxy raises instead of reporting a stale
      snapshot.

WHY:  a wire-fault test reads the client's exit code, and a clean exit means
      two opposite things — the defence held, or the fault never fired. The
      second is a green test that asserts nothing. `resilience/
      test_tls_token_leg_sweep.py` now guards every corruption case with
      `flips > 0` taken from this counter, so the counter itself has to be
      trustworthy: it must count real flips, and it must read 0 when nothing
      was flipped, or the guard is decoration.

HOW:  no XRootD stack is involved. A throwaway TCP server hands a fixed blob to
      whoever connects, the proxy is spliced in front of it, and a plain socket
      reads through the proxy — so the bytes crossing the relay, and therefore
      the counters, are fully determined by the test.

Run:
  PYTHONPATH=tests python3 -m pytest tests/resilience/test_fault_proxy_counters.py -v
"""
import os
import socket
import socketserver
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402
from ephemeral_port import free_port  # noqa: E402
from settings import BIND_HOST, HOST  # noqa: E402

pytestmark = pytest.mark.timeout(120)

BLOB = bytes(range(256)) * 256          # 64 KiB, every byte value represented
HEAVY_PCT = 5.0                         # 50000 ppm: flips are a certainty


if not os.path.isfile(servers.FAULT_PROXY):
    pytest.skip(f"brix-fault-proxy not built: {servers.FAULT_PROXY}",
                allow_module_level=True)


class _BlobHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(BLOB)


@pytest.fixture(scope="module")
def origin():
    """A TCP server that answers every connection with BLOB and nothing else.

    The port is leased from the lane's mock range rather than kernel-assigned:
    a port 0 bind is invisible to the lane ledger and can land on a managed
    service's port."""
    port = free_port()
    srv = socketserver.ThreadingTCPServer((BIND_HOST, port), _BlobHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield port
    finally:
        srv.shutdown()
        srv.server_close()


def _read_through(proxy):
    """Drain one full response from behind the proxy; returns the bytes read."""
    with socket.create_connection((HOST, proxy.listen), timeout=10) as s:
        got = b""
        while len(got) < len(BLOB):
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
        return got


def test_counters_parse_and_count_a_real_relay(origin):
    """SUCCESS: the reply parses to ints under the documented keys, and a relay
    of exactly len(BLOB) bytes moves `bytes_down` by exactly that much."""
    with servers.FaultProxy(origin) as fp:
        before = fp.counters()
        assert before["corrupt_total"] == 0, "a fresh proxy has flipped nothing"
        assert all(isinstance(v, int) for v in before.values()), before
        for key in ("conns_total", "bytes_up", "bytes_down", "severs_total",
                    "corrupt_total", "refused_total"):
            assert key in before, f"{key} missing from {sorted(before)}"

        got = _read_through(fp)
        after = fp.counters()

        assert got == BLOB, "the clean relay did not deliver the blob verbatim"
        assert after["bytes_down"] - before["bytes_down"] == len(BLOB)
        assert after["conns_total"] - before["conns_total"] == 1


def test_corrupt_total_stays_zero_when_the_lever_is_not_armed(origin):
    """SECURITY-NEGATIVE: the vacuity guard has teeth. If `corrupt_total` rose
    on its own — or the parse silently produced a non-zero from a HELP/TYPE
    line — then `flips > 0` in the sweep would pass without any corruption and
    every corruption defence in that module would be asserting nothing."""
    with servers.FaultProxy(origin) as fp:
        before = fp.counters()["corrupt_total"]
        got = _read_through(fp)
        after = fp.counters()["corrupt_total"]

        assert got == BLOB, "an unarmed proxy must forward byte-for-byte"
        assert after - before == 0, (
            f"{after - before} byte(s) counted as corrupted with the lever "
            "disarmed — the vacuity guard cannot fail, so it guards nothing")


def test_counters_count_the_bytes_the_lever_actually_flipped(origin):
    """The counter is a count of damage, not a boolean: at 5% every relay is
    hit many times, the delta matches the number of positions that actually
    differ, and the delivered length is unchanged (a flip is length-preserving,
    which is exactly why a plain read cannot notice it)."""
    with servers.FaultProxy(origin) as fp:
        fp.set_corrupt(HEAVY_PCT, "down")
        before = fp.counters()["corrupt_total"]
        got = _read_through(fp)
        flips = fp.counters()["corrupt_total"] - before

        assert len(got) == len(BLOB), "a bit flip must not change the length"
        assert flips > 0, "5% of 64 KiB flipped nothing"
        differing = sum(1 for a, b in zip(got, BLOB) if a != b)
        assert differing == flips, (
            f"the counter says {flips} flips but {differing} bytes differ")


def test_counters_raise_once_the_proxy_is_gone(origin):
    """ERROR: a control socket that no longer answers must surface as an OSError
    from the read, never as a stale or empty snapshot — a caller differencing
    two samples would otherwise compute a plausible-looking 0."""
    with servers.FaultProxy(origin) as fp:
        fp.counters()
    with pytest.raises(OSError):
        fp.counters()
