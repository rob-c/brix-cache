"""
test_official_vs_brix_cache_faults.py — under a hostile origin network the
OFFICIAL XRootD server cannot deliver a read, while a brix-cache tier fronting
that same origin still serves the bytes byte-exact.  OFFICIAL CLIENT TOOLS ONLY.

WHAT: one topology per fault —

        official leg (xfail):   xrdcp ─► [ fault ] ─► official xrootd origin
        brix leg     (pass):    xrdcp ─► brix-cache ─► [ fault ] ─► same origin
                                              └─ warm local copy, served on hit

      The fault (payload corruption / packet reorder / packet loss / a
      black-holed connection) sits on the path to the ORIGIN.  The official
      client has no tier between it and the origin, so it must cross the bad
      link and fails.  The brix-cache client crosses a clean local link to the
      cache, which already holds a complete, freshness-validated copy (warmed
      before the fault is engaged) and serves it from the local store.

WHY:  the whole point of a read-through cache in front of a flaky/​distant
      origin is decoupling: once a file is resident, a delivery to a client
      must not depend on the origin link being healthy.  These tests pin that
      promise against the exact wire pathologies a plain server cannot survive,
      using ONLY the stock `/usr/bin/xrdcp` so the result is about the SERVER,
      not this repo's client.

      The official legs are marked xfail(strict): we ASSERT the stock server
      cannot deliver under the fault.  If one ever unexpectedly succeeds
      (XPASS) the suite fails loudly — that is a claim we want kept honest.

NOTE ON LATENCY: on a cache hit the open path still probes the origin for
      freshness before falling back to the local copy.  A *refused* / corrupt /
      lossy origin fails that probe fast; a *silently black-holed* origin makes
      the probe wait out the backend timeout (~30s) before the cache is served.
      Either way the brix client gets correct bytes; the official client never
      does.  The brix legs therefore run with a generous client timeout — the
      guarantee under test is correct DELIVERY, not latency.

Skips cleanly when the official `xrootd` server, the official `/usr/bin/xrdcp`,
the repo nginx, or the fault proxy is absent.

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_official_vs_brix_cache_faults.py -v
"""
import hashlib
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "resilience"))
from resilience.servers import XrootdAnon, FaultProxy, seed_file, FAULT_PROXY  # noqa: E402
from server_registry import NginxInstanceSpec  # noqa: E402

# Stock client + server ONLY — the whole comparison is about the server, so we
# deliberately do NOT use this repo's xrdcp here.
OFFICIAL_XRDCP = "/usr/bin/xrdcp"
XROOTD = shutil.which("xrootd")

from settings import HOST
FILE_MB = 4

pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(240),
              pytest.mark.xdist_group("lc-fault-cache")]

_SKIP = None
if not XROOTD:
    _SKIP = "need the official `xrootd` server on PATH"
elif not os.path.isfile(OFFICIAL_XRDCP):
    _SKIP = f"need the official client at {OFFICIAL_XRDCP}"
elif not os.path.isfile(FAULT_PROXY):
    _SKIP = "need the built brix-fault-proxy"


def _md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _base_env():
    e = dict(os.environ)
    e.pop("LD_LIBRARY_PATH", None)   # keep the stock XRootD libs clean
    return e


def _tight_env():
    """Deployment-realistic client timeouts.  Makes a black-holed / reordered /
    slow origin surface as a deterministic client-side failure rather than an
    unbounded wait — so the official leg fails within a bounded window."""
    e = _base_env()
    e.update(XRD_REQUESTTIMEOUT="8", XRD_STREAMTIMEOUT="4", XRD_CONNECTIONWINDOW="4",
             XRD_CONNECTIONRETRY="1", XRD_TIMEOUTRESOLUTION="1")
    return e


def _loose_env():
    """Generous client timeouts for the brix leg: the cache open path may wait
    out a one-time origin freshness probe before serving the local copy.  The
    property under test is correct delivery, not speed."""
    e = _base_env()
    e.update(XRD_REQUESTTIMEOUT="60", XRD_STREAMTIMEOUT="60", XRD_CONNECTIONWINDOW="10",
             XRD_CONNECTIONRETRY="1", XRD_TIMEOUTRESOLUTION="1")
    return e


def _xrdcp(url, out, env, timeout):
    """Run the stock client.  A client-side hang (subprocess timeout) is a
    delivery FAILURE, not a test error: return a sentinel rc so callers assert
    on it uniformly."""
    if os.path.exists(out):
        os.remove(out)
    try:
        r = subprocess.run([OFFICIAL_XRDCP, "-f", url, out],
                           env=env, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "client hung — did not deliver within the window"
    return r.returncode, r.stderr.decode(errors="replace")


def _delivered(rc, out, ref):
    return rc == 0 and os.path.exists(out) and _md5(out) == ref


# --- faults the stock server cannot survive but the cache tier can -------------
# Each engages a lever on the origin-side link.  Keys map to the user's terms:
#   corruption   — in-band bit-flips (MITM / flaky NIC past the TCP checksum)
#   out_of_order — packet reordering with delay
#   loss         — per-chunk connection severing
#   blackhole    — accept-but-never-relay (silent drop)
FAULTS = {
    "corruption":   lambda P: P.set_corrupt(15, "down"),
    "out_of_order": lambda P: P.ctl("reorder 50 2000"),
    "loss":         lambda P: P.set_loss(30),
    "blackhole":    lambda P: P.ctl("hang"),
}


class _Link:
    def __init__(self, proxy, ref, cache_url, direct_url):
        self.P = proxy
        self.ref = ref
        self.cache_url = cache_url
        self.direct_url = direct_url


@pytest.fixture
def link(lifecycle, tmp_path):
    """Stand up: official xrootd origin ─► fault proxy ─► brix-cache (nginx),
    seed a file, warm the cache through the (clean) proxy, then hand back the
    levers with the proxy reset.  Each test engages its own fault."""
    if _SKIP:
        pytest.skip(_SKIP)

    with XrootdAnon() as origin:
        ref = _md5(seed_file(origin.data, "/big.bin", FILE_MB * 1024 * 1024))
        with FaultProxy(origin.port) as proxy:
            cache_dir = tmp_path / "cache"
            export_dir = tmp_path / "export"
            cache_dir.mkdir()
            export_dir.mkdir()
            cache = lifecycle.start(NginxInstanceSpec(
                name="brix-fault-cache",
                template="nginx_lc_cache_partial_cache.conf",
                protocol="root",
                data_root=str(cache_dir),
                template_values={
                    "BIND_HOST": HOST,
                    "CACHE_ALLOW_WRITE": "",
                    "CACHE_EXPORT": f"        brix_export {export_dir};\n",
                    "CACHE_BACKEND": f"root://{HOST}:{proxy.listen}",
                    "CACHE_STORE": str(cache_dir),
                    "CACHE_SLICE_SIZE": "", "CACHE_MAX_OBJECT": "",
                    "CACHE_DENY_PREFIX": "", "CACHE_INCLUDE_REGEX": "",
                }))
            cache_url = f"root://{HOST}:{cache.port}//big.bin"
            direct_url = f"root://{HOST}:{proxy.listen}//big.bin"

            # Warm the cache with the link healthy, so the resilience under test
            # is genuinely "serve the resident copy", not "fill through a fault".
            proxy.clear()
            rc, err = _xrdcp(cache_url, str(tmp_path / "warm.bin"),
                             _loose_env(), timeout=30)
            assert _delivered(rc, str(tmp_path / "warm.bin"), ref), \
                f"cache warm-up failed (rc={rc}): {err[-300:]}"

            proxy.clear()
            yield _Link(proxy, ref, cache_url, direct_url)
            proxy.clear()


# --- baseline -----------------------------------------------------------------

def test_clean_link_baseline(link, tmp_path):
    """SUCCESS: with the link healthy the stock client delivers byte-exact both
    ways — direct-from-origin and via the cache.  Without this, a 'differentiator'
    below could be an artifact of a broken topology rather than the fault."""
    direct = str(tmp_path / "d.bin")
    cached = str(tmp_path / "c.bin")
    rc, err = _xrdcp(link.direct_url, direct, _loose_env(), timeout=30)
    assert _delivered(rc, direct, link.ref), f"direct baseline failed: {err[-200:]}"
    rc, err = _xrdcp(link.cache_url, cached, _loose_env(), timeout=30)
    assert _delivered(rc, cached, link.ref), f"cache baseline failed: {err[-200:]}"


# --- official xrootd: cannot deliver under the fault (xfail strict) ------------

@pytest.mark.parametrize("fault", list(FAULTS))
@pytest.mark.xfail(strict=True,
                   reason="stock xrootd has no cache tier — it must cross the "
                          "faulted origin link and cannot deliver the read")
def test_official_xrootd_fails_under_fault(link, tmp_path, fault):
    """The stock server, read DIRECTLY through the faulted link with realistic
    client timeouts, cannot return the file byte-exact.  Asserted as the healthy
    outcome (delivery) so the fault turns it into an expected FAILURE — and an
    XPASS (server somehow delivered) fails the suite."""
    FAULTS[fault](link.P)
    out = str(tmp_path / f"official_{fault}.bin")
    rc, err = _xrdcp(link.direct_url, out, _tight_env(), timeout=30)
    assert _delivered(rc, out, link.ref), (
        f"[{fault}] official xrootd did not deliver (rc={rc}): {err[-200:]}")


# --- brix-cache: still delivers under the same fault --------------------------

@pytest.mark.parametrize("fault", list(FAULTS))
def test_brix_cache_survives_fault(link, tmp_path, fault):
    """The brix-cache tier, fronting the SAME faulted origin, serves the warm
    local copy byte-exact — the client crosses a clean link to the cache and
    never depends on the sick origin path.  This is the resilience the stock
    server lacks."""
    FAULTS[fault](link.P)
    out = str(tmp_path / f"brix_{fault}.bin")
    rc, err = _xrdcp(link.cache_url, out, _loose_env(), timeout=90)
    assert rc == 0, f"[{fault}] brix-cache read failed (rc={rc}): {err[-300:]}"
    assert _md5(out) == link.ref, \
        f"[{fault}] brix-cache delivered wrong bytes — not byte-exact"
