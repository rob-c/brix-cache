"""Phase-85 F10 — full offline survival: brix_cvmfs_offline_ttl.

Theme
-----
The phase-68 stale-if-error window hard-fails 10 x manifest_ttl after the last
successful fill — a long Stratum-1 outage takes the repo down even with every
byte cached. ``brix_cvmfs_offline_ttl <time>`` (default 0 = off) stretches that
survival horizon: through a total origin outage the site keeps serving the
last-known-good manifest — verified at fill time by the F1 signature chain —
until offline_ttl past its fill. Contract:

* past 10 x TTL but inside offline_ttl → the pinned manifest serves 200 with
  one parsable ``event=offline-degraded`` NOTICE per serve;
* already-cached CAS objects (immutable, content-addressed) serve throughout —
  the surviving view is coherent because the pinned manifest only names them;
* an UNCACHED object during the outage is refused (origin error), never
  fabricated;
* past offline_ttl the horizon is exhausted: hard failure, exactly like
  phase-68 at 10 x TTL;
* offline_ttl unset → 10 x TTL behavior is untouched (parity).

Timing: filled_at/expiry are WALL-clock and the WSL2 wall clock skews against
CLOCK_MONOTONIC (the srv_manifest suite documents the same hazard), so these
tests POLL for the state transition instead of sleeping a computed span.

Port block srv_manifest (sequential; suites run one at a time per session tile).
"""

import os
import sys
import time
import urllib.error
import urllib.request

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, srv_instance

REPO = "test.cern.ch"
TTL = 1                        # 10 x TTL bound = 10 s: outage waits stay cheap

pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN), reason=f"nginx binary not found: {NGINX_BIN}")

# ONE module-wide allocator (a fresh PortBlock would restart at base+10 and
# collide with an earlier instance still tearing down).
_BLOCK = PortBlock("srv_manifest")


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=25) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _manifest_url(srv):
    return f"{srv.base_url}/cvmfs/{REPO}/.cvmfspublished"


def _log(srv):
    return srv.error_log.read_text(errors="replace")


def _poll(pred, deadline, step=1.0):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()


# ---- success: outage past 10x TTL, offline window keeps the site up --------

@pytest.mark.timeout(90)
def test_offline_window_serves_pinned_snapshot():
    with srv_instance(_BLOCK, manifest_ttl=TTL, offline_ttl=120,
                      client_hold=2) as srv:
        st, fresh = _get(_manifest_url(srv))
        assert st == 200 and fresh

        # warm one CAS object while the origin is still up
        cas = srv.objects()[0]
        st, cas_body = _get(f"{srv.base_url}{cas}")
        assert st == 200 and cas_body

        # total outage; every request through the wait must keep serving the
        # pinned bytes, and once WALL time passes 10 x TTL the degraded-mode
        # notice proves the offline window (not phase-68) is doing it.
        srv.set_fault("http500", 10000)

        def _degraded():
            st, body = _get(_manifest_url(srv))
            assert (st, body) == (200, fresh)      # never a 5xx on the way
            return "event=offline-degraded" in _log(srv)

        assert _poll(_degraded, deadline=30), \
            "never reached the offline-degraded window"

        # cached CAS data serves throughout (immutable, no TTL)
        st, body = _get(f"{srv.base_url}{cas}")
        assert (st, body) == (200, cas_body)


# ---- error / parity: without offline_ttl the 10x bound still fails hard ----

@pytest.mark.timeout(90)
def test_without_offline_ttl_10x_bound_unchanged():
    with srv_instance(_BLOCK, manifest_ttl=TTL, client_hold=2) as srv:
        st, _ = _get(_manifest_url(srv))
        assert st == 200

        srv.set_fault("http500", 10000)

        # phase-68: stale serves absorb the outage until 10 x TTL, then refuse
        assert _poll(lambda: _get(_manifest_url(srv))[0] != 200, deadline=30), \
            "stale manifest still serving past 10x TTL without offline_ttl"
        assert "event=offline-degraded" not in _log(srv)


# ---- security-negative -----------------------------------------------------

@pytest.mark.timeout(90)
def test_offline_never_fabricates_uncached_objects():
    """Degraded mode refuses what it does not hold: an object that was never
    cached must surface the origin failure, not invented bytes."""
    with srv_instance(_BLOCK, manifest_ttl=TTL, offline_ttl=120,
                      client_hold=2) as srv:
        assert _get(_manifest_url(srv))[0] == 200      # pin the manifest

        srv.set_fault("http500", 10000)
        assert _poll(lambda: _get(_manifest_url(srv))[0] == 200
                     and "event=offline-degraded" in _log(srv), deadline=30)

        st, _ = _get(f"{srv.base_url}{srv.objects()[1]}")   # never cached
        assert st >= 500


@pytest.mark.timeout(90)
def test_offline_ttl_horizon_is_hard():
    """offline_ttl is a bound, not a license: past it the manifest fails
    exactly as phase-68 fails past 10x TTL."""
    with srv_instance(_BLOCK, manifest_ttl=TTL, offline_ttl=14,
                      client_hold=2) as srv:
        st, fresh = _get(_manifest_url(srv))
        assert st == 200

        srv.set_fault("http500", 10000)

        # ride the whole window: 200s (pinned bytes only) until the horizon
        # refuses, and the degraded notice must appear along the way — proof
        # the refusal came from offline_ttl exhaustion, not the 10x bound.
        seen = {"degraded": False}

        def _refused():
            st, body = _get(_manifest_url(srv))
            if st == 200:
                assert body == fresh
                seen["degraded"] = (seen["degraded"]
                                    or "event=offline-degraded" in _log(srv))
                return False
            return True

        assert _poll(_refused, deadline=45), \
            "manifest never refused past the offline_ttl horizon"
        assert seen["degraded"], "horizon refused before the offline window ran"
