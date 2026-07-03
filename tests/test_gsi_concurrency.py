"""
Phase 33 — GSI handshake concurrency (the plain-GSI :11095 wedge).

The bug: the GSI round-1 (kXGC_certreq) handler generated an ephemeral ffdhe2048
DH key INLINE on the single nginx event thread, head-of-line-blocking every other
connection during each keygen.  Under a concurrent GSI-handshake burst that
serialized/stalled the worker so concurrent certreqs went unanswered ("No protocols
left to try").  The fix (src/auth/gsi/keypool.c) hands keys out from a per-worker pool
refilled off-thread, so keygen never runs on the event thread.

These tests drive N *independent* GSI handshakes at once.  They use separate
PROCESSES (not threads) on purpose: pyxrootd multiplexes File handles from one
process over a single physical connection — i.e. one handshake — so only separate
processes produce N concurrent certreq→cert handshakes (the actual burst).  A small
file is used so the test stresses the HANDSHAKE, not data transfer.

  success      — N=16 concurrent GSI (and GSI+TLS) handshakes all complete.
  edge (slow)  — a burst larger than the pool falls back to inline keygen, still OK.
  wiring/PFS   — keypool is registered + popped with inline fallback; ERR_clear_error
                 is wired; each session gets a fresh single-use key (no reuse).

ENVIRONMENT NOTE: like every GSI test, these require that no `tests/run_load_test.sh`
sweep is running concurrently.  That script `rm -rf /tmp/xrd-test/pki` and regenerates
the shared PKI mid-run, which wipes the GSI server certs out from under this fleet and
makes GSI handshakes fail spuriously (the documented "host-load flakiness" — an
environment collision, not a server bug; see phase-33 doc + run_load_test.sh header).
"""

import multiprocessing as mp
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import pytest

from settings import SERVER_HOST, NGINX_GSI_PORT, NGINX_GSI_TLS_PORT, DATA_ROOT

GSI_URL     = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
GSI_TLS_URL = f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}"
PROBE_FILE  = "gsi_concurrency_probe.bin"

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module", autouse=True)
def _seed_probe_file():
    """Write the small probe file (conftest has already started the servers and
    seeded/wiped DATA_ROOT at session start)."""
    os.makedirs(DATA_ROOT, exist_ok=True)
    with open(os.path.join(DATA_ROOT, PROBE_FILE), "wb") as f:
        f.write(b"gsi-handshake-burst-probe\n" * 64)
    yield


def _gsi_handshake_worker(worker_id, base_url, path):
    """open+stat+close a small file over GSI — exercises the full certreq→cert
    handshake.  Runs in its own process so each is an independent handshake."""
    from XRootD import client  # imported in the child (spawn)
    res = {"id": worker_id, "ok": False, "error": None}
    try:
        f = client.File()
        st, _ = f.open(f"{base_url}//{path}")
        if not st.ok:
            res["error"] = f"open: {st.message}"
            return res
        st, _info = f.stat()
        if not st.ok:
            res["error"] = f"stat: {st.message}"
            return res
        f.close()
        res["ok"] = True
    except Exception as exc:        # noqa: BLE001 — report, don't raise across procs
        res["error"] = str(exc)
    return res


def _burst(base_url, n):
    with ProcessPoolExecutor(max_workers=n,
                             mp_context=mp.get_context("spawn")) as pool:
        futs = [pool.submit(_gsi_handshake_worker, i, base_url, PROBE_FILE)
                for i in range(n)]
        return [fut.result() for fut in as_completed(futs)]


# --------------------------------------------------------------------------- #
# Functional — the wedge must not recur                                        #
# --------------------------------------------------------------------------- #

@pytest.mark.timeout(120)
def test_gsi_handshake_burst_no_wedge():
    """16 concurrent plain-GSI handshakes (the ~14-concurrent wedge) all complete."""
    results = _burst(GSI_URL, 16)
    failed = [r for r in results if not r["ok"]]
    assert not failed, f"GSI handshake burst wedged ({len(failed)}/16): {failed}"


@pytest.mark.timeout(120)
def test_gsi_tls_handshake_burst_no_wedge():
    """16 concurrent GSI+TLS handshakes (:11096) all complete."""
    results = _burst(GSI_TLS_URL, 16)
    failed = [r for r in results if not r["ok"]]
    assert not failed, f"GSI+TLS handshake burst wedged ({len(failed)}/16): {failed}"


@pytest.mark.slow
@pytest.mark.timeout(300)
def test_gsi_pool_exhaustion_fallback():
    """A burst larger than the warm pool (BRIX_GSI_KEYPOOL_SIZE=64) drains it and
    forces the inline-keygen fallback — every handshake must still succeed.

    Marked slow: spawns >64 processes; run on a quiet host (the clean-box soak).
    """
    results = _burst(GSI_URL, 80)
    failed = [r for r in results if not r["ok"]]
    assert not failed, f"pool-exhaustion fallback failed ({len(failed)}/80): {failed}"


# --------------------------------------------------------------------------- #
# Wiring / invariants                                                          #
# --------------------------------------------------------------------------- #

def _rd(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_keypool_wiring():
    # keypool module registered in the build + warmed per worker.
    assert "src/auth/gsi/keypool.c" in _rd("config")
    assert "src/auth/gsi/keypool.h" in _rd("config")
    proc = _rd("src/core/config/process.c")
    assert "brix_gsi_keypool_init" in proc
    # tunables present.
    assert "BRIX_GSI_KEYPOOL_SIZE" in _rd("src/core/types/tunables.h")
    # certreq pops from the pool with an inline fallback (keygen off the event thread).
    cert = _rd("src/auth/gsi/cert_response.c")
    assert "brix_gsi_keypool_pop" in cert
    assert "brix_gsi_dh_keygen" in cert     # inline fallback retained
    # refill runs off-thread (event thread never blocks on keygen).
    kp = _rd("src/auth/gsi/keypool.c")
    assert "ngx_thread_task_post" in kp


def test_errclear_wiring():
    # The OpenSSL error-queue is cleared at the GSI auth + in-protocol TLS entries.
    assert "ERR_clear_error" in _rd("src/auth/gsi/auth.c")
    assert "ERR_clear_error" in _rd("src/protocols/root/connection/tls.c")


def test_pfs_key_is_single_use():
    """Each session gets a fresh, single-use ephemeral key (perfect forward
    secrecy): the pool POPS (removes) the key — ownership transfers to the
    connection, which frees it after round 2 — so no key is ever handed to two
    sessions.  Asserted at the source level (a runtime crypto-equality check is
    not observable through the pyxrootd client)."""
    kp = _rd("src/auth/gsi/keypool.c")
    # pop decrements the count and transfers the slot's key out (no copy/reuse).
    assert "brix_kp_ring[--brix_kp_count]" in kp
    # round-2 derive still frees the per-connection key (existing lifecycle).
    assert "EVP_PKEY_free" in _rd("src/auth/gsi/auth.c")
