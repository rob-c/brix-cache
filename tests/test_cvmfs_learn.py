# tests/test_cvmfs_learn.py — Phase-87 G11: workload-learned predictive prewarm.
#
# With ``brix_cvmfs_learn on`` the proxy passively learns per-connection CAS
# access sequences ("A is followed by B") and, once a transition is confident
# (seen >= 2 times), prewarms the predicted successor through the ordinary
# verified cache fill when its predecessor is requested again — before any
# client asks for it. The model is a property of the WORKLOAD: it holds CAS
# keys and connection numbers only, never Authorization/token content.
#
# The success/security tests need a non-resident prediction target, so they
# compose with the landed G17 scrub: corrupt the cached successor, let the
# scrub evict it, then show a single GET of the predecessor restores it.
#
# Port block: srv_dict (shared sequentially with the dict/delta suites).
from __future__ import annotations

import hashlib
import http.client
import os
import random
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, srv_instance
from settings import HOST

REPO = "learn.cern.ch"

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

BLOCK = PortBlock("srv_dict")

OBJ_NAMES = ("obj_a", "obj_b", "obj_d", "obj_e", "obj_f", "obj_g", "obj_h")


# ---- fixtures --------------------------------------------------------------

@pytest.fixture(scope="module")
def corpus():
    rng = random.Random(1091)
    return {name: rng.randbytes(8192) for name in OBJ_NAMES}


@pytest.fixture(scope="module")
def srv(corpus):
    """Origin webroot with honest-sha1 CAS objects; learn + fast scrub on."""
    root = Path(tempfile.mkdtemp(prefix="cvmfs_learn_web."))
    for body in corpus.values():
        h = hashlib.sha1(body).hexdigest()
        f = root / "cvmfs" / REPO / "data" / h[:2] / h[2:]
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(body)
    directives = ("brix_cvmfs_learn on; brix_cvmfs_scrub on; "
                  "brix_cvmfs_scrub_interval 1;")
    try:
        with srv_instance(BLOCK, webroot=root, repo=REPO,
                          extra_directives=directives) as s:
            yield s
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---- local helpers (file-local by mandate: shared infra is frozen) ---------

def rel_for(body: bytes) -> str:
    h = hashlib.sha1(body).hexdigest()
    return f"/cvmfs/{REPO}/data/{h[:2]}/{h[2:]}"


def cache_path(s, body: bytes) -> Path:
    h = hashlib.sha1(body).hexdigest()
    return Path(s.cache) / "cvmfs" / REPO / "data" / h[:2] / h[2:]


def kget(conn: http.client.HTTPConnection, path: str,
         headers: dict | None = None) -> bytes:
    """One GET on a KEPT-ALIVE connection (the model is connection-keyed)."""
    conn.request("GET", path, headers=headers or {})
    r = conn.getresponse()
    body = r.read()
    assert r.status == 200, f"GET {path} -> {r.status}"
    return body


def train_pair(s, first: bytes, then: bytes, rounds: int = 2,
               headers_per_round: list | None = None) -> None:
    """Teach the model first→then by replaying the sequence on `rounds`
    fresh keep-alive connections."""
    for i in range(rounds):
        hdrs = headers_per_round[i] if headers_per_round else None
        conn = http.client.HTTPConnection(HOST, s.nginx_port, timeout=10)
        try:
            assert kget(conn, rel_for(first), hdrs) == first
            assert kget(conn, rel_for(then), hdrs) == then
        finally:
            conn.close()


def wait_for(pred, timeout: float = 15.0, step: float = 0.2) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


def evict_via_scrub(s, body: bytes) -> None:
    """Corrupt the cached copy and wait for the G17 scrub to evict it."""
    p = cache_path(s, body)
    assert p.exists(), "successor must be cache-resident before the evict"
    p.write_bytes(b"\x00" * len(body))
    assert wait_for(lambda: not p.exists()), \
        "scrub did not evict the corrupted successor in time"


# ============================================================================
# 1. success: after training A→B twice, a fresh job's GET of A alone makes B
#    cache-resident (correct bytes) before anything requests it
# ============================================================================

def test_trained_transition_prewarms_successor(srv, corpus):
    a, b = corpus["obj_a"], corpus["obj_b"]
    train_pair(srv, a, b, rounds=2)

    evict_via_scrub(srv, b)               # make the prediction target cold

    conn = http.client.HTTPConnection(HOST, srv.nginx_port, timeout=10)
    try:
        assert kget(conn, rel_for(a)) == a     # the ONLY request made
    finally:
        conn.close()

    bp = cache_path(srv, b)
    assert wait_for(lambda: bp.exists() and bp.read_bytes() == b), \
        "predicted successor was not prewarmed with verified origin bytes"


# ============================================================================
# 2. error path: an unrecognized access prewarms nothing (no mispredict storm)
# ============================================================================

def test_unrecognized_workload_prewarms_nothing(srv, corpus):
    d = corpus["obj_d"]                   # never part of any trained sequence
    data_dir = Path(srv.cache) / "cvmfs" / REPO / "data"

    def resident() -> set:
        return {p for p in data_dir.rglob("*") if p.is_file()}

    before = resident()
    conn = http.client.HTTPConnection(HOST, srv.nginx_port, timeout=10)
    try:
        assert kget(conn, rel_for(d)) == d
    finally:
        conn.close()
    time.sleep(2.0)                       # give a (wrong) prewarm time to land

    grown = resident() - before
    assert grown <= {cache_path(srv, d)}, \
        f"an unrecognized access must fill only itself, grew: {grown}"


# ============================================================================
# 3. security-neg: the profile carries no per-user/token content — a pattern
#    trained under two different Authorization identities fires for an
#    anonymous connection, and no token material reaches the logs
# ============================================================================

def test_profile_is_user_blind_and_leaks_no_tokens(srv, corpus):
    e, f = corpus["obj_e"], corpus["obj_f"]
    train_pair(srv, e, f, rounds=2, headers_per_round=[
        {"Authorization": "Bearer secret-token-alice-0451"},
        {"Authorization": "Bearer secret-token-bob-1662"},
    ])

    evict_via_scrub(srv, f)

    conn = http.client.HTTPConnection(HOST, srv.nginx_port, timeout=10)
    try:
        assert kget(conn, rel_for(e)) == e     # anonymous — no Authorization
    finally:
        conn.close()

    fp = cache_path(srv, f)
    assert wait_for(lambda: fp.exists() and fp.read_bytes() == f), \
        "workload profile must not be keyed by user identity"

    log = Path(srv.error_log).read_text(errors="replace")
    assert "secret-token-" not in log, \
        "token material must never reach the model or its logging"


# ============================================================================
# 4. depth: the confidence gate at its boundary — ONE observation is not a
#    pattern (below CVMFS_LEARN_MIN_COUNT nothing prewarms), the SECOND
#    observation of the same transition is, and fires. (The per-second rate
#    cap is deliberately untested: forcing >8 posts inside one rolling
#    second is inherently timing-flaky — it is a load-shedding valve, not a
#    correctness property.)
# ============================================================================

def test_confidence_gate_boundary(srv, corpus):
    g, h = corpus["obj_g"], corpus["obj_h"]

    train_pair(srv, g, h, rounds=1)       # count = 1 < CVMFS_LEARN_MIN_COUNT
    evict_via_scrub(srv, h)

    conn = http.client.HTTPConnection(HOST, srv.nginx_port, timeout=10)
    try:
        assert kget(conn, rel_for(g)) == g
    finally:
        conn.close()
    time.sleep(2.0)                       # a wrong prewarm would land within this
    assert not cache_path(srv, h).exists(), \
        "a once-seen transition must stay below the confidence gate"

    # One more observation reaches MIN_COUNT — the same probe now fires.
    train_pair(srv, g, h, rounds=1)       # count = 2, h resident again
    evict_via_scrub(srv, h)

    conn = http.client.HTTPConnection(HOST, srv.nginx_port, timeout=10)
    try:
        assert kget(conn, rel_for(g)) == g
    finally:
        conn.close()

    hp = cache_path(srv, h)
    assert wait_for(lambda: hp.exists() and hp.read_bytes() == h), \
        "the transition crossed the confidence gate but did not prewarm"
