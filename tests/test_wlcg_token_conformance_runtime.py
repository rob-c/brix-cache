"""WLCG token conformance — RT family (runtime: concurrent validation / cache).

WHAT: Verifies that the token validation cache is correct under concurrency.

      RT-01  20 concurrent calls, same token          → all "accept"
             (L1/L2 cache must give consistent results under reader contention)
      RT-02  20 concurrent calls, 10 valid + 10 alg=none interleaved
             → each valid→accept, each invalid→reject
             (cache keyed per-token; no cross-contamination)
      RT-03  50 sequential calls, same token          → all "accept"
             (cache-hit path stable over repeated access)

WHY:  The SHM token validation cache (src/auth/token/) is a shared multi-worker
      structure.  A race condition or a cache-key collision would cause spurious
      rejects on valid tokens or spurious accepts on invalid tokens.  RT-01/02
      are the primary regression guards for those failure modes.

HOW:  All cases use root_ztn() on NGINX_TOKEN_PORT (11097) — a raw-socket
      kXR_auth sequence that exercises the full validation pipeline including
      any cached results.  ThreadPoolExecutor provides genuine OS-level
      concurrency without pytest-xdist infrastructure.

Concurrency verdict (to be updated after first run):
  RT-01: TBD — expect all 20 "accept" (cache-consistent)
  RT-02: TBD — expect 10 "accept" and 10 "reject" (no cross-contamination)
"""

import concurrent.futures
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from settings import NGINX_TOKEN_PORT, TOKENS_DIR
from tokenforge import TokenForge
from lib.tokenconf import ensure_conformance_data, root_ztn


# ---------------------------------------------------------------------------
# Data provisioning
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _provision():
    """Ensure fixture files exist before every RT test."""
    ensure_conformance_data()


# ---------------------------------------------------------------------------
# Shared forge factory
# ---------------------------------------------------------------------------

def _forge():
    """Return a TokenForge loaded from the fleet token directory."""
    return TokenForge(TOKENS_DIR)


# ---------------------------------------------------------------------------
# RT family test cases
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_rt_01_concurrent_same_token_all_accept():
    """RT-01: 20 concurrent root_ztn calls with ONE valid token → all "accept".

    WHAT: Fires 20 concurrent probes for the same token using 10 worker
          threads.  All 20 must return "accept".
    WHY:  If the token validation cache has a torn-read or a race between cache
          miss and cache insert, some concurrent calls may spuriously return
          "reject" even though the token is valid.  This is a cache-correctness
          regression.
    HOW:  ThreadPoolExecutor(max_workers=10) submits 20 root_ztn tasks
          simultaneously; results are collected and all compared to "accept".

    Failure mode: any "reject" in the 20 results indicates a cache-consistency
    bug under concurrent same-key access.
    """
    tok = _forge().generate(scope="storage.read:/")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = [
            ex.submit(root_ztn, tok, "/test.txt", False, NGINX_TOKEN_PORT)
            for _ in range(20)
        ]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    rejects = [r for r in results if r != "accept"]
    assert not rejects, (
        f"RT-01 FAIL: {len(rejects)}/20 calls returned unexpected verdict(s): "
        f"{rejects!r}. Cache-consistency bug under concurrent same-token access."
    )


@pytest.mark.tokenconf
def test_rt_02_concurrent_distinct_token_isolation():
    """RT-02: 20 concurrent calls — 10 valid (distinct sub) + 10 alg=none → isolated.

    WHAT: Mints 10 distinct valid tokens (different sub claims) and 10 invalid
          tokens (alg=none), submits all 20 concurrently, and asserts that each
          valid token returns "accept" and each invalid token returns "reject".
    WHY:  A cache keyed incorrectly (e.g. on token length or partial hash) could
          cause a valid-token cache entry to be returned for an invalid-token
          lookup (spurious accept) or vice versa (spurious reject).  Either
          outcome is a security bug.
    HOW:  TokenForge.generate(sub=f"rt-user-{i}") produces 10 distinct valid JWTs
          (distinct sub, same key/issuer/audience/scope).  TokenForge.alg_none()
          produces 10 identical unsigned tokens (distinct objects, same content).
          The 20 tasks are submitted concurrently; each task records its expected
          verdict alongside the actual verdict for comparison.
    """
    forge = _forge()
    # 10 distinct valid tokens (varied sub so they are different JWT strings)
    valid_tokens = [
        forge.generate(sub=f"rt-user-{i}", scope="storage.read:/")
        for i in range(10)
    ]
    # 10 invalid tokens (alg=none — no signature)
    invalid_tokens = [forge.alg_none() for _ in range(10)]

    tasks = (
        [(tok, "accept") for tok in valid_tokens]
        + [(tok, "reject") for tok in invalid_tokens]
    )

    def _probe(tok_expected):
        tok, expected = tok_expected
        observed = root_ztn(tok, "/test.txt", False, NGINX_TOKEN_PORT)
        return expected, observed

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(_probe, t) for t in tasks]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    mismatches = [
        (exp, obs) for exp, obs in results if exp != obs
    ]
    assert not mismatches, (
        f"RT-02 FAIL: {len(mismatches)}/20 verdict mismatches: "
        f"{mismatches!r}. "
        "Cache cross-contamination bug: a valid-token entry was returned for "
        "an invalid-token lookup or vice versa."
    )


@pytest.mark.tokenconf
def test_rt_03_sequential_stability():
    """RT-03: 50 sequential root_ztn calls with the same token → all "accept".

    WHAT: Issues 50 sequential probes for one valid token and asserts every
          call returns "accept".
    WHY:  Tests the cache-hit path for stability over a sustained access burst.
          A flapping cache (intermittent miss or eviction under steady load)
          would cause some calls to re-validate and potentially behave
          differently from the cached result.
    HOW:  Simple sequential loop; no concurrency.  Fast because every call
          after the first hits the warm cache.
    """
    tok = _forge().generate(scope="storage.read:/")
    rejects = []
    for i in range(50):
        result = root_ztn(tok, "/test.txt", False, NGINX_TOKEN_PORT)
        if result != "accept":
            rejects.append(i)

    assert not rejects, (
        f"RT-03 FAIL: calls {rejects!r} (0-indexed) returned non-accept. "
        "Cache-hit path is unstable — re-validation yielded different results."
    )
