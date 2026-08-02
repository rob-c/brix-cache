# tests/test_cvmfs_delta.py — Phase-87 G10: cross-revision delta transfer.
#
# A CAS data GET carrying ``X-Brix-Delta-Base: <40-hex>`` (an object the
# client already holds — e.g. its pinned revision-N catalog while fetching
# N+1) may come back as a zstd delta against that base (``Content-Encoding:
# zstd-delta``) — but ONLY when the base is cache-RESIDENT (a base miss NEVER
# fans out to the origin) and the delta is strictly smaller than identity.
# The wire coding is the G3 dict codec with the base as a raw zstd
# dictionary; trust is unchanged — the client CAS-verifies the reconstructed
# bytes and refetches whole on any mismatch.
#
# Port block: srv_dict (shared sequentially with the dict suite — module
# fixtures close before another file's run in a sweep).
import hashlib
import os
import random
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

zstandard = pytest.importorskip("zstandard")

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance
from settings import HOST

REPO = "delta.cern.ch"

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

BLOCK = PortBlock("srv_dict")


# --------------------------------------------------------------------------- #
# Corpus: a revision-N "catalog" (many structured lines) and a revision-N+1
# body that differs in ~1% of its lines — the frequent-publish case G10
# exists for.
# --------------------------------------------------------------------------- #

def _catalog_lines(rng: random.Random, n: int) -> list[str]:
    return [f"entry.{i} hash={rng.getrandbits(160):040x} size={rng.randint(1, 1 << 20)}"
            f" mode=0644 flags=regular\n" for i in range(n)]


def _make_revisions() -> tuple[bytes, bytes]:
    rng = random.Random(1087)
    lines = _catalog_lines(rng, 4000)
    rev_n = "".join(lines).encode()
    bumped = list(lines)
    for i in rng.sample(range(len(bumped)), 40):          # ~1% churn
        bumped[i] = (f"entry.{i} hash={rng.getrandbits(160):040x} "
                     f"size={rng.randint(1, 1 << 20)} mode=0644 flags=regular\n")
    rev_n1 = "".join(bumped).encode()
    assert rev_n1 != rev_n
    return rev_n, rev_n1


# ---- fixtures --------------------------------------------------------------

@pytest.fixture(scope="module")
def corpus():
    return _make_revisions()


@pytest.fixture(scope="module")
def srv(corpus):
    """Origin webroot holding both revisions as honest-sha1 CAS objects."""
    root = Path(tempfile.mkdtemp(prefix="cvmfs_delta_web."))
    for body in corpus:
        h = hashlib.sha1(body).hexdigest()
        f = root / "cvmfs" / REPO / "data" / h[:2] / h[2:]
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(body)
    try:
        with srv_instance(BLOCK, webroot=root, repo=REPO,
                          extra_directives="brix_cvmfs_delta on;") as s:
            s.webroot = root
            yield s
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---- local helpers (file-local by mandate: shared infra is frozen) ---------

def rel_for(body: bytes) -> str:
    h = hashlib.sha1(body).hexdigest()
    return f"data/{h[:2]}/{h[2:]}"


def GET(s, path, headers=None):
    return request(HOST, s.nginx_port, "GET", path, headers=headers or {})


def warm(s, body: bytes) -> str:
    """Fill one revision through the normal path; returns its 40-hex hash."""
    st, _, got = GET(s, f"/cvmfs/{REPO}/{rel_for(body)}")
    assert st == 200 and got == body, "warm fill failed"
    return hashlib.sha1(body).hexdigest()


def reconstruct(delta: bytes, base: bytes) -> bytes:
    dctx = zstandard.ZstdDecompressor(
        dict_data=zstandard.ZstdCompressionDict(base))
    return dctx.decompress(delta)


# ============================================================================
# 1. success: N→N+1 with ~1% churn ships a tiny delta that reconstructs
#    byte-identical and CAS-verifies
# ============================================================================

def test_delta_serve_reconstructs_and_cas_verifies(srv, corpus):
    rev_n, rev_n1 = corpus
    base_id = warm(srv, rev_n)
    target_id = warm(srv, rev_n1)          # both resident now

    st, hdrs, wire = GET(srv, f"/cvmfs/{REPO}/{rel_for(rev_n1)}",
                         headers={"X-Brix-Delta-Base": base_id})
    assert st == 200
    assert hdrs.get("content-encoding") == "zstd-delta", \
        f"expected a delta-coded serve, got headers {hdrs}"
    assert hdrs.get("x-brix-delta-base") == base_id
    assert hdrs.get("vary") == "X-Brix-Delta-Base"
    assert len(wire) < len(rev_n1) // 10, \
        f"1% churn should delta far below 10% of identity " \
        f"({len(wire)} vs {len(rev_n1)})"

    got = reconstruct(wire, rev_n)
    assert got == rev_n1, "delta did not reconstruct byte-identical"
    assert hashlib.sha1(got).hexdigest() == target_id, \
        "reconstructed bytes fail the CAS check"


# ============================================================================
# 2. error path: no valid resident base ⇒ whole object (identity), never an
#    origin fan-out, never an error
# ============================================================================

def test_delta_without_resident_base_serves_whole_object(srv, corpus):
    _, rev_n1 = corpus
    warm(srv, rev_n1)

    # A well-formed hash the cache has never seen — resident-only rule says
    # identity, NOT a fill of the base and NOT an error.
    ghost = hashlib.sha1(b"never-fetched-revision").hexdigest()
    st, hdrs, wire = GET(srv, f"/cvmfs/{REPO}/{rel_for(rev_n1)}",
                         headers={"X-Brix-Delta-Base": ghost})
    assert st == 200 and wire == rev_n1
    assert hdrs.get("content-encoding") is None, \
        "a non-resident base must fall back to the identity serve"
    ghost_rel = Path(srv.cache) / "cvmfs" / REPO / "data" / ghost[:2] / ghost[2:]
    assert not ghost_rel.exists(), \
        "the delta path must NEVER fill the base from the origin"

    # Malformed opt-ins (wrong length, uppercase hex) are ignored, not errors.
    for bad in ("deadbeef", "Z" * 40, hashlib.sha1(b"x").hexdigest().upper()):
        st, hdrs, wire = GET(srv, f"/cvmfs/{REPO}/{rel_for(rev_n1)}",
                             headers={"X-Brix-Delta-Base": bad})
        assert st == 200 and wire == rev_n1
        assert hdrs.get("content-encoding") is None


# ============================================================================
# 3. security-neg: a delta reconstructed against the WRONG base fails the
#    client's CAS check; the whole-object refetch path stays intact and the
#    delta path never raises a tamper signal
# ============================================================================

def test_delta_wrong_base_fails_cas_and_whole_refetch_heals(srv, corpus):
    rev_n, rev_n1 = corpus
    base_id = warm(srv, rev_n)
    target_id = warm(srv, rev_n1)

    st, hdrs, wire = GET(srv, f"/cvmfs/{REPO}/{rel_for(rev_n1)}",
                         headers={"X-Brix-Delta-Base": base_id})
    assert st == 200 and hdrs.get("content-encoding") == "zstd-delta"

    # Client-side: apply the delta against bytes that are NOT the advertised
    # base (a stale/forged local copy). Raw-dict zstd may "succeed" with
    # garbage — the CAS hash is the gate that must catch it.
    wrong_base = rev_n[:-100] + b"\x00" * 100
    try:
        forged = reconstruct(wire, wrong_base)
        assert hashlib.sha1(forged).hexdigest() != target_id, \
            "wrong-base reconstruction must never pass the CAS check"
    except zstandard.ZstdError:
        pass                                   # failing outright is fine too

    # The client's recovery is a whole-object refetch — still correct bytes.
    st, hdrs, whole = GET(srv, f"/cvmfs/{REPO}/{rel_for(rev_n1)}")
    assert st == 200 and whole == rev_n1
    assert hashlib.sha1(whole).hexdigest() == target_id

    # The delta path is a wire coding of verified stored bytes — it must
    # never manufacture an origin-tamper event.
    assert "cvmfs_tamper" not in Path(srv.error_log).read_text(errors="replace")


# ============================================================================
# 4. guard branches: Range, base==target and non-GET all decline to identity —
#    delta semantics never leak into byte-range or metadata requests
# ============================================================================

def test_delta_guard_branches_decline_to_identity(srv, corpus):
    rev_n, rev_n1 = corpus
    base_id = warm(srv, rev_n)
    target_id = warm(srv, rev_n1)

    # Range + delta base: ranges address IDENTITY bytes — a delta-coded 206
    # would hand the client 100 bytes of the wrong representation.
    st, hdrs, wire = GET(srv, f"/cvmfs/{REPO}/{rel_for(rev_n1)}",
                         headers={"X-Brix-Delta-Base": base_id,
                                  "Range": "bytes=0-99"})
    assert st == 206 and wire == rev_n1[:100], \
        "a ranged request must be served from identity bytes"
    assert hdrs.get("content-encoding") is None, \
        "a ranged request must never be delta-coded"

    # base == target names a zero delta — identity is already optimal.
    st, hdrs, wire = GET(srv, f"/cvmfs/{REPO}/{rel_for(rev_n1)}",
                         headers={"X-Brix-Delta-Base": target_id})
    assert st == 200 and wire == rev_n1
    assert hdrs.get("content-encoding") is None, \
        "base==target must decline to the identity serve"

    # Non-GET: HEAD with a valid resident base stays a plain metadata answer.
    st, hdrs, wire = request(HOST, srv.nginx_port, "HEAD",
                             f"/cvmfs/{REPO}/{rel_for(rev_n1)}",
                             headers={"X-Brix-Delta-Base": base_id})
    assert st == 200 and wire == b""
    assert hdrs.get("content-encoding") is None, \
        "HEAD must never advertise a delta coding"


# ============================================================================
# 5. error path: when the delta cannot beat identity (unrelated incompressible
#    objects) the serve falls back to identity — never a larger-than-identity
#    delta, never an error
# ============================================================================

def test_delta_not_smaller_falls_back_to_identity(srv):
    rng = random.Random(1093)
    blob_a = rng.randbytes(8192)          # incompressible, unrelated pair:
    blob_b = rng.randbytes(8192)          # no shared content for the dict
    for blob in (blob_a, blob_b):
        h = hashlib.sha1(blob).hexdigest()
        f = srv.webroot / "cvmfs" / REPO / "data" / h[:2] / h[2:]
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(blob)
    base_id = warm(srv, blob_a)
    warm(srv, blob_b)                     # both resident

    st, hdrs, wire = GET(srv, f"/cvmfs/{REPO}/{rel_for(blob_b)}",
                         headers={"X-Brix-Delta-Base": base_id})
    assert st == 200 and wire == blob_b, \
        "a no-gain delta must fall back to the exact identity bytes"
    assert hdrs.get("content-encoding") is None, \
        "the strictly-smaller rule was violated: a delta-coded serve for " \
        "an incompressible unrelated pair"
    assert hdrs.get("x-brix-delta-base") is None, \
        "an identity serve must not echo the delta-base header"


# ============================================================================
# 6. security-neg: a delta-coded serve leaves no residue — the very next
#    plain GET (no opt-in header) gets full identity bytes, so the coding can
#    never poison delta-unaware clients sharing the cache
# ============================================================================

def test_plain_get_after_delta_serve_is_identity(srv, corpus):
    rev_n, rev_n1 = corpus
    base_id = warm(srv, rev_n)
    target_id = warm(srv, rev_n1)

    st, hdrs, wire = GET(srv, f"/cvmfs/{REPO}/{rel_for(rev_n1)}",
                         headers={"X-Brix-Delta-Base": base_id})
    assert st == 200 and hdrs.get("content-encoding") == "zstd-delta"
    assert len(wire) < len(rev_n1)

    for _ in range(2):                    # repeatably, not just first-after
        st, hdrs, whole = GET(srv, f"/cvmfs/{REPO}/{rel_for(rev_n1)}")
        assert st == 200 and whole == rev_n1, \
            "a delta serve contaminated the plain identity serve"
        assert hdrs.get("content-encoding") is None
        assert hashlib.sha1(whole).hexdigest() == target_id
