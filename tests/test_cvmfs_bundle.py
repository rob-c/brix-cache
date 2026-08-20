"""Phase-87 G2 — chunk-bundle batch fetch (``POST /cvmfs/<repo>/.cvmfs-bundle``).

Theme
-----
One POST carries a newline-separated want-list of repo-relative CAS paths and
the reply is a single ``BXB1`` frame stream of the CACHE-RESIDENT members
(``src/protocols/cvmfs/bundle.c``); anything not resident — absent, cold,
oversize — comes back as a miss marker and the client falls back to single
GETs (which fill the cache the normal, verified way). The endpoint NEVER
origin-fills: it is a bounded, synchronous RTT optimization, not a second
fetch path. Default OFF behind ``brix_cvmfs_bundle``; with the gate off the
wire is byte-identical to phase-84 (POST → 405, GET on the reserved name →
403 reject).

Coverage
--------
* success: warmed objects come back byte-identical to their single-GET
  serving; cold + absent members are miss markers; frame parses exactly.
* error: gate off → POST 405 / GET 403; gate on → GET 405 (POST-only);
  POST to a non-bundle path still 405.
* security-neg: traversal / non-CAS / oversize want lines → 400; item-count
  cap → 400; oversize body → 413; want-list cannot name anything the
  classifier would not accept as CAS.

Contract citations
------------------
* Frame + caps: ``shared/cvmfs/bundle/bundle.h`` (single source for both
  sides; codec unit tests in ``shared/cvmfs/bundle/bundle_unittest.c``).
* Endpoint: ``src/protocols/cvmfs/bundle.c`` (want-list parse re-classifies
  every line through ``cvmfs_classify_url`` — a line that does not classify
  as CAS cannot reach storage).
* Gate dispatch: ``src/protocols/cvmfs/gate.c`` (CVMFS_URL_BUNDLE case).
* Client ingest (same frames): ``shared/cvmfs/fetch/fetch_bundle.c``.
"""

from __future__ import annotations

import hashlib
import os
import random
import struct
import sys
import zlib

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance
from settings import HOST

REPO = "test.cern.ch"
BUNDLE = f"/cvmfs/{REPO}/.cvmfs-bundle"
MISS = 0xFFFFFFFFFFFFFFFF

requires_nginx = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                    reason=f"nginx binary not found: {NGINX_BIN}")
pytestmark = requires_nginx


def parse_bundle(blob: bytes) -> list[tuple[str, bytes | None]]:
    """Decode a BXB1 stream into [(path, data-or-None-for-miss)]. Asserts the
    frame is exactly well-formed — trailing garbage or truncation fails."""
    assert blob[:4] == b"BXB1", blob[:16]
    (count,) = struct.unpack_from("<I", blob, 4)
    off, items = 8, []
    for _ in range(count):
        (plen,) = struct.unpack_from("<I", blob, off)
        off += 4
        path = blob[off:off + plen].decode()
        assert len(path) == plen
        off += plen
        (dlen,) = struct.unpack_from("<Q", blob, off)
        off += 8
        if dlen == MISS:
            items.append((path, None))
            continue
        data = blob[off:off + dlen]
        assert len(data) == dlen, "truncated member"
        off += dlen
        items.append((path, data))
    assert off == len(blob), "trailing bytes after final member"
    return items


def post_bundle(srv, want: list[str] | bytes, path: str = BUNDLE):
    body = want if isinstance(want, bytes) else ("\n".join(want) + "\n").encode()
    return request(HOST, srv.nginx_port, "POST", path, body=body)


# --------------------------------------------------------------------------- #
# Module fixture: bundle-enabled instance. A second, default-config instance
# is spun per-test for the gates-off parity checks (same port block, distinct
# sub-block slots).
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def block():
    return PortBlock("srv_bundle")


@pytest.fixture(scope="module")
def srv(block):
    with srv_instance(block, objects=6, seed=11, manifest_ttl=600,
                      extra_directives="brix_cvmfs_bundle on;") as s:
        yield s


@pytest.fixture(scope="module")
def rels(srv):
    """Repo-relative CAS paths ('data/xx/yyyy…') the mock origin serves."""
    prefix = f"/cvmfs/{REPO}/"
    out = [u[len(prefix):] for u in srv.objects()]
    assert len(out) >= 4
    return out


def _absent_rel(tag: str) -> str:
    """A well-formed CAS path no origin serves (absent everywhere)."""
    h = hashlib.sha1(tag.encode()).hexdigest()
    return f"data/{h[:2]}/{h[2:]}"


# ---- success --------------------------------------------------------------- #

def test_bundle_serves_resident_members_and_marks_misses(srv, rels):
    warm, cold = rels[1], rels[2]              # rels[0] is the catalog-suffixed one
    absent = _absent_rel("bundle-absent")

    # Warm exactly one member through the normal single-GET path.
    st, _, ref = request(HOST, srv.nginx_port, "GET", f"/cvmfs/{REPO}/{warm}")
    assert st == 200 and ref

    st, hdrs, body = post_bundle(srv, [warm, absent, cold])
    assert st == 200, body[:200]
    assert hdrs.get("content-type") == "application/x-cvmfs-bundle"
    assert int(hdrs["content-length"]) == len(body)

    items = dict(parse_bundle(body))
    assert set(items) == {warm, absent, cold}
    assert items[warm] == ref, "resident member must be byte-identical to its single-GET serving"
    assert items[absent] is None, "absent object must be a miss marker"
    assert items[cold] is None, "cold (origin-only) object must be a miss — the bundle never origin-fills"

    # The miss did NOT trigger an origin fill for the absent path.
    assert srv.count_log(absent) == 0


def test_bundle_all_resident_roundtrip(srv, rels):
    want = rels[3:5]
    refs = {}
    for rel in want:
        st, _, b = request(HOST, srv.nginx_port, "GET", f"/cvmfs/{REPO}/{rel}")
        assert st == 200
        refs[rel] = b

    st, _, body = post_bundle(srv, want)
    assert st == 200
    items = dict(parse_bundle(body))
    assert items == refs


def test_blank_and_crlf_lines_tolerated(srv, rels):
    rel = rels[1]                              # warmed by the first test
    st, _, body = post_bundle(srv, ("\r\n" + rel + "\r\n\r\n").encode())
    assert st == 200
    items = parse_bundle(body)
    assert len(items) == 1 and items[0][0] == rel


# ---- error ----------------------------------------------------------------- #

def test_gate_off_wire_parity(block):
    """Default config: the reserved name stays byte-compatible with phase-84 —
    POST is just another disallowed method (405), GET is a plain reject (403)."""
    with srv_instance(block, objects=2, seed=12) as off:
        st, _, _ = request(HOST, off.nginx_port, "POST", BUNDLE, body=b"data/ab/cd\n")
        assert st == 405
        st, _, _ = request(HOST, off.nginx_port, "GET", BUNDLE)
        assert st == 403


def test_enabled_get_is_post_only(srv):
    st, _, _ = request(HOST, srv.nginx_port, "GET", BUNDLE)
    assert st == 405


def test_enabled_post_elsewhere_still_rejected(srv):
    st, _, _ = request(HOST, srv.nginx_port, "POST",
                       f"/cvmfs/{REPO}/.cvmfspublished", body=b"x")
    assert st == 405


def test_empty_want_list_yields_empty_bundle(srv):
    """Degenerate but well-formed: zero want lines → a valid zero-item frame."""
    st, _, body = post_bundle(srv, b"\n\n")
    assert st == 200
    assert parse_bundle(body) == []


# ---- security-negative ----------------------------------------------------- #

@pytest.mark.parametrize("line", [
    "../../etc/passwd",                      # traversal
    "data/../../../etc/passwd",              # traversal inside a data prefix
    ".cvmfspublished",                       # metadata, not CAS
    "data/zz/" + "0" * 38,                   # bad hex dir
    "data/ab/short",                         # not a digest
    "/etc/passwd",                           # absolute
], ids=["dotdot", "data-dotdot", "metadata", "badhex", "nondigest", "absolute"])
def test_non_cas_want_line_rejected(srv, rels, line):
    """Every want line is re-classified as a full /cvmfs URL; anything that is
    not CAS — traversal shapes included — 400s the whole request."""
    st, _, _ = post_bundle(srv, [rels[1], line])
    assert st == 400
    assert srv.count_log("passwd") == 0


def test_want_line_over_path_cap_rejected(srv):
    st, _, _ = post_bundle(srv, ["data/ab/" + "0" * 600])
    assert st == 400


def test_item_count_cap_rejected(srv):
    want = [_absent_rel(f"cap-{i}") for i in range(513)]   # cap is 512
    st, _, _ = post_bundle(srv, want)
    assert st == 400


def test_oversize_body_rejected(srv):
    st, _, _ = post_bundle(srv, b"a" * (64 * 1024 + 1))    # > CVMFS_BUNDLE_MAX_WANT
    assert st == 413


# ---- per-member stored-size cap + whole-response budget -------------------- #
# A resident member over CVMFS_BUNDLE_MAX_OBJ (or over the remaining
# CVMFS_BUNDLE_MAX_TOTAL allowance) stays a miss and NEVER consumes budget or
# triggers an origin fill; the caps only exist on the bundle path — the same
# objects still serve fine as single GETs.

CAP = 8 << 20            # CVMFS_BUNDLE_MAX_OBJ (shared/cvmfs/bundle/bundle.h)
TOTAL = 32 << 20         # CVMFS_BUNDLE_MAX_TOTAL


@pytest.fixture(scope="module")
def bigsrv(block):
    """Bundle-enabled instance over a forged webroot whose incompressible
    objects straddle the per-member cap and the whole-response budget.

    The corpus lives in a private mkdtemp, NOT tmp_path_factory: the shared
    basetemp rotates under concurrent sessions and a module-lived webroot
    must survive the whole run."""
    import shutil
    import tempfile
    from pathlib import Path

    from repo_forge import File, RepoForge

    web = Path(tempfile.mkdtemp(prefix="cvmfs_bundle_big."))
    rng = random.Random(87)
    tree = {"small.bin": File(rng.randbytes(4096)),
            "over_cap.bin": File(rng.randbytes(CAP + (1 << 20)))}
    for i in range(5):
        tree[f"mid{i}.bin"] = File(rng.randbytes(7 << 20))
    RepoForge(REPO, web).build(tree, web / "master.pub")

    stored = {name: zlib.compress(node.content) for name, node in tree.items()}
    rels = {}
    for name, blob in stored.items():
        h = hashlib.sha1(blob).hexdigest()
        rels[name] = f"data/{h[:2]}/{h[2:]}"

    try:
        with srv_instance(block, webroot=web, manifest_ttl=600,
                          extra_directives="brix_cvmfs_bundle on;") as s:
            yield s, stored, rels
    finally:
        shutil.rmtree(web, ignore_errors=True)


def _warm(srv, rel: str, stored_blob: bytes) -> None:
    """Single-GET the object through nginx (fills the cache tier) and assert
    it serves the exact stored form — the caps are bundle-only."""
    st, _, body = request(HOST, srv.nginx_port, "GET", f"/cvmfs/{REPO}/{rel}")
    assert st == 200 and body == stored_blob


def test_bundle_member_over_stored_cap_stays_miss(bigsrv):
    srv, stored, rels = bigsrv
    small, big = rels["small.bin"], rels["over_cap.bin"]
    _warm(srv, small, stored["small.bin"])
    _warm(srv, big, stored["over_cap.bin"])
    assert len(stored["over_cap.bin"]) > CAP     # incompressible by design

    srv.reset_log()
    st, _, body = post_bundle(srv, [small, big])
    assert st == 200
    items = dict(parse_bundle(body))
    assert items[small] == stored["small.bin"]
    assert items[big] is None, "resident member over the per-member cap must stay a miss"
    assert srv.count_log(big) == 0, "the cap miss must not trigger an origin fill"


def test_bundle_budget_exhaustion_spares_later_members(bigsrv):
    srv, stored, rels = bigsrv
    order = ["over_cap.bin"] + [f"mid{i}.bin" for i in range(5)]
    for name in order:
        _warm(srv, rels[name], stored[name])

    # Differential oracle: replay the fill loop's contract in want order —
    # over-cap or over-remaining-budget members miss and consume nothing.
    budget, expect = TOTAL, {}
    for name in order:
        blob = stored[name]
        if len(blob) > CAP or len(blob) > budget:
            expect[rels[name]] = None
        else:
            expect[rels[name]] = blob
            budget -= len(blob)
    misses = [rel for rel, blob in expect.items() if blob is None]
    assert len(misses) == 2, "corpus must trip the cap once and the budget once"

    srv.reset_log()
    st, _, body = post_bundle(srv, [rels[n] for n in order])
    assert st == 200
    assert dict(parse_bundle(body)) == expect
    for rel in misses:
        assert srv.count_log(rel) == 0, "budget/cap misses must not origin-fill"
