"""Phase-87 G3 — trained shared-dictionary transfer coding (server side).

Theme
-----
``GET /cvmfs/<repo>/.cvmfs-dict/(current|<40-hex>)`` (gated
``brix_cvmfs_dict``, default OFF) serves a zstd dictionary lazily trained
per worker from this repo's CACHE-RESIDENT CAS objects, self-certified by
``X-Brix-Dict-Id`` = sha1 of the dict bytes.  A CAS data GET that offers a
matching ``X-Brix-Dict`` request header may then come back dict-coded
(``Content-Encoding: zstd-dict``) — but ONLY when that is strictly smaller
than identity, and never for ranged requests.  The coding is a reversible
transform of the STORED bytes: the client's CAS verify runs on exactly what
it always ran on, so a wrong dictionary can only fail decode, never emit
wrong bytes.  With the gate off the wire is byte-identical to phase-84
(reserved name → 403 reject; the request header is dead weight).

Coverage
--------
* success: warmed corpus → dict trains; id is the honest sha1 of the body;
  the id-addressed URL serves the same bytes; HEAD works; a data GET with
  the id comes back coded, strictly smaller, and zstd-dict-decodes to the
  identity serving.
* error: gate off → 403 parity + header ignored; malformed id → 400;
  unknown 40-hex id → 404; cold repo (no resident samples) → 404;
  ranged GET + header → identity 206.
* security-neg: a mismatched ``X-Brix-Dict`` id NEVER yields a coded
  response (the server must not code with a dict the client doesn't hold);
  cross-repo isolation (another repo's endpoint 404s, not serving this
  repo's dict); POST on the reserved name stays 405.

Contract citations
------------------
* Codec + caps: ``shared/cvmfs/dict/dict.h`` (units in
  ``shared/cvmfs/dict/dict_unittest.c``).
* Endpoint + coded serve: ``src/protocols/cvmfs/dict.c``.
* Gate dispatch: ``src/protocols/cvmfs/gate.c`` (CVMFS_URL_DICT case).
* Client twin: ``tests/test_cvmfs_dict_client.py``.
"""

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

REPO = "test.cern.ch"
DICT_CURRENT = f"/cvmfs/{REPO}/.cvmfs-dict/current"

requires_nginx = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                    reason=f"nginx binary not found: {NGINX_BIN}")
pytestmark = requires_nginx


# --------------------------------------------------------------------------- #
# Corpus: many SMALL, structurally-similar text objects — the case G3 exists
# for (random blobs neither train nor code smaller).  Served raw from a mock
# webroot, each honestly named data/<sha1(bytes)> so the CAS fill accepts it.
# --------------------------------------------------------------------------- #

_VOCAB = ["catalog", "manifest", "revision", "chunk", "stratum", "lease",
          "gateway", "session", "publish", "whitelist", "certificate", "tag"]


def _make_body(rng: random.Random, i: int) -> bytes:
    lines = [f"# cvmfs-dict corpus object {i} — shared boilerplate header\n"]
    for _ in range(rng.randint(300, 700)):
        k = rng.choice(_VOCAB)
        lines.append(f"{k}.{rng.randint(0, 9999)} = {rng.randint(0, 999999)}"
                     " ; provenance=stratum1 tier=hot cache=resident\n")
    return "".join(lines).encode()


def _build_webroot(root: Path, n: int = 64, seed: int = 87) -> dict[str, bytes]:
    """Populate <root>/cvmfs/<repo>/data/xx/<38hex> with honest-sha1 objects;
    returns {repo-relative rel: bytes}."""
    rng = random.Random(seed)
    rels = {}
    for i in range(n):
        body = _make_body(rng, i)
        h = hashlib.sha1(body).hexdigest()
        rel = f"data/{h[:2]}/{h[2:]}"
        f = root / "cvmfs" / REPO / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(body)
        rels[rel] = body
    return rels


@pytest.fixture(scope="module")
def webroot():
    """Private mkdtemp instead of pytest tmp_path: concurrent sessions rotate
    the shared basetemp and delete each other's live webroots."""
    d = Path(tempfile.mkdtemp(prefix="cvmfs_dict_web."))
    try:
        yield d, _build_webroot(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="module")
def block():
    return PortBlock("srv_dict")


@pytest.fixture(scope="module")
def srv(block, webroot):
    root, _ = webroot
    with srv_instance(block, webroot=root, manifest_ttl=600,
                      extra_directives="brix_cvmfs_dict on;") as s:
        yield s


@pytest.fixture(scope="module")
def warmed(srv, webroot):
    """Warm the whole corpus through the normal single-GET path (training
    samples only CACHE-RESIDENT objects) and pin the identity servings."""
    _, rels = webroot
    refs = {}
    for rel, body in rels.items():
        st, _, got = request(HOST, srv.nginx_port, "GET", f"/cvmfs/{REPO}/{rel}")
        assert st == 200, f"warm GET {rel} -> {st}"
        assert got == body, f"identity serving of {rel} differs from origin"
        refs[rel] = got
    return refs


@pytest.fixture(scope="module")
def trained(srv, warmed):
    """First touch of the endpoint trains from the warmed residents."""
    st, hdrs, body = request(HOST, srv.nginx_port, "GET", DICT_CURRENT)
    assert st == 200, (f"dict training failed: {st}\n--- nginx error log ---\n"
                       + Path(srv.error_log).read_text(errors="replace")[-3000:])
    return hdrs["x-brix-dict-id"], body


def _coded_get(srv, rel: str, dict_id: str, extra: dict | None = None):
    return request(HOST, srv.nginx_port, "GET", f"/cvmfs/{REPO}/{rel}",
                   headers={"X-Brix-Dict": dict_id, **(extra or {})})


# ---- success --------------------------------------------------------------- #

def test_dict_trains_and_self_certifies(srv, trained):
    dict_id, body = trained
    assert len(body) > 0
    assert dict_id == hashlib.sha1(body).hexdigest(), \
        "X-Brix-Dict-Id must be the honest sha1 of the served bytes"

    # The id-addressed URL serves the same dictionary (cache-forever form).
    st, hdrs, by_id = request(HOST, srv.nginx_port, "GET",
                              f"/cvmfs/{REPO}/.cvmfs-dict/{dict_id}")
    assert st == 200 and by_id == body
    assert hdrs["x-brix-dict-id"] == dict_id
    assert hdrs.get("content-type") == "application/octet-stream"

    st, hdrs, head_body = request(HOST, srv.nginx_port, "HEAD", DICT_CURRENT)
    assert st == 200 and head_body == b""
    assert int(hdrs["content-length"]) == len(body)


def test_data_get_with_id_is_dict_coded_and_decodes(srv, warmed, trained):
    dict_id, dict_bytes = trained
    rel, ref = next(iter(warmed.items()))

    st, hdrs, coded = _coded_get(srv, rel, dict_id)
    assert st == 200
    assert hdrs.get("content-encoding") == "zstd-dict", \
        "compressible corpus object must come back dict-coded"
    assert hdrs["x-brix-dict-id"] == dict_id
    assert hdrs.get("vary") == "X-Brix-Dict"
    assert len(coded) < len(ref), "coded serve must be strictly smaller"
    assert int(hdrs["content-length"]) == len(coded)

    dctx = zstandard.ZstdDecompressor(
        dict_data=zstandard.ZstdCompressionDict(dict_bytes))
    assert dctx.decompress(coded) == ref, \
        "dict decode must reproduce the identity serving byte-for-byte"

    # No header → identity, byte-frozen (phase-84 wire without the opt-in).
    st, hdrs, plain = request(HOST, srv.nginx_port, "GET", f"/cvmfs/{REPO}/{rel}")
    assert st == 200 and plain == ref
    assert "content-encoding" not in hdrs


# ---- error ----------------------------------------------------------------- #

def test_gate_off_wire_parity(block, webroot, trained):
    """Default config: reserved name → plain 403 reject; the request header
    is inert — identity bytes, no coding headers."""
    dict_id, _ = trained
    root, rels = webroot
    with srv_instance(block, webroot=root) as off:
        st, _, _ = request(HOST, off.nginx_port, "GET", DICT_CURRENT)
        assert st == 403
        rel, body = next(iter(rels.items()))
        st, hdrs, got = _coded_get(off, rel, dict_id)
        assert st == 200 and got == body
        assert "content-encoding" not in hdrs


@pytest.mark.parametrize("bad", ["zzz", "0" * 39, "0" * 41, "A" * 40, "current2"],
                         ids=["nonhex", "short", "long", "uppercase", "suffixed"])
def test_malformed_dict_id_rejected(srv, trained, bad):
    st, _, _ = request(HOST, srv.nginx_port, "GET",
                       f"/cvmfs/{REPO}/.cvmfs-dict/{bad}")
    assert st == 400


def test_unknown_dict_id_not_found(srv, trained):
    st, _, _ = request(HOST, srv.nginx_port, "GET",
                       f"/cvmfs/{REPO}/.cvmfs-dict/{'0' * 40}")
    assert st == 404


def test_cold_repo_has_no_dict(block, webroot):
    """A gate-on instance with an EMPTY cache: training finds no resident
    samples and 404s cleanly (memoized — the sampler can't be hammered)."""
    root, _ = webroot
    with srv_instance(block, webroot=root,
                      extra_directives="brix_cvmfs_dict on;") as cold:
        st, _, _ = request(HOST, cold.nginx_port, "GET", DICT_CURRENT)
        assert st == 404
        st, _, _ = request(HOST, cold.nginx_port, "GET", DICT_CURRENT)
        assert st == 404


def test_ranged_get_stays_identity(srv, warmed, trained):
    dict_id, _ = trained
    rel, ref = next(iter(warmed.items()))
    st, hdrs, got = _coded_get(srv, rel, dict_id, {"Range": "bytes=0-9"})
    assert st == 206
    assert got == ref[:10]
    assert "content-encoding" not in hdrs


# ---- security-negative ----------------------------------------------------- #

@pytest.mark.parametrize("offer", ["1" * 40, "deadbeef", ""],
                         ids=["wrong-id", "short-id", "empty"])
def test_mismatched_offer_never_coded(srv, warmed, trained, offer):
    """The server must NEVER code with a dictionary the client did not prove
    it holds — any non-matching offer serves identity."""
    rel, ref = next(iter(warmed.items()))
    st, hdrs, got = _coded_get(srv, rel, offer)
    assert st == 200 and got == ref
    assert "content-encoding" not in hdrs


def test_cross_repo_isolation(srv, trained):
    """Another repo's endpoint must not leak this repo's dictionary."""
    st, _, _ = request(HOST, srv.nginx_port, "GET",
                       "/cvmfs/other.cern.ch/.cvmfs-dict/current")
    assert st == 404


def test_post_on_reserved_name_rejected(srv, trained):
    st, _, _ = request(HOST, srv.nginx_port, "POST", DICT_CURRENT, body=b"x")
    assert st == 405
