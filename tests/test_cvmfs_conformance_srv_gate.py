"""Phase-84 CVMFS conformance corpus — server gate / URL grammar (srv_gate).

Theme
-----
The ``brix_cvmfs`` dispatch gate is the sole thing separating a CVMFS site
cache from an open HTTP endpoint: every request is classified
(``shared/cvmfs/grammar/classify.c``) and policed (``src/protocols/cvmfs/
gate.c``) before it may touch storage. This corpus drives the SERVED behavior
through a live nginx instance — HTTP status, the single-line ``cvmfs-reject:``
WARN (the fail2ban contract), and origin-side observability via the mock
Stratum-1 request log. Classifier unit tests live in
``tests/cmdscripts/cvmfs_classify.py``; nothing here re-unit-tests the parse.

Official-CVMFS is the reference: official repositories only ever publish CAS
names of exactly 40/64/96/128 hex digits, so any other length is not CVMFS
traffic and an official-faithful gate rejects it. brix accepts the whole
40..128 range (``classify.c:33`` — ``hexn + 2 < 40 || hexn + 2 > 128``);
those rows are ``xfail`` DIVERGENCE pins.

Coverage
--------
* CAS hex-length acceptance {40,64,96,128} vs rejection {0,38,39,129} and the
  in-range non-digest lengths {41,63,65,127} (DIVERGENCE: brix range-accepts).
* CAS suffix alphabet: {C,H,X,M,L,P} accepted; other letters / doubled
  suffixes rejected; lowercase 'c' folds into the hex run (DIVERGENCE row).
* Digest charset: uppercase / non-hex / punctuation / space; 2-hex dir shape.
* Path traversal: ``..`` and ``%2e%2e`` inside and escaping ``/cvmfs``,
  beyond-root, NUL; slash-merge / dot-segment / ``%2f`` normalization rows
  that must classify identically to their canonical spelling (no gate bypass).
* Repo-name grammar: ``[a-z0-9.-]+`` with no leading dot; metadata basenames
  are byte-exact.
* Query strings and fragments: stripped before classification, never traverse,
  never rescue a rejected shape.
* Non-CVMFS paths: 403 + exactly ONE ``cvmfs-reject:`` WARN line per request
  (fail2ban keys on it), with the documented fields present.
* Method matrix: GET/HEAD serve; everything else 405 and NEVER reaches the
  origin (mock request/HEAD logs stay empty for that path).
* GET/HEAD status parity is asserted inside every corpus row (both methods
  are issued per row).

Contract citations
------------------
* Classifier grammar: ``shared/cvmfs/grammar/classify.c`` (repo charset :17,
  CAS shape :26-49, metadata basenames :77-83, geo prefix :84).
* Gate policing + reject line: ``src/protocols/cvmfs/gate.c`` (reject WARN
  :81-97, method gate :186, class dispatch :203-232).
* One WARN per reject is the T17 fail2ban contract (gate.c:79).
"""

import hashlib
import os
import sys

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance

REPO = "test.cern.ch"
HOST = "127.0.0.1"
HEX = ("0123456789abcdef" * 9)  # 144 chars — covers the 130-digit rows

requires_nginx = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                    reason=f"nginx binary not found: {NGINX_BIN}")
pytestmark = requires_nginx

# classify.c now accepts only the exact official digest lengths (40/64/96/128
# hex — sha1/rmd160, sha256, sha384, sha512); the former in-range-accepts-all
# divergence (any length 40..128) was fixed 2026-07-18.


def _hex(n: int) -> str:
    return HEX[:n]


def _cas(n: int, suffix: str = "", repo: str = REPO) -> str:
    """CAS path whose total digest (2-hex dir + name) is n hex chars."""
    h = _hex(n)
    return f"/cvmfs/{repo}/data/{h[:2]}/{h[2:]}{suffix}"


def _cas_unique(tag: str) -> str:
    """A valid 40-hex CAS path unique to `tag` (per-row origin-log isolation)."""
    h = hashlib.sha1(tag.encode()).hexdigest()
    return f"/cvmfs/{REPO}/data/{h[:2]}/{h[2:]}"


# --------------------------------------------------------------------------- #
# Module fixture: ONE mock origin + nginx on the srv_gate port block.
# The location is "/" so the gate — not nginx location matching — polices
# every path, making the 403 + cvmfs-reject fail2ban contract observable for
# non-/cvmfs paths too. Distinct request paths give per-row isolation.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv():
    # manifest_ttl pinned high: the mock regenerates the manifest timestamp per
    # fetch, so byte-stability assertions need the cached copy to outlive the
    # module (default TTL is 61s).
    with srv_instance(PortBlock("srv_gate"), location="/", objects=6, seed=7,
                      manifest_ttl=600) as s:
        yield s


@pytest.fixture(scope="module")
def manifest_body(srv):
    """Reference manifest bytes as served THROUGH nginx (cached, stable)."""
    status, _, body = request(HOST, srv.nginx_port, "GET",
                              f"/cvmfs/{REPO}/.cvmfspublished")
    assert status == 200
    return body


def _reject_lines(srv) -> list:
    try:
        text = srv.error_log.read_text(errors="replace")
    except OSError:
        return []
    return [ln for ln in text.splitlines() if "cvmfs-reject:" in ln]


def _probe(srv, method, path):
    """One request; returns (status, new-reject-lines, headers, body)."""
    before = len(_reject_lines(srv))
    status, hdrs, body = request(HOST, srv.nginx_port, method, path)
    return status, _reject_lines(srv)[before:], hdrs, body


def _gate_case(srv, path, status, rejects_per_req):
    """Drive GET then HEAD through the gate; assert status, per-request reject
    line count (exactly one per rejected request — fail2ban), and GET/HEAD
    status parity. Returns the GET body."""
    st_g, rej_g, _, body = _probe(srv, "GET", path)
    assert st_g == status, f"GET {path}: {st_g} != {status}"
    assert len(rej_g) == rejects_per_req, f"GET {path}: reject lines {rej_g}"
    st_h, rej_h, _, _ = _probe(srv, "HEAD", path)
    assert st_h == st_g, f"HEAD/GET parity broken on {path}: {st_h} vs {st_g}"
    assert len(rej_h) == rejects_per_req, f"HEAD {path}: reject lines {rej_h}"
    return body


# --------------------------------------------------------------------------- #
# CAS hex-length grammar
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("n", [40, 64, 96, 128])
def test_cas_hex_length_accepted(srv, n):
    # Valid digest length: passes the gate to the tier, origin 404s the
    # unknown object — decisively NOT a 403 reject, and no reject line.
    _gate_case(srv, _cas(n), 404, 0)


@pytest.mark.parametrize("name,path", [
    ("len0", f"/cvmfs/{REPO}/data/"),          # no dir/digest at all
    ("no_digest", f"/cvmfs/{REPO}/data"),       # bare data, not even a shape
    ("len38", _cas(38)),
    ("len39", _cas(39)),
    ("len129", _cas(129)),
    ("len130", _cas(130)),
])
def test_cas_hex_length_rejected(srv, name, path):
    _gate_case(srv, path, 403, 1)


@pytest.mark.parametrize("n", [41, 63, 65, 127])
def test_cas_hex_length_nondigest_rejected(srv, n):
    # DIVERGENCE: no hash CVMFS ever publishes has these lengths; the official
    # shape set is {40 sha1/rmd160, 64 sha256, 96 sha384, 128 sha512}. brix
    # accepts the whole 40..128 range (classify.c:33) and serves a tier 404.
    _gate_case(srv, _cas(n), 403, 1)


# --------------------------------------------------------------------------- #
# CAS suffix alphabet
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("suffix,n", [
    ("C", 40), ("H", 40), ("X", 40), ("M", 40), ("L", 40), ("P", 40),
    ("C", 128),                                  # suffix on the longest digest
])
def test_cas_suffix_accepted(srv, suffix, n):
    _gate_case(srv, _cas(n, suffix), 404, 0)


@pytest.mark.parametrize("suffix", ["A", "G", "Q", "T", "Z", "m", "CC", "XX"])
def test_cas_suffix_rejected(srv, suffix):
    _gate_case(srv, _cas(40, suffix), 403, 1)


# A lowercase 'c' after 40 hex chars reads as a 41-digit hex run; under the
# fixed exact-length rule 41 is not a digest length, so brix now rejects it
# like official CVMFS (which has no lowercase suffixes and no 41-hex digests).
def test_cas_suffix_lowercase_rejected(srv):
    _gate_case(srv, _cas(40, "c"), 403, 1)


# --------------------------------------------------------------------------- #
# Digest charset + 2-hex directory shape
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,path", [
    ("upper_digest", f"/cvmfs/{REPO}/data/AB/" + _hex(38).upper()),
    ("upper_mid", _cas(40)[:40] + "G" + _cas(40)[41:]),   # one upper non-hex
    ("nonhex_g", f"/cvmfs/{REPO}/data/ab/" + "g" * 38),
    ("dash", f"/cvmfs/{REPO}/data/ab/" + _hex(30) + "-" + _hex(7)),
    ("space", f"/cvmfs/{REPO}/data/ab/" + _hex(20) + "%20" + _hex(17)),
    ("dir_upper", f"/cvmfs/{REPO}/data/AB/" + _hex(38)),
    ("dir_3hex", f"/cvmfs/{REPO}/data/abc/" + _hex(37)),
    ("dir_1hex", f"/cvmfs/{REPO}/data/a/" + _hex(39)),
])
def test_cas_charset_rejected(srv, name, path):
    _gate_case(srv, path, 403, 1)


# --------------------------------------------------------------------------- #
# Path traversal + URI normalization
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,path,status,rejects", [
    # nginx normalizes dot-segments BEFORE the gate classifies; the residue is
    # never a CVMFS shape, so each of these is a 403 with its one WARN line …
    ("dotdot_repo", f"/cvmfs/{REPO}/../secret", 403, 1),
    ("dotdot_escape", "/cvmfs/../etc/passwd", 403, 1),
    ("enc_dotdot", f"/cvmfs/{REPO}/%2e%2e/x", 403, 1),
    ("enc_dotdot_escape", "/cvmfs/%2e%2e/etc/passwd", 403, 1),
    # … while syntactically invalid URIs die in nginx request parsing (400)
    # and never reach the gate — no reject line.
    ("beyond_root", "/../cvmfs/x", 400, 0),
    ("nul_byte", f"/cvmfs/{REPO}/%00/x", 400, 0),
])
def test_traversal_rejected(srv, name, path, status, rejects):
    _gate_case(srv, path, status, rejects)


@pytest.mark.parametrize("name,path,status", [
    # Normalization must land on the canonical classification — equivalent
    # spellings may not open a side door NOR break a legitimate client.
    ("dotdot_inside", f"/cvmfs/{REPO}/data/../.cvmfspublished", 200),
    ("single_dot", f"/cvmfs/{REPO}/./.cvmfspublished", 200),
    ("double_slash", f"/cvmfs//{REPO}/.cvmfspublished", 200),
    ("leading_double_slash", f"//cvmfs/{REPO}/.cvmfspublished", 200),
    ("encoded_slash", f"/cvmfs/{REPO}%2f.cvmfspublished", 200),
    ("dotdot_within_data", f"/cvmfs/{REPO}/data/aa/../{_hex(40)[:2]}/{_hex(40)[2:]}", 404),
])
def test_traversal_normalized(srv, manifest_body, name, path, status):
    body = _gate_case(srv, path, status, 0)
    if status == 200:
        assert body == manifest_body, \
            f"{name}: normalized spelling served different bytes"


# --------------------------------------------------------------------------- #
# Repository-name grammar
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("repo", [
    "foo-bar.cern.ch",       # hyphen + dots
    "a",                     # single char
    "0start",                # leading digit
    "foo.",                  # trailing dot (grammar bans only a LEADING dot)
    "a..b",                  # doubled interior dot
    "9.9.9",                 # all digits + dots
])
def test_repo_grammar_accepted(srv, repo):
    # Grammar-valid but unknown to the origin: the gate admits it and the
    # origin 404s — never a 403.
    _gate_case(srv, f"/cvmfs/{repo}/.cvmfspublished", 404, 0)


@pytest.mark.parametrize("name,path", [
    ("leading_dot", "/cvmfs/.foo/.cvmfspublished"),
    ("uppercase", "/cvmfs/Foo.cern.ch/.cvmfspublished"),
    ("underscore", "/cvmfs/foo_bar/.cvmfspublished"),
    ("colon", "/cvmfs/foo:80/.cvmfspublished"),
    ("space", "/cvmfs/foo%20bar/.cvmfspublished"),
    ("utf8", "/cvmfs/r%C3%A9seau/.cvmfspublished"),
    ("repo_only", f"/cvmfs/{REPO}"),            # no '/' after the repo token
    ("empty_rel", f"/cvmfs/{REPO}/"),           # nothing after the repo
])
def test_repo_grammar_rejected(srv, name, path):
    _gate_case(srv, path, 403, 1)


# --------------------------------------------------------------------------- #
# Signed-metadata basenames are byte-exact
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,rel,status,rejects", [
    ("published", ".cvmfspublished", 200, 0),
    ("whitelist", ".cvmfswhitelist", 200, 0),
    ("reflog", ".cvmfsreflog", 404, 0),         # valid shape, origin lacks it
    ("case", ".cvmfsPublished", 403, 1),
    ("suffixed", ".cvmfspublishedX", 403, 1),
    ("truncated", ".cvmfspublishe", 403, 1),
])
def test_metadata_basenames(srv, name, rel, status, rejects):
    _gate_case(srv, f"/cvmfs/{REPO}/{rel}", status, rejects)


# --------------------------------------------------------------------------- #
# Query strings and fragments
# --------------------------------------------------------------------------- #
def test_query_is_stripped_before_classify(srv, manifest_body):
    body = _gate_case(srv, f"/cvmfs/{REPO}/.cvmfspublished?x=1", 200, 0)
    assert body == manifest_body


def test_query_traversal_is_inert(srv):
    _gate_case(srv, f"/cvmfs/{REPO}/.cvmfspublished?p=../../etc/passwd", 200, 0)


def test_query_on_cas_object_serves_same_bytes(srv):
    obj = srv.objects()[1]
    _, _, plain = request(HOST, srv.nginx_port, "GET", obj)
    body = _gate_case(srv, obj + "?v=2", 200, 0)
    assert body == plain


def test_fragment_is_stripped(srv, manifest_body):
    body = _gate_case(srv, f"/cvmfs/{REPO}/.cvmfspublished#frag", 200, 0)
    assert body == manifest_body


def test_query_does_not_rescue_rejected_shape(srv):
    _gate_case(srv, f"/cvmfs/{REPO}?x=1", 403, 1)


def test_cvmfs_shape_inside_query_does_not_admit(srv):
    _gate_case(srv, f"/etc/passwd?/cvmfs/{REPO}/.cvmfspublished", 403, 1)


def test_query_on_bad_cas_length_still_rejected(srv):
    _gate_case(srv, _cas(39) + "?retry=1", 403, 1)


# --------------------------------------------------------------------------- #
# Non-/cvmfs paths: 403 + exactly ONE cvmfs-reject WARN (fail2ban contract)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,path", [
    ("root", "/"),
    ("etc_passwd", "/etc/passwd"),
    ("cvmfs_bare", "/cvmfs"),
    ("cvmfs_prefix_only", "/cvmfs/"),
    ("uppercase_prefix", f"/CVMFS/{REPO}/.cvmfspublished"),
    ("prefix_superstring", f"/cvmfsx/{REPO}/{_cas(40).split('/', 3)[3]}"),
    ("no_prefix_data", "/data/" + _hex(40)[:2] + "/" + _hex(40)[2:]),
    ("bare_manifest", "/.cvmfspublished"),
])
def test_noncvmfs_rejected_with_one_warn(srv, name, path):
    _gate_case(srv, path, 403, 1)


def test_reject_line_is_single_line_and_parsable(srv):
    # The T17 fail2ban filter keys on ONE stable line: level [warn], the
    # cvmfs-reject: tag, and the method/client/class/cause fields.
    _, lines, _, _ = _probe(srv, "GET", "/not/cvmfs/at/all")
    assert len(lines) == 1
    line = lines[0]
    assert "[warn]" in line
    for field in ("method=GET", "client=", "class=reject", "cause=", "fix="):
        assert field in line, f"missing {field!r} in reject line: {line}"


def test_reject_line_uri_field_is_exact(srv):
    # gate.c now bounds the logged uri with a uri.len-limited copy (mirroring
    # handler.c:359-364) before brix_sanitize_log_string, so the uri="..." field
    # is exactly the request target — no over-read into the raw request buffer
    # (method/HTTP-version/headers). Same fix at the cvmfs-neg reject line.
    _, lines, _, _ = _probe(srv, "GET", "/definitely/not/cvmfs")
    assert len(lines) == 1
    assert 'uri="/definitely/not/cvmfs"' in lines[0], lines[0]


# --------------------------------------------------------------------------- #
# Method matrix — GET/HEAD serve, everything else never reaches storage
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("method,gated", [
    # gated=True: the request reaches the cvmfs gate, which 405s with its
    # WARN line; gated=False: nginx core refuses the method during request
    # parsing (405, no gate involvement). Either way: never touches storage.
    ("PUT", True), ("POST", True), ("DELETE", True), ("OPTIONS", True),
    ("PROPFIND", True), ("MKCOL", True), ("PATCH", True), ("FROBNICATE", True),
    ("TRACE", False), ("CONNECT", False),
])
def test_method_rejected_never_reaches_storage(srv, method, gated):
    path = _cas_unique(f"method-{method}")
    status, rej, _, _ = _probe(srv, method, path)
    assert status == 405
    assert len(rej) == (1 if gated else 0)
    # The origin mock logs every data GET and HEAD: this path must appear in
    # neither — a rejected method dies at the gate, not at storage.
    assert not any(path in e["path"] for e in srv.get_log())
    assert not any(path in e["path"] for e in srv.get_heads())


def test_get_serves_manifest(srv, manifest_body):
    status, rej, hdrs, body = _probe(srv, "GET", f"/cvmfs/{REPO}/.cvmfspublished")
    assert (status, rej) == (200, []) and body == manifest_body
    assert int(hdrs["content-length"]) == len(body)


def test_head_manifest_no_body_length_parity(srv, manifest_body):
    status, rej, hdrs, body = _probe(srv, "HEAD", f"/cvmfs/{REPO}/.cvmfspublished")
    assert (status, rej, body) == (200, [], b"")
    assert int(hdrs["content-length"]) == len(manifest_body)


def test_get_serves_cas_object_bytes(srv):
    obj = srv.objects()[2]
    origin = request(HOST, srv.mock_ports[0], "GET", obj)[2]
    status, rej, _, body = _probe(srv, "GET", obj)
    assert (status, rej) == (200, []) and body == origin


def test_head_cas_object_length_parity(srv):
    obj = srv.objects()[2]                     # warmed by the GET test or cold
    glen = len(request(HOST, srv.nginx_port, "GET", obj)[2])
    status, rej, hdrs, body = _probe(srv, "HEAD", obj)
    assert (status, rej, body) == (200, [], b"")
    assert int(hdrs["content-length"]) == glen
