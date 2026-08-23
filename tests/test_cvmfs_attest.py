"""Phase-87 G15 — runtime provenance / SLSA attestation: brix_cvmfs_attest.

Theme
-----
The proxy verifies every CAS byte it serves (phase-85 F1), so it can attest
exactly which content hashes a session consumed. Contract:

* a data request tagged `X-Brix-Attest: <label>` has its served CAS hashes
  recorded under that session (per-worker table; worker_processes 1 here);
* `GET <loc>/.cvmfs-attest?session=<label>` returns a DSSE envelope over an
  in-toto v1 Statement whose subject digests are EXACTLY the consumed set —
  signed (RSA-SHA256 over the DSSE PAE) with the configured private key;
* attestation off (directive unset) ⇒ no record, no endpoint, zero overhead;
* a tampered payload or a signature minted with a different key fails
  verification — forged attestations do not verify.

Port block srv_authz (13280-13299) via the shared per-process tile.
"""

import base64
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
def _guard_fetch_1(attest, req):
    if attest is not None:
        req.add_header("X-Brix-Attest", attest)

def _guard_fetch_2(token, req):
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")

def _guard_fetch_3(rng, req):
    if rng is not None:
        req.add_header("Range", rng)

def _check_test_session_record_lists_exact_hashes_and_verifies_2(st):
    assert st == 200                                   # untagged

def _check_test_session_record_lists_exact_hashes_and_verifies_3(st):
    assert st == 200          # manifest: no content hash — not recorded

def _check_test_session_record_lists_exact_hashes_and_verifies_4(st):
    assert st == 200

def _check_test_session_record_lists_exact_hashes_and_verifies_5(st):
    assert st == 200

def _check_test_session_record_lists_exact_hashes_and_verifies_6(stmt):
    assert stmt["predicate"]["truncated"] is False

def _check_test_session_record_lists_exact_hashes_and_verifies_7(digests, objs):
    assert digests == sorted(h for _rel, h in objs[:2])

def _check_test_session_record_lists_exact_hashes_and_verifies_1(st):
    assert st == 200


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, srv_instance

try:                                     # cryptography is an optional test dep
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    _HAVE_CRYPTO = True
except Exception:                        # noqa: BLE001
    _HAVE_CRYPTO = False

try:                                     # F3 gating leg needs the token forge
    from tokenforge import TokenForge, write_scitokens_cfg
    _HAVE_TOKENFORGE = True
except Exception:                        # noqa: BLE001
    _HAVE_TOKENFORGE = False

requires_tokens = pytest.mark.skipif(
    not _HAVE_TOKENFORGE, reason="tokenforge (cryptography) unavailable")

pytestmark = [
    pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                       reason=f"nginx binary not found: {NGINX_BIN}"),
    pytest.mark.skipif(shutil.which("openssl") is None,
                       reason="openssl not installed"),
    pytest.mark.skipif(not _HAVE_CRYPTO,
                       reason="cryptography unavailable"),
]

_BLOCK = PortBlock("srv_authz")

REPO = "attest.cern.ch"


# ---- forging ---------------------------------------------------------------

def _put_cas(webroot: Path, body: bytes) -> tuple[str, str]:
    """Honest CAS object (name = sha1 of stored bytes); returns (rel, hex)."""
    h = hashlib.sha1(body).hexdigest()
    rel = f"data/{h[:2]}/{h[2:]}"
    p = webroot / "cvmfs" / REPO / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body)
    return rel, h


def _forge(tmp: Path) -> tuple[Path, list[tuple[str, str]]]:
    webroot = tmp / "webroot"
    objs = [_put_cas(webroot, f"attest-payload-{i}\n".encode()) for i in range(3)]
    man = webroot / "cvmfs" / REPO / ".cvmfspublished"
    man.parent.mkdir(parents=True, exist_ok=True)
    man.write_bytes(b"manifest-bytes\n")
    return webroot, objs


def _gen_key(tmp: Path, name: str) -> tuple[Path, Path]:
    priv, pub = tmp / f"{name}.pem", tmp / f"{name}.pub"
    subprocess.run(["openssl", "genrsa", "-out", str(priv), "2048"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(priv), "-pubout",
                    "-out", str(pub)], check=True, capture_output=True)
    return priv, pub


# ---- fetch / verify helpers ------------------------------------------------

def _fetch(port, path, *, attest=None, token=None, rng=None, https=False):
    from settings import HOST
    scheme = "https" if https else "http"
    req = urllib.request.Request(f"{scheme}://{HOST}:{port}{path}")
    _guard_fetch_1(attest, req)
    _guard_fetch_2(token, req)
    _guard_fetch_3(rng, req)
    kw = {"context": ssl._create_unverified_context()} if https else {}
    try:
        with urllib.request.urlopen(req, timeout=15, **kw) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _pae(payload_type: bytes, payload: bytes) -> bytes:
    return (b"DSSEv1 %d %s %d " % (len(payload_type), payload_type,
                                   len(payload))) + payload


def _verify(envelope: bytes, pub_pem: Path) -> dict:
    """Verify the DSSE envelope signature; returns the decoded statement.
    Raises on any signature mismatch."""
    env = json.loads(envelope)
    payload = base64.b64decode(env["payload"])
    sig = base64.b64decode(env["signatures"][0]["sig"])
    pub = serialization.load_pem_public_key(pub_pem.read_bytes())
    pub.verify(sig, _pae(env["payloadType"].encode(), payload),
               padding.PKCS1v15(), hashes.SHA256())
    return json.loads(payload)


# ---- success: exact consumed set, signature verifies -----------------------

def test_session_record_lists_exact_hashes_and_verifies(tmp_path):
    webroot, objs = _forge(tmp_path)
    priv, pub = _gen_key(tmp_path, "sign")
    with srv_instance(_BLOCK, webroot=webroot,
                      extra_directives=f"brix_cvmfs_attest {priv};") as srv:
        # consume two of the three objects under session "job-1"; the third
        # object and the manifest go untagged / under another session
        for rel, _h in objs[:2]:
            st, _ = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/{rel}",
                           attest="job-1")
            _check_test_session_record_lists_exact_hashes_and_verifies_1(st)
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/{objs[2][0]}")
        _check_test_session_record_lists_exact_hashes_and_verifies_2(st)
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/.cvmfspublished",
                       attest="job-1")
        _check_test_session_record_lists_exact_hashes_and_verifies_3(st)
        # a re-read is not a new consumption (the record is a set)
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/{objs[0][0]}",
                       attest="job-1")
        _check_test_session_record_lists_exact_hashes_and_verifies_4(st)

        st, body = _fetch(srv.nginx_port,
                          f"/cvmfs/{REPO}/.cvmfs-attest?session=job-1")
        _check_test_session_record_lists_exact_hashes_and_verifies_5(st)
        stmt = _verify(body, pub)
        def _assert_test_session_record_lists_exact_hashes_and_verifies_1():
            assert stmt["_type"] == "https://in-toto.io/Statement/v1"
            assert stmt["predicate"]["session"] == "job-1"

        _assert_test_session_record_lists_exact_hashes_and_verifies_1()
        _check_test_session_record_lists_exact_hashes_and_verifies_6(stmt)
        digests = sorted(s["digest"]["sha1"] for s in stmt["subject"])
        _check_test_session_record_lists_exact_hashes_and_verifies_7(digests, objs)


# ---- error: attest off ⇒ no record, no endpoint ----------------------------

def test_attest_off_means_no_record_and_no_endpoint(tmp_path):
    webroot, objs = _forge(tmp_path)
    with srv_instance(_BLOCK, webroot=webroot) as srv:
        # tagging is inert when the directive is unset
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/{objs[0][0]}",
                       attest="job-1")
        assert st == 200
        # and the endpoint is not a CVMFS traffic shape → classify rejects
        st, _ = _fetch(srv.nginx_port,
                       f"/cvmfs/{REPO}/.cvmfs-attest?session=job-1")
        assert st == 403

    # enabled instance: unknown session is a clean 404, bad label a 400
    priv, _pub = _gen_key(tmp_path, "sign2")
    with srv_instance(_BLOCK, webroot=webroot,
                      extra_directives=f"brix_cvmfs_attest {priv};") as srv:
        st, _ = _fetch(srv.nginx_port,
                       f"/cvmfs/{REPO}/.cvmfs-attest?session=never-seen")
        assert st == 404
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/.cvmfs-attest")
        assert st == 400
        st, _ = _fetch(srv.nginx_port,
                       f"/cvmfs/{REPO}/.cvmfs-attest?session=bad%2Flabel")
        assert st == 400


# ---- security-neg: forged / tampered attestations fail verification --------

def test_forged_or_tampered_attestation_fails_verification(tmp_path):
    webroot, objs = _forge(tmp_path)
    priv, pub = _gen_key(tmp_path, "sign")
    _other_priv, other_pub = _gen_key(tmp_path, "attacker")
    with srv_instance(_BLOCK, webroot=webroot,
                      extra_directives=f"brix_cvmfs_attest {priv};") as srv:
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/{objs[0][0]}",
                       attest="job-x")
        assert st == 200
        st, body = _fetch(srv.nginx_port,
                          f"/cvmfs/{REPO}/.cvmfs-attest?session=job-x")
        assert st == 200
        _verify(body, pub)                     # sanity: the honest one holds

        # 1. payload tampered (hash swapped for a different object's) — the
        #    signature must not survive
        env = json.loads(body)
        payload = base64.b64decode(env["payload"])
        forged = payload.replace(objs[0][1].encode(), objs[1][1].encode())
        assert forged != payload
        env["payload"] = base64.b64encode(forged).decode()
        with pytest.raises(Exception):
            _verify(json.dumps(env).encode(), pub)

        # 2. replayed under an attacker's key — verification against the
        #    proxy's real public key must fail
        with pytest.raises(Exception):
            _verify(body, other_pub)


# ---- success: ranged tagged reads are attested -----------------------------

def test_tagged_range_read_is_attested(tmp_path):
    """The observer records on BOTH success statuses (200 and 206): a job
    that reads an object by ranges still consumed those bytes."""
    webroot, objs = _forge(tmp_path)
    priv, pub = _gen_key(tmp_path, "sign")
    rel, hexd = objs[0]
    with srv_instance(_BLOCK, webroot=webroot,
                      extra_directives=f"brix_cvmfs_attest {priv};") as srv:
        st, body = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/{rel}",
                          attest="range-job", rng="bytes=0-4")
        assert st in (200, 206)
        if st == 206:
            assert len(body) == 5
        st, rec = _fetch(srv.nginx_port,
                         f"/cvmfs/{REPO}/.cvmfs-attest?session=range-job")
        assert st == 200
        stmt = _verify(rec, pub)
        assert [s["digest"]["sha1"] for s in stmt["subject"]] == [hexd]


# ---- error: invalid tags and failed requests never enter the record --------

def test_invalid_tags_and_misses_never_recorded(tmp_path):
    webroot, objs = _forge(tmp_path)
    priv, _pub = _gen_key(tmp_path, "sign")
    with srv_instance(_BLOCK, webroot=webroot,
                      extra_directives=f"brix_cvmfs_attest {priv};") as srv:
        # a label outside the charset: request served, tag dropped
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/{objs[0][0]}",
                       attest="bad/label")
        assert st == 200
        # an overlong label (65 chars of valid charset): same — served untagged
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/{objs[0][0]}",
                       attest="x" * 65)
        assert st == 200
        # an overlong label is equally rejected at the query side
        st, _ = _fetch(srv.nginx_port,
                       f"/cvmfs/{REPO}/.cvmfs-attest?session=" + "x" * 65)
        assert st == 400

        # a tagged MISS (clean 404) creates no session: only content that
        # was actually SERVED can be attested
        ghost = hashlib.sha1(b"never-published").hexdigest()
        st, _ = _fetch(srv.nginx_port,
                       f"/cvmfs/{REPO}/data/{ghost[:2]}/{ghost[2:]}",
                       attest="ghost-job")
        assert st == 404
        st, _ = _fetch(srv.nginx_port,
                       f"/cvmfs/{REPO}/.cvmfs-attest?session=ghost-job")
        assert st == 404


# ---- error: bounded table evicts oldest, never fails -----------------------

def test_session_table_evicts_oldest_when_full(tmp_path):
    """33 sessions against the 32-slot per-worker table (attest.c
    CVMFS_ATTEST_SESSIONS): the OLDEST record is dropped (NOTICE-logged
    server-side), everything else stays queryable — bounded, never silent,
    never an error."""
    webroot, objs = _forge(tmp_path)
    priv, pub = _gen_key(tmp_path, "sign")
    rel, hexd = objs[0]
    with srv_instance(_BLOCK, webroot=webroot,
                      extra_directives=f"brix_cvmfs_attest {priv};") as srv:
        for i in range(33):
            st, _ = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/{rel}",
                           attest=f"evict-{i:02d}")
            assert st == 200
        # the first session was evicted to admit the 33rd
        st, _ = _fetch(srv.nginx_port,
                       f"/cvmfs/{REPO}/.cvmfs-attest?session=evict-00")
        assert st == 404
        # its neighbors — second-oldest and newest — survived intact
        for label in ("evict-01", "evict-32"):
            st, rec = _fetch(srv.nginx_port,
                             f"/cvmfs/{REPO}/.cvmfs-attest?session={label}")
            assert st == 200
            stmt = _verify(rec, pub)
            assert [s["digest"]["sha1"] for s in stmt["subject"]] == [hexd]
            assert stmt["predicate"]["session"] == label


# ---- success: G16 composition — member-walk serves are attested ------------

def test_virtual_member_walk_is_attested(tmp_path):
    """G16 x G15: an object reached through a virtual repo's member walk is
    recorded like any direct serve — the observer fires with the FINAL
    (member) classify state after the 404-advance."""
    virt, mem_a, mem_b = "virt-att.cern.ch", "att-a.cern.ch", "att-b.cern.ch"
    webroot = tmp_path / "webroot"
    body = b"only-in-member-b\n"
    hexd = hashlib.sha1(body).hexdigest()
    rel = f"data/{hexd[:2]}/{hexd[2:]}"
    p = webroot / "cvmfs" / mem_b / rel
    p.parent.mkdir(parents=True)
    p.write_bytes(body)

    priv, pub = _gen_key(tmp_path, "sign")
    extra = (f"brix_cvmfs_attest {priv}; "
             f"brix_cvmfs_virtual_repo {virt} {mem_a} {mem_b};")
    with srv_instance(_BLOCK, webroot=webroot, extra_directives=extra) as srv:
        st, got = _fetch(srv.nginx_port, f"/cvmfs/{virt}/{rel}",
                         attest="virt-job")
        assert (st, got) == (200, body)               # walked a→404→b
        st, rec = _fetch(srv.nginx_port,
                         f"/cvmfs/{virt}/.cvmfs-attest?session=virt-job")
        assert st == 200
        stmt = _verify(rec, pub)
        assert [s["digest"]["sha1"] for s in stmt["subject"]] == [hexd]


# ---- security-neg: a gated repo's record sits behind its F3 gate -----------

@requires_tokens
def test_gated_session_record_requires_repo_token(tmp_path):
    """F3 contract: ALL of a token-gated repo's traffic is behind its gate —
    including the attestation record of what was consumed from it. A session
    that touched gated content must not be readable anonymously, nor through
    an ungated sibling repo's name (that would be a gate bypass); a session
    of only-open content stays openly readable."""
    gated, open_ = "secret.cern.ch", "open.cern.ch"
    webroot = tmp_path / "webroot"

    def put(repo, body):
        h = hashlib.sha1(body).hexdigest()
        rel = f"data/{h[:2]}/{h[2:]}"
        p = webroot / "cvmfs" / repo / rel
        p.parent.mkdir(parents=True)
        p.write_bytes(body)
        return rel, h

    grel, ghex = put(gated, b"gated-payload\n")
    orel, ohex = put(open_, b"open-payload\n")

    priv, pub = _gen_key(tmp_path, "sign")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days",
         "1", "-subj", "/CN=localhost",  # net-literal-allow: throwaway TLS cert subject CN
         "-keyout", str(tmp_path / "key.pem"), "-out", str(tmp_path / "crt.pem")],
        check=True, capture_output=True)
    forge = TokenForge(str(tmp_path / "mint"))
    forge.init_keys()
    cfg = tmp_path / "mint" / "scitokens.cfg"
    write_scitokens_cfg(str(cfg), [{
        "name": "attest-authz", "issuer": forge.issuer,
        "audience": forge.audience, "base_paths": ["/"],
        "jwks_path": forge.jwks_path, "strategy": "capability",
    }])

    extra = (f"brix_cvmfs_attest {priv}; "
             f"brix_cvmfs_repo_authz {gated} {cfg};")
    with srv_instance(_BLOCK, webroot=webroot, extra_directives=extra,
                      ssl_cert=tmp_path / "crt.pem",
                      ssl_key=tmp_path / "key.pem") as srv:
        tok = forge.generate()
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{gated}/{grel}",
                       https=True, token=tok, attest="gated-job")
        assert st == 200
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{open_}/{orel}",
                       https=True, attest="open-job")
        assert st == 200

        # anonymous read of the gated session: refused under the gated name…
        st, _ = _fetch(srv.nginx_port,
                       f"/cvmfs/{gated}/.cvmfs-attest?session=gated-job",
                       https=True)
        assert st == 401
        # …and refused under the ungated sibling name (gate bypass closed)
        st, _ = _fetch(srv.nginx_port,
                       f"/cvmfs/{open_}/.cvmfs-attest?session=gated-job",
                       https=True)
        assert st == 401, "ungated sibling name bypassed the F3 gate"

        # the gated repo's authorized reader gets the signed record
        st, rec = _fetch(srv.nginx_port,
                         f"/cvmfs/{gated}/.cvmfs-attest?session=gated-job",
                         https=True, token=tok)
        assert st == 200
        stmt = _verify(rec, pub)
        assert [s["digest"]["sha1"] for s in stmt["subject"]] == [ghex]

        # a session of only-open content keeps the documented open contract
        st, rec = _fetch(srv.nginx_port,
                         f"/cvmfs/{open_}/.cvmfs-attest?session=open-job",
                         https=True)
        assert st == 200
        assert [s["digest"]["sha1"]
                for s in _verify(rec, pub)["subject"]] == [ohex]
