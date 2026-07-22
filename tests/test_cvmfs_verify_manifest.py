"""Phase-85 F1 — verifying proxy: manifest/whitelist signature verify at edge.

Theme
-----
With ``brix_cvmfs_verify_manifest <master.pub>`` set on a repo location, a
MANIFEST-class fill (``.cvmfspublished`` / ``.cvmfswhitelist``) is verified on
the fill thread before commit, mirroring the FUSE client's trust chain
(shared/cvmfs/signature/verify.c):

* ``.cvmfswhitelist`` — signature vs the pinned master key + not expired;
* ``.cvmfspublished`` — full chain: sibling whitelist verified as above, the
  manifest certificate (fetched from CAS through the same source tier) must be
  fingerprint-listed in the whitelist, the manifest signature must verify
  against that certificate, and the manifest ``N`` field must name this repo
  (cross-repo splice rejection);
* ``.cvmfsreflog`` is unsigned in stock CVMFS and is served unverified;
* a DEFINITIVE verification failure fails the fill (5xx to the client — no
  tampered bytes are ever committed or served) and emits the guard-core audit
  token ``signal=cvmfs_tamper`` (origin authority in the ip field) for the
  maxretry=1 fail2ban jail;
* with the directive absent the proxy is transparent exactly as in phase-84 —
  tampered metadata passes through untouched, no audit line.

Port block 13260-13279 (mocks 13260-13269, nginx 13270-13279); pairs rotate
per test so a torn-down instance can never answer for its successor.
"""

import itertools
import os
import sys
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, srv_instance
from repo_forge import Dir, File, RepoForge
from settings import HOST

REPO = "test.cern.ch"

pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN), reason=f"nginx binary not found: {NGINX_BIN}")


class _FixedBlock(PortBlock):
    """A PortBlock pinned to one mock/nginx pair (see srv_manifest corpus)."""

    def __init__(self, mock_port: int, nginx_port: int):
        super().__init__("srv_verify")
        self._mp, self._np = mock_port, nginx_port

    def mock(self) -> int:
        return self._mp

    def nginx(self) -> int:
        return self._np


_PAIRS = itertools.cycle([(13260 + i, 13270 + i) for i in range(10)])


def _tree() -> dict:
    return {"hello": File(b"verify me\n"),
            "sub": Dir({"leaf": File(b"leaf bytes\n")})}


def _forge(tmp_path: Path, **kw):
    web = tmp_path / "web"
    pub = tmp_path / "repo.pub"
    forge = RepoForge(REPO, web, **kw).build(_tree(), pub)
    return forge, web, pub


@contextmanager
def _srv(web, pub=None, **kw):
    """nginx over the forged webroot; pub!=None pins the verify master key."""
    mock_port, nginx_port = next(_PAIRS)
    if pub is not None:
        kw["verify_manifest"] = str(pub)
    with srv_instance(_FixedBlock(mock_port, nginx_port), webroot=web, **kw) as srv:
        yield srv


def _get(srv, name, repo=REPO):
    url = f"http://{HOST}:{srv.nginx_port}/cvmfs/{repo}/{name}"
    try:
        with urllib.request.urlopen(url, timeout=25) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _tamper_lines(srv):
    text = Path(srv.error_log).read_text(errors="replace")
    return [l for l in text.splitlines() if "signal=cvmfs_tamper" in l]


# ---- success ---------------------------------------------------------------

def test_verified_metadata_serves(tmp_path):
    """A correctly signed repo serves manifest, whitelist, and data through the
    verifying proxy byte-for-byte, with no tamper audit line."""
    forge, web, pub = _forge(tmp_path)
    manifest = forge.artifact_path("manifest").read_bytes()
    whitelist = forge.artifact_path("whitelist").read_bytes()
    with _srv(web, pub) as srv:
        st, body = _get(srv, ".cvmfspublished")
        assert st == 200 and body == manifest
        st, body = _get(srv, ".cvmfswhitelist")
        assert st == 200 and body == whitelist
        # the chain gate must not disturb ordinary CAS serving
        key = forge.root_catalog_hash
        st, _ = _get(srv, f"data/{key[:2]}/{key[2:]}C")
        assert st == 200
        assert _tamper_lines(srv) == []
    forge.close()


def test_unsigned_reflog_passes(tmp_path):
    """.cvmfsreflog carries no signature in stock CVMFS — the verify gate must
    skip it rather than fail it."""
    forge, web, pub = _forge(tmp_path)
    reflog = b"reflog payload, unsigned by design\n"
    (forge.repo_dir / ".cvmfsreflog").write_bytes(reflog)
    with _srv(web, pub) as srv:
        st, body = _get(srv, ".cvmfsreflog")
        assert st == 200 and body == reflog
        assert _tamper_lines(srv) == []
    forge.close()


# ---- error: tampered artifacts are refused + audited -----------------------

def test_tampered_manifest_rejected(tmp_path):
    """A manifest whose signature bytes are corrupted must fail the fill (5xx,
    no tampered bytes served) and emit signal=cvmfs_tamper."""
    forge, web, pub = _forge(tmp_path)
    forge.flip_byte("manifest", -1)
    with _srv(web, pub) as srv:
        st, _ = _get(srv, ".cvmfspublished")
        assert st >= 500
        assert _tamper_lines(srv), "expected a cvmfs_tamper audit line"
    forge.close()


def test_expired_whitelist_rejected(tmp_path):
    """A whitelist past its expiry stamp invalidates the whole chain: both the
    whitelist itself and the manifest that depends on it are refused."""
    forge, web, pub = _forge(tmp_path, whitelist_expiry="20200101000000")
    with _srv(web, pub) as srv:
        st, _ = _get(srv, ".cvmfswhitelist")
        assert st >= 500
        st, _ = _get(srv, ".cvmfspublished")
        assert st >= 500
        assert _tamper_lines(srv)
    forge.close()


# ---- security-negative -----------------------------------------------------

def test_wrong_master_key_rejected(tmp_path):
    """Whitelist signed by a key other than the pinned master must be refused —
    the pinned key is the sole trust root."""
    forge, web, pub = _forge(tmp_path)
    foreign = RepoForge.gen_key(tmp_path / "foreign.key")
    foreign_pub = tmp_path / "foreign.pub"
    foreign_pub.write_bytes(RepoForge._pubkey_pem(foreign))
    with _srv(web, foreign_pub) as srv:
        st, _ = _get(srv, ".cvmfswhitelist")
        assert st >= 500
        assert _tamper_lines(srv)
    forge.close()


def test_cross_repo_splice_rejected(tmp_path):
    """A manifest with a VALID signature chain but naming a different repo (N
    field) must be refused: splicing repo A's signed manifest under repo B's
    path is the canonical substitution attack."""
    forge, web, pub = _forge(tmp_path)
    fields = forge._manifest_fields()
    fields["N"] = "evil.cern.ch"
    forge.rewrite_manifest(fields)          # re-signed with the REAL cert key
    with _srv(web, pub) as srv:
        st, _ = _get(srv, ".cvmfspublished")
        assert st >= 500
        assert _tamper_lines(srv)
    forge.close()


# ---- phase-84 transparency with the gate off -------------------------------

def test_gate_off_transparent(tmp_path):
    """Without brix_cvmfs_verify_manifest the proxy behaves exactly as in
    phase-84: tampered metadata passes through untouched, no audit line."""
    forge, web, _pub = _forge(tmp_path)
    forge.flip_byte("manifest", -1)
    tampered = forge.artifact_path("manifest").read_bytes()
    with _srv(web) as srv:
        st, body = _get(srv, ".cvmfspublished")
        assert st == 200 and body == tampered
        assert _tamper_lines(srv) == []
    forge.close()
