# tests/test_cvmfs_conformance_srv_cas.py — Phase-84 srv_cas conformance corpus.
#
# CAS-object serve correctness through the brix_cvmfs site cache: verify-on-fill
# (corrupt / truncated / wrong-length fills are never served as a corrupt 200;
# mismatches are quarantined and refetched), cache-hit byte identity with exactly
# one origin fetch, hash-length {40,64,96,128} and suffix variants through the
# verify path, compressed stored bytes served verbatim (the cache is a byte
# proxy — the CLIENT decompresses), and the negative-404 memo (absorption count,
# per-object isolation, negative_ttl expiry, object-appears-later servability).
#
# Port block: srv_cas = 13140 (mocks 13140-13149, nginx 13150-13159).
import hashlib
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
import zlib
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance
from settings import HOST

REPO = "test.cern.ch"
NEG_TTL = 2                       # seconds; keep expiry tests fast

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

# One shared allocator for this file's 20-port block (mocks +0.., nginx +10..).
BLOCK = PortBlock("srv_cas")


# ---- fixtures --------------------------------------------------------------

@pytest.fixture(scope="module")
def srv():
    """Synthetic-object instance: verify-on-fill + cache-hit + negative tests."""
    qdir = Path(tempfile.mkdtemp(prefix="cvmfs_cas_quarantine."))
    with srv_instance(BLOCK, objects=48, seed=84, negative_ttl=NEG_TTL,
                      client_hold=2, quarantine_dir=qdir) as s:
        s.qdir = qdir
        s._alloc = iter(s.objects())
        yield s
    shutil.rmtree(qdir, ignore_errors=True)


@pytest.fixture(scope="module")
def web():
    """Webroot instance: full control of stored bytes (hash-length/suffix/
    compressed corpora, object-appears-later negative tests)."""
    root = Path(tempfile.mkdtemp(prefix="cvmfs_cas_webroot."))
    (root / "cvmfs" / REPO / "data").mkdir(parents=True)
    qdir = Path(tempfile.mkdtemp(prefix="cvmfs_cas_webq."))
    with srv_instance(BLOCK, webroot=root, negative_ttl=NEG_TTL,
                      client_hold=2, quarantine_dir=qdir) as s:
        s.webroot = root
        s.qdir = qdir
        yield s
    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(qdir, ignore_errors=True)


# ---- local helpers (file-local by mandate: shared infra is frozen) ---------

def GET(s, path, method="GET"):
    return request(HOST, s.nginx_port, method, path)


def take(s):
    """A distinct, never-before-used synthetic object path (test isolation)."""
    return next(s._alloc)


def origin_bytes(s, path):
    """Reference bytes straight from the mock (fetch BEFORE arming faults)."""
    return urllib.request.urlopen(s.mock_url + path).read()


def arm(s, mode, count, path):
    s.set_fault(mode, count, path_re=re.escape(path))


def clear_fault(s):
    s.set_fault("none", 0)


def put_obj(w, body, suffix="", hexname=None):
    """Drop a CAS object into the webroot; returns its URL path. When hexname
    is None the object is named by sha1(stored bytes) — the verifiable case."""
    hx = hexname or hashlib.sha1(body).hexdigest()
    d = w.webroot / "cvmfs" / REPO / "data" / hx[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / (hx[2:] + suffix)).write_bytes(body)
    return f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}{suffix}"


def count_heads(s, path):
    """Origin consultations for a MISSING object are HEAD size-probes (the fill
    probes before its data GET, and a 404 is definitive there) — /ctl/log only
    counts data GETs, so 404-absorption is measured on /ctl/heads."""
    return sum(1 for e in s.get_heads() if path in e["path"])


def missing_path(tag):
    """A valid-shape 40-hex CAS path guaranteed absent from both origins."""
    h = hashlib.sha1(f"srv_cas-missing:{tag}".encode()).hexdigest()
    return f"/cvmfs/{REPO}/data/{h[:2]}/{h[2:]}"


def body_for(tag, n=6000):
    """Deterministic per-test content (distinct objects per test)."""
    seed = hashlib.sha256(f"srv_cas:{tag}".encode()).digest()
    return (seed * (n // len(seed) + 1))[:n]


# ============================================================================
# 1. verify-on-fill: corrupt fills are never served, quarantined, refetched
# ============================================================================
