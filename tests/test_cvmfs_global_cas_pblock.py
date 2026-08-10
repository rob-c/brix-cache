# tests/test_cvmfs_global_cas_pblock.py — Phase-88: G13 over a PBLOCK store.
#
# The same cross-repo dedup contract as test_cvmfs_global_cas.py, served from
# a pblock cache store instead of posix: brix_cache_store
# pblock:<dir>?dedup=1&pack=1 collapses byte-identical cvmfs-cas-VERIFIED
# objects from different repos onto ONE refcounted blob (the W1 dedup slot →
# F10 refs; no hardlinks, no /.gcas names), and small CAS objects come to rest
# in the W2 packed arena (one shared-segment record instead of a per-object
# dir + block file). Keys, cinfo, authz and origin fetches stay strictly
# per-repo: repo B still fills through its OWN origin.
#
# Assertions read the store's own catalog (catalog.db: objects/blobs/pack) —
# the pblock twin of the posix suite's st_ino/st_nlink checks.
#
# Port block: srv_authz — shared sequentially with the posix gcas suite via
# the same xdist group (module fixtures close between files).
import hashlib
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance
from settings import HOST

REPO_A = "repo-a.cern.ch"
REPO_B = "repo-b.cern.ch"

pytestmark = [pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                 reason=f"nginx binary not found: {NGINX_BIN}"),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cvmfs-gcas-evict")]

BLOCK = PortBlock("srv_authz")


# ---- fixtures --------------------------------------------------------------

@pytest.fixture(scope="module")
def srv():
    """One webroot origin carrying TWO repo trees behind one nginx whose cache
    store is a dedup+pack-armed PBLOCK export with global_cas on."""
    root = Path(tempfile.mkdtemp(prefix="cvmfs_gcas_pb_webroot."))
    for repo in (REPO_A, REPO_B):
        (root / "cvmfs" / repo / "data").mkdir(parents=True)
    if os.geteuid() == 0:
        for d in root.rglob("*"):
            if d.is_dir():
                os.chmod(d, 0o777)
        os.chmod(root, 0o777)
    with srv_instance(
            BLOCK, webroot=root,
            cache_store="pblock:{cache}?dedup=1&pack=1 block_size=256m",
            extra_directives="brix_cache_global_cas on;") as s:
        s.webroot = root
        yield s
    shutil.rmtree(root, ignore_errors=True)


# ---- local helpers (file-local by mandate: shared infra is frozen) ---------

def GET(s, path):
    return request(HOST, s.nginx_port, "GET", path)


def body_for(tag, n=6000):
    seed = hashlib.sha256(f"gcas_pblock:{tag}".encode()).digest()
    return (seed * (n // len(seed) + 1))[:n]


def put_obj(s, repo, body, claimed_hex=None):
    """Drop a CAS object into `repo`'s origin tree (optionally under a LYING
    name); returns its URL path."""
    hx = claimed_hex or hashlib.sha1(body).hexdigest()
    d = s.webroot / "cvmfs" / repo / "data" / hx[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / hx[2:]).write_bytes(body)
    return f"/cvmfs/{repo}/data/{hx[:2]}/{hx[2:]}"


def catalog(s):
    """Read-only view of the pblock store's catalog (WAL — safe to read while
    the worker holds it)."""
    return sqlite3.connect(f"file:{s.cache}/catalog.db?mode=ro", uri=True)


def blob_of(s, key_suffix):
    """The blob_id backing the one cache key ending in `key_suffix`."""
    db = catalog(s)
    rows = db.execute(
        "SELECT path, blob_id FROM objects WHERE is_dir = 0 AND path LIKE ?;",
        (f"%{key_suffix}",)).fetchall()
    db.close()
    return rows


def refcount(s, blob):
    db = catalog(s)
    row = db.execute("SELECT refcount FROM blobs WHERE blob_id = ?;",
                     (blob,)).fetchone()
    db.close()
    return row[0] if row else 1        # absent row = implicit single ref


def packed(s, blob):
    db = catalog(s)
    row = db.execute("SELECT seg, len FROM pack WHERE blob_id = ?;",
                     (blob,)).fetchone()
    db.close()
    return row


def striped_files(s):
    """Block files remaining under the store's data/ tree."""
    data = Path(s.cache) / "data"
    return sorted(p for p in data.rglob("*") if p.is_file()) \
        if data.exists() else []


# ============================================================================
# 1. success: byte-identical objects in two repos collapse onto ONE refcounted
#    blob, resting as ONE packed-arena record
# ============================================================================

def test_cross_repo_dedup_one_blob_packed(srv):
    body = body_for("dedup")
    hx = hashlib.sha1(body).hexdigest()
    path_a = put_obj(srv, REPO_A, body)
    path_b = put_obj(srv, REPO_B, body)

    srv.reset_log()
    st, _, got = GET(srv, path_a)
    assert st == 200 and got == body, "repo-A fill failed"
    st, _, got = GET(srv, path_b)
    assert st == 200 and got == body, "repo-B fill failed"

    # Honesty: repo B filled through its OWN origin prefix, never repo A's.
    assert srv.count_log(f"/cvmfs/{REPO_B}/data/") >= 1, \
        "repo-B was served without its own origin proving the object"

    # Both per-repo cache keys exist and share ONE physical blob (refcount 2).
    rows = blob_of(srv, hx[2:])
    assert len(rows) == 2, f"expected two per-repo keys, got {rows}"
    blobs = {b for _, b in rows}
    assert len(blobs) == 1, f"cross-repo copies were not folded: {rows}"
    blob = blobs.pop()
    assert refcount(srv, blob) == 2, \
        f"expected refcount 2 on the shared blob, got {refcount(srv, blob)}"

    # W2: the shared blob rests in the packed arena, not as a striped file.
    rec = packed(srv, blob)
    assert rec is not None and rec[1] == len(body), \
        f"shared blob not in the packed arena: {rec}"
    assert (Path(srv.cache) / "pack" / f"seg-{rec[0]}.dat").exists()
    assert striped_files(srv) == [], \
        f"small CAS objects left striped files: {striped_files(srv)}"

    # Serving after dedup still returns genuine bytes for both repos.
    st, _, got = GET(srv, path_a)
    assert st == 200 and got == body, "repo-A re-read failed after dedup"
    st, _, got = GET(srv, path_b)
    assert st == 200 and got == body, "repo-B re-read failed after dedup"


# ============================================================================
# 2. error/no-false-dedup: same-size DIFFERENT bytes stay distinct blobs
# ============================================================================

def test_different_content_never_folds(srv):
    body_a = body_for("distinct-a")
    body_b = body_for("distinct-b")
    assert len(body_a) == len(body_b) and body_a != body_b
    path_a = put_obj(srv, REPO_A, body_a)
    path_b = put_obj(srv, REPO_B, body_b)

    st, _, got = GET(srv, path_a)
    assert st == 200 and got == body_a
    st, _, got = GET(srv, path_b)
    assert st == 200 and got == body_b

    ha = hashlib.sha1(body_a).hexdigest()
    hb = hashlib.sha1(body_b).hexdigest()
    (row_a,) = blob_of(srv, ha[2:])
    (row_b,) = blob_of(srv, hb[2:])
    assert row_a[1] != row_b[1], "different content aliased onto one blob"
    assert refcount(srv, row_a[1]) == 1 and refcount(srv, row_b[1]) == 1


# ============================================================================
# 3. security-neg: an UNVERIFIED object never caches, never dedups, never packs
# ============================================================================

def test_unverified_never_enters_the_store(srv):
    body = body_for("evil")
    claimed = hashlib.sha1(body_for("innocent")).hexdigest()
    assert claimed != hashlib.sha1(body).hexdigest()
    path = put_obj(srv, REPO_A, body, claimed_hex=claimed)

    st, _hdrs, _body = GET(srv, path)
    assert st >= 500, \
        f"a name/content-mismatched CAS object was served (status {st})"

    db = catalog(srv)
    n = db.execute("SELECT COUNT(*) FROM objects WHERE path LIKE ?;",
                   (f"%{claimed[2:]}",)).fetchone()[0]
    db.close()
    assert n == 0, "an UNVERIFIED fill committed a catalog row"
