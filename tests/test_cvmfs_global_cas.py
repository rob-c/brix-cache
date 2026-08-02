# tests/test_cvmfs_global_cas.py — Phase-87 G13: cross-repo dedup CAS.
#
# brix_cache_global_cas collapses byte-identical cvmfs-cas-VERIFIED objects
# from different repos onto ONE inode in the local posix cache store, via a
# canonical repo-agnostic hardlink under <store>/.gcas/.  Keys, cinfo, authz
# and origin fetches stay strictly per-repo: every repo still fills — and
# 404s — through its OWN origin, so resident bytes are never served to a repo
# whose origin has not proven it holds them.  Eviction GC unlinks the
# canonical once it is the last remaining name (st_nlink is the refcount).
#
# Port block: srv_authz (shared sequentially — module fixtures close before
# the other file's run in a sweep; suites never run concurrently in-session).
import hashlib
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

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
    """One webroot origin carrying TWO repo trees behind one nginx cache with
    brix_cache_global_cas on — the dedup collapses across the repo prefixes."""
    root = Path(tempfile.mkdtemp(prefix="cvmfs_gcas_webroot."))
    for repo in (REPO_A, REPO_B):
        (root / "cvmfs" / repo / "data").mkdir(parents=True)
    if os.geteuid() == 0:
        # Root harness: the webroot is only read by the root-run mock, but the
        # 0700 mkdtemp chain must stay traversable if it is ever de-escalated —
        # keep the cold_tier posture.
        for d in root.rglob("*"):
            if d.is_dir():
                os.chmod(d, 0o777)
        os.chmod(root, 0o777)
    with srv_instance(BLOCK, webroot=root,
                      extra_directives="brix_cache_global_cas on;") as s:
        s.webroot = root
        yield s
    shutil.rmtree(root, ignore_errors=True)


# ---- local helpers (file-local by mandate: shared infra is frozen) ---------

def GET(s, path, method="GET"):
    return request(HOST, s.nginx_port, method, path)


def body_for(tag, n=6000):
    seed = hashlib.sha256(f"global_cas:{tag}".encode()).digest()
    return (seed * (n // len(seed) + 1))[:n]


def put_obj(s, repo, body):
    """Drop a CAS object into `repo`'s origin tree; returns its URL path."""
    hx = hashlib.sha1(body).hexdigest()
    d = s.webroot / "cvmfs" / repo / "data" / hx[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / hx[2:]).write_bytes(body)
    return f"/cvmfs/{repo}/data/{hx[:2]}/{hx[2:]}"


def cached_data_files(s, hx):
    """All non-sidecar cache files carrying the CAS hash (keys + canonical)."""
    return sorted(p for p in s.cache.rglob("*")
                  if p.is_file() and hx[2:] in p.name
                  and not p.name.endswith((".cinfo", ".gclnk")))


# ============================================================================
# 1. success: byte-identical objects in two repos collapse onto one inode
# ============================================================================

def test_cross_repo_dedup_one_inode(srv):
    body = body_for("dedup")
    hx = hashlib.sha1(body).hexdigest()
    path_a = put_obj(srv, REPO_A, body)
    path_b = put_obj(srv, REPO_B, body)

    srv.reset_log()
    status, _, got = GET(srv, path_a)
    assert status == 200 and got == body, "repo-A fill failed"
    status, _, got = GET(srv, path_b)
    assert status == 200 and got == body, "repo-B fill failed"

    # Dedup is honest, not a shortcut: repo B still fetched through ITS origin.
    assert srv.count_log(f"/cvmfs/{REPO_B}/data/") >= 1, \
        "repo-B fill did not go through repo-B's own origin path"

    files = cached_data_files(srv, hx)
    assert len(files) == 3, \
        f"expected 2 per-repo keys + 1 canonical, found: {files}"
    canon = [p for p in files if ".gcas" in p.parts]
    assert len(canon) == 1, f"canonical /.gcas name missing: {files}"

    stats = [p.stat() for p in files]
    assert len({st.st_ino for st in stats}) == 1, \
        "cross-repo copies did not collapse onto one inode"
    assert stats[0].st_nlink == 3, \
        f"expected st_nlink==3 (2 keys + canonical), got {stats[0].st_nlink}"


# ============================================================================
# 2. security-negative: resident bytes are NEVER served across repos
# ============================================================================

def test_no_cross_repo_serve_of_resident_bytes(srv):
    body = body_for("leak-check")
    hx = hashlib.sha1(body).hexdigest()
    path_b = put_obj(srv, REPO_B, body)          # repo B ONLY

    status, _, got = GET(srv, path_b)
    assert status == 200 and got == body, "repo-B fill failed"

    # The bytes are resident (canonical registered) …
    canon = srv.cache / ".gcas" / hx[:2] / hx[2:]
    assert canon.exists(), "canonical was not registered after verified fill"

    # … but the same hash requested via repo A must fill through repo A's
    # origin, which does not hold it: an honest 404, not a cross-repo serve.
    path_a = f"/cvmfs/{REPO_A}/data/{hx[:2]}/{hx[2:]}"
    status, _, _ = GET(srv, path_a)
    assert status == 404, \
        f"repo-A request for repo-B-only bytes must 404, got {status}"
    key_a = srv.cache / "cvmfs" / REPO_A / "data" / hx[:2] / hx[2:]
    assert not key_a.exists(), "a repo-A cache key appeared without a repo-A fill"


# ============================================================================
# 3. error path: eviction GC reaps the canonical with the last data link
# ============================================================================

def _fs_usage_percent(path: Path) -> int:
    u = shutil.disk_usage(path)
    return int((u.used * 100) / u.total)


def test_evict_gc_reaps_canonical_stream(lifecycle, tmp_path):
    used = _fs_usage_percent(tmp_path)
    if used < 10 or used > 96:
        pytest.skip(f"filesystem usage {used}% outside testable 10-96% band")

    cache = tmp_path / "cache"
    cache.mkdir()
    if os.geteuid() == 0:
        # Root harness: the DE-ESCALATED worker (`nobody`) must unlink the
        # planted victims and traverse the 0700 pytest tmp chain to reach them.
        from cmdscripts import open_tree_for_worker
        open_tree_for_worker(tmp_path)

    # Plant the exact post-dedup structure: two per-repo CAS keys and the
    # canonical /.gcas name, all hardlinks of ONE inode, backdated to be LRU
    # victims. The reaper evicts the keys; the gcas GC must reap the canonical
    # once the last data link is gone — whichever order the walk picks.
    body = bytes((7 + i) % 251 for i in range(65_536))
    hx = hashlib.sha1(body).hexdigest()
    key_a = cache / "cvmfs" / REPO_A / "data" / hx[:2] / hx[2:]
    key_b = cache / "cvmfs" / REPO_B / "data" / hx[:2] / hx[2:]
    canon = cache / ".gcas" / hx[:2] / hx[2:]
    key_a.parent.mkdir(parents=True)
    key_a.write_bytes(body)
    for p in (key_b, canon):
        p.parent.mkdir(parents=True)
        os.link(key_a, p)
    stamp = time.time() - 9 * 3600
    for p in (key_a, key_b, canon):
        os.utime(p, (stamp, stamp))
    if os.geteuid() == 0:
        from cmdscripts import open_tree_for_worker
        open_tree_for_worker(tmp_path)
    assert key_a.stat().st_nlink == 3

    lifecycle.start(NginxInstanceSpec(
        name="lc-cvmfs-gcas-evict",
        template="nginx_cvmfs_gcas_evict.conf",
        template_values={
            "BIND_HOST": BIND_HOST,
            "CACHE_DIR": str(cache),
            "HIGH_WM": used - 2,
            "LOW_WM": max(1, used - 5),
        },
        reason="CVMFS G13 evict-GC of the canonical hardlink",
    ))

    deadline = time.time() + 25
    while time.time() < deadline and (key_a.exists() or key_b.exists()):
        time.sleep(1)

    assert not key_a.exists() and not key_b.exists(), \
        "watermark reaper did not purge the planted per-repo keys"
    # The canonical must not survive as an orphan inode holding the bytes.
    deadline = time.time() + 10
    while time.time() < deadline and canon.exists():
        time.sleep(1)
    assert not canon.exists(), \
        "gcas GC left the canonical behind after its last data link was evicted"
    leftovers = [p for p in cache.rglob("*") if p.is_file()]
    assert not leftovers, f"cache store did not drain fully: {leftovers}"


# ============================================================================
# 4. security-negative: the publish gate — a fill that fails the cvmfs-cas
#    verify never registers a canonical (nothing unverified enters /.gcas)
# ============================================================================

def test_unverified_fill_never_publishes_canonical(srv):
    body = body_for("liar")
    claimed = hashlib.sha1(b"some-other-object-entirely").hexdigest()
    assert claimed != hashlib.sha1(body).hexdigest()

    # Origin lies: `body` planted under a CAS name whose hash it cannot match.
    d = srv.webroot / "cvmfs" / REPO_A / "data" / claimed[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / claimed[2:]).write_bytes(body)

    status, _, got = GET(srv, f"/cvmfs/{REPO_A}/data/{claimed[:2]}/{claimed[2:]}")
    assert not (status == 200 and got == body), \
        "hash-mismatched origin bytes were served as a clean 200"
    assert status >= 500, \
        f"expected the failed-verify fill to gateway-error, got {status}"

    canon = srv.cache / ".gcas" / claimed[:2] / claimed[2:]
    assert not canon.exists(), \
        "an UNVERIFIED fill registered a /.gcas canonical"
    key_a = srv.cache / "cvmfs" / REPO_A / "data" / claimed[:2] / claimed[2:]
    assert not key_a.exists(), \
        "a failed-verify fill still published a per-repo cache object"


# ============================================================================
# 5. security-negative: a damaged canonical is never adopted — mismatched
#    bytes must not collapse; the fresh verified per-repo copy wins
# ============================================================================

def test_damaged_canonical_never_adopted(srv):
    body = body_for("damaged")
    hx = hashlib.sha1(body).hexdigest()
    path_a = put_obj(srv, REPO_A, body)

    status, _, got = GET(srv, path_a)
    assert status == 200 and got == body, "repo-A fill failed"
    canon = srv.cache / ".gcas" / hx[:2] / hx[2:]
    assert canon.exists(), "canonical was not registered after verified fill"

    # Sever the link and plant a damaged (different-size) impostor canonical —
    # the repo-A key keeps its own good inode.
    canon.unlink()
    canon.write_bytes(b"damaged-canonical-impostor")

    path_b = put_obj(srv, REPO_B, body)
    status, _, got = GET(srv, path_b)
    assert status == 200 and got == body, \
        "repo-B must serve its own verified bytes despite the bad canonical"

    log = srv.error_log.read_text(errors="replace")
    assert "canonical size mismatch" in log and "dedup skipped" in log, \
        "the damaged canonical was not detected at adopt time"

    key_b = srv.cache / "cvmfs" / REPO_B / "data" / hx[:2] / hx[2:]
    assert key_b.exists() and key_b.read_bytes() == body, \
        "repo-B cache key missing or corrupt after the skipped dedup"
    assert key_b.stat().st_ino != canon.stat().st_ino, \
        "repo-B key was collapsed onto the damaged canonical inode"
    assert canon.read_bytes() == b"damaged-canonical-impostor", \
        "the impostor canonical was rewritten instead of skipped"
