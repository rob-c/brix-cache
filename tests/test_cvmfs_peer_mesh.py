# tests/test_cvmfs_peer_mesh.py — Phase-85 F8: sibling-mesh peer CAS fetch.
#
# brix_cache_peers declares a rendezvous ring of cache nodes: a miss whose
# highest-random-weight owner is a NON-self member attempts one verified fill
# from that sibling before the origin (cold tier, if any, is still consulted
# first). Any peer failure silently falls back to the origin. A tampered
# sibling blob must never publish (the peer fetch runs the same cvmfs-cas
# verify gate as an origin fill) and — unlike a corrupt LOCAL cold copy — DOES
# raise signal=cvmfs_tamper naming the sibling: the actor is a remote
# authority, exactly what the fail2ban tamper jail exists for.
#
# The rendezvous scheme mirrored here bit-for-bit (sd_cache_fill.c
# sd_cache_hrw_fnv1a64): FNV-1a 64 over "<label>\n<key>", labels are the
# configured "host:port" tokens in declaration order, owner = argmax, ties to
# the lower index. Change both sides together or not at all.
#
# Port block: srv_verify (shared sequentially — module fixtures close before
# the other file's run in a sweep; suites never run concurrently in-session).
import contextlib
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance

REPO = "test.cern.ch"

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")


# ---- rendezvous mirror (MUST match sd_cache_hrw_fnv1a64) -------------------

def _fnv1a64(label: str, key: str) -> int:
    h = 14695981039346656037
    for b in label.encode() + b"\n" + key.encode():
        h = ((h ^ b) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def ring_owner(labels: list, key: str) -> int:
    best, owner = -1, 0
    for i, label in enumerate(labels):
        w = _fnv1a64(label, key)
        if w > best:
            best, owner = w, i
    return owner


# ---- fixtures --------------------------------------------------------------

class Mesh:
    """Two live instances sharing one origin webroot: `main` carries the
    brix_cache_peers ring (self=main, sibling=peer); `peer` is a plain cache
    node. Each has its own mock, so per-node origin traffic is countable."""


@pytest.fixture(scope="module")
def mesh():
    root = Path(tempfile.mkdtemp(prefix="cvmfs_mesh_webroot."))
    (root / "cvmfs" / REPO / "data").mkdir(parents=True)
    block = PortBlock("srv_verify")
    # PortBlock allocation is sequential and deterministic: the first
    # srv_instance (peer) takes nginx port base+10, the second (main) base+11
    # — so main's own ring slot is known before its config is written.
    peer_port, main_port = block.base + 10, block.base + 11
    with contextlib.ExitStack() as stack:
        peer = stack.enter_context(srv_instance(block, webroot=root))
        assert peer.nginx_port == peer_port, "port-block allocation drifted"
        main = stack.enter_context(srv_instance(
            block, webroot=root,
            extra_directives=(f"brix_cache_peers self=127.0.0.1:{main_port} "
                              f"127.0.0.1:{peer_port};")))
        assert main.nginx_port == main_port, "port-block allocation drifted"

        m = Mesh()
        m.webroot, m.main, m.peer, m.block = root, main, peer, block
        m.labels = [f"127.0.0.1:{main_port}", f"127.0.0.1:{peer_port}"]

        # Layout probe on the PEER: fill one object and learn where its hot
        # cache stores it, so the tamper test can corrupt a cached blob.
        probe = b"peer-mesh layout probe\n" * 64
        hx = hashlib.sha1(probe).hexdigest()
        path = put_obj(m, probe)
        status, _, got = GET(peer, path)
        assert status == 200 and got == probe, "layout probe fill failed"
        found = [p for p in peer.cache.rglob("*")
                 if p.is_file() and hx[2:] in p.name]
        assert len(found) == 1, f"probe object not found uniquely: {found}"
        m.probe_hex = hx
        m.rel_template = str(found[0].relative_to(peer.cache))
        yield m
    shutil.rmtree(root, ignore_errors=True)


# ---- local helpers (file-local by mandate: shared infra is frozen) ---------

def GET(s, path):
    return request("127.0.0.1", s.nginx_port, "GET", path)


def put_obj(m, body):
    """Drop a CAS object into the shared origin webroot; returns its URL path."""
    hx = hashlib.sha1(body).hexdigest()
    d = m.webroot / "cvmfs" / REPO / "data" / hx[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / hx[2:]).write_bytes(body)
    return f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}"


def body_owned_by(m, owner: int, tag: str, n=6000) -> bytes:
    """Synthesize a body whose CAS key's rendezvous owner is ring index `owner`."""
    for i in range(4096):
        seed = hashlib.sha256(f"peer_mesh:{tag}:{i}".encode()).digest()
        body = (seed * (n // len(seed) + 1))[:n]
        hx = hashlib.sha1(body).hexdigest()
        key = f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}"
        if ring_owner(m.labels, key) == owner:
            return body
    raise AssertionError("no candidate body landed on the wanted ring member")


def peer_cache_path(m, hx):
    rel = m.rel_template.replace(
        f"{m.probe_hex[:2]}/{m.probe_hex[2:]}", f"{hx[:2]}/{hx[2:]}")
    assert rel != m.rel_template, "hash substitution failed on the template"
    return m.peer.cache / rel


# ============================================================================
# 1. sibling hit: a peer-owned key fills from the warmed sibling — zero
#    origin data traffic on the requesting node
# ============================================================================

def test_sibling_hit_avoids_origin(mesh):
    body = body_owned_by(mesh, 1, "sibling_hit")
    hx = hashlib.sha1(body).hexdigest()
    path = put_obj(mesh, body)
    # Warm the sibling through its own front door (a normal origin fill there).
    status, _, got = GET(mesh.peer, path)
    assert status == 200 and got == body
    mesh.main.reset_log()

    status, _, got = GET(mesh.main, path)
    assert status == 200 and got == body
    assert mesh.main.count_log(path) == 0, \
        "peer-owned key still pulled origin data on the requesting node"
    log = mesh.main.error_log.read_text(encoding="utf-8", errors="replace")
    assert f'filled "{path}" from mesh sibling {mesh.labels[1]}' in log
    # and it is a normal local cache hit afterwards
    assert GET(mesh.main, path)[2] == body
    assert mesh.main.count_log(path) == 0
    assert peer_cache_path(mesh, hx).exists(), \
        "sibling fetch must COPY (the peer keeps its replica, unlike cold move)"


# ============================================================================
# 2. self-owned key: the ring never self-fetches — plain origin fill
# ============================================================================

def test_self_owned_key_fills_from_origin(mesh):
    body = body_owned_by(mesh, 0, "self_owned")
    path = put_obj(mesh, body)
    mesh.main.reset_log()
    mesh.peer.reset_log()

    status, _, got = GET(mesh.main, path)
    assert status == 200 and got == body
    assert mesh.main.count_log(path) == 1, "self-owned key skipped the origin"
    assert mesh.peer.count_log(path) == 0, "self-owned key contacted a sibling"


# ============================================================================
# 3. security-neg: a tampered sibling blob is never served, and DOES raise
#    signal=cvmfs_tamper naming the sibling (remote actor — jail-worthy)
# ============================================================================

def test_tampered_sibling_never_served_raises_tamper(mesh):
    body = body_owned_by(mesh, 1, "tamper")
    hx = hashlib.sha1(body).hexdigest()
    path = put_obj(mesh, body)
    # Warm the sibling legitimately, then corrupt its cached blob in place
    # (same length, wrong hash) — the cinfo stays valid so the peer serves it.
    assert GET(mesh.peer, path)[0] == 200
    cached = peer_cache_path(mesh, hx)
    assert cached.exists(), "warmed object not in the peer's hot cache"
    cached.write_bytes(b"EVIL" + body[4:])
    mesh.main.reset_log()

    status, _, got = GET(mesh.main, path)
    assert status == 200 and got == body, "tampered sibling bytes leaked"
    assert mesh.main.count_log(path) == 1, "expected exactly one origin refill"

    log = mesh.main.error_log.read_text(encoding="utf-8", errors="replace")
    assert "mesh-sibling object failed verification" in log
    tamper = [ln for ln in log.splitlines()
              if "signal=cvmfs_tamper" in ln and path in ln]
    assert tamper, "sibling tamper did not raise signal=cvmfs_tamper"


# ============================================================================
# 4. resilience: the owning sibling is down — silent origin fallback
# ============================================================================

def test_dead_sibling_falls_back_to_origin(mesh):
    block = mesh.block             # continue the module's allocation sequence
    dead = block.base + 9          # inside this session's tile, never listened
    with srv_instance(block, webroot=mesh.webroot,
                      extra_directives=("brix_cache_peers "
                                        "self=127.0.0.1:{0} 127.0.0.1:{1};"
                                        .format(block.base + 12, dead))) as solo:
        labels = [f"127.0.0.1:{solo.nginx_port}", f"127.0.0.1:{dead}"]
        assert solo.nginx_port == block.base + 12, "port-block allocation drifted"
        # a key owned by the dead member
        for i in range(4096):
            seed = hashlib.sha256(f"peer_mesh:dead:{i}".encode()).digest()
            body = (seed * 24)[:6000]
            hx = hashlib.sha1(body).hexdigest()
            key = f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}"
            if ring_owner(labels, key) == 1:
                break
        path = put_obj(mesh, body)
        solo.reset_log()

        status, _, got = GET(solo, path)
        assert status == 200 and got == body, "dead sibling broke the fill"
        assert solo.count_log(path) == 1, "expected exactly one origin fill"


# ============================================================================
# 5. config gates: refused at nginx -t
# ============================================================================

def _nginx_t(tmp_path, directives: str) -> str:
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(f"""daemon off; error_log {logs}/e.log info; pid {tmp_path}/nginx.pid;
events {{ worker_connections 64; }}
http {{ server {{ listen 127.0.0.1:1;
    location /cvmfs/ {{ brix_cvmfs on;
        brix_storage_backend "http://127.0.0.1:1";
        {directives}
    }}
}} }}
""")
    r = subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode != 0, f"expected nginx -t to refuse: {directives}"
    return r.stderr + r.stdout


def test_peers_without_cache_store_refused(tmp_path):
    out = _nginx_t(tmp_path,
                   "brix_cache_peers self=127.0.0.1:1 127.0.0.1:2;")
    assert "requires brix_cache_store" in out


def test_peers_without_self_refused(tmp_path):
    (tmp_path / "cache").mkdir()
    out = _nginx_t(tmp_path,
                   f"brix_cache_store posix:{tmp_path}/cache;\n"
                   "        brix_cache_peers 127.0.0.1:1 127.0.0.1:2;")
    assert "self=host:port" in out


def test_single_member_ring_refused(tmp_path):
    (tmp_path / "cache").mkdir()
    out = _nginx_t(tmp_path,
                   f"brix_cache_store posix:{tmp_path}/cache;\n"
                   "        brix_cache_peers self=127.0.0.1:1;")
    assert "at least 2 ring members" in out
