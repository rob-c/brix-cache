# tests/test_cvmfs_swarm.py — Phase-87 G12: P2P swarm cold-start.
#
# brix_cvmfs_swarm extends the phase-85 F8 static sibling mesh to dynamic
# membership: every node serves its member view at /cvmfs/.swarm/roster,
# periodically pulls a member's roster (push-pull — the query string
# introduces the prober), merges views, and republishes the live rendezvous
# ring into the cache fill spine. The data plane stays F8: one verified fetch
# from the ring owner with origin fallback, so a lying sibling still raises
# signal=cvmfs_tamper naming that sibling.
#
# The converged ring is the ALIVE labels sorted lexicographically — mirrored
# here (sorted() + the same FNV-1a64 HRW as test_cvmfs_peer_mesh). Change
# swarm.c cvmfs_swarm_ring_publish and this file together or not at all.
#
# Port block: srv_verify (shared sequentially with test_cvmfs_peer_mesh —
# module fixtures close before the other file's run in a sweep; suites never
# run concurrently in-session). This module uses ALL 10 mock and ALL 10 nginx
# ports: swarm fixture = mocks base+0..4 / nginx base+10..14, dead-member
# test = mocks base+5..7 / nginx base+15..17, slander test = mock base+8 /
# nginx base+18, refutation test = mock base+9 / nginx base+19. The scripted
# FakeMember listeners are OS-ephemeral on purpose (see the class docstring).
import contextlib
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance
from cmdscripts.live_common import (
    inject_nginx_load_modules,
    inject_nginx_runtime_paths,
)
from settings import BIND_HOST, HOST

REPO = "test.cern.ch"
ROSTER = "/cvmfs/.swarm/roster"

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


# ---- local helpers (file-local by mandate: shared infra is frozen) ---------

def GET(s, path):
    return request(HOST, s.nginx_port, "GET", path)


def roster_of(s) -> dict:
    """{label: state} from a node's roster endpoint ({} while unavailable)."""
    try:
        status, _, body = GET(s, ROSTER)
    except OSError:
        return {}
    if status != 200:
        return {}
    view = {}
    for line in body.decode(errors="replace").splitlines()[1:]:
        parts = line.split()
        if len(parts) == 3:
            view[parts[0]] = parts[1]
    return view


def wait_until(pred, timeout=45, what="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {what}")


def swarm_directives(self_port: int, seed_port: int) -> str:
    return (f"brix_cache_peers self={HOST}:{self_port} {HOST}:{seed_port}; "
            f"brix_cvmfs_swarm on; brix_cvmfs_swarm_interval 1;")


def roster_gens(s) -> dict:
    """{label: (state, gen)} from a node's roster ({} while unavailable)."""
    try:
        status, _, body = GET(s, ROSTER)
    except OSError:
        return {}
    if status != 200:
        return {}
    view = {}
    for line in body.decode(errors="replace").splitlines()[1:]:
        parts = line.split()
        if len(parts) == 3 and parts[2].isdigit():
            view[parts[0]] = (parts[1], int(parts[2]))
    return view


def next_nginx_port(block: PortBlock) -> int:
    """Peek the port the block's NEXT srv_instance will listen on: the
    `brix_cache_peers self=` label must name it BEFORE srv_instance
    allocates it, whatever subset of this file ran first."""
    return block.base + 10 + block._nginx


class FakeMember:
    """A scripted swarm member: a real HTTP listener whose roster body is
    whatever the test currently says (honest or hostile) — the adversary for
    the gossip-plane security legs. Binds an OS-ephemeral port on BIND_HOST:
    it is a transient in-test mock with no fleet/port-registry footprint,
    and this file's two PortBlock sub-blocks are fully allocated."""

    def __init__(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self):
                body = outer.body
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                outer.hits += 1

            def log_message(self, *args):  # keep pytest output clean
                pass

        self.hits = 0
        self.body = b"swarm-roster-v1\n"
        self.httpd = ThreadingHTTPServer((BIND_HOST, 0), Handler)
        self.port = self.httpd.server_address[1]
        self.label = f"{HOST}:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)

    def set_roster(self, text: str) -> None:
        self.body = text.encode()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False


def put_obj(webroot: Path, body: bytes) -> str:
    hx = hashlib.sha1(body).hexdigest()
    d = webroot / "cvmfs" / REPO / "data" / hx[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / hx[2:]).write_bytes(body)
    return f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}"


def body_owned_by(labels: list, owner: int, tag: str, n=6000) -> bytes:
    """Synthesize a body whose CAS key's rendezvous owner is ring index
    `owner` in the (sorted) `labels` ring."""
    for i in range(4096):
        seed = hashlib.sha256(f"swarm:{tag}:{i}".encode()).digest()
        body = (seed * (n // len(seed) + 1))[:n]
        hx = hashlib.sha1(body).hexdigest()
        key = f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}"
        if ring_owner(labels, key) == owner:
            return body
    raise AssertionError("no candidate body landed on the wanted ring member")


# ---- fixtures --------------------------------------------------------------

class Swarm:
    """Five live nodes sharing one origin webroot. Node 0 seeds from node 1;
    nodes 1-4 each seed from node 0 — full membership must be LEARNED via
    gossip (nobody is configured with more than one sibling)."""


@pytest.fixture(scope="module")
def swarm():
    root = Path(tempfile.mkdtemp(prefix="cvmfs_swarm_webroot."))
    (root / "cvmfs" / REPO / "data").mkdir(parents=True)
    block = PortBlock("srv_verify")
    ports = [block.base + 10 + i for i in range(5)]
    with contextlib.ExitStack() as stack:
        nodes = []
        for i, port in enumerate(ports):
            seed = ports[1] if i == 0 else ports[0]
            s = stack.enter_context(srv_instance(
                block, webroot=root,
                extra_directives=swarm_directives(port, seed)))
            assert s.nginx_port == port, "port-block allocation drifted"
            nodes.append(s)

        sw = Swarm()
        sw.webroot, sw.block, sw.nodes = root, block, nodes
        sw.labels = [f"{HOST}:{p}" for p in ports]
        sw.ring = sorted(sw.labels)          # the converged published ring
        sw.by_label = dict(zip(sw.labels, nodes))

        # Layout probe on node 0: fill one object and learn where the hot
        # cache stores it, so the tamper test can corrupt a cached blob.
        probe = b"swarm layout probe\n" * 64
        hx = hashlib.sha1(probe).hexdigest()
        path = put_obj(root, probe)
        status, _, got = GET(nodes[0], path)
        assert status == 200 and got == probe, "layout probe fill failed"
        found = [p for p in nodes[0].cache.rglob("*")
                 if p.is_file() and hx[2:] in p.name]
        assert len(found) == 1, f"probe object not found uniquely: {found}"
        sw.probe_hex = hx
        sw.rel_template = str(found[0].relative_to(nodes[0].cache))
        yield sw
    shutil.rmtree(root, ignore_errors=True)


def cache_path(sw, node, hx):
    rel = sw.rel_template.replace(
        f"{sw.probe_hex[:2]}/{sw.probe_hex[2:]}", f"{hx[:2]}/{hx[2:]}")
    assert rel != sw.rel_template, "hash substitution failed on the template"
    return node.cache / rel


def wait_converged(nodes, labels, timeout=45):
    want = set(labels)

    def converged():
        return all(
            {l for l, st in roster_of(n).items() if st == "alive"} >= want
            for n in nodes)

    wait_until(converged, timeout,
               f"all {len(nodes)} rosters listing {len(want)} alive members")


# ============================================================================
# 1. success: gossip converges from single-sibling seeds, and a cold object
#    costs the WHOLE swarm exactly one origin fetch (the G12 property)
# ============================================================================
