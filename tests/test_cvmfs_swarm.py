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

def test_swarm_converges_and_cold_start_is_o1_origin(swarm):
    wait_converged(swarm.nodes, swarm.labels)

    body = body_owned_by(swarm.ring, 2, "o1_origin")
    path = put_obj(swarm.webroot, body)
    owner = swarm.by_label[swarm.ring[2]]
    requesters = [n for n in swarm.nodes if n is not owner][:2]
    for n in swarm.nodes:
        n.reset_log()

    # Two different non-owner nodes fetch the cold object: each pulls from
    # the rendezvous owner, the owner origin-fills ONCE and feeds both.
    for n in requesters:
        status, _, got = GET(n, path)
        assert status == 200 and got == body

    counts = {n.nginx_port: n.count_log(path) for n in swarm.nodes}
    assert sum(counts.values()) == 1, \
        f"cold start cost the swarm {counts} origin fetches (want exactly 1)"
    assert counts[owner.nginx_port] == 1, \
        "the origin fetch did not come from the rendezvous owner"


# ============================================================================
# 2. error: a member that stops answering is marked dead and routed around —
#    its keys keep serving via the origin instead of black-holing
# ============================================================================

def test_dead_member_detected_and_routed_around(swarm):
    block = swarm.block            # continue the module's allocation sequence
    ports = [block.base + 15, block.base + 16, block.base + 17]
    labels = [f"{HOST}:{p}" for p in ports]
    with srv_instance(block, webroot=swarm.webroot,
                      extra_directives=swarm_directives(ports[0], ports[1])) as a, \
         srv_instance(block, webroot=swarm.webroot,
                      extra_directives=swarm_directives(ports[1], ports[0])) as b:
        assert (a.nginx_port, b.nginx_port) == (ports[0], ports[1]), \
            "port-block allocation drifted"
        with srv_instance(block, webroot=swarm.webroot,
                          extra_directives=swarm_directives(ports[2], ports[0])) as c:
            assert c.nginx_port == ports[2], "port-block allocation drifted"
            wait_converged([a, b, c], labels)
        # c is gone. a must miss 3 probes and gossip the death to b.
        wait_until(lambda: roster_of(a).get(labels[2]) == "dead", 60,
                   "node a marking the stopped member dead")
        log = a.error_log.read_text(encoding="utf-8", errors="replace")
        assert "marked dead" in log

        # The OTHER survivor must log the death too — via direct probe miss
        # or via gossip adoption, whichever arm fired first. A silent flip
        # of the dead bit is an observability bug (the pre-fix flake).
        wait_until(lambda: roster_of(b).get(labels[2]) == "dead", 60,
                   "node b marking the stopped member dead")
        log_b = b.error_log.read_text(encoding="utf-8", errors="replace")
        assert "marked dead" in log_b, \
            "death adopted without a NOTICE on the second detector"

        # a key the DEAD member owned in the 3-ring still serves: the live
        # ring re-homes it (self or the surviving sibling — either way one
        # origin fill, no black hole).
        body = body_owned_by(sorted(labels), sorted(labels).index(labels[2]),
                             "dead_owner")
        path = put_obj(swarm.webroot, body)
        a.reset_log()
        b.reset_log()
        status, _, got = GET(a, path)
        assert status == 200 and got == body, "dead member black-holed its keys"
        assert a.count_log(path) + b.count_log(path) == 1, \
            "expected exactly one origin fill after the route-around"


# ============================================================================
# 3. security-neg: a tampered swarm sibling is never served, and DOES raise
#    signal=cvmfs_tamper naming the sibling (remote actor — jail-worthy)
# ============================================================================

def test_tampered_swarm_sibling_never_served_raises_tamper(swarm):
    wait_converged(swarm.nodes, swarm.labels)

    body = body_owned_by(swarm.ring, 3, "tamper")
    hx = hashlib.sha1(body).hexdigest()
    path = put_obj(swarm.webroot, body)
    owner = swarm.by_label[swarm.ring[3]]
    requester = next(n for n in swarm.nodes if n is not owner)

    # Warm the owner legitimately, then corrupt its cached blob in place
    # (same length, wrong hash) — the cinfo stays valid so the owner serves it.
    assert GET(owner, path)[0] == 200
    cached = cache_path(swarm, owner, hx)
    assert cached.exists(), "warmed object not in the owner's hot cache"
    cached.write_bytes(b"EVIL" + body[4:])
    requester.reset_log()

    status, _, got = GET(requester, path)
    assert status == 200 and got == body, "tampered sibling bytes leaked"
    assert requester.count_log(path) == 1, "expected exactly one origin refill"

    log = requester.error_log.read_text(encoding="utf-8", errors="replace")
    assert "mesh-sibling object failed verification" in log
    tamper = [ln for ln in log.splitlines()
              if "signal=cvmfs_tamper" in ln and path in ln]
    assert tamper, "sibling tamper did not raise signal=cvmfs_tamper"


# ============================================================================
# 4. config gate: swarm without a seed ring is refused at nginx -t
# ============================================================================

def test_swarm_without_cache_peers_refused(tmp_path):
    (tmp_path / "cache").mkdir()
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(f"""daemon off; error_log {logs}/e.log info; pid {tmp_path}/nginx.pid;
events {{ worker_connections 64; }}
http {{ server {{ listen {BIND_HOST}:1;
    location /cvmfs/ {{ brix_cvmfs on;
        brix_storage_backend "http://{HOST}:1";
        brix_cache_store posix:{tmp_path}/cache;
        brix_cvmfs_swarm on;
    }}
}} }}
""")
    r = subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode != 0, "expected nginx -t to refuse swarm without peers"
    assert "requires brix_cache_peers" in r.stderr + r.stdout


# ============================================================================
# 5. security-neg (gossip plane): a lying member slanders a LIVE member with
#    an unrefutable generation — the death is adopted VIA GOSSIP (with its
#    NOTICE), then the next direct probe answer resurrects the victim.
#    Direct proof of life must always beat second-hand gossip.
# ============================================================================

def test_gossip_slander_of_live_member_self_heals(swarm):
    block = swarm.block
    with FakeMember() as t, FakeMember() as f:
        t.set_roster(f"swarm-roster-v1\n{t.label} alive 1\n")   # honest
        f.set_roster(f"swarm-roster-v1\n{f.label} alive 1\n")   # honest, for now
        px = next_nginx_port(block)
        xlabel = f"{HOST}:{px}"
        with srv_instance(
                block, webroot=swarm.webroot,
                extra_directives=(
                    f"brix_cache_peers self={xlabel} {t.label} {f.label}; "
                    "brix_cvmfs_swarm on; brix_cvmfs_swarm_interval 1;")) as x:
            assert x.nginx_port == px, "port peek drifted from allocation"

            def xlog() -> str:
                return x.error_log.read_text(encoding="utf-8",
                                             errors="replace")

            wait_until(lambda: {t.label, f.label} <=
                       {l for l, st in roster_of(x).items() if st == "alive"},
                       45, "both scripted members alive in x's roster")

            # F turns hostile: slanders T at a generation T's honest roster
            # (gen 1) can never outbid — only direct contact can save it.
            f.set_roster(f"swarm-roster-v1\n{f.label} alive 1\n"
                         f"{t.label} dead 999999\n")
            wait_until(lambda: f"member {t.label} marked dead via gossip"
                       in xlog(), 60, "x adopting the slander via gossip")

            # One-shot liar: back to honest, else every F-probe re-kills T
            # (equal-gen dead-beats-alive) and the heal can never settle.
            f.set_roster(f"swarm-roster-v1\n{f.label} alive 1\n")
            wait_until(lambda: f"member {t.label} answered a probe - "
                       "back alive" in xlog(), 60,
                       "direct probe answer resurrecting the slandered member")
            wait_until(lambda: roster_of(x).get(t.label) == "alive", 30,
                       "x's roster settling on the victim being alive")

            # Data plane never black-holed: a self-owned key in the healed
            # 3-ring serves with exactly one origin fill.
            ring3 = sorted([xlabel, t.label, f.label])
            body = body_owned_by(ring3, ring3.index(xlabel), "slander_heal")
            path = put_obj(swarm.webroot, body)
            x.reset_log()
            status, _, got = GET(x, path)
            assert status == 200 and got == body
            assert x.count_log(path) == 1, \
                "expected exactly one origin fill for a self-owned key"


# ============================================================================
# 6. security-neg (gossip plane): garbage rosters are ignored whole, and a
#    slander of THIS node triggers the SWIM refutation — the node outbids the
#    lie with a higher generation instead of adopting its own death.
# ============================================================================

def test_self_slander_refuted_and_garbage_roster_ignored(swarm):
    block = swarm.block
    with FakeMember() as f:
        px = next_nginx_port(block)
        xlabel = f"{HOST}:{px}"
        # Phase 1 payload: not a roster at all (bad header) — the slander
        # line inside it must never be parsed.
        f.set_roster(f"this-is-not-a-roster\n{xlabel} dead 5\n")
        with srv_instance(
                block, webroot=swarm.webroot,
                extra_directives=(
                    f"brix_cache_peers self={xlabel} {f.label}; "
                    "brix_cvmfs_swarm on; brix_cvmfs_swarm_interval 1;")) as x:
            assert x.nginx_port == px, "port peek drifted from allocation"

            def xlog() -> str:
                return x.error_log.read_text(encoding="utf-8",
                                             errors="replace")

            def settled_probes(n: int) -> None:
                """Wait until F has answered n MORE probes — the bounded way
                to say 'x merged (or rejected) the current payload'."""
                seen = f.hits
                wait_until(lambda: f.hits >= seen + n, 60,
                           f"{n} further roster probes of the fake member")

            settled_probes(2)
            assert "refuting gossip" not in xlog(), \
                "a non-roster body must be rejected at the header check"
            view = roster_gens(x)
            assert view.get(xlabel, ("", 0))[0] == "alive", \
                "node adopted a death from a garbage payload"

            # Phase 2: valid header, garbage lines (missing fields, non-
            # numeric gen, unknown state) — each skipped, none merged.
            f.set_roster("swarm-roster-v1\n"
                         "garbage\n"
                         f"{xlabel} dead notanumber\n"
                         f"{xlabel} zombie 7\n")
            settled_probes(2)
            assert "refuting gossip" not in xlog()
            assert set(roster_gens(x)) == {xlabel, f.label}, \
                "garbage roster lines leaked into the membership"

            # Phase 3: a real self-slander — the node must REFUTE (bump its
            # generation past the lie), never adopt its own death. The boot
            # generation is wall-clock seconds, so the lie must outbid the
            # node's CURRENT advertised generation (a lower gen is already
            # implicitly refuted stale gossip and stays silent).
            self_gen_now = roster_gens(x)[xlabel][1]
            lie_gen = self_gen_now + 1000
            f.set_roster(f"swarm-roster-v1\n{f.label} alive 1\n"
                         f"{xlabel} dead {lie_gen}\n")
            wait_until(lambda: "refuting gossip that says this node is dead"
                       in xlog(), 60, "the SWIM refutation NOTICE")

            def self_refuted() -> bool:
                st, gen = roster_gens(x).get(xlabel, ("", 0))
                return st == "alive" and gen > lie_gen

            wait_until(self_refuted, 30,
                       "self alive at a generation outbidding the slander")

            # Still serving: a self-owned key in the 2-ring fills once.
            ring2 = sorted([xlabel, f.label])
            body = body_owned_by(ring2, ring2.index(xlabel), "refute_alive")
            path = put_obj(swarm.webroot, body)
            x.reset_log()
            status, _, got = GET(x, path)
            assert status == 200 and got == body
            assert x.count_log(path) == 1


# ============================================================================
# 7. security-neg (introduction plane): malformed ?from= introductions are
#    ignored — none of them may add a member, kill the endpoint, or crash
#    the node. (A WELL-formed introduction adds the caller by design — every
#    payload here must fail the parse, not the intent.)
# ============================================================================

def test_malformed_introduction_never_pollutes_membership(swarm):
    wait_converged(swarm.nodes, swarm.labels)
    node = swarm.nodes[0]
    known = set(swarm.labels)

    bogus = f"{HOST}:1"                    # never bound; parse must not even get here
    queries = [
        "x=1",                              # <= 5 bytes: length guard
        f"from={bogus}",                    # missing &gen=
        f"from={bogus}&gen=oops",           # non-numeric generation
        "from=&gen=7",                      # empty label fails the scan
        "from=" + "A" * 400 + "&gen=7",     # overlong label breaks the scan
        "pad=" + "A" * 7000 + f"&from={bogus}&gen=7",  # from= not at start
    ]
    for q in queries:
        status, _, body = GET(node, f"{ROSTER}?{q}")
        assert status == 200, f"roster endpoint died on query {q[:40]!r}"
        assert body.decode(errors="replace").startswith("swarm-roster-v1"), \
            "roster body must still be served after a malformed introduction"

    view = roster_of(node)
    assert set(view) == known, \
        f"malformed introduction polluted the membership: {set(view) - known}"
    assert all(st == "alive" for st in view.values())

    # And the data plane is untouched.
    body = body_owned_by(swarm.ring, 0, "intro_immune")
    path = put_obj(swarm.webroot, body)
    status, _, got = GET(node, path)
    assert status == 200 and got == body
