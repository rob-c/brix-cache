"""
tests/test_audit15o_cms_windows.py — the CMS timing plane
(docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md, tranche 14).

WHY THIS FILE EXISTS
--------------------
Tranche 13 closed the last block-granularity pair the audit's §Method could
see, so tranche 14 sharpens the instrument instead.  Step 2 of the method
counted a directive as COVERED when its name appeared anywhere in the test
corpus.  That is a search, not a claim: a directive that merely sits in a
template some test launches is "covered" by `nginx -t` proving it parses and
merges, while nothing whatever proves what it DOES.  Thirteen directives with
live runtime readers turned out to be parse-only under that reading.  This
file takes four of them:

    brix_cms_locate_timeout · brix_cms_state_fanout
    brix_cms_fanout_window  · brix_metadata_only

THE MEASUREMENT PROBLEM, AND THE ANSWER
---------------------------------------
Three of the four have no header, no metric and no log line of their own —
their only observable is elapsed time.  A single server cannot prove a
duration: "the locate answered after 800ms" is equally consistent with the
directive and with a loaded host, and this suite runs beside another one.

So the config ships TWO managers identical in every respect except these
three values, and every timing assertion is about the DIFFERENCE between
them.  A host slow enough to stretch the fast manager stretches the slow one
too; the gap survives.  Absolute bounds are kept deliberately loose and only
ever assert the side that cannot be produced by scheduling noise (a park
cannot finish EARLY).

                          {PORT}      {SLOW_PORT}    merge default
   brix_cms_locate_timeout   800ms        3s            5000ms
   brix_cms_fanout_window    300ms        2500ms         500ms
   brix_cms_state_fanout     2            6                  8

brix_cms_state_fanout needs no clock at all: the probes are frames, and the
nodes that receive them are Python, so the cap is simply counted.

WHAT THE BLOCK ESTABLISHES
--------------------------
  * the kYR_state probe fan-out is capped by brix_cms_state_fanout and
    filtered by export coverage — and the filter is not the cap in disguise
    (the slow manager's cap of 6 exceeds every node registered, so a node
    that is skipped there was skipped on its exports);
  * the cap is a per-REQUEST budget, not a per-path one: under the shipped
    default (brix_cms_emptylife 0, so an expired window remembers nothing) a
    retry of the same path spends it again.  The opt-in negative cache that
    changes this is §2.6 and belongs to test_cms_parity_wave.py;
  * the CMS-parent locate leg parks the client for exactly
    brix_cms_locate_timeout and then answers kXR_wait 5;
  * brix_cms_fanout_window is a DEADLINE, not a delay: silent nodes make the
    client wait the whole of it, and nodes that all answer settle it early;
  * brix_metadata_only advertises kXR_attrMeta and refuses kXR_open with
    kXR_Unsupported while the namespace keeps answering.

DEFECT CANDIDATE #49 — the CMS parent-locate forward is write-only
------------------------------------------------------------------
ngx_brix_cms_send_locate() (src/net/cms/send.c:431) emits a CMS_RR_LOCATE (=2)
frame to the configured parent.  The receiving side's opcode table,
cms_srv_frame_routes[] (src/net/cms/server_recv_frame.c:288-306), has no row
for CMS_RR_LOCATE.  The frame therefore lands in cms_srv_frame_unknown(),
which looks the opcode up in the manager routing table, recognises it BY NAME,
and drops it with an ngx_log_debug2 line — invisible on any build without
--with-debug.

The consequence is not an error.  It is a livelock: every registry-missing
locate on a server configured with brix_cms_manager parks the client for the
full brix_cms_locate_timeout, answers kXR_wait 5, and caches nothing, so the
client's retry does exactly the same thing forever.  A hierarchy never
resolves upward, and on a stock build it never says so.

test_a_parent_locate_never_converges_however_often_the_client_retries pins the
observable consequence.  Should the routing row be added, that test is the one
that fails first, and DEFECT49 below says what to do with it.

Run:
    PYTHONPATH=tests pytest tests/test_audit15o_cms_windows.py -v
"""

import os
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import pytest

from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN, SERVER_HOST
from _test_cms_wire_pup_conformance_helpers import (
    _build_frame,
    _minimal_login_payload,
)
from test_cms_locate_have import (
    _locate,
    _recv_exact,
    _recv_response,
    _xrd_session,
)

def _expression_1(self, hdr):
    return (
        self._closing or len(hdr) < 8
    )

def _expression_2(dlen, self):
    return (
        self._recv_exact(dlen) if dlen else b""
    )

def _expression_3(code, self):
    return (
        code in (CMS_RR_RM, CMS_RR_RMDIR) \
                                and self.error_reply is not None
    )


def _phase_reader_1(self, code, streamid, payload):
    with self._lock:
        self.frames.append((time.monotonic(), code, streamid,
                            payload))


pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15o-cmswindows")]

H = SERVER_HOST
REPO = Path(__file__).resolve().parents[1]

# --- CMS wire (src/net/cms/cms_internal.h) --------------------------------- #
CMS_RR_LOGIN = 0
CMS_RSP_ERROR = 1
CMS_RR_RM = 8
CMS_RR_RMDIR = 9
CMS_RR_PING = 17
CMS_RR_PONG = 18
CMS_RR_STATE = 20

# --- kXR wire (src/protocols/root/protocol/opcodes.h, flags.h) ------------- #
kXR_ok = 0
kXR_error = 4003
kXR_wait = 4005

kXR_open = 3010
kXR_stat = 3017

kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_new = 0x0008

kXR_NotFound = 3011
kXR_Unsupported = 3013

kXR_isManager = 0x00000002
kXR_attrMeta = 0x00000100

# --- what the config says (nginx_audit15o_cmswindows.conf) ----------------- #
FAST_LOCATE_TIMEOUT = 0.8
SLOW_LOCATE_TIMEOUT = 3.0
FAST_FANOUT_WINDOW = 0.3
SLOW_FANOUT_WINDOW = 2.5
LOCATE_WINDOW = 0.6          # identical on both managers
FAST_STATE_FANOUT = 2
SLOW_STATE_FANOUT = 6        # deliberately > the number of nodes registered

# The gap the two managers must show.  Half the configured difference, so a
# host that stretches both by the same factor still passes and a host that
# stretches only one is caught.
LOCATE_GAP = (SLOW_LOCATE_TIMEOUT - FAST_LOCATE_TIMEOUT) / 2
FANOUT_GAP = (SLOW_FANOUT_WINDOW - FAST_FANOUT_WINDOW) / 2

# Data-node ports as ADVERTISED in the CMS login.  Nothing binds them: they
# are the registry key (host, dPort) and nothing else, which is why they are
# constants here rather than ladder allocations — the same shape as
# test_cms_fanout_rm.py's PORT_NODE_A/B.  Held stable across every test in the
# file so a registry row that outlives its node is re-registered under the
# same key by the next test rather than lingering as a phantom holder.
FAN_DPORTS = (43341, 43342, 43343, 43344)
OTHER_DPORT = 43345

SEED = b"audit15o metadata-only payload\n"

DEFECT49 = (
    "DEFECT CANDIDATE #49 has been FIXED: the CMS parent now answers a "
    "forwarded kYR_locate. Replace this livelock pin with the convergence "
    "test it was standing in for — the parent's answer should reach the "
    "parked client as a kXR_redirect well inside brix_cms_locate_timeout.")


# --------------------------------------------------------------------------- #
# The block.                                                                   #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def cms(lifecycle, tmp_path):
    """A fresh instance per test.

    Deliberately not shared: the SHM location cache and the server registry
    are per-instance, and §2.6 means a probed path is a single-use resource.
    A clean instance is cheaper than reasoning about which cache entry a
    previous test left behind.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    (data / "meta").mkdir(parents=True)
    (data / "meta" / "seed.txt").write_bytes(SEED)
    (data / "fan").mkdir()

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15o-cmswindows",
        template="nginx_audit15o_cmswindows.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        reason="audit-15o: the CMS timing plane — locate timeout, probe cap, "
               "fan-out window and the metadata-only role"))

    # Both managers register themselves with the CMS face on a 1s heartbeat.
    # Until that uplink exists ngx_brix_cms_pick_ctx() has nothing to send to
    # and locate_try_cms_parent() declines instead of parking, which would
    # turn every timeout assertion into a NotFound.
    _await_registered(endpoint,
                      (endpoint.port, endpoint.extra_ports["SLOW_PORT"]),
                      what="the two managers' CMS uplinks")
    return endpoint


class _Node:
    """A Python data node on the real CMS wire that timestamps what it is
    sent.

    It exists because the three windows under test are only visible from the
    node side: the manager's probe fan-out is a set of frames (countable), and
    its fan-out reply window is a deadline the node controls by choosing to
    answer or to stay silent.  kYR_ping is answered so a node stays live
    across a slow test — the server's post-login idle watchdog is re-armed by
    inbound frames, not by its own pings.
    """

    def __init__(self, cms_port, dport, paths=b"r /fan"):
        self.dport = dport
        self.frames = []            # [(monotonic, code, streamid, payload)]
        self.error_reply = None     # None, or (ecode, text) answered to RM
        self._lock = threading.Lock()
        self._closing = False
        self.sock = socket.create_connection((H, cms_port), timeout=8)
        self.sock.settimeout(0.25)
        self.sock.sendall(_build_frame(0, CMS_RR_LOGIN, 0,
                                       _minimal_login_payload(dport, paths)))
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n and not self._closing:
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("manager closed the CMS connection")
            buf += chunk
        return buf

    def _reader(self):
        try:
            while not self._closing:
                hdr = self._recv_exact(8)
                if _expression_1(self, hdr):
                    return
                streamid, code, _mod, dlen = struct.unpack(">IBBH", hdr)
                payload = _expression_2(dlen, self)
                _phase_reader_1(self, code, streamid, payload)
                if code == CMS_RR_PING:
                    self.sock.sendall(_build_frame(streamid, CMS_RR_PONG, 0))
                elif _expression_3(code, self):
                    ecode, text = self.error_reply
                    self.sock.sendall(_build_frame(
                        streamid, CMS_RSP_ERROR, 0,
                        struct.pack(">I", ecode) + text + b"\x00"))
        except (OSError, ConnectionError):
            return

    def of(self, code, path=None):
        """Every frame of `code` (optionally naming `path`), oldest first."""
        want = path.encode() if path is not None else None
        with self._lock:
            return [f for f in self.frames
                    if f[1] == code and (want is None or want in f[3])]

    def close(self):
        self._closing = True
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


# --------------------------------------------------------------------------- #
# Helpers.                                                                     #
# --------------------------------------------------------------------------- #

def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        return (Path(endpoint.prefix) / "logs" / "error.log").read_text(
            errors="replace")
    except FileNotFoundError:
        return ""


def _registrations(endpoint, dport):
    """How many times the CMS face has logged a registration for `dport`.

    Matched on the advertised port and the field that follows it rather than
    on a host literal: the login's registry key is (peer address, dPort), and
    the peer address the manager sees is not necessarily the name the test
    dialled.
    """
    return _errlog(endpoint).count(f":{dport} role=")


def _await_registered(endpoint, dports, what, baseline=None, timeout=25):
    """Block until every port in `dports` has a fresh registration line."""
    floor = baseline if baseline is not None else {p: 0 for p in dports}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(_registrations(endpoint, p) > floor[p] for p in dports):
            return
        time.sleep(0.1)
    pytest.fail(f"{what} never registered with the CMS face:\n"
                + _errlog(endpoint)[-3000:])


@pytest.fixture()
def nodes(cms):
    """Five registered data nodes: four exporting /fan and one exporting only
    /other.

    The odd one out is what separates "skipped by the cap" from "skipped by
    brix_srv_paths_cover" — the slow manager's cap of 6 can never run out on
    five nodes, so its absence from a /fan probe is the export filter and
    nothing else.
    """
    ports = FAN_DPORTS + (OTHER_DPORT,)
    baseline = {p: _registrations(cms, p) for p in ports}
    made = [_Node(cms.extra_ports["CMS_PORT"], p) for p in FAN_DPORTS]
    made.append(_Node(cms.extra_ports["CMS_PORT"], OTHER_DPORT,
                      paths=b"r /other"))

    try:
        _await_registered(cms, ports, what="the five data nodes",
                          baseline=baseline)
        yield made[:len(FAN_DPORTS)], made[-1]
    finally:
        for node in made:
            node.close()


def _timed_locate(port, path):
    """(elapsed, status, body) for one kXR_locate on a fresh session.

    The session is opened and the handshake completed BEFORE the clock
    starts, so what is timed is the locate leg chain and nothing else.
    """
    sock = _xrd_session(port)
    sock.settimeout(20)
    try:
        started = time.monotonic()
        status, body = _locate(sock, path)
        return time.monotonic() - started, status, body
    finally:
        sock.close()


def _rm(sock, path):
    """kXR_rm: 16 reserved bytes, then the path as the body."""
    payload = path.encode()
    sock.sendall(struct.pack(">BBH16sI", 0, 1, 3014,
                             b"\x00" * 16, len(payload)) + payload)
    return _recv_response(sock)


def _timed_rm(port, path):
    """(elapsed, status, body) for one kXR_rm on a fresh session."""
    sock = _xrd_session(port)
    sock.settimeout(20)
    try:
        started = time.monotonic()
        status, body = _rm(sock, path)
        return time.monotonic() - started, status, body
    finally:
        sock.close()


def _wait_seconds(body):
    """The retry interval out of a kXR_wait body (control.c:112)."""
    return struct.unpack(">I", body[:4])[0]


def _protocol_flags(port):
    """The capability flags word of the kXR_protocol reply (protocol.c)."""
    sock = socket.create_connection((H, port), timeout=8)
    sock.settimeout(8)
    try:
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        sock.sendall(struct.pack(">BB H I BB 10x I",
                                 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
        _recv_exact(sock, 16)                 # handshake response
        status, body = _recv_response(sock)
        assert status == kXR_ok, f"kXR_protocol failed: {status} {body!r}"
        assert len(body) >= 8, f"short ServerProtocolBody: {body!r}"
        _pval, flags = struct.unpack("!Ii", body[:8])
        return flags & 0xFFFFFFFF
    finally:
        sock.close()


def _open(sock, path, options):
    payload = path.encode()
    body = struct.pack(">HH12s", 0o644, options, b"\x00" * 12)
    sock.sendall(struct.pack(">BBH", 0, 1, kXR_open) + body
                 + struct.pack(">I", len(payload)) + payload)
    return _recv_response(sock)


def _stat(sock, path):
    payload = path.encode()
    sock.sendall(struct.pack(">BBH16sI", 0, 1, kXR_stat,
                             b"\x00" * 16, len(payload)) + payload)
    return _recv_response(sock)


def _error_text(body):
    """The message half of a kXR_error body: [errno:4][text NUL-terminated]."""
    return body[4:].split(b"\x00", 1)[0].decode(errors="replace")


def _error_code(body):
    return struct.unpack(">I", body[:4])[0]


def _nginx_t(conf_text, tmp_path, name):
    """Parse-check a config that exists ONLY under tmp_path."""
    conf = tmp_path / name
    conf.write_text(conf_text)
    proc = subprocess.run(
        [NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
        capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stderr


def _guard_conf(directive_lines):
    """A minimal stream server carrying `directive_lines` and nothing else."""
    return ("daemon off;\n"
            "events { worker_connections 16; }\n"
            "stream {\n"
            "    server {\n"
            f"        listen {BIND_HOST}:1;\n"
            "        brix_root on;\n"
            "        brix_auth none;\n"
            "        brix_manager_mode on;\n"
            f"{directive_lines}"
            "    }\n"
            "}\n")


# =========================================================================== #
# A. brix_cms_state_fanout — the probe cap is a count, so count it.           #
# =========================================================================== #

def test_the_probe_cap_is_the_number_of_nodes_asked(cms, nodes):
    """success: with brix_cms_state_fanout 2 and four nodes exporting the
    path, exactly two kYR_state probes leave the manager.

    locate_fanout_state() (locate_manager.c:158) walks the node table until
    `sent` reaches the cap, so the cap is not a hint about load — it is the
    exact number of frames on the wire.  Which two nodes get asked is table
    order and is deliberately not asserted.
    """
    fan, _other = nodes
    path = "/fan/cap-fast.dat"

    elapsed, status, _body = _timed_locate(cms.port, path)

    probed = [n for n in fan if n.of(CMS_RR_STATE, path)]
    total = sum(len(n.of(CMS_RR_STATE, path)) for n in fan)
    def _assert_test_the_probe_cap_is_the_number_of_nodes_asked_1():
        assert total == FAST_STATE_FANOUT, \
            (f"brix_cms_state_fanout {FAST_STATE_FANOUT} must put exactly "
             f"{FAST_STATE_FANOUT} kYR_state frames on the wire, saw {total} "
             f"across nodes {[n.dport for n in probed]}\n{_errlog(cms)[-2000:]}")
        assert len(probed) == FAST_STATE_FANOUT, \
            "the cap counts nodes, not frames — no node may be probed twice"

    _assert_test_the_probe_cap_is_the_number_of_nodes_asked_1()
    # No node answers kYR_have, so the window expires into a kXR_wait.
    def _assert_test_the_probe_cap_is_the_number_of_nodes_asked_2():
        assert status in (kXR_wait, kXR_error), \
            f"an unanswered probe window must not redirect: {status}"
        assert elapsed >= LOCATE_WINDOW * 0.5, \
            (f"a probed locate must have PARKED for the window, "
             f"returned in {elapsed:.3f}s")

    _assert_test_the_probe_cap_is_the_number_of_nodes_asked_2()


def test_a_cap_larger_than_the_cluster_asks_every_covering_node(cms, nodes):
    """success: the slow manager's brix_cms_state_fanout 6 exceeds the five
    registered nodes, so the four that export the path all get probed — the
    cap is a ceiling, never a target."""
    fan, _other = nodes
    path = "/fan/cap-slow.dat"

    _elapsed, _status, _body = _timed_locate(cms.extra_ports["SLOW_PORT"],
                                             path)

    per_node = [len(n.of(CMS_RR_STATE, path)) for n in fan]
    assert per_node == [1, 1, 1, 1], \
        (f"a cap of {SLOW_STATE_FANOUT} over four covering nodes must probe "
         f"each exactly once, got {dict(zip([n.dport for n in fan], per_node))}"
         f"\n{_errlog(cms)[-2000:]}")


def test_a_node_that_does_not_export_the_path_is_never_probed(cms, nodes):
    """security-neg: the /other node is skipped even though the slow
    manager's cap has room for it.

    This is the assertion the cap alone cannot make.  A kYR_have from a node
    that does not hold the path would name a server the client must not be
    sent to, so brix_srv_paths_cover() has to run BEFORE the cap, not as a
    tie-break once the cap is full.  A cap of six over five nodes leaves no
    room for the alternative explanation.
    """
    fan, other = nodes
    path = "/fan/scoped.dat"

    _timed_locate(cms.extra_ports["SLOW_PORT"], path)

    assert other.of(CMS_RR_STATE) == [], \
        (f"node {other.dport} exports only /other and must never be probed "
         f"for {path}: {other.of(CMS_RR_STATE)}")
    assert sum(len(n.of(CMS_RR_STATE, path)) for n in fan) == len(FAN_DPORTS), \
        "the covering nodes must still all have been probed"


# =========================================================================== #
# B. What the cap is a budget OF.                                             #
# =========================================================================== #

def test_the_probe_cap_is_charged_per_locate_not_per_path(cms, nodes):
    """success: the cap is a per-REQUEST budget.

    This config carries no brix_cms_emptylife, which is the shipped default
    (server_conf_merge_cluster.c:306 — 0 means negative caching is off), so an
    expired probe window remembers nothing and the retry of a path spends the
    cap over again: two probes, then two more.  That is the guarantee
    brix_cms_state_fanout actually makes — "no single locate storms more than
    N nodes", never "no path costs more than N probes" — and it is the shape
    an operator sizing the directive against a retrying client needs.

    The opt-in negative cache that changes this (§2.6) is
    test_cms_parity_wave.py's subject, not this file's; the point here is only
    that the cap is unaffected by it either way.
    """
    fan, _other = nodes
    path = "/fan/twice.dat"

    first_elapsed, _status, _body = _timed_locate(cms.port, path)
    after_first = sum(len(n.of(CMS_RR_STATE, path)) for n in fan)
    assert after_first == FAST_STATE_FANOUT, \
        f"the first locate must spend the cap, sent {after_first}"

    second_elapsed, _status2, _body2 = _timed_locate(cms.port, path)
    after_second = sum(len(n.of(CMS_RR_STATE, path)) for n in fan)

    assert after_second == 2 * FAST_STATE_FANOUT, \
        (f"the retry must spend the cap again, not more and not less: probe "
         f"count went {after_first} -> {after_second}")
    assert second_elapsed >= LOCATE_WINDOW * 0.5, \
        (f"with negatives off the retry must PARK again, not answer from a "
         f"cache: {second_elapsed:.3f}s after {first_elapsed:.3f}s")


# =========================================================================== #
# C. brix_cms_locate_timeout — the parent park, measured as a difference.     #
# =========================================================================== #

def test_the_parent_park_ends_in_kxr_wait(cms, nodes):
    """success: a locate no registered node covers walks past the probe leg
    and the registry into locate_try_cms_parent(), which parks the client and
    answers kXR_wait 5 when the timeout fires.

    /lost is covered by nobody: the four data nodes export /fan, the fifth
    exports /other, and the two managers register themselves under /elsewhere
    precisely so their own registry rows cannot stand in for a holder.
    """
    fan, other = nodes
    path = "/lost/absent.dat"

    elapsed, status, body = _timed_locate(cms.port, path)

    assert status == kXR_wait, \
        (f"an unresolved parent locate must answer kXR_wait, got {status} "
         f"{body!r}\n{_errlog(cms)[-2000:]}")
    assert _wait_seconds(body) == 5, \
        f"recv.c:75 sends kXR_wait 5, got {_wait_seconds(body)}"
    assert elapsed >= FAST_LOCATE_TIMEOUT * 0.6, \
        (f"the client must have been PARKED for the timeout, answered in "
         f"{elapsed:.3f}s (timeout {FAST_LOCATE_TIMEOUT}s)")
    # The probe leg found nobody to ask, so it fell through without sending.
    assert all(n.of(CMS_RR_STATE, path) == [] for n in fan + [other]), \
        "no node exports /lost — none may be probed for it"


def test_a_longer_timeout_parks_the_client_longer(cms, nodes):
    """success: the slow manager differs from the fast one only in these
    three values, so the extra seconds on the wire are brix_cms_locate_timeout
    and nothing else.

    Both parks are measured in the same test so a host that is slow is slow
    for both halves; the assertion is on the gap, not on either absolute.
    """
    fast_elapsed, fast_status, _f = _timed_locate(cms.port, "/lost/gap-a.dat")
    slow_elapsed, slow_status, _s = _timed_locate(
        cms.extra_ports["SLOW_PORT"], "/lost/gap-b.dat")

    assert fast_status == slow_status == kXR_wait, \
        f"both managers must park then wait: {fast_status} / {slow_status}"
    assert slow_elapsed - fast_elapsed >= LOCATE_GAP, \
        (f"brix_cms_locate_timeout {SLOW_LOCATE_TIMEOUT}s vs "
         f"{FAST_LOCATE_TIMEOUT}s must show on the wire: "
         f"{slow_elapsed:.3f}s vs {fast_elapsed:.3f}s "
         f"(need a gap of {LOCATE_GAP}s)")
    assert slow_elapsed >= SLOW_LOCATE_TIMEOUT * 0.6, \
        (f"the slow park cannot finish early: {slow_elapsed:.3f}s "
         f"(timeout {SLOW_LOCATE_TIMEOUT}s)")


def test_a_parent_locate_never_converges_however_often_the_client_retries(
        cms, nodes):
    """DEFECT CANDIDATE #49 — the parent-locate forward is write-only.

    ngx_brix_cms_send_locate() emits CMS_RR_LOCATE (=2); cms_srv_frame_routes[]
    has no row for it, so the parent recognises the opcode by name in
    cms_srv_frame_unknown() and drops it with a debug-only log line.  The
    parent here IS this same nginx's CMS face — a live, healthy, registered
    manager — and it still never answers.

    So a hierarchy cannot resolve upward and, on a build without --with-debug,
    never says why: the client sees kXR_wait, retries, and is parked for the
    whole timeout again, forever.  Three round trips are enough to call it a
    livelock rather than a slow start.

    The retries also pin the safety half of recv.c:60-76: a parent timeout
    caches nothing.  brix_pending_set_path() is called by the state fan-out
    leg alone, so a parent that was merely slow, unreachable or mid-restart
    can never turn one bad minute into a cluster-wide cached NotFound.  Every
    attempt below therefore costs the full timeout rather than getting
    cheaper.
    """
    path = "/lost/livelock.dat"

    outcomes = [_timed_locate(cms.port, path) for _ in range(3)]

    assert all(status == kXR_wait for _e, status, _b in outcomes), \
        (f"{DEFECT49}\nstatuses: {[s for _e, s, _b in outcomes]}")
    assert all(elapsed >= FAST_LOCATE_TIMEOUT * 0.6
               for elapsed, _s, _b in outcomes), \
        (f"{DEFECT49}\nelapsed: "
         f"{[round(e, 3) for e, _s, _b in outcomes]}")


# =========================================================================== #
# D. brix_cms_fanout_window — a deadline, not a delay.                        #
# =========================================================================== #

def test_the_silent_success_window_holds_the_client(cms, nodes):
    """success: the node executor is silent on success, so "no kYR_error
    before the deadline" IS the success signal — with silent holders the
    kXR_ok arrives exactly one brix_cms_fanout_window later."""
    fan, other = nodes
    path = "/fan/del-fast.dat"

    elapsed, status, body = _timed_rm(cms.port, path)

    assert status == kXR_ok, \
        (f"a silent window must settle as success, got {status} {body!r}\n"
         f"{_errlog(cms)[-2000:]}")
    forwarded = [len(n.of(CMS_RR_RM, path)) for n in fan]
    assert forwarded == [1, 1, 1, 1], \
        f"every holder must receive the delete, got {forwarded}"
    assert other.of(CMS_RR_RM) == [], \
        f"node {other.dport} does not export /fan and must get no delete"
    assert elapsed >= FAST_FANOUT_WINDOW * 0.5, \
        (f"the client must have been parked for the window, answered in "
         f"{elapsed:.3f}s")


def test_a_longer_window_holds_it_longer(cms, nodes):
    """success: the same delete against the same silent holders through the
    manager whose only difference is brix_cms_fanout_window 2500ms."""
    fast_elapsed, fast_status, _f = _timed_rm(cms.port, "/fan/gap-fast.dat")
    slow_elapsed, slow_status, _s = _timed_rm(
        cms.extra_ports["SLOW_PORT"], "/fan/gap-slow.dat")

    assert fast_status == slow_status == kXR_ok, \
        f"both deletes must succeed: {fast_status} / {slow_status}"
    assert slow_elapsed - fast_elapsed >= FANOUT_GAP, \
        (f"brix_cms_fanout_window {SLOW_FANOUT_WINDOW}s vs "
         f"{FAST_FANOUT_WINDOW}s must show on the wire: "
         f"{slow_elapsed:.3f}s vs {fast_elapsed:.3f}s "
         f"(need a gap of {FANOUT_GAP}s)")


def test_every_node_answering_settles_the_window_early(cms, nodes):
    """error: the window is a DEADLINE.  When every holder answers,
    brix_cms_fanout_note_error() finalizes at got_err == expected
    (fanout.c:355) instead of waiting it out — so the failure is reported on
    the slow manager in far less than its 2500ms, carrying the node's text.

    Measured on the SLOW manager on purpose: on the fast one a 300ms window is
    too close to the round trip for "early" to mean anything.
    """
    fan, _other = nodes
    for node in fan:
        node.error_reply = (kXR_NotFound, b"replica pinned")

    elapsed, status, body = _timed_rm(cms.extra_ports["SLOW_PORT"],
                                      "/fan/early.dat")

    assert status == kXR_error, \
        (f"a node error inside the window must fail the delete, got {status} "
         f"{body!r}\n{_errlog(cms)[-2000:]}")
    assert "replica pinned" in _error_text(body), \
        f"the client must see the node's own text: {body!r}"
    assert elapsed < SLOW_FANOUT_WINDOW, \
        (f"all holders answered, so the deadline must be cut short: "
         f"{elapsed:.3f}s of a {SLOW_FANOUT_WINDOW}s window")


# =========================================================================== #
# E. brix_metadata_only — a role flag with two visible halves.                #
# =========================================================================== #

def test_a_metadata_only_server_advertises_the_meta_role_bit(cms):
    """success: protocol_role_flags() (protocol.c:84) ORs kXR_attrMeta into
    the kXR_protocol reply, which is how a stock client learns not to ask this
    node for bytes.  The manager on {PORT} is the control: it sets the bit for
    kXR_isManager and must not set this one."""
    meta_flags = _protocol_flags(cms.extra_ports["META_PORT"])
    mgr_flags = _protocol_flags(cms.port)

    assert meta_flags & kXR_attrMeta, \
        (f"brix_metadata_only must advertise kXR_attrMeta (0x{kXR_attrMeta:08x}), "
         f"flags were 0x{meta_flags:08x}")
    assert not mgr_flags & kXR_attrMeta, \
        (f"a server without the directive must not advertise it, "
         f"flags were 0x{mgr_flags:08x}")
    assert mgr_flags & kXR_isManager, \
        "the control must still be recognisable as the manager it is"


def test_open_is_refused_on_a_metadata_only_server(cms):
    """error: open_request.c:69 answers kXR_Unsupported with a message that
    names the reason, so a client can tell "this node holds no data" apart
    from "this file is missing" — the file it asks for exists on disk."""
    sock = _xrd_session(cms.extra_ports["META_PORT"])
    try:
        status, body = _open(sock, "/meta/seed.txt", kXR_open_read)
    finally:
        sock.close()

    assert status == kXR_error, \
        f"a metadata-only server must refuse kXR_open, got {status} {body!r}"
    assert _error_code(body) == kXR_Unsupported, \
        (f"the refusal must be kXR_Unsupported ({kXR_Unsupported}), got "
         f"{_error_code(body)}: {_error_text(body)}")
    assert "metadata-only" in _error_text(body), \
        f"the message must name the reason: {_error_text(body)!r}"


def test_the_namespace_still_answers_on_a_metadata_only_server(cms):
    """success: metadata is the whole point of the role — kXR_stat must keep
    working, or the directive would just be an offline switch."""
    sock = _xrd_session(cms.extra_ports["META_PORT"])
    try:
        status, body = _stat(sock, "/meta/seed.txt")
    finally:
        sock.close()

    assert status == kXR_ok, \
        f"kXR_stat must still answer on a metadata-only server: {status} {body!r}"
    # "<id> <size> <flags> <mtime>" (stat_line.h) — the size field, not a
    # substring match, so the assertion cannot pass on a coincidental inode.
    fields = body.split(b"\x00", 1)[0].split()
    assert len(fields) >= 4, f"malformed stat line: {body!r}"
    assert int(fields[1]) == len(SEED), \
        f"the stat line must carry the real size {len(SEED)}: {body!r}"


def test_a_create_open_is_refused_by_the_role_not_by_read_only(cms):
    """security-neg: the block carries brix_allow_write on, so a create-open
    reaching the writable path would succeed.  It must be refused with the
    SAME kXR_Unsupported — proving brix_metadata_only is a role and not an
    alias for brix_read_only, and that the refusal is not something a write
    flag can talk its way past.
    """
    sock = _xrd_session(cms.extra_ports["META_PORT"])
    try:
        status, body = _open(sock, "/meta/new.dat", kXR_open_updt | kXR_new)
    finally:
        sock.close()

    assert status == kXR_error, \
        f"a write-open must be refused too, got {status} {body!r}"
    assert _error_code(body) == kXR_Unsupported, \
        (f"a metadata-only refusal, not a read-only one: got "
         f"{_error_code(body)}: {_error_text(body)}")
    assert not (Path(cms.data_root) / "meta" / "new.dat").exists(), \
        "a refused create must not have touched the filesystem"


# =========================================================================== #
# F. Guard negatives — parse-time, against tmp_path copies only.              #
# =========================================================================== #

def test_a_non_numeric_probe_cap_is_refused_at_parse_time(tmp_path):
    """security-neg: brix_cms_state_fanout is a num slot; a value nginx
    cannot read as one must stop the config, never silently mean 0 (which
    would disable the probe leg without saying so)."""
    rc, err = _nginx_t(
        _guard_conf("        brix_cms_state_fanout notanumber;\n"),
        tmp_path, "badcap.conf")

    assert rc != 0, f"a non-numeric probe cap must fail nginx -t:\n{err}"
    assert "invalid number" in err, \
        f"the refusal must name the problem: {err}"


def test_a_malformed_window_duration_is_refused_at_parse_time(tmp_path):
    """security-neg: brix_cms_fanout_window is a msec slot.  A misspelled
    duration must be refused, not rounded — a window silently read as 0 would
    finalize every fan-out before a single node could answer."""
    rc, err = _nginx_t(
        _guard_conf("        brix_cms_fanout_window 300millis;\n"),
        tmp_path, "badwindow.conf")

    assert rc != 0, f"a malformed duration must fail nginx -t:\n{err}"
    assert "invalid value" in err, \
        f"the refusal must name the problem: {err}"
