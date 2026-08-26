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

