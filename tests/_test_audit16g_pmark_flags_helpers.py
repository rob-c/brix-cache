"""The six pmark flags at VALUE granularity — audit §Method, 16th tranche.

WHY THIS FILE EXISTS
--------------------
Re-running the audit's Method (steps 1-2) per (directive, VALUE) over the 128
``ngx_conf_set_flag_slot`` directives turned 256 pairs into 106 that are written
nowhere in the corpus, in any form.  Six of them are one feature — SciTags
packet marking — and share one shape: the ``on`` arm is configured somewhere,
and the word ``off`` had never been written for any of them.

    brix_pmark                 config.c:42   default 0
    brix_pmark_firefly         config.c:43   default 1
    brix_pmark_flowlabel       config.c:44   default 1
    brix_pmark_scitag_cgi      config.c:45   default 1
    brix_pmark_firefly_origin  config.c:46   default 0
    brix_pmark_http_plain      config.c:48   default 0

Three of the six default to 1, which makes this tranche's usual question sharper
than it was for the S3 flags in file 6: for ``firefly``, ``flowlabel`` and
``scitag_cgi`` the never-written ``off`` arm is the ONLY way to reach the
disabled behaviour at all, so an untested ``off`` is an untested half of the
feature and not merely an untested spelling of the default.

WHAT THE VALUES SELECT — the measured table
-------------------------------------------
Thirteen WebDAV locations on one listener (see the config's header for why
``base`` is the absent arm of four flags at once).  Every row was measured
against a live server before it was written down; the collector column is what
the firefly UDP sink received, as (appname, state, experiment, activity)::

  arm      probe                        collector          metric delta
  ---------------------------------------------------------------------------
  base     GET                          start+end (2,5)    started+1 ended+1
                                                           sent+2
  moff     GET                          nothing            nothing at all
  mabs     GET                          nothing            nothing at all
  moff     GET ?scitag.flow=129         nothing            nothing at all
  ---------------------------------------------------------------------------
  ffon     GET                          start+end (2,5)    started+1 ended+1
  ffoff    GET                          nothing            started+1, ended 0
  ffoff    GET over IPv6                nothing            flowlabel_set+1
  ---------------------------------------------------------------------------
  cgion    GET ?scitag.flow=129         start+end (2,1)    started+1
  cgioff   GET ?scitag.flow=129         start+end (2,5)    started+1
  base     GET ?scitag.flow=129         start+end (2,1)    started+1
  cgion    GET ?scitag.flow=70000       start+end (2,5)    200, mapping used
  ---------------------------------------------------------------------------
  base     PUT                          start+end (2,5)    started+1
  ploff    GET                          nothing            nothing at all
  plabs    GET                          nothing            nothing at all
  ploff    COPY                         start+end (2,5)    201, and MARKED
  ---------------------------------------------------------------------------
  oron     GET                          start+end, TWICE   sent+2 (not +4)
  oroff    GET                          collector only     sent+2
  base     GET                          collector only     sent+2
  oron     GET, nothing on :10514       collector only     sent+2, dropped 0
  ---------------------------------------------------------------------------
  flon     GET over IPv6                start+end          flowlabel_set+1
  floff    GET over IPv6                start+end          neither flowlabel
  flon     GET over IPv4                start+end          neither flowlabel
  flon     40 live IPv6 connections     80 datagrams       set+failed == 40,
                                                           set <= 32
  ---------------------------------------------------------------------------

Two rows carry the whole point of the feature.  ``ffoff`` over IPv6 still stamps
the flow label: ``brix_pmark_firefly off`` turns off the out-of-band REPORT and
leaves the in-band MARK running (firefly.c:233-243), which is the only
configuration in which the two SciTags techniques can be told apart.  And
``ploff`` still marks a COPY: TPC is marked whatever ``http_plain`` says
(dispatch.c:108-112), so the flag narrows the marking surface to plain GET/PUT
rather than switching marking off.

FINDINGS
--------
DEFECT CANDIDATE #72 — ``brix_pmark_firefly off`` leaves an unbounded phantom
backlog in the exposition.  ``brix_pmark_flow_begin`` increments
``brix_pmark_flows_started_total`` unconditionally (firefly.c:245), while
``brix_pmark_flows_ended_total`` is incremented inside
``if (flow->firefly_started && flow->pm->firefly)`` (firefly.c:257-259).  On a
site that marks in-band only — the one configuration this tranche's never-written
``off`` arm selects — started climbs for ever and ended never moves, so
``started - ended``, the obvious "flows in progress" expression for a dashboard,
reads as an ever-growing number of stuck transfers on a perfectly healthy
server.  Cure: count the end unconditionally (the flow ended either way), or
stop counting the start when firefly is off.

DEFECT CANDIDATE #73 — the origin firefly copy is neither counted nor
error-tracked.  With ``brix_pmark_firefly_origin on`` every datagram is sent
twice, once to each configured collector and once to the client's own IP at the
fixed port 10514, but the second ``sendto`` is ``(void)``-cast
(firefly.c:158-161): ``brix_pmark_firefly_sent_total`` counts 2 where 4 left the
box, and a client that never listens on 10514 — the common case, since the
report is aimed at the peer's flowd — produces no ``firefly_dropped_total`` and
no log line.  The exposition understates egress by exactly the factor the
operator turned on, and the one arm with a delivery risk is the one arm with no
observability.

DEFECT CANDIDATE #74 — the flow-label capability probe leases a fixed label
EXCLusively and caches its refusal for the worker's life.
``brix_pmark_flowlabel_usable`` leases ``encode(EXP_MIN, ACT_MIN)`` = 0x20004
toward ``::1`` with ``share = IPV6_FL_S_EXCL`` (flowlabel.c:86-103), closes the
socket, and stores the verdict in a per-worker static.  A kernel flow-label
entry outlives the socket that held it (measured on this host: 6s is not enough,
10s is), and while it exists any OTHER exclusive lease of the same label is
refused with EPERM — including the probe of a second worker, a reloaded worker,
or a second brix on the same host.  The loser degrades to firefly-only for its
entire life, with one NOTICE and no metric: ``flowlabel_failed_total`` is only
incremented by the per-flow lease (flowlabel.c:134), which a declined probe never
reaches.  §F's poisoned-probe test is that state, made deterministically.  Worse,
a FAILED lease refreshes the blocking entry's lifetime (the kernel's
``fl_release`` sets ``lastuse = jiffies`` on the EPERM path), so a server that
keeps retrying keeps the blocker alive.  Cure: a non-exclusive share — measured
here, ``IPV6_FL_S_PROCESS``/``S_USER``/``S_ANY`` all admit four sockets on one
label where ``S_EXCL`` admits one — or no probe at all, since the per-flow lease
already fails open.

DEFECT CANDIDATE #75 — the per-flow label space is 32 wide per (experiment,
activity), and exhausting it silently stops the REQUIRED in-band technique.
``pmark_flowlabel_lease`` ORs 5 random bits (``BRIX_PMARK_FL_ENTROPY_MASK`` =
0x000C0103) into the structural label and leases the result EXCLusively
(flowlabel.c:123-131), so one (exp, act) pair has 32 distinct labels and each is
held by its connection.  Measured: 40 concurrent IPv6 flows on one activity
stamped 22 and were refused 18 — the failures start at the second flow, not at
the 33rd, because the draw is random with replacement.  Every refusal is
fail-open (all 40 transfers completed), so the only symptom is
``flowlabel_failed_total`` climbing while the labels routers are supposed to
classify on stop arriving.  Same cure as #74: the share, not the entropy width,
is what makes a label scarce.

DEFECT CANDIDATE #76 — the capability probe runs before the peer-family gate, so
IPv4 connections probe an IPv6-only technique.  ``brix_pmark_flowlabel_apply``
puts ``brix_pmark_flowlabel_usable(log)`` in the same condition as its ``fd < 0``
check (flowlabel.c:158-160) and only afterwards asks getpeername what family the
peer is.  Every first marked request in a worker therefore performs the probe —
a socket, an exclusive lease of the fixed label, and on refusal a NOTICE — even
on a v4-only deployment where the result can never be used.  On a host where the
probe SUCCEEDS this is worse than noise: the successful probe plants the very
10-second exclusive blocker of #74, so a v4-only site manufactures the lockout it
cannot benefit from.  The sibling entry point disagrees: ``apply_addr`` tests
``dst->sa_family != AF_INET6`` before it probes (flowlabel.c:185-189), which is
what makes this an ordering slip rather than a decision.  Cure: move the probe
below the family checks in ``apply``, as ``apply_addr`` already has it.

Observed while writing this file: because the lifecycle fixture is per-test,
every test starts a fresh nginx, every fresh nginx probes, and the probe of one
test was refused by the lingering lease of its predecessor — #74 reproducing
itself between two tests of the same file, surfaced on an IPv4 request by #76.
That is why the IPv6 positives here wait out the measured settle window before
provoking a probe (``_settle_for_a_clean_probe``) instead of polling for it.

One more fact worth recording, since the whole tranche rests on it: the audit's
step-2 grep has to be case-insensitive.  ``ngx_conf_set_flag_slot`` compares with
``ngx_strcasecmp``, so ``OFF`` is a legal spelling of the never-written arm (§G
pins that), while ``1``, ``0``, ``yes`` and ``true`` are all refused.  The one
place the corpus did write an off arm is documentation —
docs/10-reference/comparison/deployment-reference.md:411 offers ``brix_pmark_
flowlabel off`` as the "Firefly-only parity with stock XRootD" root:// recipe —
so the configuration the reference manual advertises had no test on either plane
until this file.

WHAT THIS FILE ASSERTS
----------------------
§A  brix_pmark: the pair, the default, and that a client cannot turn marking on
    from the wire when the master switch is off.
§B  brix_pmark_firefly: the datagrams stop, the in-band mark does not, and
    DEFECT #72's asymmetric counters.
§C  brix_pmark_scitag_cgi: the client override honoured, refused, and the
    out-of-range value ignored on both arms.
§D  brix_pmark_http_plain: plain GET/PUT unmarked on the off arm, COPY marked on
    both.
§E  brix_pmark_firefly_origin: the copy arrives, only on the on arm, and DEFECT
    #73's undercount.
§F  brix_pmark_flowlabel: the pair over IPv6, the IPv4 family gate and the probe
    it still triggers (DEFECT #76), the poisoned probe (DEFECT #74) and the
    32-label ceiling (DEFECT #75).
§G  the parse tier for all six, on BOTH planes the X-macro reaches: values,
    case-insensitivity, arity, duplicates, four wrong placements, and the
    documented firefly-only recipe as a whole.
§H  the source: the six merge defaults, the X-macro's two instantiations, and the
    four mechanisms the findings above name.

Ledger: lc-audit16g-pmark (one listener, thirteen arms, /metrics; the same port
on the IPv6 loopback when the host has one).
"""

import json
import os
import socket
import struct
import time
from pathlib import Path

import pytest
import requests

from config_parse import nginx_t
from ephemeral_port import free_port
from fleet_lifecycle_ports import (
    PARSE_PLACEHOLDER_PORT,
    SHARED_PARSE_PLACEHOLDER_PORT,
)
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, BIND_HOST6, HOST, HOST6, NGINX_BIN, url_host

def _expression_1():
    return (
        [_lease(PROBE_LABEL + 0x10) for _ in range(4)]
    )

def _expression_2(exclusive):
    return (
        [sock for sock in exclusive if isinstance(sock, socket.socket)]
    )

def _expression_3():
    return (
        [_lease(PROBE_LABEL + 0x20, share=3) for _ in range(4)]
    )

def _expression_4(shared):
    return (
        [sock for sock in shared if isinstance(sock, socket.socket)]
    )


def _check_test_the_label_space_is_thirty_two_wide_per_activity_2(delta):
    assert delta.get(FL_FAILED, 0.0) >= FL_FLOWS - FL_SPACE, \
        f"{FL_FLOWS} concurrent flows fitted in {FL_SPACE} labels: {delta}"

def _check_test_the_label_space_is_thirty_two_wide_per_activity_1(delta, pmark):
    assert _probe_declined(pmark.log), delta

def _check_test_the_kernel_admits_one_exclusive_holder_per_label_3(held, exclusive):
    assert len(held) == 1, \
        f"an exclusive label took {len(held)} holders: {exclusive}"

def _guard_test_the_kernel_admits_one_exclusive_holder_per_label_1(sock):
    if isinstance(sock, socket.socket):
        sock.close()

def _check_test_the_kernel_admits_one_exclusive_holder_per_label_4(held, shared):
    assert len(held) == 4, \
        f"a shared label refused a holder, so the cure is not the share: {shared}"

def _guard_test_the_kernel_admits_one_exclusive_holder_per_label_2(sock):
    if isinstance(sock, socket.socket):
        sock.close()


pytestmark = [pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16g-pmark")]

NAME = "lc-audit16g-pmark"
ROOT = Path(__file__).resolve().parents[1]
DIRECTIVES_H = ROOT / "src/observability/pmark/directives.h"
CONFIG_C = ROOT / "src/observability/pmark/config.c"
FIREFLY_C = ROOT / "src/observability/pmark/firefly.c"
FLOWLABEL_C = ROOT / "src/observability/pmark/flowlabel.c"
PMARK_H = ROOT / "src/observability/pmark/pmark.h"
DISPATCH_C = ROOT / "src/protocols/webdav/dispatch.c"

# The firefly collector is an in-process UDP sink, so its port is an OS
# ephemeral rather than a ledger slot — the exemption test_pmark.py already
# takes for the same mock.
FF_PORT = int(os.environ.get("TEST_PMARK_FF_PORT") or free_port())

# BRIX_PMARK_FF_PORT (pmark.h:40).  The origin report goes to the CLIENT's own
# address at this fixed port; it is not configurable, so a test that wants to see
# one has to bind exactly this.
ORIGIN_PORT = 10514

FILE = "file.txt"
PAYLOAD = b"audit16g-scitags-payload\n"

# What the defsfile + the two map directives resolve an unmarked request to.
EXP, ACT = 2, 5
# scitag.flow=129 → experiment 129>>6 = 2, activity 129&0x3f = 1.
OVERRIDE_FLOW, OVERRIDE_EXP, OVERRIDE_ACT = 129, 2, 1
# 70000 exceeds the 16-bit SciTags range, so it is neither honoured nor fatal.
BAD_FLOW = 70000

ON, OFF, ABSENT = 0, 1, 2
# The arms of each flag, by the location that carries them.  `base` appears as
# the ABSENT arm of four flags because it IS their absent arm: it writes none of
# them, so it carries exactly the merge default under test.
MASTER = ("base", "moff", "mabs")
FIREFLY = ("ffon", "ffoff", "base")
CGI = ("cgion", "cgioff", "base")
PLAIN = ("base", "ploff", "plabs")
ORIGIN = ("oron", "oroff", "base")
FLOWLABEL = ("flon", "floff", "base")
ARMS = ("base", "moff", "mabs", "ffon", "ffoff", "cgion", "cgioff",
        "ploff", "plabs", "oron", "oroff", "flon", "floff")

# (directive, merge field, merge default) — §G and §H read this.
FLAGS = (
    ("brix_pmark", "enable", 0),
    ("brix_pmark_firefly", "firefly", 1),
    ("brix_pmark_flowlabel", "flowlabel", 1),
    ("brix_pmark_scitag_cgi", "scitag_cgi", 1),
    ("brix_pmark_firefly_origin", "firefly_origin", 0),
    ("brix_pmark_http_plain", "http_plain", 0),
)
FLAG_NAMES = [name for name, _, _ in FLAGS]

STARTED = "brix_pmark_flows_started_total"
ENDED = "brix_pmark_flows_ended_total"
SENT = "brix_pmark_firefly_sent_total"
DROPPED = "brix_pmark_firefly_dropped_total"
FL_SET = "brix_pmark_flowlabel_set_total"
FL_FAILED = "brix_pmark_flowlabel_failed_total"
UNRESOLVED = "brix_pmark_map_unresolved_total"
COUNTERS = (STARTED, ENDED, SENT, DROPPED, FL_SET, FL_FAILED, UNRESOLVED)

_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK), reason=f"nginx not executable: {NGINX_BIN}")


# --------------------------------------------------------------------------- #
# The IPv6 flow-label manager, from the client side                            #
#                                                                              #
# flowlabel.c declares this kernel ABI privately because <linux/in6.h> clashes  #
# with <netinet/in.h>; the same declaration is repeated here because §F has to  #
# occupy the label the server's probe asks for, and no other interface can.     #
# Layout: in6_addr, __be32 label, u8 action, u8 share, u16 flags, u16 expires,  #
# u16 linger, u32 pad — with the pad naturally aligned, hence the 2x.           #
# --------------------------------------------------------------------------- #

IPV6_FLOWLABEL_MGR = 32
FL_A_GET, FL_F_CREATE, FL_S_EXCL = 0, 1, 1
FL_REQ = "=16sIBBHHH2xI"

# flowlabel.c always probes in6addr_loopback, whatever address the peer used, so
# this is the address under test rather than the host the suite dials.
PROBE_DST = "::1"          # net-literal-allow: flowlabel.c probes in6addr_loopback
# brix_pmark_flowlabel_encode(BRIX_PMARK_EXP_MIN=1, BRIX_PMARK_ACT_MIN=1):
# reverse9(1) = 0x100, so (0x100 << 9) | (1 << 2) = 0x20004.
PROBE_LABEL = 0x20004
# BRIX_PMARK_FL_ENTROPY_MASK (pmark.h:62) has five bits set, so one (exp, act)
# pair has 2**5 distinct per-flow labels and no more.
FL_ENTROPY_MASK = 0x000C0103
FL_SPACE = 1 << 5
# Flows held open at once by the exhaustion probe: more than FL_SPACE, so the
# pigeonhole bound below is arithmetic and not a coin flip.
FL_FLOWS = 40
# How long a released kernel flow-label entry keeps blocking an exclusive
# re-lease.  Measured on this host: still held at 6s, free at 10s.
FL_SETTLE = 15
# The one line a refused capability probe produces (flowlabel.c:99-102), and the
# only evidence anywhere that the REQUIRED in-band technique is off.
PROBE_NOTICE = "IPv6 flow-label marking unavailable"


def _lease(label, share=FL_S_EXCL):
    """Lease `label` toward the probe's destination.  Returns the holding socket,
    or the OSError the kernel refused it with."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
    request = struct.pack(FL_REQ, socket.inet_pton(socket.AF_INET6, PROBE_DST),
                          socket.htonl(label), FL_A_GET, FL_S_EXCL if share
                          == FL_S_EXCL else share, FL_F_CREATE, 0, 0, 0)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, request)
    except OSError as exc:
        sock.close()
        return exc
    return sock


def _have_ipv6_loopback():
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        from ephemeral_port import free_port
        sock.bind((BIND_HOST6, free_port(BIND_HOST6)))
        sock.close()
        return True
    except OSError:
        return False


_needs_ipv6 = pytest.mark.skipif(
    not _have_ipv6_loopback(),
    reason=f"no IPv6 loopback to bind ([{BIND_HOST6}]) — flow-label marking "
           "declines an AF_INET peer before it reaches the kernel")


# --------------------------------------------------------------------------- #
# The firefly sink and the exposition                                          #
# --------------------------------------------------------------------------- #

class Sink:
    """UDP collector that records firefly datagrams as parsed JSON.

    Same shape as test_pmark.py's FireflyCapture: bind, drive one request, drain
    until quiet.  `drain` extends its own deadline on every datagram so a start
    and an end that arrive a second apart are one capture.
    """

    def __init__(self, port, host=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host or BIND_HOST, port))
        self.sock.settimeout(0.3)

    def drain(self, settle=1.0):
        out = []
        deadline = time.time() + settle
        while time.time() < deadline:
            try:
                data, _ = self.sock.recvfrom(8192)
            except socket.timeout:
                continue
            text = data.decode("utf-8", "replace")
            brace = text.find("{")
            if brace >= 0:
                try:
                    out.append(json.loads(text[brace:]))
                    deadline = time.time() + settle
                except json.JSONDecodeError:
                    out.append({"raw": text[:120]})
        return out

    def close(self):
        self.sock.close()


def _rows(fireflies):
    """(appname, state, experiment, activity) per datagram, in arrival order."""
    rows = []
    for fly in fireflies:
        if "raw" in fly:
            rows.append(("RAW", fly["raw"], -1, -1))
            continue
        rows.append((fly["context"]["application"],
                     fly["flow-lifecycle"]["state"],
                     fly["context"]["experiment-id"],
                     fly["context"]["activity-id"]))
    return rows


def _states(rows):
    return sorted(state for _, state, _, _ in rows)


def _metrics(port):
    response = requests.get(f"http://{url_host(HOST)}:{port}/metrics", timeout=10)
    assert response.status_code == 200, response.text[:200]
    return {name: value for name, value in
            (_line(line) for line in response.text.splitlines()
             if line.startswith("brix_pmark_"))}


def _line(line):
    name, _, value = line.partition(" ")
    return name, float(value)


def _delta(before, after):
    """Only the counters that moved, so an assertion can name the whole delta."""
    return {name: after.get(name, 0.0) - before.get(name, 0.0)
            for name in COUNTERS
            if after.get(name, 0.0) != before.get(name, 0.0)}


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

class _Planes:
    """The started instance, the sink, and the probes every section drives."""

    def __init__(self, endpoint, data):
        self.endpoint = endpoint
        self.port = endpoint.port
        self.data = data

    @property
    def log(self):
        path = Path(self.endpoint.prefix, "logs", "error.log")
        return path.read_text(errors="replace") if path.exists() else ""

    def url(self, arm, *, host=HOST, name=FILE, query=""):
        return f"http://{url_host(host)}:{self.port}/{arm}/{name}{query}"

    def get(self, arm, *, host=HOST, query="", session=None):
        agent = session or requests
        return agent.get(self.url(arm, host=host, query=query), timeout=15)

    def put(self, arm, name, body, *, host=HOST):
        return requests.put(self.url(arm, host=host, name=name), data=body,
                            timeout=15)

    def copy(self, arm, name, *, host=HOST):
        """A same-server WebDAV COPY — method NGX_HTTP_COPY, which
        webdav_dispatch_pmark marks whatever brix_pmark_http_plain says."""
        return requests.request(
            "COPY", self.url(arm, host=host),
            headers={"Destination": self.url(arm, host=host, name=name)},
            timeout=15)

    def metrics(self):
        return _metrics(self.port)

    def measure(self, probe, *, sink_port=FF_PORT, origin=False, settle=1.0):
        """Run `probe`, and return (response, collector rows, metric delta,
        origin rows).  One helper for every row of the measured table, so a
        section cannot accidentally read the metrics before the datagrams."""
        sink = Sink(sink_port)
        osink = None
        if origin:
            try:
                osink = Sink(ORIGIN_PORT)
            except OSError as exc:                      # pragma: no cover
                pytest.skip(f"cannot bind the fixed origin port {ORIGIN_PORT}: "
                            f"{exc}")
        try:
            before = self.metrics()
            response = probe()
            rows = _rows(sink.drain(settle=settle))
            after = self.metrics()
            origin_rows = _rows(osink.drain(settle=0.6)) if osink else []
        finally:
            sink.close()
            if osink:
                osink.close()
        return response, rows, _delta(before, after), origin_rows


def _defsfile(path):
    """The SciTags registry the two map directives name.  atlas/2 with a
    `default` activity of 1 and a `write` activity of 5, so the mapped pair (2,5)
    differs from the scitag.flow=129 override's (2,1) in the activity — the
    field that says which of the two won."""
    path.write_text(json.dumps({
        "version": 1,
        "experiments": [
            {"expName": "atlas", "expId": EXP, "activities": [
                {"activityName": "default", "activityId": OVERRIDE_ACT},
                {"activityName": "write", "activityId": ACT}]},
        ],
    }))
    return path


@pytest.fixture
def pmark(lifecycle, tmp_path):
    """Thirteen arms, one listener, one collector.

    Every arm is seeded identically, so a verdict that differs between two of
    them cannot be explained by their contents.  The listener is bound on the
    IPv6 loopback as well when the host has one, on the SAME port, because §F's
    subject only exists over real IPv6 and a second listen is cheaper than a
    second instance.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    for arm in ARMS:
        (data / arm).mkdir(parents=True)
        (data / arm / FILE).write_bytes(PAYLOAD)

    port, _ = _ledger_port()
    v6 = f"listen [{BIND_HOST6}]:{port};" if _have_ipv6_loopback() else ""
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16g_pmark.conf",
        port=port,
        protocol="webdav",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST,
                         "V6_LISTEN": v6,
                         "DEFS": str(_defsfile(tmp_path / "scitags.json")),
                         "FIREFLY_HOST": HOST,
                         "FIREFLY_PORT": FF_PORT},
        reason="audit-16g the six pmark flags at value granularity"))
    return _Planes(endpoint, data)


def _ledger_port():
    """The fixed port LifecycleHarness.register would assign anyway, resolved up
    front so the ::1 listen shares it with the v4 listen instead of a divergent
    dynamic one."""
    from fleet_lifecycle_ports import lifecycle_ports_for
    return lifecycle_ports_for(NAME)


# --------------------------------------------------------------------------- #
# §A — brix_pmark: the master switch                                           #
# --------------------------------------------------------------------------- #

