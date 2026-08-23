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

class TestTheMasterSwitch:
    """`brix_pmark` gates every other flag here: webdav_dispatch_pmark returns
    before it looks at anything else when enable is 0 (dispatch.c:108)."""

    @_needs_nginx
    def test_on_marks_the_flow_and_reports_it(self, pmark):
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(MASTER[ON]))
        assert response.status_code == 200, response.text[:200]
        assert response.content == PAYLOAD
        assert _states(rows) == ["end", "start"], rows
        assert {(app, exp, act) for app, _, exp, act in rows} == \
            {("arm-base", EXP, ACT)}, rows
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta

    @_needs_nginx
    def test_off_marks_nothing_at_all(self, pmark):
        """The arm the audit says was never written.  Not "no datagram" — no
        counter either, including map_unresolved_total: the mapping is never
        consulted, because flow_begin is never called."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(MASTER[OFF]))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta == {}, delta

    @_needs_nginx
    def test_absent_is_the_same_silence_as_off(self, pmark):
        """`brix_pmark` merges to 0 (config.c:42), so the two arms are one
        behaviour — which is the result, not the assumption."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(MASTER[ABSENT]))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta == {}, delta

    @_needs_nginx
    def test_off_cannot_be_undone_from_the_wire(self, pmark):
        """Security-negative: `scitag.flow` is a client-supplied value, and the
        only thing it can do is choose codes for a flow the SERVER decided to
        mark.  With the master switch off there is no flow to choose codes for,
        so a client cannot conjure marking — or a firefly aimed at itself — out
        of a query string."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(MASTER[OFF],
                              query=f"?scitag.flow={OVERRIDE_FLOW}"))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta == {}, delta


# --------------------------------------------------------------------------- #
# §B — brix_pmark_firefly: the out-of-band report                              #
# --------------------------------------------------------------------------- #

class TestTheFireflyReport:
    """`firefly` decides whether pmark_emit runs, and nothing else: the label,
    the mapping and the flow object are all built first (firefly.c:233-245)."""

    @_needs_nginx
    def test_on_emits_the_pair_of_datagrams(self, pmark):
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FIREFLY[ON]))
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta

    @_needs_nginx
    def test_absent_emits_them_too(self, pmark):
        """`firefly` merges to 1 (config.c:43) — one of the three flags in this
        tranche whose never-written `off` arm is the only way to reach the
        disabled behaviour at all."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FIREFLY[ABSENT]))
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta

    @_needs_nginx
    def test_off_stops_the_datagrams_without_stopping_the_flow(self, pmark):
        """DEFECT CANDIDATE #72.  The off arm still counts a started flow, and
        can never count an ended one, so `started - ended` — the natural
        "in progress" expression — grows without bound on a healthy server."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FIREFLY[OFF]))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta == {STARTED: 1.0}, delta
        assert ENDED not in delta, \
            "flows_ended_total moved on the firefly-off arm — DEFECT #72 was " \
            "fixed and this test now describes the old behaviour"

    @_needs_nginx
    def test_the_phantom_backlog_grows_with_every_transfer(self, pmark):
        """#72 again, as an operator would meet it: three transfers, three
        phantom flows in progress, and nothing in the log."""
        for _ in range(3):
            assert pmark.get(FIREFLY[OFF]).status_code == 200
        metrics = pmark.metrics()
        assert metrics[STARTED] == 3.0, metrics
        assert metrics[ENDED] == 0.0, metrics
        assert "pmark" not in pmark.log or "flows" not in pmark.log

    @_needs_nginx
    @_needs_ipv6
    def test_off_leaves_the_in_band_mark_running(self, pmark):
        """The row that makes the pair worth writing.  brix_pmark_firefly off
        disables the REPORT, not the MARK: the flow label is applied at
        firefly.c:233-236, before and independently of the emit gate.  The
        control is the same request on the same worker with firefly on."""
        _settle_for_a_clean_probe()
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FIREFLY[OFF], host=HOST6))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta.get(SENT, 0.0) == 0.0, delta
        labelled = delta.get(FL_SET, 0.0) + delta.get(FL_FAILED, 0.0)
        assert labelled == 1.0 or _probe_declined(pmark.log), (
            f"a marked IPv6 flow neither leased a label nor logged a refused "
            f"probe (DEFECT #74): {delta}")


# --------------------------------------------------------------------------- #
# §C — brix_pmark_scitag_cgi: the client-supplied override                     #
# --------------------------------------------------------------------------- #

class TestTheClientOverride:
    """`scitag_cgi` is the first of the three mapping priorities
    (mapping.c:445-447): with it off, the query string is not read at all and the
    path/defsfile mapping decides alone."""

    @_needs_nginx
    def test_on_honours_the_client_flow_id(self, pmark):
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(CGI[ON], query=f"?scitag.flow={OVERRIDE_FLOW}"))
        assert response.status_code == 200, response.text[:200]
        assert {(exp, act) for _, _, exp, act in rows} == \
            {(OVERRIDE_EXP, OVERRIDE_ACT)}, rows
        assert delta[STARTED] == 1.0, delta

    @_needs_nginx
    def test_absent_honours_it_too(self, pmark):
        """`scitag_cgi` merges to 1 (config.c:45)."""
        _, rows, _, _ = pmark.measure(
            lambda: pmark.get(CGI[ABSENT], query=f"?scitag.flow={OVERRIDE_FLOW}"))
        assert {(exp, act) for _, _, exp, act in rows} == \
            {(OVERRIDE_EXP, OVERRIDE_ACT)}, rows

    @_needs_nginx
    def test_off_refuses_the_client_flow_id(self, pmark):
        """Security-negative: the never-written arm is the one that stops a
        client choosing its own SciTags codes.  A flow that would have been
        (2,1) at the client's request is reported as the (2,5) the site
        configured, so a tenant cannot mislabel its traffic as another
        activity — or another experiment — in the NREN's accounting."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(CGI[OFF], query=f"?scitag.flow={OVERRIDE_FLOW}"))
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert {(app, exp, act) for app, _, exp, act in rows} == \
            {("arm-cgioff", EXP, ACT)}, rows
        assert delta[STARTED] == 1.0, delta

    @_needs_nginx
    @pytest.mark.parametrize("arm", [CGI[ON], CGI[OFF]],
                             ids=["scitag_cgi-on", "scitag_cgi-off"])
    def test_an_out_of_range_flow_id_is_ignored_on_both_arms(self, pmark, arm):
        """brix_pmark_parse_scitag returns NGX_ERROR for a value outside the
        16-bit range, and mapping.c treats that as "no override" rather than as a
        failure — so the transfer completes and the configured mapping is used,
        on the arm that reads the query as much as on the arm that does not."""
        response, rows, _, _ = pmark.measure(
            lambda: pmark.get(arm, query=f"?scitag.flow={BAD_FLOW}"))
        assert response.status_code == 200, response.text[:200]
        assert {(exp, act) for _, _, exp, act in rows} == {(EXP, ACT)}, rows


# --------------------------------------------------------------------------- #
# §D — brix_pmark_http_plain: which HTTP methods are marked at all             #
# --------------------------------------------------------------------------- #

class TestPlainHttpMarking:
    """The flag narrows the marking surface rather than switching marking off:
    COPY (WebDAV TPC) is marked whenever brix_pmark is on, and GET/PUT only when
    http_plain is on as well (dispatch.c:108-112)."""

    @_needs_nginx
    def test_on_marks_a_plain_put(self, pmark):
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.put(PLAIN[ON], "written.txt", PAYLOAD))
        assert response.status_code in (201, 204), response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert delta[STARTED] == 1.0, delta

    @_needs_nginx
    def test_off_leaves_a_plain_get_unmarked(self, pmark):
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(PLAIN[OFF]))
        assert response.status_code == 200, response.text[:200]
        assert response.content == PAYLOAD
        assert rows == [], rows
        assert delta == {}, delta

    @_needs_nginx
    def test_absent_leaves_it_unmarked_too(self, pmark):
        """`http_plain` merges to 0 (config.c:48) — XRootD parity, where pmark
        covers transfers and not every HTTP request."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(PLAIN[ABSENT]))
        assert response.status_code == 200, response.text[:200]
        assert rows == [], rows
        assert delta == {}, delta

    @_needs_nginx
    @pytest.mark.parametrize("arm,app",
                             [(PLAIN[OFF], "arm-ploff"), (PLAIN[ON], "arm-base")],
                             ids=["http_plain-off", "http_plain-on"])
    def test_a_copy_is_marked_on_both_arms(self, pmark, arm, app):
        """The row that says what the off arm actually means.  A COPY on the off
        arm is marked exactly as on the on arm, so an operator who writes
        `brix_pmark_http_plain off` still gets TPC firefly — and an operator who
        reads it as "packet marking off" is wrong."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.copy(arm, f"copied-{app}.txt"))
        assert response.status_code in (201, 204), response.text[:200]
        assert (pmark.data / arm / f"copied-{app}.txt").exists()
        assert _states(rows) == ["end", "start"], rows
        assert {name for name, _, _, _ in rows} == {app}, rows
        assert delta[STARTED] == 1.0, delta


# --------------------------------------------------------------------------- #
# §E — brix_pmark_firefly_origin: the copy aimed at the client                  #
# --------------------------------------------------------------------------- #

class TestTheOriginCopy:
    """`firefly_origin` sends every datagram a second time, to the CLIENT's own
    address at the fixed port 10514 (firefly.c:146-162).  The test binds that
    port itself, which is the only way to observe it."""

    @_needs_nginx
    def test_on_reports_to_the_client_as_well_as_the_collector(self, pmark):
        response, rows, delta, origin = pmark.measure(
            lambda: pmark.get(ORIGIN[ON]), origin=True)
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert _states(origin) == ["end", "start"], origin
        assert {(app, exp, act) for app, _, exp, act in origin} == \
            {("arm-oron", EXP, ACT)}, origin
        assert delta[STARTED] == 1.0, delta

    @_needs_nginx
    def test_off_reports_only_to_the_collector(self, pmark):
        response, rows, delta, origin = pmark.measure(
            lambda: pmark.get(ORIGIN[OFF]), origin=True)
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert origin == [], origin
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta

    @_needs_nginx
    def test_absent_reports_only_to_the_collector(self, pmark):
        """`firefly_origin` merges to 0 (config.c:46)."""
        _, rows, delta, origin = pmark.measure(
            lambda: pmark.get(ORIGIN[ABSENT]), origin=True)
        assert _states(rows) == ["end", "start"], rows
        assert origin == [], origin
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta

    @_needs_nginx
    def test_the_origin_copy_is_never_counted(self, pmark):
        """DEFECT CANDIDATE #73.  Four datagrams leave the box and the
        exposition reports two: the origin sendto's return value is discarded
        (firefly.c:158-161), so neither firefly_sent_total nor
        firefly_dropped_total sees it."""
        _, rows, delta, origin = pmark.measure(
            lambda: pmark.get(ORIGIN[ON]), origin=True)
        assert len(rows) == 2 and len(origin) == 2, (rows, origin)
        assert delta[SENT] == 2.0, \
            f"sent_total counted the origin copies — DEFECT #73 was fixed: {delta}"
        assert DROPPED not in delta, delta

    @_needs_nginx
    def test_a_client_that_is_not_listening_is_invisible(self, pmark):
        """#73's other half, and the arm an operator actually runs: nothing is
        bound on the client's 10514, so both origin datagrams go nowhere.  The
        transfer succeeds, the collector still gets its pair, and the exposition
        shows no drop at all — there is no signal anywhere that half the
        configured reporting is failing."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(ORIGIN[ON]))
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta
        assert _origin_diagnostics(pmark.log) == [], \
            "the origin leg is reported after all — DEFECT #73 was fixed"


# --------------------------------------------------------------------------- #
# §F — brix_pmark_flowlabel: the in-band IPv6 technique                        #
# --------------------------------------------------------------------------- #

def _probe_declined(log):
    """Did this worker's one-time capability probe get refused?  That is the only
    thing that can make an IPv6 flow attempt no lease at all, and it is reported
    nowhere except the log (DEFECT #74).  §H pins the message text, so this
    predicate cannot quietly become always-false."""
    return PROBE_NOTICE in log


def _settle_for_a_clean_probe():
    """Wait out the previous test's probe lease before provoking this one.

    Each instance in this file is fresh (the lifecycle fixture is per-test), so
    each one probes, and each probe leaves an exclusive kernel entry on the one
    fixed label that outlives the worker by several seconds — DEFECT #74's
    collision, reproduced by the test file itself.  Measured on this host: the
    entry is still held at 6s and free at 10s.

    The wait is a flat sleep and NOT a poll, because a REFUSED lease refreshes
    the blocking entry's lifetime (the kernel's fl_release() stamps lastuse on
    the EPERM path), so a loop that checks whether the label is free is the one
    thing guaranteed to keep it busy.
    """
    time.sleep(FL_SETTLE)


def _hold_the_probe_label():
    """Occupy the exact label the server's capability probe asks for, so that the
    probe is refused with EPERM for certain rather than by luck.

    Returns the holding socket.  A lingering entry from an earlier pmark worker
    is the same poison and can expire mid-test, so a refusal is retried — but
    exactly ONCE, after a full settle, and never in a loop: a refused lease
    refreshes the blocking entry, so a retry loop is the one thing certain to
    keep the label busy for as long as it runs.
    """
    holder = _lease(PROBE_LABEL)
    if not isinstance(holder, socket.socket):
        _settle_for_a_clean_probe()
        holder = _lease(PROBE_LABEL)
    if not isinstance(holder, socket.socket):
        pytest.skip(f"cannot occupy the probe label 0x{PROBE_LABEL:05x}: {holder}")
    return holder


def _origin_diagnostics(log):
    """Log lines that say anything about the origin firefly leg.

    Deliberately generous — any pmark line naming the fixed origin port, the
    word `origin`, or a send failure counts — so that DEFECT #73's "there is no
    signal anywhere" claim fails the moment a signal is added.
    """
    return [line for line in log.splitlines()
            if "pmark" in line and (str(ORIGIN_PORT) in line
                                    or "origin" in line
                                    or "sendto" in line)]


@_needs_ipv6
class TestTheFlowLabel:
    """The REQUIRED SciTags technique, and the one whose `off` arm was never
    written.  Every test here dials the IPv6 loopback: brix_pmark_flowlabel_apply
    declines an AF_INET or v4-mapped peer before it touches the kernel
    (flowlabel.c:166-174), so over 127.0.0.1 the flag has no observable arm."""

    @_needs_nginx
    def test_off_never_leases_a_label_and_the_on_arm_next_door_does(self, pmark):
        """The pair, inside ONE worker.  The off leg is exact: neither flow-label
        counter moves, while the firefly plane is untouched.  The on leg is the
        control that says the off leg's silence was the flag and not the host —
        and it has to allow for a refused probe, because the probe leases a fixed
        label exclusively and any other holder on the machine wins it (#74)."""
        _, rows, off_delta, _ = pmark.measure(
            lambda: pmark.get(FLOWLABEL[OFF], host=HOST6))
        assert _states(rows) == ["end", "start"], rows
        assert FL_SET not in off_delta and FL_FAILED not in off_delta, off_delta
        assert off_delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, off_delta
        assert not _probe_declined(pmark.log), \
            "the off arm probed the capability it was told not to use"

        _settle_for_a_clean_probe()
        _, rows, on_delta, _ = pmark.measure(
            lambda: pmark.get(FLOWLABEL[ON], host=HOST6))
        assert _states(rows) == ["end", "start"], rows
        attempted = on_delta.get(FL_SET, 0.0) + on_delta.get(FL_FAILED, 0.0)
        assert attempted == 1.0 or _probe_declined(pmark.log), (
            f"the on arm neither leased a label nor logged a refused probe: "
            f"{on_delta}")

    @_needs_nginx
    def test_absent_leases_a_label_like_the_on_arm(self, pmark):
        """`flowlabel` merges to 1 (config.c:44), so `base` — which writes none
        of the six — is the on arm by default."""
        _settle_for_a_clean_probe()
        _, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FLOWLABEL[ABSENT], host=HOST6))
        assert _states(rows) == ["end", "start"], rows
        attempted = delta.get(FL_SET, 0.0) + delta.get(FL_FAILED, 0.0)
        assert attempted == 1.0 or _probe_declined(pmark.log), delta

    @_needs_nginx
    def test_an_ipv4_peer_never_reaches_a_lease(self, pmark):
        """The fail-open family gate.  Over IPv4 the on arm leases nothing — not
        a label, not a failure — because getpeername reports AF_INET and apply()
        declines (flowlabel.c:166-171).  A v4-only site therefore sees a flag
        with no effect on the counters.

        It does NOT see a flag with no effect at all: see the next test."""
        response, rows, delta, _ = pmark.measure(
            lambda: pmark.get(FLOWLABEL[ON]))
        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert FL_SET not in delta and FL_FAILED not in delta, delta

    @_needs_nginx
    def test_an_ipv4_peer_still_triggers_the_capability_probe(self, pmark):
        """DEFECT CANDIDATE #76.  ``brix_pmark_flowlabel_apply`` calls
        ``brix_pmark_flowlabel_usable`` in the SAME condition as its fd check —
        before getpeername and therefore before it knows the peer's family
        (flowlabel.c:158-160).  An IPv4 request on a v4-only deployment thus
        performs the whole probe: a socket, an EXCLusive kernel lease of the one
        fixed label, and — when that lease is refused — a NOTICE about a
        technique that could not have applied to this connection anyway.

        Held deterministic by occupying the label first, so the refusal is
        certain and the NOTICE is proof the probe ran.  ``apply_addr``, the
        libcurl/TPC entry point, orders the same two checks the other way
        (flowlabel.c:185-189) — one function short-circuits on family, its
        sibling does not, which is what marks this a defect rather than a
        deliberate order.  §H pins both orders.
        """
        holder = _hold_the_probe_label()
        try:
            response, rows, delta, _ = pmark.measure(
                lambda: pmark.get(FLOWLABEL[ON]))
        finally:
            holder.close()

        assert response.status_code == 200, response.text[:200]
        assert _states(rows) == ["end", "start"], rows
        assert FL_SET not in delta and FL_FAILED not in delta, delta
        assert _probe_declined(pmark.log), (
            "an IPv4 request no longer probes the IPv6 capability — DEFECT #76 "
            f"was fixed:\n{pmark.log[-2000:]}")

    @_needs_nginx
    def test_the_off_arm_does_not_probe_over_ipv4_either(self, pmark):
        """The control for #76, and a security-adjacent one: with the flag off,
        nothing about the connection can make brix touch the flow-label manager,
        so an operator who disables the technique really does stop brix asking
        the kernel for CAP_NET_ADMIN-shaped capabilities."""
        holder = _hold_the_probe_label()
        try:
            response, _, delta, _ = pmark.measure(
                lambda: pmark.get(FLOWLABEL[OFF]))
        finally:
            holder.close()

        assert response.status_code == 200, response.text[:200]
        assert FL_SET not in delta and FL_FAILED not in delta, delta
        assert not _probe_declined(pmark.log), \
            f"the off arm probed anyway:\n{pmark.log[-2000:]}"

    @_needs_nginx
    def test_a_blocked_probe_degrades_to_firefly_only(self, pmark):
        """DEFECT CANDIDATE #74, made deterministic: the test holds the exact
        label the probe asks for, so the probe's setsockopt is refused with
        EPERM for the whole life of this worker.

        What the operator gets is a working server with the REQUIRED in-band
        technique silently off: the transfer succeeds, the firefly plane is
        unaffected, no flow-label counter moves in either direction — a refused
        probe never reaches the increment at flowlabel.c:134 — and the only
        evidence anywhere is one NOTICE.
        """
        holder = _hold_the_probe_label()
        try:
            response, rows, delta, _ = pmark.measure(
                lambda: pmark.get(FLOWLABEL[ON], host=HOST6))
        finally:
            holder.close()

        assert response.status_code == 200, response.text[:200]
        assert response.content == PAYLOAD
        assert _states(rows) == ["end", "start"], rows
        assert delta == {STARTED: 1.0, ENDED: 1.0, SENT: 2.0}, delta
        assert _probe_declined(pmark.log), \
            f"a refused probe was not reported at all:\n{pmark.log[-2000:]}"

    @_needs_nginx
    def test_the_label_space_is_thirty_two_wide_per_activity(self, pmark):
        """DEFECT CANDIDATE #75.  Five entropy bits and an exclusive lease give
        one (experiment, activity) pair exactly 32 labels, each held by its
        connection.  Forty flows are held open at once, so the ceiling is
        arithmetic: at most 32 can be stamped and at least 8 must be refused.

        Measured on this host: 22 stamped, 18 refused — the refusals start at the
        second flow rather than at the 33rd, because the entropy is drawn with
        replacement.  Every one of the forty transfers still completes, which is
        why the ceiling is invisible without this counter.
        """
        _settle_for_a_clean_probe()
        sessions = []
        try:
            before = pmark.metrics()
            codes = set()
            for _ in range(FL_FLOWS):
                session = requests.Session()
                sessions.append(session)
                codes.add(pmark.get(FLOWLABEL[ON], host=HOST6,
                                    session=session).status_code)
            after = pmark.metrics()
        finally:
            for session in sessions:
                session.close()

        delta = _delta(before, after)
        def _assert_test_the_label_space_is_thirty_two_wide_per_activity_1():
            assert codes == {200}, codes
            assert delta[STARTED] == float(FL_FLOWS), delta

        _assert_test_the_label_space_is_thirty_two_wide_per_activity_1()
        attempted = delta.get(FL_SET, 0.0) + delta.get(FL_FAILED, 0.0)
        if attempted == 0.0:
            _check_test_the_label_space_is_thirty_two_wide_per_activity_1(delta, pmark)
            pytest.skip("this worker's flow-label probe was refused (DEFECT "
                        "#74), so the label space cannot be exercised here")
        def _assert_test_the_label_space_is_thirty_two_wide_per_activity_2():
            assert attempted == float(FL_FLOWS), \
                f"a marked IPv6 flow neither stamped nor failed: {delta}"
            assert delta.get(FL_SET, 0.0) <= FL_SPACE, \
                f"more labels than the entropy mask can spell: {delta}"

        _assert_test_the_label_space_is_thirty_two_wide_per_activity_2()
        _check_test_the_label_space_is_thirty_two_wide_per_activity_2(delta)


@_needs_ipv6
def test_the_kernel_admits_one_exclusive_holder_per_label():
    """The mechanism behind #74 and #75, and the cure, in four setsockopt calls.

    Nothing brix-side runs here: this pins the kernel behaviour the two findings
    rest on, so a future reader can tell "the label was scarce" from "brix asked
    for it to be scarce".  IPV6_FL_S_EXCL admits exactly one holder; the shares
    brix does not use admit four.
    """
    exclusive = _expression_1()
    try:
        held = _expression_2(exclusive)
        _check_test_the_kernel_admits_one_exclusive_holder_per_label_3(held, exclusive)
    finally:
        for sock in exclusive:
            _guard_test_the_kernel_admits_one_exclusive_holder_per_label_1(sock)

    shared = _expression_3()  # S_USER
    try:
        held = _expression_4(shared)
        _check_test_the_kernel_admits_one_exclusive_holder_per_label_4(held, shared)
    finally:
        for sock in shared:
            _guard_test_the_kernel_admits_one_exclusive_holder_per_label_2(sock)


# --------------------------------------------------------------------------- #
# §G — the parse tier                                                          #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, *, knobs="", srv="", http="", outer="", stream="",
           stream_main=""):
    """`nginx -t` the scaffold with one slot filled.

    Every slot is rendered with a trailing newline and the scaffold's own
    indentation, so a filled slot reads like the line an operator would type.
    """
    def _block(text, indent):
        if not text:
            return ""
        return "".join(f"{indent}{line}\n" for line in text.splitlines())

    return nginx_t(
        "nginx_audit16gparse.conf", tmp_path,
        PORT=SHARED_PARSE_PLACEHOLDER_PORT,
        STREAM_PORT=PARSE_PLACEHOLDER_PORT,
        LOG_DIR=str(tmp_path),
        DATA=str(tmp_path),
        KNOBS=_block(knobs, " " * 12),
        SRV_KNOBS=_block(srv, " " * 8),
        HTTP_KNOBS=_block(http, " " * 4),
        OUTER=_block(outer, ""),
        STREAM_KNOBS=_block(stream, " " * 8),
        STREAM_MAIN=_block(stream_main, " " * 4))


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("value", ["on", "off"])
def test_both_arms_parse_in_a_webdav_location(tmp_path, name, value):
    """The pair at parse level, for all six.  This is the claim the audit's
    step-2 measurement says nothing in the corpus had ever made: the word
    ``off``, written out, for a directive whose OFF behaviour had only ever been
    reached by leaving it out — or, for the three that default to 1, never
    reached at all."""
    result = _parse(tmp_path, knobs=f"{name} {value};")
    assert result.returncode == 0, f"{name} {value} was refused:\n{result.stderr}"


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("value", ["on", "off"])
def test_both_arms_parse_in_a_stream_server(tmp_path, name, value):
    """The same six names on the root:// plane.  They are one X-macro
    (directives.h) instantiated twice, and this is the half a WebDAV-only test
    would never touch: NGX_STREAM_SRV_CONF, a different command table and a
    different conf type."""
    result = _parse(tmp_path, stream=f"{name} {value};")
    assert result.returncode == 0, \
        f"{name} {value} was refused on the stream plane:\n{result.stderr}"


@_needs_nginx
def test_the_documented_firefly_only_stream_recipe_parses(tmp_path):
    """The one place the corpus already wrote an ``off`` arm was documentation:
    docs/10-reference/comparison/deployment-reference.md offers a root:// server
    with ``brix_pmark_flowlabel off`` as "Firefly-only parity with stock
    XRootD".  It is the advertised way to run the feature and nothing executed
    it, on either plane, until this file — so the recipe is pinned as a whole
    rather than only as four independent directives."""
    result = _parse(tmp_path, stream="brix_pmark on;\n"
                                     "brix_pmark_firefly on;\n"
                                     "brix_pmark_scitag_cgi on;\n"
                                     "brix_pmark_flowlabel off;")
    assert result.returncode == 0, \
        f"the documented firefly-only recipe was refused:\n{result.stderr}"


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("value", ["maybe", "1", "0", "yes", "true", '""'])
def test_a_non_boolean_value_is_refused(tmp_path, name, value):
    """ngx_conf_set_flag_slot accepts the two words and nothing else.  ``1``,
    ``0``, ``yes`` and ``true`` are the spellings an operator brings from other
    software, and every one of them is an error rather than a silent truth
    value — which matters most for ``0``, where a silent truthy read would turn
    an intended disable into an enable."""
    result = _parse(tmp_path, knobs=f"{name} {value};")
    assert result.returncode != 0, f"{name} {value} was accepted"
    assert "invalid value" in result.stderr, result.stderr


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("value", ["ON", "OFF", "On", "oFf"])
def test_the_two_words_are_matched_case_insensitively(tmp_path, name, value):
    """ngx_conf_set_flag_slot compares with ngx_strcasecmp, so ``OFF`` is a legal
    spelling of the arm this tranche says was never written.

    Pinned rather than assumed, because it is what makes the audit's step-2
    measurement a case-insensitive grep: had it been case-sensitive, a corpus
    that wrote ``OFF`` would have been scored as never writing the off arm and
    this whole file would rest on a miscount.
    """
    result = _parse(tmp_path, knobs=f"{name} {value};")
    assert result.returncode == 0, f"{name} {value} was refused:\n{result.stderr}"


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("args", ["", "on off"],
                         ids=["no-argument", "two-arguments"])
def test_the_wrong_arity_is_refused(tmp_path, name, args):
    line = f"{name} {args};".replace("  ", " ")
    result = _parse(tmp_path, knobs=line)
    assert result.returncode != 0, f"`{line}` was accepted"
    assert "invalid number of arguments" in result.stderr, result.stderr


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
def test_writing_the_same_flag_twice_is_refused(tmp_path, name):
    """The duplicate diagnostic is what makes the scaffold carry none of the six
    itself: it arrives before any value or arity error would."""
    result = _parse(tmp_path, knobs=f"{name} on;\n{name} off;")
    assert result.returncode != 0, f"{name} was accepted twice"
    assert "is duplicate" in result.stderr, result.stderr


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("slot", ["srv", "http", "outer", "stream_main"])
def test_the_wrong_context_is_refused(tmp_path, name, slot):
    """NGX_HTTP_LOC_CONF on the http plane and NGX_STREAM_SRV_CONF on the stream
    plane: a server-level http placement, an http-level placement, the main
    context and a stream-level placement are all wrong, and each is diagnosed
    rather than inherited.  The main-context case is the one that reads
    differently — the directive is not merely misplaced, it is unknown before any
    module's command table is in scope."""
    result = _parse(tmp_path, **{slot: f"{name} on;"})
    assert result.returncode != 0, f"{name} was accepted in the {slot} context"
    assert ("not allowed here" in result.stderr
            or "unknown directive" in result.stderr), result.stderr


# --------------------------------------------------------------------------- #
# §H — the mechanism is where this file says it is                             #
# --------------------------------------------------------------------------- #

def _source(path):
    return path.read_text(encoding="utf-8")


def _flat(path):
    """Whitespace-flattened source, so a call that wraps across lines reads the
    same as one that does not."""
    return " ".join(_source(path).split())


class TestTheMechanismIsWhereThisFileSaysItIs:

    @pytest.mark.parametrize("name,field,default", FLAGS, ids=FLAG_NAMES)
    def test_every_flag_merges_to_its_measured_default(self, name, field,
                                                       default):
        """The claim every ``absent`` arm in this file rests on — including the
        three that default to 1, where ``absent`` is the ON arm and the
        never-written ``off`` is the only way to the other behaviour."""
        call = f"ngx_conf_merge_value(conf->{field}, prev->{field}, {default});"
        assert call in _flat(CONFIG_C), \
            f"{name} no longer merges to {default} — expected {call}"

    @pytest.mark.parametrize("name,field,_default", FLAGS, ids=FLAG_NAMES)
    def test_every_flag_is_a_plain_flag_slot_in_the_x_macro(self, name, field,
                                                           _default):
        """The tranche's subject is the 128 ``ngx_conf_set_flag_slot``
        directives; a setter of its own would put the directive in a different
        measurement and give it config-time behaviour this file never probed."""
        entry = _flat(DIRECTIVES_H).split(f'ngx_string("{name}")')[1].split("},")[0]
        assert "ngx_conf_set_flag_slot" in entry, entry
        assert "conf_scope | NGX_CONF_FLAG" in entry, entry
        assert f"common.pmark.{field}" in entry, entry

    def test_the_six_are_declared_once_and_instantiated_twice(self):
        """Why §G asks about two planes.  If a third table ever instantiates the
        macro, this file's parse tier is short by a plane."""
        instantiations = sorted(
            path.name for path in ROOT.joinpath("src").rglob("*.h")
            if "BRIX_PMARK_DIRECTIVES(NGX_" in path.read_text(encoding="utf-8"))
        assert instantiations == ["directives_pmark.h", "directives_zones.h"], \
            instantiations
        source = _flat(DIRECTIVES_H)
        assert source.count("#define BRIX_PMARK_DIRECTIVES(") == 1

    def test_the_end_counter_sits_behind_the_firefly_gate(self):
        """DEFECT #72's mechanism.  The start increment is outside every gate and
        the end increment is inside the firefly one."""
        source = _flat(FIREFLY_C)
        assert "BRIX_PMARK_METRIC_INC(pmark_flows_started_total); return f; }" \
            in source, "the start counter moved out of flow_begin's tail"
        assert "if (flow->firefly_started && flow->pm->firefly) { " \
               'pmark_emit(flow, "end", 1, log); ' \
               "BRIX_PMARK_METRIC_INC(pmark_flows_ended_total);" in source, \
            "flow_end's gate changed — DEFECT #72 has to be re-measured"

    def test_the_origin_send_discards_its_result(self):
        """DEFECT #73's mechanism: one sendto is counted both ways, the other is
        cast to void."""
        source = _flat(FIREFLY_C)
        assert "(void) sendto(fd, buf, n, 0, (struct sockaddr *) &o, f->peer_len);" \
            in source, "the origin sendto now has a return path"
        assert "BRIX_PMARK_METRIC_INC(pmark_firefly_dropped_total);" in source
        assert source.count("BRIX_PMARK_METRIC_INC(pmark_firefly_sent_total);") == 1

    def test_the_probe_leases_one_fixed_label_exclusively_and_caches_it(self):
        """DEFECT #74's mechanism, in four lines of flowlabel.c: the label is a
        constant, the share is exclusive, the verdict is a per-worker static, and
        nothing retries it."""
        source = _flat(FLOWLABEL_C)
        assert "fl.flr_label = htonl(brix_pmark_flowlabel_encode(" \
               "BRIX_PMARK_EXP_MIN, BRIX_PMARK_ACT_MIN));" in source, \
            "the probe's label is no longer the structural minimum"
        assert "fl.flr_share = PMARK_FL_S_EXCL;" in source
        assert "static int pmark_fl_usable = -1;" in source
        assert source.count("pmark_fl_usable = 0;") == 1
        assert "#define PMARK_FL_S_EXCL 1" in source
        assert PROBE_NOTICE in source, \
            "the probe's NOTICE was reworded, so _probe_declined is now blind"

    def test_the_two_entry_points_order_the_probe_differently(self):
        """DEFECT #76's mechanism, as a pair of orders rather than a claim.

        apply() puts the capability probe in the same condition as its fd check,
        so it runs before getpeername tells anyone the peer's family; apply_addr()
        tests the family first and short-circuits, so a v4 destination never
        probes.  One of the two is wrong, and the tests above say which behaviour
        each order produces.
        """
        source = _flat(FLOWLABEL_C)
        assert "if (fd < 0 || brix_pmark_flowlabel_usable(log) != NGX_OK) { " \
               "return NGX_DECLINED; } " in source, \
            "apply()'s probe is no longer ahead of the family gate"
        assert "|| dst->sa_family != AF_INET6 " \
               "|| brix_pmark_flowlabel_usable(log) != NGX_OK)" in source, \
            "apply_addr() no longer short-circuits on family before probing"

    def test_the_per_flow_label_carries_five_entropy_bits(self):
        """DEFECT #75's mechanism: the mask decides how many labels one
        (experiment, activity) pair can ever spell, and the exclusive share
        decides that each is spelled once."""
        assert f"#define BRIX_PMARK_FL_ENTROPY_MASK 0x{FL_ENTROPY_MASK:08X}u" \
            in _flat(PMARK_H)
        assert bin(FL_ENTROPY_MASK).count("1") == 5
        source = _flat(FLOWLABEL_C)
        assert "label = brix_pmark_flowlabel_encode(exp, act) " \
               "| ((uint32_t) ngx_random() & BRIX_PMARK_FL_ENTROPY_MASK);" in source
        assert source.count("fl.flr_share = PMARK_FL_S_EXCL;") == 2

    def test_a_copy_is_marked_without_consulting_http_plain(self):
        """§D's mechanism: the method test short-circuits for COPY before
        http_plain is read."""
        assert "if (!conf->common.pmark.enable || (r->method != NGX_HTTP_COPY " \
               "&& !(conf->common.pmark.http_plain && (r->method == NGX_HTTP_GET " \
               "|| r->method == NGX_HTTP_PUT))))" in _flat(DISPATCH_C), \
            "webdav_dispatch_pmark's method gate changed"
