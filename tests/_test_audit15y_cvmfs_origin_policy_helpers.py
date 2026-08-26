"""The CVMFS origin-policy enums at VALUE granularity — audit §Method, 15th tranche.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the
measurement per (directive, VALUE) over the 36 ``ngx_conf_enum_t`` tables in
``src/`` turned 93 pairs into 48 written and 45 never written.  Three of those
45 belong to the CVMFS origin-policy trio, and between them they are the whole
of two directives:

    brix_cvmfs_fill_retry_policy   failover       NEVER written
                                   force-primary  written (the resilience corpus)
    brix_cvmfs_geo_answer          off            NEVER written
                                   rtt            written (the geo corpus)
    brix_cvmfs_origin_http_version 1.1            NEVER written
                                   2, 2-direct, 3 written (test_cvmfs_http2_origin.py)

All three are declared ``NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|
NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1`` (protocols/cvmfs/directives_resilience.h:
100, 107, 116), so an operator reads all three as per-location.  Every suite
that writes them writes them in a config with exactly ONE cvmfs location, which
is the one shape in which that reading cannot be wrong.

WHAT THE VALUE SELECTS
----------------------
Two of the three are merged into a PROCESS-wide global, once per cvmfs-enabled
location, in cvmfs_module_merge.c:

    :264  brix_s3_origin_http_version_set((int) conf->cvmfs.origin_http_version)
          — unconditional for every cvmfs-enabled location, into
          fs/cache/origin/s3_transport_setup.c's ``static int
          g_origin_http_version``.

    :271  if (conf->cvmfs.fill_retry_policy == BRIX_CVMFS_RETRY_FORCE_PRIMARY)
              sd_http_force_primary_set(1);
          — with NO else, into fs/backend/http/sd_http_select.c's
          ``g_sd_http_force_primary``.  ``sd_http_force_primary_set`` has
          exactly one caller in the tree and it passes 1 (§C pins this), so
          nothing can ever clear the latch.

The third is not merged into anything: ``brix_cvmfs_geo_answer`` is read off
``lcf->cvmfs.geo_answer`` at REQUEST time (gate.c:422).  It is the control that
makes the other two a defect rather than a house style — the same file, the
same request, one directive honest and two not.

WHAT THE TABLE ESTABLISHES
--------------------------
Two repositories exported side by side (the ordinary shape of a Stratum-1
cache) on ONE listener, filling from ONE HTTP/1.x-only mock Stratum-1.
Measured, ``/cvmfs/<repo>/.cvmfspublished`` through each location in turn:

    location A     location B     A          B          negotiated proto
    1.1            -              200        -          1.0
    2-direct       -              504        -          (no connection)
    1.1            2-direct       504        504        (no connection)
    2-direct       1.1            200        200        1.0, 1.0
    2-direct       (silent)       200        200        1.0, 1.0
    (silent)       2-direct       504        504        (no connection)

and, over a DEAD|LIVE origin set, counting the sd_http line "http origin
request exhausted all endpoints":

    location A     location B     A status   A exhausted-lines
    (silent)       -              200        0
    failover       -              200        0
    force-primary  -              504        >0
    failover       (silent)       200        0
    failover       force-primary  504        >0

and, for the control, counting geo requests that actually reached the origin:

    location A     location B     A                  B
    off            -              200, origin hit    -
    rtt            -              200, origin quiet  -
    off            rtt            200, origin hit    200, origin quiet
    rtt            off            200, origin quiet  404, origin hit

FINDING — DEFECT CANDIDATE #57
------------------------------
``brix_cvmfs_origin_http_version`` is a location-level directive that is not
per-location.  The last cvmfs location merged decides the origin HTTP version
for the whole worker, and the three consequences are all silent:

(a) A location's own value is discarded whenever another cvmfs location is
    merged after it — even when the value it wrote is the one that works.
(b) A location that never mentions the directive is not neutral.  Its
    ``NGX_CONF_UNSET_UINT`` merges to 0 and is written to the global like any
    other value, so adding a second, unrelated repository export with no
    opinion at all silently reverts the first one's policy (row 5).
(c) The reverse is worse and is the row an operator will actually hit: adding a
    repository that needs ``2-direct`` forces every OTHER repository onto h2c
    prior knowledge, and against an HTTP/1.x origin every one of them stops
    serving (row 6).  The export that broke is not the export that was edited.

Nothing is said at parse time (§D) and nothing distinguishes it at run time:
the trace line reports the version that was actually negotiated, never the one
this location asked for.

RETRY-POLICY CONTRACT
---------------------
``force-primary`` selects the rank-preferred endpoint and never uses an
alternate after its transport failure.  The retry cases below use the ``static``
selector so the configured DEAD|LIVE order is deterministic: failover serves
the live alternate, while force-primary retries the dead configured primary
until the bounded client hold returns 504.  A force-primary sibling still
enables the process-global latch, so a nominally failover location follows the
same fail-closed path.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
The BEHAVIOUR of ``brix_cvmfs_origin_http_version`` has an owner:
test_cvmfs_http2_origin.py measures ``2`` falling back to HTTP/1.1, ``2-direct``
against a genuine h2c origin, and the ``3``-without-an-H3-libcurl config
refusal.  What is measured here is the per-location claim that file has no
reason to make, plus the one token (``1.1``) it does not write.  The geo
passthrough-vs-rtt mechanism belongs to the Phase-84 geo corpus
(_test_cvmfs_conformance_srv_geo_helpers.py); ``off`` appears here only as the
never-written token and as the honest control.  Endpoint health scoring, rank
decay and the T11 failover machinery belong to the resilience corpus.
"""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
import requests

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from lib_py.util import pids_on_port
from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST, NGINX_BIN

# conftest chdir()s into a scratch dir — anchor the mock import on this file.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))
from mock_stratum1 import make_repo, manifest      # noqa: E402

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15y-cvpolicy")]

NAME = "lc-audit15y-cvpolicy"
MOCK_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["MOCK_PORT"]
# Reserved in the ledger and never bound by anything — the unreachable half of
# the origin set §C reads the retry policy over.
DEAD_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["DEAD_PORT"]
ROOT = Path(__file__).resolve().parents[1]
MOCK_SCRIPT = ROOT / "tests/cvmfs/mock_stratum1.py"

# Two repositories, because one location cannot show a process-global.  Only
# REPO_A is the mock's own repo: its geo endpoint answers for that name alone,
# which is what makes the relayed geo request for REPO_B a visible 404 in §B.
REPO_A, REPO_B = "alpha.cern.ch", "beta.cern.ch"
MANIFEST = ".cvmfspublished"
# The mock's geo endpoint takes a comma-separated server list and answers with
# their 1-based order; two names keep the expected body short and stable.
#
# The names are RFC-6761 `.invalid` hostnames (unresolvable on every host) on
# PURPOSE: the `rtt` policy answers locally by measuring TCP-connect RTT to each
# listed server (geo_answer.c) and ranking nearest-first, falling back to the
# client's original order for servers it cannot reach.  Real Stratum-1 hostnames
# made this test non-hermetic — on a network-isolated box both are unreachable
# so the order is preserved (`1,2`), but on an internet-connected box the probe
# succeeds and returns the honest real-network permutation (e.g. `2,1` when the
# BNL S1 answers faster than CERN's), reddening a test that only ever asserts the
# order-preserving `1,2`.  Unresolvable names keep every server in the
# order-preserving "unreachable" bucket, so the local answer is a stable `1,2`
# everywhere while still exercising the full parse→probe→rank path.  The `off`
# policy relays to the mock, which echoes the 1-based order regardless of names,
# so it stays `1,2` too.
GEO_PATH = ("api/v1.0/geo/x/"
            "s1-alpha.cvmfs.invalid,s1-beta.cvmfs.invalid")
GEO_BODY = b"1,2\n"

# The three enum tables, verbatim from protocols/cvmfs/module.c:338-356.
RETRY_TOKENS = ("failover", "force-primary")
GEO_TOKENS = ("off", "rtt")
# `3` is in the table but is refused at nginx -t on any box whose libcurl has no
# HTTP/3 backend — that refusal is test_cvmfs_http2_origin.py's contract, not
# this file's, so the parse tier here sweeps the three that are speakable.
HTTPV_TOKENS = ("1.1", "2", "2-direct")

# sd_http_select.c:395 — written once per read attempt that ran out of
# endpoints, which under force-primary is every attempt against a dead primary.
EXHAUSTED = "exhausted all endpoints"
FILL_RETRY = "xrootd-fill: event=retry"


# --------------------------------------------------------------------------- #
# The origin                                                                   #
# --------------------------------------------------------------------------- #

class _Mock:
    """The mock Stratum-1 plus the two questions this file asks it: what it was
    asked for, and (via reset) what it was asked for since a moment ago."""

    def __init__(self, proc, port):
        self.proc = proc
        self.port = port

    def _ctl(self, endpoint, method="GET"):
        request = urllib.request.Request(
            f"http://{HOST}:{self.port}/ctl/{endpoint}", method=method,
            data=b"" if method == "POST" else None)
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read()
        return json.loads(body) if body.startswith((b"[", b"{")) else body

    def paths(self):
        return [entry["path"] for entry in self._ctl("log")]

    def geo_hits(self):
        """Geo requests that actually reached the origin.  `off` is documented
        as relaying to the origin and `rtt` as answering locally, and both
        answer 200 for a repo the mock serves — so the origin's own log is the
        only thing that tells the two apart."""
        return [path for path in self.paths() if "/geo/" in path]

    def reset(self):
        self._ctl("reset-log", method="POST")


def _forge(root):
    """Both repositories on disk in the layout the mock serves from a webroot:
    the signed manifest plus a few CAS objects each."""
    for repo in (REPO_A, REPO_B):
        paths = {f"/cvmfs/{repo}/{MANIFEST}": manifest(repo, 1)}
        paths.update(make_repo(repo, 3, seed=7))
        for url_path, body in paths.items():
            target = root / url_path.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
    return root


def _listening(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((HOST, port), 0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def _holders(port):
    """Who is listening on a fixed ledger port, named rather than numbered.

    Both port assertions below say something about occupancy, and neither is
    actionable without knowing who the occupant was — the ledger's whole claim
    is that on this lane it can only be this file's own mock.
    """
    named = []
    for pid in pids_on_port(port):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                argv = handle.read().replace(b"\0", b" ").decode(
                    "utf-8", "replace").strip()
        except OSError:
            argv = "(gone)"
        named.append(f"{pid} {argv[:120]}")
    return "; ".join(named) or "nobody"


def _tail(path, limit=2000):
    try:
        with open(path, "rb") as handle:
            return handle.read()[-limit:].decode("utf-8", "replace")
    except OSError as exc:                       # pragma: no cover - diagnostic
        return f"(no mock log: {exc})"


@pytest.fixture
def mock(tmp_path):
    """The HTTP/1.x-only origin every fill in this file comes from.

    HTTP/1.x-only is the point, not a limitation: it is what makes the
    negotiated version visible as the difference between 200 and 504, and it is
    what an operator's Stratum-1 actually is.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    webroot = _forge(tmp_path / "webroot")
    # The origin's own output goes to a file rather than /dev/null: a mock that
    # exits before it listens takes the reason with it otherwise, and on a fixed
    # ledger port the reason is the whole diagnosis.
    log = tmp_path / "mock_stratum1.log"
    handle = open(log, "wb")
    try:
        proc = subprocess.Popen(
            [sys.executable, str(MOCK_SCRIPT), "--port", str(MOCK_PORT),
             "--repo", REPO_A, "--webroot", str(webroot)],
            stdout=handle, stderr=subprocess.STDOUT)
    finally:
        handle.close()
    try:
        assert _listening(MOCK_PORT), (
            f"mock Stratum-1 never listened on {MOCK_PORT} "
            f"(exit={proc.poll()}, holders={_holders(MOCK_PORT)})\n"
            f"{_tail(log)}")
        assert not _listening(DEAD_PORT, 0.5), (
            f"DEAD_PORT {DEAD_PORT} is bound by something — it is reserved in "
            "the lifecycle ledger precisely so nothing answers on it: "
            f"{_holders(DEAD_PORT)}")
        yield _Mock(proc, MOCK_PORT)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

LIVE = f"http://{HOST}:{MOCK_PORT}"
DEAD = f"http://{HOST}:{DEAD_PORT}"
# The retry policy is only readable over a set whose FIRST endpoint is dead:
# with a live primary there is nothing to fail over from.
DEAD_THEN_LIVE = f"{DEAD}|{LIVE}"


def _policy(*lines):
    """Location-level lines at the template's indentation."""
    return "".join(f"            {line}\n" for line in lines)


def _retry_policy(value=None):
    """A retry-policy arm with a stable, configured primary endpoint.

    ``force-primary`` means the rank-preferred origin, not merely the first
    member of an HTTP origin list.  These tests specifically measure a failed
    configured primary, so they use ``static`` selection and a short hold: the
    DEAD|LIVE order is observable without racing the startup RTT probe or
    spending the default 25 seconds on the intentional 504 cases.
    """
    lines = ["brix_cvmfs_origin_select static;",
             "brix_cvmfs_client_hold 4;"]
    if value is not None:
        lines.append(f"brix_cvmfs_fill_retry_policy {value};")
    return _policy(*lines)


def _start(lifecycle, tmp_path, *, policy_a="", policy_b=None, backend=LIVE):
    """Start the one- or two-location listener; `policy_b=None` means one.

    "no second location" and "a second location that says nothing" are
    different configurations and this file measures both, so the two are two
    templates rather than one template with an empty slot.
    """
    caches = {}
    for key in ("a", "b"):
        path = tmp_path / f"cache-{key}"
        path.mkdir(exist_ok=True)
        caches[key] = str(path)
    values = {"BIND_HOST": BIND_HOST, "REPO_A": REPO_A, "CACHE_A": caches["a"],
              "BACKEND": backend, "POLICY_A": policy_a}
    if policy_b is None:
        template = "nginx_audit15y_cvsolo.conf"
    else:
        template = "nginx_audit15y_cvpair.conf"
        values.update({"REPO_B": REPO_B, "CACHE_B": caches["b"],
                       "POLICY_B": policy_b})
    return lifecycle.start(NginxInstanceSpec(
        name=NAME, template=template, protocol="http",
        data_root=str(tmp_path / "data"), template_values=values,
        reason="audit-15y the cvmfs origin-policy enums at value granularity"))


def _fetch(endpoint, repo, path=MANIFEST, timeout=90):
    """One request through one location.  The timeout is generous because a
    location forced onto h2c prior knowledge against an HTTP/1.x origin does
    not fail fast — it exhausts the fill layer's retries first, and that
    latency is part of what the finding is about.

    A transport failure is re-raised carrying the instance's error log: it is
    the one outcome that lands BEFORE any assertion, so without this it is the
    one outcome whose evidence the teardown wipe destroys.
    """
    url = f"http://{HOST}:{endpoint.port}/cvmfs/{repo}/{path}"
    try:
        response = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        raise AssertionError(
            f"the listener did not answer GET /cvmfs/{repo}/{path} on port "
            f"{endpoint.port}: {exc!r}\n{_errlog(endpoint)}") from exc
    return response.status_code, response.content


# --------------------------------------------------------------------------- #
# The log                                                                      #
# --------------------------------------------------------------------------- #

def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(endpoint.prefix, "logs", "error.log")) as handle:
            return handle.read()
    except OSError:
        return "(error log unavailable)"


def _count(endpoint, needle):
    return sum(needle in line for line in _errlog(endpoint).splitlines())


def _protos(endpoint):
    """The HTTP versions the origin transport actually negotiated, in order.

    brix_cvmfs_trace writes one upstream line per origin request carrying
    proto=<v>.  An empty list is itself a reading: the fill never got a usable
    connection, which is what h2c prior knowledge against an HTTP/1.x origin
    looks like from here.
    """
    out = []
    for line in _errlog(endpoint).splitlines():
        if "cvmfs-trace: upstream GET" in line and "proto=" in line:
            out.append(line.rsplit("proto=", 1)[1].split()[0])
    return out


def _settle(seconds=0.5):
    """The fill runs on a worker thread and its last lines can land after the
    response body has already been read by the client."""
    time.sleep(seconds)


# --------------------------------------------------------------------------- #
# A. brix_cvmfs_origin_http_version — DEFECT CANDIDATE #57                     #
# --------------------------------------------------------------------------- #

