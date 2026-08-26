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

class TestTheOriginHttpVersionIsProcessGlobal:
    """A location-level directive whose value is decided by another location.

    Each test reads the SAME request through the SAME location; the only thing
    that changes between them is what a sibling location wrote.
    """

    def test_version_11_fills_over_http1(self, lifecycle, tmp_path, mock):
        """success: the token no config in the suite writes.

        ``1.1`` is what an operator pins when their Stratum-1 is behind
        something that mishandles h2c Upgrade, and until now nothing measured
        that it works.  The mock answers as HTTP/1.0 (BaseHTTPRequestHandler's
        default), so 1.0 is the honest negotiated token for a 1.x policy.
        """
        endpoint = _start(lifecycle, tmp_path,
                          policy_a=_policy("brix_cvmfs_origin_http_version 1.1;"))
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        assert status == 200, _errlog(endpoint)
        assert body, "an empty manifest is not a fill"
        protos = _protos(endpoint)
        assert protos and set(protos) <= {"1.0", "1.1"}, (
            f"1.1 negotiated something else: {protos}\n{_errlog(endpoint)}")

    def test_2direct_alone_cannot_fill_from_an_http1_origin(self, lifecycle,
                                                            tmp_path, mock):
        """error: h2c prior knowledge has no fallback, by design.

        This is the reading every other case in the class is taken against —
        the value is unambiguously wrong for this origin, and one location
        writing it fails one location.
        """
        endpoint = _start(
            lifecycle, tmp_path,
            policy_a=_policy("brix_cvmfs_origin_http_version 2-direct;"))
        status, _ = _fetch(endpoint, REPO_A)
        _settle()
        assert status == 504, f"expected a gateway timeout, got {status}"
        assert _protos(endpoint) == [], (
            "a proto was negotiated after all — the origin is no longer "
            f"HTTP/1.x-only\n{_errlog(endpoint)}")

    def test_a_sibling_location_takes_a_working_version_away(self, lifecycle,
                                                             tmp_path, mock):
        """DEFECT CANDIDATE #57(a).

        Location A writes ``1.1`` — the value that works here, proven by the
        first test in this class.  Location B, a different repository, writes
        ``2-direct``.  A stops serving.  Nothing about A changed.
        """
        endpoint = _start(
            lifecycle, tmp_path,
            policy_a=_policy("brix_cvmfs_origin_http_version 1.1;"),
            policy_b=_policy("brix_cvmfs_origin_http_version 2-direct;"))
        status_a, _ = _fetch(endpoint, REPO_A)
        status_b, _ = _fetch(endpoint, REPO_B)
        _settle()
        assert (status_a, status_b) == (504, 504), (
            "the locations no longer share one process-global HTTP version — "
            f"A={status_a} B={status_b}; #57 may be fixed\n{_errlog(endpoint)}")
        assert _protos(endpoint) == [], _errlog(endpoint)

    def test_the_last_location_merged_decides_for_both(self, lifecycle,
                                                       tmp_path, mock):
        """DEFECT CANDIDATE #57(a), the other order.

        The same two values, swapped.  Now BOTH locations serve — including the
        one that asked for h2c prior knowledge and was quietly given HTTP/1.x
        instead.  Config order, not location, is what selected the version.
        """
        endpoint = _start(
            lifecycle, tmp_path,
            policy_a=_policy("brix_cvmfs_origin_http_version 2-direct;"),
            policy_b=_policy("brix_cvmfs_origin_http_version 1.1;"))
        status_a, body_a = _fetch(endpoint, REPO_A)
        status_b, body_b = _fetch(endpoint, REPO_B)
        _settle()
        assert (status_a, status_b) == (200, 200), (
            f"A={status_a} B={status_b}\n{_errlog(endpoint)}")
        assert body_a and body_b
        protos = _protos(endpoint)
        assert protos and set(protos) <= {"1.0", "1.1"}, (
            "the 2-direct location was served over h2c after all — the global "
            f"is no longer last-merge-wins: {protos}")

    def test_a_location_that_says_nothing_overrides_one_that_does(self, lifecycle,
                                                                  tmp_path, mock):
        """DEFECT CANDIDATE #57(b): silence is not neutral.

        Location A pins ``2-direct``; location B mentions no version at all.
        B's unset value merges to 0 and is written to the global exactly like a
        chosen one, so A is served over HTTP/1.x — the policy it wrote is
        discarded by a location that expressed no policy.
        """
        endpoint = _start(
            lifecycle, tmp_path,
            policy_a=_policy("brix_cvmfs_origin_http_version 2-direct;"),
            policy_b="")
        status_a, _ = _fetch(endpoint, REPO_A)
        status_b, _ = _fetch(endpoint, REPO_B)
        _settle()
        assert (status_a, status_b) == (200, 200), (
            "the silent location no longer clobbers the explicit one — "
            f"A={status_a} B={status_b}; #57(b) may be fixed\n{_errlog(endpoint)}")
        protos = _protos(endpoint)
        assert protos and set(protos) <= {"1.0", "1.1"}, protos

    def test_a_location_that_says_nothing_is_forced_onto_h2c(self, lifecycle,
                                                             tmp_path, mock):
        """security-negative / DEFECT CANDIDATE #57(c): the blast radius.

        The same two locations in the other order.  Location A never mentions
        the directive — it is an existing, working repository export — and
        adding location B for a new repository that needs ``2-direct`` takes A
        down with it.  The export that stops serving is not the export that was
        edited, and nothing in the config names A.
        """
        endpoint = _start(
            lifecycle, tmp_path, policy_a="",
            policy_b=_policy("brix_cvmfs_origin_http_version 2-direct;"))
        status_a, _ = _fetch(endpoint, REPO_A)
        status_b, _ = _fetch(endpoint, REPO_B)
        _settle()
        assert (status_a, status_b) == (504, 504), (
            "an unrelated location no longer forces its version onto a silent "
            f"one — A={status_a} B={status_b}; #57(c) may be fixed\n"
            f"{_errlog(endpoint)}")
        assert _protos(endpoint) == [], _errlog(endpoint)


# --------------------------------------------------------------------------- #
# B. brix_cvmfs_geo_answer — the control                                       #
# --------------------------------------------------------------------------- #

class TestGeoAnswerIsHonestlyPerLocation:
    """The same trio's third directive, read at request time instead of merged.

    Every assertion here is what §A's assertions would have been if the version
    directive were per-location, which is the point of measuring it in the same
    file with the same origin.
    """

    def test_off_relays_the_geo_request_to_the_origin(self, lifecycle, tmp_path,
                                                      mock):
        """success: the token no config in the suite writes.

        ``off`` means "this cache does not answer geo itself" — the request is
        relayed to the Stratum-1, whose answer is returned verbatim.  The
        status alone cannot show that (``rtt`` answers 200 too), so the witness
        is the origin's own request log.
        """
        endpoint = _start(lifecycle, tmp_path,
                          policy_a=_policy("brix_cvmfs_geo_answer off;"))
        mock.reset()
        status, body = _fetch(endpoint, REPO_A, GEO_PATH)
        _settle(0.3)
        assert (status, body) == (200, GEO_BODY), _errlog(endpoint)
        assert len(mock.geo_hits()) == 1, (
            f"`off` did not relay to the origin: {mock.paths()}")

    def test_rtt_answers_locally_and_never_touches_the_origin(self, lifecycle,
                                                              tmp_path, mock):
        """The written half of the pair, measured the same way so the two
        readings are comparable: identical status, identical body, and the
        origin never hears about it."""
        endpoint = _start(lifecycle, tmp_path,
                          policy_a=_policy("brix_cvmfs_geo_answer rtt;"))
        mock.reset()
        status, body = _fetch(endpoint, REPO_A, GEO_PATH)
        _settle(0.3)
        assert (status, body) == (200, GEO_BODY), _errlog(endpoint)
        assert mock.geo_hits() == [], (
            f"`rtt` reached the origin: {mock.paths()}")

    def test_each_location_keeps_its_own_answer_mode(self, lifecycle, tmp_path,
                                                     mock):
        """The contrast with §A, stated in one config.

        Two locations, two different tokens, one worker: A relays and B does
        not.  Nothing here depends on which was merged last, because
        gate.c:422 reads the location's own value on the request.
        """
        endpoint = _start(lifecycle, tmp_path,
                          policy_a=_policy("brix_cvmfs_geo_answer off;"),
                          policy_b=_policy("brix_cvmfs_geo_answer rtt;"))
        mock.reset()
        status_a, body_a = _fetch(endpoint, REPO_A, GEO_PATH)
        _settle(0.3)
        relayed = len(mock.geo_hits())

        mock.reset()
        status_b, body_b = _fetch(endpoint, REPO_B, GEO_PATH)
        _settle(0.3)
        local = mock.geo_hits()

        assert (status_a, body_a) == (200, GEO_BODY), _errlog(endpoint)
        assert (status_b, body_b) == (200, GEO_BODY), _errlog(endpoint)
        assert relayed == 1, "the `off` location stopped relaying"
        assert local == [], f"the `rtt` location relayed: {local}"

    def test_the_order_does_not_change_either_location(self, lifecycle, tmp_path,
                                                       mock):
        """error arm + the order control.

        The same two tokens swapped.  ``rtt`` still answers locally and ``off``
        still relays — and because ``off`` relays, location B's geo request
        reaches an origin that serves geo for REPO_A only, so the operator sees
        the Stratum-1's own 404 rather than a locally-invented answer.  That
        pass-through of a failure is the behaviour ``off`` exists for.
        """
        endpoint = _start(lifecycle, tmp_path,
                          policy_a=_policy("brix_cvmfs_geo_answer rtt;"),
                          policy_b=_policy("brix_cvmfs_geo_answer off;"))
        mock.reset()
        status_a, body_a = _fetch(endpoint, REPO_A, GEO_PATH)
        _settle(0.3)
        quiet = mock.geo_hits()

        mock.reset()
        status_b, _ = _fetch(endpoint, REPO_B, GEO_PATH)
        _settle(0.3)
        relayed = len(mock.geo_hits())

        assert (status_a, body_a) == (200, GEO_BODY), _errlog(endpoint)
        assert quiet == [], (
            f"`rtt` relayed once a sibling wrote `off`: {quiet}")
        assert status_b == 404, (
            f"the relayed geo request did not carry the origin's verdict: "
            f"{status_b}\n{_errlog(endpoint)}")
        assert relayed == 1, "the `off` location stopped relaying"


# --------------------------------------------------------------------------- #
# C. brix_cvmfs_fill_retry_policy — DEFECT CANDIDATE #58                       #
# --------------------------------------------------------------------------- #

class TestTheFillRetryPolicy:
    """What ``failover`` is, and what stops it being that.

    Every case reads the manifest through location A over the SAME
    DEAD|LIVE origin set; the observable is the sd_http line that says a read
    ran out of endpoints, counted in the instance's own log.
    """

    def test_the_directive_absent_never_exhausts_the_endpoint_set(self, lifecycle,
                                                                  tmp_path, mock):
        """The default: a dead primary is failed over from, quietly.  This is
        the reading ``failover`` has to match to be a no-op."""
        endpoint = _start(lifecycle, tmp_path, backend=DEAD_THEN_LIVE,
                          policy_a=_retry_policy())
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        assert status == 200 and body, _errlog(endpoint)
        assert _count(endpoint, EXHAUSTED) == 0, _errlog(endpoint)

    def test_failover_is_indistinguishable_from_omitting_the_directive(
            self, lifecycle, tmp_path, mock):
        """success: the token no config in the suite writes.

        ``failover`` is the enum's 0 and the merge default, so writing it must
        be exactly writing nothing — the same 200, from the same alternate,
        with the same silent log.  An operator who writes it to document intent
        must not be changing behaviour.
        """
        endpoint = _start(lifecycle, tmp_path, backend=DEAD_THEN_LIVE,
                          policy_a=_retry_policy("failover"))
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        assert status == 200 and body, _errlog(endpoint)
        assert _count(endpoint, EXHAUSTED) == 0, (
            "`failover` exhausted the endpoint set — it is no longer the "
            f"default's twin\n{_errlog(endpoint)}")

    def test_force_primary_exhausts_the_set_and_returns_hold_expiry(
            self, lifecycle, tmp_path, mock):
        """force-primary never opens the configured alternate.

        sd_http.h:100-104 says force-primary "never fails over to an alternate
        on a transport failure".  With the static selector, the configured
        dead endpoint is rank-preferred for every retry, so the bounded hold
        returns 504 rather than silently serving the alternate.
        """
        endpoint = _start(
            lifecycle, tmp_path, backend=DEAD_THEN_LIVE,
            policy_a=_retry_policy("force-primary"))
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        log = _errlog(endpoint)
        assert status == 504, f"force-primary served an alternate ({status})\n{log}"
        assert _count(endpoint, EXHAUSTED) > 0, (
            f"force-primary did not exhaust its configured primary\n{log}")
        assert FILL_RETRY in log, (
            f"force-primary did not retry its configured primary\n{log}")

    def test_a_silent_sibling_leaves_a_failover_location_alone(self, lifecycle,
                                                               tmp_path, mock):
        """The control for the next test: a second location, by itself, changes
        nothing.  Without this the latch below could be read as "two cvmfs
        locations behave differently from one"."""
        endpoint = _start(lifecycle, tmp_path, backend=DEAD_THEN_LIVE,
                          policy_a=_retry_policy("failover"), policy_b="")
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        assert status == 200 and body, _errlog(endpoint)
        assert _count(endpoint, EXHAUSTED) == 0, _errlog(endpoint)

    def test_a_force_primary_sibling_latches_a_failover_location(self, lifecycle,
                                                                 tmp_path, mock):
        """security-negative: the process-global force-primary latch wins.

        Location A writes ``failover``.  Location B, a different repository,
        writes ``force-primary``.  A now follows the same force-primary route:
        it exhausts the configured primary until its short hold expires.  The
        merge has no clearing call, so the process-wide setter wins over A's
        local ``failover`` value.
        """
        endpoint = _start(
            lifecycle, tmp_path, backend=DEAD_THEN_LIVE,
            policy_a=_retry_policy("failover"),
            policy_b=_retry_policy("force-primary"))
        status, body = _fetch(endpoint, REPO_A)
        _settle()
        log = _errlog(endpoint)
        assert status == 504, log
        assert _count(endpoint, EXHAUSTED) > 0, (
            "the force-primary latch no longer reaches a `failover` location\n"
            + log)

    def test_nothing_in_the_tree_can_clear_the_force_primary_latch(self):
        """The source arm of the same finding, so a fix cannot land silently.

        A runtime test can only show that ``failover`` does not clear the latch
        in the orders it tried.  The tree can say something stronger: there is
        one caller, and it passes 1.
        """
        calls = subprocess.run(
            ["grep", "-rnE", r"sd_http_force_primary_set\([01]\)", "src/"],
            cwd=ROOT, capture_output=True, text=True).stdout.splitlines()
        assert calls, ("the setter has no literal call sites left — re-read "
                       "cvmfs_module_merge.c before trusting this class")
        assert all(line.endswith("sd_http_force_primary_set(1);")
                   for line in calls), (
            "something now passes a value other than 1 — the latch may be "
            "clearable, so re-measure "
            f"test_a_force_primary_sibling_latches_a_failover_location:\n"
            + "\n".join(calls))


# --------------------------------------------------------------------------- #
# D. The parse tier                                                            #
# --------------------------------------------------------------------------- #

def _knobs(*lines):
    return "".join(f"            {line}\n" for line in lines)


def _second_location(*lines):
    """A whole second cvmfs location for the parse scaffold — the shape §A
    measured, asked of `nginx -t` instead of of a request.

    The cache store is left as a CACHE2 marker for `_parse` to fill in: the
    caller is a test method that has no reason to know where the scaffold puts
    its second store.
    """
    body = "".join(f"            {line}\n" for line in lines)
    return (f"\n        location /cvmfs2/ {{\n"
            f"            brix_cvmfs           on;\n"
            f"            brix_cache_store     posix:{{CACHE2}};\n"
            f"{body}        }}\n")


def _diagnostics(out):
    """The lines of an `nginx -t` transcript that would tell an operator
    something is wrong.  Matching on the transcript as a whole cannot work: the
    prefix is a tmp_path named after the test, so tokens this file tests
    ("off", "2", "1") appear in the output as part of a directory."""
    return [line for line in out.splitlines()
            if any(sev in line for sev in ("[warn]", "[error]", "[crit]",
                                           "[emerg]"))]


def _parse(tmp_path, knobs="", loc_extra="", http_extra="", outer=""):
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    cache2 = tmp_path / "cache2"
    cache2.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit15y_cvparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, LOG_DIR=str(tmp_path),
                     CACHE=str(cache), BACKEND=LIVE, KNOBS=knobs,
                     LOC_EXTRA=loc_extra.replace("{CACHE2}", str(cache2)),
                     HTTP_EXTRA=http_extra, OUTER=outer)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


ALL_TOKENS = ([("brix_cvmfs_fill_retry_policy", t) for t in RETRY_TOKENS]
              + [("brix_cvmfs_geo_answer", t) for t in GEO_TOKENS]
              + [("brix_cvmfs_origin_http_version", t) for t in HTTPV_TOKENS])


class TestTheParseTier:
    """What the three enums accept and refuse.  Nothing here starts a server,
    and every case damages only its own tmp_path copy of the scaffold."""

    @pytest.mark.parametrize("directive,token", ALL_TOKENS,
                             ids=[f"{d.split('_', 2)[-1]}-{t}"
                                  for d, t in ALL_TOKENS])
    def test_every_token_in_the_table_parses(self, tmp_path, directive, token):
        """success: the enum tables (protocols/cvmfs/module.c:338-356) and the
        documentation agree on the spelling of all of them, including the three
        no config in the suite writes."""
        rc, out = _parse(tmp_path, _knobs(f"{directive} {token};"))
        assert rc == 0, f"{directive} {token} was rejected\n{out}"

    @pytest.mark.parametrize("directive,token", [
        ("brix_cvmfs_fill_retry_policy", "Force-Primary"),
        ("brix_cvmfs_geo_answer", "RTT"),
        ("brix_cvmfs_origin_http_version", "2-Direct")])
    def test_the_tokens_are_case_insensitive(self, tmp_path, directive, token):
        """ngx_conf_set_enum_slot compares with ngx_strcasecmp, so the config
        language is case-insensitive here while the audit's own grep for
        written values is not — which is why a value-granularity sweep has to
        read the enum table rather than the configs alone."""
        rc, out = _parse(tmp_path, _knobs(f"{directive} {token};"))
        assert rc == 0, f"the enum rejected {token!r}\n{out}"

    @pytest.mark.parametrize("directive,token", [
        ("brix_cvmfs_fill_retry_policy", "primary"),
        ("brix_cvmfs_geo_answer", "on"),
        ("brix_cvmfs_origin_http_version", "1.0")])
    def test_a_near_miss_token_is_refused(self, tmp_path, directive, token):
        """error: each of these is what an operator plausibly writes for the
        real token, and each must fail loudly rather than leave the default in
        place — for two of the three, silently keeping the default is a
        different origin policy for the whole worker."""
        rc, out = _parse(tmp_path, _knobs(f"{directive} {token};"))
        assert rc != 0 and f'invalid value "{token}"' in out, out

    @pytest.mark.parametrize("directive", ["brix_cvmfs_fill_retry_policy",
                                           "brix_cvmfs_geo_answer",
                                           "brix_cvmfs_origin_http_version"])
    def test_the_enum_number_is_not_a_token(self, tmp_path, directive):
        """error: all three are small integers internally (and the version's
        are 11/20/21/30, which read like plausible values). The enums take
        names only."""
        rc, out = _parse(tmp_path, _knobs(f"{directive} 0;"))
        assert rc != 0 and 'invalid value "0"' in out, out

    @pytest.mark.parametrize("directive", ["brix_cvmfs_fill_retry_policy",
                                           "brix_cvmfs_geo_answer",
                                           "brix_cvmfs_origin_http_version"])
    def test_an_empty_value_is_refused(self, tmp_path, directive):
        """security-negative: an unset shell variable expanding to "" must not
        quietly become the default — an operator templating origin policy per
        site would silently un-pin every export, and for two of the three that
        change lands on every OTHER export in the process too."""
        rc, out = _parse(tmp_path, _knobs(f'{directive} "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("line", [
        "brix_cvmfs_fill_retry_policy;",
        "brix_cvmfs_fill_retry_policy failover force-primary;",
        "brix_cvmfs_geo_answer;",
        "brix_cvmfs_origin_http_version 2 2-direct;"])
    def test_each_directive_takes_exactly_one_argument(self, tmp_path, line):
        """error: NGX_CONF_TAKE1.  "failover force-primary" and "2 2-direct"
        are the shapes an operator reaches for when they want a preference
        order, and neither must parse as either value."""
        rc, out = _parse(tmp_path, _knobs(line))
        assert rc != 0, f"{line!r} parsed\n{out}"
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("directive,first,second", [
        ("brix_cvmfs_fill_retry_policy", "failover", "force-primary"),
        ("brix_cvmfs_geo_answer", "off", "rtt"),
        ("brix_cvmfs_origin_http_version", "1.1", "2-direct")])
    def test_a_duplicate_directive_is_refused(self, tmp_path, directive, first,
                                              second):
        """security-negative: two values in ONE location would leave which one
        wins to the parser's ordering.  nginx refuses that — which is exactly
        the check the two directives in §A do not get across locations."""
        rc, out = _parse(tmp_path, _knobs(f"{directive} {first};",
                                          f"{directive} {second};"))
        assert rc != 0 and f'"{directive}" directive is duplicate' in out, out

    @pytest.mark.parametrize("directive,token", [
        ("brix_cvmfs_fill_retry_policy", "force-primary"),
        ("brix_cvmfs_geo_answer", "off"),
        ("brix_cvmfs_origin_http_version", "1.1")])
    def test_each_directive_is_accepted_at_http_level(self, tmp_path, directive,
                                                      token):
        """success: MAIN|SRV|LOC within http.  A site-wide default is the
        legitimate way to write the two process-global ones — it is the only
        placement whose meaning matches what the C actually does."""
        rc, out = _parse(tmp_path, http_extra=f"    {directive} {token};\n")
        assert rc == 0, f"an http-level {directive} was rejected\n{out}"

    @pytest.mark.parametrize("directive,token", [
        ("brix_cvmfs_fill_retry_policy", "force-primary"),
        ("brix_cvmfs_geo_answer", "off"),
        ("brix_cvmfs_origin_http_version", "1.1")])
    def test_each_directive_is_refused_outside_http(self, tmp_path, directive,
                                                    token):
        """security-negative: written at the top of the file it reads like a
        global default — which, for two of the three, is what it effectively
        is.  nginx must still refuse it rather than silently ignore it."""
        rc, out = _parse(tmp_path, outer=f"{directive} {token};\n")
        assert rc != 0, f"a main-context {directive} parsed\n{out}"
        assert f'"{directive}" directive is not allowed here' in out, out

    def test_two_locations_disagreeing_about_the_version_parse_in_silence(
            self, tmp_path):
        """DEFECT CANDIDATE #57, parse-time half.

        Config parse is the last moment the clobber is diagnosable: both values
        are known, the merge is about to discard one of them, and which one
        survives depends on nothing an operator can see.  Nothing is said — no
        warning, no notice, nothing naming either location — so their only
        feedback is §A's 504 on an export they did not edit.
        """
        rc, out = _parse(
            tmp_path,
            _knobs("brix_cvmfs_origin_http_version 1.1;"),
            loc_extra=_second_location("brix_cvmfs_origin_http_version 2-direct;"))
        assert rc == 0, f"the two-location config stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "the discarded origin HTTP version is now diagnosed at parse time "
            f"— pin the new diagnostic here and close #57\n{out}")

    def test_two_locations_disagreeing_about_the_retry_policy_parse_in_silence(
            self, tmp_path):
        """DEFECT CANDIDATE #58, parse-time half.

        The same silence on the directive where it is worse: here the losing
        location is not merely overridden, it is overridden in one direction
        only, and there is no ordering of these two locations that lets
        ``failover`` mean failover.
        """
        rc, out = _parse(
            tmp_path,
            _knobs("brix_cvmfs_fill_retry_policy failover;"),
            loc_extra=_second_location(
                "brix_cvmfs_fill_retry_policy force-primary;"))
        assert rc == 0, f"the two-location config stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "the one-way retry-policy latch is now diagnosed at parse time — "
            f"pin the new diagnostic here and close #58\n{out}")
