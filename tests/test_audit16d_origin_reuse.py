"""brix_cvmfs_origin_reuse_conn at VALUE granularity — audit §Method, 16th tranche.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the
measurement per (directive, VALUE) over the 128 ``ngx_conf_set_flag_slot``
directives in ``src/`` turned 256 pairs into 138 written literally, 12 reachable
only through a ``{PLACEHOLDER}``, and 106 written nowhere at all.  Seven
directives have BOTH arms unwritten; ``brix_cvmfs_origin_reuse_conn`` is the
fifth of the seven this tranche takes.

WHAT THE VALUE SELECTS
----------------------
Two libcurl options, and nothing else::

    src/fs/cache/origin/s3_transport_setup.c:379-392
        s3o_apply_reuse(CURL *curl)
            if (g_origin_no_reuse) {
                CURLOPT_FORBID_REUSE  = 1
                CURLOPT_FRESH_CONNECT = 1
                return;
            }
            CURLOPT_MAXCONNECTS = 16, TCP_KEEPALIVE/KEEPIDLE/KEEPINTVL,
            MAXAGE_CONN = 20

reached from the one place a value ever gets in::

    src/protocols/cvmfs/cvmfs_module_merge.c:270
        if (conf->cvmfs.enable) { ...
            brix_s3_origin_reuse_set(conf->cvmfs.origin_reuse_conn ? 1 : 0);

The options only mean anything because the transport keeps ONE curl easy handle
per FILL THREAD and ``curl_easy_reset()``s it between requests — reset clears the
per-request options but preserves the live connection pool and the DNS cache
(``s3o_curl_acquire``, s3_transport_setup.c:264-281).  Turn reuse off and the
2nd..Nth origin request pays a fresh TCP handshake and a cold congestion window.

That is the whole surface, and none of it is visible from the listener: same
status, same bytes, same log lines on both arms.  It is visible in exactly one
place — how many TCP connections the ORIGIN accepts for N origin requests — so
that is where this file reads it, off a mock Stratum-1 started ``--keepalive``.

WHAT THE TABLE ESTABLISHES
--------------------------
One worker, one fill thread, one warm-up fetch to take the origin selection and
the RTT ranker's own connection out of the reading, then three CAS objects
fetched through location A — measured as (origin requests seen by the listener's
trace) against (connections newly accepted by the origin):

    location A     location B     A requests   A accepts
    on             -              N            0
    off            -              N            N
    (silent)       -              N            0
    off            on             N            0
    on             off            N            N
    off            (silent)       N            0

Zero, not one: after the warm-up the fill thread already holds the connection it
will reuse, so the reuse arm costs the origin nothing at all for the whole batch
and the no-reuse arm costs it exactly one connection per request.  Neither
number has a constant in it — which is the point of warming up rather than
subtracting.

FINDING — DEFECT CANDIDATE #69
------------------------------
``brix_cvmfs_origin_reuse_conn`` is a location-level directive that is not
per-location.  It is declared ``NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|
NGX_HTTP_LOC_CONF|NGX_CONF_FLAG`` (protocols/cvmfs/directives_resilience.h:
93-99) and its merge writes a process-wide ``static int g_origin_no_reuse``, so
the last cvmfs-enabled location merged decides for the whole worker:

(a) A location's own ``off`` is discarded whenever another cvmfs location is
    merged after it — row 4.
(b) A location that never mentions the directive is not neutral.  Its
    ``NGX_CONF_UNSET`` merges to 1 (cvmfs_module_merge.c:209-210) and is written
    to the global like any chosen value, so adding a second, unrelated
    repository export with no opinion at all silently re-enables reuse for the
    first one — row 6.  This is the row an operator actually hits, because
    ``off`` is what they reached for after a middlebox reaped their idle
    connections and every fill started timing out.
(c) The reverse costs the other export its keep-alive: one repository that needs
    ``off`` puts every OTHER repository in the process back on a cold connection
    per object — row 5.  On a high-latency Stratum-1 link that is the entire
    reason the reuse path exists.
(d) The blast radius is not even limited to CVMFS.  ``s3o_apply_reuse()`` is
    applied by the transport itself (s3_transport_setup.c:481), and sd_http —
    the plain ``http://`` storage backend, with no cvmfs anywhere in its
    configuration — is "a thin driver over the injected brix_s3_transport_t (the
    same vtable the S3 origin uses)" (fs/backend/http/sd_http.c:5).  So a
    ``brix_cvmfs_*`` directive in one location re-policies the origin
    connections of a plain HTTP cache tier in another.  §D pins that in the C;
    demonstrating it at run time needs a second protocol face and is the one
    claim here taken from source rather than from the wire.

Nothing is said at parse time (§E) and nothing is said at run time: there is no
log line anywhere that names the reuse policy actually in force.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
Whether reuse is the right default, and what it is worth on a real link, belong
to the phase-33 performance corpus.  The failure mode the directive exists for —
a middlebox reaping an idle connection so that the next request times out with
no RST — is a network property this harness cannot forge, and the comment at
s3_transport_setup.c:65-71 is its only description.  Measured here is only what
the two values do, and to whom.
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
              pytest.mark.xdist_group("lc-audit16d-reuse")]

NAME = "lc-audit16d-reuse"
MOCK_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["MOCK_PORT"]
ROOT = Path(__file__).resolve().parents[1]
MOCK_SCRIPT = ROOT / "tests/cvmfs/mock_stratum1.py"
SETUP_C = ROOT / "src/fs/cache/origin/s3_transport_setup.c"
MERGE_C = ROOT / "src/protocols/cvmfs/cvmfs_module_merge.c"
SD_HTTP_C = ROOT / "src/fs/backend/http/sd_http.c"

# Two repositories, because one location cannot show a process-global.
REPO_A, REPO_B = "alpha.cern.ch", "beta.cern.ch"
MANIFEST = ".cvmfspublished"
# Three CAS objects per repository, which the fill turns into six origin
# requests (a HEAD then a ranged GET each).  More than one object is what keeps
# "reuse is on" from being indistinguishable from "there was only ever one
# request to make"; three keeps the two arms six apart while the batch still
# runs in well under a second.
OBJECTS_PER_REPO = 3

# fs/cache/origin/s3_transport.c:210 writes one of these per ORIGIN request when
# brix_cvmfs_trace is on.  Counting them is how the accept count becomes a ratio
# rather than a number.
TRACE = "cvmfs-trace: upstream "


# --------------------------------------------------------------------------- #
# The origin                                                                   #
# --------------------------------------------------------------------------- #

class _Mock:
    """The keep-alive mock Stratum-1, plus the one question this file asks it:
    how many TCP connections have you accepted since I last reset you."""

    def __init__(self, proc, port, objects, bodies):
        self.proc = proc
        self.port = port
        # The forged CAS paths, per repository — the batch every measurement
        # fetches.  Held by the mock because the mock is what serves them, and
        # a test that guessed the paths would measure a 404 instead of a fill.
        self.objects = objects
        # And their bytes, so that every batch checks WHAT came back as well as
        # how many connections it took.  A connection-reuse flag has no business
        # touching content, and an off-by-one in a reuse path would truncate
        # rather than fail — which no status code would show.
        self.bodies = bodies

    def _ctl(self, endpoint, method="GET"):
        request = urllib.request.Request(
            f"http://{HOST}:{self.port}/ctl/{endpoint}", method=method,
            data=b"" if method == "POST" else None)
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read()
        return json.loads(body) if body.startswith((b"[", b"{")) else body

    def reset(self):
        """Zero the request log and the accept counter.

        The POST's own connection is counted by Handler.setup() BEFORE do_POST
        zeroes the counter, so the counter really is 0 on return — the control
        plane does not have to be subtracted here.
        """
        self._ctl("reset-log", method="POST")

    def accepts(self):
        """Connections accepted since the last reset, EXCLUDING this reading.

        Handler.setup() runs on accept, before the request line is parsed, so
        the number ``/ctl/connections`` reports already includes the connection
        that is asking.  Every control request opens its own connection
        (urllib closes each one), which is why nothing else needs adjusting:
        exactly one connection of the count is the question itself.
        """
        return self._ctl("connections")["connections"] - 1

    def paths(self):
        return [entry["path"] for entry in self._ctl("log")]


def _forge(root):
    """Both repositories on disk in the layout the mock serves from a webroot:
    the signed manifest plus OBJECTS_PER_REPO CAS objects each.

    Returns the object paths per repository (so the tests fetch by name rather
    than by guess) and every body by path (so a fetch can be checked against
    what the origin actually holds).
    """
    objects, bodies = {}, {}
    for index, repo in enumerate((REPO_A, REPO_B)):
        paths = {f"/cvmfs/{repo}/{MANIFEST}": manifest(repo, 1)}
        # A distinct seed per repository, so a fill through one location can
        # never be served by an object another location already pulled.
        paths.update(make_repo(repo, OBJECTS_PER_REPO, seed=11 + index))
        for url_path, body in paths.items():
            target = root / url_path.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        objects[repo] = sorted(p for p in paths if "/data/" in p)
        bodies.update(paths)
    return objects, bodies


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
    """Who is listening on a fixed ledger port, named rather than numbered — a
    port assertion is not actionable without knowing who the occupant was."""
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
    """The origin every fill in this file comes from.

    ``--keepalive`` is the instrument, not a detail: the mock's default is
    HTTP/1.0, which closes after every response, and against that origin both
    arms of the flag would read as one connection per request and the directive
    would look inert.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    webroot = tmp_path / "webroot"
    objects, bodies = _forge(webroot)
    # The origin's own output goes to a file rather than /dev/null: a mock that
    # exits before it listens takes the reason with it otherwise, and on a fixed
    # ledger port the reason is the whole diagnosis.
    log = tmp_path / "mock_stratum1.log"
    handle = open(log, "wb")
    try:
        proc = subprocess.Popen(
            [sys.executable, str(MOCK_SCRIPT), "--port", str(MOCK_PORT),
             "--repo", REPO_A, "--webroot", str(webroot), "--keepalive"],
            stdout=handle, stderr=subprocess.STDOUT)
    finally:
        handle.close()
    try:
        assert _listening(MOCK_PORT), (
            f"mock Stratum-1 never listened on {MOCK_PORT} "
            f"(exit={proc.poll()}, holders={_holders(MOCK_PORT)})\n"
            f"{_tail(log)}")
        yield _Mock(proc, MOCK_PORT, objects, bodies)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

BACKEND = f"http://{HOST}:{MOCK_PORT}"
ON = "brix_cvmfs_origin_reuse_conn on;"
OFF = "brix_cvmfs_origin_reuse_conn off;"


def _policy(*lines):
    """Location-level lines at the template's indentation."""
    return "".join(f"            {line}\n" for line in lines)


def _start(lifecycle, tmp_path, *, policy_a="", policy_b=None):
    """Start the one- or two-location listener; ``policy_b=None`` means one.

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
              "BACKEND": BACKEND, "POLICY_A": policy_a}
    if policy_b is None:
        template = "nginx_audit16d_reusesolo.conf"
    else:
        template = "nginx_audit16d_reusepair.conf"
        values.update({"REPO_B": REPO_B, "CACHE_B": caches["b"],
                       "POLICY_B": policy_b})
    return lifecycle.start(NginxInstanceSpec(
        name=NAME, template=template, protocol="http",
        data_root=str(tmp_path / "data"), template_values=values,
        reason="audit-16d the cvmfs origin connection-reuse flag at value "
               "granularity"))


# --------------------------------------------------------------------------- #
# The reading                                                                  #
# --------------------------------------------------------------------------- #

def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(endpoint.prefix, "logs", "error.log")) as handle:
            return handle.read()
    except OSError:
        return "(error log unavailable)"


def _origin_requests(endpoint):
    return sum(TRACE in line for line in _errlog(endpoint).splitlines())


def _get(endpoint, path, timeout=60):
    url = f"http://{HOST}:{endpoint.port}{path}"
    try:
        return requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        raise AssertionError(
            f"the listener did not answer GET {path} on port {endpoint.port}: "
            f"{exc!r}\n{_errlog(endpoint)}") from exc


class _Reading:
    """What one batch of fetches cost the origin.

    ``requests`` comes from the listener's trace and ``accepts`` from the
    origin's accept counter; neither alone is a reading.  A batch that never
    reached the origin has 0 requests and 0 accepts on BOTH arms, and would
    otherwise pass the reuse assertion for the wrong reason.
    """

    def __init__(self, fetched, requests, accepts, errlog):
        self.fetched = fetched               # {url path: response body}
        self.statuses = tuple(status for status, _ in fetched.values())
        self.requests = requests
        self.accepts = accepts
        self.errlog = errlog

    def __str__(self):
        return (f"{self.requests} origin request(s) over {self.accepts} "
                f"connection(s), statuses {self.statuses}")


def _warm(endpoint, mock, repo, settle=1.0):
    """Fetch the manifest, and take everything that is not a fill OUT of the
    measurement that follows.

    A cold instance spends connections on things this file is not asking about:
    the origin is selected, the cvmfs RTT ranker takes its initial reading, and
    every THREAD that talks to the origin opens the first connection of its own
    per-thread curl handle — the ranker runs on the worker's own thread, so even
    a perfectly reusing fill thread leaves a cold instance answering "one per
    fill thread PLUS one".  Measured cold, the two arms are 2 and N+1, and the
    +1 would have to be written down as a constant that nothing explains.

    Measured after this, they are 0 and N: either the batch cost the origin
    nothing at all, or it cost it one connection per request.  No constant.
    """
    response = _get(endpoint, f"/cvmfs/{repo}/{MANIFEST}")
    assert response.status_code == 200, (
        f"the warm-up fetch failed with {response.status_code}\n"
        f"{_errlog(endpoint)}")
    time.sleep(settle)


def _measure(endpoint, mock, repo, extra_settle=1.0):
    """Fetch every CAS object of `repo` through the listener and report what the
    origin saw.  Call `_warm` first; the manifest is deliberately not in the
    batch, because the warm-up already pulled it into the cache.

    Sequential, deliberately: a concurrent batch could be spread over more fill
    threads than the template allows and would measure the thread pool instead
    of the flag.
    """
    mock.reset()
    before = _origin_requests(endpoint)
    fetched = {}
    for path in mock.objects[repo]:
        response = _get(endpoint, path)
        fetched[path] = (response.status_code, response.content)
    # The fill runs on a worker thread and its last trace line can land after
    # the response body has already been read by the client.
    time.sleep(extra_settle)
    return _Reading(fetched, _origin_requests(endpoint) - before,
                    mock.accepts(), _errlog(endpoint))


def _served(reading, mock):
    """Every fetch in the batch answered with the origin's own bytes, and every
    one of them went to the origin — the preconditions for the accept count to
    mean anything.

    The byte check is not ceremony.  A connection-reuse flag has no business
    touching content, so a reuse path that mixed up two responses on one warm
    connection would show up HERE and nowhere else: same status, same length
    class, wrong object.  Asserting it in the shared helper means every reading
    in the file carries it.

    The request floor is one per object rather than the two the fill actually
    makes (a HEAD to size the object, then a ranged GET): how many requests a
    fill costs is the fill layer's business, and this file's readings are all
    expressed against whatever that number turns out to be.
    """
    for path, (status, body) in reading.fetched.items():
        assert status == 200, (
            f"{path} did not succeed: {reading}\n{reading.errlog}")
        assert body == mock.bodies[path], (
            f"{path} came back with {len(body)} bytes that are not the "
            f"origin's {len(mock.bodies[path])}: {reading}\n{reading.errlog}")
    assert reading.requests >= OBJECTS_PER_REPO, (
        f"fewer origin requests than objects fetched — something was served "
        f"from cache and the connection count is not a reading: {reading}\n"
        f"{reading.errlog}")


# --------------------------------------------------------------------------- #
# A. The pair, one location                                                    #
# --------------------------------------------------------------------------- #

class TestTheFlagOnOneLocation:
    """The two values, each written out, in the one configuration shape where
    an operator's reading of the directive cannot be wrong."""

    def test_reuse_on_serves_the_whole_batch_over_one_connection(
            self, lifecycle, tmp_path, mock):
        """success: the ON arm, which until now was reachable only as the merge
        default and was therefore never distinguished from it.

        One fill thread keeps one curl handle, the handle keeps its connection
        pool across ``curl_easy_reset()``, and the origin is HTTP/1.1 — so every
        request after the first rides the connection the first one opened.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(ON))
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == 0, (
            f"reuse is on but the origin accepted {reading.accepts} new "
            f"connections for {reading.requests} requests: {reading}\n"
            f"{reading.errlog}")

    def test_reuse_off_opens_a_fresh_connection_for_every_request(
            self, lifecycle, tmp_path, mock):
        """success: the OFF arm — the value nothing in the corpus had ever
        written, and the one an operator reaches for when a middlebox is
        reaping their idle connections.

        CURLOPT_FORBID_REUSE keeps the finished connection out of the pool and
        CURLOPT_FRESH_CONNECT refuses to draw from it, so the count is exactly
        the request count: no more (nothing is opened speculatively) and no
        fewer (nothing is kept).
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(OFF))
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == reading.requests, (
            f"reuse is off but the origin accepted {reading.accepts} "
            f"connections for {reading.requests} requests: {reading}\n"
            f"{reading.errlog}")

    def test_nothing_in_the_log_names_the_policy_in_force(self, lifecycle,
                                                          tmp_path, mock):
        """DEFECT CANDIDATE #69, the run-time half of "nothing is said".

        The instance runs at ``error_log info``, the most verbose level an
        operator would ever deploy, on the arm that is NOT the default — and
        there is no line saying which reuse policy is in force.  That is what
        makes §C's clobber undiagnosable in production as well as at parse time:
        the operator whose ``off`` was taken away by a sibling location has
        nowhere to look and nothing to grep for.

        Byte-identity across the arms is not asserted here; it is asserted on
        every batch in the file, by ``_served`` against the origin's own copy.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(OFF))
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == reading.requests, (
            f"the OFF arm is not in force after all: {reading}")
        named = [line for line in reading.errlog.splitlines()
                 if any(word in line.lower()
                        for word in ("reuse", "keep-alive to origin",
                                     "fresh connect"))]
        assert named == [], (
            "the reuse policy is now named in the log — pin the new line here "
            f"and narrow #69 to the parse tier:\n" + "\n".join(named))


# --------------------------------------------------------------------------- #
# B. The merge default                                                         #
# --------------------------------------------------------------------------- #

class TestTheMergeDefault:
    """``ngx_conf_merge_value(conf->cvmfs.origin_reuse_conn,
    prev->cvmfs.origin_reuse_conn, 1)`` — cvmfs_module_merge.c:209-210."""

    def test_the_directive_absent_behaves_as_on(self, lifecycle, tmp_path,
                                                mock):
        """success: the default is reuse, asserted rather than assumed.

        Every cvmfs config in the corpus is this one, so this is the arm the
        whole suite has been exercising by accident.  Pinning it is what makes
        the ON case above a measurement of the DIRECTIVE instead of a second
        measurement of the default.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a="")
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == 0, (
            f"the merge default is no longer reuse: {reading}\n"
            f"{reading.errlog}")


# --------------------------------------------------------------------------- #
# C. DEFECT CANDIDATE #69 — the location-level flag that is not per-location   #
# --------------------------------------------------------------------------- #

class TestTheFlagIsProcessGlobal:
    """Each test reads the SAME batch through the SAME location; the only thing
    that changes between them is what a sibling location wrote."""

    def test_a_sibling_location_takes_the_operators_off_away(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #69(a).

        Location A writes ``off`` — proven above to give one connection per
        request when it is the only location.  Location B, a different
        repository, writes ``on`` and is merged after it.  A's fills go back to
        reusing.  Nothing about A changed, and nothing anywhere says so.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(OFF),
                          policy_b=_policy(ON))
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == 0, (
            "a sibling location no longer overrides this one's reuse policy — "
            f"#69(a) may be fixed: {reading}\n{reading.errlog}")

    def test_a_silent_sibling_location_takes_it_away_too(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #69(b) — the row an operator actually hits.

        Location B says NOTHING about connection reuse.  It is a second
        repository export, added months later, by someone who has never heard
        of this directive.  Its unset flag merges to 1 and is written to the
        process global exactly like a chosen value, so location A's ``off`` —
        the workaround for the middlebox that made A unusable — is gone.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(OFF),
                          policy_b="")
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == 0, (
            "an opinion-less sibling location no longer reverts this one's "
            f"reuse policy — #69(b) may be fixed: {reading}\n{reading.errlog}")

    def test_a_sibling_off_costs_this_location_its_keepalive(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #69(c).

        The reverse direction, and the expensive one: location A asked for
        nothing unusual (``on``), and one sibling that needs ``off`` puts A back
        on a cold TCP connection and a cold congestion window for every single
        object it fills.  On the high-latency link the reuse path was written
        for, that is the whole cost the path exists to avoid.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(ON),
                          policy_b=_policy(OFF))
        _warm(endpoint, mock, REPO_A)
        reading = _measure(endpoint, mock, REPO_A)
        _served(reading, mock)
        assert reading.accepts == reading.requests, (
            "a sibling location no longer imposes its no-reuse policy on this "
            f"one — #69(c) may be fixed: {reading}\n{reading.errlog}")

    def test_both_locations_get_the_same_answer(self, lifecycle, tmp_path,
                                                mock):
        """DEFECT CANDIDATE #69, stated as an identity rather than as a clobber.

        A says ``on``, B says ``off``, and the two locations are measured in the
        same process against the same origin.  If the directive were
        per-location the readings would differ; they are equal, which is the
        finding said once without reference to merge order.
        """
        endpoint = _start(lifecycle, tmp_path, policy_a=_policy(ON),
                          policy_b=_policy(OFF))
        _warm(endpoint, mock, REPO_A)
        _warm(endpoint, mock, REPO_B)
        through_a = _measure(endpoint, mock, REPO_A)
        through_b = _measure(endpoint, mock, REPO_B)
        _served(through_a, mock)
        _served(through_b, mock)
        assert through_a.accepts == through_a.requests, (
            f"location A: {through_a}\n{through_a.errlog}")
        assert through_b.accepts == through_b.requests, (
            f"location B: {through_b}\n{through_b.errlog}")


# --------------------------------------------------------------------------- #
# D. The blast radius — the flag is not per-FEATURE either                     #
# --------------------------------------------------------------------------- #

def _source(path):
    return path.read_text()


class TestTheReusePolicyIsNotConfinedToCvmfs:
    """DEFECT CANDIDATE #69(d), taken from the C.

    Demonstrating this on the wire needs a second protocol face (sd_http is
    reached from a root:// listener), which is a whole second instrument for a
    fact the source states plainly.  What is pinned here is each link of the
    chain, so a fix anywhere along it fails a test here rather than passing
    silently.
    """

    def test_the_transport_applies_the_policy_unconditionally(self):
        """The reuse policy is applied by the request path itself, with no
        condition on which feature asked for the request."""
        text = _source(SETUP_C)
        assert "    s3o_apply_reuse(curl);\n" in text, (
            "s3o_apply_reuse is no longer called unconditionally from the "
            "transport — re-read the chain and re-state #69(d)")
        assert text.count("s3o_apply_reuse(curl);") == 1, (
            "more than one call site: the single unconditional application is "
            "what makes the policy reach every caller of the transport")

    def test_the_plain_http_backend_drives_the_same_transport(self):
        """sd_http is the ``http://`` storage backend, and it shares the vtable
        the reuse policy is applied inside."""
        text = _source(SD_HTTP_C)
        assert "brix_s3_transport_t" in text, (
            "sd_http no longer names the shared transport vtable — the "
            "cross-feature half of #69(d) needs re-deriving")

    def test_only_a_cvmfs_location_can_ever_set_the_policy(self):
        """And the other end of the asymmetry: the ONLY way to write the global
        is a cvmfs-enabled location, so an sd_http tier can be re-policied by a
        cvmfs location but can never state a policy of its own."""
        text = _source(MERGE_C)
        setter = "brix_s3_origin_reuse_set("
        assert text.count(setter) == 1, (
            f"{setter} no longer has exactly one call site in the merge")
        gate = text.index("if (conf->cvmfs.enable) {")
        call = text.index(setter)
        assert gate < call < text.index("return NGX_CONF_OK;", gate), (
            "the setter call left the `if (conf->cvmfs.enable)` block — the "
            "asymmetry #69(d) describes has changed shape")


# --------------------------------------------------------------------------- #
# E. The parse tier                                                            #
# --------------------------------------------------------------------------- #

def _knobs(*lines):
    return "".join(f"            {line}\n" for line in lines)


def _second_location(*lines):
    """A whole second cvmfs location for the parse scaffold — the shape §C
    measured, asked of ``nginx -t`` instead of of a request."""
    body = "".join(f"            {line}\n" for line in lines)
    return (f"\n        location /cvmfs2/ {{\n"
            f"            brix_cvmfs           on;\n"
            f"            brix_cache_store     posix:{{CACHE2}};\n"
            f"{body}        }}\n")


def _diagnostics(out):
    """The lines of an ``nginx -t`` transcript that would tell an operator
    something is wrong.  Matching on the transcript as a whole cannot work: the
    prefix is a tmp_path named after the test, and the tokens this file tests
    ("on", "off") appear inside directory names."""
    return [line for line in out.splitlines()
            if any(sev in line for sev in ("[warn]", "[error]", "[crit]",
                                           "[emerg]"))]


def _parse(tmp_path, knobs="", loc_extra="", http_extra="", outer=""):
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    cache2 = tmp_path / "cache2"
    cache2.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit16dparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, LOG_DIR=str(tmp_path),
                     CACHE=str(cache), BACKEND=BACKEND, KNOBS=knobs,
                     LOC_EXTRA=loc_extra.replace("{CACHE2}", str(cache2)),
                     HTTP_EXTRA=http_extra, OUTER=outer)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


DIRECTIVE = "brix_cvmfs_origin_reuse_conn"


class TestTheParseTier:
    """What the flag accepts and refuses.  Nothing here starts a server, and
    every case damages only its own tmp_path copy of the scaffold."""

    @pytest.mark.parametrize("value", ["on", "off"])
    def test_both_values_parse(self, tmp_path, value):
        """success: the two arms of the pair, at the tier that costs nothing —
        and the reason a value-granularity sweep exists, since neither had ever
        been written anywhere in the corpus."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc == 0, f"{DIRECTIVE} {value} was rejected\n{out}"

    @pytest.mark.parametrize("value", ["On", "OFF", "oN"])
    def test_the_values_are_case_insensitive(self, tmp_path, value):
        """ngx_conf_set_flag_slot compares with ngx_strcasecmp after checking
        the length, so the config language is case-insensitive here while the
        audit's own grep for written values is not — which is why the sweep has
        to read the setter rather than the configs alone."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc == 0, f"the flag slot rejected {value!r}\n{out}"

    @pytest.mark.parametrize("value", ["1", "0", "true", "yes", "enabled"])
    def test_a_plausible_synonym_is_refused(self, tmp_path, value):
        """error: every one of these is what an operator writes for a boolean
        in some other configuration language, and the flag slot takes exactly
        two spellings.  Refusing loudly is the whole protection here — silently
        keeping the default would hand the operator the policy they were trying
        to change, process-wide."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} {value};"))
        assert rc != 0 and f'invalid value "{value}"' in out, out

    def test_an_empty_value_is_refused(self, tmp_path):
        """security-negative: an unset shell variable expanding to "" must not
        quietly become the default.  An operator templating this per site would
        silently re-enable reuse for every export in the process — including the
        ones whose configuration they never touched."""
        rc, out = _parse(tmp_path, _knobs(f'{DIRECTIVE} "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("line", [f"{DIRECTIVE};",
                                      f"{DIRECTIVE} on off;",
                                      f"{DIRECTIVE} off on;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        """error: NGX_CONF_FLAG is TAKE1.  "on off" is the shape an operator
        reaches for when they want a preference order, and it must not parse as
        either value."""
        rc, out = _parse(tmp_path, _knobs(line))
        assert rc != 0, f"{line!r} parsed\n{out}"
        assert "invalid number of arguments" in out, out

    def test_a_duplicate_directive_is_refused(self, tmp_path):
        """security-negative: two values in ONE location would leave which one
        wins to the parser's ordering.  nginx refuses that — which is exactly
        the check §C shows the directive does not get ACROSS locations."""
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} on;",
                                          f"{DIRECTIVE} off;"))
        assert rc != 0 and f'"{DIRECTIVE}" directive is duplicate' in out, out

    def test_the_directive_is_accepted_at_http_level(self, tmp_path):
        """success: MAIN|SRV|LOC within http.  A site-wide default is the
        legitimate way to write this one — it is the only placement whose
        meaning matches what the C actually does."""
        rc, out = _parse(tmp_path, http_extra=f"    {DIRECTIVE} off;\n")
        assert rc == 0, f"an http-level {DIRECTIVE} was rejected\n{out}"

    def test_the_directive_is_refused_outside_http(self, tmp_path):
        """security-negative: written at the top of the file it reads like a
        global default — which is what it effectively is.  nginx must still
        refuse it rather than silently ignore it."""
        rc, out = _parse(tmp_path, outer=f"{DIRECTIVE} off;\n")
        assert rc != 0, f"a main-context {DIRECTIVE} parsed\n{out}"
        assert f'"{DIRECTIVE}" directive is not allowed here' in out, out

    def test_two_locations_disagreeing_parse_in_silence(self, tmp_path):
        """DEFECT CANDIDATE #69, parse-time half.

        Config parse is the last moment the clobber is diagnosable: both values
        are known, the merge is about to discard one of them, and which one
        survives depends on nothing an operator can see.  Nothing is said — no
        warning, no notice, nothing naming either location — so their only
        feedback is a Stratum-1 link that got slow, or a middlebox workaround
        that stopped working, on an export they did not edit.
        """
        rc, out = _parse(tmp_path, _knobs(f"{DIRECTIVE} off;"),
                         loc_extra=_second_location(f"{DIRECTIVE} on;"))
        assert rc == 0, f"the two-location config stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "the discarded reuse policy is now diagnosed at parse time — pin "
            f"the new diagnostic here and close #69\n{out}")


# --------------------------------------------------------------------------- #
# F. Source pins for the mechanism                                             #
# --------------------------------------------------------------------------- #

class TestTheMechanismIsWhereTheFileSaysItIs:
    """Everything above reads the flag through a socket.  These read it in the
    C, so that a refactor which moves the mechanism fails here — where the
    message names the new shape — instead of failing as an unexplained
    connection count."""

    def test_the_global_has_exactly_one_writer_and_one_reader(self):
        """The single-writer/single-reader shape is what makes "the last
        location merged decides" a complete description of the behaviour."""
        text = _source(SETUP_C)
        assert text.count("g_origin_no_reuse = ") == 1, (
            "g_origin_no_reuse has more than one writer")
        assert text.count("if (g_origin_no_reuse)") == 1, (
            "g_origin_no_reuse has more than one reader")

    def test_the_off_arm_is_forbid_reuse_plus_fresh_connect(self):
        """Both options, not either: FORBID_REUSE keeps the finished connection
        out of the pool and FRESH_CONNECT refuses to draw from it.  One without
        the other would still reuse in one direction, and the accept counts §A
        asserts would be off by one."""
        text = _source(SETUP_C)
        for option in ("CURLOPT_FORBID_REUSE, 1L", "CURLOPT_FRESH_CONNECT, 1L"):
            assert option in text, f"{option} is gone from the no-reuse arm"

    def test_the_pool_survives_between_requests(self):
        """The ON arm is only meaningful because the handle is kept and reset
        rather than re-created; ``curl_easy_reset()`` preserves the connection
        pool, ``curl_easy_init()`` would not."""
        text = _source(SETUP_C)
        assert "curl_easy_reset(handle)" in text, (
            "the per-thread handle is no longer reset-and-reused — the ON arm "
            "would then be indistinguishable from the OFF arm")

    def test_the_merge_default_is_reuse(self):
        """§B measured it; this names the line, so that a change to the default
        fails with the reason rather than with a connection count."""
        text = _source(MERGE_C)
        assert ("ngx_conf_merge_value(conf->cvmfs.origin_reuse_conn,\n"
                "                         prev->cvmfs.origin_reuse_conn, 1);"
                ) in text, "the origin_reuse_conn merge default is no longer 1"
