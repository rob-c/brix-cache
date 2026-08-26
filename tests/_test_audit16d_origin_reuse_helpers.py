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

