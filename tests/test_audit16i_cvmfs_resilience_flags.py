"""The nine CVMFS resilience flags whose `off` arm is unwritten — audit §Method,
16th tranche, ninth file.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the
measurement per (directive, VALUE) over the 128 ``ngx_conf_set_flag_slot``
directives — 256 pairs — left 106 pairs unwritten across 99 directives.  Nine of
them belong to the CVMFS resilience group, and for every one of the nine it is
the `off` arm that nothing in the suite exercises:

    brix_cvmfs_bundle          on written (test_cvmfs_bundle.py)    off NEVER
    brix_cvmfs_dict            on written (test_cvmfs_dict.py)      off NEVER
    brix_cvmfs_delta           on written (test_cvmfs_delta.py)     off NEVER
    brix_cvmfs_scrub           on written (test_cvmfs_scrub.py)     off NEVER
    brix_cvmfs_learn           on written (test_cvmfs_learn.py)     off NEVER
    brix_cvmfs_swarm           on written (_test_cvmfs_swarm_…)     off NEVER
    brix_cvmfs_unified_origin  on written (the conformance corpus)  off see below
    brix_cvmfs_trace           on written (the 15th tranche)        off see below
    brix_scvmfs                on written (the scvmfs corpus)       off NEVER

Seven of the nine have the token nowhere in ``tests/`` or ``k8s-tests/``.  The
other two have it in exactly one place each, and it is the same place: a row in
``test_cvmfs_conformance_srv_config.py``'s ``_SINGLE_SHOT`` table (:63, :74).
That table feeds ``test_duplicate_directive_rejected``, which asserts ``nginx -t``
REFUSES the second occurrence — so no merge ever runs — and
``test_full_inventory_single_config_loads``, which renders every row into one
config and asserts only that it loads.  Neither reads a behaviour, and in the
``trace`` case the inventory writes `off` with no `on` anywhere in the same
config, which is exactly why the process-wide latch below survived a suite that
already spelled the token.

All nine merge to 0, so `off` and absent produce the SAME merged value and the
reading cannot be a value comparison.  What makes the arm worth writing is that
`off` is not uniformly "the feature is idle":

* For three of them `off` skips a whole block of CONFIG-TIME validation.  A
  location that says ``brix_cvmfs_swarm off`` may omit ``brix_cache_peers``;
  ``brix_cvmfs_unified_origin off`` may name a posix backend; ``brix_scvmfs
  off`` may carry an authz mode with no issuer registry, no trust directories
  and a token-issuer file that does not exist.  §K measures each of those as a
  pair — the identical broken block under `on` and under `off`.
* For three of them the flag is not per-location at all: ``brix_cvmfs_scrub``,
  ``_learn`` and ``_swarm`` register a service per EXPORT, and a cvmfs cache
  location declares no root, so every such location in a config canonicalises
  to the same export "/" (cvmfs_module_build.c:215-217).
* For one of them the flag is not even per-worker-configurable: the merge of
  ``brix_cvmfs_trace on`` writes a process-wide latch with no else.
* And for the remaining two the `off` arm is honest, which is what makes the
  other seven readable as findings rather than as house style.

WHAT THE TABLE ESTABLISHES
--------------------------
One cvmfs export, one mock Stratum-1, one arm per instance.  Per flag, the
observable that flag owns, read under `on` / written-`off` / absent:

    bundle   POST want-list -> 200 BXB1 frame  |  405 "method not allowed" (x2)
             GET  endpoint  -> 405 POST-only   |  403 "…disabled (…bundle off)"
    dict     GET  current   -> 200 + dict id   |  403 "…disabled (…dict off)"
                                                  (the quoted sentences are the
                                                  cause= span cvmfs_reject logs;
                                                  the client gets a bare page)
    delta    GET  w/ base   -> zstd-delta      |  identity, no headers (x2)
    scrub    corrupt object -> evicted, N pass |  kept, 0 passes (x2)
    learn    train, evict   -> prewarmed       |  not prewarmed (x2)
    swarm    GET  roster    -> 200 roster-v1   |  403 "not a CVMFS traffic shape"
    unified  proxy-form GET -> 200 (own origin)|  504 (the named origin is dead)
    scvmfs   cleartext GET  -> 400 (TLS gate)  |  200 (x2)

FINDING — DEFECT CANDIDATE #80
------------------------------
``brix_cvmfs_trace`` is a location-level flag that cannot be turned off.  Its
merge (cvmfs_module_merge.c:167-172) is

    ngx_conf_merge_value(conf->cvmfs.trace, prev->cvmfs.trace, 0);
    if (conf->cvmfs.trace) { brix_origin_trace_set(1); }

with no else, into ``static int g_origin_trace_info``
(fs/cache/origin/s3_transport_setup.c:31-37), read at :208 as
``level = g_origin_trace_info ? NGX_LOG_INFO : NGX_LOG_DEBUG``.  Nothing in the
tree ever passes 0.  §I measures the consequence in ONE config: a server that
says ``brix_cvmfs_trace on`` and a location that says ``off`` still writes the
upstream face of the trace at INFO, while the per-request face
(handler_finalize.c:88,100) correctly goes silent — one directive, two faces,
one of them retractable and one of them not.  This is DEFECT #57/#58's shape
(15th tranche) on a third directive, and the upstream face is the one that
matters: its lines carry the full origin URL, so a location that opted out is
still publishing its origin topology into a shared error log.

FINDING — DEFECT CANDIDATE #81
------------------------------
Two cvmfs CACHE locations in one server are ONE export.  A cache node declares
no ``brix_cvmfs_root``, so cvmfs_module_build.c:215-217 anchors it at "/", and
every per-export registration — the VFS backend entry, the cache tier, the
scrub/learn/swarm services — is keyed on that canonical root via
``brix_vfs_backend_entry_get_or_create()`` (fs/vfs/vfs_backend_config.c:320-400),
which OVERWRITES the entry it finds.  The last cvmfs location merged therefore
decides the store AND the origin for both.  §J measures it: adding a second
export whose Stratum-1 is not up yet takes the FIRST, working export down with
it — A's requests are sent to B's dead origin until the client hold expires, and
the live Stratum-1 A's own ``brix_storage_backend`` names is never contacted —
and nothing is said at parse time, even though the same file already knows how
to warn about a coherent-but-useless combination (cvmfs_module_build.c:315+, the
coords-without-geo WARN).

FINDING — DEFECT CANDIDATE #82
------------------------------
The same collapse makes ``brix_cvmfs_scrub``, ``_learn`` and ``_swarm``
per-export rather than per-location, so a location's `off` does not keep a
sibling's `on` off its own cached objects.  §J shows a location that wrote
``brix_cvmfs_scrub off`` having its objects checksummed and evicted by the
sibling's scrub, and the both-off control that proves it really is the flag.

OBSERVATION — the bundle refusal is inverted
--------------------------------------------
``brix_cvmfs_bundle off`` has a diagnostic that names it — "bundle endpoint
disabled (brix_cvmfs_bundle off)" (gate.c:426-439) — and the operator debugging
a broken batch fetch cannot get it written.  ``cvmfs_gate_method``
(gate.c:295-307) runs FIRST and refuses any non-GET method with the generic
"method not allowed" unless the flag is on, so the POST a batch-fetch client
actually sends is rejected before class routing.  The sentence naming the flag
is reachable only by GET or HEAD — the two methods the endpoint refuses as
"POST-only" even when the flag IS on.  §A pins both halves.

Every one of these sentences is a LOG reading, not a wire reading: ``cvmfs_reject``
(gate.c:97-102) writes the ``cause="…"`` span to the error log at WARN and returns
a bare status, so the client sees nginx's stock error page.  That is the right
design — a cache must not narrate its configuration to a stranger — and it is
also what makes the inversion a real defect rather than a cosmetic one: the log
is the only audience the sentence ever had, and the request shape with the
problem writes the other sentence into it.

OBSERVATION — three reserved names, three refusal vocabularies
--------------------------------------------------------------
Turned off, the three reserved endpoint names under a cvmfs prefix are refused
with three different logged causes at two different statuses: the bundle and dict
names 403 with a cause naming the directive, and the swarm roster 403s with "path
is not a CVMFS traffic shape" — which names neither the flag nor the feature,
because ``brix_cvmfs_swarm off`` does not disable the roster so much as never
register it, leaving classification to reject the path as it would any typo.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
The BEHAVIOUR of the `on` arms has owners and this file does not re-measure
them: test_cvmfs_bundle.py owns the BXB1 wire format, its caps and its
want-list negatives; test_cvmfs_dict.py the dictionary trainer;
test_cvmfs_delta.py the zstd-delta encoder; test_cvmfs_scrub.py the scrub
cursor and rate; test_cvmfs_learn.py the successor model;
_test_cvmfs_swarm_helpers.py the ring gossip; the Phase-84 conformance corpus
the unified-origin proxy face; and the scvmfs corpus the authz modes.  Each `on`
arm appears here only as the control its `off` arm is read against.
"""

import hashlib
import http.client
import json
import os
import random
import re
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
from test_cvmfs_bundle import parse_bundle

# conftest chdir()s into a scratch dir — anchor the mock import on this file.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))
from mock_stratum1 import make_repo, manifest      # noqa: E402

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16i-cvmfs")]

NAME = "lc-audit16i-cvmfs"
PORT = LIFECYCLE_SHARED_PORTS[NAME]["port"]
MOCK_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["MOCK_PORT"]
# Reserved in the ledger and never bound by anything.  Three sections need an
# address that refuses a connection rather than one that answers slowly: the
# dead half of §F's seed ring, the unreachable authority §G aims the proxy face
# at, and the not-yet-deployed Stratum-1 of §J's second export.
DEAD_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["DEAD_PORT"]
ROOT = Path(__file__).resolve().parents[1]
MOCK_SCRIPT = ROOT / "tests/cvmfs/mock_stratum1.py"

REPO_A, REPO_B = "alpha-16i.cern.ch", "beta-16i.cern.ch"
MANIFEST = ".cvmfspublished"
LIVE = f"http://{HOST}:{MOCK_PORT}"
DEAD = f"http://{HOST}:{DEAD_PORT}"

# The nine, and the eight of them that are MAIN|SRV|LOC.  brix_scvmfs is the
# odd one out — LOC_CONF only (directives_secure.h), which §K pins.
FLAGS = ("brix_cvmfs_bundle", "brix_cvmfs_dict", "brix_cvmfs_delta",
         "brix_cvmfs_scrub", "brix_cvmfs_learn", "brix_cvmfs_swarm",
         "brix_cvmfs_unified_origin", "brix_cvmfs_trace", "brix_scvmfs")
SCOPED_FLAGS = tuple(f for f in FLAGS if f != "brix_scvmfs")

# The two arms that share a merged value.  Every runtime section reads both:
# "off" is the token under test and "absent" is the control that says whether
# writing it changed anything at all.
CLOSED_ARMS = ("written-off", "absent")


# --------------------------------------------------------------------------- #
# The corpora                                                                  #
# --------------------------------------------------------------------------- #

def _cas_rel(body: bytes) -> str:
    """The repo-relative CAS path an honest content address puts `body` at.

    The delta and dict corpora are fetched THROUGH the cache, which verifies
    the object against its own path, so a made-up path would be evicted as
    corrupt before any flag could be read off it.
    """
    digest = hashlib.sha1(body).hexdigest()
    return f"data/{digest[:2]}/{digest[2:]}"


def _revisions() -> tuple[bytes, bytes]:
    """Two revisions of one catalogue with ~1% churn — the shape a delta
    encoder exists for, and the shape test_cvmfs_delta.py measures the encoder
    itself against."""
    rng = random.Random(1087)

    def entry(index: int) -> str:
        return (f"entry.{index} hash={rng.getrandbits(160):040x} "
                f"size={rng.randint(1, 1 << 20)} mode=0644 flags=regular\n")

    lines = [entry(i) for i in range(4000)]
    base = "".join(lines).encode()
    bumped = list(lines)
    for index in rng.sample(range(len(bumped)), 40):
        bumped[index] = entry(index)
    return base, "".join(bumped).encode()


REV_N, REV_N1 = _revisions()
# Twelve objects sharing most of their bytes: a dictionary trainer needs a
# corpus with cross-object redundancy or it has nothing to learn.
DICT_BODIES = tuple(
    (f"# dict corpus {i} — shared boilerplate\n".encode()
     + b"".join(f"field.{j} value={i}:{j}\n".encode() for j in range(200)))
    for i in range(12))
EXTRA_BODIES = (REV_N, REV_N1) + DICT_BODIES


def _forge(root: Path) -> Path:
    """Both repositories on disk in the layout the mock serves from a webroot.

    The extras (the delta revisions and the dictionary corpus) go under REPO_A
    only: they are what a section fetches, and REPO_B exists to be a SECOND
    export rather than a second corpus.
    """
    for repo, seed in ((REPO_A, 11), (REPO_B, 23)):
        paths = {f"/cvmfs/{repo}/{MANIFEST}": manifest(repo, 1)}
        paths.update(make_repo(repo, 4, seed=seed))
        for url_path, body in paths.items():
            target = root / url_path.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
    for body in EXTRA_BODIES:
        target = root / "cvmfs" / REPO_A / _cas_rel(body)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    return root


def _base_rels(repo: str) -> list[str]:
    """The four repo-relative CAS paths `_forge` put under `repo`, sorted.

    Sorted rather than in make_repo's own order because several sections name
    "the first object" and "its successor" across separate instances, and those
    have to be the same two objects every time or §E is training one pair and
    reading another.
    """
    seed = 11 if repo == REPO_A else 23
    prefix = f"/cvmfs/{repo}/"
    return sorted(url[len(prefix):] for url in make_repo(repo, 4, seed=seed))


# --------------------------------------------------------------------------- #
# The origin                                                                   #
# --------------------------------------------------------------------------- #

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
    """Who is listening on a fixed ledger port, named rather than numbered —
    the ledger's claim is that on this lane it can only be this file's own
    mock, and neither port assertion below is actionable without the name."""
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


class _Mock:
    """The mock Stratum-1 plus the one question this file asks it: what it was
    asked for, and what it was asked for since a moment ago."""

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

    def reset(self):
        self._ctl("reset-log", method="POST")


@pytest.fixture
def mock(tmp_path):
    """The one live origin every fill in this file comes from."""
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

def _arm(*lines, indent=12):
    """Config lines at a template slot's indentation."""
    return "".join(" " * indent + line + "\n" for line in lines)


def _flag(name, arm, *extra):
    """The three arms of one flag, with the arm-independent support lines.

    `extra` is written on ALL THREE arms on purpose: a `swarm off` location that
    also dropped ``brix_cache_peers`` would be a two-directive change, and the
    reading would no longer belong to the flag.
    """
    lines = list(extra)
    if arm != "absent":
        lines.insert(0, f"{name} {'on' if arm == 'on' else 'off'};")
    return _arm(*lines)


def _start(lifecycle, tmp_path, *, loc_arm="", srv_arm="", http_arm="",
           backend=LIVE):
    """One arm, one process.

    Every arm is its own instance rather than another location on a shared one.
    Three of the nine flags register their service per EXPORT and every cvmfs
    cache location in a config shares the export "/" (§J), and a fourth writes a
    process-wide latch (§I) — so two arms in one worker do not measure two arms,
    they measure whichever one merged last.
    """
    cache = tmp_path / "cache-a"
    cache.mkdir(exist_ok=True)
    return lifecycle.start(NginxInstanceSpec(
        name=NAME, template="nginx_audit16i_cvsolo.conf", protocol="http",
        data_root=str(tmp_path / "data"),
        template_values={"BIND_HOST": BIND_HOST, "CACHE_A": str(cache),
                         "BACKEND": backend, "LOC_ARM": loc_arm,
                         "SRV_ARM": srv_arm, "HTTP_ARM": http_arm},
        reason="audit-16i the cvmfs resilience flags at value granularity"))


def _start_pair(lifecycle, tmp_path, *, arm_a="", arm_b="",
                backend_a=LIVE, backend_b=LIVE):
    """Two cvmfs cache locations on one listener — §J's subject."""
    caches = {}
    for key in ("a", "b"):
        path = tmp_path / f"cache-{key}"
        path.mkdir(exist_ok=True)
        caches[key] = str(path)
    return lifecycle.start(NginxInstanceSpec(
        name=NAME, template="nginx_audit16i_cvpair.conf", protocol="http",
        data_root=str(tmp_path / "data"),
        template_values={"BIND_HOST": BIND_HOST, "REPO_A": REPO_A,
                         "REPO_B": REPO_B, "CACHE_A": caches["a"],
                         "CACHE_B": caches["b"], "BACKEND_A": backend_a,
                         "BACKEND_B": backend_b, "LOC_ARM_A": arm_a,
                         "LOC_ARM_B": arm_b},
        reason="audit-16i two cvmfs cache locations are one export"))


# --------------------------------------------------------------------------- #
# The reading                                                                  #
# --------------------------------------------------------------------------- #

def _url(endpoint, repo, path):
    return f"http://{HOST}:{endpoint.port}/cvmfs/{repo}/{path}"


def _fetch(endpoint, repo, path=MANIFEST, method="GET", data=None,
           headers=None, timeout=90):
    """One request through the listener.

    A transport failure is re-raised carrying the instance's error log: it is
    the one outcome that lands BEFORE any assertion, so without this it is the
    one outcome whose evidence the teardown wipe destroys.
    """
    url = _url(endpoint, repo, path)
    try:
        return requests.request(method, url, data=data, headers=headers,
                                timeout=timeout)
    except requests.RequestException as exc:
        raise AssertionError(
            f"the listener did not answer {method} /cvmfs/{repo}/{path} on "
            f"port {endpoint.port}: {exc!r}\n{_errlog(endpoint)}") from exc


def _absolute_form(endpoint, authority, repo, path, timeout=60):
    """A proxy-form request line — the shape a CVMFS client uses when this node
    is its HTTP proxy, and the only shape the unified-origin face answers.

    requests cannot send one: the request target has to be an absolute URI
    naming an authority that is NOT the connected socket, which is exactly what
    every client library normalises away.
    """
    conn = http.client.HTTPConnection(HOST, endpoint.port, timeout=timeout)
    target = f"http://{authority}/cvmfs/{repo}/{path}"
    started = time.time()
    try:
        conn.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", authority)
        conn.endheaders()
        response = conn.getresponse()
        return response.status, response.read(), round(time.time() - started, 1)
    except (OSError, http.client.HTTPException) as exc:
        raise AssertionError(
            f"the listener did not answer the proxy-form GET for {target}: "
            f"{exc!r}\n{_errlog(endpoint)}") from exc
    finally:
        conn.close()


def _session(endpoint, timeout=60):
    """One keep-alive connection.  The prefetch learner keys its successor
    model on the connection, so two requests down two connections are two
    sessions of one request and train nothing."""
    return http.client.HTTPConnection(HOST, endpoint.port, timeout=timeout)


def _session_get(conn, repo, path):
    conn.request("GET", f"/cvmfs/{repo}/{path}")
    response = conn.getresponse()
    body = response.read()
    return response.status, body


def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(endpoint.prefix, "logs", "error.log")) as handle:
            return handle.read()
    except OSError:
        return "(error log unavailable)"


def _count(endpoint, needle):
    return sum(needle in line for line in _errlog(endpoint).splitlines())


_REJECT_CAUSE = re.compile(r'cvmfs-reject:[^\n]*cause="([^"]*)"')


def _causes(endpoint):
    """Every ``cause="…"`` a cvmfs refusal wrote to this instance's error log.

    A refused request gets nginx's stock error page: the sentence that says WHY
    is written by ``cvmfs_reject`` (gate.c:97-102) to the error log and never to
    the client.  So every refusal-vocabulary reading in this file is an OPERATOR
    reading, which is what makes §A's inversion matter — the diagnostic that
    names the directive to flip is unreachable by the request shape that has the
    problem, and the operator staring at the log is the only audience it had.
    """
    return _REJECT_CAUSE.findall(_errlog(endpoint))


def _settle(seconds=0.5):
    """The fill and the trace both run on a worker thread and their last lines
    can land after the response body has already been read by the client."""
    time.sleep(seconds)


def _resident(tmp_path, repo, rel):
    """The one cached copy of an object, in whichever store the export ended up
    holding.  §J is the reason this searches rather than looks: two cvmfs cache
    locations share one export and the LAST one merged owns the store, so the
    object a request through location A filled is under location B's path.
    """
    for key in ("a", "b"):
        candidate = tmp_path / f"cache-{key}" / "cvmfs" / repo / rel
        if candidate.exists():
            return candidate
    return None


def _await_gone(path, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not path.exists():
            return True
        time.sleep(0.2)
    return False


def _await_present(path, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return True
        time.sleep(0.2)
    return False


def _warm(endpoint, repo, rels):
    """Fill the manifest and each named object through the cache."""
    response = _fetch(endpoint, repo)
    assert response.status_code == 200, (
        f"the manifest did not fill: {response.status_code}\n"
        f"{_errlog(endpoint)}")
    for rel in rels:
        response = _fetch(endpoint, repo, rel)
        assert response.status_code == 200, (
            f"{rel} did not fill: {response.status_code}\n{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# A. brix_cvmfs_bundle                                                         #
# --------------------------------------------------------------------------- #

BUNDLE_PATH = ".cvmfs-bundle"
BUNDLE_DISABLED = "bundle endpoint disabled (brix_cvmfs_bundle off)"
BUNDLE_POST_ONLY = "bundle endpoint is POST-only"
METHOD_NOT_ALLOWED = "method not allowed"


def _want(rels):
    """The batch-fetch want-list wire format: newline-separated repo-relative
    CAS paths (protocols/cvmfs/bundle.c:99-153)."""
    return ("\n".join(rels) + "\n").encode()


class TestTheBundleEndpoint:
    """The batch-fetch endpoint under each arm, and the two refusals that never
    meet the client they were written for."""

    def test_on_answers_the_post_with_a_frame_of_what_was_asked_for(
            self, lifecycle, tmp_path, mock):
        """success: the control every `off` reading below is taken against.

        The wire format itself belongs to test_cvmfs_bundle.py — this asks only
        that the endpoint is open, so that a 405 in the next test is the flag
        and not the corpus.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_bundle", "on"))
        rels = _base_rels(REPO_A)[:2]
        _warm(endpoint, REPO_A, rels)
        response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method="POST",
                          data=_want(rels))
        assert response.status_code == 200, (
            f"{response.status_code}: {response.content[:200]!r}\n"
            f"{_errlog(endpoint)}")
        items = parse_bundle(response.content)
        assert [path for path, _ in items] == rels, items
        assert all(data for _, data in items), "a warm object came back a miss"

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_endpoint_refuses_the_post_without_ever_naming_the_flag(
            self, lifecycle, tmp_path, mock, arm):
        """error + the first half of the refusal inversion.

        ``cvmfs_gate_method`` (gate.c:295-307) refuses a non-GET method before
        class routing unless the bundle flag is on, so the POST a batch-fetch
        client sends is answered with the generic "method not allowed".  The
        sentence that names the directive is never reached by this request, and
        writing `off` is byte-identical to writing nothing.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_bundle", arm))
        rels = _base_rels(REPO_A)[:2]
        _warm(endpoint, REPO_A, rels)
        response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method="POST",
                          data=_want(rels))
        assert response.status_code == 405, (
            f"a closed bundle endpoint answered POST with "
            f"{response.status_code}\n{_errlog(endpoint)}")
        causes = _causes(endpoint)
        assert METHOD_NOT_ALLOWED in causes, (
            f"causes: {causes}\n{_errlog(endpoint)}")
        assert BUNDLE_DISABLED not in causes, (
            "the POST now reaches the refusal that names the directive — the "
            f"inversion this case pins may be fixed: {causes}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_endpoint_never_reaches_the_want_list_parser(
            self, lifecycle, tmp_path, mock, arm):
        """security-negative: `off` closes the parser, not just the feature.

        A want-list carrying a traversal is a 400 from
        ``cvmfs_bundle_parse_want`` when the endpoint is open.  Closed, the same
        body is refused at 405 by the method gate — which is the stronger
        property: the untrusted body is never parsed at all.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_bundle", arm))
        response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method="POST",
                          data=_want(["../../../../etc/passwd"]))
        assert response.status_code == 405, (
            "a closed bundle endpoint parsed a traversal want-list: "
            f"{response.status_code} {response.content[:200]!r}\n"
            f"{_errlog(endpoint)}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_the_sentence_naming_the_flag_needs_a_method_the_endpoint_refuses(
            self, lifecycle, tmp_path, mock, arm):
        """The second half of the inversion, and the `off` arm's own wire.

        GET and HEAD DO reach class routing, so they see the 403 that names the
        directive — and those are precisely the two methods the endpoint refuses
        as POST-only when the flag is on.  Every method therefore gets a
        diagnostic written for the other one.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_bundle", arm))
        for method in ("GET", "HEAD"):
            response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method=method)
            assert response.status_code == 403, (
                f"{method} on a closed bundle endpoint answered "
                f"{response.status_code}\n{_errlog(endpoint)}")
        causes = _causes(endpoint)
        assert BUNDLE_DISABLED in causes, (
            f"causes: {causes}\n{_errlog(endpoint)}")

    def test_an_open_endpoint_refuses_the_only_methods_that_can_read_its_cause(
            self, lifecycle, tmp_path, mock):
        """The control that closes the inversion: with the flag ON, the GET
        that would have carried the "disabled" cause is itself refused."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_bundle", "on"))
        response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method="GET")
        assert response.status_code == 405, (
            f"an open bundle endpoint answered GET with "
            f"{response.status_code}\n{_errlog(endpoint)}")
        causes = _causes(endpoint)
        assert BUNDLE_POST_ONLY in causes, (
            f"causes: {causes}\n{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# B. brix_cvmfs_dict                                                           #
# --------------------------------------------------------------------------- #

DICT_CURRENT = ".cvmfs-dict/current"
DICT_DISABLED = "dict endpoint disabled (brix_cvmfs_dict off)"


class TestTheSharedDictionaryEndpoint:
    """The dictionary endpoint is GET-only, so unlike §A both arms speak the
    same method and the whole difference is the status."""

    def test_on_trains_a_dictionary_and_serves_it_under_an_id(
            self, lifecycle, tmp_path, mock):
        """success: the control.  The trainer's own quality belongs to
        test_cvmfs_dict.py; what is needed here is that the endpoint answers
        and that the error log carries the training line, so the `off` arm's
        silence below is a decision and not an empty corpus."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_dict", "on"))
        _warm(endpoint, REPO_A, [_cas_rel(body) for body in DICT_BODIES])
        response = _fetch(endpoint, REPO_A, DICT_CURRENT)
        assert response.status_code == 200, (
            f"{response.status_code}\n{_errlog(endpoint)}")
        assert response.content, "an empty dictionary is not a dictionary"
        dict_id = response.headers.get("X-Brix-Dict-Id", "")
        assert len(dict_id) == 40 and all(c in "0123456789abcdef" for c in dict_id), (
            f"X-Brix-Dict-Id is not a content address: {dict_id!r}")
        assert _count(endpoint, "cvmfs-dict:") >= 1, _errlog(endpoint)

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_endpoint_refuses_the_whole_namespace_and_names_the_flag(
            self, lifecycle, tmp_path, mock, arm):
        """error: 403 with the cause naming the directive — and not only for
        `current`.  A client that already knows a dictionary id (from a previous
        revision, or from a sibling cache) must not be able to reach one by
        naming it, so the arm is read at both spellings of the endpoint."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_dict", arm))
        _warm(endpoint, REPO_A, [_cas_rel(body) for body in DICT_BODIES[:3]])
        known_id = hashlib.sha1(b"a dictionary that was never trained").hexdigest()
        for path in (DICT_CURRENT, f".cvmfs-dict/{known_id}"):
            response = _fetch(endpoint, REPO_A, path)
            assert response.status_code == 403, (
                f"{path} answered {response.status_code} with the dict "
                f"endpoint {arm}\n{_errlog(endpoint)}")
        causes = _causes(endpoint)
        assert causes.count(DICT_DISABLED) == 2, (
            f"both spellings of the endpoint must refuse for the same stated "
            f"reason; causes: {causes}\n{_errlog(endpoint)}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_endpoint_never_trains(self, lifecycle, tmp_path, mock, arm):
        """security-negative: the refusal is not a filter in front of a running
        trainer.  Twelve objects through a closed location must leave no
        training line at all — otherwise `off` would be hiding a dictionary it
        had still built out of the tenant's bytes."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_dict", arm))
        _warm(endpoint, REPO_A, [_cas_rel(body) for body in DICT_BODIES])
        _settle()
        assert _count(endpoint, "cvmfs-dict:") == 0, (
            "a closed dict endpoint trained a dictionary anyway\n"
            f"{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# C. brix_cvmfs_delta                                                          #
# --------------------------------------------------------------------------- #

DELTA_BASE_HEADER = "X-Brix-Delta-Base"


def _delta_probe(endpoint):
    """Fill both revisions, then ask for the newer one naming the older as the
    base — the exact exchange a CVMFS client makes on a catalogue update."""
    _warm(endpoint, REPO_A, [_cas_rel(REV_N), _cas_rel(REV_N1)])
    return _fetch(endpoint, REPO_A, _cas_rel(REV_N1),
                  headers={DELTA_BASE_HEADER: hashlib.sha1(REV_N).hexdigest()})


class TestTheDeltaEncoding:
    """The one flag whose `off` arm answers 200 either way — which is why its
    reading is the body and the headers, not the status."""

    def test_on_answers_the_base_probe_with_a_delta(self, lifecycle, tmp_path,
                                                    mock):
        """success: the control.  ~1% churn between two 370 KB revisions must
        come back an order of magnitude smaller and labelled as an encoding the
        client has to reverse."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_delta", "on"))
        response = _delta_probe(endpoint)
        assert response.status_code == 200, (
            f"{response.status_code}\n{_errlog(endpoint)}")
        # requests decodes transfer encodings it knows; zstd-delta is not one,
        # so raw is what arrived on the wire.
        assert response.headers.get("Content-Encoding") == "zstd-delta", (
            f"headers: {dict(response.headers)}\n{_errlog(endpoint)}")
        assert response.headers.get(DELTA_BASE_HEADER), dict(response.headers)
        assert response.headers.get("Vary"), (
            "a response that varies on a request header must say so or a "
            f"shared cache will serve it to a client with a different base: "
            f"{dict(response.headers)}")
        assert len(response.content) < len(REV_N1) // 10, (
            f"{len(response.content)} bytes is not a delta of "
            f"{len(REV_N1)}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_encoder_ignores_the_base_and_serves_the_object(
            self, lifecycle, tmp_path, mock, arm):
        """error: the header is ignored, not refused.

        This is the arm an operator is actually choosing between — `off` must
        not 406 a client that offered a base, because every CVMFS client offers
        one once it has a previous revision.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_delta", arm))
        response = _delta_probe(endpoint)
        assert response.status_code == 200, (
            f"a closed encoder answered {response.status_code} to a request "
            f"carrying a delta base\n{_errlog(endpoint)}")
        assert response.headers.get("Content-Encoding") is None, (
            f"headers: {dict(response.headers)}")
        assert response.headers.get(DELTA_BASE_HEADER) is None, (
            f"headers: {dict(response.headers)}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_encoder_serves_the_whole_object_byte_for_byte(
            self, lifecycle, tmp_path, mock, arm):
        """security-negative: an unlabelled short body would be worse than a
        refusal.  A client that offered a base and got 200 with no
        Content-Encoding will write the bytes to its cache under the object's
        own content address, so those bytes have to BE the object."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_delta", arm))
        response = _delta_probe(endpoint)
        assert response.content == REV_N1, (
            f"{len(response.content)} bytes, sha1 "
            f"{hashlib.sha1(response.content).hexdigest()} != "
            f"{hashlib.sha1(REV_N1).hexdigest()}\n{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# D. brix_cvmfs_scrub                                                          #
# --------------------------------------------------------------------------- #

SCRUB_SUPPORT = ("brix_cvmfs_scrub_interval 1;", "brix_cvmfs_scrub_rate 4;")
SCRUB_PASS = "scrub pass"


def _corrupt(path):
    """Overwrite a cached object in place, keeping its size — the scrub's whole
    job is to notice that the bytes no longer hash to the name."""
    path.write_bytes(b"\x00" * path.stat().st_size)


class TestTheCacheScrub:
    """The background verifier.  Its cursor and rate belong to
    test_cvmfs_scrub.py; the arm is whether it runs at all."""

    def test_on_walks_the_cache_and_evicts_a_corrupted_object(
            self, lifecycle, tmp_path, mock):
        """success: the control."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_scrub", "on", *SCRUB_SUPPORT))
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels)
        victim = _resident(tmp_path, REPO_A, rels[0])
        assert victim is not None, f"nothing was cached\n{_errlog(endpoint)}"
        _corrupt(victim)
        assert _await_gone(victim), (
            f"the scrub left a corrupted object in the cache\n"
            f"{_errlog(endpoint)}")
        assert _count(endpoint, SCRUB_PASS) >= 1, _errlog(endpoint)

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_scrub_never_runs_a_pass(self, lifecycle, tmp_path, mock,
                                              arm):
        """error: nothing is scheduled, so nothing is checked.

        The wait is the same one the `on` arm is evicted inside, which is what
        makes "still there" a reading rather than an unfinished measurement.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_scrub", arm, *SCRUB_SUPPORT))
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels)
        victim = _resident(tmp_path, REPO_A, rels[0])
        assert victim is not None, f"nothing was cached\n{_errlog(endpoint)}"
        _corrupt(victim)
        assert not _await_gone(victim, timeout=8.0), (
            "a scrub ran with the flag off — the interval and rate lines are "
            f"written on every arm, so this is the flag\n{_errlog(endpoint)}")
        assert _count(endpoint, SCRUB_PASS) == 0, _errlog(endpoint)

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_scrub_still_serves_the_corrupted_bytes(
            self, lifecycle, tmp_path, mock, arm):
        """security-negative: what the operator is actually turning off.

        With no scrub, a cached object whose bytes have rotted is served on the
        next read; the client's own content-address check is the only thing left
        between it and a corrupt catalogue.  Pinning that here is what makes the
        `on` arm a safety property rather than a background chore.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_scrub", arm, *SCRUB_SUPPORT))
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels)
        victim = _resident(tmp_path, REPO_A, rels[0])
        assert victim is not None, f"nothing was cached\n{_errlog(endpoint)}"
        size = victim.stat().st_size
        _corrupt(victim)
        response = _fetch(endpoint, REPO_A, rels[0])
        assert response.status_code == 200, (
            f"{response.status_code}\n{_errlog(endpoint)}")
        # `_corrupt` wrote the object's length in NUL bytes, so this is the rot
        # itself arriving at the client — not merely a digest that fails to match.
        assert response.content == b"\x00" * size, (
            "the corrupted copy was not served — either the read path verifies "
            "content addresses on its own or the eviction happened without a "
            f"scrub; re-measure this section\n{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# E. brix_cvmfs_learn                                                          #
# --------------------------------------------------------------------------- #

LEARN_SUPPORT = ("brix_cvmfs_scrub on;", "brix_cvmfs_scrub_interval 1;",
                 "brix_cvmfs_scrub_rate 4;")
LEARN_LINE = "cvmfs-learn"


def _train_then_evict(endpoint, tmp_path, first, second):
    """Teach the successor model that `second` follows `first`, then take
    `second` out of the cache.

    The training rounds go down keep-alive connections because the model is
    connection-keyed, and the eviction goes through the scrub (corrupt the
    cached copy and let the verifier drop it) because that is the one way to
    empty a slot without also telling the cache the object was wanted.
    """
    _warm(endpoint, REPO_A, [first, second])
    for _ in range(2):
        conn = _session(endpoint)
        try:
            for rel in (first, second):
                status, _ = _session_get(conn, REPO_A, rel)
                assert status == 200, f"{rel}: {status}\n{_errlog(endpoint)}"
        finally:
            conn.close()
    resident = _resident(tmp_path, REPO_A, second)
    assert resident is not None, f"nothing was cached\n{_errlog(endpoint)}"
    _corrupt(resident)
    assert _await_gone(resident), (
        f"the scrub never evicted the successor\n{_errlog(endpoint)}")
    return resident


class TestThePrefetchLearner:
    """A read of A must pull B in behind it once the model has seen the pair —
    or must not, which is the arm."""

    def test_on_prewarms_the_successor_of_a_single_read(self, lifecycle,
                                                        tmp_path, mock):
        """success: the control.  The model itself belongs to
        test_cvmfs_learn.py; what is read here is that a lone GET of A puts B
        back in the cache without anyone asking for B."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_learn", "on", *LEARN_SUPPORT))
        first, second = _base_rels(REPO_A)[:2]
        slot = _train_then_evict(endpoint, tmp_path, first, second)
        conn = _session(endpoint)
        try:
            status, _ = _session_get(conn, REPO_A, first)
            assert status == 200, f"{status}\n{_errlog(endpoint)}"
        finally:
            conn.close()
        assert _await_present(slot), (
            f"the successor was never prewarmed\n{_errlog(endpoint)}")
        assert _count(endpoint, LEARN_LINE) >= 1, _errlog(endpoint)

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_learner_leaves_the_successor_cold(self, lifecycle,
                                                        tmp_path, mock, arm):
        """error: the same training, the same eviction, the same lone read —
        and nothing comes back.  The scrub lines on every arm are what prove the
        instance was otherwise doing its job."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_learn", arm, *LEARN_SUPPORT))
        first, second = _base_rels(REPO_A)[:2]
        slot = _train_then_evict(endpoint, tmp_path, first, second)
        conn = _session(endpoint)
        try:
            status, _ = _session_get(conn, REPO_A, first)
            assert status == 200, f"{status}\n{_errlog(endpoint)}"
        finally:
            conn.close()
        assert not _await_present(slot, timeout=6.0), (
            "the successor was prewarmed with the learner off\n"
            f"{_errlog(endpoint)}")
        assert _count(endpoint, LEARN_LINE) == 0, _errlog(endpoint)

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_learner_does_not_reach_the_origin_uninvited(
            self, lifecycle, tmp_path, mock, arm):
        """security-negative: a prefetcher is an origin-load amplifier, and
        turning it off has to stop the REQUESTS, not just the cache writes.  The
        origin's own log is the only place that difference is visible."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_learn", arm, *LEARN_SUPPORT))
        first, second = _base_rels(REPO_A)[:2]
        _train_then_evict(endpoint, tmp_path, first, second)
        mock.reset()
        conn = _session(endpoint)
        try:
            status, _ = _session_get(conn, REPO_A, first)
            assert status == 200, f"{status}\n{_errlog(endpoint)}"
        finally:
            conn.close()
        _settle(2.0)
        asked = [path for path in mock.paths() if path.endswith(second)]
        assert asked == [], (
            f"a closed learner still fetched the successor from the origin: "
            f"{asked}\n{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# F. brix_cvmfs_swarm                                                          #
# --------------------------------------------------------------------------- #

ROSTER = ".swarm/roster"
NOT_CVMFS = "path is not a CVMFS traffic shape"


def _swarm_support():
    """The seed ring.  Written on every arm, including the closed ones: the
    directive parses with the flag off (§K) and leaving it out would make the
    reading "no peers" rather than "swarm off".

    The ring names this node (the ledger's own port, which the lifecycle harness
    has already rebased to the real one) and one member that is not listening,
    because a roster of one live node cannot show a ring that was seeded from
    the directive rather than from the listener it happens to be on.
    """
    return (f"brix_cache_peers self={HOST}:{PORT} {HOST}:{DEAD_PORT};",
            "brix_cvmfs_swarm_interval 1;")


def _roster(endpoint, timeout=30):
    """The roster is a reserved name directly under the cvmfs prefix, not under
    a repository, so it does not go through `_fetch`."""
    url = f"http://{HOST}:{endpoint.port}/cvmfs/{ROSTER}"
    try:
        return requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        raise AssertionError(
            f"the listener did not answer the roster on port {endpoint.port}: "
            f"{exc!r}\n{_errlog(endpoint)}") from exc


class TestTheSwarmRoster:
    """The peer ring publishes itself at a reserved name under the cvmfs prefix,
    which is what makes its `off` arm readable over HTTP at all."""

    def test_on_publishes_a_live_ring_naming_this_node(self, lifecycle,
                                                       tmp_path, mock):
        """success: the control.  The gossip belongs to the swarm corpus; what
        is read here is that the roster answers and that the seed ring was
        taken from brix_cache_peers."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_swarm", "on",
                                        *_swarm_support()))
        _fetch(endpoint, REPO_A)
        _settle(2.5)
        response = _roster(endpoint)
        assert response.status_code == 200, (
            f"{response.status_code}: {response.text[:200]}\n"
            f"{_errlog(endpoint)}")
        assert response.headers.get("Content-Type", "").startswith("text/plain")
        assert response.text.startswith("swarm-roster-v1"), response.text
        assert f"{HOST}:{PORT} alive" in response.text, (
            f"the ring does not name this node as alive:\n{response.text}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_swarm_leaves_the_roster_name_unclassifiable(
            self, lifecycle, tmp_path, mock, arm):
        """error, and the third refusal vocabulary.

        ``brix_cvmfs_swarm off`` does not disable the roster — it never
        registers it, so ``cvmfs_gate_meta`` (gate.c:262-289) does not intercept
        the path and classification rejects it exactly as it would a typo.  The
        answer names neither the directive nor the feature, which is the one
        thing an operator debugging a silent ring has to be told.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_swarm", arm,
                                        *_swarm_support()))
        _fetch(endpoint, REPO_A)
        _settle(2.5)
        response = _roster(endpoint)
        assert response.status_code == 403, (
            f"a closed roster answered {response.status_code}\n"
            f"{_errlog(endpoint)}")
        causes = _causes(endpoint)
        assert NOT_CVMFS in causes, f"causes: {causes}\n{_errlog(endpoint)}"
        assert not any("swarm" in cause for cause in causes), (
            f"the refusal now mentions the feature — pin the new wording here: "
            f"{causes}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_swarm_never_seeds_a_ring(self, lifecycle, tmp_path, mock,
                                               arm):
        """security-negative: the peers stay unread.

        ``brix_cache_peers`` names hosts this node would otherwise gossip cache
        contents to.  With the flag off the ring must never be seeded, so the
        directive is inert config rather than a list this node is quietly
        talking to behind a 403.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_swarm", arm,
                                        *_swarm_support()))
        _fetch(endpoint, REPO_A)
        _settle(2.5)
        assert _count(endpoint, "seeded") == 0, _errlog(endpoint)
        assert _count(endpoint, "live ring") == 0, _errlog(endpoint)


# --------------------------------------------------------------------------- #
# G. brix_cvmfs_unified_origin                                                 #
# --------------------------------------------------------------------------- #

# Bounds so the closed arm's failure lands inside a test rather than inside the
# default 25s client hold and 300s fill lifetime.  Written on every arm.
UNIFIED_SUPPORT = (f"brix_cvmfs_upstream_allow {HOST};",
                   "brix_cvmfs_origin_connect_timeout 1;",
                   "brix_cvmfs_client_hold 4;",
                   "brix_cvmfs_fill_max_life 8;")


class TestTheUnifiedOriginProxy:
    """In proxy mode a request names its own upstream.  `on` serves it from the
    location's configured origin instead; `off` goes to the named one."""

    def test_on_serves_a_named_dead_origin_from_the_locations_own_backend(
            self, lifecycle, tmp_path, mock):
        """success: the control, and the whole point of the feature — a client
        pointed at a Stratum-1 that is down still gets its bytes."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_unified_origin", "on",
                                        *UNIFIED_SUPPORT))
        _fetch(endpoint, REPO_A)
        cold = _base_rels(REPO_A)[1]
        status, body, _ = _absolute_form(endpoint, f"{HOST}:{DEAD_PORT}",
                                         REPO_A, cold)
        assert status == 200, (
            f"{status}: {body[:200]!r}\n{_errlog(endpoint)}")
        assert body, "an empty body is not a fill"

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_proxy_honours_the_named_origin_and_times_out_on_it(
            self, lifecycle, tmp_path, mock, arm):
        """error: the request goes where the client said, and the client said a
        socket that refuses.  This is the arm, and it is why the flag exists."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_unified_origin", arm,
                                        *UNIFIED_SUPPORT))
        _fetch(endpoint, REPO_A)
        cold = _base_rels(REPO_A)[1]
        status, _, _ = _absolute_form(endpoint, f"{HOST}:{DEAD_PORT}",
                                      REPO_A, cold)
        assert status == 504, (
            f"a closed unified origin answered {status} for an origin that is "
            f"not listening\n{_errlog(endpoint)}")

    @pytest.mark.parametrize("arm", ("on",) + CLOSED_ARMS)
    def test_no_arm_answers_for_an_authority_outside_the_allowlist(
            self, lifecycle, tmp_path, mock, arm):
        """security-negative: `on` is not an open proxy.

        Serving a named origin's path from a local backend is exactly the shape
        of an open relay, so the allowlist has to be checked BEFORE the
        substitution — measured on all three arms, because a check that only
        holds while the feature is off is not a check.

        The authority is `localhost` on purpose: it resolves to the very address
        the allowlist DOES name, so a check that had been written against the
        resolved address rather than the requested name would pass this request
        and this case would catch it.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_unified_origin", arm,
                                        *UNIFIED_SUPPORT))
        _fetch(endpoint, REPO_A)
        unlisted = "localhost"  # net-literal-allow: the subject under test is a NAME an allowlist keyed on names must refuse while it resolves to the allowlisted address
        status, _, _ = _absolute_form(endpoint, f"{unlisted}:{MOCK_PORT}",
                                      REPO_A, _base_rels(REPO_A)[1])
        assert status == 403, (
            f"an authority outside brix_cvmfs_upstream_allow answered {status} "
            f"with the flag {arm}\n{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# H. brix_scvmfs                                                               #
# --------------------------------------------------------------------------- #

SCVMFS_SUPPORT = ("brix_scvmfs_authz none;",)


class TestTheSecureCvmfsLayer:
    """Secure-CVMFS is a LAYER on cvmfs whose preamble requires TLS.  On a
    cleartext listener that makes the flag's arm the whole listener's fate."""

    def test_on_refuses_every_request_on_a_cleartext_listener(
            self, lifecycle, tmp_path, mock):
        """success (of the gate): the preamble (secure.c:284-322) answers 400
        when ``r->connection->ssl`` is NULL, before any repo or path is
        considered.  Even the manifest — the one object a client fetches before
        it has any credentials at all — is refused."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_scvmfs", "on", *SCVMFS_SUPPORT))
        for path in (MANIFEST, _base_rels(REPO_A)[0]):
            response = _fetch(endpoint, REPO_A, path)
            assert response.status_code == 400, (
                f"{path} answered {response.status_code} on a cleartext "
                f"listener with brix_scvmfs on\n{_errlog(endpoint)}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_layer_leaves_the_cleartext_export_serving(
            self, lifecycle, tmp_path, mock, arm):
        """error: the same listener, the same requests, 200.  This is what
        makes the previous test the flag rather than the listener."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_scvmfs", arm, *SCVMFS_SUPPORT))
        for path in (MANIFEST, _base_rels(REPO_A)[0]):
            response = _fetch(endpoint, REPO_A, path)
            assert response.status_code == 200, (
                f"{path} answered {response.status_code} with brix_scvmfs "
                f"{arm}\n{_errlog(endpoint)}")
            assert response.content, "an empty body is not a fill"


# --------------------------------------------------------------------------- #
# I. What a child location can take back — DEFECT CANDIDATE #80                #
# --------------------------------------------------------------------------- #

# One probe per flag, each returning a value that differs between "the server's
# `on` reached this location" and "the location's `off` won".  The support lines
# ride at server level with the `on`, so the location writes exactly one word.
INHERIT_SUPPORT = {
    "brix_cvmfs_scrub": SCRUB_SUPPORT,
    "brix_cvmfs_learn": LEARN_SUPPORT,
    "brix_cvmfs_swarm": None,          # filled in at call time — needs the port
    "brix_cvmfs_unified_origin": UNIFIED_SUPPORT,
}


def _inherit_probe(flag, endpoint, tmp_path):
    """The flag's own observable, reduced to True = "the feature ran here"."""
    if flag == "brix_cvmfs_bundle":
        rels = _base_rels(REPO_A)[:2]
        _warm(endpoint, REPO_A, rels)
        response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method="POST",
                          data=_want(rels))
        return response.status_code == 200
    if flag == "brix_cvmfs_dict":
        _warm(endpoint, REPO_A, [_cas_rel(b) for b in DICT_BODIES])
        return _fetch(endpoint, REPO_A, DICT_CURRENT).status_code == 200
    if flag == "brix_cvmfs_delta":
        return _delta_probe(endpoint).headers.get(
            "Content-Encoding") == "zstd-delta"
    if flag == "brix_cvmfs_scrub":
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels)
        victim = _resident(tmp_path, REPO_A, rels[0])
        assert victim is not None, f"nothing was cached\n{_errlog(endpoint)}"
        _corrupt(victim)
        return _await_gone(victim, timeout=12.0)
    if flag == "brix_cvmfs_learn":
        first, second = _base_rels(REPO_A)[:2]
        slot = _train_then_evict(endpoint, tmp_path, first, second)
        conn = _session(endpoint)
        try:
            _session_get(conn, REPO_A, first)
        finally:
            conn.close()
        return _await_present(slot, timeout=10.0)
    if flag == "brix_cvmfs_swarm":
        _fetch(endpoint, REPO_A)
        _settle(2.5)
        return _roster(endpoint).status_code == 200
    if flag == "brix_cvmfs_unified_origin":
        _fetch(endpoint, REPO_A)
        status, _, _ = _absolute_form(endpoint, f"{HOST}:{DEAD_PORT}", REPO_A,
                                      _base_rels(REPO_A)[1])
        return status == 200
    raise AssertionError(f"no probe for {flag}")


# brix_cvmfs_trace is deliberately not in this list: it is the one flag whose
# probe does not reduce to a single boolean, because its two faces disagree.
INHERITED_FLAGS = ("brix_cvmfs_bundle", "brix_cvmfs_dict", "brix_cvmfs_delta",
                   "brix_cvmfs_scrub", "brix_cvmfs_learn", "brix_cvmfs_swarm",
                   "brix_cvmfs_unified_origin")


def _inherit_start(lifecycle, tmp_path, flag, child):
    support = INHERIT_SUPPORT.get(flag)
    if flag == "brix_cvmfs_swarm":
        support = _swarm_support()
    srv_arm = _arm(f"{flag} on;", *(support or ()), indent=8)
    loc_arm = _arm(f"{flag} off;") if child == "off" else ""
    return _start(lifecycle, tmp_path, srv_arm=srv_arm, loc_arm=loc_arm)


class TestWhatAChildLocationCanTakeBack:
    """All eight of the MAIN|SRV|LOC flags are documented the same way, and one
    of them does not behave the same way."""

    @pytest.mark.parametrize("flag", INHERITED_FLAGS)
    @pytest.mark.parametrize("child", ("bare", "off"))
    def test_the_child_decides(self, lifecycle, tmp_path, mock, flag, child):
        """success + error in one parametrised pair.

        The `bare` arm is not decoration: without it, "the location's `off` won"
        is indistinguishable from "the server-level `on` never reached the
        location at all", and for seven of these eight flags it is the second
        reading that would be wrong.
        """
        endpoint = _inherit_start(lifecycle, tmp_path, flag, child)
        ran = _inherit_probe(flag, endpoint, tmp_path)
        if child == "bare":
            assert ran, (
                f"a server-level `{flag} on` did not reach the location — the "
                f"`off` arm below cannot be read against this\n"
                f"{_errlog(endpoint)}")
        else:
            assert not ran, (
                f"the location's `{flag} off` did not take back the server's "
                f"`on`\n{_errlog(endpoint)}")


class TestTheTraceLatch:
    """DEFECT CANDIDATE #80 — the eighth flag, and the one whose `off` is not a
    retraction.

    ``brix_cvmfs_trace`` has two faces.  The per-request one
    (handler_finalize.c:88,100) writes ``cvmfs-trace: client …`` off the
    location's own merged value and is honest.  The origin one
    (s3_transport_setup.c:208) writes ``cvmfs-trace: upstream …`` at INFO or
    DEBUG according to a process-wide latch that only ever gets set.  One
    config, one request, two answers.
    """

    UPSTREAM = "cvmfs-trace: upstream"
    CLIENT = "cvmfs-trace: client"

    def _read(self, endpoint):
        _warm(endpoint, REPO_A, [_base_rels(REPO_A)[0]])
        _settle(1.0)
        return (_count(endpoint, self.UPSTREAM), _count(endpoint, self.CLIENT))

    def test_a_server_level_on_reaches_a_silent_child(self, lifecycle, tmp_path,
                                                      mock):
        """success: the control.  Both faces speak when nobody retracts."""
        endpoint = _start(lifecycle, tmp_path,
                          srv_arm=_arm("brix_cvmfs_trace on;", indent=8))
        upstream, client = self._read(endpoint)
        assert upstream >= 1, f"the origin face is silent\n{_errlog(endpoint)}"
        assert client >= 1, f"the request face is silent\n{_errlog(endpoint)}"

    def test_the_child_can_take_back_only_one_of_the_two_faces(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #80.

        The location writes `off`.  The per-request face obeys.  The origin
        face — the one whose lines carry the full origin URL — keeps writing at
        INFO, because ``brix_origin_trace_set(1)`` has no counterpart and the
        merge that called it has no else (cvmfs_module_merge.c:167-172).
        """
        endpoint = _start(lifecycle, tmp_path,
                          srv_arm=_arm("brix_cvmfs_trace on;", indent=8),
                          loc_arm=_arm("brix_cvmfs_trace off;"))
        upstream, client = self._read(endpoint)
        assert client == 0, (
            "the per-request face ignored the location's `off` too — this "
            f"section's honest control is gone\n{_errlog(endpoint)}")
        assert upstream >= 1, (
            "the origin face went quiet — the process-wide trace latch now has "
            "a way back, so #80 may be fixed: replace this with the new "
            f"behaviour\n{_errlog(endpoint)}")

    def test_a_config_that_never_says_on_writes_neither_face(self, lifecycle,
                                                             tmp_path, mock):
        """error / the second control.  The latch is per-process, so "nobody
        wrote `on`" has to be silent or the reading above would just be the
        default."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_arm("brix_cvmfs_trace off;"))
        upstream, client = self._read(endpoint)
        assert (upstream, client) == (0, 0), (
            f"upstream={upstream} client={client}\n{_errlog(endpoint)}")

    def test_the_latch_has_no_caller_that_can_clear_it(self):
        """The source arm of the same finding, so a fix cannot land silently.

        A runtime test can only say the latch did not clear in the orders it
        tried.  The tree can say something stronger: nothing passes 0.
        """
        calls = subprocess.run(
            ["grep", "-rn", "brix_origin_trace_set(", "src/"],
            cwd=ROOT, capture_output=True, text=True).stdout.splitlines()
        setters = [line for line in calls if "brix_origin_trace_set(0)" in line]
        assert calls, ("the setter has no call sites left — re-read "
                       "cvmfs_module_merge.c before trusting this class")
        assert setters == [], (
            "something now clears the origin trace latch — re-measure "
            f"test_the_child_can_take_back_only_one_of_the_two_faces:\n"
            + "\n".join(calls))


# --------------------------------------------------------------------------- #
# J. Two exports are one export — DEFECT CANDIDATES #81 and #82                #
# --------------------------------------------------------------------------- #

class TestTwoCacheLocationsShareOneExport:
    """A cvmfs cache location declares no root, so it is anchored at "/"
    (cvmfs_module_build.c:215-217) and every per-export registration is keyed on
    that.  Two locations, one export — which decides both what a sibling's `on`
    can reach and whose backend the export ends up using."""

    def _corrupt_a(self, lifecycle, tmp_path, arm_a, arm_b):
        endpoint = _start_pair(lifecycle, tmp_path, arm_a=arm_a, arm_b=arm_b)
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels[:1])
        victim = _resident(tmp_path, REPO_A, rels[0])
        assert victim is not None, (
            f"location A's fill was not cached anywhere\n{_errlog(endpoint)}")
        _corrupt(victim)
        return endpoint, victim

    def test_a_siblings_scrub_evicts_the_objects_of_a_location_that_said_off(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #82.

        Location A writes ``brix_cvmfs_scrub off``.  Location B, a different
        repository, writes ``on``.  A's cached object is checksummed and
        evicted anyway: the scrub is registered against the export, and both
        locations are the same export.
        """
        endpoint, victim = self._corrupt_a(
            lifecycle, tmp_path,
            arm_a=_flag("brix_cvmfs_scrub", "written-off", *SCRUB_SUPPORT),
            arm_b=_flag("brix_cvmfs_scrub", "on", *SCRUB_SUPPORT))
        assert _await_gone(victim), (
            "the sibling's scrub no longer reaches this location's objects — "
            f"#82 may be fixed\n{_errlog(endpoint)}")

    def test_the_both_off_control_keeps_the_object(self, lifecycle, tmp_path,
                                                   mock):
        """error / the control that makes the previous test the flag.

        The identical config with B also `off`.  Nothing is evicted, so what
        reached A's objects above was B's `on` and not the scrub running
        regardless.
        """
        endpoint, victim = self._corrupt_a(
            lifecycle, tmp_path,
            arm_a=_flag("brix_cvmfs_scrub", "written-off", *SCRUB_SUPPORT),
            arm_b=_flag("brix_cvmfs_scrub", "written-off", *SCRUB_SUPPORT))
        assert not _await_gone(victim, timeout=8.0), (
            f"an object was evicted with every scrub off\n{_errlog(endpoint)}")

    def test_the_reach_does_not_depend_on_which_location_said_on(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #82, the other order — the export is shared, not
        inherited, so declaration order changes nothing."""
        endpoint, victim = self._corrupt_a(
            lifecycle, tmp_path,
            arm_a=_flag("brix_cvmfs_scrub", "on", *SCRUB_SUPPORT),
            arm_b=_flag("brix_cvmfs_scrub", "written-off", *SCRUB_SUPPORT))
        assert _await_gone(victim), (
            f"the export's scrub did not run\n{_errlog(endpoint)}")

    def test_the_last_location_merged_owns_the_store(self, lifecycle, tmp_path,
                                                     mock):
        """DEFECT CANDIDATE #81, the cache half.

        Both locations name their own ``brix_cache_store``.  A request through
        the FIRST one is cached under the SECOND one's path, because
        ``brix_vfs_backend_entry_get_or_create()`` overwrites the entry it finds
        for the shared canonical root.
        """
        endpoint = _start_pair(lifecycle, tmp_path)
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels[:2])
        _settle()
        first = list((tmp_path / "cache-a").rglob("*"))
        second = list((tmp_path / "cache-b").rglob("*"))
        assert [p for p in second if p.is_file()], (
            "nothing landed in the second location's store — re-measure, the "
            f"export collapse may be fixed\n{_errlog(endpoint)}")
        assert [p for p in first if p.is_file()] == [], (
            "the first location's own store is in use again — #81 may be "
            f"fixed; re-read the section\n{_errlog(endpoint)}")

    def test_a_new_export_with_a_dead_origin_takes_the_working_one_down(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #81, the blast radius — and the row an operator
        actually hits.

        Location A is an existing, working export pointed at a live Stratum-1.
        Location B is added for a new repository whose Stratum-1 is not up yet.
        A stops serving: its requests are sent to B's origin, retried until the
        client hold expires, and the live Stratum-1 that A's own
        ``brix_storage_backend`` names is never contacted at all.  Nothing in the
        config names A, and nothing was said at parse time (§K).

        The status is whichever bound expires first — the fill's retry ladder
        outlives the client hold, so it is 504 here and would be 502 with a
        longer hold.  The reading is therefore WHERE the request went, which the
        mock's own request log answers without ambiguity.
        """
        # Written identically in both locations: origin_connect_timeout reaches a
        # process-wide setter, so two different values would not be two bounds.
        bounds = ("brix_cvmfs_origin_connect_timeout 1;",
                  "brix_cvmfs_client_hold 4;")
        endpoint = _start_pair(lifecycle, tmp_path, backend_a=LIVE,
                              backend_b=DEAD, arm_a=_arm(*bounds),
                              arm_b=_arm(*bounds))
        mock.reset()
        response = _fetch(endpoint, REPO_A, timeout=120)
        assert response.status_code in (502, 504), (
            "the first export still serves — the origin half of the collapse "
            f"may be fixed: {response.status_code}\n{_errlog(endpoint)}")
        assert mock.paths() == [], (
            "the live Stratum-1 location A names was contacted after all, so "
            "the export kept A's backend: re-read #81\n"
            f"{_errlog(endpoint)}")
        assert _count(endpoint, f"http origin {HOST}:{DEAD_PORT} failed") >= 1, (
            "location A's fill did not go to the SECOND location's origin — "
            f"the collapse this section pins has moved\n{_errlog(endpoint)}")

    def test_the_reverse_order_serves_the_first_export_from_the_seconds_origin(
            self, lifecycle, tmp_path, mock):
        """DEFECT CANDIDATE #81, the same config in the other order.

        Now the DEAD origin is the one declared first, and the export takes the
        second location's live one — so location A serves 200 from a Stratum-1
        its own ``brix_storage_backend`` never named.  Config order, not
        location, is what selected the origin.
        """
        endpoint = _start_pair(lifecycle, tmp_path, backend_a=DEAD,
                              backend_b=LIVE)
        response = _fetch(endpoint, REPO_A, timeout=120)
        assert response.status_code == 200, (
            f"{response.status_code}\n{_errlog(endpoint)}")
        assert response.content, "an empty body is not a fill"


# --------------------------------------------------------------------------- #
# K. The parse tier                                                            #
# --------------------------------------------------------------------------- #

def _knobs(*lines):
    return "".join(f"            {line}\n" for line in lines)


def _extra_location(prefix, *lines, cvmfs=False):
    """A whole second location for the parse scaffold.  Its cache store is left
    as a CACHE2 marker for `_parse` to fill in: a test method has no reason to
    know where the scaffold puts its second store."""
    body = "".join(f"            {line}\n" for line in lines)
    head = ("            brix_cvmfs           on;\n"
            "            brix_cache_store     posix:{CACHE2};\n"
            if cvmfs else "")
    return f"\n        location {prefix} {{\n{head}{body}        }}\n"


def _diagnostics(out):
    """The lines of an `nginx -t` transcript that would tell an operator
    something is wrong.  Matching on the transcript as a whole cannot work: the
    prefix is a tmp_path named after the test, so tokens this file tests ("on",
    "off") appear in the output as part of a directory name."""
    return [line for line in out.splitlines()
            if any(sev in line for sev in ("[warn]", "[error]", "[crit]",
                                           "[emerg]"))]


def _parse(tmp_path, knobs="", srv_knobs="", http_knobs="", outer="", extra="",
           backend=LIVE):
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    cache2 = tmp_path / "cache2"
    cache2.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit16iparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, LOG_DIR=str(tmp_path),
                     CACHE=str(cache), BACKEND=backend, KNOBS=knobs,
                     SRV_KNOBS=srv_knobs, HTTP_KNOBS=http_knobs, OUTER=outer,
                     EXTRA=extra.replace("{CACHE2}", str(cache2)))
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


SCOPE_SLOT = {"location": "knobs", "server": "srv_knobs", "http": "http_knobs"}
SCOPE_INDENT = {"location": 12, "server": 8, "http": 4}


def _at(scope, *lines):
    """One directive placed in one scope, as the kwargs `_parse` wants."""
    indent = SCOPE_INDENT[scope]
    return {SCOPE_SLOT[scope]:
            "".join(" " * indent + line + "\n" for line in lines)}


class TestTheParseTier:
    """What the nine accept and refuse.  Nothing here starts a server, and every
    case damages only its own tmp_path copy of the scaffold."""

    @pytest.mark.parametrize("value", ("on", "off"))
    @pytest.mark.parametrize("scope", ("location", "server", "http"))
    @pytest.mark.parametrize("flag", SCOPED_FLAGS)
    def test_both_arms_parse_in_all_three_http_scopes(self, tmp_path, flag,
                                                      scope, value):
        """success: eight of the nine are MAIN|SRV|LOC
        (directives_resilience.h), so `off` is speakable everywhere `on` is —
        including at http level, which is the only placement whose meaning
        matches what the per-export ones actually do."""
        lines = [f"{flag} {value};"]
        if flag == "brix_cvmfs_swarm" and value == "on":
            lines.append(f"brix_cache_peers self={HOST}:1 {HOST}:2;")
        rc, out = _parse(tmp_path, **_at(scope, *lines))
        assert rc == 0, f"{flag} {value} at {scope} was rejected\n{out}"

    @pytest.mark.parametrize("value", ("on", "off"))
    def test_the_secure_layer_is_a_location_directive_only(self, tmp_path,
                                                           value):
        """The ninth is not like the other eight.

        ``brix_scvmfs`` is NGX_HTTP_LOC_CONF alone, so a site-wide default — the
        obvious way to turn a whole server's exports secure, and the way the
        other eight accept — is refused.  An operator who writes it beside them
        gets a config that does not load, on both arms.
        """
        rc, out = _parse(tmp_path, **_at("location", f"brix_scvmfs {value};"))
        assert rc == 0, f"a location-level brix_scvmfs {value} was rejected\n{out}"
        for scope in ("server", "http"):
            rc, out = _parse(tmp_path, **_at(scope, f"brix_scvmfs {value};"))
            assert rc != 0, f"brix_scvmfs {value} parsed at {scope}\n{out}"
            assert '"brix_scvmfs" directive is not allowed here' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_each_flag_is_refused_in_the_main_context(self, tmp_path, flag):
        """security-negative: written at the top of the file each of these
        reads like a global default — and for the per-export ones that is
        effectively what a location-level value already is.  nginx must still
        refuse the placement rather than silently ignore it."""
        rc, out = _parse(tmp_path, outer=f"{flag} on;\n")
        assert rc != 0, f"a main-context {flag} parsed\n{out}"
        assert f'"{flag}" directive is not allowed here' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_non_boolean_value_is_refused(self, tmp_path, flag):
        """error: ngx_conf_set_flag_slot takes on|off and nothing else.  "1" is
        what an operator templating from a boolean variable writes, and it must
        not quietly leave the default in place."""
        rc, out = _parse(tmp_path, **_at("location", f"{flag} 1;"))
        assert rc != 0 and 'invalid value "1"' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_an_empty_value_is_refused(self, tmp_path, flag):
        """security-negative: an unset shell variable expanding to "" must not
        become `off` by accident — for brix_scvmfs that would silently drop a
        whole authorization layer off an export."""
        rc, out = _parse(tmp_path, **_at("location", f'{flag} "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_arity_is_exactly_one(self, tmp_path, flag):
        """error: NGX_CONF_FLAG is TAKE1.  "on off" is the shape someone
        reaches for when editing an arm in place and not finishing."""
        for line in (f"{flag};", f"{flag} on off;"):
            rc, out = _parse(tmp_path, **_at("location", line))
            assert rc != 0, f"{line!r} parsed\n{out}"
            assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_second_occurrence_in_one_location_is_a_duplicate(self, tmp_path,
                                                                flag):
        """security-negative: two values in ONE location would leave which one
        wins to the parser's ordering.  nginx refuses that — which is exactly
        the check the per-export flags do not get ACROSS locations (§J)."""
        rc, out = _parse(tmp_path,
                         **_at("location", f"{flag} on;", f"{flag} off;"))
        assert rc != 0 and f'"{flag}" directive is duplicate' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_value_is_case_insensitive(self, tmp_path, flag):
        """ngx_conf_set_flag_slot compares with ngx_strcasecmp, so ``OFF`` is
        the same token as ``off`` while the audit's own grep for written values
        is case-sensitive — which is why a value-granularity sweep has to read
        the flag table rather than the configs alone."""
        rc, out = _parse(tmp_path, **_at("location", f"{flag} OFF;"))
        assert rc == 0, f"the flag rejected 'OFF'\n{out}"


class TestTheCrossChecksTheOffArmSkips:
    """Three of the nine gate a block of config-time validation.  Each pair is
    the IDENTICAL broken block under `on` and under `off`: the flag is the only
    thing that decides whether the reload survives it."""

    SWARM_EMERG = ("brix_cvmfs_swarm requires brix_cache_peers "
                   "(the seed ring naming this node's own \"self=\" slot)")
    UNIFIED_EMERG = ("brix_cvmfs_unified_origin on requires brix_storage_backend "
                     "to name an http(s) origin set")
    SCVMFS_EMERG = "brix_scvmfs requires brix_cvmfs on"

    def test_swarm_on_without_a_seed_ring_is_a_reload_breaker(self, tmp_path):
        """error: cvmfs_module_build.c:299-312."""
        rc, out = _parse(tmp_path, **_at("location", "brix_cvmfs_swarm on;"))
        assert rc != 0, f"a swarm with no peers parsed\n{out}"
        assert self.SWARM_EMERG in out, out

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_swarm_off_never_looks_for_the_seed_ring(self, tmp_path, arm):
        """success, and the point of the pair: an operator turning the ring off
        may delete ``brix_cache_peers`` — but is never told they now MAY, and is
        never told the check stopped running."""
        knobs = ("" if arm == "absent"
                 else _knobs("brix_cvmfs_swarm off;"))
        rc, out = _parse(tmp_path, knobs=knobs)
        assert rc == 0, f"a peerless config was refused with the swarm {arm}\n{out}"

    def test_unified_origin_on_without_an_http_backend_is_a_reload_breaker(
            self, tmp_path):
        """error: cvmfs_module_merge.c:228-247.  The proxy face serves every
        request from the location's own backend, so a posix backend would 500
        per request instead."""
        rc, out = _parse(tmp_path,
                         **_at("location", "brix_cvmfs_unified_origin on;"),
                         backend="posix:/tmp")
        assert rc != 0, f"a posix-backed unified origin parsed\n{out}"
        assert self.UNIFIED_EMERG in out, out

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_unified_origin_off_never_looks_at_the_backend(self, tmp_path, arm):
        """success: the same posix backend, accepted.  Which is correct — and
        which is also why flipping the flag on months later fails the reload for
        a reason that has nothing to do with the edit."""
        knobs = ("" if arm == "absent"
                 else _knobs("brix_cvmfs_unified_origin off;"))
        rc, out = _parse(tmp_path, knobs=knobs, backend="posix:/tmp")
        assert rc == 0, (
            f"a posix backend was refused with unified_origin {arm}\n{out}")

    # Each row is a whole scvmfs block that breaks the reload the moment the
    # flag says `on`, and is inert the moment it says `off` — the early return
    # at cvmfs_module_merge.c:281 is before all of them.
    BROKEN_SCVMFS = (
        ("bearer-without-issuers", ("brix_scvmfs_authz bearer;",),
         "brix_scvmfs_authz bearer requires brix_scvmfs_token_issuers"),
        ("voms-without-trust-dirs", ("brix_scvmfs_authz voms;",),
         "brix_scvmfs_authz voms requires brix_scvmfs_vomsdir"),
        ("an-issuer-file-that-is-not-there",
         ("brix_scvmfs_authz bearer;",
          "brix_scvmfs_token_issuers /nonexistent/scitokens.cfg;"),
         "brix_token_config: open /nonexistent/scitokens.cfg"),
    )

    @pytest.mark.parametrize("tag,lines,needle", BROKEN_SCVMFS,
                             ids=[row[0] for row in BROKEN_SCVMFS])
    def test_a_broken_authz_block_breaks_the_reload_only_when_the_layer_is_on(
            self, tmp_path, tag, lines, needle):
        """error: the three EMERGs behind the early return, each with the
        identical block under `off` accepted in the same test — a pair rather
        than two cases, because the whole claim is that only the flag differs.
        """
        rc, out = _parse(tmp_path, **_at("location", "brix_scvmfs on;", *lines))
        assert rc != 0, f"{tag} parsed with brix_scvmfs on\n{out}"
        assert needle in out, out
        for arm in ("brix_scvmfs off;", None):
            body = list(lines) if arm is None else [arm, *lines]
            rc, out = _parse(tmp_path, **_at("location", *body))
            assert rc == 0, (
                f"{tag} was refused with the layer "
                f"{'off' if arm else 'absent'}\n{out}")

    def test_the_layer_is_refused_on_a_location_that_is_not_a_cvmfs_export(
            self, tmp_path):
        """security-negative: ``brix_scvmfs on`` on a location with no
        ``brix_cvmfs`` is an authorization layer over nothing, and it is the
        shape of a copy-paste into the wrong block.  It must break the reload
        rather than sit there looking enabled."""
        rc, out = _parse(tmp_path,
                         extra=_extra_location("/bare/", "brix_scvmfs on;"))
        assert rc != 0, f"brix_scvmfs on a non-cvmfs location parsed\n{out}"
        assert self.SCVMFS_EMERG in out, out

    def test_the_same_misplacement_is_silent_when_the_layer_is_off(self,
                                                                   tmp_path):
        """The other half of the pair: `off` on a non-cvmfs location parses,
        because the check is behind the flag.  A location that will never be an
        export can therefore carry a disabled security layer indefinitely
        without anyone being told the two do not go together."""
        rc, out = _parse(tmp_path,
                         extra=_extra_location("/bare/", "brix_scvmfs off;"))
        assert rc == 0, f"a disabled layer was refused\n{out}"


class TestTwoExportsParseInSilence:
    """DEFECT CANDIDATES #81 and #82, parse-time half.

    Config parse is the last moment either collapse is diagnosable: both stores
    are known, both origins are known, both arms of the flag are known, and the
    merge is about to discard one of each.
    """

    @pytest.mark.parametrize("flag", ("brix_cvmfs_scrub", "brix_cvmfs_learn"))
    def test_two_exports_disagreeing_about_a_per_export_flag_say_nothing(
            self, tmp_path, flag):
        """#82: one location says `off`, the other says `on`, and they are the
        same export.  No warning names either location, so the operator's only
        feedback is §J's eviction of objects they excluded."""
        rc, out = _parse(tmp_path, **_at("location", f"{flag} on;"),
                         extra=_extra_location("/cvmfs2/", f"{flag} off;",
                                               cvmfs=True))
        assert rc == 0, f"the two-location config stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "a disagreement between two exports is now diagnosed at parse time "
            f"— pin the new diagnostic here and close #82\n{out}")

    def test_two_exports_naming_different_origins_say_nothing(self, tmp_path):
        """#81: two stores and two origins, one export, and the file already
        knows how to warn about a coherent-but-useless combination
        (cvmfs_module_build.c:315+ warns about origin coords with no geo
        answering).  Here it says nothing at all."""
        rc, out = _parse(
            tmp_path, backend=LIVE,
            extra=_extra_location("/cvmfs2/",
                                  f'brix_storage_backend "{DEAD}";',
                                  cvmfs=True))
        assert rc == 0, f"the two-location config stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "the discarded store/origin is now diagnosed at parse time — pin "
            f"the new diagnostic here and close #81\n{out}")
