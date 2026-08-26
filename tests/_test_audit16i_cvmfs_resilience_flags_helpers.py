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

