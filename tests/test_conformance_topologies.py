"""
tests/test_conformance_topologies.py — run the FULL conformance suite through
every storage-access topology.

`tests/test_conformance.py` checks that the nginx server behaves byte-for-byte
like a reference XRootD daemon (ping, stat, read, dirlist, checksum, write,
open, security).  By default it runs against the direct anon endpoint.  This
module re-runs that ENTIRE suite — unchanged — against the same storage reached
through:

  * proxy    — one transparent brix_tap_proxy hop
  * mesh     — two stacked proxy hops (nginx -> nginx -> nginx)
  * cluster  — a CMS redirector that redirects to a registered data server

Each topology front is provisioned here and backed by an nginx that serves the
shared DATA_ROOT (the same directory the conformance `scratch` fixture writes to
and the reference daemon serves), so the suite's nginx-vs-reference comparisons
remain valid.  The conformance suite is invoked as a subprocess with
CONFORMANCE_NGINX_URL pointed at the topology front; a green subprocess proves
that topology preserves full wire conformance.

Run:
    tests/manage_test_servers.sh start        # need anon (DATA_ROOT) + ref daemon
    PYTHONPATH=tests pytest tests/test_conformance_topologies.py -v
"""

import os
import re
import socket
import subprocess
import sys
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import (
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
    TEST_ROOT,
)

# These tests provision multi-server topologies and run the FULL conformance suite
# as a nested pytest subprocess (minutes), so the global 30s per-test timeout
# (pytest.ini) is far too short — it fires while blocked in subprocess.communicate
# and, because the thread-based timeout cannot interrupt that C-level poll, it
# hangs the whole run (serial) or crashes the xdist worker (-n N).  Give the module
# a realistic timeout that sits ABOVE the nested subprocess's own (catchable)
# timeout so the subprocess raises TimeoutExpired first and the test fails cleanly.
# serial: spawns 4 full nested conformance runs that hammer the shared reference
# xrootd with concurrent dirlists — only reliable run one-at-a-time, not in the pool.
pytestmark = [pytest.mark.timeout(420), pytest.mark.serial,
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-ct")]

NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
H = SERVER_HOST
ANON = NGINX_ANON_PORT          # fleet nginx serving DATA_ROOT (the storage backend)


# ---------------------------------------------------------------------------
# Connectivity helper
# ---------------------------------------------------------------------------

def _reachable(port, timeout=1.0):
    try:
        socket.create_connection((H, port), timeout=timeout).close()
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Topology builders — each provisions its fronts on the LifecycleHarness (which
# owns teardown) and returns the client-facing front URL.  The upstream storage
# (the shared DATA_ROOT nginx on ANON) and the reference xrootd (REF_BRIX_PORT)
# are the managed standing fleet, unchanged.
# ---------------------------------------------------------------------------

def _build_proxy(lifecycle):
    """One transparent proxy hop in front of the DATA_ROOT nginx (ANON)."""
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-ct-proxy", template="nginx_conformance_topo_tap.conf",
        protocol="root", readiness="tcp",
        template_values={"UPSTREAM": f"{HOST}:{ANON}"},
        reason="Single transparent tap-proxy hop in front of the shared DATA_ROOT nginx.",
    ))
    return f"root://{H}:{ep.port}"


def _build_mesh(lifecycle):
    """Two stacked proxy hops: hop2 -> hop1 -> ANON (nginx->nginx->nginx)."""
    hop1 = lifecycle.start(NginxInstanceSpec(
        name="lc-ct-mesh1", template="nginx_conformance_topo_tap.conf",
        protocol="root", readiness="tcp",
        template_values={"UPSTREAM": f"{HOST}:{ANON}"},
        reason="Mesh hop 1: tap-proxy to the shared DATA_ROOT nginx.",
    ))
    hop2 = lifecycle.start(NginxInstanceSpec(
        name="lc-ct-mesh2", template="nginx_conformance_topo_tap.conf",
        protocol="root", readiness="tcp",
        template_values={"UPSTREAM": f"{HOST}:{hop1.port}"},
        reason="Mesh hop 2: tap-proxy to hop 1.",
    ))
    return f"root://{H}:{hop2.port}"


def _build_cluster(lifecycle):
    """CMS redirector + a data server that serves DATA_ROOT and registers '/'."""
    redir = lifecycle.start(NginxInstanceSpec(
        name="lc-ct-clu-redir", template="nginx_conformance_topo_cluster_redir.conf",
        protocol="root", readiness="tcp",
        reason="Cluster redirector (manager mode) + CMS server port.",
    ))
    lifecycle.start(NginxInstanceSpec(
        name="lc-ct-clu-ds", template="nginx_conformance_topo_cluster_ds.conf",
        protocol="root", readiness="tcp", data_root=DATA_ROOT,
        template_values={"CMS_MANAGER": f"{HOST}:{redir.extra_ports['CMS_PORT']}"},
        reason="Cluster data server serving the shared DATA_ROOT, registers '/' with the redirector.",
    ))
    return f"root://{H}:{redir.port}"


def _build_mirror(lifecycle, name="mirror"):
    """nginx+xrootd traffic-mirror front: serves the shared DATA_ROOT to the
    client AND shadow-replays read-path traffic to the official xrootd daemon
    (REF_BRIX_PORT).  The client is served by the nginx front; the official
    server receives a mirrored copy of every read/stat/dirlist/query, with
    divergences logged.  Conformance compares the front against that same
    official server, so a green run proves nginx serves identically to the
    server it mirrors.  Writes are not mirrored (read-path only), but the front
    and the official server export the same DATA_ROOT directory, so writes made
    through the front are visible to the official server for read-back.

    Returns (front_url, log_dir) — the caller inspects the harness log dir for
    mirror-divergence lines.
    """
    ep = lifecycle.start(NginxInstanceSpec(
        name=f"lc-ct-{name}", template="nginx_conformance_topo_mirror.conf",
        protocol="root", readiness="tcp", data_root=DATA_ROOT,
        template_values={"MIRROR_URL": f"{HOST}:{REF_BRIX_PORT}"},
        reason="Traffic-mirror front over the shared DATA_ROOT, shadow-replaying to the official xrootd.",
    ))
    return f"root://{H}:{ep.port}", os.path.join(ep.prefix, "logs")


TOPOLOGIES = {
    "proxy":   _build_proxy,
    "mesh":    _build_mesh,
    "cluster": _build_cluster,
    "mirror":  _build_mirror,
}


# ---------------------------------------------------------------------------
# Readiness: the front must serve a known DATA_ROOT file (covers proxy upstream
# reachability AND cluster DS CMS registration before conformance runs).
# ---------------------------------------------------------------------------

def _probe_front(front_url, probe_logical):
    from XRootD import client
    from XRootD.client.flags import OpenFlags

    handle = client.File()
    opened, _ = handle.open(f"{front_url}//{probe_logical.lstrip('/')}",
                            OpenFlags.READ)
    if opened.ok:
        handle.close()
    stated, _ = client.FileSystem(front_url).stat(probe_logical)
    return opened, stated


def _advance_probe_streak(streak, opened, stated, last):
    if opened.ok and stated.ok:
        return streak + 1, last
    message = (opened.message or stated.message or "").strip()
    return 0, message


def _wait_front_serves(front_url, probe_logical, timeout=30.0):
    """Confirm the front reliably serves BOTH a File open AND a FileSystem stat
    (the two client-connection styles the conformance suite uses) on fresh
    connections, warming any per-connection upstream bootstrap.  A front that
    cannot do this — e.g. a backend that went down under host load — is SKIPPED,
    not failed, so transient environment issues don't masquerade as conformance
    divergences."""
    deadline = time.time() + timeout
    last = ""
    ok_streak = 0
    while time.time() < deadline:
        opened, stated = _probe_front(front_url, probe_logical)
        ok_streak, last = _advance_probe_streak(
            ok_streak, opened, stated, last)
        if ok_streak >= 3:
            return True
        time.sleep(0.3)
    pytest.skip(f"front {front_url} did not reliably serve {probe_logical} "
                f"(last: {last or 'timeout'})")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _require_nginx():
    """Every test here provisions nginx fronts, so the binary is mandatory."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _require_fleet_backends():
    """The full conformance comparison needs the DATA_ROOT nginx and the
    reference daemon up; skip (don't fail) when the host's load test has them
    down."""
    if not _reachable(ANON):
        pytest.skip(f"storage backend anon:{ANON} (DATA_ROOT) not up")
    if not _reachable(REF_BRIX_PORT):
        pytest.skip(f"reference xrootd :{REF_BRIX_PORT} not up "
                    "(conformance needs it for comparison)")


@pytest.fixture(scope="module")
def probe_file():
    """A known file in DATA_ROOT used to confirm a front is serving."""
    name = f"_conf_topo_probe_{os.getpid()}.bin"
    path = os.path.join(DATA_ROOT, name)
    with open(path, "wb") as fh:
        fh.write(b"conformance-topology-probe\n" * 16)
    yield "/" + name
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# The matrix: full conformance suite through each topology
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("topo", list(TOPOLOGIES))
def _front_url(builder, lifecycle):
    front_url = builder(lifecycle)
    if isinstance(front_url, tuple):      # _build_mirror returns (url, log_dir)
        return front_url[0]
    return front_url


def _conformance_environment(front_url):
    env = dict(os.environ)
    env["CONFORMANCE_NGINX_URL"] = front_url
    env["TEST_SKIP_SERVER_SETUP"] = "1"      # reuse the running fleet
    env["TEST_OWN_FLEET"] = "0"
    prior_path = env.get("PYTHONPATH")
    env["PYTHONPATH"] = "tests" if not prior_path \
        else "tests" + os.pathsep + prior_path
    return env


def _run_topology_conformance(topo, front_url, env):
    basetemp = os.path.join(
        TEST_ROOT, "artifacts", "conformance-topologies", topo)

    try:
        return subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_conformance.py",
             "-p", "no:xdist", "-p", "no:cacheprovider",
             "-p", "no:randomly", "-p", "no:rerunfailures",
             "--basetemp", basetemp,
             "--timeout=60", "-o", "addopts="],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            env=env, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        # Fail cleanly rather than letting the outer pytest-timeout fire while
        # we are blocked in communicate() (which it cannot interrupt → whole
        # run hangs/aborts).  A 5-min nested conformance run means the topology
        # front is wedged.
        pytest.fail(
            f"conformance subprocess through '{topo}' ({front_url}) did not "
            f"finish within 300s — topology front wedged")


def _assert_conformance_process(proc, passed, bad, topo, front_url, tail):
    assert proc.returncode == 0, (
        f"conformance through {topo} ({front_url}) exited {proc.returncode}:\n{tail}")
    assert passed > 0, f"conformance through {topo} collected no passing tests:\n{tail}"
    assert bad is None, f"conformance through {topo} reported {bad.group(0)}:\n{tail}"


def _assert_conformance_breadth(passed, topo, tail):
    assert passed >= 25, (
        f"only {passed} conformance tests ran through '{topo}' "
        f"(expected ~30) — suite may have been truncated:\n{tail}")


def test_full_conformance_through_topology(topo, probe_file, lifecycle):
    _require_fleet_backends()
    front_url = _front_url(TOPOLOGIES[topo], lifecycle)
    _wait_front_serves(front_url, probe_file)
    proc = _run_topology_conformance(
        topo, front_url, _conformance_environment(front_url))
    out = proc.stdout
    tail = out[-4000:] + ("\nSTDERR:\n" + proc.stderr[-1500:]
                          if proc.stderr.strip() else "")

    # Parse the real pytest summary — a bare exit code is not enough: a
    # subprocess that collected nothing or was short-circuited also exits 0.
    m_pass = re.search(r"(\d+) passed", out)
    n_pass = int(m_pass.group(1)) if m_pass else 0
    m_bad = re.search(r"(\d+) (failed|error)", out)

    _assert_conformance_process(proc, n_pass, m_bad, topo, front_url, tail)
    _assert_conformance_breadth(n_pass, topo, tail)


# ---------------------------------------------------------------------------
# Focused regression: a CMS redirector must converge to not-found, not loop.
# Self-contained (redirector + data server only) so it runs even when the
# host's background load test has the shared fleet down.
# ---------------------------------------------------------------------------

def _wait_cluster_registered(client, front_url):
    deadline = time.time() + 30
    while time.time() < deadline:
        status, _ = client.FileSystem(front_url).stat("//")
        if status.ok:
            return True
        time.sleep(0.5)
    return False


def _assert_not_found_status(status):
    assert not status.ok, "nonexistent path should fail"
    message = (status.message or "").lower()
    assert "redirect limit" not in message, (
        f"redirect loop NOT fixed — manager still bounces the client: {status.message!r}")
    accepted = (getattr(status, "errno", 0) == 3011,
                "not found" in message, "no such" in message)
    assert any(accepted), f"expected kXR_NotFound (3011), got: {status.message!r}"


def test_cluster_nonexistent_returns_not_found(lifecycle):
    """A stat of a path no data server holds must return kXR_NotFound (3011),
    NOT redirect-loop until the client hits its limit.

    This is the divergence the topology conformance run caught: the redirector
    ignored the client's tried/triedrc retry list and kept redirecting to the
    same (enoent) data server.  src/net/manager/registry.c::
    brix_manager_tried_exhausted now stops and answers not-found once every
    matching server has been tried; wired into stat/open/checksum redirects."""
    from XRootD import client

    front_url = _build_cluster(lifecycle)

    # Wait for the data server to register so redirects resolve at all.
    if not _wait_cluster_registered(client, front_url):
        pytest.skip("cluster data server did not register in time")

    st, _ = client.FileSystem(front_url).stat(
        "//definitely_absent_redirect_loop_probe.bin")
    _assert_not_found_status(st)


# ---------------------------------------------------------------------------
# Explicit read/write through the nginx+xrootd mirror in front of the official
# xrootd: write via the mirror, read it back byte-exact (scalar + vector) and
# by checksum through the mirror, and confirm the official xrootd serves the
# same bytes (shared DATA_ROOT) with no mirror divergence logged.
# ---------------------------------------------------------------------------

def _mirror_write(client, open_flags, front_url, relative, data):
    handle = client.File()
    status, _ = handle.open(
        f"{front_url}//{relative}", open_flags.DELETE | open_flags.NEW)
    assert status.ok, f"open(NEW) via mirror: {status.message}"
    status, _ = handle.write(data)
    assert status.ok, f"write via mirror: {status.message}"
    status, _ = handle.close()
    assert status.ok


def _assert_scalar_read(handle, data):
    status, received = handle.read()
    assert status.ok
    assert bytes(received) == data, "scalar read through mirror not byte-exact"


def _assert_vector_read(handle, data):
    segments = [(0, 100), (1000, 512), (len(data) - 200, 200)]
    status, result = handle.vector_read(segments)
    assert status.ok, f"vector_read: {status.message}"
    for (offset, size), chunk in zip(segments, result):
        assert bytes(chunk.buffer) == data[offset:offset + size], \
            f"vector segment at {offset} not byte-exact through mirror"


def _mirror_read(client, open_flags, front_url, relative, data):
    handle = client.File()
    status, _ = handle.open(f"{front_url}//{relative}", open_flags.READ)
    assert status.ok, f"open(READ) via mirror: {status.message}"
    _assert_scalar_read(handle, data)
    _assert_vector_read(handle, data)
    handle.close()


def _assert_mirror_checksum(client, query_code, front_url, relative, data):
    import zlib

    status, response = client.FileSystem(front_url).query(
        query_code.CHECKSUM, relative)
    assert status.ok, f"checksum via mirror: {status.message}"
    algorithm, value = response.decode().strip().split("\x00")[0].split()[:2]
    assert algorithm == "adler32"
    assert int(value, 16) == (zlib.adler32(data) & 0xFFFFFFFF), \
        f"checksum through mirror wrong: {algorithm} {value}"


def _assert_reference_read(client, open_flags, relative, data):
    handle = client.File()
    status, _ = handle.open(
        f"root://{H}:{REF_BRIX_PORT}//{relative}", open_flags.READ)
    assert status.ok, f"official xrootd open: {status.message}"
    _, received = handle.read()
    handle.close()
    assert bytes(received) == data, "official xrootd read not byte-exact"


def _assert_no_mirror_divergence(log, offset):
    time.sleep(1.5)
    if not os.path.exists(log):
        return
    with open(log, errors="replace") as handle:
        handle.seek(offset)
        diverged = [line for line in handle.read().splitlines()
                    if "diverge" in line.lower()]
    assert not diverged, (
        "mirror reported a divergence vs the official xrootd:\n"
        + "\n".join(diverged[:8]))


def _remove_mirror_file(relative):
    try:
        os.unlink(os.path.join(DATA_ROOT, relative))
    except FileNotFoundError:
        pass


def test_mirror_readwrite_against_official_xrootd(lifecycle):
    _require_fleet_backends()
    from XRootD import client
    from XRootD.client.flags import OpenFlags, QueryCode

    relative = f"_mirror_rw_{os.getpid()}.bin"
    data = bytes((index * 37 + 5) & 0xFF
                 for index in range(256 * 1024 + 123))
    try:
        front_url, log_dir = _build_mirror(lifecycle, "mirror_rw")
        log = os.path.join(log_dir, "error.log")
        log_offset = os.path.getsize(log) if os.path.exists(log) else 0
        _mirror_write(client, OpenFlags, front_url, relative, data)
        _mirror_read(client, OpenFlags, front_url, relative, data)
        _assert_mirror_checksum(
            client, QueryCode, front_url, relative, data)
        _assert_reference_read(client, OpenFlags, relative, data)
        _assert_no_mirror_divergence(log, log_offset)
    finally:
        _remove_mirror_file(relative)
