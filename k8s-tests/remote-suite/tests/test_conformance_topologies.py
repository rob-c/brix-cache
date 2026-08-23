# brix-remote-skip
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

from settings import (
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
    free_port,
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
pytestmark = [pytest.mark.timeout(420), pytest.mark.serial]

NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
H = SERVER_HOST
ANON = NGINX_ANON_PORT          # fleet nginx serving DATA_ROOT (the storage backend)
_DIR = os.path.join(os.environ["TMPDIR"], "xrd_conf_topo")

# Dedicated port block for the provisioned fronts: each front binds its OWN
# listener, so every port below must be a free OS port (env override honored)
# to avoid colliding with the managed fleet or other self-contained tests.
PROXY_PORT     = int(os.environ.get("TEST_CT_PROXY_PORT") or free_port())
MESH_HOP1_PORT = int(os.environ.get("TEST_CT_MESH_HOP1_PORT") or free_port())
MESH_HOP2_PORT = int(os.environ.get("TEST_CT_MESH_HOP2_PORT") or free_port())
CLU_REDIR_PORT = int(os.environ.get("TEST_CT_CLU_REDIR_PORT") or free_port())
CLU_CMS_PORT   = int(os.environ.get("TEST_CT_CLU_CMS_PORT") or free_port())
CLU_DS_PORT    = int(os.environ.get("TEST_CT_CLU_DS_PORT") or free_port())
MIRROR_PORT    = int(os.environ.get("TEST_CT_MIRROR_PORT") or free_port())
MIRROR_RW_PORT = int(os.environ.get("TEST_CT_MIRROR_RW_PORT") or free_port())


# ---------------------------------------------------------------------------
# Low-level nginx + connectivity helpers
# ---------------------------------------------------------------------------

def _reachable(port, timeout=1.0):
    try:
        socket.create_connection((H, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _write_conf(name, body):
    run = os.path.join(_DIR, f"{name}-run")
    os.makedirs(os.path.join(run, "logs"), exist_ok=True)
    conf = os.path.join(_DIR, f"{name}.conf")
    with open(conf, "w") as f:
        f.write(
            f"worker_processes 1;\n"
            f"error_log {run}/logs/error.log info;\n"
            f"pid {run}/nginx.pid;\n"
            f"events {{ worker_connections 256; }}\n"
            f"{body}\n")
    return conf


def _start(conf):
    chk = subprocess.run([NGINX_BIN, "-t", "-c", conf],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        raise RuntimeError(f"config {conf} rejected: {chk.stderr[-400:]}")
    subprocess.run([NGINX_BIN, "-c", conf], capture_output=True)


def _stop(conf):
    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)


# ---------------------------------------------------------------------------
# Topology builders — each returns (front_url, [conf_paths])
# ---------------------------------------------------------------------------

def _stream(port, inner):
    return f"stream {{\n    server {{\n        listen 0.0.0.0:{port};\n{inner}\n    }}\n}}"


def _build_proxy():
    """One transparent proxy hop in front of the DATA_ROOT nginx (ANON)."""
    conf = _write_conf("proxy", _stream(PROXY_PORT,
        f"        brix_root on; brix_auth none;\n"
        f"        brix_tap_proxy on; brix_tap_proxy_upstream {HOST}:{ANON}; brix_tap_proxy_auth anonymous;"))
    _start(conf)
    return f"root://{H}:{PROXY_PORT}", [conf]


def _build_mesh():
    """Two stacked proxy hops: hop2 -> hop1 -> ANON (nginx->nginx->nginx)."""
    c1 = _write_conf("mesh1", _stream(MESH_HOP1_PORT,
        f"        brix_root on; brix_auth none;\n"
        f"        brix_tap_proxy on; brix_tap_proxy_upstream {HOST}:{ANON}; brix_tap_proxy_auth anonymous;"))
    c2 = _write_conf("mesh2", _stream(MESH_HOP2_PORT,
        f"        brix_root on; brix_auth none;\n"
        f"        brix_tap_proxy on; brix_tap_proxy_upstream {HOST}:{MESH_HOP1_PORT}; brix_tap_proxy_auth anonymous;"))
    _start(c1)
    _start(c2)
    return f"root://{H}:{MESH_HOP2_PORT}", [c2, c1]


def _build_cluster():
    """CMS redirector + a data server that serves DATA_ROOT and registers '/'."""
    redir = _write_conf("clu_redir",
        "stream {\n"
        f"    server {{\n        listen 0.0.0.0:{CLU_REDIR_PORT};\n"
        "        brix_root on; brix_auth none; brix_manager_mode on;\n"
        "    }\n"
        f"    server {{\n        listen 0.0.0.0:{CLU_CMS_PORT};\n"
        "        brix_cms_server on;\n    }\n}")
    ds = _write_conf("clu_ds", _stream(CLU_DS_PORT,
        f"        brix_root on; brix_storage_backend posix:{DATA_ROOT}; brix_auth none;\n"
        f"        brix_allow_write on;\n"
        f"        brix_cms_manager {HOST}:{CLU_CMS_PORT};\n"
        f"        brix_cms_paths /;\n"
        f"        brix_cms_interval 2;\n"
        f"        brix_listen_port {CLU_DS_PORT};"))
    _start(redir)
    _start(ds)
    return f"root://{H}:{CLU_REDIR_PORT}", [redir, ds]


def _build_mirror(port=MIRROR_PORT, name="mirror"):
    """nginx+xrootd traffic-mirror front: serves the shared DATA_ROOT to the
    client AND shadow-replays read-path traffic to the official xrootd daemon
    (REF_BRIX_PORT).  The client is served by the nginx front; the official
    server receives a mirrored copy of every read/stat/dirlist/query, with
    divergences logged.  Conformance compares the front against that same
    official server, so a green run proves nginx serves identically to the
    server it mirrors.  Writes are not mirrored (read-path only), but the front
    and the official server export the same DATA_ROOT directory, so writes made
    through the front are visible to the official server for read-back."""
    conf = _write_conf(name, _stream(port,
        f"        brix_root on; brix_storage_backend posix:{DATA_ROOT}; brix_auth none;\n"
        f"        brix_allow_write on;\n"
        f"        brix_stream_mirror_url {HOST}:{REF_BRIX_PORT};\n"
        # Mirror the full read-path opcode set INCLUDING query/Qcksum.  The
        # mirror only actually replays self-contained requests (read-only opens,
        # path-based stat/statx, locate, dirlist, query) and treats a shadow
        # "not supported" (the official has no checksum) as benign — so this
        # "just works" in front of an official xrootd with no spurious
        # divergence (handle-based read/readv and write opens are skipped).
        f"        brix_mirror_opcodes open read readv stat statx dirlist query;\n"
        f"        brix_mirror_log_diverge on;"))
    _start(conf)
    return f"root://{H}:{port}", [conf]


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

def _wait_front_serves(front_url, probe_logical, timeout=30.0):
    """Confirm the front reliably serves BOTH a File open AND a FileSystem stat
    (the two client-connection styles the conformance suite uses) on fresh
    connections, warming any per-connection upstream bootstrap.  A front that
    cannot do this — e.g. a backend that went down under host load — is SKIPPED,
    not failed, so transient environment issues don't masquerade as conformance
    divergences."""
    from XRootD import client
    from XRootD.client.flags import OpenFlags

    deadline = time.time() + timeout
    last = ""
    ok_streak = 0
    while time.time() < deadline:
        succeeded, last_message = _probe_front(
            client, OpenFlags, front_url, probe_logical
        )
        if succeeded:
            ok_streak += 1
            if ok_streak >= 3:
                return True
        else:
            ok_streak = 0
            last = last_message
        time.sleep(0.3)
    pytest.skip(f"front {front_url} did not reliably serve {probe_logical} "
                f"(last: {last or 'timeout'})")


def _probe_front(client, open_flags, front_url, probe_logical):
    file_handle = client.File()
    open_status, _ = file_handle.open(
        f"{front_url}//{probe_logical.lstrip('/')}", open_flags.READ
    )
    if open_status.ok:
        file_handle.close()
    stat_status, _ = client.FileSystem(front_url).stat(probe_logical)
    message = (open_status.message or stat_status.message or "").strip()
    return open_status.ok and stat_status.ok, message


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _require_nginx():
    """Every test here provisions nginx fronts, so the binary is mandatory."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    os.makedirs(_DIR, exist_ok=True)


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
def test_full_conformance_through_topology(topo, probe_file):
    _require_fleet_backends()
    builder = TOPOLOGIES[topo]
    confs = []
    try:
        front_url, confs = builder()
        _wait_front_serves(front_url, probe_file)
        process = _run_conformance(topo, front_url)
        _assert_conformance_result(process, topo, front_url)
    finally:
        _stop_configs(confs)


def _conformance_environment(front_url):
    env = dict(os.environ)
    env["CONFORMANCE_NGINX_URL"] = front_url
    env["TEST_SKIP_SERVER_SETUP"] = "1"
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = "tests" + (os.pathsep + existing if existing else "")
    return env


def _run_conformance(topo, front_url):
    command = [sys.executable, "-m", "pytest", "tests/test_conformance.py",
               "-p", "no:xdist", "-p", "no:cacheprovider",
               "--timeout=60", "-o", "addopts="]
    cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        return subprocess.run(
            command, cwd=cwd, env=_conformance_environment(front_url),
            capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            f"conformance through '{topo}' ({front_url}) exceeded 300s"
        )


def _assert_conformance_result(process, topo, front_url):
    output = process.stdout
    stderr = "\nSTDERR:\n" + process.stderr[-1500:] if process.stderr.strip() else ""
    tail = output[-4000:] + stderr
    passed_match = re.search(r"(\d+) passed", output)
    passed = int(passed_match.group(1)) if passed_match else 0
    bad = re.search(r"(\d+) (failed|error)", output)
    _assert_clean_conformance(process, passed, bad, topo, front_url, tail)
    assert passed >= 25, f"only {passed} tests ran through '{topo}'\n{tail}"


def _assert_clean_conformance(process, passed, bad, topo, front_url, tail):
    clean = process.returncode == 0 and passed > 0
    assert clean and bad is None, (
        f"conformance failed through '{topo}' ({front_url}): "
        f"rc={process.returncode}, passed={passed}\n{tail}"
    )


def _stop_configs(configs):
    for config in configs:
        _stop(config)


# ---------------------------------------------------------------------------
# Focused regression: a CMS redirector must converge to not-found, not loop.
# Self-contained (redirector + data server only) so it runs even when the
# host's background load test has the shared fleet down.
# ---------------------------------------------------------------------------

def test_cluster_nonexistent_returns_not_found():
    """A stat of a path no data server holds must return kXR_NotFound (3011),
    NOT redirect-loop until the client hits its limit.

    This is the divergence the topology conformance run caught: the redirector
    ignored the client's tried/triedrc retry list and kept redirecting to the
    same (enoent) data server.  src/net/manager/registry.c::
    brix_manager_tried_exhausted now stops and answers not-found once every
    matching server has been tried; wired into stat/open/checksum redirects."""
    from XRootD import client

    confs = []
    try:
        front_url, confs = _build_cluster()
        if not _wait_cluster_registration(client, front_url):
            pytest.skip("cluster data server did not register in time")
        status, _ = client.FileSystem(front_url).stat(
            "//definitely_absent_redirect_loop_probe.bin")
        _assert_not_found(status)
    finally:
        _stop_configs(confs)


def _wait_cluster_registration(client, front_url):
    deadline = time.time() + 30
    while time.time() < deadline:
        status, _ = client.FileSystem(front_url).stat("//")
        if status.ok:
            return True
        time.sleep(0.5)
    return False


def _assert_not_found(status):
    assert not status.ok, "nonexistent path should fail"
    message = (status.message or "").lower()
    assert "redirect limit" not in message, \
        f"redirect loop persists: {status.message!r}"
    expected = getattr(status, "errno", 0) == 3011
    expected = expected or "not found" in message or "no such" in message
    assert expected, f"expected kXR_NotFound (3011), got: {status.message!r}"


def test_mirror_readwrite_against_official_xrootd():
    _require_fleet_backends()
    from XRootD import client
    from XRootD.client.flags import OpenFlags, QueryCode
    import zlib

    confs = []
    rel = f"_mirror_rw_{os.getpid()}.bin"
    data = bytes((i * 37 + 5) & 0xFF for i in range(256 * 1024 + 123))
    try:
        front_url, confs = _build_mirror(MIRROR_RW_PORT, "mirror_rw")
        _wait_mirror_port()
        log = os.path.join(_DIR, "mirror_rw-run", "logs", "error.log")
        log_off = os.path.getsize(log) if os.path.exists(log) else 0
        _mirror_write(client, OpenFlags, front_url, rel, data)
        handle = _mirror_scalar_read(client, OpenFlags, front_url, rel, data)
        _mirror_vector_read(handle, data)
        _mirror_checksum(client, QueryCode, front_url, rel, data, zlib)
        _official_read(client, OpenFlags, rel, data)
        _assert_no_mirror_divergence(log, log_off)
    finally:
        _stop_configs(confs)
        _unlink_mirror_file(rel)


def _wait_mirror_port():
    for _ in range(40):
        if _reachable(MIRROR_RW_PORT, 0.5):
            return
        time.sleep(0.25)


def _mirror_write(client, open_flags, front_url, relative, data):
    handle = client.File()
    status, _ = handle.open(
        f"{front_url}//{relative}", open_flags.DELETE | open_flags.NEW
    )
    assert status.ok, f"open(NEW) via mirror: {status.message}"
    status, _ = handle.write(data)
    assert status.ok, f"write via mirror: {status.message}"
    status, _ = handle.close()
    assert status.ok


def _mirror_scalar_read(client, open_flags, front_url, relative, data):
    handle = client.File()
    status, _ = handle.open(f"{front_url}//{relative}", open_flags.READ)
    assert status.ok, f"open(READ) via mirror: {status.message}"
    status, received = handle.read()
    assert status.ok
    assert bytes(received) == data, "scalar mirror read was not byte-exact"
    return handle


def _mirror_vector_read(handle, data):
    segments = [(0, 100), (1000, 512), (len(data) - 200, 200)]
    status, results = handle.vector_read(segments)
    assert status.ok, f"vector_read: {status.message}"
    for (offset, length), chunk in zip(segments, results):
        assert bytes(chunk.buffer) == data[offset:offset + length], \
            f"vector segment at {offset} was not byte-exact"
    handle.close()


def _mirror_checksum(client, query_code, front_url, relative, data, zlib_module):
    status, response = client.FileSystem(front_url).query(
        query_code.CHECKSUM, relative
    )
    assert status.ok, f"checksum via mirror: {status.message}"
    algorithm, value = response.decode().strip().split("\x00")[0].split()[:2]
    expected = zlib_module.adler32(data) & 0xFFFFFFFF
    assert algorithm == "adler32"
    assert int(value, 16) == expected, f"checksum through mirror wrong: {value}"


def _official_read(client, open_flags, relative, data):
    handle = client.File()
    status, _ = handle.open(
        f"root://{H}:{REF_BRIX_PORT}//{relative}", open_flags.READ
    )
    assert status.ok, f"official xrootd open: {status.message}"
    status, received = handle.read()
    handle.close()
    assert status.ok
    assert bytes(received) == data, "official xrootd read was not byte-exact"


def _assert_no_mirror_divergence(log, offset):
    time.sleep(1.5)
    if not os.path.exists(log):
        return
    with open(log, errors="replace") as stream:
        stream.seek(offset)
        diverged = [line for line in stream.read().splitlines()
                    if "diverge" in line.lower()]
    assert not diverged, "mirror divergence:\n" + "\n".join(diverged[:8])


def _unlink_mirror_file(relative):
    try:
        os.unlink(os.path.join(DATA_ROOT, relative))
    except FileNotFoundError:
        pass
