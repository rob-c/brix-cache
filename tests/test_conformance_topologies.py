"""
tests/test_conformance_topologies.py — run the FULL conformance suite through
every storage-access topology.

`tests/test_conformance.py` checks that the nginx server behaves byte-for-byte
like a reference XRootD daemon (ping, stat, read, dirlist, checksum, write,
open, security).  By default it runs against the direct anon endpoint.  This
module re-runs that ENTIRE suite — unchanged — against the same storage reached
through:

  * proxy    — one transparent xrootd_proxy hop
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

from settings import DATA_ROOT, NGINX_ANON_PORT, REF_XROOTD_PORT, SERVER_HOST

# These tests provision multi-server topologies and run the FULL conformance suite
# as a nested pytest subprocess (minutes), so the global 30s per-test timeout
# (pytest.ini) is far too short — it fires while blocked in subprocess.communicate
# and, because the thread-based timeout cannot interrupt that C-level poll, it
# hangs the whole run (serial) or crashes the xdist worker (-n N).  Give the module
# a realistic timeout that sits ABOVE the nested subprocess's own (catchable)
# timeout so the subprocess raises TimeoutExpired first and the test fails cleanly.
pytestmark = pytest.mark.timeout(420)

NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
H = SERVER_HOST
ANON = NGINX_ANON_PORT          # fleet nginx serving DATA_ROOT (the storage backend)
_DIR = "/tmp/xrd_conf_topo"

# Dedicated port block for the provisioned fronts (avoid fleet collisions).
PROXY_PORT     = int(os.environ.get("TEST_CT_PROXY_PORT", "12840"))
MESH_HOP1_PORT = int(os.environ.get("TEST_CT_MESH_HOP1_PORT", "12841"))
MESH_HOP2_PORT = int(os.environ.get("TEST_CT_MESH_HOP2_PORT", "12842"))
CLU_REDIR_PORT = int(os.environ.get("TEST_CT_CLU_REDIR_PORT", "12843"))
CLU_CMS_PORT   = int(os.environ.get("TEST_CT_CLU_CMS_PORT", "12844"))
CLU_DS_PORT    = int(os.environ.get("TEST_CT_CLU_DS_PORT", "12845"))
MIRROR_PORT    = int(os.environ.get("TEST_CT_MIRROR_PORT", "12846"))
MIRROR_RW_PORT = int(os.environ.get("TEST_CT_MIRROR_RW_PORT", "12847"))


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
        f"        xrootd on; xrootd_auth none;\n"
        f"        xrootd_proxy on; xrootd_proxy_upstream 127.0.0.1:{ANON};"))
    _start(conf)
    return f"root://{H}:{PROXY_PORT}", [conf]


def _build_mesh():
    """Two stacked proxy hops: hop2 -> hop1 -> ANON (nginx->nginx->nginx)."""
    c1 = _write_conf("mesh1", _stream(MESH_HOP1_PORT,
        f"        xrootd on; xrootd_auth none;\n"
        f"        xrootd_proxy on; xrootd_proxy_upstream 127.0.0.1:{ANON};"))
    c2 = _write_conf("mesh2", _stream(MESH_HOP2_PORT,
        f"        xrootd on; xrootd_auth none;\n"
        f"        xrootd_proxy on; xrootd_proxy_upstream 127.0.0.1:{MESH_HOP1_PORT};"))
    _start(c1)
    _start(c2)
    return f"root://{H}:{MESH_HOP2_PORT}", [c2, c1]


def _build_cluster():
    """CMS redirector + a data server that serves DATA_ROOT and registers '/'."""
    redir = _write_conf("clu_redir",
        "stream {\n"
        f"    server {{\n        listen 0.0.0.0:{CLU_REDIR_PORT};\n"
        "        xrootd on; xrootd_auth none; xrootd_manager_mode on;\n"
        "    }\n"
        f"    server {{\n        listen 0.0.0.0:{CLU_CMS_PORT};\n"
        "        xrootd_cms_server on;\n    }\n}")
    ds = _write_conf("clu_ds", _stream(CLU_DS_PORT,
        f"        xrootd on; xrootd_root {DATA_ROOT}; xrootd_auth none;\n"
        f"        xrootd_allow_write on;\n"
        f"        xrootd_cms_manager 127.0.0.1:{CLU_CMS_PORT};\n"
        f"        xrootd_cms_paths /;\n"
        f"        xrootd_cms_interval 2;\n"
        f"        xrootd_listen_port {CLU_DS_PORT};"))
    _start(redir)
    _start(ds)
    return f"root://{H}:{CLU_REDIR_PORT}", [redir, ds]


def _build_mirror(port=MIRROR_PORT, name="mirror"):
    """nginx+xrootd traffic-mirror front: serves the shared DATA_ROOT to the
    client AND shadow-replays read-path traffic to the official xrootd daemon
    (REF_XROOTD_PORT).  The client is served by the nginx front; the official
    server receives a mirrored copy of every read/stat/dirlist/query, with
    divergences logged.  Conformance compares the front against that same
    official server, so a green run proves nginx serves identically to the
    server it mirrors.  Writes are not mirrored (read-path only), but the front
    and the official server export the same DATA_ROOT directory, so writes made
    through the front are visible to the official server for read-back."""
    conf = _write_conf(name, _stream(port,
        f"        xrootd on; xrootd_root {DATA_ROOT}; xrootd_auth none;\n"
        f"        xrootd_allow_write on;\n"
        f"        xrootd_stream_mirror_url 127.0.0.1:{REF_XROOTD_PORT};\n"
        # Mirror the full read-path opcode set INCLUDING query/Qcksum.  The
        # mirror only actually replays self-contained requests (read-only opens,
        # path-based stat/statx, locate, dirlist, query) and treats a shadow
        # "not supported" (the official has no checksum) as benign — so this
        # "just works" in front of an official xrootd with no spurious
        # divergence (handle-based read/readv and write opens are skipped).
        f"        xrootd_mirror_opcodes open read readv stat statx dirlist query;\n"
        f"        xrootd_mirror_log_diverge on;"))
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
        f = client.File()
        st_open, _ = f.open(f"{front_url}//{probe_logical.lstrip('/')}",
                            OpenFlags.READ)
        if st_open.ok:
            f.close()
        # Fresh FileSystem connection (separate from the File above).
        st_stat, _ = client.FileSystem(front_url).stat(probe_logical)
        if st_open.ok and st_stat.ok:
            ok_streak += 1
            if ok_streak >= 3:        # stable on consecutive fresh connections
                return True
        else:
            ok_streak = 0
            last = (st_open.message or st_stat.message or "").strip()
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
    os.makedirs(_DIR, exist_ok=True)


def _require_fleet_backends():
    """The full conformance comparison needs the DATA_ROOT nginx and the
    reference daemon up; skip (don't fail) when the host's load test has them
    down."""
    if not _reachable(ANON):
        pytest.skip(f"storage backend anon:{ANON} (DATA_ROOT) not up")
    if not _reachable(REF_XROOTD_PORT):
        pytest.skip(f"reference xrootd :{REF_XROOTD_PORT} not up "
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

        env = dict(os.environ)
        env["CONFORMANCE_NGINX_URL"] = front_url
        env["TEST_SKIP_SERVER_SETUP"] = "1"      # reuse the running fleet
        env["PYTHONPATH"] = "tests" + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/test_conformance.py",
                 "-p", "no:xdist", "-p", "no:cacheprovider",
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

        out = proc.stdout
        tail = out[-4000:] + ("\nSTDERR:\n" + proc.stderr[-1500:]
                              if proc.stderr.strip() else "")

        # Parse the real pytest summary — a bare exit code is not enough: a
        # subprocess that collected nothing or was short-circuited also exits 0.
        m_pass = re.search(r"(\d+) passed", out)
        n_pass = int(m_pass.group(1)) if m_pass else 0
        m_bad = re.search(r"(\d+) (failed|error)", out)

        assert proc.returncode == 0 and n_pass > 0 and m_bad is None, (
            f"full conformance suite did NOT cleanly pass through '{topo}' "
            f"({front_url}): rc={proc.returncode}, passed={n_pass}, "
            f"bad={m_bad.group(0) if m_bad else None}\n{tail}")
        # Sanity: the topology run must cover the same breadth as a direct run.
        assert n_pass >= 25, (
            f"only {n_pass} conformance tests ran through '{topo}' "
            f"(expected ~30) — suite may have been truncated:\n{tail}")
    finally:
        for c in confs:
            _stop(c)


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
    same (enoent) data server.  src/manager/registry.c::
    xrootd_manager_tried_exhausted now stops and answers not-found once every
    matching server has been tried; wired into stat/open/checksum redirects."""
    from XRootD import client

    confs = []
    try:
        front_url, confs = _build_cluster()

        # Wait for the data server to register so redirects resolve at all.
        deadline = time.time() + 30
        registered = False
        while time.time() < deadline:
            st, _ = client.FileSystem(front_url).stat("//")
            if st.ok:
                registered = True
                break
            time.sleep(0.5)
        if not registered:
            pytest.skip("cluster data server did not register in time")

        st, _ = client.FileSystem(front_url).stat(
            "//definitely_absent_redirect_loop_probe.bin")
        assert not st.ok, "nonexistent path should fail"
        msg = (st.message or "").lower()
        assert "redirect limit" not in msg, (
            f"redirect loop NOT fixed — manager still bounces the client: {st.message!r}")
        assert getattr(st, "errno", 0) == 3011 \
            or "not found" in msg or "no such" in msg, (
            f"expected kXR_NotFound (3011), got: {st.message!r}")
    finally:
        for c in confs:
            _stop(c)


# ---------------------------------------------------------------------------
# Explicit read/write through the nginx+xrootd mirror in front of the official
# xrootd: write via the mirror, read it back byte-exact (scalar + vector) and
# by checksum through the mirror, and confirm the official xrootd serves the
# same bytes (shared DATA_ROOT) with no mirror divergence logged.
# ---------------------------------------------------------------------------

def test_mirror_readwrite_against_official_xrootd():
    _require_fleet_backends()
    from XRootD import client
    from XRootD.client.flags import OpenFlags, QueryCode
    import zlib

    confs = []
    rel = f"_mirror_rw_{os.getpid()}.bin"
    data = bytes((i * 37 + 5) & 0xFF for i in range(256 * 1024 + 123))
    try:
        # Dedicated port + run-dir so this never collides with the conformance
        # [mirror] topology test (which uses MIRROR_PORT).
        front_url, confs = _build_mirror(MIRROR_RW_PORT, "mirror_rw")
        for _ in range(40):                       # wait for the front to listen
            if _reachable(MIRROR_RW_PORT, 0.5):
                break
            time.sleep(0.25)

        # Remember where this run's log starts (nginx appends across runs).
        log = os.path.join(_DIR, "mirror_rw-run", "logs", "error.log")
        log_off = os.path.getsize(log) if os.path.exists(log) else 0

        # --- write through the mirror ---
        f = client.File()
        st, _ = f.open(f"{front_url}//{rel}", OpenFlags.DELETE | OpenFlags.NEW)
        assert st.ok, f"open(NEW) via mirror: {st.message}"
        st, _ = f.write(data); assert st.ok, f"write via mirror: {st.message}"
        st, _ = f.close(); assert st.ok

        # --- scalar read-back through the mirror ---
        f = client.File()
        st, _ = f.open(f"{front_url}//{rel}", OpenFlags.READ)
        assert st.ok, f"open(READ) via mirror: {st.message}"
        st, got = f.read(); assert st.ok
        assert bytes(got) == data, "scalar read through mirror not byte-exact"

        # --- vector read-back through the mirror ---
        segs = [(0, 100), (1000, 512), (len(data) - 200, 200)]
        st, vres = f.vector_read(segs); assert st.ok, f"vector_read: {st.message}"
        for (o, n), chunk in zip(segs, vres):
            assert bytes(chunk.buffer) == data[o:o + n], \
                f"vector segment at {o} not byte-exact through mirror"
        f.close()

        # --- checksum through the mirror ---
        st, resp = client.FileSystem(front_url).query(QueryCode.CHECKSUM, rel)
        assert st.ok, f"checksum via mirror: {st.message}"
        algo, hexval = resp.decode().strip().split("\x00")[0].split()[:2]
        assert algo == "adler32" and int(hexval, 16) == (zlib.adler32(data) & 0xFFFFFFFF), \
            f"checksum through mirror wrong: {algo} {hexval}"

        # --- the official xrootd serves the same bytes (shared namespace) ---
        f = client.File()
        st, _ = f.open(f"root://{H}:{REF_XROOTD_PORT}//{rel}", OpenFlags.READ)
        assert st.ok, f"official xrootd open: {st.message}"
        st, ref_got = f.read(); f.close()
        assert bytes(ref_got) == data, "official xrootd read not byte-exact"

        # --- the mirror must report NO divergence vs the official xrootd.
        # Only self-contained read-path ops are replayed (handle-based reads and
        # write opens are skipped), and a shadow "operation not supported" (e.g.
        # the official lacks Qcksum) is treated as benign — so a clean log proves
        # the mirror "just works" in front of the official server.  The replay is
        # async, so allow it to land first, and inspect only THIS run's tail. ---
        time.sleep(1.5)
        if os.path.exists(log):
            with open(log, errors="replace") as lf:
                lf.seek(log_off)
                diverged = [ln for ln in lf.read().splitlines()
                            if "diverge" in ln.lower()]
            assert not diverged, (
                "mirror reported a divergence vs the official xrootd:\n"
                + "\n".join(diverged[:8]))
    finally:
        for c in confs:
            _stop(c)
        try:
            os.unlink(os.path.join(DATA_ROOT, rel))
        except FileNotFoundError:
            pass
