"""
Shared infrastructure for the real-XRootD <-> nginx-xrootd CMS mesh.

This module owns the *daemon lifecycle* for every CMS-mesh topology so the
topologies can be brought up once by the test harness (manage_test_servers.sh ->
cms_mesh_servers.py) instead of by each test.  The tests in
test_cms_mesh_interop.py only connect to the fixed ports below and skip if a
topology is not up.

It provides:
  * binary discovery + client helpers (xrdcp / xrdfs / curl, md5, etc.)
  * config builders for nginx managers / data nodes / dual-protocol nodes
  * a Mesh launcher (xrootd/cmsd via -b, nginx via its pid file)
  * PORTS: the fixed port map for every topology
  * per-topology build functions + start_all() / stop_all()

Everything binds 127.0.0.1 and uses the ports in PORTS; nothing here is
pytest-specific so cms_mesh_servers.py can import and run it standalone.
"""

import glob
import hashlib
import os
import shutil
import signal
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from settings import NGINX_BIN, HOST, BIND_HOST
from mesh_config import render
from server_launcher import launch_fleet_nginx

# --------------------------------------------------------------------------- #
# Binaries / constants
# --------------------------------------------------------------------------- #

BRIX_BIN = shutil.which(os.environ.get("TEST_BRIX_BIN", "xrootd"))
CMSD_BIN = shutil.which(os.environ.get("TEST_CMSD_BIN", "cmsd"))
XRDFS_BIN = shutil.which(os.environ.get("TEST_XRDFS_BIN", "xrdfs"))
XRDCP_BIN = shutil.which(os.environ.get("TEST_XRDCP_BIN", "xrdcp"))
CURL_BIN = shutil.which("curl")

# The mesh's reference managers/data nodes are the *stock* xrootd/cmsd daemons
# (BRIX_BIN/CMSD_BIN above resolve from PATH by design — interop testing).  The
# SSS keytab admin, however, is our own clean-room tool: it ships as
# ``xrdsssadmin-brix`` (the ``-brix`` suffix keeps the brix client RPM
# co-installable with the stock xrootd *server* package, which owns
# /usr/bin/xrdsssadmin) and carries its own CLI, distinct from the stock tool's.
# Resolve it from the in-tree client build — like test_native_sss.py and the
# other SSS suites — NOT via PATH, where only the incompatible stock binary lives.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")

# Where the harness drops the mesh's generated configs/data/logs.
MESH_DIR = os.environ.get("CMS_MESH_DIR", os.path.join(os.environ.get("TEST_ROOT", "/tmp/xrd-test"), "cms-mesh"))

# Unauthenticated XRootD client env (keep any ambient GSI proxy out).
_XRD_ENV = {
    k: v
    for k, v in os.environ.items()
    if k not in ("X509_USER_PROXY", "X509_USER_CERT", "X509_USER_KEY",
                 "XrdSecPROTOCOL", "XRD_SECPROTOCOL")
}
_XRD_ENV["XrdSecPROTOCOL"] = "unix"


def stop_all():
    """Tear down every mesh daemon reliably (process groups + cfg match + ports).

    Order matters: kill nginx by process group first (catches orphaned workers),
    then xrootd/cmsd by their config path, then sweep any survivor still holding
    one of our ports, then block until the manager front doors are actually free
    so a relaunch cannot race a lingering listener."""
    _kill_mesh_pidfiles()
    _kill_configured_daemons()
    _kill_mesh_listeners()
    _wait_manager_ports_closed()


def _kill_mesh_pidfiles():
    for pidfile in glob.glob(os.path.join(MESH_DIR, "*", "run", "*.pid")):
        _kill_pidfile_group(pidfile)


def _kill_configured_daemons():
    subprocess.run(["pkill", "-9", "-f", f"{MESH_DIR}/[^ ]*/cfg/"], check=False)
    subprocess.run(["pkill", "-9", "-f", f"{MESH_DIR}/[^ ]*/cfg/[^ ]*\\.conf"],
                   check=False)


def _list_listeners():
    try:
        return subprocess.run(
            ["ss", "-tlnp"], capture_output=True, text=True
        ).stdout.splitlines()
    except Exception:
        return []


def _mesh_listener_pid(line):
    if "pid=" not in line:
        return None
    for port in range(PORT_MIN, PORT_MAX + 1):
        if f":{port} " in line:
            return line.split("pid=")[1].split(",")[0]
    return None


def _kill_mesh_listeners():
    for line in _list_listeners():
        pid = _mesh_listener_pid(line)
        if pid:
            subprocess.run(["kill", "-9", pid], check=False)


def _wait_manager_ports_closed():
    for _ in range(40):
        if _manager_ports_closed():
            return
        time.sleep(0.25)


def _manager_ports_closed():
    for port in MANAGER_PORTS:
        if port_open(port):
            return False
    return True


# Per-round readiness probe budget.  A still-forming manager answers a locate
# with kXR_wait, so the locate blocks up to its timeout; keep it short and re-
# issue promptly (a stalled probe catches its cluster the moment the data node
# registers) rather than blocking once for a long time.
_READY_PROBE_TIMEOUT = 3      # seconds per individual xrdfs locate
_READY_POLL_INTERVAL = 0.3    # seconds between rounds
# Fail-fast on stalled topologies: once the manager front doors are up (gated
# separately by wait_managers_up), the healthy data nodes register almost at
# once — every reachable topology redirects on the first probe round (~3 s, one
# locate timeout).  A node that is genuinely stuck (misconfig / refused
# registration, e.g. the known-broken prm topology) never registers, so without
# a stall gate its single probe burns the whole `timeout`.
# Once we have probed at least `_READY_MIN_WAIT` (past real formation) AND seen
# zero newly-registered topologies for `_READY_STALL`, the remaining probes are
# stuck rather than slow — stop rather than block out the full ceiling.
_READY_MIN_WAIT = 4           # always probe at least this long before bailing
_READY_STALL = 6              # seconds of zero progress ⇒ laggards declared stuck


def _probe_ready(probe):
    """True iff (manager, path) redirects to a data port — i.e. that topology's
    data node has registered.  Swallows the locate's own timeout/errors: a
    still-forming cluster simply isn't ready yet."""
    mgr, path = probe
    try:
        rc, stdout, _ = xrdfs_locate(mgr, path, timeout=_READY_PROBE_TIMEOUT,
                                     retries=1)
        return rc == 0 and located_port(stdout) is not None
    except Exception:
        return False


def wait_ready(timeout=120):
    """Block until the mesh has actually formed: probe each topology's manager
    with a locate for a known path until it redirects (returns a data port).

    This replaces a blind settle-sleep — a redirect proves the manager is up
    AND that topology's data node(s) have registered and answer selection.
    Returns (ready_count, total, still_pending_probes).

    The ~24 probes run CONCURRENTLY each round.  A not-yet-registered manager
    answers a locate with kXR_wait, so a serial probe blocks ~timeout seconds on
    every still-forming topology and a round costs their SUM (~20-30 s total).
    Probing in parallel bounds a round by the SLOWEST single topology instead,
    so total convergence tracks real cluster formation (~8 s) — a few rounds of
    short, re-issued probes that each catch their cluster as it registers."""
    pending = list(READY_PROBES)
    total = len(pending)
    start = time.time()
    deadline = start + timeout
    last_progress = start
    with ThreadPoolExecutor(max_workers=max(len(pending), 1)) as pool:
        while pending:
            still = _pending_after_probe(pool, pending)
            if len(still) < len(pending):
                last_progress = time.time()
            pending = still
            now = time.time()
            if _ready_wait_finished(pending, now, deadline, start, last_progress):
                break
            time.sleep(_READY_POLL_INTERVAL)
    return total - len(pending), total, pending


def _pending_after_probe(pool, pending):
    readiness = pool.map(_probe_ready, pending)
    return [probe for probe, ready in zip(pending, readiness) if not ready]


def _ready_wait_finished(pending, now, deadline, start, last_progress):
    if not pending:
        return True
    if now >= deadline:
        return True
    if now - start < _READY_MIN_WAIT:
        return False
    return now - last_progress >= _READY_STALL
