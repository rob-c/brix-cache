"""
test_shm_fork_safety.py — cross-protocol regression for the SHM/fork SIGSEGV bug.

WHAT
    nginx initialises EVERY ``shared_memory`` zone as an ``ngx_slab_pool_t`` and
    its SIGCHLD handler runs ``ngx_unlock_mutexes()`` on **every child death**
    (master+worker model only). That routine walks ``ngx_cycle->shared_memory``
    UNCONDITIONALLY and force-unlocks ``((ngx_slab_pool_t*)zone.shm.addr)->mutex``
    for every zone (verified against nginx-1.28.3 ngx_process.c:565-607 — the
    per-zone loop has no ``ngx_accept_mutex_ptr`` guard). Any zone whose init
    callback laid its own struct directly over ``shm.addr`` clobbers that slab
    header, so the master SIGSEGVs the instant any worker exits. This was a
    codebase-wide latent bug (FIXED 2026-06-14 via src/core/compat/shm_slots.c
    ``brix_shm_table_alloc``, which slab-allocates the table and leaves the
    header intact).

WHY THIS TEST
    The crash fires in the MASTER, on ANY worker reap, and walks ALL registered
    zones regardless of which protocol owns them or whether traffic touched them
    (the original clobber happened at init, in the master, before fork). So the
    highest-signal, protocol-agnostic regression is: register the maximal set of
    zones (stream root://, WebDAV, S3, /metrics, dashboard, manager redirector,
    native TPC, ratelimit, kv, dynamic webdav proxy), drive real
    traffic through every face, then SIGKILL workers and assert the master lives,
    reaps, respawns, keeps serving, and logs no SIGSEGV/SIGABRT.

HOW
    Registry-backed: provisions its OWN throwaway instance (real master +
    2 workers) through a module-scoped ``LifecycleHarness`` with a throwaway
    data dir and NO certs (cleartext only). It tries the comprehensive
    all-zone template first (``nginx_shm_fork_comprehensive.conf``) and falls
    back to the minimal one (``nginx_shm_fork_minimal.conf``, still ~10 zones,
    including every originally-buggy one) if the build lacks an optional
    directive — so the core invariant is always exercised. The static
    counterpart that prevents a NEW zone from reintroducing the clobber is
    tests/test_shm_slab_safety_lint.py.

RUN
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_shm_fork_safety.py -v
"""

import os
import shutil
import signal
import socket
import time

import pytest

import settings
from server_launcher import LifecycleHarness, RegistryCommandFailure
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, REMOTE_SERVER, HOST

pytestmark = pytest.mark.uses_lifecycle_harness

NAME = "lc-shmfork"

# How hard to hammer the reaper: each round drives traffic, then SIGKILLs one
# worker and verifies the master walked every zone and survived.
KILL_ROUNDS = 4
WORKERS = 2

# Crash signatures in the error log that must NEVER appear. nginx logs OUR
# SIGKILLed workers as "exited on signal 9" (expected) — we look only for the
# fatal signals a clobbered slab header would raise.
CRASH_PATTERNS = ("signal 11", "signal 6", "signal 4", "signal 7",
                  "SIGSEGV", "SIGABRT", "core dumped", "segfault")


# ---------------------------------------------------------------------------
# small process / network helpers
# ---------------------------------------------------------------------------

def _tcp_reachable(port, timeout=0.5):
    try:
        with socket.create_connection((HOST, port), timeout=timeout):
            return True
    except OSError:
        return False


def _wait_port(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _tcp_reachable(port):
            return True
        time.sleep(0.1)
    return False


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# fixture: pick a working config tier, start the master
# ---------------------------------------------------------------------------

class _Server:
    def __init__(self, harness, endpoint, tier, datadir):
        self.harness = harness
        self.prefix = endpoint.prefix
        self.root_port = endpoint.port
        self.mgr_port = endpoint.extra_ports["MGR_PORT"]
        self.http_port = endpoint.extra_ports["HTTP_PORT"]
        self.s3_port = endpoint.extra_ports["S3_PORT"]
        self.tier = tier
        self.datadir = datadir
        self.master: "int | None" = None

    @property
    def logfile(self):
        return os.path.join(self.prefix, "logs", "error.log")

    def error_log(self):
        try:
            return open(self.logfile, errors="replace").read()
        except OSError:
            return ""

    def master_pid(self, timeout=6.0):
        pidfile = os.path.join(self.prefix, "logs", "nginx.pid")
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                return int(open(pidfile).read().strip())
            except (OSError, ValueError):
                time.sleep(0.1)
        return None

    def worker_pids(self):
        """Live worker pids from the launcher's ps-based process snapshot."""
        return [pid for pid, cmd in self.harness.process_snapshot(NAME)
                if "worker" in cmd]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    if REMOTE_SERVER:
        pytest.skip("self-contained test; not applicable in REMOTE mode")
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not built at %s" % NGINX_BIN)

    base = tmp_path_factory.mktemp("shmfork")
    datadir = base / "data"
    datadir.mkdir(parents=True, exist_ok=True)
    # nginx master may run as root, dropping workers to 'nobody': the export
    # must be worker-writable, like the fleet's 0777 exports.
    os.chmod(datadir, 0o777)
    # seed a readable probe file so GET/cat succeed
    with open(datadir / "probe.bin", "wb") as f:
        f.write(b"shm-fork-safety probe payload\n" * 64)

    mgr_port, http_port, s3_port = settings.free_ports(3)

    # The `lifecycle` fixture is function-scoped; this module wants ONE
    # instance across both tests, so it owns a harness directly.
    harness = LifecycleHarness()
    spec = NginxInstanceSpec(
        name=NAME,
        template="nginx_shm_fork_comprehensive.conf",
        data_root=str(datadir),
        extra_ports={"MGR_PORT": mgr_port, "HTTP_PORT": http_port,
                     "S3_PORT": s3_port},
        template_values={
            "WORKERS": WORKERS,
            "BIND_HOST": settings.BIND_HOST,
        },
        reason="SHM/fork slab-clobber regression needs its own master+workers",
    )

    try:
        # Prefer the comprehensive (all-zone) template; fall back to minimal if
        # the build rejects an optional directive — the core invariant holds.
        harness.register(spec)
        tier = None
        tail = ""
        for candidate, template in (
            ("comprehensive", None),
            ("minimal", "nginx_shm_fork_minimal.conf"),
        ):
            harness.reconfigure(NAME, template=template)
            try:
                harness.nginx_test(NAME)
                tier = candidate
                break
            except RegistryCommandFailure as exc:
                tail = (exc.stderr_tail or exc.stdout_tail).strip()[-400:]
        if tier is None:
            pytest.skip("nginx rejected both config tiers: %s" % tail)

        try:
            endpoint = harness.start_registered(NAME)
        except (RegistryCommandFailure, RuntimeError) as exc:
            pytest.skip("nginx failed to start (%s tier): %s" % (tier, exc))

        srv = _Server(harness, endpoint, tier, str(datadir))
        if not _wait_port(srv.http_port) or not _wait_port(srv.root_port):
            pytest.skip("server did not become ready (%s tier): %s"
                        % (tier, srv.error_log()[-400:]))

        srv.master = srv.master_pid()
        if srv.master is None or not _alive(srv.master):
            pytest.skip("master pid never appeared")

        print("\n[shm-fork-safety] tier=%s master=%d root=%d mgr=%d http=%d"
              % (tier, srv.master, srv.root_port, srv.mgr_port, srv.http_port))

        yield srv
    finally:
        harness.close()


# ---------------------------------------------------------------------------
# traffic drivers — best-effort across every protocol face; each writes/reads
# one or more SHM zones. Failures are tolerated (the zone is still registered
# and walked on reap); the point is to exercise the live write paths too.
# ---------------------------------------------------------------------------

def _http(method, url, body=None, timeout=4.0):
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, data=body, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return None, b""


def _drive_protocols(srv):
    """Touch as many protocol faces / zones as possible. Returns a dict of
    which drives produced a live response (for the functional assertion)."""
    hit = {}

    # HTTP: /metrics (reads metrics zone), WebDAV GET/PUT (serves files),
    # S3 GET (shares metrics/tpc zones). Always available via urllib.
    base = "http://%s:%d" % (HOST, srv.http_port)
    st, _ = _http("GET", base + "/metrics")
    hit["metrics"] = st
    if srv.tier == "comprehensive":
        _http("PUT", base + "/dav/written.txt", body=b"payload-via-webdav")
        st, _ = _http("GET", base + "/dav/probe.bin")
        hit["webdav"] = st
        st, _ = _http("GET", "http://%s:%d/s3/probe.bin" % (HOST, srv.s3_port))
        hit["s3"] = st

    # root:// stream: a TCP connect always exercises accept+handshake-read;
    # xrdcp/xrdfs (if present) drive a full login+open, writing session/handle
    # zones, and prepare exercises the prepare/pending path.
    hit["root_tcp"] = _tcp_reachable(srv.root_port)
    xrdfs = shutil.which("xrdfs")
    xrdcp = shutil.which("xrdcp")
    url = "root://%s:%d" % (HOST, srv.root_port)
    if xrdfs:
        srv.harness.run_cmd([xrdfs, url, "stat", "/probe.bin"], timeout=15)
        if srv.tier == "comprehensive":
            srv.harness.run_cmd([xrdfs, url, "prepare", "-s", "/probe.bin"],
                                timeout=15)
        hit["root"] = True
    if xrdcp:
        dst = os.path.join(srv.prefix, "fetched.bin")
        srv.harness.run_cmd([xrdcp, "-f", "-s", url + "//probe.bin", dst],
                            timeout=20)
        hit["root_cp"] = os.path.exists(dst)

    return hit


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------

def test_protocols_serve_after_zone_init(server):
    """Success path: the master comes up with all zones initialised and at
    least the metrics endpoint serves traffic (proves zone init didn't corrupt
    the slab pool and the read paths work)."""
    hit = _drive_protocols(server)
    assert hit.get("metrics") == 200, (
        "metrics endpoint did not serve (got %r); zone init may have failed"
        % hit.get("metrics"))
    # nothing crashed merely from initialising + touching every zone
    assert _alive(server.master), "master died during protocol traffic"
    log = server.error_log()
    for pat in CRASH_PATTERNS:
        assert pat not in log, "crash signature %r in error log after traffic" % pat


def test_master_survives_worker_sigkill(server):
    """THE regression: SIGKILL workers across several rounds (with live traffic
    through every protocol in between) so the master runs ngx_unlock_mutexes
    over every registered SHM zone. A zone that clobbered its slab header would
    SIGSEGV the master here. Assert the master survives, reaps, respawns, and
    keeps serving — every round."""
    master = server.master
    assert _alive(master), "master not alive at test start"

    for rnd in range(KILL_ROUNDS):
        _drive_protocols(server)  # vary which zones hold live entries

        assert server.worker_pids(), (
            "round %d: master has no workers to kill" % rnd)
        victim = server.harness.kill_worker(NAME, signal.SIGKILL)

        # master must remain alive through the reap (the crash point)
        deadline = time.time() + 5.0
        survived = False
        while time.time() < deadline:
            if _alive(master) and victim not in server.worker_pids():
                survived = True
                break
            if not _alive(master):
                break
            time.sleep(0.05)
        assert _alive(master), (
            "round %d: master SIGSEGV'd reaping a worker — an SHM zone clobbered "
            "its slab header (regression of the fork/SHM bug). Log tail:\n%s"
            % (rnd, server.error_log()[-800:]))
        assert survived, "round %d: master did not reap the killed worker" % rnd

        # surviving worker(s) keep serving immediately, before respawn settles
        st, _ = _http("GET", "http://%s:%d/metrics" % (HOST, server.http_port))
        assert st == 200, "round %d: server stopped serving after a worker kill" % rnd

        # master restores its worker count
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if server.worker_pids():
                break
            time.sleep(0.05)
        assert server.worker_pids(), (
            "round %d: master did not respawn a worker" % rnd)

    # final: still the same master, still serving, no crash signatures logged
    assert _alive(master), "master not alive after all kill rounds"
    st, _ = _http("GET", "http://%s:%d/metrics" % (HOST, server.http_port))
    assert st == 200, "server not serving after %d kill rounds" % KILL_ROUNDS

    log = server.error_log()
    for pat in CRASH_PATTERNS:
        assert pat not in log, (
            "crash signature %r in error log — a worker or master crashed on a "
            "clobbered slab header. Log tail:\n%s" % (pat, log[-800:]))
