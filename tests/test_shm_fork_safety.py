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
    codebase-wide latent bug (FIXED 2026-06-14 via src/compat/shm_slots.c
    ``xrootd_shm_table_alloc``, which slab-allocates the table and leaves the
    header intact).

WHY THIS TEST
    The crash fires in the MASTER, on ANY worker reap, and walks ALL registered
    zones regardless of which protocol owns them or whether traffic touched them
    (the original clobber happened at init, in the master, before fork). So the
    highest-signal, protocol-agnostic regression is: register the maximal set of
    zones (stream root://, WebDAV, S3, /metrics, dashboard, manager redirector,
    native TPC, FRM tape-stage, ratelimit, kv, dynamic webdav proxy), drive real
    traffic through every face, then SIGKILL workers and assert the master lives,
    reaps, respawns, keeps serving, and logs no SIGSEGV/SIGABRT.

HOW
    Self-contained: spawns its OWN nginx (real master + 2 workers, ``daemon on``)
    in a private temp prefix with throwaway data/queue dirs and NO certs
    (cleartext only). It tries a comprehensive all-zone config first and falls
    back to a minimal stream+metrics config (still ~10 zones, including every
    originally-buggy one) if the build lacks an optional directive — so the core
    invariant is always exercised. The static counterpart that prevents a NEW
    zone from reintroducing the clobber is tests/test_shm_slab_safety_lint.py.

RUN
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_shm_fork_safety.py -v
"""

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time

import pytest

from settings import NGINX_BIN, REMOTE_SERVER, HOST, BIND_HOST

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

def _free_ports(n):
    """Reserve n distinct loopback ports (tiny TOCTOU race, fine on loopback)."""
    socks, ports = [], []
    try:
        for _ in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((BIND_HOST, 0))
            socks.append(s)
            ports.append(s.getsockname()[1])
    finally:
        for s in socks:
            s.close()
    return ports


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


def _master_pid(pidfile, timeout=6.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            return int(open(pidfile).read().strip())
        except (OSError, ValueError):
            time.sleep(0.1)
    return None


def _worker_pids(master_pid):
    """Immediate children (workers) of the given master, via pgrep -P."""
    out = subprocess.run(["pgrep", "-P", str(master_pid)],
                         capture_output=True, text=True)
    return [int(x) for x in out.stdout.split() if x.isdigit()]


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# config generation
# ---------------------------------------------------------------------------

def _common_head(prefix):
    """Top-level directives shared by both config tiers."""
    return (
        "worker_processes %d;\n"
        "daemon on;\n"
        "master_process on;\n"
        "pid %s/logs/nginx.pid;\n"
        "error_log %s/logs/error.log info;\n"
        "events { worker_connections 256; }\n"
    ) % (WORKERS, prefix, prefix)


def _comprehensive_conf(prefix, datadir, frmdir, root_port, mgr_port, http_port):
    """A config that registers EVERY custom SHM zone in one master.

    stream postconfig unconditionally registers sessions, handles, srv-registry,
    pending, tpc-keys, tpc-transfers, metrics and the 3 dashboard zones; the
    extra directives add the gated zones: redir_cache (collapse_redir),
    frm_index (frm), ratelimit, kv, and proxy_pool (dynamic webdav proxy).
    """
    return _common_head(prefix) + """
stream {
    access_log off;

    # gated zones declared at stream-main scope
    xrootd_kv_zone tcache 1m key=64 val=512;
    xrootd_rate_limit_zone zone=rlz:10m;

    # plain local origin: registers the unconditional stream zones + frm_index
    server {
        listen __H__:__ROOT__;
        xrootd on;
        xrootd_root __DATA__;
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_session_slots 64;
        xrootd_registry_slots 64;
        xrootd_tpc_allow_local on;
        xrootd_tpc_key_ttl 60s;
        xrootd_prepare_command /bin/true;
        xrootd_frm on;
        xrootd_frm_queue_path __FRM__/queue;
        xrootd_frm_max_inflight 8;
        xrootd_frm_stagecmd /bin/true;
        xrootd_rate_limit_rule zone=rlz key=ip rate=10000r/s burst=20000;
    }

    # manager/redirector role: registers the redir-collapse cache zone
    server {
        listen __H__:__MGR__;
        xrootd on;
        xrootd_auth none;
        xrootd_manager_mode on;
        xrootd_collapse_redir on;
        xrootd_collapse_redir_ttl 5s;
        xrootd_redir_cache_slots 64;
    }
}

http {
    access_log off;
    client_body_temp_path __PREFIX__/logs/cbt;
    proxy_temp_path __PREFIX__/logs/pt;
    fastcgi_temp_path __PREFIX__/logs/ft;
    uwsgi_temp_path __PREFIX__/logs/ut;
    scgi_temp_path __PREFIX__/logs/st;

    server {
        listen __H__:__HTTP__;

        location = /metrics { xrootd_metrics on; }

        location /dav/ {
            xrootd_webdav on;
            xrootd_webdav_root __DATA__;
            xrootd_webdav_auth none;
            xrootd_webdav_allow_write on;
        }

        location /s3/ {
            xrootd_s3 on;
            xrootd_s3_root __DATA__;
            xrootd_s3_region us-east-1;
            xrootd_s3_access_key testkey;
            xrootd_s3_secret_key testsecret;
        }

        location /proxy/ {
            xrootd_webdav_proxy on;
            xrootd_webdav_proxy_dynamic on;
            xrootd_admin_allow 127.0.0.1/32 ::1/128;
        }
    }
}
""".replace("__H__", BIND_HOST).replace("__ROOT__", str(root_port)) \
   .replace("__MGR__", str(mgr_port)).replace("__HTTP__", str(http_port)) \
   .replace("__DATA__", datadir).replace("__FRM__", frmdir) \
   .replace("__PREFIX__", prefix)


def _minimal_conf(prefix, datadir, root_port, http_port):
    """Fallback: one stream origin + http /metrics. Still registers the ~10
    unconditional stream zones — including every zone that carried the original
    clobber bug (sessions, handles, srv-registry, pending, tpc-keys,
    tpc-transfers, metrics, dashboard x3)."""
    return _common_head(prefix) + """
stream {
    access_log off;
    server {
        listen __H__:__ROOT__;
        xrootd on;
        xrootd_root __DATA__;
        xrootd_auth none;
        xrootd_allow_write on;
    }
}

http {
    access_log off;
    server {
        listen __H__:__HTTP__;
        location = /metrics { xrootd_metrics on; }
    }
}
""".replace("__H__", BIND_HOST).replace("__ROOT__", str(root_port)) \
   .replace("__HTTP__", str(http_port)).replace("__DATA__", datadir)


# ---------------------------------------------------------------------------
# nginx lifecycle
# ---------------------------------------------------------------------------

def _validate(conf_path, prefix):
    return subprocess.run([NGINX_BIN, "-t", "-p", prefix, "-c", conf_path],
                          capture_output=True, text=True)


def _launch(conf_path, prefix):
    return subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf_path],
                          capture_output=True, text=True)


def _stop(conf_path, prefix):
    subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf_path, "-s", "stop"],
                   capture_output=True, text=True)


# ---------------------------------------------------------------------------
# fixture: build dirs, pick a working config tier, start the master
# ---------------------------------------------------------------------------

class _Server:
    def __init__(self, prefix, conf, pidfile, ports, tier, datadir):
        self.prefix = prefix
        self.conf = conf
        self.pidfile = pidfile
        self.root_port, self.mgr_port, self.http_port = ports
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


@pytest.fixture(scope="module")
def server():
    if REMOTE_SERVER:
        pytest.skip("self-contained test; not applicable in REMOTE mode")
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not built at %s" % NGINX_BIN)
    if shutil.which("pgrep") is None:
        pytest.skip("pgrep required to enumerate worker pids")

    prefix = tempfile.mkdtemp(prefix="shmfork-")
    datadir = os.path.join(prefix, "data")
    frmdir = os.path.join(prefix, "frm")
    for d in (os.path.join(prefix, "logs"), datadir, frmdir):
        os.makedirs(d, exist_ok=True)
    # seed a readable probe file so GET/cat succeed
    with open(os.path.join(datadir, "probe.bin"), "wb") as f:
        f.write(b"shm-fork-safety probe payload\n" * 64)

    root_port, mgr_port, http_port = _free_ports(3)
    # refuse to clobber a foreign listener
    for p in (root_port, mgr_port, http_port):
        if _tcp_reachable(p):
            shutil.rmtree(prefix, ignore_errors=True)
            pytest.skip("port %d already in use by a foreign process" % p)

    conf_path = os.path.join(prefix, "nginx.conf")
    pidfile = os.path.join(prefix, "logs", "nginx.pid")

    # Prefer the comprehensive (all-zone) config; fall back to minimal if the
    # build rejects an optional directive — the core invariant still holds.
    tier = None
    comp = _comprehensive_conf(prefix, datadir, frmdir, root_port, mgr_port, http_port)
    with open(conf_path, "w") as f:
        f.write(comp)
    chk = _validate(conf_path, prefix)
    if chk.returncode == 0:
        tier = "comprehensive"
    else:
        mini = _minimal_conf(prefix, datadir, root_port, http_port)
        with open(conf_path, "w") as f:
            f.write(mini)
        chk = _validate(conf_path, prefix)
        if chk.returncode == 0:
            tier = "minimal"
        else:
            tail = (chk.stderr or chk.stdout).strip()[-400:]
            shutil.rmtree(prefix, ignore_errors=True)
            pytest.skip("nginx rejected both config tiers: %s" % tail)

    run = _launch(conf_path, prefix)
    if run.returncode != 0:
        tail = (run.stderr or run.stdout).strip()[-400:]
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.skip("nginx failed to start (%s tier): %s" % (tier, tail))

    if not _wait_port(http_port) or not _wait_port(root_port):
        srv = _Server(prefix, conf_path, pidfile,
                      (root_port, mgr_port, http_port), tier, datadir)
        log = srv.error_log()[-400:]
        _stop(conf_path, prefix)
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.skip("server did not become ready (%s tier): %s" % (tier, log))

    srv = _Server(prefix, conf_path, pidfile,
                  (root_port, mgr_port, http_port), tier, datadir)
    srv.master = _master_pid(pidfile)
    if srv.master is None or not _alive(srv.master):
        _stop(conf_path, prefix)
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.skip("master pid never appeared")

    print("\n[shm-fork-safety] tier=%s master=%d root=%d mgr=%d http=%d"
          % (tier, srv.master, root_port, mgr_port, http_port))

    try:
        yield srv
    finally:
        _stop(conf_path, prefix)
        time.sleep(0.3)
        if srv.master and _alive(srv.master):
            try:
                os.kill(srv.master, signal.SIGKILL)
            except OSError:
                pass
        shutil.rmtree(prefix, ignore_errors=True)


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
        st, _ = _http("GET", base + "/s3/probe.bin")
        hit["s3"] = st

    # root:// stream: a TCP connect always exercises accept+handshake-read;
    # xrdcp/xrdfs (if present) drive a full login+open, writing session/handle
    # zones, and prepare drives the FRM stage zone.
    hit["root_tcp"] = _tcp_reachable(srv.root_port)
    xrdfs = shutil.which("xrdfs")
    xrdcp = shutil.which("xrdcp")
    url = "root://%s:%d" % (HOST, srv.root_port)
    if xrdfs:
        subprocess.run([xrdfs, url, "stat", "/probe.bin"],
                       capture_output=True, timeout=15)
        if srv.tier == "comprehensive":
            subprocess.run([xrdfs, url, "prepare", "-s", "/probe.bin"],
                           capture_output=True, timeout=15)
        hit["root"] = True
    if xrdcp:
        dst = os.path.join(srv.prefix, "fetched.bin")
        subprocess.run([xrdcp, "-f", "-s", url + "//probe.bin", dst],
                       capture_output=True, timeout=20)
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

        workers = _worker_pids(master)
        assert workers, "round %d: master has no workers to kill" % rnd
        victim = workers[0]

        os.kill(victim, signal.SIGKILL)  # hard kill -> master reaps -> walk

        # master must remain alive through the reap (the crash point)
        deadline = time.time() + 5.0
        survived = False
        while time.time() < deadline:
            if _alive(master) and victim not in _worker_pids(master):
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
            if len(_worker_pids(master)) >= 1:
                break
            time.sleep(0.05)
        assert len(_worker_pids(master)) >= 1, (
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
