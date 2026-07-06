"""
tests/test_chaos_mixed_auth.py

Chaos test for a small mesh of nginx-xrootd instances whose UPSTREAM auth
requirements are a *mix* of X.509 (GSI) and SSS — exercised concurrently while
backends are restarted underneath the front instances.

Topology
--------
        anon client ──► cache-gsi ──(X.509 VOMS proxy)──► gsi-origin   (brix_auth gsi)
        anon client ──► proxy-sss ──(SSS keytab)────────► sss-origin   (brix_auth sss)

  gsi-origin : data server requiring GSI.  cache-gsi is a tier cache
               (storage_backend root://gsi-origin) whose brix_credential
               x509_proxy is a temp proxy minted by a voms-proxy-init-like call
               (utils/voms_proxy_fake.py) against the temp PKI framework — so
               the cache authenticates UPSTREAM with X.509.
  sss-origin : data server requiring SSS.  proxy-sss forwards to it with an SSS
               credential built from a shared keytab — so the proxy authenticates
               UPSTREAM with SSS.

The clients themselves connect anonymously to the two fronts; the auth *mix*
under test lives on the upstream hops (X.509 vs SSS).

What the chaos asserts
----------------------
  * happy path: each route serves byte-exact data through its upstream auth;
  * negative:   a proxy pointed at the SSS origin with the WRONG keytab is
                cleanly rejected (NotAuthorized), never hangs/crashes;
  * resilience: under concurrent mixed load with the two backends being
                restarted repeatedly, every request either succeeds or fails
                cleanly, and NO worker crashes (master alive, no SIGSEGV in
                any log).

Self-contained: mints its own credentials and starts its own instances on free
ports; never touches the shared fleet.  Serial only.

Run:
    PYTHONPATH=tests pytest tests/test_chaos_mixed_auth.py -v -p no:xdist
"""

import os
import random
import shutil
import socket
import subprocess
import sys
import threading
import time

import pytest

from settings import (
    BIND_HOST,
    CA_DIR,
    HOST,
    PKI_DIR,
    SERVER_CERT,
    SERVER_KEY,
    USER_CERT,
    USER_KEY,
    VOMS_CERT,
    VOMS_KEY,
    VOMSDIR,
)

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")
XRDSSSADMIN = os.path.join(CLIENT_DIR, "bin", "xrdsssadmin")

_UTILS = os.path.join(REPO, "utils")
_VOMS_FAKE = os.path.join(_UTILS, "voms_proxy_fake.py")
_MAKE_PROXY = os.path.join(_UTILS, "make_proxy.py")

CHAOS_VO = "chaos"
CHAOS_FQAN = "/chaos/Role=NULL/Capability=NULL"


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _clean_env(extra=None):
    """Env with all ambient credential vars stripped (so each call is explicit)."""
    env = {k: v for k, v in os.environ.items()}
    for k in ("X509_USER_PROXY", "X509_CERT_DIR", "BEARER_TOKEN",
              "BEARER_TOKEN_FILE", "XrdSecSSSKT", "XrdSecsssKT", "LD_LIBRARY_PATH"):
        env.pop(k, None)
    if extra:
        env.update(extra)
    return env


def _wait_port(port, tries=80, sleep_s=0.1):
    for _ in range(tries):
        try:
            with socket.create_connection((HOST, port), timeout=1):
                return True
        except OSError:
            time.sleep(sleep_s)
    return False


def _voms_dn(pem, field):
    r = subprocess.run(
        ["openssl", "x509", "-in", pem, "-noout", f"-{field}", "-nameopt", "compat"],
        check=True, capture_output=True, text=True)
    return r.stdout.strip().split("=", 1)[1].strip()


def _make_voms_signing_cert():
    """VOMS signing key+cert signed by the test CA (idempotent)."""
    os.makedirs(os.path.dirname(VOMS_CERT), exist_ok=True)
    if os.path.exists(VOMS_CERT) and os.path.exists(VOMS_KEY):
        return
    subprocess.run(["openssl", "genrsa", "-out", VOMS_KEY, "2048"],
                   check=True, capture_output=True)
    csr = VOMS_CERT.replace(".pem", ".csr")
    subprocess.run(["openssl", "req", "-new", "-key", VOMS_KEY,
                    "-subj", "/DC=test/DC=xrootd/CN=voms.test.local", "-out", csr],
                   check=True, capture_output=True)
    ext = VOMS_CERT.replace(".pem", "_ext.conf")
    with open(ext, "w") as f:
        f.write("[voms_ext]\nsubjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid:always\nbasicConstraints = CA:FALSE\n")
    subprocess.run(["openssl", "x509", "-req", "-in", csr,
                    "-CA", f"{CA_DIR}/ca.pem", "-CAkey", f"{CA_DIR}/ca.key",
                    "-CAcreateserial", "-out", VOMS_CERT, "-days", "365",
                    "-extensions", "voms_ext", "-extfile", ext],
                   check=True, capture_output=True)


def _make_vomsdir_lsc(vo):
    """LSC entry so the origin trusts our VOMS signer for *vo*."""
    subject = _voms_dn(VOMS_CERT, "subject")
    issuer = _voms_dn(VOMS_CERT, "issuer")
    d = os.path.join(VOMSDIR, vo)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "voms.test.local.lsc"), "w") as f:
        f.write(f"{subject}\n{issuer}\n")


def _mint_voms_proxy(out):
    """voms-proxy-init-like call: a temp X.509 proxy bearing the chaos VO AC."""
    subprocess.run([sys.executable, _VOMS_FAKE,
                    "-cert", USER_CERT, "-key", USER_KEY, "-certdir", CA_DIR,
                    "-hostcert", VOMS_CERT, "-hostkey", VOMS_KEY,
                    "-voms", CHAOS_VO, "-fqan", CHAOS_FQAN,
                    "-uri", "voms.test.local:15000", "-out", out, "-hours", "12"],
                   check=True, capture_output=True)


def _start_nginx(conf_path):
    t = subprocess.run([NGINX_BIN, "-t", "-c", conf_path],
                       capture_output=True, text=True)
    assert t.returncode == 0, f"nginx -t failed for {conf_path}:\n{t.stderr}"
    r = subprocess.run([NGINX_BIN, "-c", conf_path], capture_output=True, text=True)
    assert r.returncode == 0, f"nginx start failed for {conf_path}:\n{r.stderr}"


def _stop_nginx(conf_path):
    subprocess.run([NGINX_BIN, "-c", conf_path, "-s", "quit"],
                   capture_output=True)


def _master_pid(pidfile):
    try:
        with open(pidfile) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _alive(pid):
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# the mesh fixture
# ---------------------------------------------------------------------------

class Inst:
    def __init__(self, name, port, conf, pidfile, logfile):
        self.name = name
        self.port = port
        self.conf = conf
        self.pidfile = pidfile
        self.logfile = logfile


@pytest.fixture(scope="module")
def mesh(tmp_path_factory):
    # ---- preflight -------------------------------------------------------
    if shutil.which("openssl") is None:
        pytest.skip("openssl required")
    if not os.path.isfile(_VOMS_FAKE):
        pytest.skip("utils/voms_proxy_fake.py missing")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    b = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp", "xrdsssadmin"],
                       capture_output=True, text=True, timeout=240)
    if b.returncode != 0 or not all(os.path.exists(x)
                                    for x in (XRDFS, XRDCP, XRDSSSADMIN)):
        pytest.skip(f"native client build failed:\n{b.stdout}\n{b.stderr}")
    # the temp PKI framework must be present (conftest builds it; build if absent)
    if not (os.path.exists(f"{CA_DIR}/ca.pem") and os.path.exists(USER_CERT)
            and os.path.exists(SERVER_CERT)):
        try:
            import pki_helpers
            pki_helpers.blitz_test_pki()
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"temp PKI unavailable: {e}")

    root = tmp_path_factory.mktemp("chaos")

    # ---- credentials -----------------------------------------------------
    _make_voms_signing_cert()
    _make_vomsdir_lsc(CHAOS_VO)
    proxy_pem = str(root / "proxy_chaos.pem")
    _mint_voms_proxy(proxy_pem)

    kt = str(root / "chaos.keytab")            # shared by proxy + sss-origin
    r = subprocess.run([XRDSSSADMIN, "-k", kt, "add", "--id", "1",
                        "--user", "chaosusr", "--group", "chaosgrp",
                        "--name", "chaoskey"], capture_output=True, text=True)
    assert r.returncode == 0, f"keytab mint failed: {r.stdout}{r.stderr}"
    kt_bad = str(root / "wrong.keytab")        # different secret → must be rejected
    r = subprocess.run([XRDSSSADMIN, "-k", kt_bad, "add", "--id", "1",
                        "--user", "chaosusr", "--group", "chaosgrp",
                        "--name", "chaoskey"], capture_output=True, text=True)
    assert r.returncode == 0

    # ---- data ------------------------------------------------------------
    payload_gsi = b"x509-upstream payload :: " + os.urandom(8).hex().encode() + b"\n"
    payload_sss = b"sss-upstream payload :: " + os.urandom(8).hex().encode() + b"\n"
    gsi_data = root / "gsi-origin-data"
    sss_data = root / "sss-origin-data"
    gsi_data.mkdir()
    sss_data.mkdir()
    (gsi_data / "probe.txt").write_bytes(payload_gsi)
    (sss_data / "probe.txt").write_bytes(payload_sss)

    insts = {}

    def mk(name, body):
        d = root / name
        (d / "conf").mkdir(parents=True)
        (d / "logs").mkdir(parents=True)
        if not (d / "data").exists():
            (d / "data").mkdir(parents=True)
        (d / "cache").mkdir(parents=True, exist_ok=True)  # tier cache_store dir
        port = _free_port()
        conf = str(d / "conf" / "nginx.conf")
        pidf = str(d / "logs" / "nginx.pid")
        logf = str(d / "logs" / "error.log")
        with open(conf, "w") as f:
            f.write(body(port, d, pidf, logf))
        insts[name] = Inst(name, port, conf, pidf, logf)
        return insts[name]

    # gsi-origin (X.509 backend)
    gsi_origin = mk("gsi-origin", lambda port, d, pidf, logf: f"""
worker_processes 1; error_log {logf} info; pid {pidf};
events {{ worker_connections 128; }}
stream {{ server {{
    listen {BIND_HOST}:{port};
    brix_root on;
    brix_export {gsi_data};
    brix_auth gsi;
    brix_certificate     {SERVER_CERT};
    brix_certificate_key {SERVER_KEY};
    brix_trusted_ca      {CA_DIR}/ca.pem;
}} }}
""")

    # sss-origin (SSS backend)
    sss_origin = mk("sss-origin", lambda port, d, pidf, logf: f"""
worker_processes 1; error_log {logf} info; pid {pidf};
events {{ worker_connections 128; }}
stream {{ server {{
    listen {BIND_HOST}:{port};
    brix_root on;
    brix_export {sss_data};
    brix_auth sss;
    brix_sss_keytab {kt};
}} }}
""")

    # cache-gsi: anon front, X.509 UPSTREAM auth to gsi-origin (phase-64 tier
    # grammar: the GSI origin is the storage backend, its credential a named
    # brix_credential block, the local read cache a posix cache_store).
    cache_gsi = mk("cache-gsi", lambda port, d, pidf, logf: f"""
worker_processes 1; error_log {logf} info; pid {pidf};
events {{ worker_connections 128; }}
thread_pool chaos_cache threads=2 max_queue=8192;
stream {{
brix_credential chaosgsi {{ x509_proxy {proxy_pem}; ca_dir {CA_DIR}; }}
server {{
    listen {BIND_HOST}:{port};
    brix_root on;
    brix_export {d}/data;
    brix_auth none;
    brix_allow_write off;
    brix_thread_pool chaos_cache;
    brix_storage_backend root://{BIND_HOST}:{gsi_origin.port};
    brix_storage_credential chaosgsi;
    brix_cache_store posix:{d}/cache;
    brix_cache_export /;
}} }}
""")

    # proxy-sss: anon front, SSS UPSTREAM auth to sss-origin
    proxy_sss = mk("proxy-sss", lambda port, d, pidf, logf: f"""
worker_processes 1; error_log {logf} info; pid {pidf};
events {{ worker_connections 128; }}
stream {{ server {{
    listen {BIND_HOST}:{port};
    brix_root on;
    brix_auth none;
    brix_tap_proxy on;
    brix_tap_proxy_auth sss;
    brix_sss_keytab {kt};
    brix_tap_proxy_upstream {BIND_HOST}:{sss_origin.port} sss;
}} }}
""")

    # proxy-sss-bad: SSS upstream with the WRONG keytab (negative path)
    proxy_bad = mk("proxy-sss-bad", lambda port, d, pidf, logf: f"""
worker_processes 1; error_log {logf} info; pid {pidf};
events {{ worker_connections 128; }}
stream {{ server {{
    listen {BIND_HOST}:{port};
    brix_root on;
    brix_auth none;
    brix_tap_proxy on;
    brix_tap_proxy_auth sss;
    brix_sss_keytab {kt_bad};
    brix_tap_proxy_upstream {BIND_HOST}:{sss_origin.port} sss;
}} }}
""")

    for inst in insts.values():
        _start_nginx(inst.conf)
    for inst in insts.values():
        if not _wait_port(inst.port):
            for i2 in insts.values():
                _stop_nginx(i2.conf)
            pytest.skip(f"{inst.name} never came up on {inst.port}")

    ctx = {
        "insts": insts,
        "cache_gsi": cache_gsi,
        "proxy_sss": proxy_sss,
        "proxy_bad": proxy_bad,
        "gsi_origin": gsi_origin,
        "sss_origin": sss_origin,
        "payload_gsi": payload_gsi,
        "payload_sss": payload_sss,
    }
    yield ctx

    for inst in insts.values():
        _stop_nginx(inst.conf)
    time.sleep(0.3)


# ---------------------------------------------------------------------------
# client helpers (anonymous fronts)
# ---------------------------------------------------------------------------

def _cat(port, path="/probe.txt", timeout=30):
    return subprocess.run([XRDFS, f"root://{HOST}:{port}", "cat", path],
                          capture_output=True, env=_clean_env(), timeout=timeout)


def _stat(port, path="/probe.txt", timeout=30):
    return subprocess.run([XRDFS, f"root://{HOST}:{port}", "stat", path],
                          capture_output=True, text=True, env=_clean_env(),
                          timeout=timeout)


def _no_crash(inst):
    """Master still alive AND no fatal signal/alert in the log."""
    if not _alive(_master_pid(inst.pidfile)):
        return False, f"{inst.name}: master pid dead"
    try:
        with open(inst.logfile, errors="replace") as f:
            log = f.read()
    except OSError:
        log = ""
    for bad in ("signal 11", "SIGSEGV", "signal 6", "SIGABRT",
                "segfault", "worker process .* exited on signal"):
        if bad in log:
            return False, f"{inst.name}: log shows {bad!r}"
    return True, ""


# ---------------------------------------------------------------------------
# happy paths — each route serves byte-exact data over its upstream auth
# ---------------------------------------------------------------------------

def test_x509_upstream_route(mesh):
    """anon -> cache-gsi -(X.509 VOMS proxy)-> gsi-origin serves byte-exact."""
    r = _cat(mesh["cache_gsi"].port)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert r.stdout == mesh["payload_gsi"], r.stdout


def test_sss_upstream_route(mesh):
    """anon -> proxy-sss -(SSS keytab)-> sss-origin serves byte-exact."""
    r = _cat(mesh["proxy_sss"].port)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert r.stdout == mesh["payload_sss"], r.stdout


def test_both_routes_stat(mesh):
    for inst in (mesh["cache_gsi"], mesh["proxy_sss"]):
        r = _stat(inst.port)
        assert r.returncode == 0 and "Size:" in r.stdout, \
            f"{inst.name}: {r.stderr}"


# ---------------------------------------------------------------------------
# negative — wrong SSS upstream key is cleanly rejected, never crashes
# ---------------------------------------------------------------------------

def test_sss_wrong_upstream_key_rejected(mesh):
    r = _cat(mesh["proxy_bad"].port, timeout=30)
    assert r.returncode != 0, "wrong-keytab proxy must NOT serve data"
    ok, why = _no_crash(mesh["proxy_bad"])
    assert ok, why
    ok, why = _no_crash(mesh["sss_origin"])
    assert ok, why


# ---------------------------------------------------------------------------
# chaos — concurrent mixed load while backends restart underneath
# ---------------------------------------------------------------------------

def test_chaos_concurrent_mixed_auth_with_restarts(mesh):
    rng = random.Random(0xC4A05)
    fronts = [("x509", mesh["cache_gsi"].port, mesh["payload_gsi"]),
              ("sss", mesh["proxy_sss"].port, mesh["payload_sss"])]
    backends = [mesh["gsi_origin"], mesh["sss_origin"]]

    stop = threading.Event()
    results = []          # (route, ok, clean_error)
    results_lock = threading.Lock()

    def worker(wid):
        wrng = random.Random(wid * 7919 + 1)
        for _ in range(8):
            if stop.is_set():
                break
            route, port, payload = fronts[wrng.randrange(len(fronts))]
            try:
                r = _cat(port, timeout=40)
                ok = (r.returncode == 0 and r.stdout == payload)
                # a non-zero rc is acceptable (backend may be mid-restart) as
                # long as the process returned cleanly rather than hanging.
                clean = ok or (r.returncode != 0)
            except subprocess.TimeoutExpired:
                ok, clean = False, False
            with results_lock:
                results.append((route, ok, clean))
            time.sleep(wrng.uniform(0.0, 0.05))

    def chaos_agent():
        # Restart each backend a few times while the workers run.
        for _ in range(4):
            if stop.is_set():
                break
            time.sleep(0.4)
            b = backends[rng.randrange(len(backends))]
            _stop_nginx(b.conf)
            time.sleep(rng.uniform(0.1, 0.3))
            _start_nginx(b.conf)
            _wait_port(b.port)

    workers = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    agent = threading.Thread(target=chaos_agent)
    for t in workers:
        t.start()
    agent.start()
    for t in workers:
        t.join(timeout=120)
    stop.set()
    agent.join(timeout=30)

    # Make sure the backends are up for the final assertions.
    for b in backends:
        if not _wait_port(b.port, tries=20):
            _start_nginx(b.conf)
            _wait_port(b.port)

    # 1) Nothing crashed — every instance's master is alive, no fatal signals.
    for inst in mesh["insts"].values():
        ok, why = _no_crash(inst)
        assert ok, why

    # 2) Every request returned cleanly (no hangs/timeouts).
    assert results, "no chaos results recorded"
    clean = sum(1 for _, _, c in results if c)
    assert clean == len(results), \
        f"{len(results) - clean}/{len(results)} requests hung/timed out"

    # 3) Recovery: after the dust settles, both routes serve correctly again.
    rg = _cat(mesh["cache_gsi"].port, timeout=40)
    assert rg.returncode == 0 and rg.stdout == mesh["payload_gsi"], \
        f"x509 route did not recover: {rg.stderr}"
    rs = _cat(mesh["proxy_sss"].port, timeout=40)
    assert rs.returncode == 0 and rs.stdout == mesh["payload_sss"], \
        f"sss route did not recover: {rs.stderr}"

    # 4) At least some requests succeeded during the storm (sanity).
    succeeded = sum(1 for _, ok, _ in results if ok)
    assert succeeded > 0, "no request succeeded during the chaos window"
