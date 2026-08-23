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
XRDSSSADMIN = os.path.join(CLIENT_DIR, "bin", "xrdsssadmin-brix")

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


def _skip_unless(condition, reason):
    if not condition:
        pytest.skip(reason)


def _remote_preflight():
    _skip_unless(shutil.which("openssl") is not None, "openssl required")
    _skip_unless(os.path.isfile(_VOMS_FAKE), "utils/voms_proxy_fake.py missing")
    _skip_unless(os.access(NGINX_BIN, os.X_OK),
                 f"nginx binary not executable: {NGINX_BIN}")
    result = subprocess.run(
        ["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp", "xrdsssadmin-brix"],
        capture_output=True, text=True, timeout=240,
    )
    binaries = all(os.path.exists(path) for path in (XRDFS, XRDCP, XRDSSSADMIN))
    if result.returncode != 0 or not binaries:
        pytest.skip(f"native client build failed:\n{result.stdout}\n{result.stderr}")
    _remote_pki()


def _remote_pki():
    required = (f"{CA_DIR}/ca.pem", USER_CERT, SERVER_CERT)
    if all(os.path.exists(path) for path in required):
        return
    try:
        import pki_helpers
        pki_helpers.blitz_test_pki()
    except Exception as exc:
        pytest.skip(f"temp PKI unavailable: {exc}")


def _mint_keytab(path, label):
    result = subprocess.run(
        [XRDSSSADMIN, "-k", path, "add", "--id", "1", "--user", "chaosusr",
         "--group", "chaosgrp", "--name", "chaoskey"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"{label}: {result.stdout}{result.stderr}"


def _remote_credentials(root):
    _make_voms_signing_cert()
    _make_vomsdir_lsc(CHAOS_VO)
    proxy = str(root / "proxy_chaos.pem")
    _mint_voms_proxy(proxy)
    keytab, wrong = str(root / "chaos.keytab"), str(root / "wrong.keytab")
    _mint_keytab(keytab, "keytab mint failed")
    _mint_keytab(wrong, "wrong keytab mint failed")
    return proxy, keytab, wrong


def _remote_data(root):
    payload_gsi = b"x509-upstream payload :: " + os.urandom(8).hex().encode() + b"\n"
    payload_sss = b"sss-upstream payload :: " + os.urandom(8).hex().encode() + b"\n"
    gsi_data, sss_data = root / "gsi-origin-data", root / "sss-origin-data"
    gsi_data.mkdir()
    sss_data.mkdir()
    (gsi_data / "probe.txt").write_bytes(payload_gsi)
    (sss_data / "probe.txt").write_bytes(payload_sss)
    return gsi_data, sss_data, payload_gsi, payload_sss


def _make_instance(root, instances, name, renderer):
    directory = root / name
    (directory / "conf").mkdir(parents=True)
    (directory / "logs").mkdir(parents=True)
    (directory / "data").mkdir(parents=True)
    (directory / "cache").mkdir(parents=True, exist_ok=True)
    port = _free_port()
    config = str(directory / "conf/nginx.conf")
    pidfile, logfile = str(directory / "logs/nginx.pid"), str(directory / "logs/error.log")
    with open(config, "w") as stream:
        stream.write(renderer(port, directory, pidfile, logfile))
    instances[name] = Inst(name, port, config, pidfile, logfile)
    return instances[name]


def _gsi_origin_config(data):
    return lambda port, _d, pid, log: f"""
worker_processes 1; error_log {log} info; pid {pid};
events {{ worker_connections 128; }}
stream {{ server {{
    listen {BIND_HOST}:{port}; brix_root on; brix_export {data}; brix_auth gsi;
    brix_certificate {SERVER_CERT}; brix_certificate_key {SERVER_KEY};
    brix_trusted_ca {CA_DIR}/ca.pem;
}} }}
"""


def _sss_origin_config(data, keytab):
    return lambda port, _d, pid, log: f"""
worker_processes 1; error_log {log} info; pid {pid};
events {{ worker_connections 128; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on;
    brix_export {data}; brix_auth sss; brix_sss_keytab {keytab};
}} }}
"""


def _cache_config(proxy, origin):
    return lambda port, directory, pid, log: f"""
worker_processes 1; error_log {log} info; pid {pid};
events {{ worker_connections 128; }}
thread_pool chaos_cache threads=2 max_queue=8192;
stream {{ brix_credential chaosgsi {{ x509_proxy {proxy}; ca_dir {CA_DIR}; }}
server {{ listen {BIND_HOST}:{port}; brix_root on; brix_export {directory}/data;
    brix_auth none; brix_allow_write off; brix_thread_pool chaos_cache;
    brix_storage_backend root://{BIND_HOST}:{origin.port};
    brix_storage_credential chaosgsi; brix_cache_store posix:{directory}/cache;
    brix_cache_export /;
}} }}
"""


def _proxy_config(keytab, origin):
    return lambda port, _d, pid, log: f"""
worker_processes 1; error_log {log} info; pid {pid};
events {{ worker_connections 128; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on; brix_auth none;
    brix_tap_proxy on; brix_tap_proxy_auth sss; brix_sss_keytab {keytab};
    brix_tap_proxy_upstream {BIND_HOST}:{origin.port} sss;
}} }}
"""


def _remote_instances(root, credentials, data):
    proxy, keytab, wrong = credentials
    gsi_data, sss_data, _, _ = data
    instances = {}
    gsi = _make_instance(root, instances, "gsi-origin", _gsi_origin_config(gsi_data))
    sss = _make_instance(root, instances, "sss-origin", _sss_origin_config(sss_data, keytab))
    cache = _make_instance(root, instances, "cache-gsi", _cache_config(proxy, gsi))
    front = _make_instance(root, instances, "proxy-sss", _proxy_config(keytab, sss))
    bad = _make_instance(root, instances, "proxy-sss-bad", _proxy_config(wrong, sss))
    return instances, gsi, sss, cache, front, bad


def _start_remote_instances(instances):
    for instance in instances.values():
        _start_nginx(instance.conf)
    for instance in instances.values():
        if not _wait_port(instance.port):
            _stop_remote_instances(instances)
            pytest.skip(f"{instance.name} never came up on {instance.port}")


def _stop_remote_instances(instances):
    for instance in instances.values():
        _stop_nginx(instance.conf)


@pytest.fixture(scope="module")
def mesh(tmp_path_factory):
    _remote_preflight()
    root = tmp_path_factory.mktemp("chaos")
    credentials = _remote_credentials(root)
    data = _remote_data(root)
    insts, gsi_origin, sss_origin, cache_gsi, proxy_sss, proxy_bad = \
        _remote_instances(root, credentials, data)
    _start_remote_instances(insts)
    ctx = {
        "insts": insts,
        "cache_gsi": cache_gsi,
        "proxy_sss": proxy_sss,
        "proxy_bad": proxy_bad,
        "gsi_origin": gsi_origin,
        "sss_origin": sss_origin,
        "payload_gsi": data[2],
        "payload_sss": data[3],
    }
    yield ctx
    _stop_remote_instances(insts)
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


from split_continuation import load as _load_continuation
_load_continuation(globals(), __file__, "test_chaos_mixed_auth_part2.py")
