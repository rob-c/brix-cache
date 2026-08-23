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
    NGINX_BIN,
    PKI_DIR,
    SERVER_CERT,
    SERVER_KEY,
    USER_CERT,
    USER_KEY,
    VOMS_CERT,
    VOMS_KEY,
    VOMSDIR,
)
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-chaos")]

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
    """Registry handle for one mesh instance.

    ``regname`` is the base registry name the LifecycleHarness owns (it appends a
    per-pid suffix internally); ``pidfile``/``logfile`` come from the rendered
    endpoint so the crash checks read exactly the launcher's files.
    """

    def __init__(self, name, regname, port, pidfile, logfile):
        self.name = name
        self.regname = regname
        self.port = port
        self.pidfile = pidfile
        self.logfile = logfile


def _mesh_preflight():
    _skip_unless(shutil.which("openssl") is not None, "openssl required")
    _skip_unless(os.path.isfile(_VOMS_FAKE), "utils/voms_proxy_fake.py missing")
    _skip_unless(os.access(NGINX_BIN, os.X_OK),
                 f"nginx binary not executable: {NGINX_BIN}")
    result = subprocess.run(
        ["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp", "xrdsssadmin-brix"],
        capture_output=True, text=True, timeout=240,
    )
    if _client_build_failed(result):
        pytest.skip(f"native client build failed:\n{result.stdout}\n{result.stderr}")
    _ensure_mesh_pki()


def _skip_unless(condition, reason):
    if not condition:
        pytest.skip(reason)


def _client_build_failed(result):
    binaries = all(os.path.exists(path) for path in (XRDFS, XRDCP, XRDSSSADMIN))
    return result.returncode != 0 or not binaries


def _ensure_mesh_pki():
    paths = (f"{CA_DIR}/ca.pem", USER_CERT, SERVER_CERT)
    if all(os.path.exists(path) for path in paths):
        return
    try:
        import pki_helpers
        pki_helpers.blitz_test_pki()
    except Exception as exc:
        pytest.skip(f"temp PKI unavailable: {exc}")


def _mesh_credentials(root):
    _make_voms_signing_cert()
    _make_vomsdir_lsc(CHAOS_VO)
    proxy = str(root / "proxy_chaos.pem")
    _mint_voms_proxy(proxy)
    keytab = str(root / "chaos.keytab")
    wrong_keytab = str(root / "wrong.keytab")
    _mint_keytab(keytab, "keytab mint failed")
    _mint_keytab(wrong_keytab, "wrong keytab mint failed")
    return proxy, keytab, wrong_keytab


def _mint_keytab(path, failure):
    result = subprocess.run(
        [XRDSSSADMIN, "-k", path, "add", "--id", "1", "--user", "chaosusr",
         "--group", "chaosgrp", "--name", "chaoskey"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"{failure}: {result.stdout}{result.stderr}"


def _mesh_data(root):
    payload_gsi = b"x509-upstream payload :: " + os.urandom(8).hex().encode() + b"\n"
    payload_sss = b"sss-upstream payload :: " + os.urandom(8).hex().encode() + b"\n"
    gsi_data = root / "gsi-origin-data"
    sss_data = root / "sss-origin-data"
    gsi_data.mkdir()
    sss_data.mkdir()
    (gsi_data / "probe.txt").write_bytes(payload_gsi)
    (sss_data / "probe.txt").write_bytes(payload_sss)
    cache_export = root / "cache-gsi-export"
    cache_store = root / "cache-gsi-store"
    cache_export.mkdir()
    cache_store.mkdir()
    return {"payload_gsi": payload_gsi, "payload_sss": payload_sss,
            "gsi_data": gsi_data, "sss_data": sss_data,
            "cache_export": cache_export, "cache_store": cache_store}


def _instance(instances, name, registry_name, endpoint):
    instance = Inst(name, registry_name, endpoint.port, endpoint.pidfile,
                    os.path.join(endpoint.prefix, "logs", "error.log"))
    instances[name] = instance
    return instance


def _start_gsi_origin(harness, instances, data):
    endpoint = harness.start(NginxInstanceSpec(
        name="chaos-gsi-origin", template="nginx_chaos_gsi_origin.conf",
        protocol="root", data_root=str(data), readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST, "SERVER_CERT": SERVER_CERT,
                         "SERVER_KEY": SERVER_KEY, "TRUSTED_CA": f"{CA_DIR}/ca.pem"},
        reason="Chaos mixed-auth GSI origin data server.",
    ))
    return _instance(instances, "gsi-origin", "chaos-gsi-origin", endpoint)


def _start_sss_origin(harness, instances, data, keytab):
    endpoint = harness.start(NginxInstanceSpec(
        name="chaos-sss-origin", template="nginx_chaos_sss_origin.conf",
        protocol="root", data_root=str(data), readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST, "KEYTAB": keytab},
        reason="Chaos mixed-auth SSS origin data server.",
    ))
    return _instance(instances, "sss-origin", "chaos-sss-origin", endpoint)


def _start_cache(harness, instances, data, proxy, origin):
    endpoint = harness.start(NginxInstanceSpec(
        name="chaos-cache-gsi", template="nginx_chaos_cache_gsi.conf",
        protocol="root", data_root=str(data["cache_export"]), readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST, "PROXY_PEM": proxy,
                         "CA_DIR": CA_DIR, "GSI_ORIGIN_PORT": origin.port,
                         "CACHE_DIR": str(data["cache_store"])},
        reason="Chaos mixed-auth anon front, X.509 upstream to gsi-origin.",
    ))
    return _instance(instances, "cache-gsi", "chaos-cache-gsi", endpoint)


def _start_sss_proxy(harness, instances, name, keytab, origin, reason):
    registry_name = f"chaos-{name}"
    endpoint = harness.start(NginxInstanceSpec(
        name=registry_name, template="nginx_chaos_proxy_sss.conf",
        protocol="root", readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST, "KEYTAB": keytab,
                         "SSS_ORIGIN_PORT": origin.port}, reason=reason,
    ))
    return _instance(instances, name, registry_name, endpoint)


def _launch_registry_mesh(harness, data, credentials):
    proxy, keytab, wrong_keytab = credentials
    instances = {}
    gsi_origin = _start_gsi_origin(harness, instances, data["gsi_data"])
    sss_origin = _start_sss_origin(harness, instances, data["sss_data"], keytab)
    cache = _start_cache(harness, instances, data, proxy, gsi_origin)
    proxy_sss = _start_sss_proxy(
        harness, instances, "proxy-sss", keytab, sss_origin,
        "Chaos mixed-auth anon front, SSS upstream to sss-origin.",
    )
    proxy_bad = _start_sss_proxy(
        harness, instances, "proxy-sss-bad", wrong_keytab, sss_origin,
        "Chaos mixed-auth negative front, wrong SSS upstream keytab.",
    )
    return instances, gsi_origin, sss_origin, cache, proxy_sss, proxy_bad


@pytest.fixture(scope="module")
def mesh(tmp_path_factory):
    _mesh_preflight()
    root = tmp_path_factory.mktemp("chaos")
    credentials = _mesh_credentials(root)
    data = _mesh_data(root)
    harness = LifecycleHarness()
    try:
        launched = _launch_registry_mesh(harness, data, credentials)
    except Exception:
        harness.close()
        raise
    insts, gsi_origin, sss_origin, cache_gsi, proxy_sss, proxy_bad = launched
    ctx = {
        "harness": harness,
        "insts": insts,
        "cache_gsi": cache_gsi,
        "proxy_sss": proxy_sss,
        "proxy_bad": proxy_bad,
        "gsi_origin": gsi_origin,
        "sss_origin": sss_origin,
        "payload_gsi": data["payload_gsi"],
        "payload_sss": data["payload_sss"],
    }
    yield ctx

    harness.close()
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
