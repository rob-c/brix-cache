"""
tests/resilience/servers.py — dedicated, self-contained server lifecycle for
fault-injection / wire-loss resilience testing.

WHAT: launch and tear down a dedicated nginx (root://+GSI) and a dedicated
      official `xrootd` daemon (root://+GSI) on a unique high port block, each
      with its own data root, plus the in-repo TCP fault proxy
      (client/bin/brix-fault-proxy) spliced in front of either one.

WHY:  the shared manage_test_servers.sh fleet squats 11094-12126, is flaky to
      bring up, and must not be perturbed by loss sweeps.  Resilience runs need
      isolated, reproducible endpoints that never collide with the main suite,
      living in their own subfolder.

HOW:  reuse the repo's PKI helpers (own PKI dir under a dedicated prefix), the
      module's already-built nginx (objs/nginx, with the xrootd stream module
      compiled in), and the system official `xrootd`.  Every server and the
      fault proxy is a context manager that guarantees teardown.

Nothing here touches the main suite's ports, data, or PKI.
"""
import getpass
import os
import shutil
import socket
import subprocess
import sys
import time

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

# --- Layout ------------------------------------------------------------------

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLIENT_BIN = os.path.join(REPO, "client", "bin")
XRDFS = os.path.join(CLIENT_BIN, "xrdfs")
XRDCP = os.path.join(CLIENT_BIN, "xrdcp")
FAULT_PROXY = os.path.join(CLIENT_BIN, "brix-fault-proxy")

# Dedicated prefix + port block, both overridable but defaulting well clear of
# the main suite (which lives in 11094-12126 under /tmp/xrd-test). The default
# prefix is per-invoking-user: a root lane hands server trees to the
# de-escalated worker (nobody) and would otherwise leave debris an
# unprivileged lane on the same host cannot write over.
PREFIX = os.environ.get(
    "RESIL_PREFIX", f"/tmp/xrd-resilience-{getpass.getuser()}")
NGINX_BIN = os.environ.get("RESIL_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
BRIX_BIN = os.environ.get("RESIL_BRIX_BIN") or shutil.which("xrootd")

NGINX_GSI_PORT = int(os.environ.get("RESIL_NGINX_GSI_PORT", "13901"))
BRIX_GSI_PORT = int(os.environ.get("RESIL_BRIX_GSI_PORT", "13902"))

PKI_DIR = os.path.join(PREFIX, "pki")
CA_DIR = os.path.join(PKI_DIR, "ca")
CA_CERT = os.path.join(CA_DIR, "ca.pem")
SERVER_CERT = os.path.join(PKI_DIR, "server", "hostcert.pem")
SERVER_KEY = os.path.join(PKI_DIR, "server", "hostkey.pem")
USER_PROXY = os.path.join(PKI_DIR, "user", "proxy_std.pem")

_SEC_LIB_CANDIDATES = (
    "/usr/lib64/libXrdSec-5.so",
    "/usr/lib/libXrdSec-5.so",
    "/usr/lib64/libXrdSec.so",
    "/usr/lib/libXrdSec.so",
)


# --- Small helpers ------------------------------------------------------------

def find_sec_lib():
    """Path to the official XRootD security plugin loader, or None."""
    for cand in _SEC_LIB_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    return None


def _chmod(argv):
    """Run a chmod (best-effort); tolerate missing paths so pre-open of an
    absent optional path never aborts server startup."""
    subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def free_port():
    """Return an infrastructure-assigned port for this isolated harness."""
    from ephemeral_port import free_port as assigned_port
    return assigned_port(BIND_HOST)


def port_up(port, host=HOST):
    """True if something accepts a TCP connection on host:port right now."""
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _wait_port(port, timeout=15.0, proc=None):
    """Block until port accepts connections; raise if it never does (or the
    process died first)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_up(port):
            return
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"server on :{port} exited early (rc={proc.returncode})")
        time.sleep(0.1)
    raise RuntimeError(f"server on :{port} never came up within {timeout}s")


def gsi_env(base=None):
    """Environment for a native-client GSI invocation against our PKI.

    Drops LD_LIBRARY_PATH: a conda prefix on it breaks the system XRootD libs
    (see memory: client GSI interop / firewall-resilience gotchas)."""
    env = dict(base or os.environ)
    env["X509_CERT_DIR"] = CA_DIR
    env["X509_USER_PROXY"] = USER_PROXY
    env.pop("LD_LIBRARY_PATH", None)
    return env


# --- PKI ----------------------------------------------------------------------

def _proxy_valid(path, slack=300):
    """True if the cert at `path` will still be valid `slack` seconds from now.

    `openssl x509 -checkend N` exits 0 when the cert is valid for at least N more
    seconds, 1 once it is (about to be) expired."""
    try:
        r = subprocess.run(["openssl", "x509", "-in", path, "-checkend", str(slack)],
                           capture_output=True)
        return r.returncode == 0
    except Exception:
        return False


def ensure_pki():
    """Generate a dedicated PKI (CA + host cert + RFC-3820 user proxy) under
    PREFIX/pki if it is not already present.  Reuses the repo's blitz_test_pki
    helper, keyed on TEST_ROOT so it writes into our prefix rather than the
    main suite's /tmp/xrd-test.

    The user proxy is a short-lived RFC-3820 proxy (~12 h).  We must regenerate
    when it has EXPIRED, not only when files are missing — otherwise a cached
    prefix keeps serving a stale proxy and every GSI handshake fails with
    "certificate verification failed".  blitz_test_pki() wipes + rebuilds the
    whole PKI (fresh proxy), so triggering it on expiry is sufficient."""
    if (os.path.isfile(CA_CERT) and os.path.isfile(SERVER_CERT)
            and os.path.isfile(USER_PROXY) and _proxy_valid(USER_PROXY)):
        return
    env = dict(os.environ)
    env["TEST_ROOT"] = PREFIX
    env.pop("LD_LIBRARY_PATH", None)
    code = (
        "import sys; sys.path.insert(0, 'tests'); "
        "from pki_helpers import blitz_test_pki; blitz_test_pki()"
    )
    subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env, check=True)
    if not (os.path.isfile(CA_CERT) and os.path.isfile(SERVER_CERT) and os.path.isfile(USER_PROXY)):
        raise RuntimeError("PKI generation did not produce the expected files")


# --- nginx (GSI) --------------------------------------------------------------

class NginxGsi:
    """A dedicated nginx serving root://+GSI on its own port and data root,
    owned by the phase-81 registry harness.

    The module is compiled into NGINX_BIN (the repo's objs/nginx), so no
    load_module line is needed.  The harness renders the committed
    ``nginx_resilience_gsi.conf`` template on an auto-assigned port with its own
    export tree; ``.data`` (the export root) and ``.port`` keep the surface the
    resilience harness and brix-fault-proxy expect."""

    def __init__(self, port=None):
        self._port = port
        self.harness = None
        self.port = None
        self.data = None

    def __enter__(self):
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name="resil-nginx-gsi",
            template="nginx_resilience_gsi.conf",
            port=self._port,
            protocol="root",
            readiness="tcp",
            template_values={
                "SERVER_CERT": SERVER_CERT,
                "SERVER_KEY": SERVER_KEY,
                "CA_CERT": CA_CERT,
            },
        ))
        self.port = endpoint.port
        self.data = endpoint.data_root
        return self

    def __exit__(self, *exc):
        if self.harness is not None:
            self.harness.close()
        return False


# --- nginx (anonymous, no auth) ----------------------------------------------

class NginxAnon:
    """A dedicated nginx serving root:// with NO authentication (`brix_auth
    none`) on its own port and data root — for tests that exercise the data plane
    (read/write, resilience) without depending on the GSI/PKI machinery.  Same
    registry-harness lifecycle as NginxGsi; a separate instance name keeps the
    two export trees from colliding."""

    def __init__(self, port=None):
        self._port = port
        self.harness = None
        self.port = None
        self.data = None

    def __enter__(self):
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name="resil-nginx-anon",
            template="nginx_resilience_anon.conf",
            port=self._port,
            protocol="root",
            readiness="tcp",
        ))
        self.port = endpoint.port
        self.data = endpoint.data_root
        return self

    def __exit__(self, *exc):
        if self.harness is not None:
            self.harness.close()
        return False


class NginxTlsAnon:
    """A dedicated nginx serving roots:// (TLS) with NO authentication on its own
    port and data root — the TLS leg of the sweep harness, which was cleartext
    everywhere.  Uses the resilience PKI (ensure_pki() must have run), so a client
    verifies with X509_CERT_DIR=CA_DIR.  ``.port`` and ``.data`` mirror NginxAnon."""

    def __init__(self, port=None):
        self._port = port
        self.harness = None
        self.port = None
        self.data = None

    def __enter__(self):
        ensure_pki()
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name="resil-nginx-tls-anon",
            template="nginx_resilience_tls_anon.conf",
            port=self._port,
            protocol="root",
            readiness="tcp",
            template_values={"SERVER_CERT": SERVER_CERT,
                             "SERVER_KEY": SERVER_KEY},
        ))
        self.port = endpoint.port
        self.data = endpoint.data_root
        return self

    def __exit__(self, *exc):
        if self.harness is not None:
            self.harness.close()
        return False


class NginxTokenRoot:
    """A dedicated nginx serving root:// behind WLCG-token auth (`brix_auth
    token`) — the token leg of the sweep harness, which hard-coded GSI.  The
    caller supplies an already-provisioned issuer (jwks path + issuer +
    audience); ``.port`` and ``.data`` mirror NginxAnon."""

    def __init__(self, jwks_path, issuer, audience, port=None):
        self._port = port
        self._jwks = jwks_path
        self._issuer = issuer
        self._audience = audience
        self.harness = None
        self.port = None
        self.data = None

    def __enter__(self):
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name="resil-nginx-token",
            template="nginx_resilience_token.conf",
            port=self._port,
            protocol="root",
            readiness="tcp",
            template_values={"JWKS_PATH": self._jwks,
                             "ISSUER": self._issuer,
                             "AUDIENCE": self._audience},
        ))
        self.port = endpoint.port
        self.data = endpoint.data_root
        return self

    def __exit__(self, *exc):
        if self.harness is not None:
            self.harness.close()
        return False


class NginxSssRoot:
    """A dedicated nginx serving root:// behind SSS (shared-secret) auth on its
    own port and data root — the last login mechanism with no fault coverage.
    The caller supplies an already-minted keytab (see ``gen_sss_keytab`` in
    tests/cms_mesh_lib.py, or xrdsssadmin-brix directly); the same file
    authenticates the client, so one keytab serves both ends.  ``.port`` and
    ``.data`` mirror NginxAnon."""

    def __init__(self, keytab, port=None):
        self._port = port
        self._keytab = keytab
        self.harness = None
        self.port = None
        self.data = None

    def __enter__(self):
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name="resil-nginx-sss",
            template="nginx_resilience_sss.conf",
            port=self._port,
            protocol="root",
            readiness="tcp",
            template_values={"KEYTAB": self._keytab},
        ))
        self.port = endpoint.port
        self.data = endpoint.data_root
        return self

    def __exit__(self, *exc):
        if self.harness is not None:
            self.harness.close()
        return False


class NginxHttpOriginFront:
    """A root:// front whose STORAGE BACKEND is a remote http:// origin.

    Every other server here is damaged on its client-facing leg.  This one is
    built so the damage lands on the leg the client cannot see: pass the fault
    proxy's listen port as ``origin_port`` and the front's backend fetches all
    cross it, while the client's own connection stays pristine.  ``brix_stage
    off`` in the template keeps sd_http as the top driver so every read really
    goes to the wire.  ``.data`` is the front's export root — which stays EMPTY,
    because the bytes live on the origin."""

    def __init__(self, origin_port, port=None):
        self._port = port
        self._origin_port = origin_port
        self.harness = None
        self.port = None
        self.data = None

    def __enter__(self):
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name="resil-nginx-http-front",
            template="nginx_resilience_http_origin.conf",
            port=self._port,
            protocol="root",
            readiness="tcp",
            template_values={"ORIGIN_PORT": str(self._origin_port)},
        ))
        self.port = endpoint.port
        self.data = endpoint.data_root
        return self

    def __exit__(self, *exc):
        if self.harness is not None:
            self.harness.close()
        return False


class NginxTpcDest:
    """A native root:// third-party-copy DESTINATION (`brix_tpc_allow_local on`).

    In a native TPC the destination dials the source, so aiming the client's
    ``--tpc only`` source URL at a fault proxy puts the damage on the
    destination->source PULL leg — a leg with no client on it.  ``.data`` is
    where a committed copy lands, which is what the assertions read."""

    def __init__(self, port=None):
        self._port = port
        self.harness = None
        self.port = None
        self.data = None

    def __enter__(self):
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name="resil-nginx-tpc-dest",
            template="nginx_resilience_tpc_dest.conf",
            port=self._port,
            protocol="root",
            readiness="tcp",
        ))
        self.port = endpoint.port
        self.data = endpoint.data_root
        return self

    def __exit__(self, *exc):
        if self.harness is not None:
            self.harness.close()
        return False

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "servers_part2.py", "servers_part3.py")
