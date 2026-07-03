"""
tests/resilience/servers.py — dedicated, self-contained server lifecycle for
fault-injection / wire-loss resilience testing.

WHAT: launch and tear down a dedicated nginx (root://+GSI) and a dedicated
      official `xrootd` daemon (root://+GSI) on a unique high port block, each
      with its own data root, plus the in-repo TCP fault proxy
      (client/bin/fault_proxy) spliced in front of either one.

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
import os
import shutil
import socket
import subprocess
import sys
import time

# --- Layout ------------------------------------------------------------------

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLIENT_BIN = os.path.join(REPO, "client", "bin")
XRDFS = os.path.join(CLIENT_BIN, "xrdfs")
XRDCP = os.path.join(CLIENT_BIN, "xrdcp")
FAULT_PROXY = os.path.join(CLIENT_BIN, "fault_proxy")

# Dedicated prefix + port block, both overridable but defaulting well clear of
# the main suite (which lives in 11094-12126 under /tmp/xrd-test).
PREFIX = os.environ.get("RESIL_PREFIX", "/tmp/xrd-resilience")
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


def free_port():
    """An ephemeral TCP port currently free on loopback."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def port_up(port, host="127.0.0.1"):
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

_NGINX_CONF = """\
worker_processes 1;
daemon off;
error_log {logs}/error.log error;
pid {logs}/nginx.pid;

events {{ worker_connections 1024; }}

stream {{
    server {{
        listen 127.0.0.1:{port};
        xrootd on;
        brix_storage_backend posix:{data};
        brix_auth gsi;
        brix_allow_write on;
        brix_certificate     {server_cert};
        brix_certificate_key {server_key};
        brix_trusted_ca      {ca_cert};
        brix_access_log {logs}/brix_access_gsi.log;
    }}
}}
"""


class NginxGsi:
    """A dedicated nginx serving root://+GSI on its own port and data root.

    The module is compiled into NGINX_BIN (the repo's objs/nginx), so no
    load_module line is needed.  Runs with `daemon off` so the Popen handle is
    the master and teardown is a single terminate()."""

    def __init__(self, port=NGINX_GSI_PORT):
        self.port = port
        self.prefix = os.path.join(PREFIX, "nginx")
        self.data = os.path.join(self.prefix, "data")
        self.logs = os.path.join(self.prefix, "logs")
        self.conf = os.path.join(self.prefix, "conf", "nginx.conf")
        self.proc = None

    def __enter__(self):
        if not os.path.isfile(NGINX_BIN):
            raise RuntimeError(f"nginx binary not found: {NGINX_BIN}")
        for d in (self.data, self.logs, os.path.dirname(self.conf)):
            os.makedirs(d, exist_ok=True)
        with open(self.conf, "w") as fh:
            fh.write(_NGINX_CONF.format(
                port=self.port, data=self.data, logs=self.logs,
                server_cert=SERVER_CERT, server_key=SERVER_KEY, ca_cert=CA_CERT,
            ))
        env = dict(os.environ)
        env.pop("LD_LIBRARY_PATH", None)
        self.proc = subprocess.Popen(
            [NGINX_BIN, "-p", self.prefix, "-c", "conf/nginx.conf"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        )
        _wait_port(self.port, proc=self.proc)
        return self

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return False


# --- nginx (anonymous, no auth) ----------------------------------------------

_NGINX_ANON_CONF = """\
worker_processes 1;
daemon off;
error_log {logs}/error.log error;
pid {logs}/nginx.pid;

events {{ worker_connections 1024; }}

stream {{
    server {{
        listen 127.0.0.1:{port};
        xrootd on;
        brix_storage_backend posix:{data};
        brix_auth none;
        brix_allow_write on;
        brix_access_log {logs}/brix_access_anon.log;
    }}
}}
"""


class NginxAnon:
    """A dedicated nginx serving root:// with NO authentication (`brix_auth
    none`) on its own port and data root — for tests that exercise the data plane
    (read/write, resilience) without depending on the GSI/PKI machinery.  Same
    lifecycle as NginxGsi; uses a separate prefix so the two never collide."""

    def __init__(self, port=None):
        self.port = port or free_port()
        self.prefix = os.path.join(PREFIX, "nginx_anon")
        self.data = os.path.join(self.prefix, "data")
        self.logs = os.path.join(self.prefix, "logs")
        self.conf = os.path.join(self.prefix, "conf", "nginx.conf")
        self.proc = None

    def __enter__(self):
        if not os.path.isfile(NGINX_BIN):
            raise RuntimeError(f"nginx binary not found: {NGINX_BIN}")
        for d in (self.data, self.logs, os.path.dirname(self.conf)):
            os.makedirs(d, exist_ok=True)
        with open(self.conf, "w") as fh:
            fh.write(_NGINX_ANON_CONF.format(
                port=self.port, data=self.data, logs=self.logs))
        env = dict(os.environ)
        env.pop("LD_LIBRARY_PATH", None)
        self.proc = subprocess.Popen(
            [NGINX_BIN, "-p", self.prefix, "-c", "conf/nginx.conf"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        )
        _wait_port(self.port, proc=self.proc)
        return self

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return False


# --- official xrootd (GSI) ----------------------------------------------------

_BRIX_CFG = """\
xrd.port {port}
xrd.network nodnr
xrd.allow host *
oss.localroot {data}
all.export /
all.adminpath {admin}
all.pidpath   {run}
xrd.trace off
xrootd.seclib {seclib}
sec.protocol gsi -certdir:{ca_dir} -cert:{server_cert} -key:{server_key} -gridmap:none -gmapopt:10
sec.protbind * gsi
"""


class XrootdGsi:
    """A dedicated official `xrootd` daemon serving root://+GSI on its own port
    and data root.  Runs in the foreground (no -b) so the Popen handle owns it.

    Readiness is an actual GSI `ls /` with our native client — the anonymous
    probe the fleet uses cannot authenticate, which is why its 11099 readiness
    check spuriously fails."""

    def __init__(self, port=BRIX_GSI_PORT):
        self.port = port
        self.prefix = os.path.join(PREFIX, "xrootd")
        self.data = os.path.join(self.prefix, "data")
        self.admin = os.path.join(self.prefix, "admin")
        self.run = os.path.join(self.prefix, "run")
        self.logs = os.path.join(self.prefix, "logs")
        self.cfg = os.path.join(self.prefix, "xrootd.cfg")
        self.log = os.path.join(self.logs, "xrootd.log")
        self.proc = None

    def __enter__(self):
        if not BRIX_BIN:
            raise RuntimeError("official `xrootd` daemon not found on PATH")
        seclib = find_sec_lib()
        if not seclib:
            raise RuntimeError("libXrdSec not found; cannot run GSI xrootd")
        for d in (self.data, self.admin, self.run, self.logs):
            os.makedirs(d, exist_ok=True)
        with open(self.cfg, "w") as fh:
            fh.write(_BRIX_CFG.format(
                port=self.port, data=self.data, admin=self.admin, run=self.run,
                seclib=seclib, ca_dir=CA_DIR,
                server_cert=SERVER_CERT, server_key=SERVER_KEY,
            ))
        env = dict(os.environ)
        env.pop("LD_LIBRARY_PATH", None)
        self.proc = subprocess.Popen(
            [BRIX_BIN, "-c", self.cfg, "-l", self.log],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        )
        _wait_port(self.port, proc=self.proc)
        self._wait_gsi_ready()
        return self

    def _wait_gsi_ready(self, timeout=20.0):
        deadline = time.monotonic() + timeout
        url = f"root://127.0.0.1:{self.port}/"
        last = ""
        while time.monotonic() < deadline:
            r = subprocess.run([XRDFS, url, "ls", "/"], env=gsi_env(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=15)
            if r.returncode == 0:
                return
            last = r.stderr.decode(errors="replace").strip()
            time.sleep(0.3)
        raise RuntimeError(f"xrootd GSI not ready on :{self.port}: {last[-300:]}")

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return False


# --- official xrootd (anonymous, no auth) ------------------------------------

_BRIX_ANON_CFG = """\
xrd.port {port}
xrd.network nodnr
xrd.allow host *
oss.localroot {data}
all.export / r/w
all.adminpath {admin}
all.pidpath   {run}
xrd.trace off
"""

OFFICIAL_XRDFS = shutil.which("xrdfs")


class XrootdAnon:
    """A dedicated official `xrootd` daemon serving root:// with NO authentication
    (default unix/host) on its own port and data root — the official-server side of
    a client/server comparison, apples-to-apples with NginxAnon."""

    def __init__(self, port=None):
        self.port = port or free_port()
        self.prefix = os.path.join(PREFIX, "brix_anon")
        self.data = os.path.join(self.prefix, "data")
        self.admin = os.path.join(self.prefix, "admin")
        self.run = os.path.join(self.prefix, "run")
        self.logs = os.path.join(self.prefix, "logs")
        self.cfg = os.path.join(self.prefix, "xrootd.cfg")
        self.log = os.path.join(self.logs, "xrootd.log")
        self.proc = None

    def __enter__(self):
        if not BRIX_BIN:
            raise RuntimeError("official `xrootd` daemon not found on PATH")
        for d in (self.data, self.admin, self.run, self.logs):
            os.makedirs(d, exist_ok=True)
        with open(self.cfg, "w") as fh:
            fh.write(_BRIX_ANON_CFG.format(
                port=self.port, data=self.data, admin=self.admin, run=self.run))
        env = dict(os.environ)
        env.pop("LD_LIBRARY_PATH", None)
        self.proc = subprocess.Popen(
            [BRIX_BIN, "-c", self.cfg, "-l", self.log],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        )
        _wait_port(self.port, proc=self.proc)
        self._wait_ready()
        return self

    def _wait_ready(self, timeout=20.0):
        """Best-effort readiness: an anonymous `ls /` with the official xrdfs."""
        if not OFFICIAL_XRDFS:
            time.sleep(1.0)
            return
        deadline = time.monotonic() + timeout
        url = f"root://127.0.0.1:{self.port}/"
        env = dict(os.environ)
        env.pop("LD_LIBRARY_PATH", None)
        while time.monotonic() < deadline:
            r = subprocess.run([OFFICIAL_XRDFS, url, "ls", "/"], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=15)
            if r.returncode == 0:
                return
            time.sleep(0.3)

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return False


# --- fault proxy --------------------------------------------------------------

class FaultProxy:
    """The in-repo TCP fault injector (client/bin/fault_proxy) spliced in front
    of a target server.  Listen + control ports are ephemeral so concurrent or
    repeated runs never collide.

    Faults are toggled over the control port; see tests/c/fault_proxy.c for the
    full lever set.  set_loss(pct) maps to `lossy <pct>` (per-chunk probability
    of severing the stream — application-visible wire loss); set_jitter(ms) maps
    to `jitter <ms>` (per-chunk uniform-random 0..ms delay — the faithful app-layer
    signature of out-of-order packet delivery on a TCP stream)."""

    def __init__(self, target_port, target_host="127.0.0.1"):
        self.target_host = target_host
        self.target_port = target_port
        self.listen = free_port()
        self.control = free_port()
        self.proc = None

    def __enter__(self):
        if not os.path.isfile(FAULT_PROXY):
            raise RuntimeError(f"fault_proxy not built: {FAULT_PROXY}")
        self.proc = subprocess.Popen(
            [FAULT_PROXY, str(self.listen), self.target_host,
             str(self.target_port), str(self.control)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _wait_port(self.control, proc=self.proc)
        _wait_port(self.listen, proc=self.proc)
        return self

    def ctl(self, cmd):
        with socket.create_connection(("127.0.0.1", self.control), timeout=3) as s:
            s.sendall((cmd + "\n").encode())
            return s.recv(256).decode(errors="replace").strip()

    def set_loss(self, pct):
        # `pct` may be fractional (sub-percent); the proxy honours parts-per-million.
        return self.ctl(f"lossy {pct:g}") if pct > 0 else self.ctl("clear")

    def set_jitter(self, ms):
        return self.ctl(f"jitter {int(ms)}") if ms > 0 else self.ctl("clear")

    def set_reorder(self, pct, delay_ms=50):
        """`reorder <pct> <ms>`: hold back pct% of chunks by delay_ms (the app-layer
        analog of `tc netem reorder pct% delay ms` — a fraction of segments arriving
        out of order). pct may be fractional (sub-percent, ppm resolution); pct=0
        clears all faults."""
        return (self.ctl(f"reorder {pct:g} {int(delay_ms)}")
                if pct > 0 else self.ctl("clear"))

    def url(self, path="/"):
        return f"root://127.0.0.1:{self.listen}/"

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return False


def seed_file(data_root, rel_path, size_bytes, src=None):
    """Place a file of size_bytes at data_root/rel_path.  If src is given, copy
    it (so multiple servers can share byte-identical content); otherwise fill
    from /dev/urandom.  Returns the absolute path."""
    dst = os.path.join(data_root, rel_path.lstrip("/"))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if src:
        shutil.copyfile(src, dst)
        return dst
    with open(dst, "wb") as out, open("/dev/urandom", "rb") as rnd:
        remaining = size_bytes
        chunk = 8 * 1024 * 1024
        while remaining > 0:
            n = min(chunk, remaining)
            out.write(rnd.read(n))
            remaining -= n
    return dst
