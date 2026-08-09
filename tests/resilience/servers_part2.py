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

class NginxWebdavAnon:
    """A dedicated nginx serving WebDAV/HTTP with NO authentication
    (`brix_webdav_auth none`) on its own port and data root — the write-direction
    analogue of NginxAnon, for tests that exercise the PUT ingest gateway
    (client->server body integrity) with a fault proxy in the path.  ``.port`` and
    ``.data`` (the export root) mirror the NginxAnon surface."""

    def __init__(self, port=None, extra_directives=""):
        self._port = port
        self._extra = extra_directives
        self.harness = None
        self.port = None
        self.data = None

    def __enter__(self):
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name="resil-nginx-webdav-anon",
            template="nginx_resilience_webdav_anon.conf",
            port=self._port,
            protocol="http",
            readiness="tcp",
            template_values={"EXTRA_DIRECTIVES": self._extra},
        ))
        self.port = endpoint.port
        self.data = endpoint.data_root
        return self

    def __exit__(self, *exc):
        if self.harness is not None:
            self.harness.close()
        return False


class NginxS3Anon:
    """A dedicated nginx serving the S3 object API with NO authentication (no
    SigV4) on its own port and data root — the S3 analogue of NginxWebdavAnon, for
    tests that exercise the S3 PutObject ingest gateway (client->server body
    integrity, e.g. Content-MD5) with a fault proxy in the path.  Objects live
    under the ``resilbucket`` bucket; ``.port`` and ``.data`` (the export root)
    mirror the NginxAnon surface."""

    bucket = "resilbucket"

    def __init__(self, port=None, extra_directives=""):
        self._port = port
        self._extra = extra_directives
        self.harness = None
        self.port = None
        self.data = None

    def __enter__(self):
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name="resil-nginx-s3-anon",
            template="nginx_resilience_s3_anon.conf",
            port=self._port,
            protocol="http",
            readiness="tcp",
            template_values={"EXTRA_DIRECTIVES": self._extra},
        ))
        self.port = endpoint.port
        self.data = endpoint.data_root
        return self

    def __exit__(self, *exc):
        if self.harness is not None:
            self.harness.close()
        return False


class NginxS3OriginFront:
    """A root:// front whose STORAGE BACKEND is a remote s3:// origin.

    The s3:// sibling of ``NginxHttpOriginFront``, and a separate class rather
    than a parameter because the two drivers do not share a fetch path — sd_s3
    signs its request, parses an S3 error document and has its own handling of a
    short body, so a contract measured through sd_http says nothing about it.
    Pass the fault proxy's listen port as ``origin_port`` and every backend fetch
    crosses the damaged leg while the client's connection stays pristine;
    ``bucket`` must match the origin's ``brix_s3_bucket``.  ``.data`` is the
    front's export root, which stays EMPTY because the bytes live on the origin.
    """

    def __init__(self, origin_port, bucket=NginxS3Anon.bucket, port=None):
        self._port = port
        self._origin_port = origin_port
        self._bucket = bucket
        self.harness = None
        self.port = None
        self.data = None

    def __enter__(self):
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name="resil-nginx-s3-front",
            template="nginx_resilience_s3_origin.conf",
            port=self._port,
            protocol="root",
            readiness="tcp",
            template_values={"ORIGIN_PORT": str(self._origin_port),
                             "BUCKET": self._bucket},
        ))
        self.port = endpoint.port
        self.data = endpoint.data_root
        return self

    def __exit__(self, *exc):
        if self.harness is not None:
            self.harness.close()
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
        argv = [BRIX_BIN, "-c", self.cfg, "-l", self.log]
        # Stock xrootd refuses to run as superuser ("Security reasons prohibit
        # running as superuser; program is terminating." -> exit 8), so under a
        # root test harness drop it to `nobody` via `-R` and pre-open ONLY the
        # paths the dropped user must touch: the traversal path down to our tree,
        # the data root (read + traverse — a+rwX), the admin/pid/log dirs it
        # writes into, the CA + host cert it reads, and the host key (which
        # XrdSecgsi refuses group/world-writable, so chown it to `nobody` 0400 —
        # the root-run nginx master still reads it, root bypassing DAC).
        if os.geteuid() == 0:
            runas = os.environ.get("REF_RUNAS_USER", "nobody")
            _chmod(["chmod", "a+rx", PREFIX, self.prefix])
            _chmod(["chmod", "-R", "a+rwX", self.data, self.admin,
                    self.run, self.logs])
            for d in (os.path.dirname(CA_DIR), CA_DIR,
                      os.path.dirname(SERVER_CERT)):
                _chmod(["chmod", "a+rx", d])
            _chmod(["chmod", "-R", "a+rX", CA_DIR])
            if os.path.isfile(SERVER_CERT):
                _chmod(["chmod", "a+r", SERVER_CERT])
            if os.path.isfile(SERVER_KEY):
                shutil.chown(SERVER_KEY, runas)
                os.chmod(SERVER_KEY, 0o400)
            # Same stale-state hazard as XrootdAnon: a prior unprivileged lane's
            # admin/.xrd under this fixed prefix blocks xrootd-as-`runas`.
            _chmod(["chown", "-R", runas, self.prefix])
            argv += ["-R", runas]
        self.proc = subprocess.Popen(
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        )
        _wait_port(self.port, proc=self.proc)
        self._wait_gsi_ready()
        return self

    def _wait_gsi_ready(self, timeout=20.0):
        deadline = time.monotonic() + timeout
        url = f"root://{HOST}:{self.port}/"
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
{extra}"""

OFFICIAL_XRDFS = shutil.which("xrdfs")


class XrootdAnon:
    """A dedicated official `xrootd` daemon serving root:// with NO authentication
    (default unix/host) on its own port and data root — the official-server side of
    a client/server comparison, apples-to-apples with NginxAnon."""

    def __init__(self, port=None, chksum=None):
        # chksum: e.g. "adler32" to advertise an in-band digest via
        # `xrootd.chksum` (kXR_Qcksum), so a downstream brix-cache with
        # brix_cache_verify best-effort|require has an origin digest to check the
        # staged bytes against.  None (default) → NO digest advertised, exactly
        # like a bare anonymous origin, so `require` has nothing to verify and
        # must fail closed.
        self.chksum = chksum
        self.port = port or free_port()
        self.prefix = os.path.join(PREFIX, "brix_anon_ck" if chksum else "brix_anon")
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
            extra = ("xrootd.chksum max 2 {}\n".format(self.chksum)
                     if self.chksum else "")
            fh.write(_BRIX_ANON_CFG.format(
                port=self.port, data=self.data, admin=self.admin, run=self.run,
                extra=extra))
        env = dict(os.environ)
        env.pop("LD_LIBRARY_PATH", None)
        argv = [BRIX_BIN, "-c", self.cfg, "-l", self.log]
        # Stock xrootd refuses to run as superuser (exit 8) — same handling as
        # the GSI server above: drop to `nobody` via `-R` and open the paths the
        # dropped user must traverse/write (no certs here — anonymous).
        if os.geteuid() == 0:
            runas = os.environ.get("REF_RUNAS_USER", "nobody")
            _chmod(["chmod", "a+rx", PREFIX, self.prefix])
            _chmod(["chmod", "-R", "a+rwX", self.data, self.admin,
                    self.run, self.logs])
            # The prefix is FIXED shared state: a prior unprivileged lane leaves
            # admin/.xrd etc. owned by its user, and xrootd-as-`runas` cannot
            # chmod dirs it does not own ("Unable to set permission for admin
            # path ... operation not permitted").  These trees are throwaway —
            # hand them to the runas account wholesale.
            _chmod(["chown", "-R", runas, self.prefix])
            argv += ["-R", runas]
        self.proc = subprocess.Popen(
            argv,
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
        url = f"root://{HOST}:{self.port}/"
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

