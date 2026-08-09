"""
tests/test_gsi_bridge.py

Cross-server GSI transfer tests: copy files between an official xrootd server
and the nginx-xrootd plugin, both using GSI/x509 authentication and the local
test CA.

Topology
--------
                       GSI proxy cert (local test CA)
                               │
      xrootd server            │           nginx-xrootd plugin
      port 11097               │           port 11095
      /tmp/xrd-gsi-bridge/data │           /tmp/xrd-test/data
           │                   │                 │
           └─── xrdcp ─────────┴─── xrdcp ───────┘

Both servers use:
  - The same test CA: /tmp/xrd-test/pki/ca/
  - The same server certificate: /tmp/xrd-test/pki/server/hostcert.pem
  - The same user proxy:         /tmp/xrd-test/pki/user/proxy_std.pem

Tests
-----
  - xrootd → nginx  : copy a file from xrootd server to nginx endpoint
  - nginx  → xrootd : copy a file from nginx endpoint to xrootd server
  - round-trip      : upload to xrootd, copy to nginx, read back; check bytes
  - large file      : 10 MB transfer in each direction
  - auth required   : transfers without a proxy cert must fail on both servers
  - integrity       : adler32 checksums match after transfer

Run against already-running nginx-xrootd (port 11095) and a reference xrootd
server started by the session fixture on port 11097.

    pytest tests/test_gsi_bridge.py -v

Environment required:
    X509_CERT_DIR  — must not be set (we set it explicitly in each call)
    X509_USER_PROXY — must not be set (we set it explicitly)
"""

import hashlib
import os
import shutil
import socket
import subprocess
import tempfile
import time
import zlib

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags, QueryCode
from settings import BIND_HOST
from settings import (
    CA_DIR,
    DATA_ROOT,
    HOST,
    NGINX_GSI_PORT,
    PROXY_STD,
    REF_BRIX_GSI_PORT,
    SERVER_CERT,
    SERVER_KEY,
    TEST_ROOT,
    url_host,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROXY_PEM   = PROXY_STD
NGINX_PORT  = NGINX_GSI_PORT
NGINX_URL   = f"root://{url_host(HOST)}:{NGINX_GSI_PORT}"
NGINX_DATA  = DATA_ROOT
REF_PORT    = REF_BRIX_GSI_PORT
REF_URL     = f"root://{url_host(HOST)}:{REF_BRIX_GSI_PORT}"
BRIDGE_DATA = os.path.join(TEST_ROOT, "data-gsi-bridge")


# ---------------------------------------------------------------------------
# Reference GSI xrootd — self-healing so these tests never hang or skip.
#
# The harness is unreliable at provisioning the reference xrootd on REF_PORT
# (its readiness probe fails / it is not always started).  Without it the bridge
# xrdcp calls would block forever.  So if REF_PORT is not already listening, we
# start a throwaway stock xrootd ourselves, using the harness PKI and exporting
# BRIDGE_DATA exactly as the harness reference config does.
# ---------------------------------------------------------------------------
def _port_open(port, host=BIND_HOST):
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _find_seclib():
    for p in ("/usr/lib64/libXrdSec-5.so", "/usr/lib/libXrdSec-5.so",
              "/usr/lib64/libXrdSec.so", "/usr/lib/libXrdSec.so"):
        if os.path.exists(p):
            return p
    return "libXrdSec.so"


@pytest.fixture(scope="module", autouse=True)
def _reference_xrootd():
    """Guarantee a GSI reference xrootd is listening on REF_PORT for the whole
    module — starting one ourselves when the harness has not."""
    if _port_open(REF_PORT):
        yield
        return
    assert shutil.which("xrootd"), \
        "stock xrootd is required for the GSI bridge tests"
    os.makedirs(BRIDGE_DATA, exist_ok=True)
    cfgdir = tempfile.mkdtemp(prefix="gsi_ref_")
    cfg = os.path.join(cfgdir, "ref.cfg")
    with open(cfg, "w") as f:
        f.write(
            f"xrd.port {REF_PORT}\n"
            "all.export / w\n"
            f"oss.localroot {BRIDGE_DATA}\n"
            f"xrootd.seclib {_find_seclib()}\n"
            f"sec.protocol gsi -certdir:{CA_DIR} -cert:{SERVER_CERT} "
            f"-key:{SERVER_KEY} -crl:0 -gmapopt:10 -dlgpxy:0\n"
            "sec.protbind * only gsi\n")
    proc = subprocess.Popen(
        ["xrootd", "-c", cfg, "-l", os.path.join(cfgdir, "ref.log"),
         "-n", "gsibridge"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    up = False
    for _ in range(80):
        if _port_open(REF_PORT):
            up = True
            break
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    assert up, f"could not start a GSI reference xrootd on {REF_PORT}"
    yield
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module", autouse=True)
def _save_restore_env():
    """Save and restore process env vars that test bodies modify directly."""
    _ENV_KEYS = ("X509_CERT_DIR", "X509_USER_PROXY", "XrdSecPROTOCOL",
                 "X509_USER_CERT", "X509_USER_KEY")
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gsi_env() -> dict:
    """Environment variables for GSI-authenticated xrdcp / XRootD client calls."""
    env = os.environ.copy()
    env["X509_CERT_DIR"]   = CA_DIR
    env["X509_USER_PROXY"] = PROXY_PEM
    env["XrdSecPROTOCOL"]  = "gsi"
    # Remove any conflicting env vars from the parent shell
    env.pop("X509_USER_CERT", None)
    env.pop("X509_USER_KEY",  None)
    return env


def _no_gsi_env() -> dict:
    """Environment with no proxy certificate — auth should fail."""
    env = os.environ.copy()
    env.pop("X509_CERT_DIR",    None)
    env.pop("X509_USER_PROXY",  None)
    env.pop("X509_USER_CERT",   None)
    env.pop("X509_USER_KEY",    None)
    env["XrdSecPROTOCOL"] = "gsi"
    return env


def _gsi_client(url: str) -> client.FileSystem:
    """Return a FileSystem connected to *url* with GSI credentials."""
    env_patch = {
        "XRD_SECPROTOCOL":  "gsi",
    }
    # The Python XRootD client reads X509_* from the process environment.
    os.environ["X509_CERT_DIR"]   = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM
    os.environ["XrdSecPROTOCOL"]  = "gsi"
    return client.FileSystem(url)


def _xrdcp(src: str, dst: str, *, gsi: bool = True, extra_args: str = "") -> int:
    """
    Run xrdcp src → dst and return the exit code.

    src/dst may be local paths or root:// URLs.
    When gsi=True, injects X509_* and XrdSecPROTOCOL into the environment.
    Always force overwrite so repeated test runs do not fail on stale artifacts.
    """
    env = _gsi_env() if gsi else _no_gsi_env()
    cmd = f"xrdcp -f -s {extra_args} {src} {dst}"
    # Capture stdout/stderr so successful runs stay quiet and failures are
    # inspectable.  A timeout guards against a wedged/missing peer hanging the
    # whole suite (a no-proxy attempt to a gsi-only server can otherwise retry
    # indefinitely); a timeout is reported as a non-zero (failed) transfer.
    try:
        result = subprocess.run(cmd, shell=True, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=90)
    except subprocess.TimeoutExpired:
        return 124
    return result.returncode


def _adler32(path: str) -> int:
    """Compute adler32 of a local file."""
    csum = 1
    with open(path, "rb") as f:
        # Adler32 is defined as an iterative checksum, so stream the file in chunks.
        for chunk in iter(lambda: f.read(65536), b""):
            csum = zlib.adler32(chunk, csum)
    return csum & 0xFFFFFFFF


def _md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_local(content: bytes) -> str:
    """Write *content* to a temp file and return the path."""
    fd, path = tempfile.mkstemp(prefix="xrd_bridge_", suffix=".bin")
    os.write(fd, content)
    os.close(fd)
    return path


# ---------------------------------------------------------------------------
# Helper fixture: ensure nginx GSI endpoint is reachable
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def nginx_gsi_ready(test_env):
    """Verify nginx-xrootd GSI endpoint is up before running tests."""
    url = test_env["gsi_url"]
    ca  = test_env["ca_dir"]
    proxy = test_env["proxy_pem"]
    env = os.environ.copy()
    env["X509_CERT_DIR"]   = ca
    env["X509_USER_PROXY"] = proxy
    env["XrdSecPROTOCOL"]  = "gsi"
    for _ in range(10):
        try:
            r = subprocess.run(
                ["xrdfs", url, "ls", "/"],
                env=env, capture_output=True, timeout=5,
            )
        except subprocess.TimeoutExpired:
            time.sleep(0.5)
            continue
        if r.returncode == 0:
            return
        time.sleep(0.5)
    pytest.skip(f"nginx-xrootd GSI endpoint not reachable at {url}.")


# ---------------------------------------------------------------------------
# Tests: xrootd → nginx (GSI on both ends)
# ---------------------------------------------------------------------------
