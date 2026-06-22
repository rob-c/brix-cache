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
from settings import (
    CA_DIR,
    DATA_ROOT,
    HOST,
    NGINX_GSI_PORT,
    PROXY_STD,
    REF_XROOTD_GSI_PORT,
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
REF_PORT    = REF_XROOTD_GSI_PORT
REF_URL     = f"root://{url_host(HOST)}:{REF_XROOTD_GSI_PORT}"
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
def _port_open(port, host="127.0.0.1"):
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

class TestXrootdToNginx:
    """Copy files from the official xrootd server to the nginx-xrootd endpoint."""

    def test_small_file_transfer(self, nginx_gsi_ready):
        """Copy a small file from xrootd to nginx; verify content is identical."""
        content = b"Hello from official xrootd server via GSI!\n" * 10
        filename = "bridge_small_xrd_to_nginx.txt"

        # Write source file into xrootd's data directory
        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        # Copy xrootd → nginx via xrdcp (GSI on both ends)
        rc = _xrdcp(
            f"{REF_URL}//{filename}",
            f"{NGINX_URL}//{filename}",
        )
        assert rc == 0, "xrdcp xrootd→nginx failed"

        # Verify on nginx side
        dst_path = os.path.join(NGINX_DATA, filename)
        assert os.path.exists(dst_path), "File not found in nginx data dir"
        with open(dst_path, "rb") as f:
            got = f.read()
        assert got == content, "File content mismatch after xrootd→nginx transfer"

    def test_large_file_transfer(self, nginx_gsi_ready):
        """Transfer a 10 MB file from xrootd to nginx and verify md5."""
        size = 10 * 1024 * 1024
        content = bytes(range(256)) * (size // 256)
        filename = "bridge_large_xrd_to_nginx.bin"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)
        expected_md5 = _md5(src_path)

        rc = _xrdcp(
            f"{REF_URL}//{filename}",
            f"{NGINX_URL}//{filename}",
        )
        assert rc == 0, "xrdcp large file xrootd→nginx failed"

        dst_path = os.path.join(NGINX_DATA, filename)
        assert os.path.exists(dst_path)
        assert _md5(dst_path) == expected_md5, "md5 mismatch after 10 MB xrootd→nginx"

    def test_checksum_preserved(self, nginx_gsi_ready):
        """Adler32 checksum returned by nginx must match the source file's checksum."""
        content = b"checksum integrity test " * 512
        filename = "bridge_cksum_xrd_to_nginx.txt"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)
        expected = _adler32(src_path)

        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0

        # Query checksum from nginx via GSI
        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        fs = client.FileSystem(NGINX_URL)
        st, resp = fs.query(QueryCode.CHECKSUM, f"/{filename}")
        assert st.ok, f"Checksum query failed: {st.message}"

        # Response: b"adler32 <hex>\x00"
        parts = resp.decode("ascii", errors="replace").strip("\x00").split()
        assert len(parts) == 2 and parts[0] == "adler32"
        got = int(parts[1], 16)
        assert got == expected, (
            f"Checksum mismatch: nginx returned {got:#010x}, expected {expected:#010x}"
        )


# ---------------------------------------------------------------------------
# Tests: nginx → xrootd (GSI on both ends)
# ---------------------------------------------------------------------------

class TestNginxToXrootd:
    """Copy files from the nginx-xrootd endpoint to the official xrootd server."""

    def test_small_file_transfer(self, nginx_gsi_ready):
        """Upload to nginx, then copy nginx → xrootd; verify content."""
        content = b"Hello from nginx-xrootd via GSI!\n" * 10
        filename = "bridge_small_nginx_to_xrd.txt"

        # Upload to nginx
        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0, "Upload to nginx failed"

            # Copy nginx → xrootd
            rc = _xrdcp(
                f"{NGINX_URL}//{filename}",
                f"{REF_URL}//{filename}",
            )
            assert rc == 0, "xrdcp nginx→xrootd failed"

            # Verify on disk in xrootd data dir
            dst_path = os.path.join(BRIDGE_DATA, filename)
            assert os.path.exists(dst_path)
            with open(dst_path, "rb") as f:
                got = f.read()
            assert got == content
        finally:
            os.unlink(local)

    def test_large_file_transfer(self, nginx_gsi_ready):
        """Upload 10 MB to nginx, copy to xrootd, verify md5."""
        size = 10 * 1024 * 1024
        content = os.urandom(size)
        filename = "bridge_large_nginx_to_xrd.bin"

        local = _write_local(content)
        try:
            expected_md5 = _md5(local)

            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0, "Upload 10 MB to nginx failed"

            rc = _xrdcp(
                f"{NGINX_URL}//{filename}",
                f"{REF_URL}//{filename}",
            )
            assert rc == 0, "xrdcp 10 MB nginx→xrootd failed"

            dst_path = os.path.join(BRIDGE_DATA, filename)
            assert _md5(dst_path) == expected_md5
        finally:
            os.unlink(local)


# ---------------------------------------------------------------------------
# Tests: round-trip transfers
# ---------------------------------------------------------------------------

class TestRoundTrip:
    """Upload, bridge, and read back to verify end-to-end GSI transfer integrity."""

    def test_xrootd_to_nginx_and_back(self, nginx_gsi_ready):
        """
        Write a file on xrootd → copy to nginx → read back from nginx.
        Verifies the full path: xrootd GSI read + nginx GSI write + nginx GSI read.
        """
        content = b"round-trip: xrootd write, nginx read\n" * 200
        filename = "bridge_roundtrip_fwd.txt"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        # xrootd → nginx
        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0, "xrootd→nginx copy failed"

        # Read back from nginx via Python client (GSI)
        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        f_obj = client.File()
        st, _ = f_obj.open(f"{NGINX_URL}//{filename}", OpenFlags.READ)
        assert st.ok, f"nginx GSI open failed: {st.message}"
        st, data = f_obj.read()
        assert st.ok
        f_obj.close()
        assert data == content, "Round-trip content mismatch (xrootd write → nginx read)"

    def test_nginx_to_xrootd_and_back(self, nginx_gsi_ready):
        """
        Upload to nginx → copy to xrootd → read back from xrootd.
        Verifies: nginx GSI write + xrootd GSI read.
        """
        content = b"round-trip: nginx write, xrootd read\n" * 200
        filename = "bridge_roundtrip_rev.txt"

        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0, "Upload to nginx failed"

            rc = _xrdcp(
                f"{NGINX_URL}//{filename}",
                f"{REF_URL}//{filename}",
            )
            assert rc == 0, "nginx→xrootd copy failed"

            # Read back via xrdcp to a local temp file
            local_out = _write_local(b"")  # empty placeholder
            os.unlink(local_out)
            rc = _xrdcp(f"{REF_URL}//{filename}", local_out)
            assert rc == 0, "xrootd read-back failed"
            with open(local_out, "rb") as fh:
                got = fh.read()
            os.unlink(local_out)
            assert got == content, "Round-trip content mismatch (nginx write → xrootd read)"
        finally:
            os.unlink(local)

    def test_integrity_across_multiple_chunks(self, nginx_gsi_ready):
        """
        Transfer a file large enough to require multiple xrdcp read chunks (>4 MB),
        verifying that chunked reassembly produces identical bytes on both ends.
        """
        size = 12 * 1024 * 1024   # 12 MB — forces at least 3 read chunks
        content = os.urandom(size)
        filename = "bridge_multichunk.bin"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)
        expected_md5 = _md5(src_path)

        # xrootd → nginx
        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0, "Multi-chunk xrootd→nginx failed"

        # Read back from nginx
        local_out = src_path + ".verify"
        rc = _xrdcp(f"{NGINX_URL}//{filename}", local_out)
        assert rc == 0, "Multi-chunk nginx read-back failed"
        try:
            assert _md5(local_out) == expected_md5
        finally:
            os.unlink(local_out)


# ---------------------------------------------------------------------------
# Tests: authentication enforcement
# ---------------------------------------------------------------------------

class TestAuthEnforcement:
    """Verify that GSI authentication is required and rejected credentials fail."""

    def test_no_proxy_rejected_by_nginx(self, nginx_gsi_ready):
        """
        xrdcp to nginx GSI port without a proxy certificate must fail.
        The server should refuse the connection at the authentication stage.
        """
        local = _write_local(b"should not be written\n")
        try:
            rc = _xrdcp(
                local,
                f"{NGINX_URL}//bridge_auth_test_no_proxy.txt",
                gsi=False,   # no X509 env vars
            )
            assert rc != 0, (
                "xrdcp to GSI nginx port without credentials should have failed"
            )
        finally:
            os.unlink(local)

    def test_no_proxy_rejected_by_xrootd(self, nginx_gsi_ready):
        """
        xrdcp to reference xrootd GSI port without a proxy must also fail,
        confirming the test CA setup enforces authentication on the xrootd side too.
        """
        local = _write_local(b"should not be written\n")
        try:
            # Write a file into xrootd's data dir to try reading without a proxy
            src_path = os.path.join(BRIDGE_DATA, "bridge_no_proxy_src.txt")
            with open(src_path, "wb") as f:
                f.write(b"secret")

            local_out = local + ".out"
            rc = _xrdcp(
                f"{REF_URL}//bridge_no_proxy_src.txt",
                local_out,
                gsi=False,
            )
            assert rc != 0, (
                "xrdcp from GSI xrootd port without credentials should have failed"
            )
            assert not os.path.exists(local_out), (
                "Output file should not exist when auth fails"
            )
        finally:
            os.unlink(local)

    def test_valid_proxy_accepted_by_both(self, nginx_gsi_ready):
        """
        With a valid proxy, transfers to both servers must succeed.
        This is the positive control for the auth tests above.
        """
        content = b"valid proxy accepted\n"
        filename = "bridge_auth_valid.txt"

        # Write to xrootd
        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        # Read from xrootd — must succeed
        local_out = src_path + ".verify"
        rc = _xrdcp(f"{REF_URL}//{filename}", local_out, gsi=True)
        assert rc == 0, "Valid GSI proxy should be accepted by xrootd"
        os.unlink(local_out)

        # Write to nginx — must succeed
        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}", gsi=True)
            assert rc == 0, "Valid GSI proxy should be accepted by nginx-xrootd"
        finally:
            os.unlink(local)


# ---------------------------------------------------------------------------
# Tests: directory listing via GSI
# ---------------------------------------------------------------------------

class TestDirlistGSI:
    """Verify directory listing works across both GSI endpoints."""

    def test_nginx_dirlist_after_bridge_transfer(self, nginx_gsi_ready):
        """
        Files copied from xrootd to nginx must appear in nginx's directory listing.
        """
        filename = "bridge_dirlist_test.txt"
        content  = b"dirlist test file\n"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0

        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        from XRootD.client.flags import DirListFlags
        fs = client.FileSystem(NGINX_URL)
        st, listing = fs.dirlist("/", DirListFlags.STAT)
        assert st.ok, f"nginx GSI dirlist failed: {st.message}"
        names = [e.name for e in listing]
        assert filename in names, (
            f"{filename!r} not found in nginx directory listing.\n"
            f"Got: {names}"
        )

    def test_xrootd_dirlist_after_bridge_transfer(self, nginx_gsi_ready):
        """
        Files copied from nginx to xrootd must appear in xrootd's directory listing.
        """
        filename = "bridge_dirlist_xrd.txt"
        content  = b"dirlist xrootd test file\n"

        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0

            rc = _xrdcp(f"{NGINX_URL}//{filename}", f"{REF_URL}//{filename}")
            assert rc == 0
        finally:
            os.unlink(local)

        from XRootD.client.flags import DirListFlags
        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        fs = client.FileSystem(REF_URL)
        st, listing = fs.dirlist("/", DirListFlags.STAT)
        assert st.ok, f"xrootd GSI dirlist failed: {st.message}"
        names = [e.name for e in listing]
        assert filename in names, (
            f"{filename!r} not found in xrootd directory listing.\n"
            f"Got: {names}"
        )
