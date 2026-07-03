"""
tests/test_authdb.py

authdb enforcement tests: verify that brix_authdb restricts access
based on user identity and VO membership.
"""

import os
import subprocess
import sys
import time
import pytest
from settings import (
    AUTHDB_PORT,
    AUTHDB_DIR,
    CA_DIR,
    HOST,
    NGINX_BIN,
    PROXY_ATLAS,
    PROXY_CMS,
    PROXY_STD,
    USER_CERT,
    USER_KEY,
    VOMS_CERT,
    VOMSDIR,
    VOMS_KEY,
    url_host,
)

from settings import TEST_ROOT as _TEST_ROOT

AUTHDB_URL  = f"root://{url_host(HOST)}:{AUTHDB_PORT}"
AUTHDB_DATA = os.path.join(_TEST_ROOT, "data-authdb")
AUTHDB_FILE = os.path.join(AUTHDB_DATA, "authdb")
AUTHDB_UPLOAD = os.path.join(AUTHDB_DIR, "upload.txt")
VOMS_PROXY_FAKE = os.path.join(
    os.path.dirname(__file__), "..", "utils", "voms_proxy_fake.py"
)


def _proxy_is_valid(path: str) -> bool:
    if not os.path.exists(path):
        return False
    r = subprocess.run(
        ["openssl", "x509", "-in", path, "-noout", "-checkend", "3600"],
        capture_output=True,
    )
    return r.returncode == 0


def _voms_dn(pem: str, field: str) -> str:
    r = subprocess.run(
        ["openssl", "x509", "-in", pem, "-noout", f"-{field}", "-nameopt", "compat"],
        check=True, capture_output=True, text=True,
    )
    return r.stdout.strip().split("=", 1)[1].strip()


def _make_voms_signing_cert() -> None:
    os.makedirs(os.path.dirname(VOMS_CERT), exist_ok=True)
    if os.path.exists(VOMS_CERT) and os.path.exists(VOMS_KEY):
        return

    subprocess.run(
        ["openssl", "genrsa", "-out", VOMS_KEY, "2048"],
        check=True, capture_output=True,
    )
    csr = VOMS_CERT.replace(".pem", ".csr")
    subprocess.run(
        [
            "openssl", "req", "-new",
            "-key", VOMS_KEY,
            "-subj", "/DC=test/DC=xrootd/CN=voms.test.local",
            "-out", csr,
        ],
        check=True, capture_output=True,
    )

    ext_file = VOMS_CERT.replace(".pem", "_ext.conf")
    with open(ext_file, "w") as f:
        f.write(
            "[voms_ext]\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid:always\n"
            "basicConstraints = CA:FALSE\n"
        )

    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", csr,
            "-CA", os.path.join(CA_DIR, "ca.pem"),
            "-CAkey", os.path.join(CA_DIR, "ca.key"),
            "-CAcreateserial",
            "-out", VOMS_CERT,
            "-days", "365",
            "-extensions", "voms_ext",
            "-extfile", ext_file,
        ],
        check=True, capture_output=True,
    )


def _make_vomsdir() -> None:
    subject = _voms_dn(VOMS_CERT, "subject")
    issuer = _voms_dn(VOMS_CERT, "issuer")
    content = f"{subject}\n{issuer}\n"

    for vo in ("cms", "atlas"):
        vo_dir = os.path.join(VOMSDIR, vo)
        os.makedirs(vo_dir, exist_ok=True)
        with open(os.path.join(vo_dir, "voms.test.local.lsc"), "w") as f:
            f.write(content)


def _make_voms_proxy(vo: str, fqan: str, out: str) -> None:
    subprocess.run(
        [
            sys.executable, VOMS_PROXY_FAKE,
            "-cert", USER_CERT,
            "-key", USER_KEY,
            "-certdir", CA_DIR,
            "-hostcert", VOMS_CERT,
            "-hostkey", VOMS_KEY,
            "-voms", vo,
            "-fqan", fqan,
            "-uri", "voms.test.local:15000",
            "-out", out,
            "-hours", "24",
        ],
        check=True, capture_output=True,
    )


def _ensure_voms_proxies() -> None:
    if not os.path.exists(VOMS_PROXY_FAKE):
        pytest.skip("voms_proxy_fake.py not available for authdb VO proxy tests")

    _make_voms_signing_cert()
    _make_vomsdir()

    if not _proxy_is_valid(PROXY_CMS):
        _make_voms_proxy("cms", "/cms/Role=NULL/Capability=NULL", PROXY_CMS)
    if not _proxy_is_valid(PROXY_ATLAS):
        _make_voms_proxy("atlas", "/atlas/Role=NULL/Capability=NULL", PROXY_ATLAS)


@pytest.fixture(scope="session")
def authdb_setup():
    os.makedirs(AUTHDB_DATA, exist_ok=True)
    _ensure_voms_proxies()

    with open(AUTHDB_FILE, "w") as f:
        f.write("# authdb for nginx-xrootd tests\n")
        f.write("u * /public rl\n")
        f.write("g cms /cms r\n")
        f.write("g atlas /atlas r\n")
        f.write("u * /private rw\n")
        f.write("p 127.0.0.1 /host r\n")
        f.write("p ::1 /host r\n")
        f.write("p 127.0.0.0/8 /hostcidr r\n")
        f.write("p ::1/128 /hostcidr r\n")
        f.write("p 192.0.2.0/24 /hostdeny r\n")

    for subdir in ("public", "cms", "atlas", "private", "host",
                   "hostcidr", "hostdeny"):
        path = os.path.join(AUTHDB_DATA, subdir)
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "seed.txt"), "w") as f:
            f.write(f"seed in {subdir}\n")

    with open(AUTHDB_UPLOAD, "w") as f:
        f.write("authdb upload test\n")

    yield AUTHDB_FILE


@pytest.fixture(scope="session")
def authdb_nginx(authdb_setup):
    """Use the pre-started dedicated authdb nginx instance.

    The dedicated instance is launched by manage_test_servers.sh start-all at
    port AUTHDB_PORT=11114 with nginx_authdb.conf.  authdb_setup already wrote
    the authdb rules file to {DATA_DIR}/authdb; we SIGHUP nginx so it reloads.
    """
    import signal
    import socket

    # Skip if the dedicated server is not up.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    reachable = s.connect_ex((HOST, AUTHDB_PORT)) == 0
    s.close()
    if not reachable:
        pytest.skip(f"Dedicated authdb nginx not running on port {AUTHDB_PORT}")

    # SIGHUP so nginx reloads the authdb rules written by authdb_setup.
    pidfile = os.path.join(_TEST_ROOT, "dedicated", "authdb", "logs", "nginx.pid")
    if os.path.exists(pidfile):
        try:
            pid = int(open(pidfile).read().strip())
            os.kill(pid, signal.SIGHUP)
            time.sleep(0.5)
        except (ValueError, ProcessLookupError):
            pass

    env = {**os.environ,
           "X509_CERT_DIR":   CA_DIR,
           "X509_USER_PROXY": PROXY_STD,
           "XrdSecPROTOCOL":  "gsi"}

    for _ in range(20):
        r = subprocess.run(
            ["xrdfs", AUTHDB_URL, "stat", "/public/seed.txt"],
            env=env, capture_output=True, timeout=5,
        )
        if r.returncode == 0:
            break
        time.sleep(0.5)
    else:
        pytest.skip(f"Authdb nginx not ready on port {AUTHDB_PORT}")

    yield {}  # server is pre-started; nothing to stop


def _gsi_env(proxy: str) -> dict:
    env = os.environ.copy()
    env["X509_CERT_DIR"]   = CA_DIR
    env["X509_USER_PROXY"] = proxy
    env["XrdSecPROTOCOL"]  = "gsi"
    return env


def test_public_read(authdb_nginx):
    """u * /public rl: everyone can stat."""
    for proxy in (PROXY_STD, PROXY_CMS, PROXY_ATLAS):
        r = subprocess.run(
            ["xrdfs", AUTHDB_URL, "stat", "/public/seed.txt"],
            env=_gsi_env(proxy), capture_output=True, timeout=10,
        )
        assert r.returncode == 0, f"stat failed for {proxy}: {r.stderr.decode()}"


def test_public_write_denied(authdb_nginx):
    """u * /public rl: write is denied (no 'w' priv)."""
    r = subprocess.run(
        ["xrdcp", "-f", AUTHDB_UPLOAD, f"{AUTHDB_URL}/public/test.txt"],
        env=_gsi_env(PROXY_STD), capture_output=True, timeout=10,
    )
    assert r.returncode != 0, "write to /public should be denied"


def test_cms_vo_read(authdb_nginx):
    """g cms /cms r: CMS VO proxy can stat."""
    r = subprocess.run(
        ["xrdfs", AUTHDB_URL, "stat", "/cms/seed.txt"],
        env=_gsi_env(PROXY_CMS), capture_output=True, timeout=10,
    )
    assert r.returncode == 0, f"CMS VO stat failed: {r.stderr.decode()}"


def test_cms_vo_denied_for_atlas(authdb_nginx):
    """g cms /cms r: ATLAS VO proxy is denied."""
    r = subprocess.run(
        ["xrdfs", AUTHDB_URL, "stat", "/cms/seed.txt"],
        env=_gsi_env(PROXY_ATLAS), capture_output=True, timeout=10,
    )
    assert r.returncode != 0, "ATLAS VO access to /cms should be denied"


def test_user_private_write(authdb_nginx):
    """u * /private rw: authenticated users can write."""
    r = subprocess.run(
        ["xrdcp", "-f", AUTHDB_UPLOAD, f"{AUTHDB_URL}/private/test.txt"],
        env=_gsi_env(PROXY_STD), capture_output=True, timeout=10,
    )
    assert r.returncode == 0, f"private write failed: {r.stderr.decode()}"


def test_unlisted_path_denied(authdb_nginx):
    """Paths absent from authdb are denied."""
    other = os.path.join(AUTHDB_DATA, "other")
    os.makedirs(other, exist_ok=True)
    with open(os.path.join(other, "seed.txt"), "w") as f:
        f.write("other\n")

    r = subprocess.run(
        ["xrdfs", AUTHDB_URL, "stat", "/other/seed.txt"],
        env=_gsi_env(PROXY_STD), capture_output=True, timeout=10,
    )
    assert r.returncode != 0, "access to /other (not in authdb) should be denied"


def test_host_rule_exact_peer_read(authdb_nginx):
    """p 127.0.0.1 /host r (or ::1) authorizes the loopback peer."""
    r = subprocess.run(
        ["xrdfs", AUTHDB_URL, "stat", "/host/seed.txt"],
        env=_gsi_env(PROXY_STD), capture_output=True, timeout=10,
    )
    assert r.returncode == 0, f"host authdb rule did not match: {r.stderr.decode()}"


def test_host_rule_cidr_peer_read(authdb_nginx):
    """p 127.0.0.0/8 /hostcidr r (or ::1/128) authorizes via CIDR."""
    r = subprocess.run(
        ["xrdfs", AUTHDB_URL, "stat", "/hostcidr/seed.txt"],
        env=_gsi_env(PROXY_STD), capture_output=True, timeout=10,
    )
    assert r.returncode == 0, f"host CIDR authdb rule did not match: {r.stderr.decode()}"


def test_host_rule_nonmatching_peer_denied(authdb_nginx):
    """A p-rule for an unrelated network must not authorize this peer."""
    r = subprocess.run(
        ["xrdfs", AUTHDB_URL, "stat", "/hostdeny/seed.txt"],
        env=_gsi_env(PROXY_STD), capture_output=True, timeout=10,
    )
    assert r.returncode != 0, "nonmatching host authdb rule should be denied"
