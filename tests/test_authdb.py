"""
tests/test_authdb.py

authdb enforcement tests: verify that xrootd_authdb restricts access
based on user identity and VO membership.
"""

import os
import subprocess
import time
import pytest
from settings import (
    AUTHDB_PORT,
    CA_DIR,
    NGINX_BIN,
    PROXY_ATLAS,
    PROXY_CMS,
    PROXY_STD,
    VOMSDIR,
)

AUTHDB_URL  = f"root://localhost:{AUTHDB_PORT}"
AUTHDB_DIR  = "/tmp/xrd-authdb-test"
AUTHDB_DATA = os.path.join(AUTHDB_DIR, "data")
AUTHDB_FILE = os.path.join(AUTHDB_DIR, "authdb")


def _proxy_dn(pem: str) -> str:
    """Return the X.509 subject of the leaf cert in pem — matches ctx->dn."""
    r = subprocess.run(
        ["openssl", "x509", "-in", pem, "-noout", "-subject", "-nameopt", "compat"],
        check=True, capture_output=True, text=True,
    )
    return r.stdout.strip().split("=", 1)[1].strip()


@pytest.fixture(scope="session")
def authdb_setup():
    os.makedirs(AUTHDB_DATA, exist_ok=True)

    # ctx->dn is set from the leaf cert (the proxy), not the EEC.
    proxy_dn = _proxy_dn(PROXY_STD)

    with open(AUTHDB_FILE, "w") as f:
        f.write("# authdb for nginx-xrootd tests\n")
        f.write("u * /public rl\n")
        f.write("g cms /cms r\n")
        f.write("g atlas /atlas r\n")
        f.write(f"u {proxy_dn} /private rw\n")

    for subdir in ("public", "cms", "atlas", "private"):
        path = os.path.join(AUTHDB_DATA, subdir)
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "seed.txt"), "w") as f:
            f.write(f"seed in {subdir}\n")

    yield AUTHDB_FILE


@pytest.fixture(scope="session")
def authdb_nginx(authdb_setup):
    import server_control

    # Use conf_text so server_control manages prefix/pid/logs.
    # {PORT}, {DATA_DIR}, {SERVER_CERT}, {SERVER_KEY}, {CA_CERT} come from
    # server_control's defaults; VOMSDIR, VOMS_CERT_DIR, AUTHDB_FILE are extras.
    conf_text = """\
daemon off;
worker_processes 1;
stream {
    server {
        listen {PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_auth gsi;
        xrootd_allow_write on;
        xrootd_certificate     {SERVER_CERT};
        xrootd_certificate_key {SERVER_KEY};
        xrootd_trusted_ca      {CA_CERT};
        xrootd_vomsdir         {VOMSDIR};
        xrootd_voms_cert_dir   {VOMS_CERT_DIR};
        xrootd_authdb          {AUTHDB_FILE};
    }
}
"""

    info = server_control.start_nginx_instance(
        port=AUTHDB_PORT,
        nginx_bin=NGINX_BIN,
        conf_text=conf_text,
        template_kwargs={
            "DATA_DIR":      AUTHDB_DATA,
            "VOMSDIR":       VOMSDIR,
            "VOMS_CERT_DIR": CA_DIR,
            "AUTHDB_FILE":   AUTHDB_FILE,
        },
    )

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
        info["stop"]()
        pytest.fail(f"Authdb nginx did not become ready on port {AUTHDB_PORT}.")

    yield info
    info["stop"]()


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
        ["xrdcp", "-f", "/etc/hostname", f"{AUTHDB_URL}/public/test.txt"],
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
    """u <proxy-dn> /private rw: specific proxy DN can write."""
    r = subprocess.run(
        ["xrdcp", "-f", "/etc/hostname", f"{AUTHDB_URL}/private/test.txt"],
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
