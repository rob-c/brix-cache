"""
Native Kerberos 5 (krb5) auth — phase-37 §6 + §14.3.

End-to-end gate for the clean-room client's krb5 support: an isolated MIT test
realm (kdc_helpers.py) provisions a KDC, a service keytab for
xrootd/localhost@NGINX.TEST, and a kinit'd client (alice); a self-contained nginx
stream server is configured with `brix_auth krb5` against that keytab; and the
native xrdfs authenticates with `--auth krb5` — proving the client builds a valid
AP-REQ ("krb5" + AP_REQ bytes) the server accepts via krb5_rd_req.

Self-contained: spins up its own nginx (NGINX_BIN) on a free port; uses the
session KDC. Skips cleanly when MIT KDC tooling is absent or krb5 dev libs were
not compiled in (the client links sec_krb5 only under -DBRIX_HAVE_KRB5).

Run (serial):
    PYTHONPATH=tests pytest tests/test_native_krb5.py -v -p no:xdist
"""

import hashlib
import os
import shutil
import socket
import subprocess
import time

import pytest

import kdc_helpers
from settings import (
    BIND_HOST,
    HOST,
    KRB5_CCACHE,
    KRB5_CONF,
    KRB5_KEYTAB,
    KRB5_SERVICE_PRINCIPAL,
    url_host,
)

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _client_has_krb5():
    """The client links sec_krb5 only when built with -DBRIX_HAVE_KRB5; detect
    it by asking xrdfs to force krb5 with no ccache and seeing a krb5-specific
    message (vs. 'no usable auth protocol')."""
    if not os.path.exists(XRDFS):
        return False
    p = subprocess.run([XRDFS, "--auth", "krb5", f"root://{url_host(HOST)}:1", "stat", "/"],
                       capture_output=True, text=True, timeout=20,
                       env={k: v for k, v in os.environ.items()})
    return "krb5" in (p.stderr + p.stdout).lower()


@pytest.fixture(scope="module")
def krb5_server(tmp_path_factory):
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDFS):
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not kdc_helpers.krb5_tools_available():
        pytest.skip("MIT KDC tooling not installed (install krb5-server)")

    # Stand up the isolated realm (KDC + service keytab + kinit'd alice).
    if not kdc_helpers.up():
        pytest.skip("krb5 realm could not be provisioned")

    root = tmp_path_factory.mktemp("krb5srv")
    data = root / "data"
    data.mkdir()
    payload = os.urandom(40000)
    (data / "probe.txt").write_bytes(b"krb5-ok\n")
    (data / "blob.bin").write_bytes(payload)

    port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 256; }}
stream {{
    server {{
        listen {url_host(BIND_HOST)}:{port};
        xrootd on;
        brix_storage_backend posix:{data};
        brix_auth krb5;
        brix_krb5_principal {KRB5_SERVICE_PRINCIPAL};
        brix_krb5_keytab {KRB5_KEYTAB};
        brix_allow_write on;
    }}
}}
""")
    # The acceptor needs the realm config (auth_to_local + default_realm).
    srv_env = {k: v for k, v in os.environ.items()}
    srv_env["KRB5_CONFIG"] = KRB5_CONF
    t = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)], capture_output=True,
                       text=True, env=srv_env)
    if t.returncode != 0:
        kdc_helpers.down()
        pytest.skip("nginx -t failed for the krb5 config:\n" + t.stderr)
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True, env=srv_env)
    for _ in range(50):
        try:
            with socket.create_connection((HOST, port), timeout=1):
                break
        except OSError:
            time.sleep(0.1)

    if not _client_has_krb5():
        subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True,
                       env=srv_env)
        kdc_helpers.down()
        pytest.skip("client built without -DBRIX_HAVE_KRB5")

    yield {"port": port, "payload": payload, "conf": str(conf), "env": srv_env}

    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True,
                   env=srv_env)
    time.sleep(0.3)
    kdc_helpers.down()


def _client_env(ccache=KRB5_CCACHE):
    env = {k: v for k, v in os.environ.items()}
    env.pop("X509_USER_PROXY", None)
    env.pop("BEARER_TOKEN", None)
    env["KRB5_CONFIG"] = KRB5_CONF
    if ccache is not None:
        env["KRB5CCNAME"] = ccache
    else:
        env.pop("KRB5CCNAME", None)
    return env


def _xrdfs(server, *args, ccache=KRB5_CCACHE, timeout=30):
    url = f"root://{url_host(HOST)}:{server['port']}"
    return subprocess.run([XRDFS, "--auth", "krb5", url, *args],
                          capture_output=True, text=True, env=_client_env(ccache),
                          timeout=timeout)


# --------------------------------------------------------------------------
# standalone (no KDC needed): the krb5 module is compiled in + wired
# --------------------------------------------------------------------------

def test_krb5_compiled_and_clean():
    """Always-runnable signal (no KDC): when built with -DBRIX_HAVE_KRB5 the
    client links libkrb5, still links NO libXrd*, and advertises --auth krb5."""
    if not os.path.exists(XRDFS):
        proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs"],
                              capture_output=True, text=True, timeout=180)
        if proc.returncode != 0 or not os.path.exists(XRDFS):
            pytest.skip("native client build failed")
    ldd = subprocess.run(["ldd", XRDFS], capture_output=True, text=True).stdout
    if "libkrb5" not in ldd:
        pytest.skip("client built without -DBRIX_HAVE_KRB5 (no libkrb5 dev)")
    assert "libXrd" not in ldd, f"must not link libXrd*:\n{ldd}"
    help_txt = subprocess.run([XRDFS, "-h"], capture_output=True, text=True).stderr
    assert "krb5" in help_txt, help_txt


# --------------------------------------------------------------------------
# the gate: krb5 auth succeeds (needs a KDC — skips without krb5-server)
# --------------------------------------------------------------------------

def test_krb5_stat_authenticates(krb5_server):
    p = _xrdfs(krb5_server, "stat", "/probe.txt")
    assert p.returncode == 0, f"krb5 stat failed:\n{p.stdout}\n{p.stderr}"
    assert "Size:" in p.stdout, p.stdout


def test_krb5_ls(krb5_server):
    p = _xrdfs(krb5_server, "ls", "/")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "blob.bin" in p.stdout and "probe.txt" in p.stdout, p.stdout


def test_krb5_explain_reports_krb5(krb5_server):
    p = _xrdfs(krb5_server, "explain")
    assert p.returncode == 0, p.stderr
    assert "authenticated with: krb5" in p.stdout, p.stdout


def test_krb5_download_md5_exact(krb5_server, tmp_path):
    out = tmp_path / "blob.out"
    url = f"root://{url_host(HOST)}:{krb5_server['port']}//blob.bin"
    p = subprocess.run([XRDCP, "--auth", "krb5", url, str(out)],
                       capture_output=True, text=True, env=_client_env(), timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    got = out.read_bytes()
    assert hashlib.md5(got).hexdigest() == hashlib.md5(krb5_server["payload"]).hexdigest()


# --------------------------------------------------------------------------
# negatives
# --------------------------------------------------------------------------

def test_krb5_no_ccache_fails(krb5_server, tmp_path):
    """No credential cache → clean client-side failure, no silent success."""
    missing = str(tmp_path / "nope.ccache")
    p = _xrdfs(krb5_server, "stat", "/probe.txt", ccache=missing)
    assert p.returncode != 0, p.stdout
    assert "krb5" in (p.stderr + p.stdout).lower(), p.stderr


def test_krb5_destroyed_ticket_rejected(krb5_server, tmp_path):
    """An empty ccache (no TGT) must not authenticate — security-neg: you cannot
    reach the export without a valid Kerberos credential."""
    empty = tmp_path / "empty.ccache"
    empty.write_bytes(b"")   # not a valid ccache → no usable creds
    p = _xrdfs(krb5_server, "stat", "/probe.txt", ccache=str(empty))
    assert p.returncode != 0, f"empty ccache was accepted!\n{p.stdout}"
