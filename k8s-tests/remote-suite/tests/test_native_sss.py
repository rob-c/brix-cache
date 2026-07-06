"""
Native SSS (Simple Shared Secret) auth — phase-37 §6 + §14.3.

End-to-end gate for the clean-room client's SSS support: xrdsssadmin mints a
keytab, an nginx stream server is configured with `brix_auth sss` against that
same keytab, and the native xrdfs authenticates with `--auth sss` — proving the
client builds a byte-exact SSS credential (16-byte header + BF32(40-byte data
header + NAME TLV + IEEE-CRC32)) that the server decrypts and accepts.

Self-contained: spins up its own nginx (NGINX_BIN) on a free port with a temp
keytab and data dir, so it never touches the shared fleet. Builds the client.

Run (serial):
    PYTHONPATH=tests pytest tests/test_native_sss.py -v -p no:xdist
"""

import hashlib
import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDSSSADMIN = os.path.join(CLIENT_DIR, "bin", "xrdsssadmin")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _clean_env(extra=None):
    env = {k: v for k, v in os.environ.items()}
    for k in ("X509_USER_PROXY", "X509_CERT_DIR", "BEARER_TOKEN",
              "BEARER_TOKEN_FILE", "XrdSecSSSKT", "XrdSecsssKT"):
        env.pop(k, None)
    if extra:
        env.update(extra)
    return env


@pytest.fixture(scope="module")
def sss_server(tmp_path_factory):
    # Build the client tools we need.
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp", "xrdsssadmin"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDSSSADMIN):
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("sss")
    data = root / "data"
    data.mkdir()
    payload = os.urandom(40000)
    (data / "probe.txt").write_bytes(b"sss-ok\n")
    (data / "blob.bin").write_bytes(payload)

    # Server keytab: anybody/anygroup so the client's local login name is accepted.
    kt_srv = str(root / "server.keytab")
    r = subprocess.run([XRDSSSADMIN, "-k", kt_srv, "add", "--id", "1",
                        "--user", "anybody", "--group", "anygroup", "--name", "testhost"],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"xrdsssadmin add failed: {r.stdout}{r.stderr}"

    port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 256; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_storage_backend posix:{data};
        brix_auth sss;
        brix_sss_keytab {kt_srv};
        brix_allow_write on;
    }}
}}
""")
    t = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                       capture_output=True, text=True)
    if t.returncode != 0:
        pytest.skip("nginx -t failed for the SSS config:\n" + t.stderr)
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)

    # Wait for the listener.
    for _ in range(50):
        try:
            with socket.create_connection((HOST, port), timeout=1):
                break
        except OSError:
            time.sleep(0.1)

    yield {"port": port, "kt_srv": kt_srv, "data": data, "payload": payload,
           "root": root}

    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def _xrdfs(server, *args, keytab=None, timeout=30):
    env = _clean_env({"XrdSecSSSKT": keytab} if keytab else None)
    url = f"root://{HOST}:{server['port']}"
    return subprocess.run([XRDFS, "--auth", "sss", url, *args],
                          capture_output=True, text=True, env=env, timeout=timeout)


# --------------------------------------------------------------------------
# the gate: SSS auth succeeds
# --------------------------------------------------------------------------

def test_sss_stat_authenticates(sss_server):
    p = _xrdfs(sss_server, "stat", "/probe.txt", keytab=sss_server["kt_srv"])
    assert p.returncode == 0, f"sss stat failed:\n{p.stdout}\n{p.stderr}"
    assert "Size:" in p.stdout, p.stdout


def test_sss_ls(sss_server):
    p = _xrdfs(sss_server, "ls", "/", keytab=sss_server["kt_srv"])
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "blob.bin" in p.stdout and "probe.txt" in p.stdout, p.stdout


def test_sss_explain_reports_sss(sss_server):
    p = _xrdfs(sss_server, "explain", keytab=sss_server["kt_srv"])
    assert p.returncode == 0, p.stderr
    assert "authenticated with: sss" in p.stdout, p.stdout


def test_sss_download_md5_exact(sss_server, tmp_path):
    out = tmp_path / "blob.out"
    env = _clean_env({"XrdSecSSSKT": sss_server["kt_srv"]})
    url = f"root://{HOST}:{sss_server['port']}//blob.bin"
    p = subprocess.run([XRDCP, "--auth", "sss", url, str(out)],
                       capture_output=True, text=True, env=env, timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    got = out.read_bytes()
    assert hashlib.md5(got).hexdigest() == hashlib.md5(sss_server["payload"]).hexdigest()


# --------------------------------------------------------------------------
# negatives
# --------------------------------------------------------------------------

def test_sss_no_keytab_fails(sss_server, tmp_path):
    missing = str(tmp_path / "nope.keytab")
    p = _xrdfs(sss_server, "stat", "/probe.txt", keytab=missing)
    assert p.returncode != 0, p.stdout


def test_sss_wrong_key_rejected(sss_server, tmp_path):
    # Same wire id (1) but a different random key → server CRC mismatch → reject.
    kt_bad = str(tmp_path / "bad.keytab")
    r = subprocess.run([XRDSSSADMIN, "-k", kt_bad, "add", "--id", "1",
                        "--user", "anybody", "--group", "anygroup"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    p = _xrdfs(sss_server, "stat", "/probe.txt", keytab=kt_bad)
    assert p.returncode != 0, f"wrong key was accepted!\n{p.stdout}"
