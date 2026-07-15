"""
xrddiag compare --davs (phase-37 §15.6): the cross-protocol consistency oracle.

Reads the SAME logical object via `root://` and cleartext WebDAV (HTTP GET) and
asserts size + MD5 agree — the capability no upstream client has, since this
project unifies the planes over one VFS. (S3 SigV4 + HTTPS-WebDAV planes are
deferred — the tool prints a one-line note.)

Self-contained: one nginx with a stream root:// server on data-R, a WebDAV
location on the SAME data-R (the "match" plane), and a second WebDAV location on
a DIFFERENT data-B (the "mismatch/404" plane). Free loopback ports throughout.

Run (serial):
    PYTHONPATH=tests pytest tests/test_xrddiag_compare_davs.py -v -p no:xdist
"""

import os
import shutil
import socket
import subprocess
import time

import pytest

from config_templates import render_config
from settings import HOST, BIND_HOST

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrddiag"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDDIAG):
        pytest.skip(f"xrddiag build failed:\n{proc.stdout}\n{proc.stderr}")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("davs")
    dataR = root / "dataR"
    dataB = root / "dataB"
    dataR.mkdir()
    dataB.mkdir()
    payload = os.urandom(300000)
    (dataR / "match.bin").write_bytes(payload)     # same on root + davs-OK
    (dataR / "mism.bin").write_bytes(payload)      # root copy
    (dataB / "mism.bin").write_bytes(os.urandom(300000))  # davs-BAD: different bytes
    # dataB intentionally has NO match.bin → 404 on the BAD plane

    rport = _free_port()
    ok_port = _free_port()
    bad_port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(render_config(
        "nginx_xrddiag_compare_davs.conf",
        BASE_DIR=root,
        BIND_HOST=BIND_HOST,
        ROOT_PORT=rport,
        OK_PORT=ok_port,
        BAD_PORT=bad_port,
        DATA_R=dataR,
        DATA_B=dataB,
    ))
    t = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)], capture_output=True, text=True)
    if t.returncode != 0:
        pytest.skip("nginx -t failed:\n" + t.stderr)
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        try:
            with socket.create_connection((HOST, rport), timeout=1):
                break
        except OSError:
            time.sleep(0.1)
    yield {"rport": rport, "ok": ok_port, "bad": bad_port}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def _cmp(fx, name, davs_port, timeout=30):
    url = f"root://{HOST}:{fx['rport']}//{name}"
    return subprocess.run([XRDDIAG, "compare", url, "--davs", f"{HOST}:{davs_port}"],
                          capture_output=True, text=True, timeout=timeout)


def test_davs_identical_matches(fixture):
    p = _cmp(fixture, "match.bin", fixture["ok"])
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "[PASS] davs-http" in p.stdout, p.stdout
    assert "[PASS] davs-md5" in p.stdout, p.stdout
    assert "Result: 0 difference(s)" in p.stdout, p.stdout


def test_davs_mismatch_fails(fixture):
    """security-neg: root and davs serving different bytes for the same path must
    be reported as a difference (non-zero exit)."""
    p = _cmp(fixture, "mism.bin", fixture["bad"])
    assert p.returncode != 0, f"divergence not caught:\n{p.stdout}"
    assert "[FAIL] davs-md5" in p.stdout, p.stdout


def test_davs_missing_clean_fail(fixture):
    """error: the object is absent on the WebDAV plane (404) → clean non-zero."""
    p = _cmp(fixture, "match.bin", fixture["bad"])   # match.bin not in dataB
    assert p.returncode != 0, p.stdout
    assert "davs-http" in p.stdout, p.stdout
