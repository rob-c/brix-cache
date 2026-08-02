"""
xrddiag compare --davs (phase-37 §15.6): the cross-protocol consistency oracle.

Reads the SAME logical object via `root://` and cleartext WebDAV (HTTP GET) and
asserts size + MD5 agree — the capability no upstream client has, since this
project unifies the planes over one VFS. The HTTPS WebDAV plane (--davs-tls,
TLS + chunked) is also compared when supplied; only S3 SigV4 remains deferred
(the tool prints a one-line note).

Self-contained: one nginx with a stream root:// server on data-R, a WebDAV
location on the SAME data-R (the "match" plane), a second WebDAV location on a
DIFFERENT data-B (the "mismatch/404" plane), and a TLS WebDAV listener on data-R
(the --davs-tls plane). Free loopback ports throughout.

Run (serial):
    PYTHONPATH=tests pytest tests/test_xrddiag_compare_davs.py -v -p no:xdist
"""

import os
import shutil
import subprocess

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-xrddiag-compare-davs")]

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")


@pytest.fixture
def fixture(lifecycle, tmp_path_factory):
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

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-xrddiag-compare-davs",
        template="nginx_xrddiag_compare_davs.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(dataR),
        # OK_PORT / BAD_PORT (the two WebDAV planes) come from the fixed-port
        # lifecycle ledger via lifecycle_ports_for("lc-xrddiag-compare-davs").
        template_values={"DATA_B": str(dataB)},
        reason="root:// + two WebDAV planes (same data / different data) for the compare oracle.",
    ))
    yield {"rport": ep.port,
           "ok": ep.extra_ports["OK_PORT"],
           "bad": ep.extra_ports["BAD_PORT"],
           "tls": ep.extra_ports["TLS_PORT"]}


def _cmp(fx, name, davs_port, timeout=30):
    url = f"root://{HOST}:{fx['rport']}//{name}"
    return subprocess.run([XRDDIAG, "compare", url, "--davs", f"{HOST}:{davs_port}"],
                          capture_output=True, text=True, timeout=timeout)


def _cmp_tls(fx, name, tls_port, extra=(), env=None, timeout=30):
    """Run compare with both the cleartext plane (always required) and the
    --davs-tls HTTPS plane against `tls_port`."""
    url = f"root://{HOST}:{fx['rport']}//{name}"
    cmd = [XRDDIAG, "compare", url,
           "--davs", f"{HOST}:{fx['ok']}",
           "--davs-tls", f"{HOST}:{tls_port}", *extra]
    runenv = None
    if env is not None:
        runenv = {**os.environ, **env}
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          env=runenv)


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


def test_davs_tls_identical_matches(fixture):
    """success: same object over the HTTPS WebDAV plane (--davs-tls) agrees with
    root://. Self-signed test cert → --no-verify-tls."""
    p = _cmp_tls(fixture, "match.bin", fixture["tls"], extra=("--no-verify-tls",))
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "[PASS] davs-tls" in p.stdout, p.stdout
    assert "[PASS] davs-tls-md5" in p.stdout, p.stdout
    assert "Result: 0 difference(s)" in p.stdout, p.stdout


def test_davs_tls_verify_enforced(fixture):
    """security-neg: with TLS verification ON (default), the self-signed cert
    MUST be rejected — the oracle must not silently trust an unverified peer."""
    p = _cmp_tls(fixture, "match.bin", fixture["tls"])   # no --no-verify-tls
    assert p.returncode != 0, f"self-signed cert accepted:\n{p.stdout}"
    assert "[FAIL] davs-tls" in p.stdout, p.stdout


def test_davs_tls_connect_error_clean_fail(fixture):
    """error: pointing --davs-tls at a closed port → connection refused → clean
    [FAIL] davs-tls, non-zero (the TLS plane surfaces a connect error, not a
    silent pass). --no-verify-tls isolates this from cert verification."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, 0))
    closed_port = s.getsockname()[1]
    s.close()                               # port now free → connect refused
    # XRDC_MAX_STALL_MS=0 disables the resume/retry window so a hard connect
    # refusal fails on the first attempt instead of riding the patience window.
    p = _cmp_tls(fixture, "match.bin", closed_port, extra=("--no-verify-tls",),
                 env={"XRDC_MAX_STALL_MS": "0"})
    assert p.returncode != 0, p.stdout
    assert "[FAIL] davs-tls" in p.stdout, p.stdout
