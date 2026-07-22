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
           "bad": ep.extra_ports["BAD_PORT"]}


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
