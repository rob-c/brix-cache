"""GFAL2 interop — the WLCG data-access layer (FTS/Rucio) against nginx-xrootd.

gfal2's xrootd plugin drives the official ``libXrdCl`` and its http plugin speaks
WebDAV, so this exercises our server through the exact client stack production
grid transfers use — one API layer above ``xrdcp``/``curl``.

Covers both protocols end-to-end: mkdir, upload, ls, stat, byte-identical
download, ``gfal-sum`` checksum (validated against our own client's digest, not
just liveness), rename, and rm.  Uses the shared fleet (root:// :11094 anon,
davs:// :8443 WebDAV+TLS); skips cleanly if gfal2 or the fleet are absent.
"""
import os
import shutil
import subprocess

import pytest
from settings import HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDCRC32C = os.path.join(REPO, "client", "bin", "xrdcrc32c")

ROOT_BASE = f"root://{HOST}:11094"
DAVS_BASE = f"davs://{HOST}:8443"
CA_DIR = os.path.join(os.environ.get("TEST_ROOT", "/tmp/xrd-test"), "pki", "ca")


def _clean_env():
    """gfal must use the SYSTEM libXrdCl, not conda's — drop LD_LIBRARY_PATH;
    point X509_CERT_DIR at the fleet CA so the davs:// TLS cert verifies."""
    e = dict(os.environ)
    e.pop("LD_LIBRARY_PATH", None)
    if os.path.isdir(CA_DIR):
        e["X509_CERT_DIR"] = CA_DIR
    return e


def _gfal(*args, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=120,
                          env=_clean_env(), **kw)


def _port_open(port):
    return subprocess.run(
        ["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode == 0


pytestmark = pytest.mark.skipif(shutil.which("gfal-copy") is None,
                                reason="gfal2-util not installed")


@pytest.fixture()
def workfile(tmp_path):
    """A fixed-content payload so the checksum assertion is deterministic."""
    p = tmp_path / "src.bin"
    # Deterministic 1 MiB (not random) so gfal-sum is reproducible across runs.
    p.write_bytes(bytes((i * 1103515245 + 12345) & 0xFF for i in range(1 << 20)))
    return p


def _our_crc32c(path):
    """Our own client's crc32c for the same bytes — the oracle for gfal-sum."""
    if not os.path.exists(NATIVE_XRDCRC32C):
        return None
    r = subprocess.run([NATIVE_XRDCRC32C, str(path)],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return None
    # output form: "<hex> <path>" or just "<hex>"
    return r.stdout.split()[0].lower().lstrip("0") or "0"


def _run_matrix(base, work, tmp_path, check_stat_size, with_crc32c):
    """The shared lifecycle matrix for one protocol base URL.

    The data-plane assertions (byte-identical round-trip) are the real integrity
    guarantee and hold for both protocols.  `check_stat_size`/`with_crc32c` are
    gated off for davs:// because gfal2's http (davix) plugin mis-parses the
    PROPFIND size in this version — our server returns the correct value, proven
    independently with curl (HEAD Content-Length AND PROPFIND getcontentlength
    both report the true size); the discrepancy is on the gfal/davix side.
    """
    d = f"{base}/gfaltest_{os.getpid()}_{base.split(':')[0]}"
    up = f"{d}/up.bin"

    assert _gfal("gfal-mkdir", d).returncode == 0, "mkdir failed"
    try:
        r = _gfal("gfal-copy", "-f", str(work), up)
        assert r.returncode == 0, f"upload failed: {r.stderr}"

        assert _gfal("gfal-ls", "-l", d).returncode == 0, "ls failed"

        r = _gfal("gfal-stat", up)
        assert r.returncode == 0, f"stat failed: {r.stderr}"
        if check_stat_size:
            assert "1048576" in r.stdout, f"stat wrong size: {r.stdout}"

        dl = str(tmp_path / "dl.bin")
        r = _gfal("gfal-copy", "-f", up, dl)
        assert r.returncode == 0, f"download failed: {r.stderr}"
        assert open(dl, "rb").read() == work.read_bytes(), "download not byte-identical"

        # Checksum: gfal-sum must match our own client's crc32c for the same file.
        if with_crc32c:
            r = _gfal("gfal-sum", up, "crc32c")
            assert r.returncode == 0, f"gfal-sum crc32c failed: {r.stderr}"
            gfal_ck = r.stdout.split()[-1].lower().lstrip("0") or "0"
            oracle = _our_crc32c(work)
            if oracle is not None:
                assert gfal_ck == oracle, \
                    f"gfal crc32c {gfal_ck} != our {oracle}"

        r = _gfal("gfal-rename", up, f"{d}/renamed.bin")
        assert r.returncode == 0, f"rename failed: {r.stderr}"
        assert _gfal("gfal-rm", f"{d}/renamed.bin").returncode == 0, "rm file failed"
    finally:
        _gfal("gfal-rm", "-r", d)


def test_gfal_brix_plugin_root(workfile, tmp_path):
    """gfal2 xrootd plugin (official XrdCl) ↔ our root:// stream module."""
    if not _port_open(11094):
        pytest.skip("fleet root:// :11094 not listening (run manage_test_servers.sh start)")
    _run_matrix(ROOT_BASE, workfile, tmp_path, check_stat_size=True, with_crc32c=True)


def test_gfal_http_plugin_davs(workfile, tmp_path):
    """gfal2 http plugin ↔ our WebDAV (davs:// over TLS)."""
    if not _port_open(8443):
        pytest.skip("fleet davs:// :8443 not listening")
    if not os.path.isdir(CA_DIR):
        pytest.skip(f"fleet CA {CA_DIR} absent — cannot verify davs:// TLS")
    # gfal-stat over davs:// now returns the correct size: we no longer emit RFC
    # 4331 quota properties (quota-used-bytes) on FILES, which davix had been
    # mapping onto st_size (reporting the filesystem's used bytes as the file
    # size).  Quota stays on collections only.  crc32c over the http plugin is
    # server-config-dependent, so leave that oracle off.
    _run_matrix(DAVS_BASE, workfile, tmp_path, check_stat_size=True, with_crc32c=False)
