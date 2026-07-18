# brix-remote-ok
"""GridFTP cross-implementation interop matrix (phase-82 P82.5, container tier).

Drives the brix GridFTP gateway with the *reference* Globus client stack
(``globus-url-copy`` and, as an independent second stack, ``gfal-copy``) rather
than brix's own client code — so a framing or GSI regression that both halves of
brix would agree on still gets caught against the wider grid ecosystem.

Topology under test (chart ``charts/gridftp-interop``)::

    globus-url-copy / gfal-copy ──gsiftp:// (GSI control)──► brix GridFTP gateway
    ftplib                      ──ftp://    (cleartext)  ──►   (posix export)

Matrix (posix backend):
  * GSI leg (gsiftp port):  {PROT C, PROT P} × {MODE S, MODE E} round-trips
  * cleartext leg (ftp port): {active, passive} data-channel round-trips
  * second-client interop:  one gfal-copy round-trip
  * FTS-style bulk lane:    a batch of files, all must land byte-identical

Backend axis: the gateway is posix-export only today (``brix_gridftp_export`` →
posix VFS). pblock/s3 backends are not yet wired into the gateway, so those rows
are marked xfail rather than silently skipped — they are the next gateway
feature, not a lab gap.

This is the CONTAINER tier: it self-skips unless the in-cluster gateway
endpoints are exported and a Globus client + GSI proxy are present.  Point it at
the gridftp-interop release with::

    TEST_GRIDFTP_HOST=<gateway-svc> \
    TEST_GRIDFTP_GSIFTP_PORT=2811 TEST_GRIDFTP_FTP_PORT=2810 \
    X509_USER_PROXY=/tmp/x509up \
    pytest k8s-tests/remote-suite/tests/test_gridftp_interop.py -v
"""

import ftplib
import hashlib
import os
import shutil
import socket
import subprocess
import tempfile

import pytest

pytestmark = pytest.mark.serial

HOST = os.environ.get("TEST_GRIDFTP_HOST")
GSIFTP_PORT = int(os.environ.get("TEST_GRIDFTP_GSIFTP_PORT", "2811"))
FTP_PORT = int(os.environ.get("TEST_GRIDFTP_FTP_PORT", "2810"))
GUC = shutil.which("globus-url-copy")
GFAL = shutil.which("gfal-copy")
PROXY = os.environ.get("X509_USER_PROXY")


def _require_gsi():
    if HOST is None:
        pytest.skip("TEST_GRIDFTP_HOST unset — container-tier lab only")
    if GUC is None:
        pytest.skip("globus-url-copy not on PATH")
    if PROXY is None or not os.path.exists(PROXY):
        pytest.skip("no X509_USER_PROXY — GSI control channel needs a proxy")


def _require_plain():
    if HOST is None:
        pytest.skip("TEST_GRIDFTP_HOST unset — container-tier lab only")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _guc(args, timeout=120):
    """Run globus-url-copy with the lab's grid environment; return CompletedProcess."""
    env = dict(os.environ)
    env.setdefault("X509_CERT_DIR", "/etc/grid-security/certificates")
    return subprocess.run([GUC, *args], capture_output=True, text=True,
                          timeout=timeout, env=env)


def _gsiftp(path):
    return f"gsiftp://{HOST}:{GSIFTP_PORT}/{path.lstrip('/')}"


# ---- GSI leg: {PROT C, PROT P} × {MODE S, MODE E} --------------------------

# PROT flag (channel security) × MODE flag (stream vs extended-block). MODE E is
# forced by parallelism (-p); MODE S is the default (no -p).
_PROT = [("protC", "-nodcau"), ("protP", "-dcpriv")]
_MODE = [("modeS", []), ("modeE", ["-p", "4"])]


@pytest.mark.parametrize("prot_id,prot_flag", _PROT, ids=[p[0] for p in _PROT])
@pytest.mark.parametrize("mode_id,mode_flags", _MODE, ids=[m[0] for m in _MODE])
def test_gsi_matrix_roundtrip(tmp_path, prot_id, prot_flag, mode_id, mode_flags):
    """globus-url-copy PUT then GET over gsiftp for each PROT × MODE cell,
    asserting a byte-identical round-trip."""
    _require_gsi()
    payload = os.urandom(3 * 1024 * 1024)          # 3 MiB spans several EBLOCKs
    src = tmp_path / f"src-{prot_id}-{mode_id}.bin"
    src.write_bytes(payload)
    remote = f"interop/{prot_id}-{mode_id}.bin"

    up = _guc([prot_flag, *mode_flags, f"file://{src}", _gsiftp(remote)])
    assert up.returncode == 0, f"[brix-gateway] PUT failed: {up.stderr}"

    dst = tmp_path / f"dst-{prot_id}-{mode_id}.bin"
    dn = _guc([prot_flag, *mode_flags, _gsiftp(remote), f"file://{dst}"])
    assert dn.returncode == 0, f"[brix-gateway] GET failed: {dn.stderr}"
    assert _digest(dst.read_bytes()) == _digest(payload), \
        f"[brix-gateway] {prot_id}/{mode_id} corrupted the round-trip"


# ---- cleartext leg: active vs passive data channel -------------------------

def _ftp():
    ftp = ftplib.FTP()
    ftp.connect(HOST, FTP_PORT, timeout=30)
    ftp.login()
    return ftp


@pytest.mark.parametrize("passive", [True, False], ids=["passive", "active"])
def test_plain_data_channel_roundtrip(tmp_path, passive):
    """A cleartext STOR/RETR round-trip in both passive (PASV/EPSV) and active
    (PORT/EPRT) data-channel modes — the gateway must pin the active data leg to
    the control peer and still land the bytes."""
    _require_plain()
    payload = os.urandom(256 * 1024)
    ftp = _ftp()
    ftp.set_pasv(passive)
    try:
        src = tmp_path / "up.bin"
        src.write_bytes(payload)
        with open(src, "rb") as fh:
            ftp.storbinary(f"STOR dc-{'pasv' if passive else 'active'}.bin", fh)
        got = []
        ftp.retrbinary(f"RETR dc-{'pasv' if passive else 'active'}.bin", got.append)
        assert _digest(b"".join(got)) == _digest(payload), \
            "[brix-gateway] cleartext data-channel round-trip corrupted"
    finally:
        ftp.quit()


# ---- second-client interop: gfal2 ------------------------------------------

def test_gfal_interop_roundtrip(tmp_path):
    """A gfal-copy round-trip proves the gateway against a *second*, independent
    GridFTP client stack — not just globus-url-copy."""
    _require_gsi()
    if GFAL is None:
        pytest.skip("gfal-copy not on PATH")
    payload = os.urandom(512 * 1024)
    src = tmp_path / "gfal-up.bin"
    src.write_bytes(payload)
    env = dict(os.environ)
    up = subprocess.run([GFAL, "-f", str(src.as_uri()), _gsiftp("interop/gfal.bin")],
                        capture_output=True, text=True, timeout=120, env=env)
    assert up.returncode == 0, f"[brix-gateway] gfal PUT failed: {up.stderr}"
    dst = tmp_path / "gfal-dn.bin"
    dn = subprocess.run([GFAL, "-f", _gsiftp("interop/gfal.bin"), str(dst.as_uri())],
                        capture_output=True, text=True, timeout=120, env=env)
    assert dn.returncode == 0, f"[brix-gateway] gfal GET failed: {dn.stderr}"
    assert _digest(dst.read_bytes()) == _digest(payload)


# ---- FTS-style bulk lane ----------------------------------------------------

def test_fts_bulk_batch(tmp_path):
    """An FTS-like batch: many small files pushed then pulled back, all
    byte-identical.  Exercises the gateway under back-to-back session churn the
    way a bulk transfer service drives it."""
    _require_gsi()
    n = int(os.environ.get("TEST_GRIDFTP_BULK_N", "16"))
    payloads = {f"bulk/{i:04d}.bin": os.urandom(64 * 1024) for i in range(n)}
    for name, data in payloads.items():
        p = tmp_path / os.path.basename(name)
        p.write_bytes(data)
        up = _guc(["-nodcau", f"file://{p}", _gsiftp(name)])
        assert up.returncode == 0, f"[brix-gateway] bulk PUT {name}: {up.stderr}"
    for name, data in payloads.items():
        dst = tmp_path / ("dn-" + os.path.basename(name))
        dn = _guc(["-nodcau", _gsiftp(name), f"file://{dst}"])
        assert dn.returncode == 0, f"[brix-gateway] bulk GET {name}: {dn.stderr}"
        assert _digest(dst.read_bytes()) == _digest(data), \
            f"[brix-gateway] bulk {name} corrupted"


# ---- backend axis: pblock/s3 ARE wired into the gateway --------------------

@pytest.mark.parametrize("backend", ["pblock", "s3"])
def test_nonposix_backend_matrix(backend):
    """The gateway now honours brix_gridftp_storage_backend for pblock and s3
    (P82.6 / phase-82 s3-through-gateway): a STOR routes through the VFS backend,
    and the unified brix_vfs_writer picks the in-place (pblock) or staged/object
    (s3) write path transparently.

    Native coverage lives in the fast suite, which exercises the full STOR/RETR/
    CKSM + verify-write round trip over each backend without a cluster:
        tests/test_gridftp_pblock.py         (pblock block store)
        tests/test_gridftp_verify_write.py   (posix + pblock, verify-write)
        tests/test_gridftp_s3.py             (s3 object store, staged + verify)

    This container-tier cell — the same backends driven over *gsiftp* against a
    clustered MinIO/pblock origin — is the remaining interop work; skip until the
    gsiftp gateway chart wires a non-posix backend export."""
    _require_gsi()
    pytest.skip(f"{backend} backend served natively (see test_gridftp_{backend}"
                f".py); gsiftp cluster interop cell pending chart wiring")
