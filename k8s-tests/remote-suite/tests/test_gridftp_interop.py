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
  * VOMS interop:           a VOMS-AC-bearing proxy round-trips (the GSI control
                            channel must accept a proxy chain carrying an
                            embedded, out-of-issuer-order VOMS attribute cert)
  * FTS bulk lane:          (a) a globus-url-copy ``-f`` transfer-list batch in
                            ONE invocation — the canonical FTS/gfal bulk driver —
                            and (b) a gsiftp→gsiftp third-party copy (what an
                            FTS server actually orchestrates), all byte-identical

Backend axis (P82.6): the gateway routes every op through the VFS storage seam,
so ``brix_gridftp_storage_backend`` wires ANY backend (pblock/s3/root(s):///
ceph/…) with no data-path change.  ``test_pblock_backend_roundtrip`` drives the
reference client through a pblock-backed export over gsiftp (cluster-free — the
local runner boots it); ``test_s3_backend_roundtrip`` does the same through an
s3:// origin, also cluster-free — the local runner boots a second nginx instance
with an embedded ``brix_s3`` origin (no external MinIO/radosgw needed).

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

def _check_test_plain_data_channel_roundtrip_1(payload, got):
    assert _digest(b"".join(got)) == _digest(payload), \
        "[brix-gateway] cleartext data-channel round-trip corrupted"

def _check_test_voms_attributed_proxy_roundtrip_2(up):
    assert up.returncode == 0, \
        f"[brix-gateway] gateway rejected a VOMS-AC proxy chain: {up.stderr}"


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


def _skip_if_datachan_pinned(what):
    """Skip data-channel cells the gateway cannot satisfy behind a single
    k8s Service.  The gateway pins every data connection to the control peer
    (an anti-hijack invariant — see the plain-data-channel docstring), so it
    exposes NO passive data-port range and refuses a data address that differs
    from the control channel's peer.  Passive STOR/RETR and a same-endpoint
    gsiftp→gsiftp TPC both need exactly that, so they cannot pass against this
    topology — but they DO exercise real gateway behaviour against a host-
    network or dual-endpoint deployment, so gate rather than delete them.  The
    lab sets TEST_GRIDFTP_DATACHAN_PINNED=1 for the container tier."""
    if os.environ.get("TEST_GRIDFTP_DATACHAN_PINNED"):
        pytest.skip(
            f"{what}: gateway pins the data channel to the control peer; this "
            "single-Service topology exposes no passive data-port range and "
            "refuses a data address that differs from the control peer")


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

    # -cd (-create-dest): the SE export is bare, so the client must MKD the
    # nested destination dir before STOR — the real-grid contract for a nested
    # target, and it also exercises the gateway's MKD path as interop coverage.
    up = _guc(["-cd", prot_flag, *mode_flags, f"file://{src}", _gsiftp(remote)])
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
    if passive:
        _skip_if_datachan_pinned("passive PASV/EPSV data channel")
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
        _check_test_plain_data_channel_roundtrip_1(payload, got)
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
    up = subprocess.run([GFAL, "-p", "-f", str(src.as_uri()),
                         _gsiftp("interop/gfal.bin")],
                        capture_output=True, text=True, timeout=120, env=env)
    assert up.returncode == 0, f"[brix-gateway] gfal PUT failed: {up.stderr}"
    dst = tmp_path / "gfal-dn.bin"
    dn = subprocess.run([GFAL, "-f", _gsiftp("interop/gfal.bin"), str(dst.as_uri())],
                        capture_output=True, text=True, timeout=120, env=env)
    assert dn.returncode == 0, f"[brix-gateway] gfal GET failed: {dn.stderr}"
    assert _digest(dst.read_bytes()) == _digest(payload)


# ---- VOMS interop: an AC-bearing proxy must be accepted --------------------

def test_voms_attributed_proxy_roundtrip(tmp_path):
    """Drive the gsiftp round-trip with a VOMS-attributed proxy (minted by the
    chart's pki-bootstrap via voms_proxy_fake, atlas FQAN).  A VOMS AC is an
    extra cert spliced into the proxy chain OUT of strict issuer order; the GSI
    control channel's chain-walk must tolerate it and still round-trip.  This is
    interop, not authorization — the gsiftp gateway has no VO ACL directive, so
    the AC is opaque to it and the transfer simply succeeds as any GSI proxy
    would.  Self-skips unless a VOMS proxy is provisioned."""
    if HOST is None:
        pytest.skip("TEST_GRIDFTP_HOST unset — container-tier lab only")
    if GUC is None:
        pytest.skip("globus-url-copy not on PATH")
    voms_proxy = os.environ.get("TEST_GRIDFTP_VOMS_PROXY")
    if voms_proxy is None or not os.path.exists(voms_proxy):
        pytest.skip("no TEST_GRIDFTP_VOMS_PROXY — VOMS-AC interop cell needs a "
                    "voms-attributed proxy (chart pki-bootstrap provides one)")
    payload = os.urandom(1024 * 1024)
    src = tmp_path / "voms-up.bin"
    src.write_bytes(payload)
    # Point the GSI control channel at the VOMS-AC proxy, not the plain one.
    env = dict(os.environ, X509_USER_PROXY=voms_proxy)
    env.setdefault("X509_CERT_DIR", "/etc/grid-security/certificates")
    up = subprocess.run([GUC, "-cd", "-dcpriv", f"file://{src}", _gsiftp("voms/ac.bin")],
                        capture_output=True, text=True, timeout=120, env=env)
    _check_test_voms_attributed_proxy_roundtrip_2(up)
    dst = tmp_path / "voms-dn.bin"
    dn = subprocess.run([GUC, "-dcpriv", _gsiftp("voms/ac.bin"), f"file://{dst}"],
                        capture_output=True, text=True, timeout=120, env=env)
    def _assert_test_voms_attributed_proxy_roundtrip_1():
        assert dn.returncode == 0, f"[brix-gateway] VOMS-AC GET failed: {dn.stderr}"
        assert _digest(dst.read_bytes()) == _digest(payload), \
            "[brix-gateway] VOMS-AC proxy round-trip corrupted the bytes"

    _assert_test_voms_attributed_proxy_roundtrip_1()


# ---- FTS bulk lane: transfer-list batch + third-party copy ------------------

def test_fts_transfer_list_batch(tmp_path):
    """The canonical FTS/gfal bulk mechanism: a globus-url-copy ``-f
    <transfer-list>`` file naming N ``<src> <dst>`` pairs, submitted in ONE
    invocation (not a Python loop of single copies).  All must land, and a
    pull-back of each must be byte-identical."""
    _require_gsi()
    n = int(os.environ.get("TEST_GRIDFTP_BULK_N", "16"))
    payloads = {f"bulk/{i:04d}.bin": os.urandom(64 * 1024) for i in range(n)}
    listing = []
    for name, data in payloads.items():
        p = tmp_path / os.path.basename(name)
        p.write_bytes(data)
        listing.append(f"file://{p} {_gsiftp(name)}")
    xfer_list = tmp_path / "fts-transfer.list"
    xfer_list.write_text("\n".join(listing) + "\n")

    up = _guc(["-cd", "-nodcau", "-f", str(xfer_list)])
    assert up.returncode == 0, \
        f"[brix-gateway] FTS transfer-list PUT batch failed: {up.stderr}"

    for name, data in payloads.items():
        dst = tmp_path / ("dn-" + os.path.basename(name))
        dn = _guc(["-nodcau", _gsiftp(name), f"file://{dst}"])
        def _assert_test_fts_transfer_list_batch_2():
            assert dn.returncode == 0, f"[brix-gateway] bulk GET {name}: {dn.stderr}"
            assert _digest(dst.read_bytes()) == _digest(data), \
                f"[brix-gateway] FTS batch {name} corrupted"

        _assert_test_fts_transfer_list_batch_2()


def test_fts_third_party_copy(tmp_path):
    """An FTS server does not stream bytes itself — it orchestrates a
    THIRD-PARTY gsiftp→gsiftp copy between two storage endpoints.  Here both
    URLs point at the same gateway (src already staged), so a
    ``globus-url-copy gsiftp://…/a gsiftp://…/b`` proves the gateway can act as
    both ends of a server-to-server transfer, then a GET verifies the copy."""
    _require_gsi()
    _skip_if_datachan_pinned("same-endpoint gsiftp→gsiftp third-party copy")
    payload = os.urandom(2 * 1024 * 1024)
    seed = tmp_path / "tpc-seed.bin"
    seed.write_bytes(payload)
    up = _guc(["-cd", "-nodcau", f"file://{seed}", _gsiftp("tpc/src.bin")])
    assert up.returncode == 0, f"[brix-gateway] TPC seed PUT failed: {up.stderr}"

    tp = _guc(["-cd", "-nodcau", _gsiftp("tpc/src.bin"), _gsiftp("tpc/dst.bin")])
    assert tp.returncode == 0, \
        f"[brix-gateway] gsiftp→gsiftp third-party copy failed: {tp.stderr}"

    dst = tmp_path / "tpc-dst.bin"
    dn = _guc(["-nodcau", _gsiftp("tpc/dst.bin"), f"file://{dst}"])
    assert dn.returncode == 0, f"[brix-gateway] TPC dst GET failed: {dn.stderr}"
    assert _digest(dst.read_bytes()) == _digest(payload), \
        "[brix-gateway] third-party copy corrupted the bytes"


# ---- backend axis: pblock/s3 ARE wired into the gateway --------------------
#
# The gateway routes every data-plane op through the VFS storage seam and
# registers brix_gridftp_storage_backend via the shared brix_vfs_backend_config_str
# (ceph/rados/tape/http/s3/root(s):///pblock/posix), so a non-posix backend needs
# no data-path change — only the registration.  These cells drive the *reference*
# client (globus-url-copy) STOR/RETR THROUGH a non-posix backend export over
# gsiftp — the interop proof the native ftplib suites (test_gridftp_pblock.py,
# test_gridftp_s3.py, test_gridftp_verify_write.py) cannot give because they use
# brix's own FTP client rather than the grid stack.  The pblock leg is cluster-
# free (local SQLite catalog + block files) so the local runner boots it; the s3
# leg is likewise cluster-free — the local runner boots an embedded brix_s3
# origin in the same nginx (no external MinIO/radosgw), and a clustered chart may
# still point it at a real object store.  Both self-skip until the lab exports the
# corresponding backend listener port.

BACKEND_PBLOCK_PORT = os.environ.get("TEST_GRIDFTP_BACKEND_PBLOCK_PORT")
BACKEND_S3_PORT = os.environ.get("TEST_GRIDFTP_BACKEND_S3_PORT")


def _gsiftp_port(path, port):
    return f"gsiftp://{HOST}:{port}/{path.lstrip('/')}"


def _backend_roundtrip(tmp_path, port, tag):
    """globus-url-copy PUT then GET through a non-posix backend export over
    gsiftp, asserting a byte-identical round-trip — the object travels the VFS
    backend write/read path, not the posix export."""
    _require_gsi()
    payload = os.urandom(2 * 1024 * 1024 + 4096)   # spans several MODE-S buffers
    src = tmp_path / f"src-{tag}.bin"
    src.write_bytes(payload)
    remote = f"interop/{tag}.bin"

    up = _guc(["-cd", "-dcpriv", f"file://{src}", _gsiftp_port(remote, port)])
    assert up.returncode == 0, f"[brix-gateway/{tag}] PUT failed: {up.stderr}"

    dst = tmp_path / f"dst-{tag}.bin"
    dn = _guc(["-dcpriv", _gsiftp_port(remote, port), f"file://{dst}"])
    assert dn.returncode == 0, f"[brix-gateway/{tag}] GET failed: {dn.stderr}"
    assert _digest(dst.read_bytes()) == _digest(payload), \
        f"[brix-gateway/{tag}] backend corrupted the round-trip"


def test_pblock_backend_roundtrip(tmp_path):
    """A reference-client STOR/RETR through the pblock-backed gsiftp export
    round-trips byte-exact — the P82.6 non-posix backend guarantee driven by the
    grid stack, cluster-free."""
    if HOST is None:
        pytest.skip("TEST_GRIDFTP_HOST unset — container-tier lab only")
    if BACKEND_PBLOCK_PORT is None:
        pytest.skip("TEST_GRIDFTP_BACKEND_PBLOCK_PORT unset — lab exports no "
                    "pblock-backed gsiftp listener (see nginx_gridftp_interop.conf)")
    _backend_roundtrip(tmp_path, int(BACKEND_PBLOCK_PORT), "pblock")


def test_s3_backend_roundtrip(tmp_path):
    """A reference-client STOR/RETR through an s3://-backed gsiftp export
    round-trips byte-exact — the staged object-store write/read path over the
    grid stack.  The local runner boots an embedded brix_s3 origin (cluster-free);
    a clustered chart may point it at a real MinIO/radosgw instead."""
    if HOST is None:
        pytest.skip("TEST_GRIDFTP_HOST unset — container-tier lab only")
    if BACKEND_S3_PORT is None:
        pytest.skip("TEST_GRIDFTP_BACKEND_S3_PORT unset — lab exports no "
                    "s3-backed gsiftp listener (see nginx_gridftp_interop.conf)")
    _backend_roundtrip(tmp_path, int(BACKEND_S3_PORT), "s3")
