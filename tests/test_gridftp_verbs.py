"""
GridFTP gateway — RFC 959 / RFC 3659 / GridFTP verb surface (phase-82 P82.4).

Drives a *cleartext* brix GridFTP gateway (``brix_gridftp`` with the GSI security
layer off) with Python's ``ftplib`` so the verb batch can be exercised directly,
without a GSSAPI handshake.  The wire behaviour of each verb is identical whether
or not the control channel is GSS-wrapped — the security layer only frames the
same reply bytes — so this is the natural place to prove the command semantics.

Covered (each verb: a success path, plus an error and/or security-negative path):
  * SYST / STAT / MDTM / MLST          -- metadata over the control channel
  * MODE / STRU / ALLO                 -- transfer-parameter verbs (honest 504s)
  * SIZE / REST + resumed RETR         -- restart offset threaded into RETR
  * APPE                               -- append extends in place
  * RNFR / RNTO                        -- two-step rename (and RNTO-without-RNFR)
  * CKSM ADLER32/CRC32/MD5             -- whole-object checksum (bad algo, range)
  * EPSV                               -- RFC 2428 extended passive reply
  * active mode (PORT/EPRT)            -- data channel pinned to the control peer
  * path traversal                     -- confinement holds for every verb

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_verbs.py -v -p no:xdist
"""

import ftplib
import hashlib
import os
import zlib

import pytest

from settings import BIND_HOST, NGINX_BIN, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]


def _require():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


class _Gateway:
    """A registry-owned cleartext FTP gateway, torn down on close()."""

    def __init__(self, harness, name):
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_plain.conf",
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST},
        ))
        self.harness = harness
        self.port = endpoint.port
        self.export = endpoint.data_root

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def gateway():
    _require()
    gw = _Gateway(LifecycleHarness(), "gridftp-plain")
    yield gw
    gw.close()


def _connect(gw):
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, gw.port, timeout=30)
    ftp.login()                                   # USER anonymous / PASS
    return ftp


def _seed(gw, name, data):
    path = os.path.join(gw.export, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


# ---- metadata verbs --------------------------------------------------------

def test_syst(gateway):
    ftp = _connect(gateway)
    try:
        assert ftp.sendcmd("SYST").startswith("215")
    finally:
        ftp.quit()


def test_mdtm_success_and_missing(gateway):
    _seed(gateway, "mtime.bin", b"x" * 10)
    ftp = _connect(gateway)
    try:
        resp = ftp.sendcmd("MDTM mtime.bin")
        assert resp.startswith("213 ")
        # 14-digit UTC timestamp YYYYMMDDHHMMSS
        ts = resp.split()[1]
        assert len(ts) == 14 and ts.isdigit(), resp
        with pytest.raises(ftplib.error_perm):
            ftp.sendcmd("MDTM does-not-exist.bin")
    finally:
        ftp.quit()


def test_mlst_success_and_missing(gateway):
    _seed(gateway, "facts.bin", b"y" * 1234)
    ftp = _connect(gateway)
    try:
        resp = ftp.sendcmd("MLST facts.bin")
        assert resp.startswith("250")
        assert "size=1234" in resp and "type=file" in resp, resp
        with pytest.raises(ftplib.error_perm):
            ftp.sendcmd("MLST nope.bin")
    finally:
        ftp.quit()


def test_stat_status_and_path(gateway):
    _seed(gateway, "stat.bin", b"z" * 7)
    ftp = _connect(gateway)
    try:
        assert ftp.sendcmd("STAT").startswith("211")
        resp = ftp.sendcmd("STAT stat.bin")
        assert resp.startswith("213") and "size=7" in resp, resp
    finally:
        ftp.quit()


# ---- transfer-parameter verbs ----------------------------------------------

def test_mode_and_stru(gateway):
    ftp = _connect(gateway)
    try:
        assert ftp.sendcmd("MODE S").startswith("200")
        assert ftp.sendcmd("STRU F").startswith("200")
        assert ftp.sendcmd("ALLO 4096").startswith("200")
        # Extended-block (E) mode is supported (GFD.020, parallel streams); a
        # bare MODE E is accepted and reset by a subsequent MODE S.
        assert ftp.sendcmd("MODE E").startswith("200")
        assert ftp.sendcmd("MODE S").startswith("200")
        # Record structure remains honestly declined.
        with pytest.raises(ftplib.error_perm) as e2:
            ftp.sendcmd("STRU R")
        assert e2.value.args[0].startswith("504")
    finally:
        ftp.quit()


# ---- SIZE / REST + resumed RETR --------------------------------------------

def test_size_and_rest_resume(gateway, tmp_path):
    payload = os.urandom(5000)
    _seed(gateway, "resume.bin", payload)
    ftp = _connect(gateway)
    try:
        assert ftp.size("resume.bin") == 5000
        # Resume from byte 2000: the RETR must return only the tail.
        chunks = []
        ftp.retrbinary("RETR resume.bin", chunks.append, rest=2000)
        assert b"".join(chunks) == payload[2000:]
        # A negative restart offset is rejected.
        with pytest.raises(ftplib.error_perm):
            ftp.sendcmd("REST -1")
    finally:
        ftp.quit()


# ---- APPE ------------------------------------------------------------------

def test_appe_extends_in_place(gateway, tmp_path):
    _seed(gateway, "log.bin", b"HEAD")
    src = tmp_path / "tail.bin"
    src.write_bytes(b"TAIL")
    ftp = _connect(gateway)
    try:
        with open(src, "rb") as fh:
            ftp.storbinary("APPE log.bin", fh)
    finally:
        ftp.quit()
    with open(os.path.join(gateway.export, "log.bin"), "rb") as fh:
        assert fh.read() == b"HEADTAIL"


# ---- RNFR / RNTO -----------------------------------------------------------

def test_rename_and_rnto_without_rnfr(gateway):
    _seed(gateway, "old-name.bin", b"payload")
    ftp = _connect(gateway)
    try:
        ftp.rename("old-name.bin", "new-name.bin")     # RNFR + RNTO
        assert os.path.exists(os.path.join(gateway.export, "new-name.bin"))
        assert not os.path.exists(os.path.join(gateway.export, "old-name.bin"))
        # RNTO with no preceding RNFR is a sequence error.
        with pytest.raises(ftplib.error_perm) as e:
            ftp.sendcmd("RNTO stray.bin")
        assert e.value.args[0].startswith("503")
    finally:
        ftp.quit()


# ---- CKSM ------------------------------------------------------------------

def test_cksm_algorithms(gateway):
    data = b"checksum me, please " * 64
    _seed(gateway, "ck.bin", data)
    ftp = _connect(gateway)
    try:
        adler = ftp.sendcmd("CKSM ADLER32 0 -1 ck.bin").split()[1]
        assert adler.lower() == f"{zlib.adler32(data) & 0xffffffff:08x}"

        crc = ftp.sendcmd("CKSM CRC32 0 -1 ck.bin").split()[1]
        assert crc.lower() == f"{zlib.crc32(data) & 0xffffffff:08x}"

        md5 = ftp.sendcmd("CKSM MD5 0 -1 ck.bin").split()[1]
        assert md5.lower() == hashlib.md5(data).hexdigest()
    finally:
        ftp.quit()


def test_cksm_bad_algo(gateway):
    _seed(gateway, "ck2.bin", b"data")
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm) as bad:
            ftp.sendcmd("CKSM NOPE32 0 -1 ck2.bin")
        assert bad.value.args[0].startswith("504")
    finally:
        ftp.quit()


def test_cksm_partial_range(gateway):
    """A CKSM with a non-trivial offset/length sums exactly that byte extent —
    the driver-routed _range kernels checksum [offset, offset+length)."""
    data = bytes(range(256)) * 40          # 10 240 bytes, every value present
    _seed(gateway, "ckr.bin", data)
    ftp = _connect(gateway)
    try:
        # Interior window [1000, 1000+2048).
        adler = ftp.sendcmd("CKSM ADLER32 1000 2048 ckr.bin").split()[1]
        assert adler.lower() == f"{zlib.adler32(data[1000:3048]) & 0xffffffff:08x}"

        crc = ftp.sendcmd("CKSM CRC32 1000 2048 ckr.bin").split()[1]
        assert crc.lower() == f"{zlib.crc32(data[1000:3048]) & 0xffffffff:08x}"

        md5 = ftp.sendcmd("CKSM MD5 4 8 ckr.bin").split()[1]
        assert md5.lower() == hashlib.md5(data[4:12]).hexdigest()

        # length past EOF clamps to the bytes that exist (offset..EOF).
        tail = ftp.sendcmd("CKSM CRC32 10200 9999 ckr.bin").split()[1]
        assert tail.lower() == f"{zlib.crc32(data[10200:]) & 0xffffffff:08x}"
    finally:
        ftp.quit()


def test_cksm_malformed_range_rejected(gateway):
    """A malformed range (negative offset, or a length below the -1 EOF sentinel)
    is a 501 usage error, not a bogus digest or a checksum failure."""
    _seed(gateway, "ckm.bin", b"data")
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm) as neg_off:
            ftp.sendcmd("CKSM ADLER32 -1 8 ckm.bin")
        assert neg_off.value.args[0].startswith("501")
        with pytest.raises(ftplib.error_perm) as neg_len:
            ftp.sendcmd("CKSM ADLER32 0 -2 ckm.bin")
        assert neg_len.value.args[0].startswith("501")
    finally:
        ftp.quit()


# ---- EPSV ------------------------------------------------------------------

def test_epsv_reply(gateway):
    ftp = _connect(gateway)
    try:
        resp = ftp.sendcmd("EPSV")
        assert resp.startswith("229") and "(|||" in resp, resp
    finally:
        ftp.quit()


# ---- active mode (PORT/EPRT) -----------------------------------------------

def test_active_mode_get_and_put(gateway, tmp_path):
    payload = os.urandom(4096)
    _seed(gateway, "active-dl.bin", payload)
    ftp = _connect(gateway)
    ftp.set_pasv(False)                            # forces PORT (IPv4) / EPRT
    try:
        got = []
        ftp.retrbinary("RETR active-dl.bin", got.append)
        assert b"".join(got) == payload

        up = tmp_path / "active-up.bin"
        up.write_bytes(payload)
        with open(up, "rb") as fh:
            ftp.storbinary("STOR active-ul.bin", fh)
    finally:
        ftp.quit()
    with open(os.path.join(gateway.export, "active-ul.bin"), "rb") as fh:
        assert fh.read() == payload


# ---- security-negative: confinement holds ----------------------------------

def test_path_traversal_rejected(gateway):
    """Every namespace verb resolves through the confinement guard, so a
    traversal argument can never escape the export root."""
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm):
            ftp.sendcmd("MDTM ../../../../etc/passwd")
        with pytest.raises(ftplib.error_perm):
            ftp.sendcmd("MLST ../../../../etc/passwd")
        with pytest.raises(ftplib.error_perm):
            ftp.sendcmd("CKSM MD5 0 -1 ../../../../etc/passwd")
    finally:
        ftp.quit()


def test_active_bounce_to_third_party_rejected(gateway):
    """Security negative (FTP-bounce): an active-mode PORT to any IP other than
    the control peer is refused on a cleartext (no-DCAU-A) session.  Only a
    GSI-authenticated DCAU A leg (gsiftp↔gsiftp TPC) may target a third party."""
    ftp = _connect(gateway)
    try:
        # 10.0.0.1 is never the loopback control peer; no DCAU A here → 500.
        with pytest.raises(ftplib.error_perm) as e:
            ftp.sendcmd("PORT 10,0,0,1,200,0")
        assert e.value.args[0].startswith("500"), e.value.args[0]
    finally:
        ftp.quit()
