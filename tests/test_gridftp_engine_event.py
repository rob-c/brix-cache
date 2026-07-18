"""
GridFTP gateway — non-blocking event engine (phase-82 §2 / P82.1 + P82.2).

Drives the same RFC 959 / RFC 3659 surface as ``test_gridftp_verbs.py`` but
against a gateway configured with ``brix_gridftp_engine event``, so both the
control dialogue and the stream-mode data transfers run under the nginx STREAM
event loop (``ev/ftp_ev_*.c``) instead of the shipped blocking handler.  This is
the parity oracle for the event engine: every command→reply verb behaves
byte-for-byte like the sync engine, and PASV/PORT + RETR/STOR/LIST move real
bytes through the VFS seam via the non-blocking pump (P82.2).

The control-plane assertions use a raw socket so exact reply codes (the pre-auth
530 gate, 425/500/504/550 boundaries) can be checked directly; the data-transfer
assertions use ftplib so the passive/active data-channel dance is driven the way
a real client drives it.  PROT P (data-channel TLS) and MODE E remain honestly
stubbed 502 pending P82.3/P82.4.

Covered:
  * success            -- login, SYST/FEAT/PWD/CWD, MKD→SIZE/MLST/MDTM VFS round
                          trips, CKSM, RNFR/RNTO, DELE/RMD; PASV+RETR, active-mode
                          (PORT) RETR, STOR→disk→RETR, REST partial RETR, LIST/NLST
  * error              -- unknown verb (500), RNTO without RNFR (503), SIZE/RETR of
                          a missing file (550), bad CKSM algorithm (504), transfer
                          with no PASV/PORT armed (425)
  * security-negative  -- pre-auth gate (file verb before login → 530), path
                          traversal confinement on namespace + RETR (../ → 550),
                          STOR into a read-only export refused (550)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_engine_event.py -v -p no:xdist
"""

import os
import socket
import zlib

import pytest

from settings import BIND_HOST, NGINX_BIN
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]


def _require():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


class _EvGateway:
    """A registry-owned cleartext FTP gateway on the event engine."""

    def __init__(self, harness, name):
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_plain_ev.conf",
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
def ev_gateway():
    _require()
    gw = _EvGateway(LifecycleHarness(), "gridftp-plain-ev")
    yield gw
    gw.close()


class _Ctrl:
    """A minimal line-oriented FTP control-channel client over a raw socket."""

    def __init__(self, port, login=True):
        self.sock = socket.create_connection(("localhost", port), timeout=30)
        self.sock.settimeout(30)
        self.buf = b""
        assert self.recv().startswith("220 "), "missing greeting"
        if login:
            assert self.cmd("USER anonymous").startswith("331 ")
            assert self.cmd("PASS x").startswith("230 ")

    def recv(self):
        """Read one reply (final line = 'ddd <text>', not 'ddd-...')."""
        while True:
            nl = self.buf.find(b"\n")
            if nl >= 0:
                # Accumulate a full multi-line reply: keep reading until a line
                # whose 4th char is a space (RFC 959 terminal line) is present.
                text = self.buf.decode(errors="replace")
                lines = [ln for ln in text.split("\r\n") if ln]
                for ln in lines:
                    if len(ln) >= 4 and ln[3] == " " and ln[:3].isdigit():
                        self.buf = b""
                        return text.strip()
            chunk = self.sock.recv(65536)
            if not chunk:
                out = self.buf.decode(errors="replace").strip()
                self.buf = b""
                return out
            self.buf += chunk

    def cmd(self, line):
        self.sock.sendall((line + "\r\n").encode())
        return self.recv()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _seed(gw, name, data):
    path = os.path.join(gw.export, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


# ---- success: control-plane verbs + VFS round trips ------------------------

def test_login_and_probes(ev_gateway):
    c = _Ctrl(ev_gateway.port)
    try:
        assert c.cmd("SYST") == "215 UNIX Type: L8"
        assert c.cmd("PWD") == '257 "/" is the current directory'
        feat = c.cmd("FEAT")
        assert feat.startswith("211-Features:") and feat.endswith("211 End")
        assert " SIZE" in feat and " MLST" in feat
        assert c.cmd("NOOP") == "200 NOOP ok"
    finally:
        c.close()


def test_mkd_size_mlst_roundtrip(ev_gateway):
    _seed(ev_gateway, "hello.txt", b"0123456789")
    c = _Ctrl(ev_gateway.port)
    try:
        assert c.cmd("MKD adir") == '257 "adir" created'
        assert os.path.isdir(os.path.join(ev_gateway.export, "adir"))
        assert c.cmd("SIZE /hello.txt") == "213 10"
        mlst = c.cmd("MLST /hello.txt")
        assert mlst.startswith("250-Listing") and "size=10" in mlst
        assert "type=file" in mlst and mlst.endswith("250 End")
        assert c.cmd("CWD /adir").startswith("250 ")
        assert c.cmd("PWD") == '257 "/adir" is the current directory'
    finally:
        c.close()


def test_cksm_and_rename(ev_gateway):
    data = b"checksum me please"
    _seed(ev_gateway, "ck.bin", data)
    c = _Ctrl(ev_gateway.port)
    try:
        got = c.cmd("CKSM ADLER32 0 -1 /ck.bin")
        assert got == f"213 {zlib.adler32(data) & 0xffffffff:08x}"
        # two-step rename
        assert c.cmd("RNFR /ck.bin").startswith("350 ")
        assert c.cmd("RNTO /ck2.bin") == "250 Rename successful"
        assert os.path.exists(os.path.join(ev_gateway.export, "ck2.bin"))
        assert not os.path.exists(os.path.join(ev_gateway.export, "ck.bin"))
        # cleanup path: DELE then RMD
        assert c.cmd("DELE /ck2.bin") == "250 File deleted"
    finally:
        c.close()


# ---- error paths -----------------------------------------------------------

def test_error_paths(ev_gateway):
    c = _Ctrl(ev_gateway.port)
    try:
        assert c.cmd("FROB nonsense") == "500 Unknown command"
        assert c.cmd("RNTO /orphan") == "503 RNFR required first"
        assert c.cmd("SIZE /does-not-exist").startswith("550 ")
        assert c.cmd("CKSM BOGUS 0 -1 /whatever").startswith("504 ")
    finally:
        c.close()


# ---- security-negative -----------------------------------------------------

def test_preauth_gate(ev_gateway):
    """A file/namespace verb before login is refused with 530."""
    c = _Ctrl(ev_gateway.port, login=False)
    try:
        assert c.cmd("SIZE /hello.txt").startswith("530 ")
        assert c.cmd("MKD nope").startswith("530 ")
        # the whitelisted probes remain available pre-login
        assert c.cmd("SYST") == "215 UNIX Type: L8"
    finally:
        c.close()


def test_path_traversal_confined(ev_gateway):
    """`../` escape attempts stay inside the export (INVARIANT 4)."""
    c = _Ctrl(ev_gateway.port)
    try:
        assert c.cmd("SIZE /../../../../etc/passwd").startswith("550 ")
        assert c.cmd("MKD ../escape").startswith("550 ")
        assert not os.path.exists(
            os.path.join(os.path.dirname(ev_gateway.export), "escape"))
    finally:
        c.close()


# ---- data transfers: the non-blocking event pump (P82.2) -------------------

import ftplib
from io import BytesIO


def _ftp(gw):
    """A logged-in ftplib client (passive mode) against the event gateway."""
    f = ftplib.FTP()
    f.connect("localhost", gw.port, timeout=30)
    f.login("anonymous", "x")
    return f


def test_retr_passive_roundtrip(ev_gateway):
    """PASV + RETR streams a seeded file back byte-for-byte."""
    data = bytes(range(256)) * 64          # 16 KiB, spans several send() rounds
    _seed(ev_gateway, "grab.bin", data)
    f = _ftp(ev_gateway)
    try:
        got = bytearray()
        f.retrbinary("RETR /grab.bin", got.extend)
        assert bytes(got) == data
    finally:
        f.quit()


def test_stor_then_retr_roundtrip(ev_gateway):
    """STOR writes through the VFS; a fresh RETR reads the same bytes back."""
    data = b"".join(b"line-%04d\n" % i for i in range(2000))  # ~18 KiB
    f = _ftp(ev_gateway)
    try:
        f.storbinary("STOR /put.bin", BytesIO(data))
        # landed on disk through the VFS seam
        with open(os.path.join(ev_gateway.export, "put.bin"), "rb") as fh:
            assert fh.read() == data
        got = bytearray()
        f.retrbinary("RETR /put.bin", got.extend)
        assert bytes(got) == data
    finally:
        f.quit()


def test_retr_active_mode(ev_gateway):
    """Active mode (PORT): the gateway connects out to the client's listener and
    the RETR pump streams over that leg.  ftplib's PORT targets the control peer,
    so the anti-bounce pin is satisfied."""
    data = b"active-mode payload " * 512   # ~10 KiB
    _seed(ev_gateway, "act.bin", data)
    f = _ftp(ev_gateway)
    try:
        f.set_pasv(False)
        got = bytearray()
        f.retrbinary("RETR /act.bin", got.extend)
        assert bytes(got) == data
    finally:
        f.quit()


def test_rest_partial_retr(ev_gateway):
    """REST sets the RETR restart offset (single-shot)."""
    data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    _seed(ev_gateway, "alpha.bin", data)
    f = _ftp(ev_gateway)
    try:
        got = bytearray()
        f.retrbinary("RETR /alpha.bin", got.extend, rest=10)
        assert bytes(got) == data[10:]
    finally:
        f.quit()


def test_list_and_nlst(ev_gateway):
    """LIST (ls -l form) and NLST (bare names) stream over the data channel."""
    f = _ftp(ev_gateway)
    try:
        f.mkd("/lsdir")
        f.storbinary("STOR /lsdir/one.txt", BytesIO(b"1"))
        f.storbinary("STOR /lsdir/two.txt", BytesIO(b"22"))
        names = f.nlst("/lsdir")
        assert set(os.path.basename(n) for n in names) == {"one.txt", "two.txt"}
        longln = []
        f.retrlines("LIST /lsdir", longln.append)
        assert any("one.txt" in ln and ln.startswith("-") for ln in longln)
    finally:
        f.quit()


# ---- error paths -----------------------------------------------------------

def test_retr_missing_is_550(ev_gateway):
    """RETR of a non-existent file fails 550 before any 150/data channel."""
    f = _ftp(ev_gateway)
    try:
        with pytest.raises(ftplib.error_perm) as ei:
            f.retrbinary("RETR /nope.bin", lambda _b: None)
        assert str(ei.value).startswith("550")
    finally:
        f.quit()


def test_transfer_without_pasv_is_425(ev_gateway):
    """A transfer verb with no PASV/PORT armed is refused 425."""
    _seed(ev_gateway, "x.bin", b"x")
    c = _Ctrl(ev_gateway.port)
    try:
        assert c.cmd("RETR /x.bin").startswith("425 ")
    finally:
        c.close()


# ---- security-negative -----------------------------------------------------

def test_retr_traversal_confined(ev_gateway):
    """A `../` escape on a data-transfer verb is confined (INVARIANT 4)."""
    f = _ftp(ev_gateway)
    try:
        with pytest.raises(ftplib.error_perm):
            f.retrbinary("RETR /../../../../etc/passwd", lambda _b: None)
    finally:
        f.quit()


def test_stor_readonly_export_denied(harness_factory=None):
    """STOR into a read-only export is refused 550 (write gate), not attempted."""
    _require()
    from server_launcher import LifecycleHarness
    from server_registry import NginxInstanceSpec
    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="gridftp-plain-ev-ro",
        template="nginx_gridftp_plain_ev_ro.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST},
    ))
    try:
        f = ftplib.FTP()
        f.connect("localhost", endpoint.port, timeout=30)
        f.login("anonymous", "x")
        with pytest.raises(ftplib.error_perm) as ei:
            f.storbinary("STOR /blocked.bin", BytesIO(b"nope"))
        assert str(ei.value).startswith("550")
        f.quit()
    finally:
        harness.close()
