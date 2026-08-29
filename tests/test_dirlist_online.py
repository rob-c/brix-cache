"""kXR_dirlist kXR_online (0x01) — omit entries whose data is not online.

Feature-parity audit §1.7: stock XRootD's dirlist honours the kXR_online
option; BriX decoded the options byte but never consulted the bit, so a
listing always carried nearline/offline entries. The filter's residency
authority is the same ``brix_vfs_residency()`` decorator walk the stat/statx
handlers advertise ``kXR_offline`` through — here exercised over the pblock
``?nearline=1`` lab (absent nearline row = ONLINE, the test-side "tape robot"
demotes by inserting a row).

Coverage (the change-class trio):
  * success      — before demotion the online listing carries everything (the
                   bit is inert for online data); after demoting one file it
                   vanishes from the online listing while the plain listing
                   still carries it; directories always pass.
  * error        — dirlist-with-online of a missing directory still answers
                   kXR_error/kXR_NotFound (the filter must not swallow the
                   error path).
  * security-neg — kXR_online|kXR_dstat: the omitted entry's name appears
                   NOWHERE in the response body (no stat-line leak of a
                   filtered entry).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_dirlist_online.py -v
"""

import os
import socket
import sqlite3
import struct
import subprocess
import time
from pathlib import Path

import pytest

from settings import NGINX_BIN
from cmdscripts.pblock_live import XRDCP, XRDFS, pblock_lab_spec, pblock_worker_own

pytestmark = [pytest.mark.timeout(150), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-dirlist-online")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# wire constants (protocol/flags.h + opcodes)
kXR_login, kXR_dirlist = 3007, 3004
kXR_ok, kXR_oksofar, kXR_error = 0, 4000, 4003
kXR_online, kXR_dstat = 0x01, 0x02
kXR_NotFound = 3011


# --------------------------------------------------------------------------- #
# minimal raw-wire client (framing copied from _test_conf_dirlist_helpers.py)
# --------------------------------------------------------------------------- #

def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed mid-frame")
        buf += chunk
    return buf


def _resp(s):
    hdr = _recv_exact(s, 8)
    status = struct.unpack("!H", hdr[2:4])[0]
    dlen = struct.unpack("!I", hdr[4:8])[0]
    return status, (_recv_exact(s, dlen) if dlen else b"")


def _session(host, port):
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _ = _resp(s)
    assert status == kXR_ok, "handshake failed"
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0x7FFFFFFF, b"onl\x00\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    status, _ = _resp(s)
    assert status == kXR_ok, "anon login failed"
    return s


def _dirlist(host, port, path, options=0):
    """One kXR_dirlist round-trip. Returns (None, joined_body) on success or
    (errnum, error_body) on a kXR_error reply."""
    s = _session(host, port)
    try:
        payload = path.encode()
        filler = b"\x00" * 15 + bytes([options])
        s.sendall(struct.pack("!2sH16sI", b"\x00\x04", kXR_dirlist, filler,
                              len(payload)) + payload)
        chunks = b""
        while True:
            status, body = _resp(s)
            if status == kXR_error:
                errnum = struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None
                return errnum, body
            assert status in (kXR_ok, kXR_oksofar), f"dirlist status={status}"
            chunks += body
            if status == kXR_ok:
                return None, chunks
    finally:
        s.close()


def _names(body):
    """Plain-listing body -> set of entry names."""
    out = set()
    for token in body.replace(b"\x00", b"\n").decode("utf-8", "replace").split("\n"):
        token = token.strip()
        if token:
            out.add(token)
    return out


# --------------------------------------------------------------------------- #
# fixture — pblock ?nearline=1 lab with one dir + two files, one demoted
# --------------------------------------------------------------------------- #

def _demote(catalog: Path, path: str, res: int) -> None:
    """Mark `path` nearline(1)/offline(2) — the test-side tape robot."""
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS nearline("
                     "  path TEXT PRIMARY KEY, res INTEGER NOT NULL);")
        conn.execute("INSERT INTO nearline VALUES(?, ?)"
                     " ON CONFLICT(path) DO UPDATE SET res = excluded.res;",
                     (path, res))
        conn.commit()
    finally:
        conn.close()
    pblock_worker_own(catalog)


def _reset_residency(catalog: Path) -> None:
    """Drop every demotion so each test starts all-ONLINE — the pblock data
    root persists across the per-test server starts."""
    if not catalog.exists():
        return
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS nearline("
                     "  path TEXT PRIMARY KEY, res INTEGER NOT NULL);")
        conn.execute("DELETE FROM nearline;")
        conn.commit()
    finally:
        conn.close()
    pblock_worker_own(catalog)


def _seed_lab_tree(hub, src):
    """Upload on.bin/off.bin and mkdir /sub into the lab export."""
    for name in ("on.bin", "off.bin"):
        proc = subprocess.run([str(XRDCP), "-f", str(src), f"{hub}{name}"],
                              capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, f"upload {name}: {proc.stderr}"
    proc = subprocess.run([str(XRDFS), hub.rstrip("/"), "mkdir", "/sub"],
                          capture_output=True, text=True, timeout=60)
    assert any((proc.returncode == 0, "ItExists" in proc.stderr)), \
        f"mkdir /sub: {proc.stderr}"


@pytest.fixture()
def lab(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not XRDCP.exists() or not XRDFS.exists():
        pytest.skip("client binaries (xrdcp/xrdfs) not built")

    ep = lifecycle.start(pblock_lab_spec("lc-dirlist-online", "?nearline=1"))
    time.sleep(1)
    hub = f"root://{ep.host}:{ep.port}/"

    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(4096))
    _seed_lab_tree(hub, src)

    catalog = Path(ep.data_root) / "catalog.db"
    _reset_residency(catalog)
    return {"host": ep.host, "port": ep.port, "catalog": catalog}


# --------------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------------- #

def test_online_bit_inert_while_everything_online(lab):
    """(success) With no demoted entries the kXR_online listing equals the
    plain listing — the filter never drops online data or directories."""
    err, plain = _dirlist(lab["host"], lab["port"], "/", options=0)
    assert err is None, f"plain dirlist failed: {err}"
    err, online = _dirlist(lab["host"], lab["port"], "/", options=kXR_online)
    assert err is None, f"online dirlist failed: {err}"
    assert {"on.bin", "off.bin", "sub"} <= _names(plain)
    assert _names(online) == _names(plain)


def test_online_omits_demoted_entry(lab):
    """(success) A NEARLINE-demoted file vanishes from the kXR_online listing;
    the plain listing still carries it; the directory always passes."""
    _demote(lab["catalog"], "/off.bin", 1)

    err, plain = _dirlist(lab["host"], lab["port"], "/", options=0)
    assert err is None
    assert {"on.bin", "off.bin", "sub"} <= _names(plain), \
        f"plain listing lost entries: {_names(plain)}"

    err, online = _dirlist(lab["host"], lab["port"], "/", options=kXR_online)
    assert err is None
    got = _names(online)
    assert "off.bin" not in got, f"demoted entry leaked into online listing: {got}"
    assert {"on.bin", "sub"} <= got, f"online entries were wrongly dropped: {got}"


def test_online_missing_dir_still_notfound(lab):
    """(error) The filter must not swallow the error path: dirlist-with-online
    of a nonexistent directory answers kXR_error/kXR_NotFound."""
    err, _body = _dirlist(lab["host"], lab["port"], "/no-such-dir",
                          options=kXR_online)
    assert err == kXR_NotFound, f"expected kXR_NotFound(3011), got {err}"


def test_online_dstat_no_stat_line_leak(lab):
    """(security-neg) kXR_online|kXR_dstat: the omitted entry's name must not
    appear anywhere in the response — a filter that only suppressed the name
    line but leaked the stat line would still disclose the entry."""
    _demote(lab["catalog"], "/off.bin", 1)
    err, body = _dirlist(lab["host"], lab["port"], "/",
                         options=kXR_online | kXR_dstat)
    assert err is None
    assert b"off.bin" not in body, "filtered entry leaked into dstat body"
    assert b"on.bin" in body, "online entry missing from dstat body"
