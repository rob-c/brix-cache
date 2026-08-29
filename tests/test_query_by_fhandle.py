"""Query-by-fhandle semantics (parity-audit §1.15) — differential vs stock.

kXR_query carries an fhandle field; with an empty payload the request refers
to an open file.  Live-verified against stock 5.6.9 (2026-08-10):

  * stock NEVER serves Qcksum/Qxattr purely by fhandle — a valid open handle
    with no path payload is kXR_ArgMissing ("Required query argument not
    present"), so BriX's genuine by-fhandle Qcksum (same digest as by-path)
    is a documented SUPERSET;
  * an fhandle that is NOT an open file of this session is kXR_FileNotOpen
    on both servers (message text differs; clients parse the code).

This suite pins the BriX behavior and, when the fleet's stock reference
server is up, the stock half of the differential too.

  * success   — by-fhandle Qcksum returns the same digest as by-path (BriX);
                stock refuses the same request with kXR_ArgMissing
  * error     — non-open fhandle: kXR_FileNotOpen on BOTH servers
  * security  — a foreign session's fhandle value serves NOTHING here: the
                handle table is per-session, so the same bytes in a fresh
                session are simply "not open" (no cross-session data leak)

Run:
    PYTHONPATH=tests pytest tests/test_query_by_fhandle.py -v
"""

import os
import socket
import struct

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, REF_BRIX_PORT, SERVER_HOST
from _test_conf_pgio_helpers import (
    _handshake, _login, _open, _read_response, kXR_ok, kXR_error,
)

kXR_query = 3001
kXR_Qcksum = 3
kXR_Qxattr = 4
kXR_ArgMissing = 3001
kXR_FileNotOpen = 3004

NAME = "qfh-parity.bin"
PAYLOAD = b"query-by-fhandle parity probe\n"

# xdist_group: this module stages its fixture data under the SHARED
# DATA_ROOT in a module-scoped fixture.  Ungrouped cells spread across
# workers under --dist loadgroup, so each worker runs its own copy of
# that fixture and the first teardown deletes the file out from under
# the workers still using it ("NotFound").  One group == one worker.
pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(60),
              pytest.mark.xdist_group("query-by-fhandle")]


@pytest.fixture(scope="module", autouse=True)
def staged():
    os.makedirs(DATA_ROOT, exist_ok=True)
    with open(os.path.join(DATA_ROOT, NAME), "wb") as f:
        f.write(PAYLOAD)
    yield
    try:
        os.remove(os.path.join(DATA_ROOT, NAME))
    except FileNotFoundError:
        pass


def _session(port):
    sock = _handshake(SERVER_HOST, port)
    _login(sock)
    return sock


def _query(sock, infotype, fhandle=b"\x00\x00\x00\x00", payload=b""):
    """kXR_query body: infotype[2] reserved[2] fhandle[4] reserved[8]."""
    req = struct.pack("!2sHH2s4s8sI", b"\x00\x09", kXR_query, infotype,
                      b"\x00\x00", fhandle, b"\x00" * 8, len(payload))
    sock.sendall(req + payload)
    _sid, status, body = _read_response(sock)
    if status == kXR_error:
        (code,) = struct.unpack("!i", body[:4])
        return ("error", code)
    return ("ok", body.rstrip(b"\x00"))


def _stock_up():
    try:
        s = socket.create_connection((SERVER_HOST, REF_BRIX_PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False


class TestQueryByFhandle:

    def test_brix_qcksum_by_fhandle_matches_path(self):
        """(success) BriX serves a by-fhandle Qcksum with the SAME digest the
        by-path form computes — the documented superset over stock."""
        sock = _session(NGINX_ANON_PORT)
        try:
            _sid, st, body = _open(sock, "/" + NAME)
            assert st == kXR_ok, f"open failed: {st}"
            fh = body[:4]
            by_fh = _query(sock, kXR_Qcksum, fhandle=fh)
            by_path = _query(_session(NGINX_ANON_PORT), kXR_Qcksum,
                             payload=("/" + NAME).encode() + b"\x00")
            assert by_fh[0] == "ok", by_fh
            assert by_fh == by_path, (by_fh, by_path)
            assert by_fh[1].startswith(b"adler32 "), by_fh
        finally:
            sock.close()

    @pytest.mark.skipif(not _stock_up(), reason="stock reference not up")
    def test_stock_refuses_pure_fhandle_query(self):
        """(differential) stock answers the SAME request with kXR_ArgMissing —
        recorded so the superset claim stays live-verified, not folklore."""
        sock = _session(REF_BRIX_PORT)
        try:
            _sid, st, body = _open(sock, "/" + NAME)
            assert st == kXR_ok, f"stock open failed: {st}"
            assert _query(sock, kXR_Qcksum, fhandle=body[:4]) == \
                ("error", kXR_ArgMissing)
            assert _query(sock, kXR_Qxattr, fhandle=body[:4]) == \
                ("error", kXR_ArgMissing)
        finally:
            sock.close()

    def test_nonopen_fhandle_is_file_not_open(self):
        """(error) an empty-payload query whose fhandle is not an open file of
        this session is kXR_FileNotOpen — the stock code, live-verified."""
        verdict = _query(_session(NGINX_ANON_PORT), kXR_Qcksum)
        assert verdict == ("error", kXR_FileNotOpen), verdict
        if _stock_up():
            verdict = _query(_session(REF_BRIX_PORT), kXR_Qcksum)
            assert verdict == ("error", kXR_FileNotOpen), verdict

    def test_foreign_session_fhandle_serves_nothing(self):
        """(security-neg) an fhandle minted in session A is meaningless in
        session B: handle tables are per-session, so B gets kXR_FileNotOpen —
        never A's data."""
        a = _session(NGINX_ANON_PORT)
        try:
            _sid, st, body = _open(a, "/" + NAME)
            assert st == kXR_ok
            stolen = body[:4]
            verdict = _query(_session(NGINX_ANON_PORT), kXR_Qcksum,
                             fhandle=stolen)
            assert verdict == ("error", kXR_FileNotOpen), (
                f"foreign fhandle was served: {verdict}")
        finally:
            a.close()
