"""A scriptable XRootD origin that can (or cannot, or will not) page-read.

Support module for test_phase115_pgread_verify.py (phase-115 W4.3).  The unit
under test is src/fs/cache/origin_pgread.c — the kXR_pgread client the xroot
storage driver uses when a store line carries `verify_pages` — and the only way
to drive its refusal paths is an origin that misbehaves on purpose.  The stock
`xrootd` server cannot be made to send a page with a wrong CRC, a frame for an
offset nobody asked for, or an endless train of empty partial frames; this stub
can, and it needs no external binary, so the suite is hermetic.

It speaks exactly the frames the origin client sends: the 20-byte handshake,
kXR_protocol (this is where kXR_suppgrw is advertised, or withheld),
anonymous kXR_login, kXR_open with the kXR_retstat stat string, kXR_stat,
kXR_read, kXR_pgread, kXR_close.  Everything else is answered kXR_Unsupported.
"""
import socket
import struct
import threading

from ephemeral_port import free_port
from settings import HOST

# ---- opcodes / flags (src/protocols/root/protocol/{opcodes,flags}.h) --------
kXR_query = 3001
kXR_close = 3003
kXR_protocol = 3006
kXR_login = 3007
kXR_open = 3010
kXR_read = 3013
kXR_stat = 3017
kXR_pgread = 3030
kXR_1stRequest = 3000

kXR_ok = 0
kXR_error = 4003
kXR_status = 4007

kXR_Unsupported = 3013
kXR_InvalidRequest = 3006

kXR_suppgrw = 0x00200000
kXR_pgPageSZ = 4096

kXR_FinalResult = 0
kXR_PartialResult = 1

_CRC32C_POLY = 0x82F63B78
_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ _CRC32C_POLY if _c & 1 else _c >> 1
    _TABLE.append(_c)


def crc32c(data: bytes) -> int:
    """CRC32c (Castagnoli) — the per-page checksum kXR_pgread carries."""
    crc = 0xFFFFFFFF
    for b in data:
        crc = _TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def pack_pages(data: bytes, file_offset: int, corrupt_page: int = -1) -> bytes:
    """Page units for `data`: [CRC32c big-endian 4][data <= 4096], aligned to
    the FILE offset — the first unit is short when file_offset is not page
    aligned, exactly as the wire spec requires.  `corrupt_page` flips one
    unit's checksum, which is the only way to test that the reader checks."""
    out = bytearray()
    pos = 0
    idx = 0
    off = file_offset
    while pos < len(data):
        take = kXR_pgPageSZ - (off % kXR_pgPageSZ)
        chunk = data[pos:pos + take]
        crc = crc32c(chunk)
        if idx == corrupt_page:
            crc ^= 0xDEADBEEF
        out += struct.pack("!I", crc & 0xFFFFFFFF) + chunk
        pos += len(chunk)
        off += len(chunk)
        idx += 1
    return bytes(out)


def pgread_status_frame(sid: bytes, file_offset: int, pgdlen: int,
                        resptype: int = kXR_FinalResult) -> bytes:
    """The 32-byte kXR_status header for a pgread reply.

    hdr.dlen is 24 and does NOT count the page bytes; bdy.dlen does.  The body
    CRC covers streamID..offset (20 bytes).  Mirrors
    brix_build_pgread_status_sid (src/protocols/root/response/status.c)."""
    body = (sid
            + bytes([kXR_pgread - kXR_1stRequest, resptype])
            + b"\x00" * 4
            + struct.pack("!I", pgdlen)
            + struct.pack("!q", file_offset))
    hdr = sid + struct.pack("!HI", kXR_status, 24)
    return hdr + struct.pack("!I", crc32c(body)) + body


def error_frame(sid: bytes, errnum: int, msg: bytes) -> bytes:
    body = struct.pack("!I", errnum) + msg + b"\x00"
    return sid + struct.pack("!HI", kXR_error, len(body)) + body


def ok_frame(sid: bytes, body: bytes = b"") -> bytes:
    return sid + struct.pack("!HI", kXR_ok, len(body)) + body


class PgOrigin:
    """A root:// origin under test control.

    behaviour:
      ``ok``            correct pages (the success leg)
      ``corrupt``       one page's CRC32c is wrong — the bytes are otherwise
                        perfect, so ONLY a per-page check can catch it
      ``refuse``        advertises kXR_suppgrw, then answers kXR_pgread with
                        kXR_Unsupported (a mixed-vintage federation, or an
                        origin whose export disabled paged reads)
      ``bad_offset``    a well-formed frame carrying pages for an offset the
                        client never asked for (a write-anywhere primitive if
                        the client trusted it)
      ``empty_partial`` an endless train of PARTIAL frames with no pages (a
                        worker-thread wedge if the client kept reading)

    ``advertise`` withholds kXR_suppgrw when False — a pre-5.x origin.
    """

    def __init__(self, payload: bytes, behaviour: str = "ok",
                 advertise: bool = True, corrupt_page: int = 0):
        self.payload = payload
        self.behaviour = behaviour
        self.advertise = advertise
        self.corrupt_page = corrupt_page
        self.pgreads = 0
        self.reads = 0
        self._lock = threading.Lock()
        self._closing = False
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # A leased mock-range port, never a kernel-assigned one: port 0 puts
        # the listener outside the test-port ledger, where it can land on a
        # managed service's port whenever the lane overlaps the host ephemeral
        # range.  Guarded by test_fleet_port_uniqueness.
        self.port = free_port(HOST)
        self._srv.bind((HOST, self.port))
        self._srv.listen(16)
        self._srv.settimeout(0.2)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    # -- lifecycle ----------------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def close(self):
        self._closing = True
        try:
            self._srv.close()
        except OSError:
            pass
        self._thread.join(timeout=2)

    def counts(self):
        with self._lock:
            return self.pgreads, self.reads

    # -- wire ---------------------------------------------------------------
    def _accept_loop(self):
        while not self._closing:
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()

    @staticmethod
    def _exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed")
            buf += chunk
        return buf

    def _flags(self):
        return kXR_suppgrw if self.advertise else 0

    def _stat_string(self):
        return b"0 %d 0 0" % len(self.payload)

    def _pgread(self, conn, sid, hdr):
        with self._lock:
            self.pgreads += 1
        offset, rlen = struct.unpack("!qi", hdr[8:20])
        if self.behaviour == "refuse":
            conn.sendall(error_frame(sid, kXR_Unsupported,
                                     b"pgread not supported here"))
            return
        if self.behaviour == "empty_partial":
            # Never terminates on its own: a client that keeps reading hangs.
            while not self._closing:
                conn.sendall(pgread_status_frame(sid, offset, 0,
                                                 kXR_PartialResult))
            return

        data = self.payload[offset:offset + max(rlen, 0)]
        corrupt = self.corrupt_page if self.behaviour == "corrupt" else -1
        pages = pack_pages(data, offset, corrupt)
        claimed = offset + kXR_pgPageSZ if self.behaviour == "bad_offset" \
            else offset
        conn.sendall(pgread_status_frame(sid, claimed, len(pages)))
        conn.sendall(pages)

    def _read(self, conn, sid, hdr):
        with self._lock:
            self.reads += 1
        offset, rlen = struct.unpack("!qi", hdr[8:20])
        conn.sendall(ok_frame(sid, self.payload[offset:offset + max(rlen, 0)]))

    def _dispatch(self, conn, sid, reqid, hdr):
        if reqid == kXR_protocol:
            conn.sendall(ok_frame(sid, struct.pack("!II", 0x00000310,
                                                   self._flags())))
        elif reqid == kXR_login:
            conn.sendall(ok_frame(sid, b"\x00" * 16))
        elif reqid == kXR_open:
            conn.sendall(ok_frame(sid, struct.pack("!I", 7) + b"\x00" * 8
                                  + self._stat_string()))
        elif reqid == kXR_stat:
            conn.sendall(ok_frame(sid, self._stat_string() + b"\x00"))
        elif reqid == kXR_read:
            self._read(conn, sid, hdr)
        elif reqid == kXR_pgread:
            self._pgread(conn, sid, hdr)
        elif reqid == kXR_close:
            conn.sendall(ok_frame(sid))
        else:
            conn.sendall(error_frame(sid, kXR_Unsupported, b"no"))

    def _serve(self, conn):
        conn.settimeout(15)
        try:
            self._exact(conn, 20)                       # ClientInitHandShake
            conn.sendall(struct.pack("!HHI", 0, 0, 8)
                         + struct.pack("!II", 0x00000310, 1))
            while not self._closing:
                hdr = self._exact(conn, 24)
                sid = hdr[:2]
                reqid = struct.unpack("!H", hdr[2:4])[0]
                dlen = struct.unpack("!I", hdr[20:24])[0]
                if dlen:
                    self._exact(conn, dlen)
                self._dispatch(conn, sid, reqid, hdr)
        except (OSError, ConnectionError, struct.error):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass
