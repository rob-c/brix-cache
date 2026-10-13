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
import time

from ephemeral_port import bind_port
from settings import HOST

# ---- opcodes / flags (src/protocols/root/protocol/{opcodes,flags}.h) --------
kXR_query = 3001
kXR_chmod = 3002
kXR_close = 3003
kXR_gpfile = 3005
kXR_protocol = 3006
kXR_login = 3007
kXR_mkdir = 3008
kXR_mv = 3009
kXR_auth = 3000
kXR_ping = 3011
kXR_open = 3010
kXR_read = 3013
kXR_rm = 3014
kXR_rmdir = 3015
kXR_stat = 3017
kXR_write = 3019
kXR_fattr = 3020
kXR_prepare = 3021
kXR_bind = 3024
kXR_readv = 3025
kXR_pgwrite = 3026
kXR_locate = 3027
kXR_truncate = 3028
kXR_dirlist = 3004
kXR_sync = 3016
kXR_writev = 3031
kXR_chkpoint = 3012
kXR_pgread = 3030
kXR_1stRequest = 3000

kXR_ok = 0
kXR_oksofar = 4000
kXR_attn = 4001
kXR_error = 4003
kXR_redirect = 4004
kXR_wait = 4005
kXR_waitresp = 4006
kXR_status = 4007

kXR_asyncms = 5002
kXR_asynresp = 5008

kXR_Unsupported = 3013
kXR_InvalidRequest = 3006
kXR_NotAuthorized = 3010
kXR_NotFound = 3011
kXR_ServerError = 3012
kXR_ArgMissing = 3005
kXR_IOError = 3007
kXR_isDirectory = 3016
kXR_fsReadOnly = 3025

kXR_suppgrw = 0x00200000
kXR_isServer = 0x00000001
kXR_isManager = 0x00000002
kXR_attrSuper = 0x00000400
kXR_supgpf = 0x00400000
kXR_anongpf = 0x00800000
kXR_tlsData = 0x01000000
kXR_gotoTLS = 0x40000000
kXR_haveTLS = 0x80000000
kXR_secreqs = 0x01
kXR_bifreqs = 0x08
kXR_ExpTPC = 0x04
kXR_ExpMask = 0x0f
kXR_pgPageSZ = 4096

kXR_FinalResult = 0
kXR_PartialResult = 1
kXR_ArgInvalid = 3000

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
                        resptype: int = kXR_FinalResult,
                        body_sid: bytes = None, requestid: int = None,
                        reserved: bytes = b"\x00" * 4) -> bytes:
    """The 32-byte kXR_status header for a pgread reply.

    hdr.dlen is 24 and does NOT count the page bytes; bdy.dlen does.  The body
    CRC covers streamID..offset (20 bytes).  Mirrors
    brix_build_pgread_status_sid (src/protocols/root/response/status.c)."""
    body = ((sid if body_sid is None else body_sid)
            + bytes([kXR_pgread - kXR_1stRequest if requestid is None
                     else requestid, resptype])
            + reserved
            + struct.pack("!I", pgdlen)
            + struct.pack("!q", file_offset))
    hdr = sid + struct.pack("!HI", kXR_status, 24)
    return hdr + struct.pack("!I", crc32c(body)) + body


def error_frame(sid: bytes, errnum: int, msg: bytes) -> bytes:
    body = struct.pack("!I", errnum) + msg + b"\x00"
    return sid + struct.pack("!HI", kXR_error, len(body)) + body


def ok_frame(sid: bytes, body: bytes = b"") -> bytes:
    return sid + struct.pack("!HI", kXR_ok, len(body)) + body


from split_continuation import load as _load_continuations

_load_continuations(
    globals(), __file__,
    "_phase115_pgread_read_mixin.py",
    "_phase115_pgread_dispatch_mixin.py",
    "_phase115_pgread_connection_mixin.py",
)


def _root_listener(port):
    listener = socket.socket()
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, port))
        listener.listen(16)
        listener.settimeout(0.2)
        return listener
    except OSError:
        listener.close()
        raise


class PgOrigin(PgOriginReadMixin, PgOriginDispatchMixin,
               PgOriginConnectionMixin):
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
      ``bad_body_sid`` / ``bad_requestid`` / ``bad_reserved`` /
      ``bad_resptype``  structurally invalid kXR_status bodies with a valid CRC
      ``bad_status_crc`` a structurally valid status body with a corrupt CRC
      ``empty_partial`` an endless train of PARTIAL frames with no pages (a
                        worker-thread wedge if the client kept reading)
      ``redirect``      first stat redirects to ``redirect_port``
      ``redirect_always`` every stat redirects to ``redirect_port``
      ``bad_redirect``  first stat carries an empty, zero-port redirect
      ``empty_manager`` a manager with no data servers returns a defined error
      ``bad_empty_manager`` such a manager returns an empty redirect
      ``wait_once``     first stat asks for an immediate retry
      ``wait_repeat``   first two stats return the same wait response
      ``bad_wait``      load shedding returns an implausible delay
      ``waitresp``      first stat is completed by attn(asynresp)
      ``bad_waitresp_sid`` as above, but the inner stream ID is forged
      ``asyncms``       first stat is preceded by a valid async message
      ``bad_asyncms``   first stat is preceded by unterminated message text
      ``readonly``      every open is refused with kXR_fsReadOnly
      ``readonly_auth`` every open is incorrectly refused as NotAuthorized

    ``advertise`` withholds kXR_suppgrw when False — a pre-5.x origin.
    """

    def __init__(self, payload: bytes, behaviour: str = "ok",
                 advertise: bool = True, corrupt_page: int = 0,
                 redirect_port: int = None):
        self.payload = payload
        self.behaviour = behaviour
        self.advertise = advertise
        self.corrupt_page = corrupt_page
        self.redirect_port = redirect_port
        self.pgreads = 0
        self.reads = 0
        self.stats = 0
        self.protocol_calls = 0
        self.connections = 0
        self.moves = 0
        self.chmods = 0
        self.cancels = 0
        self.bound_connections = {}
        self.next_pathid = 1
        self._connection_context = threading.local()
        self._lock = threading.Lock()
        self._closing = False
        self.port, self._srv = bind_port(_root_listener, HOST)
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
        if self.behaviour in ("empty_manager", "bad_empty_manager",
                              "claim_bad_manager"):
            return kXR_isManager
        flags = kXR_isServer | (kXR_suppgrw if self.advertise else 0)
        additions = {
            "claim_supgpf_broken": kXR_supgpf,
            "claim_anongpf_broken": kXR_anongpf,
            "claim_tls_broken": kXR_haveTLS,
            "claim_gototls_broken": kXR_haveTLS | kXR_gotoTLS,
            "protocol_bad_role": kXR_isManager,
            "protocol_tls_without_capability": kXR_tlsData,
            "claim_bad_super": kXR_attrSuper,
            "claim_unknown_bit": 0x00000004,
        }
        return flags | additions.get(self.behaviour, 0)

    def _protocol_body(self, hdr):
        body = struct.pack(
            "!II", self._protocol_version(), self._protocol_flags(hdr),
        )
        if self.behaviour == "protocol_bad_bif" and hdr[8] & kXR_bifreqs:
            return body + b"B"
        if not (hdr[8] & kXR_secreqs):
            return body
        return body + self._protocol_trailer()

    def _protocol_version(self):
        return (0x00000300 if self.behaviour == "claim_old_version"
                else 0x00000310)

    def _protocol_flags(self, hdr):
        flags = self._flags()
        if self._protocol_flags_change(hdr):
            flags ^= kXR_suppgrw
        if self._protocol_tpc_flags_change(hdr):
            flags ^= kXR_suppgrw
        return flags

    def _protocol_flags_change(self, hdr):
        return (self.behaviour == "protocol_changes"
                and self.protocol_calls > 1 and hdr[8] & kXR_secreqs)

    def _protocol_tpc_flags_change(self, hdr):
        return (self.behaviour == "protocol_tpc_changes"
                and hdr[9] == kXR_ExpTPC)

    def _protocol_trailer(self):
        trailers = {
            "protocol_missing_sec": b"",
            "protocol_bad_seclvl": b"S\x00\x00\x00\x05\x00",
            "protocol_bad_secvec": b"S\x00\x00\x00\x00\x01",
            "protocol_bad_secreq": b"S\x00\x00\x00\x00\x01\x00\x03",
        }
        return trailers.get(
            self.behaviour, b"S\x00\x00\x00\x00\x00",
        )

    def _stat_string(self, request_body=b"", stat_sequence=0):
        hostile_stat = stat_sequence > 1
        if self.behaviour == "stat_malformed" and hostile_stat:
            return b"malformed"
        size, flags = self._stat_values(request_body, hostile_stat)
        line = b"0 %d %d 0" % (size, flags)
        if self.behaviour in ("open_bad_mode", "mkdir_bad_mode"):
            return line + b" 0 0 65535 owner group"
        return line

    def _stat_values(self, request_body, hostile_stat):
        size = len(self.payload)
        size += int(self._wrong_stat_size(hostile_stat))
        size += int(self._handle_stat_mismatch(request_body))
        return size, self._stat_flags(hostile_stat)

    def _wrong_stat_size(self, hostile_stat):
        return self.behaviour == "stat_wrong_size" and hostile_stat

    def _handle_stat_mismatch(self, request_body):
        return self.behaviour == "stat_handle_mismatch" and request_body == b""

    def _stat_flags(self, hostile_stat):
        if self.behaviour == "stat_writable":
            return 32
        hostile_flags = {
            "stat_bad_flags": 2,
            "stat_offline": 8,
        }.get(self.behaviour, 0)
        return hostile_flags if hostile_stat else 0

    def _open_frame(self, sid):
        """Return an ordinary open reply or the selected read-only refusal."""
        errors = {
            "readonly": kXR_fsReadOnly,
            "readonly_auth": kXR_NotAuthorized,
        }
        error = errors.get(self.behaviour)
        if error is not None:
            return error_frame(sid, error, b"read only")
        return ok_frame(sid, struct.pack("!I", 7) + b"\x00" * 8
                        + self._stat_string(b"open"))


    def _flow_stat(self, conn, sid):
        sequence = getattr(self._connection_context, "flow_stats", 0)
        self._connection_context.flow_stats = sequence + 1
        if not self._flow_active(sequence):
            return False
        handlers = {
            "redirect": self._flow_redirect,
            "redirect_always": self._flow_redirect,
            "redirect_opaque": self._flow_redirect,
            "bad_redirect": self._flow_bad_redirect,
            "empty_manager": self._flow_empty_manager,
            "bad_empty_manager": self._flow_bad_redirect,
            "wait_once": self._flow_wait,
            "wait_repeat": self._flow_wait,
            "bad_wait": self._flow_bad_wait,
            "waitresp": self._flow_waitresp,
            "bad_waitresp_sid": self._flow_waitresp,
            "asyncms": self._flow_asyncms,
            "bad_asyncms": self._flow_asyncms,
        }
        handler = handlers.get(self.behaviour)
        if handler is None:
            return False
        handler(conn, sid)
        return True

    def _flow_active(self, sequence):
        always = self.behaviour == "redirect_always"
        repeated_wait = self.behaviour == "wait_repeat" and sequence == 1
        return always or sequence == 0 or repeated_wait

    def _flow_redirect(self, conn, sid):
        port = self.redirect_port if self.redirect_port is not None else self.port
        opaque = b"?cap=controlled" \
            if self.behaviour == "redirect_opaque" else b""
        body = struct.pack("!I", port) + HOST.encode() + opaque + b"\x00"
        conn.sendall(sid + struct.pack("!HI", kXR_redirect, len(body)) + body)

    @staticmethod
    def _flow_bad_redirect(conn, sid):
        body = struct.pack("!I", 0) + b"\x00"
        conn.sendall(sid + struct.pack("!HI", kXR_redirect, len(body)) + body)

    @staticmethod
    def _flow_empty_manager(conn, sid):
        conn.sendall(error_frame(sid, 3005, b"no eligible data server"))

    @staticmethod
    def _flow_wait(conn, sid):
        body = struct.pack("!I", 0)
        conn.sendall(sid + struct.pack("!HI", kXR_wait, len(body)) + body)

    @staticmethod
    def _flow_bad_wait(conn, sid):
        body = struct.pack("!I", 3601)
        conn.sendall(sid + struct.pack("!HI", kXR_wait, len(body)) + body)

    def _flow_waitresp(self, conn, sid):
        stat = self._stat_string() + b"\x00"
        inner_sid = sid if self.behaviour == "waitresp" \
            else bytes([sid[0] ^ 1, sid[1]])
        inner = inner_sid + struct.pack("!HI", kXR_ok, len(stat)) + stat
        pushed = struct.pack("!II", kXR_asynresp, 0) + inner
        conn.sendall(sid + struct.pack("!HI", kXR_waitresp, 4)
                     + struct.pack("!I", 0))
        conn.sendall(sid + struct.pack("!HI", kXR_attn, len(pushed)) + pushed)

    def _flow_asyncms(self, conn, sid):
        text = b"controlled message\x00" if self.behaviour == "asyncms" \
            else b"unterminated message"
        inner = b"\x00\x00" + struct.pack("!HI", kXR_ok, len(text))
        pushed = struct.pack("!II", kXR_asyncms, 0) + inner + text
        conn.sendall(b"\x00\x00" + struct.pack(
            "!HI", kXR_attn, len(pushed)) + pushed)
        conn.sendall(ok_frame(sid, self._stat_string() + b"\x00"))

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        self._consume_writev_payload(conn, reqid, body)
        handlers = {
            kXR_protocol: self._dispatch_protocol,
            0: self._dispatch_second_handshake,
            kXR_login: self._dispatch_login,
            kXR_auth: self._dispatch_auth,
            kXR_query: self._dispatch_query,
            kXR_prepare: self._dispatch_prepare,
            kXR_bind: self._dispatch_bind,
            kXR_ping: self._dispatch_ping,
            kXR_fattr: self._dispatch_fattr,
            kXR_open: self._dispatch_open,
            kXR_stat: self._dispatch_stat,
            kXR_locate: self._dispatch_locate,
            kXR_dirlist: self._dispatch_dirlist,
            kXR_read: self._dispatch_read,
            kXR_readv: self._dispatch_readv,
            kXR_write: self._dispatch_write,
            kXR_writev: self._dispatch_writev,
            kXR_sync: self._dispatch_sync,
            kXR_chkpoint: self._dispatch_checkpoint,
            kXR_truncate: self._dispatch_truncate,
            kXR_pgwrite: self._dispatch_pgwrite,
            kXR_pgread: self._dispatch_pgread,
            kXR_close: self._dispatch_close,
            kXR_mkdir: self._dispatch_mkdir,
            kXR_mv: self._dispatch_move,
            kXR_rm: self._dispatch_remove,
            kXR_rmdir: self._dispatch_rmdir,
            kXR_chmod: self._dispatch_chmod,
            kXR_gpfile: self._dispatch_gpfile,
        }
        handler = handlers.get(reqid, self._dispatch_unsupported)
        handler(conn, sid, hdr, body, authenticated)
        return authenticated or reqid == kXR_login
