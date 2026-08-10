# Lazily populated by _crc32c() on first use; the module-level sentinel must exist
# so the `global _CRC32C_TABLE; if _CRC32C_TABLE is None` guard reads a defined name
# rather than raising NameError before the table is ever built.
_CRC32C_TABLE = None


def _is_server_sidecar(name):
    """True for a server-managed metadata sidecar — the checksum/residency carriers
    the backend creates AS THE WORKER (svc-owned 0600) *even under impersonation*,
    by explicit design (see src/fs/meta/xmeta_path.c's SECURITY note: keeping the
    integrity/cache metadata server-owned stops a mapped low-priv uid reading it on
    a shared fs).  These are NOT user data, so the "uploaded data must be owned by
    the mapped user, never svc/root" invariant does not apply to them.  The leak
    sweeps skip them or they false-positive on every upload's `.cinfo`.  Suffix set
    mirrors the product's own scrub_is_sidecar()/reap_is_sidecar() exactly."""
    for suf in (".cinfo", ".meta", ".part", ".lock"):
        if name.endswith(suf):
            return True
    return ".__xrds" in name


def _crc32c(data):
    """CRC-32C (Castagnoli, poly 0x1EDC6F41 reflected = 0x82F63B78) — the exact
    checksum the kXR_pgread/kXR_pgwrite wire path computes per 4096-byte page.
    Lazily builds the byte table so a degraded (no-auth) run never pays for it."""
    global _CRC32C_TABLE
    if _CRC32C_TABLE is None:
        _CRC32C_TABLE = _build_crc32c_table()
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC32C_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


def _build_crc32c_table():
    table = []
    for number in range(256):
        value = number
        for _ in range(8):
            value = _crc32c_table_step(value)
        table.append(value)
    return table


def _crc32c_table_step(value):
    if value & 1:
        return (value >> 1) ^ 0x82F63B78
    return value >> 1


def _kxr_auth_bytes(token, streamid=b"\x00\x03"):
    """ClientAuthRequest for the 'ztn' (XrdSecztn bearer JWT) sec-protocol:
    streamid[2] requestid[2] reserved[12] credtype[4]='ztn\\0' dlen[4], then a
    payload of 4 prefix bytes ('ztn\\0') + the raw token (the handler reads the
    token from payload+4).  This is the credential the login reply advertises via
    '&P=ztn'."""
    tok = token.encode() if isinstance(token, str) else token
    payload = b"ztn\x00" + tok
    hdr = struct.pack("!2sH12s4sI", streamid, _KXR_AUTH, b"\x00" * 12,
                      b"ztn\x00", len(payload))
    return hdr + payload


# kXR_open opcode + open-option flags (XProtocol; src/protocols/root/protocol/
# opcodes.h + flags.h).  Defined here — before _kxr_open_bytes below uses one as
# a default arg (evaluated at import time).
_KXR_OPEN      = 3010         # kXR_open opcode (ClientOpenRequest)
_KXR_NEW       = 0x0008       # kXR_new: fail with kXR_ItExists if the file exists
_KXR_OPEN_READ = 0x0010       # kXR_open_read: open for reading (O_RDONLY)
_KXR_OPEN_UPDT = 0x0020       # kXR_open_updt: open for read + write (O_RDWR)

# ---- kXR opcode / status constants (src/protocols/root/protocol/opcodes.h) ----
# The wire-builders above and the session scaffolding below reference these; they
# resolve at call time in the shared split_continuation namespace.
_KXR_OK       = 0             # kXR_ok
_KXR_ERROR    = 4003          # kXR_error   (body = errnum[4] + NUL-terminated msg)
_KXR_AUTHMORE = 4002          # kXR_authmore (login accepted, server wants kXR_auth)
_KXR_AUTH     = 3000
_KXR_CLOSE    = 3003
_KXR_DIRLIST  = 3004
_KXR_PROTOCOL = 3006
_KXR_LOGIN    = 3007
_KXR_BIND     = 3024          # bind a secondary data channel to a session
_KXR_READ     = 3013
_KXR_STAT     = 3017
_KXR_STATX    = 3022
_KXR_READV    = 3025
_KXR_PGWRITE  = 3026
_KXR_TRUNCATE = 3028
_KXR_PGREAD   = 3030
_KXR_PROTOCOLVERSION = 0x00000520   # v5.2.0
_ROOTD_PQ     = 2012          # handshake fifth word (client_hello.c)
_KXR_EXPLOGIN = 0x03          # kXR_ExpLogin — a kXR_login follows the protocol req
_KXR_VER005   = 5             # capver: XRootD v5 client


def _kxr_stat_bytes(path, streamid=b"\x00\x30", dlen=None):
    """kXR_stat: ClientStatRequest (options[1] reserved[7] wants[4] fhandle[4]
    dlen[4]) + path body — shares kXR_statx's layout.  `dlen` is overridable so a
    caller can forge a length that disagrees with the actual path body (the
    oversized/negative-dlen framing-attack probes in run_raw_kxr_wire)."""
    p = path if isinstance(path, bytes) else path.encode()
    d = len(p) if dlen is None else (dlen & 0xFFFFFFFF)
    hdr = struct.pack("!2sHB7sI4sI", streamid, _KXR_STAT, 0, b"\x00" * 7,
                      0, b"\x00" * 4, d)
    return hdr + p


def _kxr_connect(timeout=4.0):
    """Open a raw TCP connection to the impersonation stream server (the same
    127.0.0.1:_stream_port the native root:// helpers use) with `timeout` armed on
    every subsequent send/recv.  Raises on connect failure so the caller degrades."""
    s = socket.create_connection((HOST, _stream_port), timeout=timeout)
    s.settimeout(timeout)
    return s


def _kxr_handshake_bytes(fourth=4, fifth=None):
    """20-byte XRootD client hello {0,0,0,fourth,fifth}; the server validates
    fourth==4 && fifth==2012 (client_hello.c) before switching to request framing.
    `fourth`/`fifth` are overridable so a caller can forge an INVALID magic and
    prove the server rejects it."""
    return struct.pack("!5I", 0, 0, 0, fourth & 0xFFFFFFFF,
                       (_ROOTD_PQ if fifth is None else fifth) & 0xFFFFFFFF)


def _kxr_protocol_bytes(streamid=b"\x00\x01"):
    """ClientProtocolRequest (24B): clientpv(4) flags(1) expect(1) reserved(10).
    flags=0 — this bed is ztn-over-cleartext, so we advertise no TLS capability."""
    return struct.pack("!2sHiBB10sI", streamid, _KXR_PROTOCOL,
                       _KXR_PROTOCOLVERSION, 0, _KXR_EXPLOGIN, b"\x00" * 10, 0)


def _kxr_login_bytes(username="alice", pid=4242, streamid=b"\x00\x02"):
    """ClientLoginRequest (24B): pid(4) username(8, NUL-padded) ability2(1)
    ability(1) capver(1=kXR_ver005) reserved(1); dlen=0 => the credential (if any)
    follows in a separate kXR_auth."""
    u = username.encode()[:8].ljust(8, b"\x00")
    return struct.pack("!2sHi8sBBBBI", streamid, _KXR_LOGIN, pid, u,
                       0, 0, _KXR_VER005, 0, 0)


def _kxr_read_response(s):
    """Read one ServerResponseHdr (streamid[2] status[2] dlen[4]) + its dlen-byte
    body from `s`.  Returns (status, body); status is a kXR_* code (kXR_ok=0) or -1
    when the peer closed / timed out before a full frame arrived (a malformed
    request the server drops is a NON-ok outcome, which is exactly what the callers
    assert)."""
    try:
        hdr = b""
        while len(hdr) < 8:
            chunk = s.recv(8 - len(hdr))
            if not chunk:
                return -1, b""
            hdr += chunk
        _sid, status, dlen = struct.unpack("!2sHI", hdr)
        body = b""
        while len(body) < dlen:
            chunk = s.recv(dlen - len(body))
            if not chunk:
                break
            body += chunk
        return status, body
    except (OSError, socket.timeout):
        return -1, b""


def _kxr_send_recv(s, req):
    """Send one framed request on `s` and return its single (status, body) reply;
    (-1, b"") if the peer reset/timed out (a dropped malformed request)."""
    try:
        s.sendall(req)
    except (OSError, socket.timeout):
        return -1, b""
    return _kxr_read_response(s)


def _kxr_oneshot(req, handshake=None, timeout=4.0):
    """One-shot raw exchange: connect, send the handshake (the valid 20-byte hello
    by default, or a caller-supplied blob for malformed-hello tests), read its
    reply, then -- if `req` is non-empty -- send `req` and read one reply.  Returns
    (hs_status, resp_status, resp_body, closed): each status is -1 when that stage
    got no framed reply, and `closed` is True when the peer had dropped the
    connection by the end.  Never raises -- a reset/timeout is reported, not thrown,
    because a server that drops a hostile frame is the outcome under test."""
    hs_status, resp_status, resp_body, closed = -1, -1, b"", False
    try:
        s = _kxr_connect(timeout)
    except (OSError, socket.timeout):
        return hs_status, resp_status, resp_body, True
    try:
        hs_status, _hb = _kxr_send_recv(
            s, handshake if handshake is not None else _kxr_handshake_bytes())
        if req:
            resp_status, resp_body = _kxr_send_recv(s, req)
        # Probe whether the peer has closed: a 0-length recv (or reset) => closed.
        try:
            s.settimeout(0.3)
            closed = (s.recv(1) == b"")
        except socket.timeout:
            closed = False
        except OSError:
            closed = True
    except (OSError, socket.timeout):
        closed = True
    finally:
        try:
            s.close()
        except OSError:
            pass
    return hs_status, resp_status, resp_body, closed


def _kxr_session(do_protocol=True, do_login=True, username="alice", timeout=4.0):
    """Bring a raw connection up through the handshake and (optionally) the
    kXR_protocol + anonymous kXR_login exchange.  Returns (sock, hs_status,
    login_status): login_status is None when do_login is False, else kXR_ok (a
    no-auth server) or kXR_authmore (a token/GSI server wants a follow-up kXR_auth).
    Returns (None, -1, None) on any transport failure so callers degrade honestly."""
    try:
        s = _kxr_connect(timeout)
    except (OSError, socket.timeout):
        return None, -1, None
    try:
        hs, _ = _kxr_send_recv(s, _kxr_handshake_bytes())
        if do_protocol:
            _kxr_send_recv(s, _kxr_protocol_bytes())
        lg = None
        if do_login:
            lg, _ = _kxr_send_recv(s, _kxr_login_bytes(username))
        return s, hs, lg
    except (OSError, socket.timeout):
        try:
            s.close()
        except OSError:
            pass
        return None, -1, None


def _kxr_open_bytes(path, options=_KXR_OPEN_READ, mode=0, streamid=b"\x00\x20"):
    """ClientOpenRequest: streamid[2] requestid[2] mode[2] options[2] optiont[2]
    reserved[6] fhtemplt[4] dlen[4] + path body."""
    p = path if isinstance(path, bytes) else path.encode()
    hdr = struct.pack("!2sHHHH6s4sI", streamid, _KXR_OPEN, mode & 0xFFFF,
                      options & 0xFFFF, 0, b"\x00" * 6, b"\x00" * 4, len(p))
    return hdr + p


def _kxr_read_bytes(fhandle, offset, rlen, streamid=b"\x00\x21"):
    """ClientReadRequest: streamid[2] requestid[2] fhandle[4] offset[8] rlen[4]
    dlen[4] (no read-ahead args)."""
    fh = (fhandle + b"\x00" * 4)[:4]
    return struct.pack("!2sH4sqiI", streamid, _KXR_READ, fh,
                       offset, rlen, 0)


def _kxr_readv_bytes(segments, streamid=b"\x00\x22"):
    """ClientReadVRequest: streamid[2] requestid[2] reserved[15] pathid[1] dlen[4]
    followed by read_list elements {fhandle[4], rlen[int32], offset[int64]}.
    segments = list of (fhandle_bytes, rlen, offset)."""
    rl = b""
    for fh, rlen, off in segments:
        rl += struct.pack("!4siq", (fh + b"\x00" * 4)[:4], rlen, off)
    hdr = struct.pack("!2sH15sBI", streamid, _KXR_READV, b"\x00" * 15, 0, len(rl))
    return hdr + rl


def _kxr_pgread_bytes(fhandle, offset, rlen, streamid=b"\x00\x23"):
    """ClientPgReadRequest: streamid[2] requestid[2] fhandle[4] offset[8] rlen[4]
    dlen[4]=0 (no args)."""
    fh = (fhandle + b"\x00" * 4)[:4]
    return struct.pack("!2sH4sqiI", streamid, _KXR_PGREAD, fh, offset, rlen, 0)


def _kxr_pgwrite_bytes(fhandle, offset, data, crc=None, streamid=b"\x00\x24"):
    """ClientPgWriteRequest: streamid[2] requestid[2] fhandle[4] offset[8]
    pathid[1] reqflags[1] reserved[2] dlen[4] + payload.  Payload per page is
    [CRC32c(4 BE)][data], CRC first.  Pass crc=None for a VALID checksum, or an
    explicit (wrong) 32-bit int to forge a corrupted page."""
    d = data if isinstance(data, bytes) else data.encode()
    use_crc = _crc32c(d) if crc is None else (crc & 0xFFFFFFFF)
    payload = struct.pack("!I", use_crc) + d
    fh = (fhandle + b"\x00" * 4)[:4]
    hdr = struct.pack("!2sH4sqBB2sI", streamid, _KXR_PGWRITE, fh, offset,
                      0, 0, b"\x00" * 2, len(payload))
    return hdr + payload


def _kxr_statx_bytes(path, streamid=b"\x00\x25"):
    """kXR_statx shares the ClientStatRequest layout (options[1] reserved[7]
    wants[4] fhandle[4] dlen[4]) + path body."""
    p = path if isinstance(path, bytes) else path.encode()
    hdr = struct.pack("!2sHB7sI4sI", streamid, _KXR_STATX, 0, b"\x00" * 7,
                      0, b"\x00" * 4, len(p))
    return hdr + p


def _kxr_dirlist_bytes(path, streamid=b"\x00\x26"):
    """ClientDirlistRequest: streamid[2] requestid[2] reserved[15] options[1]
    dlen[4] + path body."""
    p = path if isinstance(path, bytes) else path.encode()
    hdr = struct.pack("!2sH15sBI", streamid, _KXR_DIRLIST, b"\x00" * 15, 0, len(p))
    return hdr + p


def _kxr_truncate_bytes(fhandle, offset, streamid=b"\x00\x27"):
    """ClientTruncateRequest: streamid[2] requestid[2] fhandle[4] offset[8]
    reserved[4] dlen[4]=0 (handle-based truncate)."""
    fh = (fhandle + b"\x00" * 4)[:4]
    return struct.pack("!2sH4sq4sI", streamid, _KXR_TRUNCATE, fh, offset,
                       b"\x00" * 4, 0)


def _kxr_close_bytes(fhandle, streamid=b"\x00\x28"):
    """ClientCloseRequest: streamid[2] requestid[2] fhandle[4] reserved[12]
    dlen[4]."""
    fh = (fhandle + b"\x00" * 4)[:4]
    return struct.pack("!2sH4s12sI", streamid, _KXR_CLOSE, fh, b"\x00" * 12, 0)


def _kxr_authed_session(token, timeout=4.0):
    """Bring a raw connection all the way up to an AUTHENTICATED ztn session:
    handshake -> kXR_protocol -> kXR_login -> kXR_auth(ztn, token).  Returns
    (sock, ok_bool): ok_bool is True only when kXR_auth returned kXR_ok, meaning
    the impersonation identity for this connection is now the token's subject.
    Returns (None, False) if any stage fails (so the caller degrades honestly)."""
    try:
        s = _kxr_connect(timeout)
    except (OSError, socket.timeout):
        return None, False
    try:
        s.sendall(_kxr_handshake_bytes())
        hs, _ = _kxr_read_response(s)
        if hs != _KXR_OK:
            s.close()
            return None, False
        s.sendall(_kxr_protocol_bytes())
        _kxr_read_response(s)
        s.sendall(_kxr_login_bytes())
        lg, _ = _kxr_read_response(s)
        if lg != _KXR_OK:
            s.close()
            return None, False
        st, _b = _kxr_send_recv(s, _kxr_auth_bytes(token))
        if st != _KXR_OK:
            try:
                s.close()
            except OSError:
                pass
            return None, False
        return s, True
    except (OSError, socket.timeout):
        try:
            s.close()
        except OSError:
            pass
        return None, False


def _kxr_open_fhandle(sock, path, options=_KXR_OPEN_READ, mode=0,
                      streamid=b"\x00\x20"):
    """Send kXR_open on an authed socket; return (status, fhandle_bytes|None).
    On kXR_ok the 4-byte fhandle is the first 4 bytes of ServerResponseBody_Open
    (the open-slot index in byte 0)."""
    st, body = _kxr_send_recv(sock, _kxr_open_bytes(path, options, mode, streamid))
    if st == _KXR_OK and body is not None and len(body) >= 4:
        return st, body[:4]
    return st, None



# ===== Round-9 batch helpers (workflow-authored) =====
def _s3_raw(method, key, port, params=None, access_key="alice", extra_hdrs=None,
            read_timeout=4.0):
    """SigV4 header-auth S3 request sent RAW so the FULL response header block is
    visible (the s3()/http() helpers discard headers).  Returns
    (status_int, headers_dict_lowercased, body_bytes, raw_head_bytes); status 0 on a
    framing/conn failure.  `params` (signed query, e.g. response-* overrides) is
    canonicalized identically to the signer so the signature validates; conditional
    headers go in `extra_hdrs` (unsigned -- the server signs only host;x-amz-date)."""
    raw = _s3_request_bytes(method, key, port, params, access_key, extra_hdrs)
    resp = raw_http(raw, port, read_timeout=read_timeout)
    if not resp or b"\r\n" not in resp:
        return 0, {}, b"", b""
    head, _, body = resp.partition(b"\r\n\r\n")
    head_lines = head.split(b"\r\n")
    return _s3_status(head_lines[0]), _s3_headers(head_lines[1:]), body, head


def _s3_request_bytes(method, key, port, params, access_key, extra_headers):
    path = f"/{S3_BUCKET}/{key}"
    full_path = _s3_full_path(path, params)
    headers = _s3_signed_headers(method, path, port, params, access_key,
                                 extra_headers)
    lines = [f"{method} {full_path} HTTP/1.1", f"Host: {HOST}:{port}",
             "Connection: close"]
    lines.extend(_s3_header_lines(headers))
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def _s3_full_path(path, params):
    query = _canon_query(params or {})
    return path + "?" + query if query else path


def _s3_signed_headers(method, path, port, params, access_key, extra_headers):
    headers = s3_sign(method, path, port, params, access_key)
    if extra_headers:
        headers.update(extra_headers)
    return headers


def _s3_header_lines(headers):
    return [f"{name}: {value}" for name, value in headers.items()]


def _s3_status(status_line):
    match = re.match(rb"HTTP/\d\.\d\s+(\d{3})", status_line)
    if match:
        return int(match.group(1))
    return 0


def _s3_headers(lines):
    headers = {}
    for line in lines:
        name, separator, value = line.partition(b":")
        key = name.strip().lower().decode("latin1")
        if separator and key and key not in headers:
            headers[key] = value.strip().decode("latin1")
    return headers

_KXR_QUERY    = 3001          # kXR_query opcode (ClientQueryRequest)
_KXR_QSTATS   = 1             # XQueryType: kXR_QStats
_KXR_QCKSUM   = 3             # kXR_Qcksum
_KXR_QXATTR   = 4             # kXR_Qxattr
_KXR_QSPACE   = 5             # kXR_Qspace
_KXR_QCONFIG  = 7             # kXR_Qconfig
_KXR_QOPAQUF  = 32            # kXR_Qopaquf


def _kxr_query_bytes(infotype, args, streamid=b"\x00\x60"):
    """ClientQueryRequest (24-byte header) + arg body, matching XProtocol.hh:
    streamid[2] requestid[2](=kXR_query 3001) infotype[2] reserved1[2] fhandle[4]
    reserved2[8] dlen[4], then `args` as the dlen body.  The native client
    (client/lib/ops_fs.c brix_query) frames it identically: Qcksum args are the
    space-separated '<algo> <path>' string, Qxattr/Qopaquf args are the path,
    Qconfig args are the capability key(s); global subcodes (Qspace/QStats) take a
    bare/'/' arg.  dlen is computed from the supplied body so the frame is
    self-consistent (use the raw struct.pack form directly to forge a length
    mismatch)."""
    a = args if isinstance(args, bytes) else args.encode()
    hdr = struct.pack("!2sHH2s4s8sI", streamid, _KXR_QUERY,
                      infotype & 0xFFFF, b"\x00" * 2, b"\x00" * 4,
                      b"\x00" * 8, len(a))
    return hdr + a
