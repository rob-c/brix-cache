#!/usr/bin/env python3
"""e2e_redteam.py — full-stack privilege-escalation red-team for phase-40
impersonation.  RUNS AS IN-NS ROOT (launched by userns_exec_launcher inside an
unprivileged user namespace with a subuid range + bind-mounted fake passwd/group).

This is the pseudo-production permissions test: it boots the REAL nginx binary
with `brix_impersonation map` (so the real master spawns the real broker, real
svc-uid workers connect, and the real auth->identity->dispatch->broker->setfsuid
chain runs), then drives it over the network with token-authenticated WebDAV
requests as many identities and tries to break the permissions model.

It asserts the model holds end-to-end: files owned by the MAPPED user (not the
worker/broker), DAC enforced, every escalation/forbidden identity denied,
confinement intact, and no credential leak under concurrency.

argv[1] = work dir (pre-created by the pytest wrapper, holds nothing required —
this script generates keys/tokens/config/export tree itself as in-ns root).
Prints "PASS:"/"FAIL:" per check and "ALL PASSED" + exit 0 on success.
"""

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.client import HTTPConnection   # imported by name: the http() helper below
from urllib.parse import quote           # would otherwise shadow the `http` module

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from settings import BIND_HOST, HOST

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/e2e_redteam"
NGINX = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
# repo root = .../tests/userns/e2e_redteam.py -> up 3.  The native root:// clients
# (built under client/) drive the stream server with a bearer token (BEARER_TOKEN).
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# The native CLI binaries are built into client/bin/ (the Makefile's BINDIR), not
# client/ directly — an older layout this path lagged behind.
NATIVE_XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
# set in main(): the JWT signing key + the impersonation stream port, so the
# root:// helpers can mint a per-subject token without threading them everywhere.
_jwt_key = None
_stream_port = 0
ISSUER = "https://redteam.example"
AUDIENCE = "nginx-xrootd"
KID = "rt-es256"
WRITE_SCOPE = "storage.create:/ storage.modify:/ storage.read:/"

# S3 SigV4: access_key == the UNIX user the broker maps to (subject = access key).
S3_BUCKET = "testbucket"
S3_REGION = "us-east-1"
S3_SECRET = "rt-s3-secret-0123456789"

# in-ns uids (match the fake /etc/passwd the launcher bind-mounted).
UID_ALICE, UID_BOB, UID_SVC = 1001, 1002, 1500
UID_CAROL, UID_DAVE, UID_ERIN, UID_FRANK = 1003, 1004, 1005, 1006
UID_MANYU, UID_FLOOR, UID_LOW = 1008, 1000, 999
# supplementary groups (match the fake /etc/group): staff={alice,carol},
# research={bob,dave}, shared={alice,bob,carol}, proj={carol,dave,erin}.
GID_STAFF, GID_RESEARCH, GID_SHARED, GID_PROJ = 2001, 2002, 2003, 2004

_pass = _fail = 0


def _crc32c(data):
    """CRC-32C (Castagnoli, poly 0x1EDC6F41 reflected = 0x82F63B78) — the exact
    checksum the kXR_pgread/kXR_pgwrite wire path computes per 4096-byte page.
    Lazily builds the byte table so a degraded (no-auth) run never pays for it."""
    global _CRC32C_TABLE
    if _CRC32C_TABLE is None:
        tbl = []
        for n in range(256):
            c = n
            for _ in range(8):
                c = (c >> 1) ^ 0x82F63B78 if (c & 1) else (c >> 1)
            tbl.append(c)
        _CRC32C_TABLE = tbl
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC32C_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


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
    path = f"/{S3_BUCKET}/{key}"
    cq = _canon_query(params or {})
    full = path + (("?" + cq) if cq else "")
    h = s3_sign(method, path, port, params, access_key)
    if extra_hdrs:
        h.update(extra_hdrs)
    lines = [f"{method} {full} HTTP/1.1", f"Host: {HOST}:{port}", "Connection: close"]
    for k, v in h.items():
        lines.append(f"{k}: {v}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode()
    resp = raw_http(raw, port, read_timeout=read_timeout)
    if not resp or b"\r\n" not in resp:
        return 0, {}, b"", b""
    head, _, body = resp.partition(b"\r\n\r\n")
    head_lines = head.split(b"\r\n")
    status = 0
    m = re.match(rb"HTTP/\d\.\d\s+(\d{3})", head_lines[0])
    if m:
        status = int(m.group(1))
    hdrs = {}
    for hl in head_lines[1:]:
        name, _, val = hl.partition(b":")
        n = name.strip().lower().decode("latin1")
        if n and n not in hdrs:
            hdrs[n] = val.strip().decode("latin1")
    return status, hdrs, body, head

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


