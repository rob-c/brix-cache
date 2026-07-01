"""
tests/test_ssi_cta.py — Phase-5 end-to-end: the flagship CTA SSI service.

A raw-wire client builds a real (byte-compatible) cta.xrd.Request protobuf, opens
/.ssi/cta, and verifies:
  - archive/retrieve (CLOSEW/PREPARE) defer → kXR_waitresp → progress alerts →
    pushed cta.xrd.Response (RSP_SUCCESS);
  - a query (admincmd) answers synchronously (polled);
  - a malformed request answers with a cta.xrd.Response error type.

Protobuf field numbers match CTA's real .proto (see src/ssi/svc_cta/cta_pb.c).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_ssi_cta.py -v
"""
import struct

from settings import HOST
from test_ssi_wire import (
    ssi_server,
    _handshake_login, _open_ssi, _read_response, _parse_ssi_reply, _query_wait,
    _rrinfo, kXR_write, kXR_ok, SSI_CMD_RXQ,
)
from test_ssi_async import _submit, _parse_asynresp, kXR_attn, kXR_waitresp

# ---- minimal protobuf encoder ----
def _vbytes(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | 0x80]) if n else bytes([b])
        if not n:
            return out


def _ld(field, data):    # length-delimited field
    return _vbytes((field << 3) | 2) + _vbytes(len(data)) + data


def _vi(field, val):     # varint field
    return _vbytes((field << 3) | 0) + _vbytes(val)


def _s(field, txt):
    return _ld(field, txt.encode())


# EventType: CLOSEW=4 (archive), PREPARE=6 (retrieve), ABORT_PREPARE=8 (cancel)
def build_request(event, instance, user, group, lpath, archive_id):
    svc   = _s(1, instance)                          # Service.name=1
    wf    = _vi(1, event) + _ld(5, svc)              # Workflow.event=1, instance=5
    rid   = _s(1, user) + _s(2, group)               # RequesterId.username/groupname
    cli   = _ld(1, rid)                              # Client.user=1
    meta  = _s(11, lpath) + _vi(15, archive_id)      # Metadata.lpath=11, afid=15
    notif = _ld(1, wf) + _ld(2, cli) + _ld(4, meta)  # Notification.wf/cli/file
    return _ld(1, notif)                             # Request.notification=1


def build_admincmd_request():
    return _ld(2, b"\x08\x01")                       # Request.admincmd=2 (present)


def _read_varint(b, i):
    shift = 0
    v = 0
    while True:
        x = b[i]; i += 1
        v |= (x & 0x7F) << shift
        if not (x & 0x80):
            return v, i
        shift += 7


def parse_cta_response(body):
    """Parse cta.xrd.Response → {field_number: value}."""
    res = {}
    i = 0
    while i < len(body):
        tag, i = _read_varint(body, i)
        field, wt = tag >> 3, tag & 7
        if wt == 0:
            res[field], i = _read_varint(body, i)
        elif wt == 2:
            ln, i = _read_varint(body, i)
            res[field] = body[i:i + ln]; i += ln
        else:
            break
    return res


CTA_RSP_SUCCESS = 1


def _submit_raw(sock, fh, req_id, data):
    off = _rrinfo(SSI_CMD_RXQ, req_id, len(data))
    fhandle = bytes([fh, 0, 0, 0])
    sock.sendall(struct.pack(">BB H 4s 8s B 3x I", 0, 1, kXR_write, fhandle, off,
                             0, len(data)) + data)
    return _read_response(sock)[0]


def _collect_pushed_response(sock):
    """Read pushed kXR_attn frames; return (alerts, response_dict)."""
    alerts = []
    for _ in range(16):
        status, body = _read_response(sock)
        assert status == kXR_attn, f"expected attn, got {status}"
        _, inner_status, inner_body = _parse_asynresp(body)
        tag, _, data = _parse_ssi_reply(inner_body)
        if tag == b"!":
            alerts.append(data)
        elif tag == b":":
            return alerts, parse_cta_response(data)
    raise AssertionError("no terminal response pushed")


class TestSsiCta:
    def test_archive_pushed_with_alerts(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "cta")
            req = build_request(4, "eosdev", "alice", "eosusers",
                                "/eos/dev/f1", 42)
            assert _submit(sock, fh, 1, req) == kXR_waitresp
            alerts, rsp = _collect_pushed_response(sock)
            assert any(b"tape" in a for a in alerts), alerts
            assert rsp.get(1) == CTA_RSP_SUCCESS, rsp
        finally:
            sock.close()

    def test_retrieve_pushed(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "cta")
            req = build_request(6, "eosp", "bob", "grp", "/eos/p/f", 7)
            assert _submit(sock, fh, 1, req) == kXR_waitresp
            _, rsp = _collect_pushed_response(sock)
            assert rsp.get(1) == CTA_RSP_SUCCESS, rsp
        finally:
            sock.close()

    def test_query_synchronous(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "cta")
            assert _submit_raw(sock, fh, 1, build_admincmd_request()) == kXR_ok
            status, body = _query_wait(sock, fh, 1)
            assert status == kXR_ok
            _, _, data = _parse_ssi_reply(body)
            rsp = parse_cta_response(data)
            assert rsp.get(1) == CTA_RSP_SUCCESS, rsp   # type SUCCESS
            assert b"active request" in rsp.get(3, b""), rsp   # message_txt
        finally:
            sock.close()

    def test_malformed_request_errors(self, ssi_server):
        sock = _handshake_login(HOST, ssi_server)
        try:
            fh = _open_ssi(sock, "cta")
            assert _submit_raw(sock, fh, 1, b"\x07not-protobuf\xff") == kXR_ok
            status, body = _query_wait(sock, fh, 1)
            assert status == kXR_ok
            _, _, data = _parse_ssi_reply(body)
            rsp = parse_cta_response(data)
            assert rsp.get(1) != CTA_RSP_SUCCESS, rsp   # an error ResponseType
        finally:
            sock.close()
