"""
test_audit15c_ssi_knobs.py — the SSI operational knobs that had zero live
coverage (audit §A2, testsuite-combinatorial-coverage-audit 2026-08-15):
`brix_ssi_cta_journal`, `brix_ssi_cta_executor`, `brix_ssi_request_max`,
`brix_ssi_response_max`.

Two instances on the stock nginx_lc_ssi.conf template:

  * journal — cta service with an explicit `executor test` and a journal
    path; an archive submit must succeed AND leave a non-empty journal
    (cta_service.c opens the journal lazily on the first request)
  * caps — request_max 32 / response_max 16; the caps are enforced at
    ssi_dispatch.c (append > request cap → kXR_error "SSI request too large";
    response append > cap → the queued response errors), with an in-cap echo
    roundtrip on the SAME instance as the control
"""

import struct

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST
from test_ssi_async import _submit, kXR_waitresp
from test_ssi_cta import CTA_RSP_SUCCESS, _collect_pushed_response, build_request
from test_ssi_wire import (SSI_CMD_RXQ, _handshake_login, _open_ssi,
                           _parse_ssi_reply, _query_wait, _read_response,
                           _rrinfo, kXR_ok, kXR_write)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15c-ssi")]


@pytest.fixture()
def ssi_journal(lifecycle, tmp_path):
    journal = tmp_path / "cta.journal"
    data = tmp_path / "data-journal"
    data.mkdir()
    port = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15c-ssi-journal",
        template="nginx_lc_ssi.conf",
        data_root=str(data),
        template_values={"BIND_HOST": HOST, "SSI_DIRECTIVES": (
            "        brix_ssi on;\n"
            "        brix_ssi_service cta;\n"
            "        brix_ssi_cta_executor test;\n"
            f"        brix_ssi_cta_journal {journal};\n")},
        reason="audit-15c SSI CTA journal + executor selection")).port
    return port, journal


@pytest.fixture()
def ssi_caps(lifecycle, tmp_path):
    data = tmp_path / "data-caps"
    data.mkdir()
    return lifecycle.start(NginxInstanceSpec(
        name="lc-audit15c-ssi-caps",
        template="nginx_lc_ssi.conf",
        data_root=str(data),
        template_values={"BIND_HOST": HOST, "SSI_DIRECTIVES": (
            "        brix_ssi on;\n"
            "        brix_ssi_service cta;\n"
            "        brix_ssi_request_max 32;\n"
            "        brix_ssi_response_max 16;\n")},
        reason="audit-15c SSI request/response caps")).port


def _write_raw(sock, fh, req_id, data):
    """kXR_write submit returning (status, body) — no ok-assert, unlike
    test_ssi_wire._write_request, so cap refusals can be inspected."""
    off = _rrinfo(SSI_CMD_RXQ, req_id, len(data))
    fhandle = bytes([fh, 0, 0, 0])
    sock.sendall(struct.pack(">BB H 4s 8s B 3x I", 0, 1, kXR_write, fhandle,
                             off, 0, len(data)) + data)
    return _read_response(sock)


def test_cta_journal_recorded(ssi_journal):
    port, journal = ssi_journal
    sock = _handshake_login(HOST, port)
    try:
        fh = _open_ssi(sock, "cta")
        req = build_request(4, "eosdev", "alice", "eosusers",
                            "/eos/a15c/f1", 99)   # CLOSEW = archive
        assert _submit(sock, fh, 1, req) == kXR_waitresp
        alerts, rsp = _collect_pushed_response(sock)
        assert rsp.get(1) == CTA_RSP_SUCCESS, rsp
    finally:
        sock.close()
    assert journal.exists(), "journal file was never created"
    assert journal.stat().st_size > 0, "journal file is empty after a submit"


def test_request_cap_refuses_oversize(ssi_caps):
    sock = _handshake_login(HOST, ssi_caps)
    try:
        fh = _open_ssi(sock, "echo")
        status, body = _write_raw(sock, fh, 1, b"x" * 100)
        assert status != kXR_ok, "100-byte request admitted past request_max 32"
        assert b"SSI request too large" in body, body
    finally:
        sock.close()


def test_response_cap_trips(ssi_caps):
    sock = _handshake_login(HOST, ssi_caps)
    try:
        fh = _open_ssi(sock, "echo")
        payload = b"y" * 24     # <= request_max 32, echo > response_max 16
        status, body = _write_raw(sock, fh, 2, payload)
        if status == kXR_ok:
            status, body = _query_wait(sock, fh, 2)
        assert status != kXR_ok, \
            f"echo beyond response_max 16 was delivered intact: {body!r}"
    finally:
        sock.close()


def test_in_cap_echo_roundtrip(ssi_caps):
    # Control on the SAME capped instance: within both caps the service is
    # fully functional, so the refusals above are the caps and nothing else.
    sock = _handshake_login(HOST, ssi_caps)
    try:
        fh = _open_ssi(sock, "echo")
        payload = b"ok15c"      # <= response_max 16
        status, body = _write_raw(sock, fh, 3, payload)
        assert status == kXR_ok, (status, body)
        status, body = _query_wait(sock, fh, 3)
        assert status == kXR_ok, (status, body)
        tag, _, data = _parse_ssi_reply(body)
        assert tag == b":" and data == payload, (tag, data)
    finally:
        sock.close()
