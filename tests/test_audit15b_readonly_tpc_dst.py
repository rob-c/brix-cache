"""
test_audit15b_readonly_tpc_dst.py — the readonly × native-TPC(destination) pair
(audit §B1.6, testsuite-combinatorial-coverage-audit 2026-08-15:
"`brix_allow_write off` on a TPC *destination* must refuse the pull cleanly" —
the security-negative had zero units).

A native-TPC destination leg begins as a write-open carrying the stock
`tpc.src=host:port&tpc.lfn=/path&tpc.stage=copy` opaque.  The write gate
(brix_open_mode_guard, src/protocols/root/read/open_request.c) fires before any
TPC opaque parsing, so on a read-only destination the pull must die at the open
with kXR_fsReadOnly — the TPC control path gets no chance to bypass the gate.
The three cases:

  * security-negative — TPC dest-open on the read-only instance is refused
    with kXR_fsReadOnly and nothing is created on disk
  * cleanly — the refused connection is not desynced: a read of the seeded
    source file on the same connection still answers
  * control — the identical dest-open on a writable twin is GRANTED (the
    refusal above is attributable to allow_write, not to the TPC opaque)
"""

import struct

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST
from test_phase25_ratelimit import (_start_stream, _xrd_login, _xrd_open,
                                    _xrd_read, _xrd_recv_status, KXR_OK)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15b-tpc-ro")]

KXR_ERROR = 4003
KXR_FS_READONLY = 3025

SEED = b"tpc-source-bytes\n"

_TPC_KNOBS = ("        brix_tpc_allow_local on;\n"
              "        brix_tpc_allow_private on;\n")


def _tpc_dst_open(s, path, src_port):
    """Destination write-open with the stock native-TPC destination opaque."""
    opaque = (f"?tpc.src=127.0.0.1:{src_port}"  # net-literal-allow: local TPC wire payload
              f"&tpc.lfn=/src.bin&tpc.stage=copy&oss.asize={len(SEED)}")
    payload = (path + opaque).encode()
    # kXR_new | kXR_open_wrto | kXR_mkpath
    body = struct.pack(">HH12s", 0o644, 0x0008 | 0x4000 | 0x0100, b"\x00" * 12)
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


@pytest.fixture()
def tpc_pair(lifecycle, tmp_path):
    """(ro_port, rw_port, ro_data): a read-only and a writable TPC endpoint."""
    ro_data = tmp_path / "ro-data"
    ro_data.mkdir()
    (ro_data / "src.bin").write_bytes(SEED)
    ro_port = _start_stream(lifecycle, ro_data, "lc-audit15b-tpc-ro",
                            "        brix_allow_write off;\n" + _TPC_KNOBS, "")

    rw_data = tmp_path / "rw-data"
    rw_data.mkdir()
    # The writable control needs a main-context thread_pool (a granted TPC
    # dest-open refuses with "TPC pull requires brix_thread_pool" otherwise);
    # nginx_rl_stream.conf has no main-level hook, so the control reuses the
    # stock writable TPC-destination template instead.
    rw_ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15b-tpc-rw",
        template="nginx_resilience_tpc_dest.conf",
        data_root=str(rw_data),
        reason="audit-15b readonly x TPC-dst writable control"))
    return ro_port, rw_ep.port, ro_data


def test_readonly_destination_refuses_tpc_pull(tpc_pair):
    ro_port, rw_port, ro_data = tpc_pair
    s = _xrd_login(HOST, ro_port)
    try:
        status, body = _tpc_dst_open(s, "/pulled.bin", rw_port)
        assert status == KXR_ERROR, \
            f"TPC dest-open on a read-only server was not refused: {status}"
        errnum = struct.unpack(">I", body[:4])[0]
        assert errnum == KXR_FS_READONLY, (errnum, body)
        assert b"read-only" in body, body
    finally:
        s.close()
    assert not (ro_data / "pulled.bin").exists(), \
        "refused TPC pull left a file on the read-only destination"


def test_refusal_does_not_desync_connection(tpc_pair):
    ro_port, rw_port, _ = tpc_pair
    s = _xrd_login(HOST, ro_port)
    try:
        status, _ = _tpc_dst_open(s, "/pulled2.bin", rw_port)
        assert status == KXR_ERROR
        # "cleanly": the same connection still serves — open+read the source.
        status, body = _xrd_open(s, "/src.bin")
        assert status == KXR_OK, (status, body)
        status, data = _xrd_read(s, body[:4], 0, len(SEED))
        assert status == KXR_OK and data == SEED, (status, data)
    finally:
        s.close()


def test_writable_destination_grants_the_same_open(tpc_pair):
    # Control: byte-identical dest-open (source = the read-only twin, which is
    # a legitimate TPC source) granted on the writable instance, pinning
    # allow_write as the only variable in the refusal above.  The pull itself
    # is not driven here (that is test_root_tpc.py's job); the granted handle
    # is closed unsynced, which aborts the rendezvous.
    ro_port, rw_port, _ = tpc_pair
    s = _xrd_login(HOST, rw_port)
    try:
        status, body = _tpc_dst_open(s, "/pulled.bin", ro_port)
        assert status == KXR_OK, \
            f"TPC dest-open refused on a writable destination: {status} {body}"
        assert len(body) >= 4, body
        fhandle = body[:4]
        # kXR_close = 3003; body: fhandle[4] fsize[8] pad[4]
        s.sendall(struct.pack(">BBH", 0, 1, 3003) + fhandle
                  + struct.pack(">q", 0) + b"\x00" * 4
                  + struct.pack(">I", 0))
        _xrd_recv_status(s)   # best-effort: aborting an unsynced rendezvous
    finally:
        s.close()
