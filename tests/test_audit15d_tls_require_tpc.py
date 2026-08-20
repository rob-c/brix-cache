"""
test_audit15d_tls_require_tpc.py — the `brix_tls_require tpc` capability mask
at the native-TPC open choke point (audit §B1.4,
testsuite-combinatorial-coverage-audit 2026-08-15: test_tls_require.py drives
the login/session/data masks and ADVERTISES the tpc bit, but no test ever
presented a TPC-role open to a tpc-masked server — the gate at
src/protocols/root/read/open_tpc.c, `brix_tls_gate_refused(...,
BRIX_TLSREQ_TPC, ...)`, had zero execution).

Both TPC roles are gated at the same choke point:

  * destination role — a write-open whose opaque carries `tpc.src`;
  * source-arm role — a read-open whose opaque carries `tpc.key`/`tpc.dst`
    (the rendezvous registration leg).

Cases:

  * security-negative — a cleartext TPC destination open on a tpc-masked
    server is refused kXR_TLSRequired naming the TPC capability
  * security-negative — the cleartext source-arm read-open is refused the
    same way (the register leg must not be weaker than the pull leg)
  * success/control — non-TPC opens and reads on the SAME masked server
    proceed on cleartext: the mask is capability-scoped, not session-wide
  * success — after the in-protocol TLS upgrade both TPC-role opens are
    granted under the same mask
  * control — with no mask the same cleartext TPC-role opens are granted
    (pinning that the refusal above is the mask's doing)
"""

import struct

import pytest

from settings import HOST
from test_min_sec_level import _errcode, kXR_TLSRequired
from test_phase25_ratelimit import (KXR_OK, _xrd_open, _xrd_read,
                                    _xrd_recv_status)
from test_tls_require import (KXR_ERROR, _connect, _data_dir, _send_protocol,
                              _start, _upgrade_tls, _xrd_login)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15d-tlstpc")]

TPC_LINES = ("        brix_allow_write on;\n"
             "        brix_tpc_allow_local on;\n")


def _session(port, *, tls=False):
    """handshake(+protocol) [+ in-band TLS upgrade] + anonymous login."""
    s = _connect(port)
    _send_protocol(s)
    if tls:
        s = _upgrade_tls(s)
    status, body = _xrd_login(s)
    assert status == KXR_OK, ("login refused", status, body)
    return s


def _tpc_source_arm_open(s, key):
    """Source-role read-open: tpc.key + tpc.dst select the rendezvous
    register leg (open_tpc.c tpc_open_is_source)."""
    return _xrd_open(
        s, f"/real.dat?tpc.key={key}&tpc.dst=127.0.0.1&tpc.stage=placement")  # net-literal-allow: local TPC wire payload


def _tpc_dest_open(s, path, src_port, key):
    """Destination-role write-open: the tpc.src opaque selects the pull leg
    (open_tpc.c tpc_open_is_dest).  The pull itself only starts at kXR_sync,
    so a granted open is a complete positive for the gate under test."""
    opaque = (f"?tpc.src=127.0.0.1:{src_port}&tpc.key={key}"  # net-literal-allow: local TPC wire payload
              f"&tpc.lfn=/real.dat&tpc.stage=copy&oss.asize=8")
    payload = (path + opaque).encode()
    # kXR_new | kXR_open_wrto | kXR_mkpath
    body = struct.pack(">HH12s", 0o644, 0x0008 | 0x4000 | 0x0100, b"\x00" * 12)
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


@pytest.fixture()
def masked_port(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    return _start(lifecycle, data, "lc-audit15d-tlstpc-mask",
                  tls=False, auth="none", tls_require="tpc",
                  auth_lines=TPC_LINES)


@pytest.fixture()
def tls_masked_port(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    return _start(lifecycle, data, "lc-audit15d-tlstpc-tls",
                  tls=True, auth="none", tls_require="tpc",
                  auth_lines=TPC_LINES)


@pytest.fixture()
def unmasked_port(lifecycle, tmp_path):
    data = _data_dir(tmp_path)
    return _start(lifecycle, data, "lc-audit15d-tlstpc-none",
                  tls=False, auth="none", tls_require="none",
                  auth_lines=TPC_LINES)


def test_cleartext_tpc_dest_open_refused(masked_port):
    s = _session(masked_port)
    status, body = _tpc_dest_open(s, "/pulled.bin", masked_port, "a15dmask")
    s.close()
    assert status == KXR_ERROR, ("tpc mask must refuse the dest open", status)
    assert _errcode(body) == kXR_TLSRequired, (hex(_errcode(body)), body)
    assert b"requires TLS for TPC" in body, body


def test_cleartext_tpc_source_arm_refused(masked_port):
    s = _session(masked_port)
    status, body = _tpc_source_arm_open(s, "a15dsrc")
    s.close()
    assert status == KXR_ERROR, \
        ("tpc mask must refuse the source register leg", status, body)
    assert _errcode(body) == kXR_TLSRequired, (hex(_errcode(body)), body)


def test_cleartext_non_tpc_ops_unaffected(masked_port):
    # The mask is capability-scoped: a plain open/read on the very same
    # cleartext session must proceed (the grain brix_min_sec_level and a
    # session mask cannot express).
    s = _session(masked_port)
    st_open, body_open = _xrd_open(s, "/real.dat")
    st_read, body_read = _xrd_read(s, body_open[:4], 0, 8)
    s.close()
    assert (st_open, st_read) == (KXR_OK, KXR_OK), \
        (st_open, st_read, body_open, body_read)
    assert body_read == b"present\n", body_read


def test_tls_upgrade_frees_tpc_opens(tls_masked_port):
    s = _session(tls_masked_port, tls=True)
    st_arm, body_arm = _tpc_source_arm_open(s, "a15dtls")
    assert st_arm == KXR_OK, ("TLS must satisfy the tpc mask", st_arm,
                              body_arm)
    d = _session(tls_masked_port, tls=True)
    st_dst, body_dst = _tpc_dest_open(d, "/pulled-tls.bin", tls_masked_port,
                                      "a15dtls")
    d.close()
    s.close()
    assert st_dst == KXR_OK, (st_dst, body_dst)


def test_no_mask_cleartext_tpc_grants(unmasked_port):
    # Control: identical cleartext TPC-role opens succeed without the mask,
    # so the refusals above are the mask's doing and nothing else's.
    s = _session(unmasked_port)
    st_arm, body_arm = _tpc_source_arm_open(s, "a15dnone")
    assert st_arm == KXR_OK, (st_arm, body_arm)
    d = _session(unmasked_port)
    st_dst, body_dst = _tpc_dest_open(d, "/pulled-none.bin", unmasked_port,
                                      "a15dnone")
    d.close()
    s.close()
    assert st_dst == KXR_OK, (st_dst, body_dst)
