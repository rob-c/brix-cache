"""
brix_require_pgwrite — hostile-network wire-integrity gate for native uploads
(fault-hardening finding #11).

THE GAP (verified, not a poison-commit bug): the native plain kXR_write / kXR_writev
ingest path is already sound against truncation (explicit kXR_close signal +
abort-on-disconnect + POSC), BUT — unlike kXR_pgwrite — it carries NO per-page
CRC32c (INVARIANT 1 covers only pgwrite).  A byte a hostile middlebox flips past
the TCP checksum in a cleartext write is committed undetected; brix_verify_write
is a storage read-back (it re-reads and matches the corrupt bytes), never a wire
check.  pgwrite exists precisely to catch this, but nothing let a deployment
REQUIRE it.

THE KNOB (opt-in, default off — plain write is the stock upload op): when
brix_require_pgwrite is on, a data-carrying kXR_write / kXR_writev on a writable
handle is refused with kXR_Unsupported, forcing clients onto the checksummed
pgwrite path.  This is the native-write analogue of brix_webdav_require_digest
(#6) / brix_gridftp_require_allo_size (#9).  SSI request-accumulation and
zero-length no-ops carry no data and stay exempt.

CONTRACT proven here, driven over the native root:// wire (the shared pgwrite
helpers from test_pgwrite_cse) against two co-hosted servers over one posix
export — {PORT} with the knob on, {OFF_PORT} with it off:
  * knob on  + plain kXR_write (data)   -> kXR_Unsupported, nothing on disk   [error]
  * knob on  + proper kXR_pgwrite        -> clean status + close ok, byte-exact [success / no FP]
  * knob on  + kXR_writev (data)         -> kXR_Unsupported, nothing on disk   [security-neg]
  * knob off + plain kXR_write (data)    -> kXR_ok, byte-exact                 [opt-in proof]

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_root_require_pgwrite.py -v -p no:xdist
"""

import os
import struct

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

from test_pgwrite_cse import (
    _handshake_login,
    _open,
    _close,
    _read_response,
    send_pgwrite,
    build_payload,
    kXR_ok,
    kXR_error,
    kXR_status,
)

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]

kXR_write       = 3019     # request opcode (distinct domain from kXR_ChkSumErr)
kXR_writev      = 3031
kXR_Unsupported = 3013     # error code (distinct domain from the kXR_read opcode)


def _free_port():
    import socket
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _write(sock, fhandle, offset, data):
    """Send a cleartext kXR_write; return (status, errcode|None).
    ClientWriteRequest: fhandle[4] offset(i64) pathid(1) reserved[3] dlen."""
    sock.sendall(struct.pack("!2sH4sqB3sI",
                             b"\x00\x04", kXR_write, fhandle, offset,
                             0, b"\x00\x00\x00", len(data)) + data)
    status, body = _read_response(sock)
    errcode = (struct.unpack("!I", body[:4])[0]
               if (status == kXR_error and len(body) >= 4) else None)
    return status, errcode


def _writev(sock, segments):
    """Send a kXR_writev over `segments` = [(fhandle, offset, data)].
    ClientWriteVRequest header: options[1] reserved[15] dlen (dlen frames ONLY
    the write_list descriptors; data streams after). write_list = fhandle[4]
    wlen(i32) offset(i64), 16 bytes packed."""
    desc = b"".join(struct.pack("!4sIq", fh, len(d), off)
                    for (fh, off, d) in segments)
    data = b"".join(d for (_fh, _off, d) in segments)
    hdr = struct.pack("!2sHB15sI", b"\x00\x05", kXR_writev, 0,
                      b"\x00" * 15, len(desc))
    sock.sendall(hdr + desc + data)
    status, body = _read_response(sock)
    errcode = (struct.unpack("!I", body[:4])[0]
               if (status == kXR_error and len(body) >= 4) else None)
    return status, errcode


@pytest.fixture(scope="module")
def node(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    off_port = _free_port()
    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="root-require-pgwrite",
        template="nginx_root_require_pgwrite.conf",
        protocol="root",
        readiness="tcp",
        extra_ports={"OFF_PORT": off_port},
        template_values={"BIND_HOST": BIND_HOST},
    ))
    yield {"on_port": endpoint.port, "off_port": off_port,
           "root": endpoint.data_root}
    harness.close()


def _disk(node, remote):
    return os.path.join(node["root"], remote.lstrip("/"))


def _login(node, port):
    return _handshake_login(host=HOST, port=port)


def test_require_pgwrite_rejects_plain_write(node):
    """[error] With the knob on, a cleartext kXR_write carrying data is refused
    with kXR_Unsupported and nothing lands on disk."""
    sock = _login(node, node["on_port"])
    try:
        fh = _open(sock, b"/plain-refused.bin")
        status, err = _write(sock, fh, 0, os.urandom(4096))
        assert status == kXR_error, f"plain write must be refused, got {status}"
        assert err == kXR_Unsupported, f"expected kXR_Unsupported, got {err}"
    finally:
        sock.close()
    p = _disk(node, "/plain-refused.bin")
    assert (not os.path.exists(p)) or os.path.getsize(p) == 0, \
        "a refused cleartext write must not commit bytes"


def test_require_pgwrite_accepts_pgwrite(node):
    """[success / no false positive] The sanctioned CRC32c path still works: a
    proper kXR_pgwrite commits byte-exact under the knob."""
    sock = _login(node, node["on_port"])
    good = os.urandom(6000)
    try:
        fh = _open(sock, b"/pgwrite-ok.bin")
        st, _off, cse = send_pgwrite(sock, fh, 0, build_payload(good, 0))
        assert st == kXR_status and cse == b"", "clean pgwrite must succeed"
        st, err = _close(sock, fh)
        assert st == kXR_ok, f"clean close must succeed, got {st}/{err}"
    finally:
        sock.close()
    assert open(_disk(node, "/pgwrite-ok.bin"), "rb").read() == good, \
        "pgwrite must commit the exact bytes"


def test_require_pgwrite_rejects_writev(node):
    """[security-neg] kXR_writev is the sibling non-CRC op; it must not sneak past
    the gate — a data-carrying vector is refused with kXR_Unsupported, no bytes."""
    sock = _login(node, node["on_port"])
    try:
        fh = _open(sock, b"/writev-refused.bin")
        status, err = _writev(sock, [(fh, 0, os.urandom(2048))])
        assert status == kXR_error, f"writev must be refused, got {status}"
        assert err == kXR_Unsupported, f"expected kXR_Unsupported, got {err}"
    finally:
        sock.close()
    p = _disk(node, "/writev-refused.bin")
    assert (not os.path.exists(p)) or os.path.getsize(p) == 0, \
        "a refused writev must not commit bytes"


def test_plain_write_allowed_when_knob_off(node):
    """[opt-in proof] On the OFF_PORT server (knob absent = default off) the very
    same cleartext kXR_write is accepted and commits byte-exact — proving the gate
    is genuinely opt-in, not a global behaviour change."""
    sock = _login(node, node["off_port"])
    data = os.urandom(4096)
    try:
        fh = _open(sock, b"/plain-allowed.bin")
        status, err = _write(sock, fh, 0, data)
        assert status == kXR_ok, f"plain write must succeed off-knob, got {status}/{err}"
        st, err = _close(sock, fh)
        assert st == kXR_ok, f"close must succeed, got {st}/{err}"
    finally:
        sock.close()
    assert open(_disk(node, "/plain-allowed.bin"), "rb").read() == data, \
        "default-off plain write must commit the exact bytes"
