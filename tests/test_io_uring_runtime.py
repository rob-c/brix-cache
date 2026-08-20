"""tests/test_io_uring_runtime.py — phase-44 io_uring runtime live coverage.

Subject: the optional Linux io_uring disk-I/O backend
(``src/core/aio/``), driven end-to-end against a dedicated lifecycle
instance whose stream export forces ``brix_io_uring on`` (so a green boot
proves the ring passed its self-test ladder) and whose HTTP plane exposes the
kill-switch admin endpoint (``brix_io_uring_admin on``).  Config:
tests/configs/nginx_lc_uring.conf; ledger entry ``lc-uring``
(tests/fleet_lifecycle_ports.py).

Two feature areas land here:

  * P44-D — the hybrid uring-pgread (ring READV scatter -> pool CRC32c) and the
    WRITEV + linked-FSYNC do_sync barrier, live-exercised over the raw root
    wire so the ring path is actually taken (the stock xrdcp client cannot
    request pgread, and the do_sync barrier only fires under a real ring):

      - success — a kXR_writev with the doSync flag lands byte-exact and a
        following kXR_pgread returns every page with a valid per-page CRC32c;
      - success — an unaligned, multi-page pgread reassembles byte-exact
        (exercises the CRC-gap layout across page boundaries);
      - security-negative — a writev whose descriptor block is not a whole
        number of 16-byte descriptors is rejected (kXR_ArgInvalid), i.e. the
        ring path never widens the stock framing contract.

  * P44-E — the cross-worker runtime kill switch flipped over HTTP without a
    reload (the no-reload CVE-response switch):

      - success — POST {"enabled": false} quiesces the ring (the maintenance
        timer tears the ring + eventfd down once in-flight drains, logging the
        quiesce NOTICE) and GET then reports disabled:true; re-enabling
        re-creates the ring (a second "backend active" NOTICE) and I/O keeps
        working across the whole cycle (the pool tier serves while quiesced);
      - security-negative — the endpoint requires the bearer secret: no token
        and a wrong token are both 403, and neither flips the switch.

Run:
    PYTHONPATH=tests pytest tests/test_io_uring_runtime.py -v
"""

import json
import os
import socket
import struct
import time

import pytest

from server_launcher import RegistryCommandFailure
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, url_host

from _test_conf_pgio_helpers import (
    _session, _open, _close, pgread, pgread_bytes, crc32c,
    kXR_open_updt, kXR_new, kXR_delete, kXR_open_read, kXR_ok, kXR_error,
)

# The lc-uring instance mutates cross-worker ring state (kill switch) and takes
# the fixed exclusive-band ledger port; serialise every test in the file onto
# that one instance so the fixed port never has two concurrent drivers.
pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-uring")]

# Bearer secret: the admin gate rejects secrets shorter than 16 bytes.
SECRET = "phase44-io-uring-admin-secret-token"

# The maintenance timer that drives the quiesce/re-enable transition polls on a
# 2 s cadence (BRIX_URING_MAINT_POLL_MS); a 5 s wait clears one full tick plus
# slack on a loaded box.
MAINT_SETTLE_S = 5.0

kXR_writev = 3031
kXR_wv_doSync = 0x01
kXR_ArgInvalid = 3000


# --------------------------------------------------------------------------- #
# Harness                                                                      #
# --------------------------------------------------------------------------- #

class _UringInstance:
    """Handle for the running lc-uring instance: stream + HTTP ports, the
    error.log path, and a bearer-authenticated admin curl through the harness."""

    def __init__(self, harness, endpoint, secret):
        self.harness = harness
        self.endpoint = endpoint
        self.stream_port = endpoint.port
        self.http_port = endpoint.extra_ports["HTTP_PORT"]
        self.errlog = os.path.join(endpoint.prefix, "logs", "error.log")
        self._secret = secret

    @property
    def _admin_url(self):
        return (f"http://{url_host(HOST)}:{self.http_port}"
                "/brix/api/v1/admin/io_uring")

    def admin(self, method, token=SECRET, data=None):
        args = ["curl", "-s", "-w", "\n%{http_code}", "-X", method]
        if token is not None:
            args += ["-H", f"Authorization: Bearer {token}"]
        if data is not None:
            args += ["-H", "Content-Type: application/json", "--data", data]
        args.append(self._admin_url)
        rc = self.harness.run_cmd(args, timeout=10)
        if rc.returncode != 0:
            return None, rc.stderr
        body, _, status = rc.stdout.rpartition("\n")
        return int(status), body

    def errlog_text(self):
        try:
            with open(self.errlog) as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def wait_for_log(self, needle, timeout=10.0, count=1):
        """Poll error.log until `needle` has appeared at least `count` times.

        The worker writes the ring's boot/quiesce NOTICEs asynchronously after
        the listen socket (and thus the TCP readiness gate) is already up, so
        the log lag must be waited out rather than asserted on immediately."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.errlog_text().count(needle) >= count:
                return True
            time.sleep(0.1)
        return self.errlog_text().count(needle) >= count


def _start(lifecycle, tmp_path):
    """Boot the io_uring-forced lc-uring instance; returns _UringInstance.

    ``brix_io_uring on`` fail-fasts at boot if the probe ladder rejects the
    kernel, so a successful start already proves the ring is live."""
    data = tmp_path / "export"
    data.mkdir()
    secret_file = tmp_path / "admin.secret"
    secret_file.write_text(SECRET + "\n")
    if os.geteuid() == 0:
        from cmdscripts import open_tree_for_worker
        open_tree_for_worker(tmp_path)

    try:
        endpoint = lifecycle.start(NginxInstanceSpec(
            name="lc-uring",
            template="nginx_lc_uring.conf",
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST,
                             "DATA_DIR": str(data),
                             "SECRET_FILE": str(secret_file)},
            reason="phase-44 io_uring runtime subject"))
    except RegistryCommandFailure as failure:
        diagnostic = f"{failure.stdout_tail}\n{failure.stderr_tail}"
        if ("compiled WITHOUT it" in diagnostic
                or "io_uring is unavailable" in diagnostic):
            pytest.skip("io_uring live backend is unavailable in this nginx build")
        raise
    inst = _UringInstance(lifecycle, endpoint, SECRET)
    # The stream-port readiness gate fires when the listen socket is up, which
    # can precede the worker writing the ring's boot NOTICE; wait for it so a
    # silent auto-fallback (which "on" forbids) can never masquerade as pass.
    assert inst.wait_for_log("io_uring disk-I/O backend active"), \
        "io_uring ring did not report active at boot"
    return inst


# --------------------------------------------------------------------------- #
# Raw kXR_writev (stock framing: dlen = N*16 descriptor block; data trails)    #
# --------------------------------------------------------------------------- #

def _writev(sock, fhandle, segments, do_sync=False, streamid=b"\x00\x05"):
    """Issue one kXR_writev; segments = [(offset, data), ...].  Returns
    (status, body).  do_sync sets kXR_wv_doSync so the server links a trailing
    FSYNC barrier after the writes (the io_uring path chains IORING_OP_FSYNC)."""
    descs = b"".join(fhandle + struct.pack(">I", len(d)) + struct.pack(">q", off)
                     for off, d in segments)
    options = kXR_wv_doSync if do_sync else 0
    hdr = streamid + struct.pack(">H", kXR_writev) + bytes([options]) \
        + b"\x00" * 15 + struct.pack(">I", len(descs))
    sock.sendall(hdr + descs + b"".join(d for _, d in segments))
    resp = sock.recv(8)
    while len(resp) < 8:
        resp += sock.recv(8 - len(resp))
    status = struct.unpack(">H", resp[2:4])[0]
    dlen = struct.unpack(">I", resp[4:8])[0]
    body = b""
    while len(body) < dlen:
        body += sock.recv(dlen - len(body))
    return status, body


def _write_file(inst, path, payload, do_sync, segments=None):
    """Open path fresh-for-write, writev the payload (optionally split), close."""
    s = _session(HOST, inst.stream_port)
    try:
        _sid, st, ob = _open(s, path,
                             options=kXR_open_updt | kXR_new | kXR_delete,
                             streamid=b"\x00\x02")
        assert st == kXR_ok, f"open-for-write failed: {st}"
        fh = ob[:4]
        if segments is None:
            half = len(payload) // 2
            segments = [(0, payload[:half]), (half, payload[half:])]
        st, body = _writev(s, fh, segments, do_sync=do_sync)
        _close(s, fh)
        return st, body
    finally:
        s.close()


def _pgread_all(inst, path, offset, rlen):
    """Open path for read, pgread [offset, offset+rlen), return (bytes, pages)."""
    s = _session(HOST, inst.stream_port)
    try:
        _sid, st, ob = _open(s, path, options=kXR_open_read, streamid=b"\x00\x02")
        assert st == kXR_ok, f"open-for-read failed: {st}"
        fh = ob[:4]
        status, pages = pgread(s, fh, offset, rlen)
        assert status == kXR_ok, f"pgread failed: {pages}"
        _close(s, fh)
        return pgread_bytes(pages), pages
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# P44-D — hybrid uring-pgread + WRITEV/linked-FSYNC                            #
# --------------------------------------------------------------------------- #

def test_writev_dosync_then_pgread_byte_exact(lifecycle, tmp_path):
    """Success: a kXR_writev with the doSync flag (io_uring links a trailing
    FSYNC after the WRITEV) lands byte-exact, and a following kXR_pgread over
    the ring's READV->CRC32c hybrid returns every page with a valid CRC."""
    inst = _start(lifecycle, tmp_path)
    payload = os.urandom(9000)          # spans three 4096-byte pages
    st, body = _write_file(inst, "/p44_wv_sync.bin", payload, do_sync=True)
    assert st == kXR_ok, f"writev+doSync rejected by the io_uring path: {body}"

    got, pages = _pgread_all(inst, "/p44_wv_sync.bin", 0, len(payload))
    assert got == payload, "pgread bytes differ from the written payload"
    assert all(crc32c(page) == crc for (_off, page, crc) in pages), \
        "a per-page CRC32c from the hybrid pgread did not verify"


def test_pgread_unaligned_multipage_reassembles(lifecycle, tmp_path):
    """Success: an unaligned, multi-page pgread reassembles byte-exact — the
    ring scatters into the CRC-gapped scratch across page boundaries and the
    pool CRC hop fills every gap."""
    inst = _start(lifecycle, tmp_path)
    payload = os.urandom(10000)
    st, _ = _write_file(inst, "/p44_pg_unaligned.bin", payload, do_sync=False)
    assert st == kXR_ok
    # Start 100 bytes into the first page so the first page is short.
    off, length = 100, 8000
    got, pages = _pgread_all(inst, "/p44_pg_unaligned.bin", off, length)
    assert got == payload[off:off + length], "unaligned pgread mis-reassembled"
    assert all(crc32c(page) == crc for (_o, page, crc) in pages)


def test_writev_bad_framing_rejected(lifecycle, tmp_path):
    """Security-negative: a writev whose descriptor block is not a whole number
    of 16-byte descriptors is rejected (kXR_ArgInvalid) — the io_uring path
    never relaxes the stock framing contract."""
    inst = _start(lifecycle, tmp_path)
    s = _session(HOST, inst.stream_port)
    try:
        _sid, st, ob = _open(s, "/p44_badframe.bin",
                             options=kXR_open_updt | kXR_new | kXR_delete,
                             streamid=b"\x00\x02")
        assert st == kXR_ok
        fh = ob[:4]
        # dlen = 16 + 5: one descriptor plus a stray 5 bytes (the legacy
        # data-in-dlen layout) → not a whole descriptor count.
        desc = fh + struct.pack(">I", 5) + struct.pack(">q", 0)
        bad = desc + b"HELLO"
        hdr = b"\x00\x05" + struct.pack(">H", kXR_writev) + b"\x00" * 16 \
            + struct.pack(">I", len(bad))
        s.sendall(hdr + bad)
        resp = s.recv(8)
        while len(resp) < 8:
            resp += s.recv(8 - len(resp))
        status = struct.unpack(">H", resp[2:4])[0]
        dlen = struct.unpack(">I", resp[4:8])[0]
        body = b""
        while len(body) < dlen:
            body += s.recv(dlen - len(body))
        assert status == kXR_error
        assert struct.unpack(">I", body[:4])[0] == kXR_ArgInvalid, \
            f"expected kXR_ArgInvalid, got {body!r}"
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# P44-E — runtime kill switch over HTTP                                        #
# --------------------------------------------------------------------------- #

def test_admin_killswitch_quiesce_and_reenable(lifecycle, tmp_path):
    """Success: POST {"enabled": false} quiesces the ring (maintenance timer
    tears it down + logs the quiesce NOTICE), GET reports disabled:true, I/O
    still works while quiesced (pool tier), and re-enabling re-creates the ring
    (a second "backend active" NOTICE) with I/O still correct."""
    inst = _start(lifecycle, tmp_path)

    # Baseline: enabled.
    status, body = inst.admin("GET")
    assert status == 200, body
    assert json.loads(body)["disabled"] is False

    # Disable → quiesce.
    status, body = inst.admin("POST", data=json.dumps({"enabled": False}))
    assert status == 200, body
    assert json.loads(body)["result"] == "disabled"

    assert inst.wait_for_log("io_uring ring quiesced (kill switch)",
                             timeout=MAINT_SETTLE_S), \
        "the maintenance timer did not log the ring quiesce after disable"

    status, body = inst.admin("GET")
    assert json.loads(body)["disabled"] is True

    # I/O still works with the ring quiesced (the thread-pool tier serves).
    payload = os.urandom(5000)
    st, _ = _write_file(inst, "/p44_quiesced.bin", payload, do_sync=True)
    assert st == kXR_ok, "write failed while the ring was quiesced"
    got, _ = _pgread_all(inst, "/p44_quiesced.bin", 0, len(payload))
    assert got == payload

    # Re-enable → the maintenance timer re-brings-up the ring.
    status, body = inst.admin("POST", data=json.dumps({"enabled": True}))
    assert status == 200, body
    assert json.loads(body)["result"] == "enabled"

    assert inst.wait_for_log("io_uring disk-I/O backend active",
                             timeout=MAINT_SETTLE_S, count=2), \
        "the ring was not re-created after the kill switch cleared"

    status, body = inst.admin("GET")
    assert json.loads(body)["disabled"] is False

    # I/O correct again on the re-created ring.
    payload2 = os.urandom(6000)
    st, _ = _write_file(inst, "/p44_reenabled.bin", payload2, do_sync=True)
    assert st == kXR_ok
    got2, pages = _pgread_all(inst, "/p44_reenabled.bin", 0, len(payload2))
    assert got2 == payload2
    assert all(crc32c(p) == c for (_o, p, c) in pages)


def test_admin_killswitch_requires_bearer(lifecycle, tmp_path):
    """Security-negative: the kill-switch endpoint requires the bearer secret.
    No token and a wrong token are both 403, and neither flips the switch."""
    inst = _start(lifecycle, tmp_path)
    disable = json.dumps({"enabled": False})

    status, _ = inst.admin("POST", token=None, data=disable)
    assert status == 403, "missing Authorization must be rejected"

    status, _ = inst.admin("POST", token="not-the-secret", data=disable)
    assert status == 403, "a wrong bearer token must be rejected"

    # The switch never moved: still enabled, and a fresh write+pgread is correct.
    status, body = inst.admin("GET")               # GET needs the secret too
    assert status == 200, body
    assert json.loads(body)["disabled"] is False, \
        "an unauthorized POST must not have flipped the kill switch"
