"""Phase-115 W3.1 — the root:// residency gate recalls what it used to park on.

One symptom hid three defects: every read of a tape-resident object under
``brix_frm on`` answered ``file is offline (recall failed)``.

* ``sd_frm_residency`` passed the MSS adapter's OFFLINE ("on tape; a recall
  will fault it in") through as the storage-driver OFFLINE ("not retrievable
  right now"), the terminal class the open gate refuses outright.
* The gate recorded a stage request and parked the client, but nothing drove
  the recall — the former ``frm_stage_kick`` survived only as a comment — so a
  parked open never woke.
* The frm driver advertised CAP_RANDOM_WRITE with no pwrite slot, so every
  root:// write-open took the in-place route ``sd_frm_open`` refuses with
  EROFS ("read-only export") instead of the staged adapter.

This module pins the repaired contract over the stub adapter: a tape-only
object is served on its first open with no wait when the adapter recalls
synchronously; an asynchronous adapter parks the client with kXR_wait and the
retry is served; writes land through the staged adapter and migrate to tape;
a missing key is NotFound; a read-only export still recalls for reads but
refuses the write; and no recall ever reaches outside the tape base.

Also pinned: the helper's kXR opcode constants match src/protocols/root/
protocol/opcodes.h — ``kXR_write`` carried kXR_stat's value (3017) for months,
so "writes" over the helper stat'ed the handle and landed nothing.
"""

import os
import re
import struct
import time
from pathlib import Path

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec

import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-recall")]

OPCODES_H = Path(__file__).resolve().parents[1] / "src/protocols/root/protocol/opcodes.h"

kXR_open_updt = 0x0020
kXR_mkpath = 0x0100
kXR_sync = 3016
kXR_ItExists = 3018
kXR_NotFound = 3011
kXR_ArgInvalid = 3000
kXR_NotAuthorized = 3010
kXR_fsReadOnly = 3025


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _launch(lifecycle, tmp_path, allow_write="on", recall_delay_ms=0):
    """A tape:// stub backend behind the W3.2 template; the stub's recall is
    synchronous unless ``recall_delay_ms`` > 0 (async marker + poll)."""
    export = tmp_path / "export"
    export.mkdir(exist_ok=True)
    for sub in ("cache", "control", "tape"):
        (tmp_path / sub).mkdir(exist_ok=True)
    return lifecycle.start(NginxInstanceSpec(
        name="lc-p115-recall",
        template="nginx_p115_tape_purge.conf",
        data_root=str(export),
        env={"BRIX_CACHE_REAP_FIRST_MS": "600000",
             "BRIX_FRM_STUB_RECALL_DELAY_MS": str(recall_delay_ms)},
        template_values={
            "BIND_HOST": BIND_HOST,
            "BACKEND": f"tape://{tmp_path}/tape",
            "CACHE_DIR": str(tmp_path / "cache"),
            "QUEUE_PATH": str(tmp_path / "frm.queue"),
            "CONTROL_DIR": str(tmp_path / "control"),
            "PURGE_LINES": "",
            "ALLOW_WRITE": allow_write,
        },
        reason="phase-115 W3.1 tape residency gate"))


def _session(port):
    H.ANON_HOST = BIND_HOST
    return H._establish_primary(port)


def _err(body):
    return struct.unpack(">i", body[:4])[0], body[4:].rstrip(b"\x00").decode(errors="replace")


def _open_once(sock, stream, path, flags):
    """One raw kXR_open (no kXR_wait handling) — the first-open verdict."""
    body = struct.pack(">HH", 0o644, flags) + b"\x00" * 12
    return H._send_req(sock, stream, H.kXR_open, body=body, payload=path.encode() + b"\x00")


def _read_after(sock, stream, path, length):
    """Open (honouring kXR_wait) + read; (status, data-or-error-body)."""
    status, body = H._open_waiting(sock, stream, path, H.kXR_open_read)
    if status != H.kXR_ok:
        return status, body
    return H._read_handle(sock, stream, body[:4], length)


def _put(port, path, data):
    """(status, body) of the first failing step of open/write/close, else the
    kXR_close reply."""
    sock, _sessid, stream = _session(port)
    try:
        status, body = H._open_waiting(sock, stream, path,
                                       H.kXR_new | kXR_open_updt | kXR_mkpath)
        if status != H.kXR_ok:
            return status, body
        fhandle = body[:4]
        wbody = fhandle + struct.pack(">q", 0) + b"\x00" * 4
        status, body = H._send_req(sock, stream, H.kXR_write, body=wbody, payload=data)
        if status != H.kXR_ok:
            return status, body
        return H._send_req(sock, stream, H.kXR_close, body=fhandle + b"\x00" * 12)
    finally:
        sock.close()


def _open_new_and_write(sock, stream, path, data):
    """kXR_new open + one write; the fhandle (the commit is the caller's)."""
    status, body = H._open_waiting(sock, stream, path,
                                   H.kXR_new | kXR_open_updt | kXR_mkpath)
    assert status == H.kXR_ok, f"open {path}: status {status} {body!r}"
    fhandle = body[:4]
    wbody = fhandle + struct.pack(">q", 0) + b"\x00" * 4
    status, body = H._send_req(sock, stream, H.kXR_write, body=wbody, payload=data)
    assert status == H.kXR_ok, f"write {path}: status {status} {body!r}"
    return fhandle


def _plant(tmp_path, name, data):
    """A tape-only copy: present under <base>/<name>, absent from .online."""
    (tmp_path / "tape").mkdir(exist_ok=True)
    (tmp_path / "tape" / name).write_bytes(data)
    assert not (tmp_path / "tape" / ".online" / name).exists()


def _online(tmp_path, name):
    return tmp_path / "tape" / ".online" / name


# --------------------------------------------------------------------------
# success
# --------------------------------------------------------------------------

def test_tape_only_object_is_served_on_first_open(lifecycle, tmp_path):
    """(success) a synchronous adapter brings the object online inside the
    open: no kXR_wait, no error, byte-exact data, and the online copy exists."""
    data = os.urandom(3000)
    _plant(tmp_path, "a.bin", data)
    ep = _launch(lifecycle, tmp_path)
    sock, _sessid, stream = _session(ep.port)
    try:
        status, body = _open_once(sock, stream, "/a.bin", H.kXR_open_read)
        assert status == H.kXR_ok, f"first open: status {status} {body!r}"
        status, got = H._read_handle(sock, stream, body[:4], len(data))
    finally:
        sock.close()
    assert (status, got) == (H.kXR_ok, data)
    assert _online(tmp_path, "a.bin").read_bytes() == data


def test_async_adapter_parks_the_open_then_serves_it(lifecycle, tmp_path):
    """(success) with the stub recalling asynchronously the first open is
    answered kXR_wait carrying brix_frm_stage_wait (1 s); retrying the same
    open until the recall lands serves the bytes."""
    data = os.urandom(2048)
    _plant(tmp_path, "slow.bin", data)
    ep = _launch(lifecycle, tmp_path, recall_delay_ms=1500)
    sock, _sessid, stream = _session(ep.port)
    try:
        status, body = _open_once(sock, stream, "/slow.bin", H.kXR_open_read)
        assert status == H.kXR_wait, f"first open: status {status} {body!r}"
        assert struct.unpack(">i", body[:4])[0] == 1, body
        assert (tmp_path / "tape" / ".recalling" / "slow.bin").exists()
        t0 = time.monotonic()
        status, got = _read_after(sock, stream, "/slow.bin", len(data))
    finally:
        sock.close()
    assert (status, got) == (H.kXR_ok, data)
    assert time.monotonic() - t0 >= 1.0, "served before the adapter's delay elapsed"
    assert not (tmp_path / "tape" / ".recalling" / "slow.bin").exists()
    assert _online(tmp_path, "slow.bin").read_bytes() == data


def test_write_lands_via_the_staged_adapter_and_migrates(lifecycle, tmp_path):
    """(success) a root:// write-open no longer hits the frm driver's EROFS:
    the staged adapter takes it, the close migrates to tape and the online
    buffer, and a read-back is byte-exact."""
    data = os.urandom(4096)
    ep = _launch(lifecycle, tmp_path)
    status, body = _put(ep.port, "/w.bin", data)
    assert status == H.kXR_ok, f"put: status {status} {body!r}"
    assert (tmp_path / "tape" / "w.bin").read_bytes() == data
    assert _online(tmp_path, "w.bin").read_bytes() == data
    sock, _sessid, stream = _session(ep.port)
    try:
        assert _read_after(sock, stream, "/w.bin", len(data)) == (H.kXR_ok, data)
    finally:
        sock.close()


def _opcodes_in_header():
    text = OPCODES_H.read_text()
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r"^#define (kXR_\w+)\s+(\d+)", text, re.M)}


def _opcodes_in_helper(defined):
    return {n: v for n, v in vars(H).items()
            if n.startswith("kXR_") and isinstance(v, int) and n in defined}


def test_helper_opcodes_match_the_module_header():
    """(success, static) every kXR_* opcode / status the bind helper carries
    is the value opcodes.h defines — the 3017-for-write mix-up cannot recur."""
    defined = _opcodes_in_header()
    ours = _opcodes_in_helper(defined)
    assert "kXR_write" in ours and "kXR_wait" in ours
    assert {n: defined[n] for n in ours} == ours


def _read_via_new_session(port, path, length):
    """(status, data-or-error-body) of an open+read on a fresh session."""
    sock, _sessid, stream = _session(port)
    try:
        return _read_after(sock, stream, path, length)
    finally:
        sock.close()


def _wait_gone(path, timeout=5.0):
    deadline = time.time() + timeout
    while path.exists() and time.time() < deadline:
        time.sleep(0.1)
    return not path.exists()


def _assert_refused_it_exists(status, body):
    assert status == H.kXR_error, (status, body)
    code, text = _err(body)
    assert code == kXR_ItExists and "exists" in text.lower(), (code, text)


# --------------------------------------------------------------------------
# error
# --------------------------------------------------------------------------

def test_missing_key_is_not_found(lifecycle, tmp_path):
    """(error) a key on neither tape nor the online buffer is kXR_NotFound,
    not "offline (recall failed)"."""
    ep = _launch(lifecycle, tmp_path)
    sock, _sessid, stream = _session(ep.port)
    try:
        status, body = _open_once(sock, stream, "/nope.bin", H.kXR_open_read)
    finally:
        sock.close()
    assert status == H.kXR_error and _err(body)[0] == kXR_NotFound, (status, body)
    assert not _online(tmp_path, "nope.bin").exists()


def test_read_only_export_still_recalls_for_reads(lifecycle, tmp_path):
    """(error path, policy) the stage policy's EROFS on a read-only export
    must not fail a read: the gate defers to the cache tier's fill-time
    recall and the tape-only object is served."""
    data = os.urandom(1500)
    _plant(tmp_path, "ro.bin", data)
    ep = _launch(lifecycle, tmp_path, allow_write="off")
    sock, _sessid, stream = _session(ep.port)
    try:
        assert _read_after(sock, stream, "/ro.bin", len(data)) == (H.kXR_ok, data)
    finally:
        sock.close()
    assert _online(tmp_path, "ro.bin").read_bytes() == data


@pytest.mark.parametrize("commit_op", ["close", "sync"])
def test_kxr_new_commit_refuses_a_key_that_reached_tape_meanwhile(lifecycle, tmp_path, commit_op):
    """(error) kXR_new carries create-if-absent to the COMMIT.  The frm driver
    judged it by the adapter's residency, which always saw the handle's own
    online buffer: every create was refused EEXIST.  It now asks the durable
    copy (on_tape): a key that reached tape between open and commit is
    refused kXR_ItExists — the errno reaches the wire through close and sync
    alike, where close used to blanket "staged commit failed" as IOError —
    and the buffer is purged, the tape copy untouched."""
    ep = _launch(lifecycle, tmp_path)
    sock, _sessid, stream = _session(ep.port)
    try:
        fhandle = _open_new_and_write(sock, stream, "/race.bin", b"mine")
        (tmp_path / "tape" / "race.bin").write_bytes(b"theirs")   # another writer wins
        op = H.kXR_close if commit_op == "close" else kXR_sync
        status, body = H._send_req(sock, stream, op, body=fhandle + b"\x00" * 12)
    finally:
        sock.close()
    _assert_refused_it_exists(status, body)
    assert (tmp_path / "tape" / "race.bin").read_bytes() == b"theirs"
    assert _wait_gone(_online(tmp_path, "race.bin")), "refused buffer survived"
    # The VFS abort used to purge only the POSIX temp: the driver's online
    # buffer stayed under the final key and shadowed the tape copy, so this
    # read returned "mine" from the writer that had just been refused.
    assert _read_via_new_session(ep.port, "/race.bin", 64) == (H.kXR_ok, b"theirs")


def test_disconnected_upload_leaves_no_object(lifecycle, tmp_path):
    """(error) a client that vanishes mid-upload — write, no close — must leave
    nothing: the handle teardown aborts the staged writer, and that abort now
    reaches the driver, so the partial online buffer is purged instead of
    surviving under the final key as a live, truncated object."""
    ep = _launch(lifecycle, tmp_path)
    sock, _sessid, stream = _session(ep.port)
    _open_new_and_write(sock, stream, "/partial.bin", b"half")
    assert _online(tmp_path, "partial.bin").exists()   # buffered while open
    sock.close()                                       # no close / sync
    assert _wait_gone(_online(tmp_path, "partial.bin")), "partial buffer survived"
    assert not (tmp_path / "tape" / "partial.bin").exists()
    status, body = _read_via_new_session(ep.port, "/partial.bin", 64)
    assert status == H.kXR_error and _err(body)[0] == kXR_NotFound, (status, body)


# --------------------------------------------------------------------------
# security-negative
# --------------------------------------------------------------------------

def test_read_only_export_refuses_the_write(lifecycle, tmp_path):
    """(security-neg) with brix_allow_write off a write-open is refused with
    kXR_fsReadOnly and nothing reaches tape or the online buffer."""
    ep = _launch(lifecycle, tmp_path, allow_write="off")
    status, body = _put(ep.port, "/x.bin", b"never")
    assert status == H.kXR_error, (status, body)
    assert _err(body)[0] == kXR_fsReadOnly, _err(body)
    assert not (tmp_path / "tape" / "x.bin").exists()
    assert not _online(tmp_path, "x.bin").exists()


def test_recall_never_leaves_the_tape_base(lifecycle, tmp_path):
    """(security-neg) a traversal key beside the tape base is refused (never
    served) and no recall copies the victim into the online buffer."""
    victim = tmp_path / "victim.bin"
    victim.write_bytes(b"outside the base")
    ep = _launch(lifecycle, tmp_path)
    sock, _sessid, stream = _session(ep.port)
    try:
        status, body = _read_after(sock, stream, "/../victim.bin", 16)
    finally:
        sock.close()
    assert status == H.kXR_error, (status, body)
    assert _err(body)[0] in (kXR_NotFound, kXR_ArgInvalid, kXR_NotAuthorized), _err(body)
    assert not _online(tmp_path, "victim.bin").exists()
    assert not (tmp_path / ".online").exists()
    assert victim.read_bytes() == b"outside the base"
