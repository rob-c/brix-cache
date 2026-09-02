"""
tests/test_vfs_evict.py

W6 (phase-107 C2) — the kXR_prepare EVICT arm through brix_vfs_evict, and the
FRM-1 ownership negatives shared with cancel.

Until W6 the kXR_prepare evict option was a documented no-op.  On the same
frm://exec nearline subject as tests/test_prepare_recall.py this proves:

  * kXR_prepare(optionX=kXR_evict) releases the ONLINE-BUFFER copy through the
    cache decorator's relay down to the frm leaf — the tape copy stays the
    durable one, the retired registry record stops QPrep reporting a stale
    'A', and the bytes-released INFO line is emitted;
  * evict of a nearline-but-not-online path is IDEMPOTENT advisory success
    (sd_frm_evict: OFFLINE -> NGX_OK, 0 bytes) — never an error, never a
    driver recall;
  * security-negative: ``brix_allow_write off`` refuses evict with
    kXR_fsReadOnly BEFORE the scan — no driver call, no record disclosure
    (evict is a typed export mutation, MUTATE_EVICT);
  * security-negative (FRM-1): identity B cannot evict or cancel identity A's
    staged path/reqid — kXR_NotAuthorized, record untouched (a later prepare
    by A still JOINS the same reqid); after A's own cancel the record is
    CANCELLED, kept, and never absorbs a fresh prepare (new reqid).

Two anonymous logins are DISTINCT owners (brix_prepare_owner_key scopes
anonymous callers to their login session id), so the FRM-1 negatives need no
token machinery.  Subjects: ``lc-prepare-own`` (writable) and
``lc-prepare-recall-ro`` — both on the lifecycle ledger, serialised with
tests/test_prepare_recall.py via the shared xdist group.
"""

import os
import pathlib

import pytest

from _test_prepare_recall_helpers import (
    kXR_stage, kXR_noerrs, kXR_cancel, kXR_evict, kXR_ok, kXR_error,
    kXR_fsReadOnly, kXR_NotAuthorized,
    _session, _prepare, _qprep_status, _err_of, _audit_verbs, _start_frm,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-prepare-recall")]


@pytest.fixture
def frm(lifecycle, tmp_path):
    yield _start_frm(lifecycle, tmp_path, name="lc-prepare-own")


@pytest.fixture
def frm_ro(lifecycle, tmp_path):
    yield _start_frm(lifecycle, tmp_path, name="lc-prepare-recall-ro",
                     allow_write="off")


def _stage(sock, path):
    status, body = _prepare(sock, [path], kXR_stage | kXR_noerrs)
    assert status == kXR_ok, f"stage failed: {status} {body!r}"
    return body.rstrip(b"\x00").decode()


def _evict(sock, path, streamid=b"\x00\x05"):
    return _prepare(sock, [path], kXR_noerrs, optionx=kXR_evict,
                    streamid=streamid)


def test_evict_drops_online_copy_and_keeps_tape(frm):
    """success: evict releases the recalled online-buffer copy through
    brix_vfs_evict, retires the registry record, and keeps the tape copy."""
    s = _session(frm.port)
    reqid = _stage(s, "/near.dat")
    online = os.path.join(frm.online, "near.dat")
    assert os.path.exists(online), "stage did not recall the online copy"

    status, body = _evict(s, "/near.dat")
    assert status == kXR_ok, f"evict failed: {status} {body!r}"

    assert not os.path.exists(online), "evict left the online-buffer copy"
    # QPrep answers from residency truth, not a stale DONE record: the file
    # is nearline-offline again and the record was deleted -> 'M'.
    assert _qprep_status(s, reqid, "/near.dat") == "M"
    s.close()

    log = pathlib.Path(frm.prefix, "logs", "error.log")
    assert "bytes released" in log.read_text(errors="replace"), \
        "the evict INFO accounting line was not emitted"


def test_evict_offline_path_is_idempotent_ok(frm):
    """success: evicting a nearline path that was never recalled is advisory
    success (sd_frm_evict OFFLINE -> NGX_OK), and drives no recall."""
    s = _session(frm.port)
    status, body = _evict(s, "/cold.dat")
    assert status == kXR_ok, f"idempotent evict failed: {status} {body!r}"
    s.close()

    assert not os.path.exists(os.path.join(frm.online, "cold.dat"))
    assert not _audit_verbs(frm.audit, "recall"), \
        "evict of an offline path drove a recall"


def test_read_only_refuses_evict_before_driver(frm_ro):
    """security-negative: brix_allow_write off -> kXR_fsReadOnly for evict,
    BEFORE the scan — the MSS adapter is never consulted."""
    s = _session(frm_ro.port)
    status, body = _evict(s, "/near.dat")
    assert status == kXR_error, f"read-only server accepted an evict: {status}"
    code, msg = _err_of(body)
    assert code == kXR_fsReadOnly, (code, msg)   # EROFS, never EACCES
    s.close()

    assert not _audit_verbs(frm_ro.audit), \
        "read-only refusal still reached the MSS adapter"


def test_foreign_session_cannot_evict_or_cancel(frm):
    """security-negative (FRM-1): identity B can neither evict identity A's
    staged path nor cancel A's reqid — kXR_NotAuthorized, record untouched.
    After A's OWN cancel the record is CANCELLED, kept, and a fresh prepare
    gets a NEW reqid (a retired record never absorbs a join)."""
    a = _session(frm.port)
    b = _session(frm.port)                       # distinct anon owner key
    reqid1 = _stage(a, "/near.dat")
    online = os.path.join(frm.online, "near.dat")
    assert os.path.exists(online)

    status, body = _evict(b, "/near.dat")
    assert status == kXR_error, "foreign session evicted another owner's path"
    code, msg = _err_of(body)
    assert code == kXR_NotAuthorized, (code, msg)
    assert os.path.exists(online), "denied evict still dropped the copy"

    status, body = _prepare(b, [reqid1], kXR_cancel, streamid=b"\x00\x06")
    assert status == kXR_error, "foreign session cancelled another's reqid"
    assert _err_of(body)[0] == kXR_NotAuthorized

    # The record survived both denials: A's re-prepare JOINS the same reqid.
    assert _stage(a, "/near.dat") == reqid1, "denial damaged the live record"

    # A's own cancel: ok, record kept as CANCELLED -> never absorbs a join.
    status, _ = _prepare(a, [reqid1], kXR_cancel, streamid=b"\x00\x07")
    assert status == kXR_ok
    reqid2 = _stage(a, "/near.dat")
    assert reqid2 and reqid2 != reqid1, \
        "a fresh prepare joined a CANCELLED record"
    a.close(); b.close()
