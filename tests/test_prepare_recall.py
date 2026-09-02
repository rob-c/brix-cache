"""
tests/test_prepare_recall.py

W6 (phase-107 C2) — the kXR_prepare STAGE arm through brix_vfs_recall.

Until W6, prestage ran only as the fork/exec ``brix_prepare_command`` while every
wire-native recall slot sat implemented and uncalled.  This proves the new
per-path lifecycle on a real ``frm://exec`` nearline export (no prepare_command:
the DRIVER is the stager) with the durable stage-request registry armed:

  * kXR_prepare(kXR_stage) drives the MSS adapter's ``recall`` verb through
    brix_vfs_recall, returns a durable host-qualified reqid, and kXR_QPrep
    reports 'A' from residency truth once the recall lands;
  * a second prepare for the same path JOINS — same reqid, ONE driver recall;
  * a recall that fails synchronously DELETES the record (record-before-
    driver-call + delete-on-failure): kXR_QPrep answers 'M', never a reqid
    that polls "queued forever";
  * the "nearline but unstageable" refusal (kXR_Unsupported) + startup advisor:
    the shape is unconstructible from a live config (every shipped nearline
    driver implements the recall slot), so the probe's truth table runs as the
    ``vfs_nearline_probe`` C object unit and this file pins the wiring + the
    advisor's silence on a stageable export;
  * security-negative: ``brix_allow_write off`` refuses kXR_stage with
    kXR_fsReadOnly BEFORE anything is recorded (stage is a typed export
    mutation, MUTATE_STAGE — the phase-105 §F.1 closure).

Raw-wire framing follows tests/test_frm_queue.py; provisioning follows
tests/test_frm_scratch.py (cmdscripts.frm_stagecmd).  Self-provisioned, no
fleet dependency.
"""

import os
import pathlib
import re

import pytest

from _test_prepare_recall_helpers import (
    kXR_stage, kXR_noerrs, kXR_ok, kXR_error, kXR_fsReadOnly,
    _session, _prepare, _qprep_status, _err_of, _audit_verbs, _start_frm,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-prepare-recall")]

REPO = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture
def frm(lifecycle, tmp_path):
    yield _start_frm(lifecycle, tmp_path, name="lc-prepare-recall",
                 failkey="bad.dat")


@pytest.fixture
def frm_ro(lifecycle, tmp_path):
    yield _start_frm(lifecycle, tmp_path, name="lc-prepare-recall-ro",
                 allow_write="off")


def test_stage_drives_driver_recall_and_reports_available(frm):
    """success: kXR_prepare(kXR_stage) on an frm export with no prepare_command
    returns a durable reqid and drives the MSS adapter's recall; QPrep then
    reports 'A' from residency truth."""
    s = _session(frm.port)
    status, body = _prepare(s, ["/near.dat"], kXR_stage | kXR_noerrs)
    assert status == kXR_ok, f"prepare failed: {status} {body!r}"
    reqid = body.rstrip(b"\x00").decode()
    assert reqid != "0" and "@" in reqid, f"not a durable reqid: {reqid!r}"

    # The driver recall is synchronous for the exec adapter: the object is in
    # the online buffer and QPrep's residency-first probe answers 'A'.
    assert _qprep_status(s, reqid, "/near.dat") == "A"
    s.close()

    recalls = _audit_verbs(frm.audit, "recall")
    assert [v[1] for v in recalls] == ["near.dat"], recalls
    # exec-adapter online buffer: <base>/.online/<key> (sd_frm_exec.c banner)
    assert os.path.exists(os.path.join(frm.base, ".online", "near.dat")), \
        "recall did not materialise the online-buffer copy"


def test_second_prepare_joins_same_reqid_one_recall(frm):
    """success: a second prepare for the same path JOINS the live record —
    same reqid, and the driver recall ran exactly once."""
    s = _session(frm.port)
    _, body1 = _prepare(s, ["/near.dat"], kXR_stage | kXR_noerrs)
    reqid1 = body1.rstrip(b"\x00").decode()
    _, body2 = _prepare(s, ["/near.dat"], kXR_stage | kXR_noerrs,
                        streamid=b"\x00\x07")
    reqid2 = body2.rstrip(b"\x00").decode()
    s.close()

    assert reqid1 != "0" and reqid1 == reqid2, (reqid1, reqid2)
    recalls = _audit_verbs(frm.audit, "recall")
    assert len(recalls) == 1, f"join re-drove the driver: {recalls}"


def test_failed_recall_deletes_record_no_orphan_reqid(frm):
    """error: a synchronous driver failure deletes the record-before-driver-call
    record — QPrep answers 'M' (unknown), never a 'q' that polls forever."""
    s = _session(frm.port)
    status, body = _prepare(s, ["/bad.dat"], kXR_stage | kXR_noerrs)
    # Best-effort per path (the pre-W6 staging-command contract): the request
    # itself succeeds, the failure is logged and the record deleted.
    assert status == kXR_ok, f"prepare failed hard: {status} {body!r}"
    reqid = body.rstrip(b"\x00").decode()

    # bad.dat is still nearline (recall exited 1) and the record is gone:
    # residency says not-online, the registry holds nothing -> 'M'.
    assert _qprep_status(s, reqid or "0", "/bad.dat") == "M", \
        "failed recall left an orphan registry record"
    s.close()
    assert _audit_verbs(frm.audit, "recall"), "driver recall never attempted"


def test_unstageable_refusal_and_advisor_wiring(frm):
    """error: a nearline export with neither a recall slot nor a
    prepare_command answers kXR_Unsupported, and the startup advisor warns.

    The shape is UNCONSTRUCTIBLE from a live config (every shipped nearline
    driver implements the slot), so the probe's truth table is proven by the
    ``vfs_nearline_probe`` C object unit against synthetic chains; here we pin
    the wiring of both arms and assert the advisor's SILENCE on this genuinely
    stageable export (the warning must never fire spuriously)."""
    recall_c = (REPO / "src/protocols/root/query/prepare_recall.c").read_text()
    assert "kXR_Unsupported" in recall_c
    assert "brix_vfs_nearline_export" in recall_c, \
        "the refusal no longer keys on nearline-ness"

    init_c = (REPO / "src/core/config/process_server_init.c").read_text()
    assert "brix_vfs_chain_nearline_unstageable" in init_c, \
        "the startup advisor no longer calls the VFS probe"
    assert "brix_init_server_stage_advisor" in init_c
    assert re.search(r"nearline but no tier .*implements recall", init_c,
                     re.DOTALL), "the advisor warning text changed"

    log = pathlib.Path(frm.prefix, "logs", "error.log")
    assert log.exists()
    assert "is nearline but no tier" not in log.read_text(errors="replace"), \
        "advisor warned on an export whose chain CAN recall"


def test_vfs_nearline_probe_c_unit(tmp_path):
    """The advisor probe's truth table on synthetic driver chains (the only
    place the unstageable shape is constructible) — real vfs_recall.o."""
    from cmdscripts import c_object_units
    (ok, out), = c_object_units.run_checks(tmp_path, ["vfs_nearline_probe"])
    assert ok, out


def test_read_only_refuses_stage_before_recording(frm_ro):
    """security-negative: brix_allow_write off -> kXR_fsReadOnly for kXR_stage,
    and NO registry record is created (the refusal fires before the scan)."""
    s = _session(frm_ro.port)
    status, body = _prepare(s, ["/near.dat"], kXR_stage | kXR_noerrs)
    assert status == kXR_error, f"read-only server accepted a stage: {status}"
    code, msg = _err_of(body)
    assert code == kXR_fsReadOnly, (code, msg)   # EROFS, never EACCES

    # Nothing recorded, nothing recalled: QPrep is a query and still answers.
    assert _qprep_status(s, "0", "/near.dat") == "M"
    s.close()
    assert not _audit_verbs(frm_ro.audit, "recall"), \
        "read-only refusal still reached the driver"
