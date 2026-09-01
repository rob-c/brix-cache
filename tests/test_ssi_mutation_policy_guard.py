"""SSI service handles carry a WRITE-ALLOWED mutation policy (bug 24 guard).

An SSI handle is a SERVICE conversation, not an export file: a "write" on it is
the request the executor consumes (e.g. the CTA archive submission).  The
handle-based write gate in brix_validate_write_handle reads the handle's
CARRIED mutation policy, whose fail-closed zero value is READ_ONLY.  So unless
the SSI open explicitly stamps BRIX_VFS_MUTATION_ALLOWED on its virtual handle,
every SSI submit answers kXR_fsReadOnly — which is exactly what happened: the
CTA workflow runs against a read-only export (`brix_root on` with no
`brix_allow_write`), and every submit there was refused (bug 24, the 8
audit15aa/audit15c failures).

The audit15aa cluster tests exercise the submit end-to-end, but only fail
INCIDENTALLY (as a wrong CTA response) if the stamp regresses, and only under a
full fleet.  This guard pins the property directly and deterministically:

  * success   — the SSI open stamps mutation_policy = BRIX_VFS_MUTATION_ALLOWED
  * security  — the stamp is documented as scoped to the virtual service
                handle (a real file mutation goes through its own VFS path),
                so the guard cannot be satisfied by widening the gate globally
  * error     — the extractor is non-vacuous: it really reads ssi.c's open path

Run:
    PYTHONPATH=tests pytest tests/test_ssi_mutation_policy_guard.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(60),
              pytest.mark.xdist_group("ssi-mutation-policy-guard")]

SSI_C = Path(__file__).resolve().parent.parent / "src" / "protocols" / "ssi" / "ssi.c"


def _open_path_text() -> str:
    """The body of the SSI open handler — the code that populates the virtual
    handle (files[idx]) and where the stamp must live."""
    text = SSI_C.read_text()
    # Anchor on the actual handle install — `ctx->files[idx].ssi = sess;` — and
    # run to the handler's `return ssi_open_send_reply(...)`.  Using the ctx->
    # assignment (not a bare docstring mention) and the CALL (not the function
    # definition) keeps the region to the real open body.
    m = re.search(r"ctx->files\[idx\]\.ssi\s*=.*?return\s+ssi_open_send_reply\s*\(",
                  text, re.S)
    assert m, "SSI open handler shape changed — ctx->files[idx].ssi / return"
    return m.group(0)


def test_ssi_open_stamps_write_allowed():
    """(success) The SSI open stamps BRIX_VFS_MUTATION_ALLOWED on its virtual
    handle, so the handle-based write gate admits the service submission on a
    read-only export instead of answering kXR_fsReadOnly."""
    body = _open_path_text()
    assert re.search(
        r"files\[idx\]\.mutation_policy\s*=\s*BRIX_VFS_MUTATION_ALLOWED\s*;",
        body), (
        "the SSI open no longer stamps mutation_policy = "
        "BRIX_VFS_MUTATION_ALLOWED — every SSI/CTA submit will answer "
        "kXR_fsReadOnly on a read-only export again (bug 24)")


def test_stamp_is_scoped_to_the_service_handle():
    """(security-neg) The stamp must be documented as governing ONLY this
    virtual service handle — a real file mutation is judged on its own VFS
    path.  This is the line that keeps the fix from reading as 'SSI widens the
    write gate', which would be a genuine authorization regression."""
    text = SSI_C.read_text()
    idx = text.find("files[idx].mutation_policy = BRIX_VFS_MUTATION_ALLOWED")
    assert idx != -1, "stamp missing (see test_ssi_open_stamps_write_allowed)"
    # The explanatory comment sits immediately above the stamp.
    preamble = text[max(0, idx - 900):idx]
    assert "read-only export" in preamble, (
        "the stamp's rationale (works on a read-only export) is gone — keep "
        "it so a reader knows this is a recorded posture, not a gate widening")
    assert re.search(r"real file mutation.*own", preamble, re.S), (
        "the scoping note (a real file mutation goes through its own VFS "
        "path) is gone — without it the stamp reads as a global write-gate "
        "widening, which would be an authz regression")


def test_extractor_is_not_vacuous():
    """(error) The open-path extractor really isolates the handle-install
    region, so the success assertion is not trivially true over the whole
    file."""
    body = _open_path_text()
    assert "files[idx].ssi" in body and "ssi_open_send_reply" in body
    assert len(body) < 3000, (
        "the extracted open-path region is implausibly large — the anchor "
        "regex went greedy and the guard would pass on unrelated code")
