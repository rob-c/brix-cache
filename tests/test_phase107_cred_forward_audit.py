"""Phase-107 closure, shard 2 — the credential-forwarding confused-deputy audit.

Split out of `test_phase107_mutation_surface_closure.py` on 2026-09-09 when
that file reached the 600-line cap (coding-standards §1); it is the same pin,
in its own module because the 2.0 F5 amendment below gave it a declaration
table, a helper and two negatives of its own.

What it holds: every `*_maybe_cred` wrapper in `src/fs/backend/sd_cred_forward.h`
answers a deny-mode credential with a refusal rather than running the operation
as the export identity — the confused-deputy class the storage-driver slot wave
found three times. A wrapper may answer it itself (the `fallback_deny`/EACCES
clause) or by a DECLARED tail call to a wrapper that does; the declaration is
checked to still be that tail call, and to still carry the guard that keeps a
credential off a driver slot not declared able to honour it.

Run:
    PYTHONPATH=tests pytest tests/test_phase107_cred_forward_audit.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.xdist_group("phase107-closure")]


def _text(rel: str) -> str:
    return (SRC / rel).read_text()



# The wrappers that do not carry the deny clause themselves because their
# fall-through hands the credential to a wrapper that does. One entry per
# delegation, declared here so a new wrapper cannot join the set silently.
# 2026-09-09 (2.0 F5): `open_hinted` is an OPTIONAL driver slot layered over
# the plain open. Its wrapper routes to the slot only when there is a hint AND
# the driver is credential-capable (`sd.h` requires open_hinted to honour a
# cred exactly as open_cred does); every other case, deny-mode included, is
# the tail call below — so duplicating the clause here would state the policy
# twice and let the two copies drift.
_DENY_BY_DELEGATION = {
    "brix_sd_open_hinted_maybe_cred": "brix_sd_open_maybe_cred",
}


def _assert_deny_mode_is_answered(name, body, audited):
    """`name` refuses a deny-mode credential, itself or by delegation."""
    if "fallback_deny" in body and "EACCES" in body:
        return
    delegate = _DENY_BY_DELEGATION.get(name)
    assert delegate is not None, (
        f"{name} falls back to the plain slot for a deny-mode credential "
        "— the operation would run as the export identity")
    assert delegate in audited, (
        f"{name} delegates its deny answer to {delegate}, which is not one of "
        "the audited forwarding wrappers")
    assert body.rstrip().endswith(f"return {delegate}(inst, path, sd_flags, "
                                  "mode, cred, err_out);"), (
        f"{name}'s fall-through is no longer the tail call to {delegate}")
    assert "cred == NULL || inst->driver->open_cred != NULL" in body, (
        f"{name} may reach an optional driver slot with a credential the "
        "driver is not declared able to honour")


def test_every_credential_forwarding_wrapper_refuses_deny_mode():
    """The confused-deputy class the storage-driver slot wave found three
    times, generalised.  Each `*_maybe_cred` wrapper routes to a `_cred` twin
    when the caller has a credential; when the driver has no twin, a credential
    carrying `fallback_deny` must make the wrapper REFUSE (EACCES) rather than
    fall through to the plain slot, which would run the operation as the export
    identity — precisely the escalation the flag exists to prevent.  C4 added
    `unlink_many` to this set, where the blast radius is a whole batch.  A new
    wrapper added without the clause is invisible until someone audits it."""
    header = _text("fs/backend/sd_cred_forward.h")
    wrappers = re.findall(
        r"\n(brix_sd_\w+_maybe_cred)\(.*?\n\{(.*?)\n\}\n", header, re.S)
    assert len(wrappers) >= 18, (
        f"expected at least the eighteen forwarding wrappers, "
        f"found {len(wrappers)}")

    for name, body in wrappers:
        _assert_deny_mode_is_answered(name, body, [w for w, _ in wrappers])

    names = [name for name, _ in wrappers]
    assert "brix_sd_unlink_many_maybe_cred" in names, \
        "C4's batch slot must be inside the forwarding rule, not beside it"


def test_a_wrapper_without_the_clause_and_without_a_declaration_still_fails():
    """Error: the amendment above must not have widened the rule into nothing.
    A wrapper that neither carries the deny clause nor appears in
    `_DENY_BY_DELEGATION` is exactly the confused deputy the audit exists to
    catch, and it must still fail — declaring a delegation is a deliberate
    act, not a default."""
    body = "\n    return inst->driver->open(inst, path, sd_flags, mode, err_out);"
    with pytest.raises(AssertionError, match="falls back to the plain slot"):
        _assert_deny_mode_is_answered(
            "brix_sd_invented_maybe_cred", body,
            ["brix_sd_open_maybe_cred", "brix_sd_invented_maybe_cred"])


def test_a_declared_delegation_that_stops_delegating_fails():
    """Security negative: the declaration is not a permanent excuse. If the
    hinted wrapper's fall-through ever stops being the tail call to the
    audited wrapper — or loses the credential-capability guard that keeps a
    cred off a driver slot not declared able to honour it — the deny answer is
    gone and the row must go red rather than vouch for the old shape."""
    delegate = "brix_sd_open_maybe_cred"
    guard = "cred == NULL || inst->driver->open_cred != NULL"
    tail_call = (f"return {delegate}(inst, path, sd_flags, mode, cred, "
                 "err_out);")
    audited = [delegate, "brix_sd_open_hinted_maybe_cred"]

    no_tail = "\n    /* " + guard + " */\n    return NULL;"
    with pytest.raises(AssertionError, match="no longer the tail call"):
        _assert_deny_mode_is_answered(
            "brix_sd_open_hinted_maybe_cred", no_tail, audited)

    no_guard = "\n    " + tail_call
    with pytest.raises(AssertionError, match="not declared able to honour"):
        _assert_deny_mode_is_answered(
            "brix_sd_open_hinted_maybe_cred", no_guard, audited)

    ok = "\n    if (" + guard + ") { }\n    " + tail_call
    _assert_deny_mode_is_answered("brix_sd_open_hinted_maybe_cred", ok, audited)
