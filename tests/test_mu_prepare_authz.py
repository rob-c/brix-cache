"""F4 — prepare/stage authorization, including the noerrs bypass (threat T4, T9).

prepare.c returns NGX_OK for an ABSENT path + kXR_noerrs BEFORE the three authz checks
(authz_check / vo_acl / token_scope at prepare.c:208/214/220). So an unauthorized user can
prepare/stage a restricted path that does not yet exist. The bypass cells are RED today; the
existing-path and control cells document the enforced behavior.

Run: sudo -E env PYTHONPATH=tests pytest tests/test_mu_prepare_authz.py -v
"""
import pytest

from mu_authz_lib.prepare import prepare_as

# (subject, path, noerrs) — bypass cells: absent path + noerrs by a denied subject.
_BYPASS = [
    ("carol", "/cms/not-yet-created-1.dat", True),
    ("bob",   "/cms/not-yet-created-2.dat", True),
    ("mallory", "/cms/not-yet-created-3.dat", True),
]
# Enforced cells: existing restricted path must be denied (authz runs).
_ENFORCED = [
    ("carol", "/cms/secret.dat", False),
    ("bob",   "/cms/secret.dat", False),
]
_CONTROL = [("alice", "/cms/secret.dat", False)]   # authorized -> allowed


@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("subject,path,noerrs", _BYPASS,
                         ids=[f"{s}-absent-noerrs" for s, _, _ in _BYPASS])
def test_prepare_absent_noerrs_still_requires_authz(mu_fleet, cast, subject, path, noerrs):
    """Absent path + noerrs must NOT bypass authorization for a denied subject. RED today."""
    denied = prepare_as(cast[subject], path, noerrs=noerrs)
    assert denied, f"prepare of absent restricted {path} by {subject} must be denied (bypass=leak)"


@pytest.mark.privileged
@pytest.mark.parametrize("subject,path,noerrs", _ENFORCED,
                         ids=[f"{s}-existing" for s, _, _ in _ENFORCED])
def test_prepare_existing_restricted_is_denied(mu_fleet, cast, subject, path, noerrs):
    denied = prepare_as(cast[subject], path, noerrs=noerrs)
    assert denied, f"prepare of existing restricted {path} by {subject} must be denied"


@pytest.mark.privileged
@pytest.mark.parametrize("subject,path,noerrs", _CONTROL,
                         ids=[f"{s}-authorized" for s, _, _ in _CONTROL])
def test_prepare_authorized_is_allowed(mu_fleet, cast, subject, path, noerrs):
    denied = prepare_as(cast[subject], path, noerrs=noerrs)
    assert not denied, f"prepare of {path} by authorized {subject} must be allowed"


@pytest.mark.privileged
@pytest.mark.parametrize("subject,path,noerrs", _CONTROL,
                         ids=[f"{s}-stage" for s, _, _ in _CONTROL])
def test_stage_needs_more_than_read_even_for_the_owner(mu_fleet, cast, subject, path, noerrs):
    """(security negative) A read grant does not confer a RECALL.

    Alice is the one principal the corpus authorizes on this object, and the cell
    above proves she may browse it.  kXR_stage is a different request: it asks the
    operator's storage to move bytes — a tape mount, a nearline recall — and 2.0
    F20 put that behind its own privilege precisely so a population of readers
    cannot schedule that work.  `rl` is read and lookup, so the same principal, on
    the same path, one flag later, must be refused.

    This is also the cell that pins the two authdb engines together.  The gate
    routes to whichever `brix_authdb_engine` names, and the engines express the
    stage privilege differently — the native grammar spells it `x`
    (authdb_grammar.c), while under `xrdacc` it lives in the composite that only
    `a` confers.  What must NOT differ is the answer: a bare prepare allowed and a
    recall refused, off one and the same `u <dn> <path> rl` record.
    """
    assert prepare_as(cast[subject], path, noerrs=noerrs, stage=True), (
        f"kXR_stage of {path} by {subject} must be denied: the corpus grants "
        f"`rl` (read+lookup), which is not the stage privilege")
