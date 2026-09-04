"""Guard: metadata walks stay off the event loop (phase-109 W4).

phase-109 moved the PROPFIND/SEARCH builds onto the thread pool behind a gate
(walk_offload.c). Nothing structural stops a refactor from reintroducing the
inline call — the stall would return silently, because the inline path still
WORKS (it just blocks the worker). This guard pins the three properties that
make the offload real:

  1. every offload-adopted body handler dispatches through the offload before
     its inline fallback;
  2. the gate DECLINES under impersonation (the copy_collection.c precedent:
     the broker socket is single-user and a task lacks the principal — without
     this decline the offload is an authorization bug, not an optimisation);
  3. the offloaded build allocates via webdav_req_pool, never bare r->pool
     (nginx pools are not thread-safe against event-loop teardown).

  * success   — the real tree satisfies all three
  * error     — the detector flags a fixture with the inline-only shape
  * security  — the impersonation decline and the pool rule are present
                verbatim in the gate (their absence is the security bug)

Run:
    PYTHONPATH=tests pytest tests/test_metadata_offload_guard.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(60),
              pytest.mark.xdist_group("metadata-offload-guard")]

WEBDAV = Path(__file__).resolve().parent.parent / "src" / "protocols" / "webdav"

# handler file -> (offload call, inline call) that must appear in that order.
ADOPTERS = {
    "propfind.c": ("webdav_propfind_offload(r)", "propfind_do(r)"),
    "search.c": ("webdav_search_offload(r)", "webdav_search_do(r)"),
}

# The build-phase files that may run on the thread: bare r->pool is forbidden
# (they must allocate through webdav_req_pool / propfind_pool).
THREAD_SIDE = ("propfind.c", "propfind_walk.c", "propfind_props.c",
               "propfind_props_acl.c", "search.c", "resource.c")


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def test_adopters_dispatch_through_the_offload():
    """(success) Each adopted handler tries the offload before its inline
    fallback — the shape that keeps the stall gone."""
    for fname, (offload, inline) in ADOPTERS.items():
        text = _strip_comments((WEBDAV / fname).read_text())
        oi, ii = text.find(offload), text.find(inline)
        assert oi != -1, f"{fname}: offload dispatch {offload} missing"
        assert ii != -1, f"{fname}: inline fallback {inline} missing"
        assert oi < ii, (
            f"{fname}: the offload dispatch must precede the inline call — "
            "an inline-first shape reintroduces the event-loop stall")


def test_thread_side_files_never_touch_bare_request_pool():
    """(success/security) nginx pools are not thread-safe: the files whose code
    can run on the walk task must reach their pool via webdav_req_pool (which
    returns the task-private pool while offloaded), never bare r->pool."""
    offenders = {}
    for fname in THREAD_SIDE:
        text = _strip_comments((WEBDAV / fname).read_text())
        hits = len(re.findall(r"\br->pool\b", text))
        if hits:
            offenders[fname] = hits
    assert not offenders, (
        "bare r->pool on a thread-capable path — route through "
        f"webdav_req_pool(): {offenders}")


def test_gate_declines_under_impersonation():
    """(security-neg) The single most important line in the gate: under
    impersonation the walk must stay inline (single-user broker socket; the
    task lacks the principal). If this decline disappears, the offload becomes
    a walk executed as the WORKER instead of the mapped user."""
    text = _strip_comments((WEBDAV / "walk_offload.c").read_text())
    gate = text[text.find("webdav_walk_offload_wanted"):]
    assert "brix_imp_enabled()" in gate, (
        "walk_offload's gate no longer checks brix_imp_enabled() — an "
        "offloaded walk under impersonation runs as the worker (authz bug)")
    # And the decline must come BEFORE the remote/pool logic, so no partial
    # setup happens for an impersonated request.
    assert gate.find("brix_imp_enabled()") < gate.find("is_remote"), (
        "the impersonation decline must be the gate's first check")


def test_gate_offloads_local_exchange_mode():
    """(security-neg / W3) The whole of W3: a LOCAL backend normally stays
    inline, but EXCHANGE-mode delegation mints an RFC-8693 token through a
    BLOCKING POST inside the walk's cred gate even on local storage — the exact
    event-loop stall phase-106 R-7 traced. So the local-backend decline MUST
    carry an EXCHANGE exception (`backend_delegation != BRIX_CRED_EXCHANGE`),
    routing a local EXCHANGE-mode metadata walk onto the thread anyway. Without
    this arm the token exchange silently returns to the event loop and R-7
    reopens with no other test catching it — the gate would still 'work', it
    would just block the worker on every cold token mint."""
    text = _strip_comments((WEBDAV / "walk_offload.c").read_text())
    gate = text[text.find("webdav_walk_offload_wanted"):]
    gate = gate[:gate.find("\n}")]
    assert "BRIX_CRED_EXCHANGE" in gate, (
        "walk_offload's gate no longer references BRIX_CRED_EXCHANGE — a local "
        "EXCHANGE-mode walk would stay inline and mint its RFC-8693 token on "
        "the event loop (phase-109 W3 / phase-106 R-7 reopened)")
    # The EXCHANGE check must be part of the LOCAL-backend decline, i.e. paired
    # with the is_remote test so that !remote AND !exchange is what declines —
    # EXCHANGE overrides the local fast-path and offloads.
    decline = gate[gate.find("is_remote"):]
    assert "BRIX_CRED_EXCHANGE" in decline[:decline.find("return 0")], (
        "the EXCHANGE exception is not inside the local-backend decline — a "
        "local EXCHANGE walk must escape the inline fast-path and offload")


# The LOCK path files and the offload seams that must NOT appear in them while
# the conflict walk still mutates (reaps expired locks) inline.
_LOCK_FILES = ("lock.c", "lock_check.c")
_OFFLOAD_SEAMS = ("webdav_walk_offload", "webdav_search_offload",
                  "webdav_propfind_offload")


def _lock_path_texts() -> dict:
    """Comment-stripped text of the LOCK path files that exist."""
    out = {}
    for fname in _LOCK_FILES:
        p = WEBDAV / fname
        if p.exists():
            out[fname] = _strip_comments(p.read_text())
    return out


def _seam_in_lock_path(texts: dict):
    """(file, seam) of the first offload seam wired into a LOCK file, or None."""
    for fname, text in texts.items():
        for seam in _OFFLOAD_SEAMS:
            if seam in text:
                return fname, seam
    return None


def test_lock_is_not_offloaded_while_its_walk_mutates():
    """(security-neg) LOCK is a deliberate NON-adopter: its conflict walk
    (check_locks_descendants) reaps expired locks INLINE — a VFS mutation
    (webdav_lock_expired_cleanup) interleaved with the readdir/stat. Offloading
    it would run that reap on a thread, i.e. as the worker rather than the
    mapped principal under impersonation. This cell pins the invariant that the
    LOCK path does NOT dispatch through the walk offload while that in-walk
    mutation is still present: whoever wants to offload LOCK must FIRST lift the
    reap out of the walk (see phase-109 W2 acceptance), and this guard makes
    them confront that instead of silently splitting a mutation flow."""
    texts = _lock_path_texts()
    assert texts, "neither lock.c nor lock_check.c found — path moved?"

    # The reason for the exclusion must still hold: the walk still mutates.
    assert "webdav_lock_expired_cleanup" in texts.get("lock_check.c", ""), (
        "lock_check.c no longer reaps expired locks inside the walk — the "
        "phase-109 LOCK-exclusion rationale is now stale; re-evaluate whether "
        "LOCK can (and should) join the offload adopters and update W2")

    # And the offload seam must not be wired into the LOCK path while it does.
    wired = _seam_in_lock_path(texts)
    assert wired is None, (
        f"{wired[0]} dispatches through {wired[1]} while its walk still "
        "mutates inline (webdav_lock_expired_cleanup) — lift the reap out of "
        "the walk before offloading LOCK (phase-109 W2)")


def test_detector_is_not_vacuous():
    """(error) The order check really rejects the inline-first shape."""
    fake = "rc = propfind_do(r); if (webdav_propfind_offload(r) == NGX_DONE)"
    oi, ii = fake.find("webdav_propfind_offload(r)"), fake.find("propfind_do(r)")
    assert not (oi != -1 and ii != -1 and oi < ii), (
        "detector logic broken: it would accept an inline-first handler")
