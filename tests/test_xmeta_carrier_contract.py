"""The xmeta carrier <-> sd_remote errno contract (bug 26 regression guard).

The xmeta carrier persists a metadata value in a real xattr when it fits and
falls back to a "<key>.cinfo" sidecar object when it does not.  That fallback
is keyed on ERRNO: xmeta_xattr_unfit() (xmeta_carrier.c) decides "the driver
could not REPRESENT this value here, ride the sidecar" from the errno the
driver's setxattr returned.  Its accepted set is E2BIG / ERANGE / ENOSPC /
ENOTSUP (+ EOPNOTSUPP).  EINVAL is deliberately NOT in it — EINVAL means "bad
argument", a hard error the carrier must not paper over.

Bug 26: sd_remote's setxattr reported EINVAL for a value it simply could not
carry in an x-amz-meta HTTP header (a CR/LF/NUL byte, or an oversize blob).
Because EINVAL is not "unfit", the carrier hard-failed instead of falling back
— and the cache's own cinfo record is a binary blob, so this broke EVERY
sidecar-backed cinfo store over a remote store the moment sd_remote gained a
setxattr slot.  The fix moved those branches to ENOTSUP / E2BIG.

The C unit (tests/c/test_sd_remote_setattr.c, test 3) pins the sd_remote side
— CR/LF/NUL -> ENOTSUP, oversize -> E2BIG.  Nothing pinned the CARRIER side:
if a refactor drops ENOTSUP from xmeta_xattr_unfit's set, that C unit still
passes while the fallback silently breaks again.  This guard pins the contract
that binds the two files, so drift on EITHER side is caught.

  * success   — xmeta_xattr_unfit accepts the representation-failure errnos
                (ENOTSUP, E2BIG) that sd_remote actually returns
  * error     — xmeta_xattr_unfit rejects EINVAL (the exact bug-26 errno):
                a value-representation failure must never surface as EINVAL
  * security  — every representation-rejection branch in sd_remote's setxattr
                sets an errno inside the carrier's fallback set, never EINVAL,
                so a binary cinfo blob is preserved via the sidecar rather than
                dropped (a dropped residency record is a correctness/security
                fault, not a cosmetic one)

Run:
    PYTHONPATH=tests pytest tests/test_xmeta_carrier_contract.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(60),
              pytest.mark.xdist_group("xmeta-carrier-contract")]

SRC = Path(__file__).resolve().parent.parent / "src"
CARRIER = SRC / "fs" / "meta" / "xmeta_carrier.c"
SD_REMOTE = SRC / "fs" / "backend" / "remote" / "sd_remote_xattr.c"


def _unfit_set() -> set[str]:
    """The errno macro names xmeta_xattr_unfit() treats as 'ride the sidecar'.

    Parses the single `return err == A || err == B || ...;` expression of the
    static xmeta_xattr_unfit(int err) function, ignoring #ifdef'd portability
    duplicates and comments (which is where EOPNOTSUPP and the phase74 note
    live)."""
    text = CARRIER.read_text()
    m = re.search(r"\bxmeta_xattr_unfit\s*\([^)]*\)\s*\{(.*?)\}", text, re.S)
    assert m, "xmeta_xattr_unfit(int) not found — did the carrier move?"
    body = re.sub(r"/\*.*?\*/", " ", m.group(1), flags=re.S)
    return set(re.findall(r"err\s*==\s*([A-Z0-9_]+)", body))


def test_carrier_accepts_the_errnos_sd_remote_returns():
    """(success) The two errnos sd_remote's setxattr raises for a value it
    cannot represent — ENOTSUP (header-breaking byte) and E2BIG (oversize) —
    are both in the carrier's sidecar-fallback set."""
    unfit = _unfit_set()
    assert "ENOTSUP" in unfit, (
        "xmeta_xattr_unfit no longer accepts ENOTSUP — sd_remote's CR/LF/NUL "
        "rejection would hard-fail the cinfo store again (bug 26)")
    assert "E2BIG" in unfit, (
        "xmeta_xattr_unfit no longer accepts E2BIG — sd_remote's oversize "
        "rejection would hard-fail the cinfo store again (bug 26)")


def test_carrier_rejects_einval():
    """(error) EINVAL must stay OUT of the fallback set: it means 'bad
    argument', a hard error.  This is the invariant the bug-26 fix depended on
    when it moved sd_remote off EINVAL — if EINVAL were folded in here, that
    fix would be silently undone and a genuinely invalid call would be masked
    as a sidecar write."""
    assert "EINVAL" not in _unfit_set(), (
        "EINVAL is now treated as 'unfit' — it must remain a hard error; "
        "folding it in masks real bad-argument bugs AND papers over any "
        "sd_remote regression back to EINVAL")


def test_sd_remote_representation_branches_stay_in_the_fallback_set():
    """(security-neg) Every branch of sd_remote's setxattr that rejects a value
    it cannot REPRESENT must set an errno inside the carrier's fallback set —
    never EINVAL.  A miss here silently drops the binary cinfo residency record
    for that object instead of riding the sidecar."""
    unfit = _unfit_set()
    text = SD_REMOTE.read_text()
    m = re.search(r"sd_remote_setxattr_impl\s*\([^)]*\)\s*\{(.*?)\n\}",
                  text, re.S)
    assert m, "sd_remote_setxattr_impl not found — did the driver move?"
    body = m.group(1)

    # The representation-rejection guards: the oversize length test and the
    # header-unsafe-byte (memchr) test.  Each is `if (...) { errno = X; ... }`.
    stripped = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
    reject_errnos = set(re.findall(r"errno\s*=\s*(E2BIG|ENOTSUP|EINVAL)\b",
                                   stripped))
    assert reject_errnos, (
        "no E2BIG/ENOTSUP/EINVAL branch found in sd_remote_setxattr_impl — "
        "the representation-failure guards were removed or renamed")
    assert "EINVAL" not in reject_errnos, (
        "sd_remote_setxattr_impl sets errno=EINVAL for a value it cannot "
        "represent — the exact bug-26 regression; use E2BIG/ENOTSUP so the "
        "xmeta carrier falls back to the .cinfo sidecar")
    assert reject_errnos <= unfit, (
        f"sd_remote raises {reject_errnos - unfit} which the carrier does not "
        "treat as unfit — that value would hard-fail instead of riding the "
        "sidecar")


def test_guard_is_not_vacuous():
    """(meta) The unfit-set parser really extracts macro names, so the
    assertions above cannot pass on an empty set."""
    unfit = _unfit_set()
    assert len(unfit) >= 3, (
        f"parsed only {unfit} from xmeta_xattr_unfit — the extractor broke, "
        "so the contract assertions are vacuous")
