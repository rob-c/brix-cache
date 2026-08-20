"""Pytest lane for an RPM repository served from CVMFS (phase-104 D13).

Composition only — `brixrpm createrepo` (D12) into `brixcvmfs ingest dir`
(D9) — so it adds no new C. It proves the round trip through the
content-addressed store is byte-exact and that stock dnf installs from what
comes back out, snapshots included. The operator-facing form of this lane is
docs/05-operations/rpm-on-cvmfs.md.

The pipeline runs once in a module-scoped fixture — two tool builds and four
dnf transactions in user namespaces — and each test asserts one leg of that
run, so a failure says whether it was the round trip, the time machine or the
tamper refusal that broke.
"""

import pytest

from cmdscripts.rpm_cvmfs_compose import preflight, run_checks

# Two standalone tool builds (~20 s) plus four dnf transactions in user
# namespaces: the 30 s module default cannot fit this lane.
pytestmark = pytest.mark.timeout(600)


@pytest.fixture(scope="module")
def checked(tmp_path_factory):
    blocked = preflight()
    if blocked:
        pytest.skip(blocked)
    return run_checks(tmp_path_factory.mktemp("rpm-cvmfs"))


def _group(results, prefix):
    """One check group's results, asserted as a unit (see the D9 lane)."""
    rows = [(ok, msg) for ok, msg in results if msg.startswith(prefix)]
    assert rows, "check group %r never ran: %s" % (
        prefix, "; ".join(m for _, m in results))
    assert all(ok for ok, _ in rows), "\n".join(
        "%s %s" % ("ok" if ok else "FAIL", msg) for ok, msg in rows)


def test_dnf_installs_from_the_published_repo(checked):
    """C1 — createrepo → ingest → every byte back out of CAS → dnf installs."""
    _group(checked, "c1:")


def test_republish_adds_a_package_and_the_old_snapshot_still_installs(checked):
    """C2 — the time machine: a pinned revision keeps depsolving as it did."""
    _group(checked, "c2:")


def test_a_tampered_rpm_in_the_tree_is_refused(checked):
    """C3 — fail-closed: dnf's checksum chain, and the ordering rule's cost."""
    _group(checked, "c3:")
