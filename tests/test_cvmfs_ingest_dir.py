"""Pytest lane for `brixcvmfs ingest dir` + `ingest prune` (phase-104 D9).

Pure-local (no servers): builds the standalone ingesttool, publishes folders
straight into a freshly minted Stratum-0, and verifies catalogs/CAS
independently in Python. Covers the demo path, incremental + --delete
mirroring, the fail-closed grammar/collision/lock negatives, and the
10k-file scale budget.

The whole pipeline runs ONCE, in a module-scoped fixture, because two tool
builds and a 10k-file publish are not something to repeat four times. What
each test then asserts is one group of that single run's results — so a
failure names the property that broke (`--delete` mirroring, the busy lock,
the scale budget) instead of one opaque red mark for the lane.
"""

import pytest

from cmdscripts.cvmfs_ingest_dir import run_checks

# Two standalone tool builds (~20 s) plus a 10k-file publish: the 30 s module
# default cannot fit this lane even when every check passes.
pytestmark = pytest.mark.timeout(300)


@pytest.fixture(scope="module")
def checked(tmp_path_factory):
    return run_checks(tmp_path_factory.mktemp("ingest-dir"))


def _group(results, prefix):
    """The results of one check group, asserted as a unit.

    A group that produced nothing is a failure in its own right: it means the
    driver bailed before reaching it (a build that did not compile), and a
    lane that reports green because it never ran is the one failure mode this
    split exists to prevent.
    """
    rows = [(ok, msg) for ok, msg in results if msg.startswith(prefix)]
    assert rows, "check group %r never ran: %s" % (
        prefix, "; ".join(m for _, m in results))
    assert all(ok for ok, _ in rows), "\n".join(
        "%s %s" % ("ok" if ok else "FAIL", msg) for ok, msg in rows)


def test_the_tools_build_standalone(checked):
    """Everything below is meaningless if the front-end did not compile."""
    _group(checked, "ingesttool")
    _group(checked, "repotool")


def test_a_folder_publishes_with_its_shape_intact(checked):
    """I1 — files, nested and empty dirs, symlinks stored verbatim, dry-run."""
    _group(checked, "i1:")


def test_reingest_updates_in_place_and_delete_mirrors(checked):
    """I2 — add-only by default; `--delete` makes the prefix mirror-exact."""
    _group(checked, "i2:")


def test_every_refusal_leaves_the_old_revision_standing(checked):
    """I3 — reserved grammar, bad prefixes, collisions, locks, crash-resume."""
    _group(checked, "i3:")


def test_ten_thousand_files_publish_inside_the_budget(checked):
    """I4 — the scale claim, measured rather than asserted in prose."""
    _group(checked, "i4:")
