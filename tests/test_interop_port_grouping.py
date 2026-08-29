"""Guard: co-owners of a fixed interop port must share one xdist worker.

``official_interop_lib.worker_port(base)`` hands out ONE fixed ladder port per
interop base, and its contract is that "the owning module runs on ONE xdist
worker".  Two things broke that contract at once, and together they silently
cost ~526 conf-interop tests per fast run:

  1. 48 of the 65 bases have MORE THAN ONE owning module — the split-file
     siblings (``X``, ``X_b``, ``X_c``) reexport one helper and so bind the same
     ports, and ``test_deep_tree_special_files`` allocates two other families'
     bases outright.  Grouping by module NAME put co-owners on different
     workers.
  2. ``--dist loadgroup`` schedules on the ``@group`` suffix xdist appends to a
     nodeid during ITS collection hook, so an ``xdist_group`` marker added later
     by a conftest hook never reaches the scheduler at all.

Either one alone yields two servers racing for one port; the loser dies with
``bind() ... (98: Address already in use)``, the pair launch raises, and the
module SKIPS.  A skip keeps the suite green, so nothing ever failed — which is
why this needs a guard rather than a passing run.

Run:
    PYTHONPATH=tests pytest tests/test_interop_port_grouping.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import conftest_part3 as grouping

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.xdist_group("interop-port-grouping")]

TESTS_DIR = Path(__file__).resolve().parent
_PORT_CALL = re.compile(r"worker_port\(\s*(\d+)\s*\)")


def _base_owners():
    """base -> sorted owning test-module stems, straight from the sources."""
    owners: dict[int, set[str]] = {}
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        for base in grouping._interop_bases_in(path):
            owners.setdefault(base, set()).add(path.stem)
    return {base: sorted(mods) for base, mods in owners.items()}


def test_every_port_has_exactly_one_group():
    """(success) Every co-owner of a base resolves to the SAME group."""
    groups = grouping._interop_port_groups()
    split = {}
    for base, mods in _base_owners().items():
        assigned = {groups.get(m, m) for m in mods}
        if len(assigned) > 1:
            split[base] = (mods, sorted(assigned))
    assert not split, (
        "these interop ports are bound by modules in DIFFERENT xdist groups, so "
        "two workers will race to bind one port and the loser's module will "
        "silently skip:\n"
        + "\n".join(f"  base {b}: {m} -> {g}" for b, (m, g) in split.items()))


def test_sharing_is_real_so_the_guard_is_not_vacuous():
    """(non-vacuity) Bases really are shared — otherwise the check proves nothing."""
    shared = {b: m for b, m in _base_owners().items() if len(m) > 1}
    assert shared, "no shared interop bases found — the scan is broken"
    assert len(shared) >= 40, f"expected the known sharing, found {len(shared)}"


def test_group_reaches_the_scheduler_not_just_the_marker():
    """(error) The group must land in the NODEID, which is what loadgroup reads.

    A marker alone is invisible to the scheduler when a conftest adds it after
    xdist's own collection hook — the exact defect that made the grouping a
    no-op.  Pin the nodeid rewrite, and pin that it REPLACES a stale suffix
    rather than appending a second one.
    """
    class _Item:
        nodeid = "tests/test_conf_rename.py::test_x@conf_rename"

        def __init__(self):
            self._nodeid = self.nodeid
            self.markers = []

        def add_marker(self, marker, append=True):
            self.markers.append(marker)

    item = _Item()
    grouping._force_xdist_group(item, "interop-test_conf_rename")
    assert item._nodeid == (
        "tests/test_conf_rename.py::test_x@interop-test_conf_rename")
    assert item._nodeid.count("@") == 1, "stale suffix was appended, not replaced"
    assert item.markers, "the marker must be set too, for -m selection"
