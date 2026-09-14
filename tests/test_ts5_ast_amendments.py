"""Exact post-move body pins preserve strict drift detection; AST/hash data only."""

import pytest

from ts5_ast_checks import pinned_move_problem


def _problem(**overrides):
    arguments = {
        "before": {"changed": "old", "same": "stable"},
        "after": {"changed": "new", "same": "stable", "added": "addition"},
        "expected_shape": (2, 2),
        "changes": {"changed": ("old", "new")},
        "additions": {"added": "addition"},
    }
    arguments.update(overrides)
    return pinned_move_problem(**arguments)


def test_exact_reviewed_body_evolution_is_accepted():
    assert _problem() is None


@pytest.mark.parametrize("after,diagnostic", [
    ({"changed": "new", "added": "addition"}, "definitions lost"),
    ({"changed": "new", "same": "drift", "added": "addition"}, "bodies changed"),
    ({"changed": "new", "same": "stable", "added": "addition", "extra": "x"}, "definitions invented"),
    ({"changed": "old", "same": "stable", "added": "addition"}, "changed body does not match"),
    ({"changed": "later", "same": "stable", "added": "addition"}, "changed body does not match"),
    ({"same": "stable", "added": "addition"}, "changed body does not match"),
    ({"changed": "new", "same": "stable"}, "added body does not match"),
    ({"changed": "new", "same": "stable", "added": "later"}, "added body does not match"),
])
def test_loss_invention_reversion_and_unreviewed_body_edits_fail(after, diagnostic):
    assert diagnostic in _problem(after=after)


def test_changed_archive_cannot_reuse_an_old_pin():
    assert "changed-body archive does not match" in _problem(
        before={"changed": "rewritten", "same": "stable"})


def test_an_added_body_cannot_already_exist_in_the_archive():
    assert "stale added-body amendment" in _problem(
        before={"changed": "old", "same": "stable", "added": "addition"})


def test_an_unchanged_body_cannot_be_listed_as_a_change():
    assert "stale changed-body amendment" in _problem(changes={"changed": ("old", "old")})


def test_archive_shape_remains_part_of_the_contract():
    before = {"changed": "old", "same": "stable", "third": "stable"}
    after = {"changed": "new", "same": "stable", "third": "stable", "added": "addition"}
    assert "archive shape" in _problem(before=before, after=after)
