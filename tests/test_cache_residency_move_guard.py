"""The historical move guard accepts only the exact native-lock repair."""

import pytest

from test_ci_ts5_cachemx_move import CACHEMX, LEGACY, _bodies, _move_drift


def _drift(tmp_path, current):
    """Compare real AST hashes without importing or executing fixture code."""
    before = tmp_path / "_cache_partial_helpers_flat.py"
    after = tmp_path / "_cache_partial_helpers.py"
    before.write_text("def residency():\n    return subprocess.run([XRDCINFO, cinfo], capture_output=True, text=True)\n")
    after.write_text("def residency():\n    return " + current + "\n")
    # The enclosing move gate also pins the HTTP/S3 builder refactor. Keep its
    # real archive/current bodies and replace only the residency probe under
    # test, so these controls cannot bypass or accidentally omit that ledger.
    archived = _bodies(LEGACY / '_cache_partial_helpers_flat.py')
    current_bodies = _bodies(CACHEMX / '_cache_partial_helpers.py')
    archived['residency'] = _bodies(before)['residency']
    current_bodies['residency'] = _bodies(after)['residency']
    return _move_drift("_cache_partial_helpers", archived, current_bodies)[-1]


def test_exact_lock_and_deadline_upgrade_is_recognized(tmp_path):
    """The known repair leaves every existing native argument unchanged."""
    call = 'client_run(os.path.join(REPO, "client"), [XRDCINFO, cinfo], capture_output=True, text=True, timeout=30)'
    assert _drift(tmp_path, call) == []


@pytest.mark.parametrize("mutation", ["timeout=31", "timeout=None"])
def test_a_different_or_unbounded_deadline_is_still_drift(tmp_path, mutation):
    """Declaring the repair cannot silently authorize another timing contract."""
    call = 'client_run(os.path.join(REPO, "client"), [XRDCINFO, cinfo], capture_output=True, text=True, ' + mutation + ')'
    assert _drift(tmp_path, call) == ["residency"]


def test_returning_to_the_unlocked_subprocess_is_rejected(tmp_path):
    """Security-negative: a build race cannot hide as a verbatim old body."""
    assert _drift(tmp_path, 'subprocess.run([XRDCINFO, cinfo], capture_output=True, text=True)') == ["residency"]
