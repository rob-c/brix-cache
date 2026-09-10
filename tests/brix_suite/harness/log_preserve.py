"""Session-end preservation of registry instance logs (history §21(g), the
fleet half).

``TEST_REGISTRY_KEEP_LOGS=1`` has been a settings field since the registry
refactor, but nothing consumed it: ``_remove_test_root()`` wiped every
instance's ``logs/`` regardless, so a fail-fast halt's only evidence — the
fleet's and the lifecycle subjects' error.log — was gone by the time the run
script's EXIT line ran (race-hunt run 40's post-EXIT tar was empty).  With
the knob set, the session-end wipe first moves each instance's ``logs/``
directory aside, to ``<dest>/<instance>/logs`` — a sibling outside the tree
about to be removed.
"""

from __future__ import annotations

import shutil
from pathlib import Path


def _has_content(logs: Path) -> bool:
    try:
        return any(f.is_file() and f.stat().st_size > 0 for f in logs.iterdir())
    except OSError:
        return False


def _move_logs(prefix: Path, dest: Path) -> bool:
    """Move ``prefix/logs`` to ``dest/<prefix name>/logs`` when it holds a
    non-empty file; False when there is nothing to keep or the move fails."""
    logs = prefix / "logs"
    if not logs.is_dir() or not _has_content(logs):
        return False
    target = dest / prefix.name / "logs"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(logs), str(target))
    except OSError:
        return False
    return True


def preserve_registry_logs(registry_root: Path, dest: Path) -> list[str]:
    """Move every instance ``logs/`` directory holding a non-empty file from
    ``registry_root/<instance>/logs`` to ``dest/<instance>/logs``.

    Returns the instance names preserved, in name order.  Only a directory
    literally named ``logs`` directly under an instance prefix moves — data
    roots, pidfiles and configs stay for the wipe.  Never raises: a missing
    registry root, an unreadable entry or a failed move is skipped, because
    this runs inside session teardown where a second red helps nobody.
    """
    try:
        prefixes = sorted(p for p in registry_root.iterdir() if p.is_dir())
    except OSError:
        return []
    return [prefix.name for prefix in prefixes if _move_logs(prefix, dest)]
