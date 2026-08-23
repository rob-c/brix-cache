"""Explicit retention and integrity operations for session archives."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Sequence

from brixtest.errors import SpecError


@dataclasses.dataclass(frozen=True)
class RetentionPolicy:
    keep_days: int = 90
    keep_failures_days: int = 365
    keep_latest: int = 20

    def __post_init__(self) -> None:
        for name in ("keep_days", "keep_failures_days", "keep_latest"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SpecError("retention.%s" % name, value, "must be an integer >= 0")


def candidates(root: Path, policy: RetentionPolicy, *, now: float = 0.0) -> list[Path]:
    base = Path(root).resolve()
    current = now or time.time()
    sessions = _sessions(base)
    selected = []
    for index, path in enumerate(sessions):
        if _expired(path, index, policy, current):
            selected.append(path)
    return selected


def _sessions(base: Path) -> list[Path]:
    if not base.is_dir():
        return []
    rows = [path for path in base.iterdir() if path.is_dir()]
    return sorted(rows, key=lambda path: path.stat().st_mtime, reverse=True)


def _session_payload(path: Path) -> object:
    try:
        return json.loads((path / "session.json").read_text())
    except (OSError, ValueError, TypeError):
        return None


def _expired(
    path: Path, index: int, policy: RetentionPolicy, current: float,
) -> bool:
    if index < policy.keep_latest:
        return False
    payload = _session_payload(path)
    if not isinstance(payload, dict):
        return False
    failed = bool(payload.get("counts", {}).get("failed", 0))
    age_days = (current - path.stat().st_mtime) / 86400.0
    threshold = policy.keep_failures_days if failed else policy.keep_days
    return age_days > threshold


def prune(root: Path, paths: Sequence[Path]) -> int:
    """Delete only paths returned beneath the exact metrics-session root."""
    base = Path(root).resolve()
    count = 0
    for raw in paths:
        path = Path(raw).resolve()
        try:
            confined = path.parent == base
        except OSError:
            confined = False
        if not confined or not (path / "session.json").is_file():
            raise SpecError("retention target", str(path), "is not a direct session child")
        shutil.rmtree(path)
        count += 1
    return count


def verify_objects(session_dir: Path) -> dict:
    root = Path(session_dir).resolve()
    errors = []
    checked = 0
    for path in (root / "objects" / "sha256").glob("*/*"):
        if not path.is_file() or path.is_symlink():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        checked += 1
        if path.name != digest.hexdigest():
            errors.append(str(path.relative_to(root)))
    return {"ok": not errors, "checked": checked, "corrupt": errors}
