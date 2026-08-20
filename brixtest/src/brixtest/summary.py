"""Read-only discovery of retained per-case ``summary.json`` records."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import List, Mapping, Optional

from brixtest.errors import SpecError

__all__ = ["default_runs_root", "list_runs", "load_run"]


def default_runs_root() -> Path:
    return Path(os.environ.get(
        "BRIXTEST_RUNS", str(Path(tempfile.gettempdir()) / "brixtest-runs")
    )).resolve()


def list_runs(root: Optional[Path] = None) -> List[dict[str, object]]:
    base = Path(root or default_runs_root())
    rows: List[dict[str, object]] = []
    if not base.is_dir():
        return rows
    for path in base.iterdir():
        summary = path / "summary.json"
        try:
            row = json.loads(summary.read_text())
        except (OSError, ValueError, TypeError):
            continue
        row["summary_path"] = str(summary)
        rows.append(row)
    return sorted(rows, key=lambda item: str(item.get("started_at", "")), reverse=True)


def load_run(name: str = "latest", root: Optional[Path] = None) -> Mapping[str, object]:
    rows = list_runs(root)
    if name == "latest":
        if rows:
            return rows[0]
        raise SpecError("summary", name, "no retained BriXTest runs were found")
    base = Path(root or default_runs_root())
    path = Path(name)
    if not path.is_absolute():
        path = base / path
    summary = path if path.name == "summary.json" else path / "summary.json"
    try:
        return json.loads(summary.read_text())
    except (OSError, ValueError, TypeError) as exc:
        raise SpecError("summary", name, "cannot read %s: %s" % (summary, exc)) from exc
