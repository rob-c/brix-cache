"""Replay failed managed cases from their durable session record."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from brixtest.errors import SpecError
from brixtest.metrics import load_metric_session
from brixtest.summary import default_runs_root


def run_command(args) -> int:
    runs = Path(args.runs).resolve() if args.runs else default_runs_root()
    payload = load_metric_session(args.session, runs)
    tests = payload.get("tests", [])
    rows = [row for row in tests if isinstance(row, dict)] if isinstance(tests, list) else []
    if args.test:
        selected = [row for row in rows if row.get("nodeid") == args.test]
        if not selected:
            raise SpecError("rerun test", args.test, "is not present in the selected session")
    else:
        selected = [row for row in rows if row.get("outcome") not in ("passed", "skipped")]
        if not args.all:
            selected = selected[:1]
    if not selected:
        raise SpecError("rerun", args.session, "contains no failing managed tests")
    for row in selected:
        replay = row.get("replay", {})
        argv = replay.get("argv", []) if isinstance(replay, dict) else []
        cwd = replay.get("cwd", "") if isinstance(replay, dict) else ""
        if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
            raise SpecError("rerun", row.get("nodeid"), "has no valid replay command")
        print("BriXTest rerun: %s" % row.get("nodeid"))
        status = subprocess.call(argv, cwd=str(cwd) or None, env=dict(os.environ))
        if status:
            return status
    return 0
