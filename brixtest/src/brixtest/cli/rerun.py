"""Replay failed managed cases from their durable session record."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from brixtest.errors import SpecError
from brixtest.metrics import load_metric_session
from brixtest.summary import default_runs_root
from brixtest.runtime.binaries import REPLAY_BINARIES_ENV


def _session_rows(payload) -> list[dict]:
    tests = payload.get("tests", [])
    return [row for row in tests if isinstance(row, dict)] if isinstance(tests, list) else []


def _selected_rows(rows: list[dict], test: str, all_failures: bool) -> list[dict]:
    if test:
        selected = [row for row in rows if row.get("nodeid") == test]
        if not selected:
            raise SpecError("rerun test", test, "is not present in the selected session")
        return selected
    selected = [row for row in rows if row.get("outcome") not in ("passed", "skipped")]
    return selected if all_failures else selected[:1]


def _replay(row: dict) -> int:
    replay = _replay_record(row)
    argv = _replay_argv(row, replay.get("argv", []))
    cwd = replay.get("cwd", "")
    print("BriXTest rerun: %s" % row.get("nodeid"))
    return subprocess.call(
        argv, cwd=str(cwd) or None, env=_replay_environment(replay),
    )


def _replay_environment(replay: dict) -> dict[str, str]:
    environment = dict(os.environ)
    binaries = replay.get("binaries", {})
    if binaries:
        if not isinstance(binaries, dict):
            raise SpecError("rerun binaries", binaries, "must be an identity mapping")
        environment[REPLAY_BINARIES_ENV] = json.dumps(binaries, sort_keys=True)
    fingerprint = replay.get("resource_graph_fingerprint", "")
    if fingerprint:
        if not isinstance(fingerprint, str):
            raise SpecError("rerun resource graph", fingerprint, "must be a fingerprint")
        environment["BRIXTEST_REPLAY_GRAPH_FINGERPRINT"] = fingerprint
    return environment


def _replay_record(row: dict) -> dict:
    replay = row.get("replay", {})
    return replay if isinstance(replay, dict) else {}


def _replay_argv(row: dict, value: object) -> list[str]:
    valid = isinstance(value, list) and bool(value)
    valid = valid and all(isinstance(item, str) for item in value)
    if not valid:
        raise SpecError("rerun", row.get("nodeid"), "has no valid replay command")
    return value


def run_command(args) -> int:
    runs = Path(args.runs).resolve() if args.runs else default_runs_root()
    payload = load_metric_session(args.session, runs)
    selected = _selected_rows(_session_rows(payload), args.test, args.all)
    if not selected:
        raise SpecError("rerun", args.session, "contains no failing managed tests")
    for row in selected:
        status = _replay(row)
        if status:
            return status
    return 0
