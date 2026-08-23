"""Fleet, lane, artifact, log, gate, and map CLI commands."""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path
from typing import List

from brixtest.errors import QuiescenceError
from brixtest.fleet.launcher import FleetPlan
from brixtest.fleet.prep import FleetPrep
from brixtest.results import mapping
from brixtest.util.net import listening_ports, pids_on_port


def _emit(payload, as_json: bool, human_lines: List[str]) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        for line in human_lines:
            print(line)


def _fleet_status(app: object, args) -> int:
    rows = [{
        "name": spec.name, "kind": spec.kind, "port": spec.primary_port,
        "ready": app.backend.is_ready(spec),
    } for spec in app.registry.all_specs()]
    lines = ["%-28s %-10s %-6s %s" % ("NAME", "KIND", "PORT", "READY")] + [
        "%-28s %-10s %-6s %s" % (
            row["name"], row["kind"], row["port"] or "-", "yes" if row["ready"] else "no",
        ) for row in rows
    ]
    _emit(rows, args.json, lines)
    return 0


def _fleet_start(app: object, args) -> int:
    if not _prepare_restart(app, args.fleet_cmd):
        return 1
    steps = app.hc.prep_steps(app.lane)
    artifacts = _prep_artifacts(app, steps)
    app.backend.prepare(app.lane, artifacts)
    report = app.launcher.start_registered()
    payload = [dataclasses.asdict(outcome) for outcome in report.outcomes]
    lines = [_outcome_line(row) for row in report.outcomes] + [report.summary()]
    _emit(payload, args.json, lines)
    return int(not report.ok)


def _prepare_restart(app: object, command: str) -> bool:
    if command != "restart":
        return True
    return _stop_launcher(app)


def _prep_artifacts(app: object, steps):
    if not steps:
        return None
    return FleetPrep(app.lane, steps).run()


def _outcome_line(row) -> str:
    detail = ""
    if row.error:
        detail = " — " + row.error
    return "%s: %s%s" % (row.name, row.status, detail)


def _stop_launcher(app: object) -> bool:
    try:
        app.launcher.stop()
    except QuiescenceError as exc:
        print(str(exc), file=sys.stderr)
        return False
    return True


def _fleet_stop(app: object, args) -> int:
    if not _stop_launcher(app):
        return 1
    _emit({"stopped": True}, args.json, ["fleet stopped; quiescence proven"])
    return 0

def _cmd_fleet(app: object, args) -> int:
    if args.fleet_cmd == "plan":
        plan = FleetPlan.build(app.registry.all_specs())
        _emit(
            {"levels": [[s.name for s in level] for level in plan.levels]},
            args.json, plan.describe().splitlines(),
        )
        return 0

    if args.fleet_cmd == "status":
        return _fleet_status(app, args)

    if args.fleet_cmd in ("start-all", "restart"):
        return _fleet_start(app, args)

    if args.fleet_cmd == "stop-all":
        return _fleet_stop(app, args)

    return 2


def _cmd_prep(app: object, args) -> int:
    prep = app.prep()
    if args.explain:
        text = prep.explain()
        _emit({"explain": text.splitlines()}, args.json, text.splitlines())
        return 0
    prep.run()
    text = prep.explain()
    _emit({"ran": True, "decision": text.splitlines()}, args.json, text.splitlines())
    return 0


def _cmd_lane(app: object, args) -> int:
    lane = app.lane
    owner = lane.owner()
    holders = {
        port: sorted(pids_on_port(port))
        for port in sorted(listening_ports(lane.port_range()))
    }
    payload = {
        "root": str(lane.root),
        "port_base": lane.port_base,
        "port_span": lane.port_span,
        "owner": _owner_payload(owner),
        "listening": {str(k): v for k, v in holders.items()},
    }
    lines = [
        "lane root:  %s" % lane.root,
        "ports:      %d-%d" % (lane.port_base, lane.port_base + lane.port_span - 1),
        "owner:      %s" % _owner_description(owner),
    ]
    lines.extend(_listener_lines(app, holders))
    _emit(payload, args.json, lines)
    return 0


def _owner_payload(owner):
    return dataclasses.asdict(owner) if owner else None


def _owner_description(owner) -> str:
    if owner is None:
        return "none"
    state = "alive" if owner.alive() else "dead"
    return "%s (pid %d, since %s, %s)" % (
        owner.session, owner.pid, owner.started_at, state,
    )


def _listener_lines(app: object, holders: dict) -> List[str]:
    if not holders:
        return ["listening:  nothing in range"]
    named = app.registry.declared_ports()
    lines = ["listening:"]
    for port, pids in holders.items():
        processes = ",".join(map(str, pids)) or "?"
        lines.append("  %-6d %-28s pids %s" % (
            port, named.get(port, "(undeclared)"), processes,
        ))
    return lines


def _cmd_artifacts(app: object, args) -> int:
    catalog = app.artifacts
    if args.artifacts_cmd == "list":
        rows = catalog.describe()
        payload = [
            {"name": n, "kind": k, "path": p, "note": note} for n, k, p, note in rows
        ]
        lines = ["%-28s %-4s %-40s %s" % ("NAME", "KIND", "PATH", "NOTE")] + [
            "%-28s %-4s %-40s %s" % row for row in rows
        ] if rows else ["catalog is empty — try: brixtest prep"]
        _emit(payload, args.json, lines)
        return 0
    if args.artifacts_cmd == "path":
        path = catalog.path(args.name)     # ArtifactNotFound → exit 1 with names
        _emit({"name": args.name, "path": str(path)}, args.json, [str(path)])
        return 0
    return 2


def _cmd_logs(app: object, args) -> int:
    view = app.log_view(args.instance)
    if args.path:
        _emit({"instance": args.instance, "path": str(view.path)},
              args.json, [str(view.path)])
        return 0
    if not view.path.exists():
        print("brixtest: %s has no log yet (%s)" % (args.instance, view.path),
              file=sys.stderr)
        return 1
    text = view.tail(args.tail)
    _emit({"instance": args.instance, "tail": text.splitlines()},
          args.json, text.splitlines())
    return 0


def _cmd_gate(app: object, args) -> int:
    text = app.gate.explain(Path(args.file))
    _emit({"explain": text.splitlines()}, args.json, text.splitlines())
    return 0 if "verdict: clean" in text else 1


def _collect_test_files(paths: List[str]) -> List[Path]:
    files: List[Path] = []
    for entry in paths:
        path = Path(entry)
        if path.is_dir():
            files.extend(sorted(path.rglob("test_*.py")))
        else:
            files.append(path)
    return files


def _cmd_map(app: object, args) -> int:
    if args.run:
        store = app.store()
        if store is None:
            return 1
        run_id = app.resolve_run(store, args.run)
        if run_id is None:
            return 1
        rows, dynamic = mapping.observed_rows(store.tests(run_id))
    else:
        files = _collect_test_files(args.paths)
        if not files:
            print("usage: brixtest map <test files or dirs> "
                  "(or --run <id> for the observed view)", file=sys.stderr)
            return 2
        rows, dynamic = mapping.declared_rows(app.gate, files)
    lines = (mapping.mermaid_lines(rows, dynamic) if args.mermaid
             else mapping.matrix_lines(rows, dynamic))
    _emit(mapping.as_payload(rows, dynamic), args.json, lines)
    return 0
