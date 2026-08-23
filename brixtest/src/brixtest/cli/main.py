"""Command-line interface for BriXTest projects and stored runs.

Every verb works through the same objects the pytest plugin uses, so
what the CLI reports is what a session would see.  A file-configured
project is named by ``--project`` or ``BRIXTEST_PROJECT``; advanced
adapters can still use ``--app module:attr`` or ``BRIXTEST_APP``.

Exit codes: 0 success · 1 operational failure · 2 usage error.
``--json`` swaps the human tables for one JSON document on stdout.
"""

from __future__ import annotations

import dataclasses
import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from brixtest.cli.app_commands import (
    _cmd_artifacts,
    _cmd_fleet,
    _cmd_gate,
    _cmd_lane,
    _cmd_logs,
    _cmd_map,
    _cmd_prep,
)
from brixtest.cli.author_commands import _cmd_api, _cmd_design, _cmd_new
from brixtest.cli.metrics import run_command as run_metrics_command
from brixtest.cli.parser import build_parser as _parser
from brixtest.cli.rerun import run_command as run_rerun_command
from brixtest.deploy.local import LocalBackend
from brixtest.errors import BrixTestError, SpecError
from brixtest.extensions import extension_registry, installed_extensions
from brixtest.fleet.launcher import FleetLauncher
from brixtest.fleet.prep import FleetPrep
from brixtest.fleet.registry import Registry
from brixtest.harness.gate import UndeclaredServerGate
from brixtest.harness.plugin import HarnessConfig
from brixtest.minikube import MinikubeConfig, minikube_command, minikube_status
from brixtest.project import Project
from brixtest.results.report import serve, write_index, write_report
from brixtest.results.store import ResultStore
from brixtest.services.artifacts import ArtifactCatalog
from brixtest.services.logs import LogView
from brixtest.summary import default_runs_root, list_runs, load_run

__all__ = ["main"]

_APP_ENV = "BRIXTEST_APP"
_PROJECT_ENV = "BRIXTEST_PROJECT"


class _App:
    """The CLI's working set, built once from the adapter's HarnessConfig."""

    def __init__(self, hc: HarnessConfig) -> None:
        self.hc = hc
        hc.register_kinds()
        self.registry = Registry()
        hc.register_catalogue(self.registry)
        self.registry.freeze()
        self.lane = hc.lane
        if hc.spec_validation != "off":
            warnings = self.registry.validate(self.lane)
            if warnings and hc.spec_validation == "refuse":
                raise SpecError(
                    "catalogue", "%d finding(s)" % len(warnings),
                    "; ".join(warnings),
                )
            for warning in warnings:
                print("brixtest spec warning: %s" % warning, file=sys.stderr)
        self.backend = LocalBackend(
            self.registry, self.lane, strict_templates=hc.strict_templates
        )
        self.backend.prepare(self.lane, None)
        self.launcher = FleetLauncher(
            self.registry, self.backend, self.lane, workers=hc.workers
        )
        self.gate = UndeclaredServerGate(
            self.registry, hc.declaration_map(), mode=hc.gate_mode
        )

    def prep(self) -> FleetPrep:
        return FleetPrep(self.lane, self.hc.prep_steps(self.lane))

    @property
    def artifacts(self) -> ArtifactCatalog:
        return ArtifactCatalog(self.lane.artifacts_dir)

    def log_view(self, name: str) -> LogView:
        self.registry.get_spec(name)  # unknown instance fails with known names
        return LogView(name, self.backend.logs(name))

    @property
    def results_dir(self) -> Path:
        return self.lane.root / "results"

    def store(self) -> Optional[ResultStore]:
        """The lane's run store, or None (with a hint) when no run has
        ever been catalogued — reading verbs must not create an empty db."""
        db_path = self.results_dir / "brixtest.db"
        if not db_path.exists():
            print(
                "brixtest: no runs catalogued in this lane (%s) — "
                "run the suite first" % db_path,
                file=sys.stderr,
            )
            return None
        return ResultStore(db_path)

    def resolve_run(self, store: ResultStore, run_id: str) -> Optional[str]:
        if run_id != "latest":
            return run_id
        latest = store.latest_run_id()
        if latest is None:
            print("brixtest: the store holds no runs yet", file=sys.stderr)
        return latest


def _load_app(spec: Optional[str], project: Optional[str] = None) -> _App:
    project = project or os.environ.get(_PROJECT_ENV, "")
    if project:
        return _load_project_app(project, spec)
    spec = spec or os.environ.get(_APP_ENV, "")
    return _load_adapter_app(spec)


def _load_project_app(project: str, spec: Optional[str]) -> _App:
    if spec:
        raise SystemExit("usage: --project and --app are mutually exclusive")
    return _App(Project.load(Path(project)).harness_config())


def _load_adapter_app(spec: str) -> _App:
    if not spec or ":" not in spec:
        raise SystemExit(
            "usage: name a project with --project PATH or %s, or name an "
            "adapter with --app module:attr or %s" % (_PROJECT_ENV, _APP_ENV)
        )
    module_name, attr = spec.split(":", 1)
    module = importlib.import_module(module_name)
    target = getattr(module, attr)
    hc = _harness_config(target)
    if not isinstance(hc, HarnessConfig):
        raise SystemExit("--app %s did not yield a HarnessConfig (got %r)" % (spec, type(hc)))
    return _App(hc)


def _harness_config(target):
    if callable(target) and not isinstance(target, HarnessConfig):
        return target()
    return target


def _emit(payload, as_json: bool, human_lines: List[str]) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        for line in human_lines:
            print(line)


def _cmd_run(args) -> int:
    project = args.project or os.environ.get(_PROJECT_ENV, "")
    pytest_args = _project_pytest_args(project, args.pytest_args)
    argv = [
        sys.executable, "-m", "pytest", "-p", "brixtest.pytest_plugin",
        *pytest_args,
    ]
    return subprocess.call(argv, cwd=project or None)


def _project_pytest_args(project: str, values) -> list[str]:
    pytest_args = list(values or [])
    if project and not pytest_args:
        return ["tests"]
    return pytest_args


def _cmd_summary(args) -> int:
    root = Path(args.runs).resolve() if args.runs else default_runs_root()
    if args.run == "list":
        rows = list_runs(root)
        lines = ["%-28s %-16s %-10s %8s  %s" % (
            "RUN", "OUTCOME", "BACKEND", "WALL s", "TEST"
        )] + [
            "%-28s %-16s %-10s %8.2f  %s" % (
                Path(str(row["run_root"])).name[:28], row.get("outcome", "?"),
                row.get("backend", "?"), float(row.get("wall_seconds", 0.0)),
                row.get("nodeid", "?"),
            ) for row in rows
        ] if rows else ["no retained runs under %s" % root]
        _emit(rows, args.json, lines)
        return 0
    row = load_run(args.run, root)
    _emit(row, args.json, [json.dumps(row, indent=2, sort_keys=True)])
    return 0


def _cmd_results(app: _App, args) -> int:
    store = app.store()
    if store is None:
        return 1
    handlers = {"list": _results_list, "show": _results_show}
    handler = handlers.get(args.results_cmd)
    return handler(app, store, args) if handler is not None else 2


def _results_list(app, store, args) -> int:
    rows = store.runs()
    payload = [dataclasses.asdict(info) for info in rows]
    lines = ["%-18s %-22s %6s %6s %8s" % (
        "RUN", "STARTED", "TESTS", "FAIL", "WALL s")] + [
        "%-18s %-22s %6d %6d %8.1f" % (
            info.run_id, info.started_at, info.total,
            info.counts.get("failed", 0) + info.counts.get("error", 0), info.wall_seconds,
        ) for info in rows
    ] if rows else ["the store holds no runs yet"]
    _emit(payload, args.json, lines)
    return 0


def _results_show(app, store, args) -> int:
    run_id = app.resolve_run(store, args.run)
    if run_id is None:
        return 1
    records = store.tests(run_id)
    findings = store.findings(run_id)
    payload = {
        "run_id": run_id,
        "tests": [dataclasses.asdict(record) for record in records],
        "findings": [dataclasses.asdict(finding) for finding in findings],
    }
    lines = ["%-58s %-8s %8s %7s" % ("TEST", "OUTCOME", "WALL s", "CPU s")] + [
        "%-58s %-8s %8.2f %7.2f" % (
            record.nodeid[:58], record.outcome, record.wall_seconds, record.cpu_seconds,
        ) for record in records
    ]
    lines.extend(
        "FINDING [%s] %s: %s" % (finding.kind, finding.instance, finding.detail)
        for finding in findings
    )
    _emit(payload, args.json, lines)
    return 0


def _cmd_report(app: _App, args) -> int:
    store = app.store()
    if store is None:
        return 1
    run_id = app.resolve_run(store, args.run)
    if run_id is None:
        return 1
    out = Path(args.out) if args.out else app.results_dir / run_id / "report.html"
    path = write_report(store, run_id, out)
    index = write_index(store, app.results_dir / "index.html")
    _emit({"report": str(path), "index": str(index)}, args.json,
          [str(path), str(index)])
    return 0


def _cmd_export(app: _App, args) -> int:
    store = app.store()
    if store is None:
        return 1
    run_id = app.resolve_run(store, args.run)
    if run_id is None:
        return 1
    out = Path(args.out) if args.out else app.results_dir / ("%s.jsonl" % run_id)
    count = store.export_opensearch(run_id, out, index_prefix=args.index_prefix)
    _emit({"path": str(out), "documents": count}, args.json,
          ["%s (%d documents, OpenSearch bulk format)" % (out, count)])
    return 0


def _cmd_portal(app: _App, args) -> int:
    store = app.store()
    if store is not None:
        write_index(store, app.results_dir / "index.html")  # fresh landing page
    port = args.port or app.lane.port_base + app.lane.port_span - 1
    serve(app.results_dir, port)   # blocks until Ctrl-C
    return 0


def _cmd_plugins(args) -> int:
    _load_builtin_extensions()
    payload = [_plugin_payload(info, args.load) for info in installed_extensions(args.kind)]
    lines = _plugin_lines(payload)
    _emit({"extensions": payload}, args.json, lines)
    return 1 if any(row["error"] for row in payload) else 0


def _load_builtin_extensions() -> None:
    for module in (
        "brixtest.runtime.artifacts", "brixtest.runtime.backends",
        "brixtest.runtime.executors", "brixtest.runtime.launchers",
    ):
        importlib.import_module(module)


def _plugin_payload(info, load: bool) -> dict:
    error = ""
    loaded = info.loaded
    if load:
        try:
            extension_registry.load(info.kind, info.name)
            loaded = True
        except Exception as exc:
            error = "%s: %s" % (type(exc).__name__, exc)
    return {
        "kind": info.kind, "name": info.name, "api_version": info.api_version,
        "capabilities": list(info.capabilities), "origin": info.origin,
        "loaded": loaded, "error": error,
    }


def _plugin_lines(payload) -> list[str]:
    lines = ["%-12s %-24s %-7s %-8s %s" % (
        "KIND", "NAME", "API", "LOADED", "ORIGIN",
    )]
    lines.extend(
        "%-12s %-24s %-7d %-8s %s%s" % (
            row["kind"], row["name"], row["api_version"],
            "yes" if row["loaded"] else "no", row["origin"],
            " (%s)" % row["error"] if row["error"] else "",
        ) for row in payload
    )
    if len(lines) == 1:
        lines.append("no extensions discovered")
    return lines


def _cmd_doctor(args) -> int:
    import pytest

    _load_builtin_extensions()
    tools = _doctor_tools()
    required = tuple(args.require or ())
    missing = [name for name in required if not tools[name]["available"]]
    extensions = installed_extensions()
    payload = _doctor_payload(tools, missing, extensions, pytest.__version__)
    _emit(payload, args.json, _doctor_lines(payload, tools, extensions))
    return int(bool(missing))


def _doctor_payload(tools, missing, extensions, pytest_version: str) -> dict:
    payload = {
        "ok": not missing,
        "python": {"version": sys.version.split()[0], "executable": sys.executable},
        "pytest": {"version": pytest_version},
        "package": str(Path(__file__).resolve().parents[2]),
        "tools": tools,
        "extensions": len(extensions),
        "missing_required": missing,
    }
    return payload


def _doctor_lines(payload: dict, tools: dict, extensions) -> list[str]:
    lines = [
        "BriXTest doctor: %s" % _doctor_health(payload["ok"]),
        "Python %s: %s" % (payload["python"]["version"], payload["python"]["executable"]),
        "pytest %s" % payload["pytest"]["version"],
    ]
    lines.extend(
        "%-10s %s" % (name, row["path"] or "not installed")
        for name, row in tools.items()
    )
    lines.append("extensions: %d" % len(extensions))
    return lines


def _doctor_health(healthy: bool) -> str:
    return "healthy" if healthy else "requirements missing"


def _doctor_tools() -> dict:
    tools = {}
    for name in ("docker", "podman", "runc", "nsenter", "kubectl", "minikube"):
        path = shutil.which(name)
        tools[name] = {"available": path is not None, "path": path or ""}
    return tools


def _cmd_minikube(args) -> int:
    """Operate the dedicated Docker-backed local Kubernetes target."""
    config = _minikube_config(args)
    if args.minikube_cmd == "status":
        return _minikube_status_command(config, args.json)
    paths = _minikube_paths(args.minikube_cmd, args.pytest_args)
    return minikube_command(args.minikube_cmd, config, pytest_args=paths)


def _minikube_config(args) -> MinikubeConfig:
    defaults = MinikubeConfig.from_environment()
    cpus = defaults.cpus if args.cpus is None else args.cpus
    memory = defaults.memory_mb if args.memory is None else args.memory
    return dataclasses.replace(
        defaults, profile=args.profile or defaults.profile,
        cpus=cpus, memory_mb=memory,
    )


def _minikube_paths(command: str, values) -> tuple[str, ...]:
    paths = tuple(values or ())
    if command == "test" and not paths:
        return ("tests/integration/test_minikube_auth.py", "-v")
    return paths


def _minikube_status_command(config, json_output: bool) -> int:
    payload = minikube_status(config)
    lines = [
        "Minikube profile %s: %s" % (
            config.profile, "ready" if payload["ok"] else "not ready",
        ),
        "driver: docker; container runtime: docker",
    ]
    lines.extend(_minikube_detail_lines(payload))
    _emit(payload, json_output, lines)
    return int(not payload["ok"])


def _minikube_detail_lines(payload: dict) -> list[str]:
    lines = []
    if payload.get("details"):
        lines.append(json.dumps(payload["details"], sort_keys=True))
    if payload.get("error"):
        lines.append(str(payload["error"]))
    return lines


def _direct_command(args) -> Optional[int]:
    commands = {
        "run": _cmd_run, "new": _cmd_new, "design": _cmd_design,
        "api": _cmd_api, "plugins": _cmd_plugins, "doctor": _cmd_doctor,
        "minikube": _cmd_minikube, "summary": _cmd_summary,
        "metrics": run_metrics_command, "rerun": run_rerun_command,
    }
    command = commands.get(args.cmd)
    return command(args) if command is not None else None


def _app_command(app: _App, args) -> int:
    commands = {
        "fleet": _cmd_fleet, "prep": _cmd_prep, "lane": _cmd_lane,
        "artifacts": _cmd_artifacts, "logs": _cmd_logs, "gate": _cmd_gate,
        "map": _cmd_map, "results": _cmd_results, "report": _cmd_report,
        "export": _cmd_export, "portal": _cmd_portal,
    }
    if args.cmd == "artifacts" and args.artifacts_cmd == "path" and not args.name:
        print("usage: brixtest artifacts path <name>", file=sys.stderr)
        return 2
    command = commands.get(args.cmd)
    return command(app, args) if command is not None else 2


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        direct = _direct_command(args)
        if direct is not None:
            return direct
        app = _load_app(args.app, args.project)
        return _app_command(app, args)
    except BrixTestError as exc:
        print("brixtest: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
