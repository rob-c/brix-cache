"""``brixtest`` — the operator's front end (feature F14).

Every verb works through the same objects the pytest plugin uses, so
what the CLI reports is what a session would see.  A file-configured
project is named by ``--project`` or ``BRIXTEST_PROJECT``; advanced
adapters can still use ``--app module:attr`` or ``BRIXTEST_APP``.

Exit codes: 0 success · 1 operational failure · 2 usage error.
``--json`` swaps the human tables for one JSON document on stdout.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from brixtest.cli.metrics import add_parser as add_metrics_parser
from brixtest.cli.metrics import run_command as run_metrics_command
from brixtest.cli.rerun import run_command as run_rerun_command
from brixtest.deploy.local import LocalBackend
from brixtest.errors import BrixTestError, QuiescenceError, SpecError
from brixtest.extensions import ENTRY_POINT_GROUPS, extension_registry, installed_extensions
from brixtest.fleet.launcher import FleetLauncher, FleetPlan
from brixtest.fleet.prep import FleetPrep
from brixtest.fleet.registry import Registry
from brixtest.harness.gate import UndeclaredServerGate
from brixtest.harness.plugin import HarnessConfig
from brixtest.introspection import api_contract
from brixtest.minikube import MinikubeConfig, minikube_command, minikube_status
from brixtest.project import Project
from brixtest.results import mapping
from brixtest.results.report import serve, write_index, write_report
from brixtest.results.store import ResultStore
from brixtest.services.artifacts import ArtifactCatalog
from brixtest.services.logs import LogView
from brixtest.summary import default_runs_root, list_runs, load_run
from brixtest.util.net import listening_ports, pids_on_port

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
        if hc.spec_validation != "off":     # F1: same tiers as the plugin
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
        if spec:
            raise SystemExit("usage: --project and --app are mutually exclusive")
        return _App(Project.load(Path(project)).harness_config())
    spec = spec or os.environ.get(_APP_ENV, "")
    if not spec or ":" not in spec:
        raise SystemExit(
            "usage: name a project with --project PATH or %s, or name an "
            "adapter with --app module:attr or %s" % (_PROJECT_ENV, _APP_ENV)
        )
    module_name, attr = spec.split(":", 1)
    module = importlib.import_module(module_name)
    target = getattr(module, attr)
    hc = target() if callable(target) and not isinstance(target, HarnessConfig) else target
    if not isinstance(hc, HarnessConfig):
        raise SystemExit("--app %s did not yield a HarnessConfig (got %r)" % (spec, type(hc)))
    return _App(hc)


def _emit(payload, as_json: bool, human_lines: List[str]) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        for line in human_lines:
            print(line)


# -- verbs ---------------------------------------------------------------

def _cmd_fleet(app: _App, args) -> int:
    if args.fleet_cmd == "plan":
        plan = FleetPlan.build(app.registry.all_specs())
        _emit(
            {"levels": [[s.name for s in level] for level in plan.levels]},
            args.json, plan.describe().splitlines(),
        )
        return 0

    if args.fleet_cmd == "status":
        rows = []
        for spec in app.registry.all_specs():
            ready = app.backend.is_ready(spec)
            rows.append({
                "name": spec.name, "kind": spec.kind,
                "port": spec.primary_port, "ready": ready,
            })
        lines = [
            "%-28s %-10s %-6s %s" % ("NAME", "KIND", "PORT", "READY"),
        ] + [
            "%-28s %-10s %-6s %s" % (
                r["name"], r["kind"], r["port"] or "-", "yes" if r["ready"] else "no",
            ) for r in rows
        ]
        _emit(rows, args.json, lines)
        return 0

    if args.fleet_cmd in ("start-all", "restart"):
        if args.fleet_cmd == "restart":
            try:
                app.launcher.stop()
            except QuiescenceError as exc:
                print(str(exc), file=sys.stderr)
                return 1
        steps = app.hc.prep_steps(app.lane)
        artifacts = FleetPrep(app.lane, steps).run() if steps else None
        app.backend.prepare(app.lane, artifacts)
        report = app.launcher.start_registered()
        payload = [dataclasses.asdict(o) for o in report.outcomes]
        lines = ["%s: %s%s" % (o.name, o.status, " — " + o.error if o.error else "")
                 for o in report.outcomes] + [report.summary()]
        _emit(payload, args.json, lines)
        return 0 if report.ok else 1

    if args.fleet_cmd == "stop-all":
        try:
            app.launcher.stop()
        except QuiescenceError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        _emit({"stopped": True}, args.json, ["fleet stopped; quiescence proven"])
        return 0

    return 2


def _cmd_prep(app: _App, args) -> int:
    prep = app.prep()
    if args.explain:
        text = prep.explain()
        _emit({"explain": text.splitlines()}, args.json, text.splitlines())
        return 0
    prep.run()
    text = prep.explain()
    _emit({"ran": True, "decision": text.splitlines()}, args.json, text.splitlines())
    return 0


def _cmd_lane(app: _App, args) -> int:
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
        "owner": dataclasses.asdict(owner) if owner else None,
        "listening": {str(k): v for k, v in holders.items()},
    }
    lines = [
        "lane root:  %s" % lane.root,
        "ports:      %d-%d" % (lane.port_base, lane.port_base + lane.port_span - 1),
        "owner:      %s" % (
            "%s (pid %d, since %s, %s)" % (
                owner.session, owner.pid, owner.started_at,
                "alive" if owner.alive() else "dead",
            ) if owner else "none"
        ),
    ]
    if holders:
        lines.append("listening:")
        named = app.registry.declared_ports()
        for port, pids in holders.items():
            lines.append("  %-6d %-28s pids %s" % (
                port, named.get(port, "(undeclared)"), ",".join(map(str, pids)) or "?",
            ))
    else:
        lines.append("listening:  nothing in range")
    _emit(payload, args.json, lines)
    return 0


def _cmd_artifacts(app: _App, args) -> int:
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


def _cmd_logs(app: _App, args) -> int:
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


def _cmd_gate(app: _App, args) -> int:
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


def _cmd_map(app: _App, args) -> int:
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


def _cmd_run(args) -> int:
    project = args.project or os.environ.get(_PROJECT_ENV, "")
    pytest_args = list(args.pytest_args or [])
    if project and not pytest_args:
        pytest_args = ["tests"]
    argv = [
        sys.executable, "-m", "pytest", "-p", "brixtest.pytest_plugin"
    ] + pytest_args
    return subprocess.call(argv, cwd=project or None)


def _cmd_new(args) -> int:
    """Create a minimal managed test without hiding generated machinery."""
    project = Path(args.project or os.environ.get(_PROJECT_ENV, ".")).resolve()
    destination = Path(args.path)
    if not destination.is_absolute():
        destination = project / destination
    if destination.suffix != ".py":
        raise SpecError("new test path", str(destination), "must end in .py")
    files = {destination: (
        "import sys\n\n"
        "from brixtest import case, execution, tool\n\n"
        "PYTHON = tool(\"python\", execution=execution(\n"
        "    sys.executable, \"-c\", \"print('hello from BriXTest')\",\n"
        "))\n\n\n"
        "@case(PYTHON)\n"
        "def test_new_feature(run):\n"
        "    result = run.tool(PYTHON).run()\n"
        "    assert result.stdout.strip() == \"hello from BriXTest\"\n"
    )}
    if args.nginx:
        config = destination.parent / "configs" / "nginx.conf.in"
        files = {
            config: (
                "pid {workspace}/nginx.pid;\n"
                "error_log /dev/stderr notice;\n"
                "events {}\n"
                "http {\n"
                "    access_log /dev/stdout;\n"
                "    server {\n"
                "        listen {host}:{port};\n"
                "        location / { return 200 'hello from BriXTest\\n'; }\n"
                "    }\n"
                "}\n"
            ),
            destination: (
                "import sys\n"
                "from pathlib import Path\n\n"
                "from brixtest import (\n"
                "    binary, case, config_ref, execution, http_endpoint, http_probe,\n"
                "    server, server_ref, template_config, tool,\n"
                ")\n\n"
                "HERE = Path(__file__).parent\n"
                "NGINX = binary(\"nginx\", \"nginx\")\n"
                "ORIGIN = server(\n"
                "    \"origin\", binary=NGINX,\n"
                "    args=[\"-p\", \"{workspace}\", \"-c\", config_ref(\"nginx.conf\"), \"-g\", \"daemon off;\"],\n"
                "    config=template_config(HERE / \"configs/nginx.conf.in\", destination=\"nginx.conf\"),\n"
                "    endpoints=[http_endpoint()], probe=http_probe(),\n"
                ")\n"
                "HTTP = tool(\"http\", execution=execution(\n"
                "    sys.executable, \"-c\",\n"
                "    \"import sys,urllib.request;print(urllib.request.urlopen(sys.argv[1]).read().decode(),end='')\",\n"
                "    server_ref(ORIGIN, role=\"http\"),\n"
                "))\n\n\n"
                "@case(ORIGIN, HTTP)\n"
                "def test_nginx_serves_a_page(run):\n"
                "    assert run.tool(HTTP).run().stdout == \"hello from BriXTest\\n\"\n"
            ),
        }
    existing = [path for path in files if path.exists()]
    if existing and not args.force:
        raise SpecError(
            "new test", ", ".join(str(path) for path in existing),
            "already exists; pass --force to replace generated files",
        )
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    print("created %s" % destination)
    if args.nginx:
        print("created %s" % (destination.parent / "configs" / "nginx.conf.in"))
    return 0


def _cmd_design(args) -> int:
    project = args.project or os.environ.get(_PROJECT_ENV, "")
    paths = list(args.paths or ["tests"])
    argv = [
        sys.executable, "-m", "pytest", "-p", "brixtest.pytest_plugin", *paths,
        "--collect-only", "--brixtest-describe", "-q",
    ]
    return subprocess.call(argv, cwd=project or None)


def _cmd_api(args) -> int:
    contract = api_contract()
    symbols = [
        symbol for symbol in contract["symbols"]
        if (not args.group or symbol["group"] == args.group)
        and (not args.name or symbol["name"] == args.name)
    ]
    if args.name and not symbols:
        print(
            "brixtest: no public API symbol named %r; use `brixtest api` to list names"
            % args.name,
            file=sys.stderr,
        )
        return 2

    if args.json:
        payload = dict(contract)
        payload["symbols"] = symbols
        if args.group or args.name:
            visible = {symbol["name"] for symbol in symbols}
            payload["groups"] = {
                group: [name for name in names if name in visible]
                for group, names in contract["groups"].items()
                if any(name in visible for name in names)
            }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    lines = [
        "BriXTest %s public API (schema %s)"
        % (contract["version"], contract["schema_version"]),
    ]
    group_order = {name: index for index, name in enumerate(contract["groups"])}
    human_symbols = sorted(
        symbols,
        key=lambda symbol: (group_order[symbol["group"]], symbol["name"]),
    )
    current_group = None
    for symbol in human_symbols:
        if symbol["group"] != current_group:
            current_group = symbol["group"]
            lines.extend(("", current_group + ":"))
        name = symbol["name"]
        if symbol["kind"] in ("function", "class"):
            name += "(" + ", ".join(symbol["call_shape"]) + ")"
        lines.append("  %-38s %-8s %s" % (
            name, symbol["kind"], symbol["module"],
        ))
        if symbol["attributes"]:
            lines.append("    attributes: " + ", ".join(symbol["attributes"]))
        if symbol["members"]:
            member_rows = []
            properties = set(symbol["properties"])
            for member in symbol["members"]:
                if member in properties:
                    member_rows.append(member + " [property]")
                else:
                    shape = symbol["member_call_shapes"][member]
                    member_rows.append(member + "(" + ", ".join(shape) + ")")
            lines.append("    members: " + ", ".join(member_rows))
    if not args.name and not args.group:
        pytest_surface = contract["pytest"]
        lines.extend((
            "",
            "pytest:",
            "  fixtures: " + ", ".join(pytest_surface["fixtures"]),
            "  markers:  " + ", ".join(pytest_surface["markers"]),
            "  ini:      " + ", ".join(pytest_surface["ini"]),
            "  hooks:    " + ", ".join(pytest_surface["hooks"]),
            "  options:  %d public --brixtest-* options"
            % len(pytest_surface["options"]),
        ))
    for line in lines:
        print(line)
    return 0


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
    if args.results_cmd == "list":
        rows = store.runs()
        payload = [dataclasses.asdict(info) for info in rows]
        lines = ["%-18s %-22s %6s %6s %8s" % (
            "RUN", "STARTED", "TESTS", "FAIL", "WALL s")] + [
            "%-18s %-22s %6d %6d %8.1f" % (
                info.run_id, info.started_at, info.total,
                info.counts.get("failed", 0) + info.counts.get("error", 0),
                info.wall_seconds,
            ) for info in rows
        ] if rows else ["the store holds no runs yet"]
        _emit(payload, args.json, lines)
        return 0
    if args.results_cmd == "show":
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
            "%-58s %-8s %8.2f %7.2f" % (record.nodeid[:58], record.outcome,
                                        record.wall_seconds, record.cpu_seconds)
            for record in records
        ]
        for finding in findings:
            lines.append("FINDING [%s] %s: %s"
                         % (finding.kind, finding.instance, finding.detail))
        _emit(payload, args.json, lines)
        return 0
    return 2


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
    # Built-in backends implement the same contract as package extensions and
    # should be visible to operators even before a test imports the runtime.
    for module in (
        "brixtest.runtime.artifacts", "brixtest.runtime.backends",
        "brixtest.runtime.executors", "brixtest.runtime.launchers",
    ):
        importlib.import_module(module)
    rows = installed_extensions(args.kind)
    payload = []
    for info in rows:
        error = ""
        loaded = info.loaded
        if args.load:
            try:
                extension_registry.load(info.kind, info.name)
                loaded = True
            except Exception as exc:
                error = "%s: %s" % (type(exc).__name__, exc)
        payload.append({
            "kind": info.kind, "name": info.name,
            "api_version": info.api_version,
            "capabilities": list(info.capabilities),
            "origin": info.origin, "loaded": loaded, "error": error,
        })
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
    _emit({"extensions": payload}, args.json, lines)
    return 1 if any(row["error"] for row in payload) else 0


def _cmd_doctor(args) -> int:
    import pytest

    for module in (
        "brixtest.runtime.artifacts", "brixtest.runtime.backends",
        "brixtest.runtime.executors", "brixtest.runtime.launchers",
    ):
        importlib.import_module(module)
    tools = {}
    for name in ("docker", "podman", "runc", "nsenter", "kubectl", "minikube"):
        path = shutil.which(name)
        tools[name] = {"available": path is not None, "path": path or ""}
    required = tuple(args.require or ())
    missing = [name for name in required if not tools[name]["available"]]
    extensions = installed_extensions()
    payload = {
        "ok": not missing,
        "python": {"version": sys.version.split()[0], "executable": sys.executable},
        "pytest": {"version": pytest.__version__},
        "package": str(Path(__file__).resolve().parents[2]),
        "tools": tools,
        "extensions": len(extensions),
        "missing_required": missing,
    }
    lines = [
        "BriXTest doctor: %s" % ("healthy" if not missing else "requirements missing"),
        "Python %s: %s" % (payload["python"]["version"], payload["python"]["executable"]),
        "pytest %s" % payload["pytest"]["version"],
    ]
    lines.extend(
        "%-10s %s" % (name, row["path"] or "not installed")
        for name, row in tools.items()
    )
    lines.append("extensions: %d" % len(extensions))
    _emit(payload, args.json, lines)
    return 1 if missing else 0


def _cmd_minikube(args) -> int:
    """Operate the dedicated Docker-backed local Kubernetes target."""
    defaults = MinikubeConfig.from_environment()
    config = dataclasses.replace(
        defaults,
        profile=args.profile or defaults.profile,
        cpus=args.cpus if args.cpus is not None else defaults.cpus,
        memory_mb=args.memory if args.memory is not None else defaults.memory_mb,
    )
    if args.minikube_cmd == "status":
        payload = minikube_status(config)
        details = payload.get("details", {})
        lines = [
            "Minikube profile %s: %s" % (
                config.profile, "ready" if payload["ok"] else "not ready",
            ),
            "driver: docker; container runtime: docker",
        ]
        if details:
            lines.append(json.dumps(details, sort_keys=True))
        if payload.get("error"):
            lines.append(str(payload["error"]))
        _emit(payload, args.json, lines)
        return 0 if payload["ok"] else 1
    paths = tuple(args.pytest_args or ())
    if args.minikube_cmd == "test" and not paths:
        paths = ("tests/integration/test_minikube_auth.py", "-v")
    return minikube_command(args.minikube_cmd, config, pytest_args=paths)


# -- entry ---------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="brixtest", description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--project", help="BriXTest project directory (or $%s)" % _PROJECT_ENV
    )
    source.add_argument("--app", help="adapter as module:attr (or $%s)" % _APP_ENV)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="cmd", required=True)

    fleet = sub.add_parser("fleet", help="start, stop, and inspect the fleet")
    fleet.add_argument(
        "fleet_cmd",
        choices=["start-all", "stop-all", "restart", "status", "plan"],
    )

    prep = sub.add_parser("prep", help="build or restore the artifact tree")
    prep.add_argument("--explain", action="store_true", help="narrate; do not run")

    lane = sub.add_parser("lane", help="lane ownership and listeners")
    lane.add_argument("lane_cmd", choices=["status"])

    artifacts = sub.add_parser("artifacts", help="the published-artifact catalog")
    artifacts.add_argument("artifacts_cmd", choices=["list", "path"])
    artifacts.add_argument("name", nargs="?", help="artifact name (for `path`)")

    logs = sub.add_parser("logs", help="an instance's service log")
    logs.add_argument("instance", help="registered instance name")
    logs.add_argument("--tail", type=int, default=40, metavar="N",
                      help="show the last N lines (default 40)")
    logs.add_argument("--path", action="store_true",
                      help="print the log path instead of content")

    gate = sub.add_parser("gate", help="declared-usage analysis")
    gate.add_argument("gate_cmd", choices=["explain"])
    gate.add_argument("file", help="test file to analyze")

    mapper = sub.add_parser(
        "map", help="the test ↔ server map, declared or observed"
    )
    mapper.add_argument("paths", nargs="*",
                        help="test files/dirs for the declared (contract) view")
    mapper.add_argument("--run", metavar="RUN",
                        help="observed view from a catalogued run ('latest' works)")
    mapper.add_argument("--mermaid", action="store_true",
                        help="emit a Mermaid graph instead of the matrix")

    run = sub.add_parser("run", help="run pytest under the harness")
    run.add_argument("pytest_args", nargs=argparse.REMAINDER)

    new = sub.add_parser("new", help="scaffold a minimal managed pytest case")
    new.add_argument("path", help="new test path, relative to --project")
    new.add_argument("--nginx", action="store_true",
                     help="include an on-disk nginx template and live HTTP assertion")
    new.add_argument("--force", action="store_true",
                     help="replace only the generated target files if they exist")

    design = sub.add_parser(
        "design", help="inspect Pythonic case resource graphs without starting them"
    )
    design.add_argument("paths", nargs="*", help="test files or directories")

    api = sub.add_parser(
        "api", help="browse the stable Python and pytest author contract"
    )
    api.add_argument("name", nargs="?", help="show one exact top-level symbol")
    api.add_argument(
        "--group", choices=tuple(api_contract()["groups"]),
        help="show one public API category",
    )

    plugins = sub.add_parser(
        "plugins", help="discover and validate BriXTest extension packages"
    )
    plugins.add_argument("--kind", choices=tuple(sorted(ENTRY_POINT_GROUPS)))
    plugins.add_argument("--load", action="store_true",
                         help="import and contract-check discovered implementations")

    doctor = sub.add_parser(
        "doctor", help="check pytest, runtimes, Kubernetes tooling, and extensions"
    )
    doctor.add_argument(
        "--require", action="append", choices=("docker", "podman", "runc", "nsenter", "kubectl", "minikube"),
        help="fail when this optional execution tool is unavailable (repeatable)",
    )

    minikube = sub.add_parser(
        "minikube", help="operate the supported Docker-backed local Kubernetes target",
    )
    minikube.add_argument("minikube_cmd", choices=("start", "status", "test"))
    minikube.add_argument(
        "--profile",
        help="dedicated profile name (default: brixtest)",
    )
    minikube.add_argument("--cpus", type=int)
    minikube.add_argument("--memory", type=int, metavar="MIB")
    minikube.add_argument("pytest_args", nargs=argparse.REMAINDER)
    api.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS,
        help="emit the immutable contract as JSON",
    )

    summary = sub.add_parser(
        "summary", help="list or inspect retained isolated case runs"
    )
    summary.add_argument("run", nargs="?", default="list",
                         help="list, latest, a run id, or a run path")
    summary.add_argument("--runs", help="runs directory (default: $BRIXTEST_RUNS)")

    add_metrics_parser(sub)

    rerun = sub.add_parser("rerun", help="re-run a failed managed test exactly")
    rerun.add_argument("session", nargs="?", default="latest",
                       help="session id or latest (default: latest)")
    rerun.add_argument("--test", help="exact node id (default: first failure)")
    rerun.add_argument("--all", action="store_true", help="re-run all failures in order")
    rerun.add_argument("--runs", help="runs directory (default: $BRIXTEST_RUNS)")

    results = sub.add_parser("results", help="catalogued runs and their tests")
    results.add_argument("results_cmd", choices=["list", "show"])
    results.add_argument("run", nargs="?", default="latest",
                         help="run id (default: latest)")

    report = sub.add_parser("report", help="render a run to a static HTML page")
    report.add_argument("--run", default="latest", help="run id (default: latest)")
    report.add_argument("-o", "--out", help="output path (default: in the run dir)")

    export = sub.add_parser(
        "export", help="emit a run as OpenSearch bulk-API JSONL"
    )
    export.add_argument("--run", default="latest", help="run id (default: latest)")
    export.add_argument("-o", "--out", help="output path (default: <run>.jsonl)")
    export.add_argument("--index-prefix", default="brixtest",
                        help="index name prefix (default: brixtest)")

    portal = sub.add_parser("portal", help="serve the results directory over HTTP")
    portal.add_argument("--port", type=int, default=0,
                        help="port (default: the lane's top port)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.cmd == "run":
            return _cmd_run(args)
        if args.cmd == "new":
            return _cmd_new(args)
        if args.cmd == "design":
            return _cmd_design(args)
        if args.cmd == "api":
            return _cmd_api(args)
        if args.cmd == "plugins":
            return _cmd_plugins(args)
        if args.cmd == "doctor":
            return _cmd_doctor(args)
        if args.cmd == "minikube":
            return _cmd_minikube(args)
        if args.cmd == "summary":
            return _cmd_summary(args)
        if args.cmd == "metrics":
            return run_metrics_command(args)
        if args.cmd == "rerun":
            return run_rerun_command(args)
        app = _load_app(args.app, args.project)
        if args.cmd == "fleet":
            return _cmd_fleet(app, args)
        if args.cmd == "prep":
            return _cmd_prep(app, args)
        if args.cmd == "lane":
            return _cmd_lane(app, args)
        if args.cmd == "artifacts":
            if args.artifacts_cmd == "path" and not args.name:
                print("usage: brixtest artifacts path <name>", file=sys.stderr)
                return 2
            return _cmd_artifacts(app, args)
        if args.cmd == "logs":
            return _cmd_logs(app, args)
        if args.cmd == "gate":
            return _cmd_gate(app, args)
        if args.cmd == "map":
            return _cmd_map(app, args)
        if args.cmd == "results":
            return _cmd_results(app, args)
        if args.cmd == "report":
            return _cmd_report(app, args)
        if args.cmd == "export":
            return _cmd_export(app, args)
        if args.cmd == "portal":
            return _cmd_portal(app, args)
        return 2
    except BrixTestError as exc:
        print("brixtest: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
