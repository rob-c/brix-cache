"""Argument parser for the BriXTest operator CLI."""

from __future__ import annotations

import argparse

from brixtest.cli.metrics import add_parser as add_metrics_parser
from brixtest.extensions import ENTRY_POINT_GROUPS
from brixtest.introspection import api_contract

_APP_ENV = "BRIXTEST_APP"
_PROJECT_ENV = "BRIXTEST_PROJECT"

def build_parser() -> argparse.ArgumentParser:
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

    _add_result_commands(sub)
    return parser


def _add_result_commands(sub) -> None:
    summary = sub.add_parser(
        "summary", help="list or inspect retained isolated case runs"
    )
    summary.add_argument(
        "run", nargs="?", default="list",
        help="list, latest, a run id, or a run path",
    )
    summary.add_argument("--runs", help="runs directory (default: $BRIXTEST_RUNS)")
    add_metrics_parser(sub)

    rerun = sub.add_parser("rerun", help="re-run a failed managed test exactly")
    rerun.add_argument(
        "session", nargs="?", default="latest",
        help="session id or latest (default: latest)",
    )
    rerun.add_argument("--test", help="exact node id (default: first failure)")
    rerun.add_argument("--all", action="store_true", help="re-run all failures in order")
    rerun.add_argument("--runs", help="runs directory (default: $BRIXTEST_RUNS)")

    results = sub.add_parser("results", help="catalogued runs and their tests")
    results.add_argument("results_cmd", choices=["list", "show"])
    results.add_argument(
        "run", nargs="?", default="latest", help="run id (default: latest)",
    )

    report = sub.add_parser("report", help="render a run to a static HTML page")
    report.add_argument("--run", default="latest", help="run id (default: latest)")
    report.add_argument("-o", "--out", help="output path (default: in the run dir)")

    export = sub.add_parser(
        "export", help="emit a run as OpenSearch bulk-API JSONL"
    )
    export.add_argument("--run", default="latest", help="run id (default: latest)")
    export.add_argument("-o", "--out", help="output path (default: <run>.jsonl)")
    export.add_argument(
        "--index-prefix", default="brixtest",
        help="index name prefix (default: brixtest)",
    )

    portal = sub.add_parser("portal", help="serve the results directory over HTTP")
    portal.add_argument(
        "--port", type=int, default=0,
        help="port (default: the lane's top port)",
    )
