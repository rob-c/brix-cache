"""CLI parser and workflows for unified experiment evidence."""

from __future__ import annotations

import json
from pathlib import Path

from brixtest.archive import write_bulk_archive, write_sqlite_archive
from brixtest.evidence.analysis import compare, session_insights, trend
from brixtest.evidence.export import package_session, write_otlp_json, write_parquet
from brixtest.evidence.store import integrity, query, query_duckdb
from brixtest.evidence.retention import verify_objects
from brixtest.errors import SpecError
from brixtest.extensions import get_extension
from brixtest.metrics import (
    list_metric_sessions, load_metric_session, render_metrics_html, write_metrics_csv,
)
from brixtest.summary import default_runs_root

__all__ = ["add_parser", "run_command"]


def add_parser(sub) -> None:
    parser = sub.add_parser(
        "metrics", help="inspect, compare, query, or export unified test evidence"
    )
    parser.add_argument(
        "metrics_cmd", nargs="?", default="show",
        choices=["list", "show", "export", "report", "compare", "trend", "insights",
                 "regress", "query", "integrity", "analyze"],
    )
    parser.add_argument("session", nargs="?", default="latest", help="session id or latest")
    parser.add_argument("other", nargs="?", help="candidate session for compare/regress")
    parser.add_argument("--runs", help="runs directory (default: $BRIXTEST_RUNS)")
    parser.add_argument("-o", "--out", help="export/report output path")
    parser.add_argument(
        "--format", choices=["json", "csv", "sqlite", "bulk", "parquet", "otlp", "package", "plugin"],
        default="json", help="export format (default: json)",
    )
    parser.add_argument("--plugin", help="named analyzer/exporter extension")
    parser.add_argument(
        "--option", action="append", default=[], metavar="NAME=VALUE",
        help="extension option; JSON values are decoded when possible",
    )
    parser.add_argument("--metric", help="restrict comparisons/trends to one metric")
    parser.add_argument("--threshold", type=float, default=0.05,
                        help="relative regression threshold (default: 0.05)")
    parser.add_argument("--effect", type=float, default=0.147,
                        help="minimum Cliff's delta (default: 0.147)")
    parser.add_argument("--sql", help="read-only SQLite or DuckDB query")
    parser.add_argument("--engine", choices=["sqlite", "duckdb"], default="sqlite")
    parser.add_argument("--limit", type=int, default=20,
                        help="maximum sessions used by trend (default: 20)")
    parser.add_argument("--min-samples", type=int, default=3,
                        help="minimum aligned samples for insights (default: 3)")
    parser.add_argument("--correlation", type=float, default=0.7,
                        help="absolute correlation reported by insights (default: 0.7)")
    parser.add_argument("--outlier-z", type=float, default=3.5,
                        help="robust outlier threshold for insights (default: 3.5)")
    parser.add_argument("--max-series", type=int, default=128,
                        help="maximum correlation series per test (default: 128)")


def _emit(payload, as_json: bool, lines: list[str]) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        for line in lines:
            print(line)


def _title(row) -> str:
    labels = dict(row.get("labels", {}))
    suffix = "{%s}" % ",".join("%s=%s" % item for item in sorted(labels.items())) if labels else ""
    return "%s%s" % (row.get("name", "?"), suffix)


def _list(args, runs: Path) -> int:
    sessions = list_metric_sessions(runs)
    lines = ["%-30s %7s %7s  %s" % ("SESSION", "TESTS", "FAIL", "REPORT")] + [
        "%-30s %7d %7d  %s" % (
            str(row.get("session_id", "?"))[:30], len(row.get("tests", [])),
            int(row.get("counts", {}).get("failed", 0)),
            Path(str(row.get("path", ""))) / "report.html",
        ) for row in sessions
    ] if sessions else ["no metric sessions under %s" % (runs / "metrics")]
    _emit(sessions, args.json, lines)
    return 0


def _show(args, payload) -> int:
    rows = payload.get("aggregates", [])
    lines = ["%-48s %-8s %6s %12s %12s %12s" % (
        "METRIC", "UNIT", "N", "MEAN", "P95", "MAX"
    )] + [
        "%-48s %-8s %6d %12.6g %12.6g %12.6g" % (
            _title(row)[:48], str(row.get("unit", ""))[:8],
            int(row.get("samples", 0)), float(row.get("mean", 0)),
            float(row.get("p95", 0)), float(row.get("max", 0)),
        ) for row in rows
    ]
    _emit(payload, args.json, lines)
    return 0


def _comparison(args, runs: Path, *, gate: bool) -> int:
    if not args.other:
        raise SpecError("metrics comparison", args.other, "needs BASELINE CANDIDATE sessions")
    baseline = load_metric_session(args.session, runs)
    candidate = load_metric_session(args.other, runs)
    result = compare(
        baseline, candidate, metric=args.metric or "",
        relative_threshold=args.threshold, effect_threshold=args.effect,
    )
    lines = ["%-42s %-28s %10s %10s %9s" % (
        "TEST", "METRIC", "BASE", "CAND", "CHANGE"
    )]
    for row in result["series"]:
        lines.append("%-42s %-28s %10.4g %10.4g %+8.2f%%" % (
            row["nodeid"][-42:], row["metric"][:28],
            row["baseline"].get("mean", 0), row["candidate"].get("mean", 0),
            row["relative_change"] * 100,
        ))
    for finding in result["findings"]:
        lines.append("REGRESSION %s %s: %s" % (
            finding["nodeid"], finding["metric"], finding["detail"]
        ))
    _emit(result, args.json, lines)
    return 1 if gate and any(row.get("severity") == "error"
                             for row in result["findings"]) else 0


def _trend(args, runs: Path) -> int:
    if not args.metric:
        raise SpecError("metrics trend", args.metric, "requires --metric NAME")
    sessions = list(reversed(list_metric_sessions(runs)[:max(1, args.limit)]))
    result = trend(sessions, metric=args.metric)
    lines = ["%-30s %8s %12s %12s" % ("SESSION", "N", "MEAN", "P95")] + [
        "%-30s %8d %12.6g %12.6g" % (
            str(row["session_id"])[:30], row["n"], row["mean"], row["p95"]
        ) for row in result["points"]
    ] + ["slope/session: %.6g" % result["slope_per_session"]]
    _emit(result, args.json, lines)
    return 0


def _insights(args, payload) -> int:
    result = session_insights(
        payload, min_samples=args.min_samples,
        correlation_threshold=args.correlation, outlier_z=args.outlier_z,
        max_series=args.max_series,
    )
    lines = [
        "%d attempts · %d numeric series · %d correlations · %d outliers" % (
            result["attempts"], len(result["series"]),
            len(result["correlations"]), len(result["outliers"]),
        )
    ]
    lines.extend(
        "CORRELATION %.3f/%.3f %s ↔ %s [%s]" % (
            row["pearson"], row["spearman"], row["left"], row["right"], row["nodeid"],
        ) for row in result["correlations"]
    )
    lines.extend(
        "OUTLIER %.3f %s [%s attempt %s]" % (
            row["score"], row["series"], row["nodeid"], row["attempt_id"],
        ) for row in result["outliers"]
    )
    _emit(result, args.json, lines)
    return 0


def _query(args, payload, session_path: Path) -> int:
    if not args.sql:
        raise SpecError("metrics query", args.sql, "requires --sql SELECT...")
    if args.engine == "sqlite":
        database = session_path / "archive.sqlite3"
        if not database.is_file():
            write_sqlite_archive(payload, session_path, database)
        result = query(database, args.sql)
    else:
        parquet = session_path / "evidence.parquet"
        if not parquet.is_file():
            write_parquet(payload, parquet)
        result = query_duckdb(parquet, args.sql)
    lines = ["\t".join(map(str, result["columns"]))] + [
        "\t".join(str(row.get(column, "")) for column in result["columns"])
        for row in result["rows"]
    ]
    _emit(result, args.json, lines)
    return 0


def _export(args, payload, session_path: Path) -> int:
    suffix = "tar.gz" if args.format == "package" else args.format
    output = Path(args.out).resolve() if args.out else session_path / ("evidence." + suffix)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "plugin":
        if not args.plugin:
            raise SpecError("metrics exporter", args.plugin, "requires --plugin NAME")
        result = get_extension("exporter", args.plugin)(
            payload, output,
            {"session_path": str(session_path), "options": _plugin_options(args.option)},
        )
        _validated_plugin_result("exporter", result)
        _emit(
            {"export": str(output), "format": "plugin", "plugin": args.plugin,
             "result": result},
            args.json, [str(output)],
        )
        return 0
    writers = {
        "csv": lambda: write_metrics_csv(payload, output),
        "sqlite": lambda: write_sqlite_archive(payload, session_path, output),
        "bulk": lambda: write_bulk_archive(payload, session_path, output),
        "parquet": lambda: write_parquet(payload, output),
        "otlp": lambda: write_otlp_json(payload, output),
        "package": lambda: package_session(session_path, output),
        "json": lambda: output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n"),
    }
    writers[args.format]()
    _emit({"export": str(output), "format": args.format}, args.json, [str(output)])
    return 0


def _plugin_options(values: list[str]) -> dict[str, object]:
    options: dict[str, object] = {}
    for value in values:
        if "=" not in value:
            raise SpecError("extension option", value, "must use NAME=VALUE")
        name, raw = value.split("=", 1)
        if not name:
            raise SpecError("extension option", value, "needs a non-empty name")
        try:
            options[name] = json.loads(raw)
        except ValueError:
            options[name] = raw
    return options


def _analyze(args, payload, session_path: Path) -> int:
    if not args.plugin:
        raise SpecError("metrics analyzer", args.plugin, "requires --plugin NAME")
    result = get_extension("analyzer", args.plugin)(
        payload,
        {"session_path": str(session_path), "options": _plugin_options(args.option)},
    )
    _validated_plugin_result("analyzer", result)
    _emit(result, args.json, [json.dumps(result, indent=2, sort_keys=True)])
    return 0


def _validated_plugin_result(kind: str, result: object) -> None:
    try:
        json.dumps(result)
    except (TypeError, ValueError) as exc:
        raise SpecError(
            "metrics %s result" % kind, type(result).__name__, "must be JSON-safe",
        ) from exc


def run_command(args) -> int:
    runs = Path(args.runs).resolve() if args.runs else default_runs_root()
    if args.metrics_cmd == "list":
        return _list(args, runs)
    if args.metrics_cmd in ("compare", "regress"):
        return _comparison(args, runs, gate=args.metrics_cmd == "regress")
    if args.metrics_cmd == "trend":
        return _trend(args, runs)
    payload = load_metric_session(args.session, runs)
    session_path = Path(str(payload.get("path", runs / "metrics" / args.session)))
    if args.metrics_cmd == "show":
        return _show(args, payload)
    if args.metrics_cmd == "analyze":
        return _analyze(args, payload, session_path)
    if args.metrics_cmd == "insights":
        return _insights(args, payload)
    if args.metrics_cmd == "query":
        return _query(args, payload, session_path)
    if args.metrics_cmd == "integrity":
        database = integrity(session_path / "archive.sqlite3")
        objects = verify_objects(session_path)
        result = {"ok": database["ok"] and objects["ok"],
                  "database": database, "objects": objects}
        _emit(result, args.json, [json.dumps(result, sort_keys=True)])
        return 0 if result["ok"] else 1
    if args.metrics_cmd == "report":
        output = Path(args.out).resolve() if args.out else session_path / "report.html"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_metrics_html(payload))
        _emit({"report": str(output)}, args.json, [str(output)])
        return 0
    if args.metrics_cmd == "export":
        return _export(args, payload, session_path)
    return 2
