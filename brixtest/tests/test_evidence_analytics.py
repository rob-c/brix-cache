"""Analytics, normalized storage, transport, and compatibility contracts."""

import json
import sqlite3
import tarfile
from pathlib import Path

import pytest

from brixtest.archive import write_bulk_archive, write_sqlite_archive
from brixtest.errors import SpecError
from brixtest.evidence.analysis import (
    bootstrap_mean_ci, cliffs_delta, compare, describe, percentile,
    session_insights, trend,
)
from brixtest.evidence.export import otlp_payloads, package_session, write_otlp_json
from brixtest.evidence.report import render
from brixtest.evidence.search import SearchClient, bulk_lines, documents
from brixtest.evidence.store import integrity, query
from brixtest.evidence.legacy import publish as publish_legacy
from brixtest.results.model import Finding, PhaseResult, RunInfo, Sample
from brixtest.results.model import TestRecord as ResultTestRecord
from brixtest.results.store import ResultStore


def _case(session, values, *, nodeid="test_x.py::test_x", outcome="passed"):
    attempts = []
    samples = []
    for trial, value in enumerate(values):
        sample = {
            "name": "request.latency", "value": value, "unit": "s",
            "kind": "observation", "labels": {"route": "read"},
            "at_seconds": value, "trial": trial, "attempt_id": "a%d" % trial,
        }
        samples.append(sample)
        attempts.append({
            "attempt_id": "%s-a%d" % (session, trial), "index": trial, "trial": trial,
            "warmup": False, "outcome": outcome, "started_at": "2026-01-01T00:00:00Z",
            "wall_seconds": value, "run_root": "/tmp/run", "error": "",
            "metrics": [sample], "resources": [{
                "name": "process.rss_bytes", "value": 1024 + trial, "unit": "bytes",
                "labels": {"process": "server"}, "at_seconds": value,
            }],
            "spans": [{
                "span_id": ("%016d" % trial)[-16:], "parent_id": "", "name": "request",
                "start_seconds": 0.0, "duration_seconds": value, "status": "ok",
            }],
            "artifacts": [{"name": "result.json", "sha256": "f" * 64, "size": 10}],
            "logs": [{"path": "logs/server.log", "sha256": "e" * 64}],
            "findings": [], "provenance": {"runtime": {"backend": "local"}},
        })
    return {
        "schema": 2, "session_id": session, "nodeid": nodeid, "outcome": outcome,
        "backend": "local", "isolation": "process", "run_root": "/tmp/run",
        "started_at": "2026-01-01T00:00:00Z", "wall_seconds": sum(values),
        "metrics": {"samples": samples, "tags": {}, "rollups": []},
        "properties": [], "error": "", "attempts": attempts,
    }


def _payload(session, values):
    return {
        "schema": 2, "session_id": session, "generated_at": "2026-01-01T00:00:00Z",
        "exitstatus": 0, "tests": [_case(session, values)],
        "aggregates": [{
            "name": "request.latency", "unit": "s", "kind": "observation",
            "labels": {"route": "read"}, "samples": len(values),
            "min": min(values), "mean": sum(values) / len(values),
            "p95": max(values), "max": max(values), "sum": sum(values),
        }],
    }


@pytest.mark.parametrize("fraction,expected", [(0, 1), (0.5, 2.5), (0.95, 3.85), (1, 4)])
def test_percentile_interpolates(fraction, expected):
    assert percentile([1, 2, 3, 4], fraction) == pytest.approx(expected)


def test_describe_reports_robust_and_variability_statistics():
    stats = describe([1, 2, 3, 4])
    assert stats["n"] == 4 and stats["median"] == 2.5
    assert stats["mad"] == 1 and stats["stddev"] > 1
    assert stats["p99"] > stats["p95"]


def test_describe_empty_is_explicit():
    assert describe([]) == {"n": 0}


def test_bootstrap_interval_is_deterministic_and_contains_mean():
    first = bootstrap_mean_ci([1, 2, 3, 4], samples=200, seed="same")
    second = bootstrap_mean_ci([1, 2, 3, 4], samples=200, seed="same")
    assert first == second and first[0] <= 2.5 <= first[1]


def test_cliffs_delta_has_direction_and_zero_for_ties():
    assert cliffs_delta([3, 4], [1, 2]) == 1.0
    assert cliffs_delta([1, 1], [1, 1]) == 0.0
    assert cliffs_delta([], [1]) == 0.0


def test_compare_emits_regression_only_above_both_thresholds():
    result = compare(_payload("old", [1, 1, 1]), _payload("new", [2, 2, 2]))
    assert len(result["series"]) == 1
    assert result["series"][0]["relative_change"] == 1.0
    assert result["findings"][0]["kind"] == "regression"


def test_compare_metric_filter_can_exclude_all_series():
    result = compare(_payload("old", [1]), _payload("new", [2]), metric="other")
    assert result["series"] == [] and result["findings"] == []


def test_compare_does_not_call_improvement_a_regression():
    result = compare(_payload("old", [2, 2]), _payload("new", [1, 1]))
    assert result["series"][0]["relative_change"] == -0.5
    assert result["findings"] == []


def test_compare_marks_backend_mismatch_incomparable_not_regressed():
    old = _payload("old", [1, 1])
    new = _payload("new", [2, 2])
    new["tests"][0]["backend"] = "kubernetes"
    result = compare(old, new)
    assert result["series"][0]["compatibility"]["comparable"] is False
    assert [row["kind"] for row in result["findings"]] == ["incompatible-provenance"]


def test_trend_returns_linear_slope_over_sessions():
    result = trend([_payload("s1", [1]), _payload("s2", [2]),
                    _payload("s3", [3])], metric="request.latency")
    assert result["slope_per_session"] == pytest.approx(1.0)
    assert [row["session_id"] for row in result["points"]] == ["s1", "s2", "s3"]


def test_session_insights_correlate_metrics_resources_and_artifact_sizes():
    payload = _payload("s1", [1, 2, 3, 4])
    for index, attempt in enumerate(payload["tests"][0]["attempts"], 1):
        attempt["artifacts"][0]["size"] = index * 10
    result = session_insights(payload, correlation_threshold=0.9)

    pairs = {(row["left"], row["right"]) for row in result["correlations"]}
    assert ("artifact.result.json.bytes", "metric.request.latency{route=read}") in pairs
    assert result["evidence"]["artifacts"]["checksum_coverage"] == 1.0
    assert result["attempts"] == 4


@pytest.mark.parametrize(
    "options, message",
    [
        ({"min_samples": 1}, "min_samples"),
        ({"correlation_threshold": 1.1}, "correlation_threshold"),
        ({"outlier_z": 0}, "outlier_z"),
        ({"max_series": 1}, "max_series"),
    ],
)
def test_session_insights_reject_invalid_analysis_policy(options, message):
    with pytest.raises(SpecError, match=message):
        session_insights(_payload("s1", [1, 2, 3]), **options)


def test_session_insights_ignore_nonfinite_untrusted_observations_and_flag_outliers():
    payload = _payload("s1", [1, 1, 1, 20])
    payload["tests"][0]["attempts"][0]["metrics"].append({
        "name": "unsafe", "value": "nan", "labels": {"source": "<script>"},
    })
    result = session_insights(payload)

    assert all(row["name"] != "metric.unsafe{source=<script>}" for row in result["series"])
    assert any(row["value"] == 20 for row in result["outliers"])


def test_sqlite_archive_contains_normalized_attempt_metric_and_entities(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    database = write_sqlite_archive(_payload("s1", [1, 2]), session,
                                    session / "archive.sqlite3")
    connection = sqlite3.connect(str(database))
    try:
        assert connection.execute("select count(*) from evidence_attempts").fetchone()[0] == 2
        assert connection.execute("select count(*) from evidence_metrics").fetchone()[0] == 2
        entities = dict(connection.execute(
            "select entity, count(*) from evidence_entities group by entity"
        ))
        assert entities["span"] == 2 and entities["resource"] == 2
    finally:
        connection.close()


def test_read_only_query_returns_named_rows(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    database = write_sqlite_archive(_payload("s1", [1, 2]), session,
                                    session / "archive.sqlite3")
    result = query(database, "select name, avg(value) as mean from evidence_metrics group by name")
    assert result["columns"] == ["name", "mean"]
    assert result["rows"] == [{"name": "request.latency", "mean": 1.5}]


@pytest.mark.parametrize("sql", ["delete from evidence_metrics", "select 1; select 2"])
def test_read_only_query_refuses_mutation_or_multiple_statements(tmp_path, sql):
    database = tmp_path / "empty.sqlite3"
    sqlite3.connect(str(database)).close()
    with pytest.raises(SpecError, match="read-only"):
        query(database, sql)


def test_sqlite_integrity_reports_schema_version(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    database = write_sqlite_archive(_payload("s1", [1]), session,
                                    session / "archive.sqlite3")
    assert integrity(database) == {"ok": True, "detail": "ok", "schema": 2}


def test_search_documents_cover_every_evidence_entity():
    rows = list(documents(_payload("s1", [1]), prefix="brixtest-ci"))
    entity_names = {row["document"]["entity"] for row in rows}
    assert {"session", "case", "attempt", "metric", "resource", "span",
            "artifact", "log", "provenance"} <= entity_names
    assert all(row["index"].startswith("brixtest-ci-evidence-") for row in rows)


def test_search_documents_redact_secret_fields():
    payload = _payload("s1", [1])
    payload["tests"][0]["attempts"][0]["provenance"]["token"] = "secret-value"
    encoded = "\n".join(bulk_lines(payload))
    assert "secret-value" not in encoded and "[REDACTED]" in encoded


def test_search_index_name_is_confined():
    with pytest.raises(SpecError, match="lowercase"):
        list(documents(_payload("s1", [1]), prefix="Bad/Index"))


def test_search_client_retries_transient_http_error(monkeypatch):
    calls = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return b'{"errors":false}'

    def opener(request, timeout):
        calls.append(request)
        if len(calls) == 1:
            raise __import__("urllib.error").error.HTTPError(
                request.full_url, 503, "busy", {}, None
            )
        return Response()

    monkeypatch.setattr("brixtest.evidence.search.time.sleep", lambda _: None)
    SearchClient("https://search.example", retries=1, opener=opener,
                 compress=False).post(_payload("s1", [1]))
    assert len(calls) == 2


def test_bulk_archive_keeps_legacy_logs_and_new_entities(tmp_path):
    session = tmp_path / "session"
    log = session / "logs" / "server.log"
    log.parent.mkdir(parents=True)
    log.write_text("token=must-redact")
    payload = _payload("s1", [1])
    payload["tests"][0]["logs"] = [{"relative": "logs/server.log"}]
    path = write_bulk_archive(payload, session, tmp_path / "bulk.ndjson")
    content = path.read_text()
    assert "brixtest-logs" in content and "brixtest-evidence-attempt" in content
    assert "must-redact" not in content


def test_otlp_payloads_contain_metrics_spans_and_logs():
    payload = _payload("s1", [1])
    payload["tests"][0]["attempts"][0]["findings"] = [{
        "kind": "regression", "severity": "error", "detail": "slower",
    }]
    signals = otlp_payloads(payload)
    assert signals["metrics"]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
    assert signals["traces"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert signals["logs"]["resourceLogs"][0]["scopeLogs"][0]["logRecords"]


def test_write_otlp_json_is_self_contained(tmp_path):
    output = write_otlp_json(_payload("s1", [1]), tmp_path / "otlp.json")
    assert set(json.loads(output.read_text())) == {"metrics", "traces", "logs"}


def test_package_session_has_relative_safe_members(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    (session / "session.json").write_text("{}")
    archive = package_session(session, tmp_path / "session.tar.gz")
    with tarfile.open(archive) as handle:
        names = handle.getnames()
    assert names == ["session/session.json"]
    assert all(not Path(name).is_absolute() and ".." not in Path(name).parts for name in names)


def test_report_contains_metrics_findings_attachments_and_embedded_data():
    payload = _payload("s1", [1])
    payload["tests"][0]["attempts"][0]["findings"] = [{
        "kind": "regression", "severity": "error", "detail": "slower",
    }]
    page = render(payload)
    assert "request.latency{route=read}" in page
    assert "regression" in page and "result.json" in page
    assert "machine-readable evidence" in page


def test_legacy_fleet_store_publishes_the_same_evidence_schema(tmp_path):
    store = ResultStore(tmp_path / "legacy.sqlite3")
    info = RunInfo("run1", "2026-01-01T00:00:00Z", str(tmp_path), 20000, "host",
                   finished_at="2026-01-01T00:01:00Z", wall_seconds=60,
                   counts={"passed": 1})
    store.begin_run(info)
    record = ResultTestRecord(
        "run1", "test_x.py::test_x", outcome="passed",
        started_at="2026-01-01T00:00:01Z", wall_seconds=1, cpu_seconds=.5,
        maxrss_kb=100, servers=["origin"], artifacts=["payload"],
        phases=[PhaseResult("call", "passed", 1)],
    )
    store.add_test(record)
    store.add_samples("run1", [Sample("origin", 1, 42, 100, 2.0, record.nodeid)])
    store.add_finding("run1", Finding("cpu-spike", "origin", "busy", record.nodeid,
                                      "2026-01-01T00:00:02Z"))
    store.finish_run(info)
    payload = publish_legacy(store, info, tmp_path / "evidence")
    store.close()
    assert payload["schema"] == 2 and payload["source"] == "fleet-harness"
    attempt = payload["tests"][0]["attempts"][0]
    assert attempt["resources"] and attempt["findings"][0]["kind"] == "cpu-spike"
    assert (tmp_path / "evidence" / "archive.sqlite3").is_file()
