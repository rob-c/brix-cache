"""Unit contracts for the versioned evidence, journal, and artifact core."""

import json
import os
from pathlib import Path

import pytest

from brixtest import case
from brixtest.errors import SpecError
from brixtest.evidence.artifacts import ContentStore
from brixtest.evidence.collectors import (
    CollectorManager,
    CollectorSpec,
    _prometheus_rows,
    kubernetes_events,
    process_tree,
    prometheus,
    structured_logs,
)
from brixtest.evidence.journal import EvidenceJournal
from brixtest.evidence.model import (
    SCHEMA_VERSION,
    canonical_json,
    iter_entities,
    merge_attempt_metrics,
    migrate_case,
    normalize_session,
    stable_id,
    validate_session,
)
from brixtest.evidence.provenance import capture, environment_contract, file_identity
from brixtest.evidence.redaction import text as redact_text
from brixtest.evidence.redaction import value as redact_value
from brixtest.evidence.retention import (
    RetentionPolicy,
    candidates,
    prune,
    verify_objects,
)
from brixtest.evidence.spans import SpanRecorder


def _v1_case():
    return {
        "schema": 1, "session_id": "s1", "nodeid": "test_x.py::test_x",
        "outcome": "passed", "started_at": "2026-01-01T00:00:00+00:00",
        "wall_seconds": 1.25, "run_root": "/tmp/run", "error": "",
        "metrics": {"samples": [{
            "name": "latency", "value": 1.0, "unit": "s", "kind": "gauge",
            "labels": {}, "at_seconds": 0.5,
        }]},
    }


def test_process_collector_reports_case_relative_cgroup_cpu(monkeypatch, tmp_path):
    emitted = []
    current = {"cpu": 20000.0, "throttled": 300.0}
    monkeypatch.setattr(
        "brixtest.evidence.collectors._descendants",
        lambda roots: {123: "test-helper"},
    )
    monkeypatch.setattr(
        "brixtest.evidence.collectors._proc_values", lambda pid: {},
    )
    monkeypatch.setattr(
        "brixtest.evidence.collectors._cgroup_values",
        lambda pid: {
            "cgroup_cpu_seconds": current["cpu"],
            "cgroup_throttled_seconds": current["throttled"],
        },
    )
    original_read_text = Path.read_text

    def read_text(path, *args, **kwargs):
        if str(path) == "/proc/123/cgroup":
            return "0::/brixtest-unit\n"
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    manager = CollectorManager(
        [process_tree()], root=tmp_path,
        pid_provider=lambda: {"test-helper": 123},
        metric=lambda *args, **kwargs: None,
        event=lambda kind, row: emitted.append((kind, dict(row))),
        namespace_provider=lambda: "",
    )
    manager._sample(manager.specs[0])
    current.update(cpu=20002.5, throttled=300.25)
    manager._sample(manager.specs[0])
    cpu = _metric_values(emitted, "process.cgroup_cpu_seconds")
    throttled = _metric_values(emitted, "process.cgroup_throttled_seconds")
    assert (cpu, throttled) == ([0.0, 2.5], [0.0, 0.25])


def _metric_values(emitted, name):
    return [row[1]["value"] for row in emitted if row[1]["name"] == name]


def test_stable_id_is_deterministic_and_part_sensitive():
    assert stable_id("a", 1) == stable_id("a", 1)
    assert stable_id("a", 1) != stable_id("a1")


def test_published_schema_is_valid_json_and_names_v2():
    path = Path(__file__).resolve().parents[1] / "docs" / "evidence-schema-v2.json"
    schema = json.loads(path.read_text())
    assert schema["properties"]["schema"] == {"const": 2}
    assert schema["properties"]["schema_name"]["const"] == "brixtest.evidence"


def test_migrate_v1_case_preserves_metric_in_one_attempt():
    migrated = migrate_case(_v1_case())
    assert migrated["schema"] == SCHEMA_VERSION
    assert len(migrated["attempts"]) == 1
    assert migrated["attempts"][0]["metrics"][0]["name"] == "latency"


def test_migrate_does_not_mutate_caller():
    original = _v1_case()
    migrate_case(original)
    assert original["schema"] == 1 and "attempts" not in original


def test_migrate_refuses_unknown_future_schema():
    with pytest.raises(SpecError, match="supported versions"):
        migrate_case({"schema": 99})


def test_normalize_session_derives_counts_and_ids():
    payload = normalize_session({"session_id": "s1", "tests": [_v1_case()]})
    assert payload["counts"] == {"passed": 1}
    assert payload["tests"][0]["case_id"]


def test_validate_session_refuses_empty_nodeid():
    record = _v1_case()
    record["nodeid"] = ""
    with pytest.raises(SpecError, match="nodeid"):
        validate_session({"session_id": "s1", "tests": [record]})


def test_validate_session_refuses_non_finite_values():
    record = _v1_case()
    record["metrics"]["samples"][0]["value"] = float("inf")
    with pytest.raises(SpecError, match="finite"):
        validate_session({"session_id": "s1", "tests": [record]})


def test_iter_entities_yields_session_case_attempt_metric_and_provenance():
    record = migrate_case(_v1_case())
    record["attempts"][0]["provenance"] = {"runtime": {"python": "3"}}
    entities = [row["entity"] for row in iter_entities({"session_id": "s1", "tests": [record]})]
    assert entities == ["session", "case", "attempt", "metric", "provenance"]


def test_canonical_json_is_sorted_and_stringifies_paths():
    assert canonical_json({"z": Path("x"), "a": 1}) == '{"a":1,"z":"x"}'


def test_merge_attempt_metrics_excludes_warmups_and_adds_identity():
    attempts = [
        {"warmup": True, "metrics": [{"name": "x", "value": 1}]},
        {"warmup": False, "trial": 0, "attempt_id": "a", "metrics": [{"name": "x", "value": 2}]},
    ]
    assert merge_attempt_metrics(attempts) == [{
        "name": "x", "value": 2, "trial": 0, "attempt_id": "a",
    }]


def test_journal_round_trip_has_monotonic_sequence(tmp_path):
    journal = EvidenceJournal(tmp_path / "journal.jsonl", attempt_id="a1")
    journal.append("metric", {"name": "x", "value": 1})
    journal.append("finding", {"kind": "x"})
    rows = EvidenceJournal.recover(journal.path)
    assert [row["sequence"] for row in rows] == [1, 2]
    assert all(row["attempt_id"] == "a1" for row in rows)


def test_journal_recovery_ignores_incomplete_final_line(tmp_path):
    path = tmp_path / "journal.jsonl"
    path.write_bytes(b'{"sequence":1}\n{"sequence":2')
    assert EvidenceJournal.recover(path) == [{"sequence": 1}]


def test_journal_recovery_skips_invalid_complete_lines(tmp_path):
    path = tmp_path / "journal.jsonl"
    path.write_bytes(b"not-json\n{\"event\":\"ok\"}\n")
    assert EvidenceJournal.recover(path) == [{"event": "ok"}]


def test_content_store_attaches_and_deduplicates_file(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    source = run / "result.txt"
    source.write_text("result")
    store = ContentStore(tmp_path / "session" / "objects", run)
    first = store.attach(source)
    second = store.attach(source, name="again.txt")
    assert first["sha256"] == second["sha256"]
    assert len(list((tmp_path / "session" / "objects" / "sha256").glob("*/*"))) == 1


def test_content_store_text_and_json_are_typed(tmp_path):
    run = tmp_path / "run"
    store = ContentStore(tmp_path / "session" / "objects", run)
    text = store.attach_text("note.txt", "hello")
    structured = store.attach_json("result.json", {"ok": True})
    assert text["media_type"].startswith("text/plain")
    assert structured["media_type"] == "application/json"


def test_content_store_refuses_outside_file(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("secret")
    with pytest.raises(SpecError, match="inside the run root"):
        ContentStore(tmp_path / "objects", run).attach(outside)


def test_content_store_refuses_symlink(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    target = run / "target"
    target.write_text("data")
    link = run / "link"
    link.symlink_to(target)
    with pytest.raises(SpecError, match="regular file"):
        ContentStore(tmp_path / "objects", run).attach(link)


def test_content_store_enforces_size_limit(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    source = run / "big"
    source.write_bytes(b"xx")
    with pytest.raises(SpecError, match="size limit"):
        ContentStore(tmp_path / "objects", run, max_bytes=1).attach(source)


def test_content_store_refuses_path_like_display_name(tmp_path):
    run = tmp_path / "run"
    store = ContentStore(tmp_path / "objects", run)
    with pytest.raises(SpecError, match="attachment name"):
        store.attach_text("../escape.json", "{}")


def test_span_recorder_nests_and_records_attributes():
    recorder = SpanRecorder()
    with recorder.span("outer", answer=42) as outer, recorder.span("inner"):
        pass
    rows = recorder.snapshot()
    assert rows[0]["parent_id"] == outer
    assert rows[1]["span_id"] == outer
    assert rows[1]["attributes"] == {"answer": 42}


def test_span_records_error_without_swallowing_it():
    recorder = SpanRecorder()
    with pytest.raises(RuntimeError, match="boom"), recorder.span("failure"):
        raise RuntimeError("boom")
    assert recorder.snapshot()[0]["status"] == "error"


@pytest.mark.parametrize("name", ["Bad", "../x", "", "x" * 97])
def test_collector_names_are_bounded(name):
    with pytest.raises(SpecError, match="collector name"):
        CollectorSpec("process", name)


def test_collector_factories_keep_options_immutable_by_copy():
    spec = prometheus("http://127.0.0.1/metrics", allow=["requests_total"])
    assert spec.kind == "prometheus" and spec.options["allow"] == ("requests_total",)
    assert prometheus("{server_origin_url}/metrics").options["url"].startswith("{")
    assert structured_logs("runtime/*.log").kind == "structured-logs"
    assert kubernetes_events().kind == "kubernetes"


def test_prometheus_collector_rejects_non_http_urls():
    with pytest.raises(SpecError, match=r"http:// or https://"):
        prometheus("file:///tmp/metrics")


def test_prometheus_parser_filters_and_rejects_non_finite():
    rows = _prometheus_rows("# HELP x x\nrequests_total 3\nnoise 9\nbad NaN\n", ["requests_total"])
    assert rows == [("requests.total", 3.0, {"source": "prometheus"})]


def test_case_defaults_to_process_observation_and_validates_trials():
    @case()
    def declared(run):
        pass

    definition = declared.__brixtest_case__
    assert definition.observe[0].kind == "process"
    with pytest.raises(SpecError, match=r"case\.trials"):
        case(trials=0)
    with pytest.raises(SpecError, match=r"case\.warmup"):
        case(warmup=-1)


def test_case_can_explicitly_disable_automatic_observation():
    @case(observe=[])
    def declared(run):
        pass

    assert declared.__brixtest_case__.observe == ()


def test_redaction_covers_nested_keys_and_inline_tokens():
    assert redact_value({"password": "secret", "ok": "Bearer abc.def"}) == {
        "password": "[REDACTED]", "ok": "Bearer [REDACTED]",
    }
    assert redact_text("token=abc password:xyz") == "token=[REDACTED] password:[REDACTED]"


def test_environment_provenance_hashes_without_storing_value(monkeypatch):
    monkeypatch.setenv("BRIXTEST_TEST_SECRET", "must-not-appear")
    row = environment_contract(["BRIXTEST_TEST_SECRET"])["BRIXTEST_TEST_SECRET"]
    assert row["present"] is True and row["sha256"]
    assert "must-not-appear" not in json.dumps(row)


def test_file_identity_streams_size_and_digest(tmp_path):
    path = tmp_path / "binary"
    path.write_bytes(b"abc")
    row = file_identity(path)
    assert row["size"] == 3
    assert row["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_capture_provenance_is_json_safe_and_backend_aware(tmp_path):
    row = capture(source_root=tmp_path, backend="local", isolation="process")
    assert row["runtime"]["backend"] == "local"
    assert row["runtime"]["isolation"] == "process"
    json.dumps(row)


def test_retention_policy_refuses_negative_values():
    with pytest.raises(SpecError, match="keep_days"):
        RetentionPolicy(keep_days=-1)


def test_retention_candidates_keep_recent_and_failures_longer(tmp_path):
    root = tmp_path / "metrics"
    old_pass = root / "old-pass"
    old_fail = root / "old-fail"
    for path, counts in ((old_pass, {"passed": 1}), (old_fail, {"failed": 1})):
        path.mkdir(parents=True)
        (path / "session.json").write_text(json.dumps({"counts": counts}))
        os.utime(path, (1, 1))
    found = candidates(root, RetentionPolicy(keep_days=1, keep_failures_days=99999,
                                              keep_latest=0), now=100 * 86400)
    assert found == [old_pass]


def test_prune_refuses_non_session_and_removes_selected_session(tmp_path):
    root = tmp_path / "metrics"
    session = root / "session"
    session.mkdir(parents=True)
    (session / "session.json").write_text("{}")
    assert prune(root, [session]) == 1 and not session.exists()
    outsider = tmp_path / "outsider"
    outsider.mkdir()
    with pytest.raises(SpecError, match="direct session child"):
        prune(root, [outsider])


def test_verify_objects_detects_valid_and_corrupt_names(tmp_path):
    root = tmp_path / "session"
    valid_data = b"data"
    digest = __import__("hashlib").sha256(valid_data).hexdigest()
    valid = root / "objects" / "sha256" / digest[:2] / digest
    valid.parent.mkdir(parents=True)
    valid.write_bytes(valid_data)
    assert verify_objects(root) == {"ok": True, "checked": 1, "corrupt": []}
    (valid.parent / ("0" * 64)).write_bytes(b"wrong")
    assert verify_objects(root)["ok"] is False
