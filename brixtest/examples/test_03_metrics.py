"""Examples 9-12: metrics, timers, budgets, and native pytest properties."""

import time

import pytest

from brixtest import case, process_tree


@case(observe=[process_tree(interval=0.1)], keep="never")
def test_09_gauge_counter_and_tag(run):
    run.metrics.gauge("example.queue_depth", 3, unit="items")
    run.metrics.count("example.requests", 2)
    run.metrics.tag("example_mode", "tutorial")
    snapshot = run.metrics.snapshot()
    assert snapshot["tags"]["example_mode"] == "tutorial"
    names = {sample["name"] for sample in snapshot["samples"]}
    assert {"example.queue_depth", "example.requests"} <= names


@case(keep="never")
def test_10_timer_and_observation(run, metrics):
    assert metrics is run.metrics
    with metrics.timer("example.operation") as measured:
        time.sleep(0.001)
    metrics.observe("example.latency", measured.elapsed, unit="s", labels={"route": "read"})
    assert measured.elapsed > 0


@pytest.mark.brixtest_budget("example.throughput", min=100, max=200)
@case(warmup=1, trials=3, keep="never")
def test_11_pytest_metric_budget(run):
    run.metrics.gauge("example.throughput", 150, unit="MiB/s")


@case(keep="never")
def test_12_native_pytest_property(run, record_property):
    record_property("example_revision", "documentation")
    run.metrics.count("example.properties_recorded")
    samples = run.metrics.snapshot()["samples"]
    recorded = next(
        sample for sample in samples
        if sample["name"] == "example.properties_recorded"
    )
    assert recorded["value"] == 1
    with run.step("publish-example", kind="json"):
        attachment = run.attach_json("example-result.json", {"recorded": True})
    assert attachment["media_type"] == "application/json"
