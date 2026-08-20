# Metrics and performance budgets

Metrics are part of every managed BriXTest case. Use `run.metrics`, or request
the equivalent `metrics`/`brixtest_metrics` pytest fixture when that reads more
clearly:

```python
import pytest
from brixtest import case


@pytest.mark.brixtest_budget("download.throughput", min=80, aggregate="mean")
@case()
def test_download(run, metrics, record_property):
    with metrics.timer("download.latency"):
        result = run.client("reader").run()

    metrics.gauge("download.throughput", 112.4, unit="MiB/s")
    metrics.count("download.bytes", len(result.stdout), unit="bytes")
    metrics.observe("chunk.latency", 0.018, unit="s", labels={"route": "data"})
    metrics.tag("protocol", "xrootd")

    # Native pytest properties survive BriXTest's helper-process boundary too.
    record_property("build_type", "release")
```

## The four numeric operations

| Operation | Meaning |
|---|---|
| `gauge(name, value, unit=..., labels=...)` | A point-in-time or final value |
| `count(name, value=1, unit="count", labels=...)` | An increment or amount |
| `observe(name, value, unit=..., labels=...)` | One member of a distribution |
| `timer(name, labels=...)` | A `with` block measured in seconds |

`tag(name, value)` adds non-numeric context to that case. `record(...)` is the
expansive underlying API when a custom metric kind is needed.

Names use lowercase dotted identifiers such as `transfer.throughput`. Values
must be finite. A sample may have at most eight short scalar labels. These
checks keep reports bounded and make malformed or accidental high-cardinality
data fail at its source.

## Automatic metrics

BriXTest records useful framework measurements without test code:

- case startup and total wall time;
- helper CPU time and maximum resident memory;
- pytest setup/call/teardown phase time;
- declared server, client, artifact, and captured-binary counts and bytes;
- per-server startup time;
- named-client call counts, duration, return code, and errors.

Automatic and test-defined samples use exactly the same storage and reporting
model. Local and Kubernetes backends therefore produce comparable records.
The default process-tree collector additionally records server/helper CPU,
RSS, faults, I/O, descriptors, threads, context switches, and cgroup-v2
counters. See [the evidence guide](evidence-and-analytics.md) for Prometheus,
Kubernetes events, structured logs, spans, attachments, trials, and findings.

## Pytest-native budgets

Use a marker to turn a metric into a test contract:

```python
@pytest.mark.brixtest_budget("request.latency", max=0.25, aggregate="p95")
@pytest.mark.brixtest_budget("transfer.bytes", min=100_000_000, aggregate="sum")
```

Supported aggregates are `last` (the default), `min`, `mean`, `p95`, `max`,
and `sum`. Add `labels={"route": "read"}` to select one labelled series. A
missing metric fails the budget rather than silently passing it.

## Storage and display

Every pytest invocation gets a unique directory under
`$BRIXTEST_RUNS/metrics/`:

```text
metrics/<session>/
├── cases/<nodeid-sha256>.json  # atomic, crash-resilient case records
├── logs/<nodeid-sha256>/       # helper, server, and client logs for every outcome
├── objects/sha256/             # deduplicated output attachments
├── archive.sqlite3             # normalized evidence and compressed full logs
├── insights.json               # correlations, robust outliers, checksum coverage
├── session.json                # completed aggregate and all case records
└── report.html                 # self-contained, searchable HTML report
```

Per-case files are independent, so xdist workers never contend on a shared
append-only file. The controller composes them after all workers finish.

Pytest shows a compact aggregate table by default. Control it with:

```console
pytest --brixtest-metrics=off          # store, but do not display
pytest --brixtest-metrics=all          # aggregate plus per-test lines
pytest --brixtest-metrics-top=40
pytest --brixtest-metrics-json=metrics.json
pytest --brixtest-metrics-html=metrics.html
pytest --brixtest-sqlite=/archive/results.sqlite3
```

SQLite uses only Python's standard library and is created automatically. The
`sessions`, `tests`, `metrics`, and `logs` tables make ad-hoc SQL analysis and
complete diagnostic retention straightforward. Log BLOBs use zlib and record
their encoding and SHA-256 digest.

Elasticsearch and OpenSearch use the same records and logs through the bulk
API:

```console
pytest --brixtest-search-url=https://search.example \
       --brixtest-search-index=brixtest-ci
```

Set `BRIXTEST_SEARCH_BEARER_TOKEN`, or `BRIXTEST_SEARCH_BASIC_AUTH=user:pass`,
in the controller environment. Credentials and replay commands are not placed
in remotely indexed documents. An explicit search export that reports item
errors fails session finalization instead of silently losing results.

The CLI works without a project adapter:

```console
brixtest metrics                       # show the latest session
brixtest metrics list
brixtest metrics show <session>
brixtest metrics report <session> -o report.html
brixtest metrics export <session> --format csv -o metrics.csv
brixtest metrics export <session> --format sqlite -o archive.sqlite3
brixtest metrics export <session> --format bulk -o opensearch.ndjson
brixtest metrics compare <baseline> <candidate> --metric request.latency
brixtest metrics regress <baseline> <candidate> --threshold .05
brixtest metrics trend --metric transfer.rate
brixtest metrics insights <session> --min-samples 3 --correlation .7 --outlier-z 3.5
brixtest metrics query <session> --sql "select * from evidence_metrics limit 10"
brixtest metrics export <session> --format parquet -o evidence.parquet
```

Use `--runs PATH` on these commands when records live outside the default run
root. JSON is the lossless interchange format; CSV contains the aggregate
metric table and HTML is a portable human report with no external assets.
`insights` aligns trials by attempt and computes descriptive distributions,
Pearson and Spearman correlations across metrics/resources/wall time/artifact
and log sizes, robust MAD-based outliers, and checksum coverage. Correlations
are intentionally reported as evidence for investigation, not as causal claims.
