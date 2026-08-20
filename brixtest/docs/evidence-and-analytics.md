# Evidence, trials, analytics, and extensions

BriXTest treats every managed test as a reproducible experiment. A session
contains cases; a case contains one or more isolated attempts; each attempt
owns its metrics, resource samples, spans, attachments, logs, findings, and
provenance. It also records the stable identity of every server instance used.
Session-scoped server pools contribute their lifetime resource metrics,
provenance, findings, timestamps, and one checksum-addressed physical log. The
versioned JSON schema is also used by SQLite, Parquet,
OpenSearch, OTLP, and the HTML report, so an export does not silently change
the meaning of the result. The normative interchange contract is
[`evidence-schema-v2.json`](evidence-schema-v2.json); readers accept v1 and
migrate it in memory without rewriting the source archive.

## A complete declaration

```python
from brixtest import case, process_tree, prometheus, structured_logs


@case(
    warmup=1,
    trials=5,
    observe=[
        process_tree(interval=0.25),
        prometheus("{server_origin_url}/metrics", allow=["requests_total"]),
        structured_logs("runtime/**/*.log"),
    ],
)
def test_transfer(run):
    with run.step("upload", object_size=100_000_000):
        result = run.client("uploader").run()

    run.metrics.observe("transfer.rate", 418.2, unit="MiB/s")
    run.attach_json("client-result.json", {
        "returncode": result.returncode,
        "stdout": result.stdout,
    })
```

Each warmup and trial is a new helper process with a new run directory and
fresh managed resources. Warmup observations remain in the evidence but are
excluded from aggregate metrics and regression decisions. BriXTest stops the
sequence at its first failed or timed-out attempt.

`process_tree()` is the default collector. Pass `observe=[]` for a case where
automatic process/cgroup observations are deliberately unwanted. The process
collector covers the helper, each managed local server, descendants, CPU,
RSS, faults, threads, file descriptors, I/O, context switches, and cgroup-v2
CPU/memory/PID counters. A disappearing critical process becomes an error
finding. Kubernetes events, Prometheus text endpoints, and JSON-lines logs are
opt-in because they need case-specific locations.

## Correlation and output attachments

`run.step(name, **attributes)` creates a nested timing span. Resource samples
and metrics carry attempt-relative time, which lets the report or downstream
analytics correlate a CPU/RSS change with a test action.

Output files must be regular, non-symlink files inside `run.root`:

```python
run.attach(run.workspace / "profile.svg", role="profile")
run.attach_text("decision.txt", "selected candidate A\n")
run.attach_json("analysis.json", {"score": 0.97})
```

Attachments are SHA-256 addressed and deduplicated in the session `objects/`
store before an ephemeral run may be removed. The default per-object limit is
1 GiB and can be changed with `--brixtest-attachment-max-bytes`.

## Provenance and crash recovery

Every attempt records source commit/dirty state, platform/kernel/Python,
hardware totals, backend/isolation, tool discovery, captured binary and
rendered-config hashes, and environment-variable presence plus a value hash.
Environment values are not written to provenance.

Evidence is appended as one fsynced JSON event per line under
`run/evidence/journal.jsonl`. If a helper is killed or times out, the controller
recovers every complete line and ignores only an incomplete final line. The
normal completed record is compacted into the session case JSON.

## Comparison and querying

```console
brixtest metrics compare BASELINE CANDIDATE --metric request.latency
brixtest metrics regress BASELINE CANDIDATE --threshold .05 --effect .147
brixtest metrics trend --metric transfer.rate --limit 30
brixtest metrics insights latest --min-samples 3 --correlation .7 --outlier-z 3.5
brixtest metrics query SESSION --sql \
  "select nodeid, avg(value) from evidence_metrics group by nodeid"
brixtest metrics query SESSION --engine duckdb --sql \
  "select entity, count(*) from evidence group by entity"
brixtest metrics integrity SESSION
```

Comparison reports descriptive statistics, deterministic bootstrap confidence
intervals, relative change, and Cliff's delta. `regress` returns non-zero only
for series exceeding both the relative and effect thresholds. This prevents a
large but noisy percentage from becoming a finding without a material effect.
Use enough independent trials for a meaningful decision; the framework does
not manufacture confidence from one sample.

SQLite queries are restricted to one read-only statement. DuckDB operates on
the normalized Parquet export and requires `pip install -e '.[analytics]'`.

## Export and archival

```console
brixtest metrics export SESSION --format parquet -o evidence.parquet
brixtest metrics export SESSION --format otlp -o otlp.json
brixtest metrics export SESSION --format package -o session.tar.gz

pytest --brixtest-otlp-endpoint=http://collector:4318
pytest --brixtest-search-url=https://search.example \
       --brixtest-search-index=brixtest-ci \
       --brixtest-search-manage-schema
pytest --brixtest-s3=s3://test-evidence/project/nightly
```

The OpenSearch option installs composable data-stream templates and an ISM
rollover/delete policy when schema management is explicitly enabled. Bulk
uploads are compressed, retried with exponential backoff, and report the first
item errors. Text shipped remotely is recursively redacted for common secret
keys, bearer tokens, and password/token assignments. Local log archives retain
the original bytes with mode `0600`, SHA-256, and zlib encoding.

The normalized SQLite tables `evidence_server_pools`,
`evidence_server_instances`, and `evidence_test_server_links` answer which
tests used an instance without parsing log names. Instance rows include actual
ports, final config filename, source/declaration/final config SHA-256 values,
and log provenance; the JSON payload also links the content-addressed final
config artifact. See
[Dynamic topology](dynamic-topology.md) for the lifecycle and deduplication
contract.

S3 support requires `brixtest[s3]`; Parquet/DuckDB requires
`brixtest[analytics]`. OTLP/HTTP JSON and OpenSearch use the standard library.

## Extension points

External distributions can publish callable entry points in these groups:

- `brixtest.collectors`
- `brixtest.analyzers`
- `brixtest.exporters`

Collectors receive the collector manager and immutable `CollectorSpec`.
Analyzers and exporters are loaded lazily through the same versioned registry
used by every BriXTest runtime extension, so installation never changes
collection-time behavior unless a test or command names the extension. Run
analyzers with `brixtest metrics analyze --plugin NAME` and exporters with
`brixtest metrics export --format plugin --plugin NAME`. Extension output must
use the same finite numeric, bounded-label, JSON-safe evidence contract as
built-in components.

## Sanitizer and candidate-binary suites

```console
brixtest run tests -- \
  --brixtest-binary nginx=/build/asan/objs/nginx \
  --brixtest-sanitizer asan
```

The binary and its discovered dynamic libraries are copied before the first
server starts. `--brixtest-sanitizer` applies fail-fast settings to helper,
server, and client environments. ASan, LeakSanitizer, and UBSan signatures in
managed logs become error findings, so a passing assertion cannot hide a
sanitizer report. The case record includes an exact `brixtest rerun` command.
