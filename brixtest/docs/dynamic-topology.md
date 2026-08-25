# Dynamic server topology and correlation

BriXTest derives the server fleet entirely from the collected `@case`
declarations. There is no separate fleet inventory to keep synchronized with
the tests. Adding ten tests with ten distinct server declarations produces ten
managed instances; deleting those tests removes the instances on the next run.

The `scope` on `server()` selects ownership:

- `scope="case"` (default) creates a fresh instance for every warmup/trial,
  starts it inside that attempt's helper, and tears it down with the attempt.
- `scope="function"` is the pytest-familiar synonym for attempt ownership.
- `scope="class"`, `"module"`, or `"package"` shares a content-addressed pool
  within the corresponding collected node domain.
- `scope="session"` fingerprints the complete server graph and its immutable
  inputs during collection. Config identity uses the declaration-completed
  template content, not its source-template path, so equivalent independently
  loaded templates share one supervised instance. Different effective configs, binaries, credentials,
  authentication resources, host mappings, backend, or isolation produce
  different pools.
- `scope="worker"` deliberately creates one broker-supervised instance for
  each xdist worker that actually consumes it.

```python
origin = server(
    "origin",
    command=[origin_binary, "-c", "{config}"],
    config=template_config("configs/origin.conf.in"),
    ports=["http"],
    readiness=tcp("http"),
    scope="session",
)


@case(servers=[origin], binaries=[origin_binary])
def test_get(run):
    assert fetch(run.server(origin).url()).status == 200


@case(servers=[origin], binaries=[origin_binary])
def test_missing(run):
    assert fetch(run.server(origin).url(path="/missing")).status == 404
```

Both tests receive the normal `Service` API and the same `instance_id`, host,
ports, captured config, config checksums/artifact, and physical log. The session supervisor—not either
test helper—owns that process. It monitors the child/port-forward, samples its
resources for the whole lifetime, and stops it before session reports and
archives are finalized. A shared server may depend only on servers with the
same lifetime; a case/function server may consume any shared lifetime.

## Stored relationships

Every attempt records the exact server instances it used. A shared server log
is copied once to:

```text
<session>/logs/instances/<instance-id>/<log-name>
```

Its manifest contains byte length and SHA-256. Every consuming attempt links
to that one manifest row, rather than copying the same log per test. The
session's `topology.json` distinguishes scheduled and actually run consumers,
timestamps, teardown outcome, service endpoints, log objects, resource
metrics, findings, and provenance.

SQLite exposes the relationship directly:

```sql
select i.name, i.instance_id, i.ports, i.config_sha256, i.log_sha256, l.nodeid
from evidence_server_instances i
join evidence_test_server_links l using (session_id, instance_id)
order by i.name, l.nodeid;
```

The HTML report displays the same instance-to-consumer mapping. Normalized
`server-pool` and `server-instance` entities are also exported to Parquet and
OpenSearch/Elasticsearch; supervisor metrics and findings participate in the
same session analytics as case evidence.

Collection and `brixtest design` remain side-effect free. Pools start lazily
immediately before the first managed test. Under xdist, class/module/package/
session plans from every worker are merged before execution and one
controller-supervised broker owns each physical pool. Workers receive resolved
services through bounded, authenticated local IPC. Use `scope="worker"` only
when a server must intentionally have one physical instance per consuming
xdist worker; the worker identity and exact
instance links remain visible in the topology archive.

If a shared service exits, the pool monitor records its status and full trace.
A later consumer fails during controller setup as an ordinary BriXTest attempt,
before a helper is launched, and is linked to the same pool, instance, and
content-addressed log as earlier consumers.
