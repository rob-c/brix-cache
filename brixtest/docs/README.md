# BriXTest documentation

Start here:

- [Getting started](getting-started.md) — install and run the executable example.
- [Writing tests](writing-tests.md) — the Python declaration model and `run` API.
- [Native C and C++ tests](native-tests.md) — one compiled program per normal,
  independently selectable, supervised pytest item.
- [Managed resources](managed-resources.md) — typed plans, finite tasks,
  volumes, capability failures, and `Service.fs`.
- [Public API reference](api-reference.md) — every stable top-level name,
  runtime convenience, fixture, and pytest integration point.
- [Architecture](architecture.md) — pytest ownership, process safety, resource
  graphs, backend boundaries, and compatibility policy.
- [Capability expansion plan](capability-expansion-plan.md) — tracked actions
  for full networking, isolation, Kubernetes, authentication, and storage parity.
- [Dynamic topology](dynamic-topology.md) — derived server lifetimes, sharing,
  monitoring, test-instance links, and deduplicated logs.
- [Executable API examples](../examples/README.md) — the 20-test core catalogue,
  a real nginx HTTP server, and minimal authentication recipes.
- [Authentication recipes](authentication.md) — custom credentials, tokens,
  TLS CA/CRL/host certificates, VOMS/GSI PKI, Kerberos realms, and test DNS.
- [Metrics and performance budgets](metrics.md) — collection, budgets, storage,
  terminal output, and JSON/CSV/HTML reports.
- [Evidence and analytics](evidence-and-analytics.md) — trials, collectors,
  spans, attachments, provenance, findings, comparison, and remote export.
- [Configuration](configuration.md) — on-disk templates and placeholder reference.
- [Backends](backends.md) — the local/Kubernetes contract and selection.
- [Extensions](extensions.md) — versioned drivers, entry points, pytest hooks,
  and reusable conformance tests.
- [Compatibility and migration](migration.md) — canonical spellings,
  deprecation guarantees, and the legacy catalogue boundary.
- [Isolation and runs](isolation-and-runs.md) — helper supervision, captured
  binaries, resource ownership, and summaries.

Everything referenced by these docs lives inside the standalone BriXTest
sub-project. The repository-specific nginx-xrootd adapter is not part of the
BriXTest distribution.
