# Changelog

All notable BriXTest changes are documented here. The project follows Semantic
Versioning; compatibility aliases are retained for at least one minor release
before removal.

## 0.15.0

- Added declaration-owned typed references, parameter/workspace/run-root
  references, and concise overloads for the canonical `Execution` API.
- Added a versioned per-server launcher seam with independently selectable
  process, Docker, and Podman placement under uniform supervision.
- Added the Docker-backed `minikube` backend, explicit kube-context handling,
  and `brixtest minikube start|status|test` operator workflow.
- Added live `Service` health, bounded log follow/tail, signal, restart, wait,
  and in-environment command controls.
- Replaced post-hoc command truncation with bounded concurrent pipe draining
  and capped server logs, retaining partial diagnostics on timeout.
- Tightened public extension typing and added a server-launcher conformance kit.
- Added a complete PEP 561 top-level facade plus built-in cross-signal session
  insights for correlations, robust outliers, and evidence checksum coverage.

## 0.14.0

- Added explicit `run.execute(Execution)` and distinct bound `ConfiguredTool`
  values while retaining the earlier `run.tool(Execution)` compatibility path.
- Added real executor and artifact-provider extension seams, including local,
  Docker, Podman, and Kubernetes tool execution.
- Added analyzer/exporter CLI execution, Kubernetes `SecretKeyRef` credential
  injection, and structured per-tool logs for every executor.
- Unified backend, executor, probe, provider, collector, analyzer, and exporter
  discovery under the versioned extension registry.
- Added public backend/tool/provider contexts, lifecycle pytest hooks, and
  black-box extension conformance helpers.
- Made server configuration optional at the author boundary; BriXTest retains
  a checksummed empty config when a process has no native configuration file.
- Added package lifecycle, migration, contribution, and isolated wheel-test
  documentation.

## 0.13.0

- Established the canonical `Execution`, `Server`, `Tool`, typed-reference,
  dynamic-topology, suite-profile, and helper-report transport APIs.
