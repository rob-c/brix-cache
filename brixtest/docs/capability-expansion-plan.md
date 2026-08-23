# BriXTest capability expansion plan

Status: implementation in progress  
Scope: BriXTest only  
Compatibility target: existing public API remains source-compatible

This document tracks the work required to make BriXTest capable of expressing
the privileged, distributed, authentication, storage, networking, and
Kubernetes tests currently found in the raw Python and prototype Kubernetes
suites. A checked item must meet its stated acceptance criteria; partial or
experimental implementations remain unchecked.

## Architectural constraints

- [ ] **BXP-001** Keep pytest responsible for collection, parametrization,
  fixtures, selection, reporting, skip/xfail semantics, and xdist scheduling.
- [ ] **BXP-002** Keep every managed test body in a supervised helper, never in
  the controller interpreter.
- [x] **BXP-003** Keep declarations immutable, import-safe, and side-effect-free
  during collection.
- [x] **BXP-004** Compile all declarations into one typed, backend-neutral
  resource graph before any backend creates resources.
- [ ] **BXP-005** Reject unsupported semantics during planning; no backend may
  silently ignore a declaration.
- [ ] **BXP-006** Keep ordinary tests free of Docker, Podman, runc, Helm,
  Kubernetes, or transport orchestration.
- [ ] **BXP-007** Keep BriXTest standalone: production code, tests, templates,
  images, and documentation must not import files outside `brixtest/`.
- [x] **BXP-008** Preserve existing declarations and defaults. New declarations
  must be optional and positional resource inference must remain available.
- [x] **BXP-009** Record every planned and realized resource in the evidence
  model without exposing secret contents.
- [ ] **BXP-010** Keep Python files below 500 lines and within the repository's
  CCN, Cognitive, NPath, Halstead, and nesting limits.

## Intended public surface

The normal path remains `@case`, `server`, `tool`, `artifact`, `binary`, and
`run`. Add only the following general resources:

- [x] **BXP-020** Add `Environment` and `environment()` for explicit execution
  realms, namespaces, clusters, DNS domains, and network isolation.
- [x] **BXP-021** Add `Volume` and `volume()` for temporary, persistent, shared,
  host, device, and provider-backed storage.
- [x] **BXP-022** Add `Identity` and `identity()` for UID/GID/groups, user
  namespaces, capabilities, ServiceAccounts, and abstract permissions.
- [x] **BXP-023** Add `Task` and `task()` for supervised build, preparation,
  init, bootstrap, and finalization actions.
- [x] **BXP-024** Add `Resource` and `resource()` as the versioned provider path
  for infrastructure that is not a process, identity, network, or volume.
- [ ] **BXP-025** Add `kubernetes()` helper isolation beside `process()`,
  `docker()`, `podman()`, `runc()`, and `nsenter()`.
- [x] **BXP-026** Extend `Endpoint` with address family and exposure policy.
- [x] **BXP-027** Extend `Placement` with environment, execution-group, identity,
  and typed scheduling/network policy.
- [x] **BXP-028** Extend `Mount` with `Volume` sources and mount propagation.
- [x] **BXP-029** Extend `Server` with replica count while keeping one replica as
  the default.
- [ ] **BXP-030** Extend `Binary` so a local capture can be materialized into an
  immutable OCI image without changing its declaration.
- [ ] **BXP-031** Add managed-authority and rotation options to authentication
  recipes.
- [ ] **BXP-032** Add `Service.fs` and replica inspection without changing the
  existing endpoint, log, signal, restart, or command methods.
- [ ] **BXP-033** Add issuance, revocation, rotation, and availability controls
  to materialized authentication stacks.
- [x] **BXP-034** Update the machine-readable API manifest, stubs, API reference,
  introspection contract, and compatibility tests for every public addition.

## Milestone 1: typed resource plan

Dependencies: BXP-001 through BXP-010.

- [x] **BXP-100** Define versioned immutable graph nodes for environments,
  workloads, tasks, identities, volumes, endpoints, authorities, and provider
  resources.
- [ ] **BXP-101** Define typed edges for ordering, readiness, co-location,
  connectivity, consumption, and reverse-order teardown.
- [x] **BXP-102** Expand existing `CaseDefinition` resources into the graph
  without changing their behavior.
- [ ] **BXP-103** Resolve typed references according to the consuming resource,
  rather than using one address/path representation globally.
- [x] **BXP-104** Fingerprint graph nodes and their effective inputs for pooling,
  caching, provenance, and reproducible reruns.
- [ ] **BXP-105** Implement transactional prepare/start/stop/collect processing
  with reverse-order rollback after partial failure.
- [x] **BXP-106** Persist the declared graph, effective plan, allocation choices,
  and checksums in case evidence.
- [ ] **BXP-107** Preserve exact config-content-based server merging across the
  new graph.
- [ ] **BXP-108** Add graph validation for cycles, invalid lifetimes, ambiguous
  outputs, unsafe cross-environment references, and conflicting groups.

Acceptance:

- [ ] Existing BriXTest examples generate equivalent effective plans.
- [x] Plan creation performs no process, port, credential, image, or cluster
  mutation.
- [ ] A partial-start failure leaves no owned resource running.

## Milestone 2: capability negotiation

Dependencies: milestone 1.

- [x] **BXP-120** Define stable capability names for networking, execution,
  workload shape, storage, identity, security, and transport.
- [x] **BXP-121** Infer required capabilities from the graph.
- [ ] **BXP-122** Publish capabilities from every built-in backend, launcher,
  executor, provider, and transport.
- [x] **BXP-123** Produce one diagnostic containing the resource, requirement,
  selected backend, and available alternatives when planning fails.
- [x] **BXP-124** Extend `brixtest design` with effective-plan and capability
  explanations.
- [ ] **BXP-125** Add capability declarations and conformance checks to the
  extension API.

Acceptance:

- [ ] Unsupported UDP, IPv6, PTY, device, identity, and storage requests fail
  before resource creation.
- [ ] No built-in backend ignores a public declaration field.

## Milestone 3: environments and networking

Dependencies: milestones 1 and 2.

- [ ] **BXP-200** Support multiple environments, namespaces, and Kubernetes
  contexts in one case.
- [x] **BXP-201** Add IPv4, IPv6, IPv6-only, and dual-stack port allocation.
- [ ] **BXP-202** Make local, OCI, and Kubernetes endpoints address-family aware.
- [ ] **BXP-203** Support UDP service discovery and reachability in every capable
  environment.
- [ ] **BXP-204** Use direct in-environment endpoints where possible and
  supervised TCP/UDP gateways where crossing an environment boundary.
- [ ] **BXP-205** Support server-to-helper callbacks and reverse connections.
- [ ] **BXP-206** Resolve server references to internal or external addresses
  according to their consumer.
- [ ] **BXP-207** Materialize declared host mappings as real forward and reverse
  DNS/NSS behavior for helpers, containers, and pods.
- [ ] **BXP-208** Derive default-deny network policy from declared dependencies
  and endpoint exposure.
- [ ] **BXP-209** Archive addresses, routes, gateways, DNS records, policies, and
  allocation checksums.

Acceptance:

- [ ] The same UDP test runs locally and in Docker-backed Minikube.
- [x] IPv6-only and dual-stack fallback tests exercise real IPv6 sockets.
- [ ] TLS/GSI reverse-DNS tests use libc/NSS rather than only `run.reverse()`.
- [ ] A Kubernetes server can connect to a managed callback listener.

## Milestone 4: workloads, tasks, and Kubernetes rendering

Dependencies: milestones 1 through 3.

- [ ] **BXP-300** Compile grouped servers into one local/OCI isolation unit or
  Kubernetes Pod template.
- [ ] **BXP-301** Compile grouped init tasks into ordered local setup operations
  or Kubernetes init containers.
- [ ] **BXP-302** Compile standalone tasks into supervised processes, one-shot
  containers, or Kubernetes Jobs.
- [ ] **BXP-303** Support sidecars with independent readiness, logs, metrics,
  health monitoring, and teardown.
- [ ] **BXP-304** Support replicated services and expose both the load-balanced
  service and individual replica records.
- [ ] **BXP-305** Render identity, RBAC, networking, scheduling, volumes, probes,
  lifecycle, and security from typed graph nodes.
- [ ] **BXP-306** Add Deployments, StatefulSets, Jobs, Pods, Services,
  ServiceAccounts, Roles, RoleBindings, NetworkPolicies, PVCs, and associated
  cleanup to the Kubernetes backend.
- [ ] **BXP-307** Support provider-owned CRDs through a lifecycle contract; do
  not add raw manifest dictionaries to normal test declarations.
- [ ] **BXP-308** Collect per-container logs, events, status, restarts, exits, and
  resource metrics.
- [ ] **BXP-309** Make Kubernetes teardown UID-aware so BriXTest cannot delete a
  similarly named object that it did not create.

Acceptance:

- [ ] Minimal examples cover init container, sidecar, Job, three replicas,
  ServiceAccount/RBAC, NetworkPolicy, and PVC behavior.
- [ ] All rendered Kubernetes resources have graph-node and test-instance
  provenance links.

## Milestone 5: helper isolation and command transport

Dependencies: milestones 1 through 4.

- [ ] **BXP-400** Define a transport-neutral helper protocol for heartbeats,
  pytest reports, tracebacks, attachments, logs, and cancellation.
- [ ] **BXP-401** Produce a content-addressed bundle containing the selected test,
  BriXTest installation, required pure-Python files, and dependency identity.
- [ ] **BXP-402** Launch the helper as a Kubernetes Job with its declared
  environment and identity.
- [ ] **BXP-403** Keep fixture and test execution inside the remote helper while
  pytest reporting remains controller-owned.
- [ ] **BXP-404** Enforce deadlines and terminate the remote Job/process tree
  when heartbeats stop.
- [ ] **BXP-405** Support text and binary stdin in the Kubernetes tool executor.
- [ ] **BXP-406** Support PTY allocation, resize, streaming, and termination.
- [ ] **BXP-407** Apply the same bounded capture, retry, cancellation, and durable
  log semantics on every executor.
- [ ] **BXP-408** Preserve complete remote tracebacks and partial output on error.

Acceptance:

- [ ] A test proves its Kubernetes ServiceAccount identity and RBAC permissions.
- [ ] Interactive and binary-stdin clients behave consistently locally and in
  Kubernetes.
- [ ] A deliberately hung remote test is killed without blocking the controller.

## Milestone 6: identity, user namespaces, devices, and filesystems

Dependencies: milestones 1, 2, and 4.

- [ ] **BXP-500** Implement UID, GID, supplementary-group, and NSS materialization.
- [ ] **BXP-501** Implement user-namespace UID/GID mappings for capable local and
  OCI runtimes.
- [ ] **BXP-502** Implement least-privilege Linux capability translation.
- [ ] **BXP-503** Implement explicit host/device volumes, including `/dev/fuse`.
- [ ] **BXP-504** Implement mount propagation and mount lifecycle supervision.
- [x] **BXP-505** Implement `Service.fs` using confined native operations locally.
- [ ] **BXP-506** Implement binary-safe OCI filesystem transport.
- [ ] **BXP-507** Implement binary-safe Kubernetes filesystem transport without
  shell/base64 helpers in test code.
- [x] **BXP-508** Support stat, list, read, write, mkdir, remove, chmod, chown,
  symlink, and xattr operations.
- [ ] **BXP-509** Prevent traversal, symlink escapes, undeclared host access, and
  implicit privilege escalation.
- [x] **BXP-510** Journal filesystem mutations and resulting checksums.

Acceptance:

- [ ] Port the real FUSE mount lifecycle test to the public API.
- [ ] Port the user-namespace setfsuid/supplementary-group red-team test.
- [ ] Run the same server filesystem assertions locally and in Kubernetes.

## Milestone 7: managed authentication authorities

Dependencies: milestones 1 through 6.

- [ ] **BXP-600** Model authorities, issued material, consumers, refresh behavior,
  and revocation as graph resources.
- [ ] **BXP-601** Provide HS256, ES256, and RSA token issuance.
- [ ] **BXP-602** Provide managed JWKS and OIDC discovery endpoints.
- [ ] **BXP-603** Support signing-key rotation and observable JWKS refresh.
- [ ] **BXP-604** Manage TLS CA, host/client identities, CRLs, revocation, and CRL
  publication.
- [ ] **BXP-605** Manage VOMS/GSI authority, trust roots, LSC data, proxy issuance,
  FQANs, and revocation.
- [ ] **BXP-606** Run Kerberos KDCs as reachable managed services with TCP and UDP
  endpoints and generated realm/domain configuration.
- [ ] **BXP-607** Support authority stop/start and failure injection for refresh
  and recovery tests.
- [ ] **BXP-608** Distribute credentials by declared role and environment only.
- [ ] **BXP-609** Archive public material, versions, checksums, issuance events,
  rotations, and revocations while redacting private material.

Acceptance:

- [ ] Minimal examples cover token, JWKS rotation, TLS CRL reload, VOMS/GSI, and
  Kerberos on local and Minikube backends.
- [ ] A server pod never receives client-only credentials.

## Milestone 8: binary, build, and image pipeline

Dependencies: milestones 1, 2, 4, and 5.

- [ ] **BXP-700** Permit task outputs to become artifact or binary inputs for
  later graph nodes.
- [ ] **BXP-701** Snapshot a binary, interpreter/loader, selected libraries, and
  runtime data before any dependent server starts.
- [ ] **BXP-702** Construct deterministic minimal OCI layers from captured
  binaries.
- [ ] **BXP-703** Record image manifests, layer digests, file checksums, build
  inputs, tool versions, and an SBOM.
- [ ] **BXP-704** Load generated images into the Docker-backed Minikube profile.
- [ ] **BXP-705** Push generated images to a configured content-addressed registry
  for remote clusters.
- [ ] **BXP-706** Preserve support for explicitly supplied digest-pinned images.
- [ ] **BXP-707** Add project/profile configuration for base images and registries
  without requiring per-test settings.
- [ ] **BXP-708** Verify ASan and dynamically linked nginx substitutions through a
  complete suite rerun.
- [ ] **BXP-709** Support build/RPM tasks without allowing a rebuild to replace a
  captured executable used by an active run.

Acceptance:

- [ ] `binary("nginx", path="...")` works unchanged on local and Minikube.
- [ ] A build modified after capture cannot alter the running suite.

## Milestone 9: provider-managed storage and infrastructure

Dependencies: milestones 1, 2, 4, and 6.

- [ ] **BXP-800** Add versioned resource, volume, identity, transport, and image
  provider contracts with reusable conformance suites.
- [ ] **BXP-801** Require providers to return typed plan fragments, ownership
  metadata, readiness, outputs, and teardown operations.
- [ ] **BXP-802** Implement a Rook/Ceph provider covering operator discovery,
  CephCluster, pools, CephFS, PVCs, credentials, and health.
- [ ] **BXP-803** Add persistence, restart, rescheduling, and snapshot tests.
- [ ] **BXP-804** Add orphan discovery and conservative cleanup for provider
  resources.
- [ ] **BXP-805** Correlate provider logs, events, metrics, object UIDs, and storage
  identities with consuming tests.

Acceptance:

- [ ] A test requests a Ceph-backed volume without importing Kubernetes or Rook
  APIs.
- [ ] Provider failure rolls back all resources BriXTest owns and nothing else.

## Milestone 10: global shared topology

Dependencies: milestones 1 through 5.

- [ ] **BXP-900** Move session-scoped pool ownership to a controller-supervised
  topology broker shared by xdist workers.
- [ ] **BXP-901** Merge collected worker plans before starting shared resources.
- [ ] **BXP-902** Publish resolved services to workers through bounded authenticated
  IPC.
- [ ] **BXP-903** Monitor shared servers, gateways, authorities, and port-forwards
  independently of test helpers.
- [ ] **BXP-904** Add explicit `scope="worker"` for intentionally worker-local
  instances.
- [ ] **BXP-905** Include environment, image, identity, network, volume, auth, and
  config identity in shared-pool fingerprints.
- [ ] **BXP-906** Link all consumers to one instance/log record and tear it down
  after the final actual consumer.
- [ ] **BXP-907** Recover or safely reap broker resources after worker or
  controller failure.

Acceptance:

- [ ] Two xdist workers consume one session-scoped server instance.
- [ ] A shared server crash fails consumers quickly with one correlated trace.

## Milestone 11: evidence, migration, and release readiness

Dependencies: all preceding milestones.

- [ ] **BXP-1000** Extend JSON, SQLite, Parquet, HTML, OpenSearch, and Elasticsearch
  schemas for the complete resource graph.
- [ ] **BXP-1001** Store internal/external endpoints, routes, DNS, identities,
  RBAC, policies, images, volumes, tasks, authorities, replicas, and provider
  objects.
- [ ] **BXP-1002** Store individual stdout/stderr/log streams and checksums for
  every task, container, server, client, helper, and authority.
- [ ] **BXP-1003** Retain exact test-to-resource and shared-resource relationships.
- [ ] **BXP-1004** Add one-command rerun for failures using the recorded backend,
  parameters, binaries, images, and resource plan.
- [ ] **BXP-1005** Port representative IPv6, UDP, callback/TPC, FUSE, userns,
  filesystem, RBAC, JWKS, CRL, Kerberos, VOMS/GSI, Ceph, interactive, and xdist
  tests into self-contained BriXTest examples.
- [ ] **BXP-1006** Add concise examples for every new public declaration and
  runtime method.
- [ ] **BXP-1007** Update architecture, API, backend, isolation, authentication,
  extension, migration, and evidence documentation.
- [ ] **BXP-1008** Make Docker-backed Minikube the mandatory Kubernetes
  conformance target in CI and the documented reference profile.
- [ ] **BXP-1009** Run the complete unit, contract, integration, live Minikube,
  complexity, API compatibility, and documentation suites.
- [ ] **BXP-1010** Confirm BriXTest imports and packages successfully when copied
  out of the parent repository.

## Required validation for every action

Every implementation action above requires all applicable boxes:

- [ ] Public success-path unit test.
- [ ] Validation/error-path unit test.
- [ ] Security-negative unit test.
- [ ] Backend contract test.
- [ ] Provenance/evidence assertion.
- [ ] Public API manifest and type-stub update.
- [ ] User-facing documentation or example.
- [ ] File-size and complexity checks.
- [ ] Full BriXTest suite remains green.

## Final definition of done

- [ ] Existing BriXTest tests run without source changes.
- [ ] Advanced examples contain no direct runtime or cluster orchestration.
- [ ] Local and Minikube use the same test source wherever physical capabilities
  permit equivalent behavior.
- [ ] Unsupported physical capabilities fail during planning with an actionable
  diagnostic.
- [ ] FUSE, userns, IPv6, UDP, reverse callback, live authority rotation, Ceph,
  and in-cluster identity tests are first-class examples.
- [ ] All processes, containers, Jobs, volumes, gateways, and authorities are
  supervised and transactionally torn down.
- [ ] Every resource, operation, log, metric, checksum, and consumer relationship
  is queryable from the evidence archive.
- [ ] A failing test can be rerun with the exact captured plan and executable
  identities.
- [ ] BriXTest remains standalone and AGPLv3-licensed.
- [ ] No raw manifest, shell/base64 filesystem workaround, backend conditional,
  unmanaged side process, compatibility exception, or complexity backlog is
  required by the shipped examples.
