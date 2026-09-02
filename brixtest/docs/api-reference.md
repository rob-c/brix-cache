# Public Python API reference

`from brixtest import ...` is the stable test-author surface. The table below
is generated from the same conceptual contract enforced by
`tests/test_public_api_contract.py`: adding, removing, accidentally exposing,
or incompatibly changing the call shape of a name fails BriXTest's own suite.
BriXTest also ships `py.typed` and an exact top-level typing facade, so mypy,
pyright, IDE completion, and runtime introspection see the same contract.

<!-- PUBLIC-API:START -->
| Name | Category | Purpose |
|---|---|---|
| `__version__` | package | Installed semantic version. |
| `api_contract` | introspection | Immutable, machine-readable Python and pytest API contract. |
| `Artifact` | declaration | Immutable input-artifact declaration. |
| `Binary` | declaration | Immutable executable/image declaration. |
| `CaseDefinition` | declaration | Complete contract attached by `@case`. |
| `Client` | declaration | Named shell-free client declaration. |
| `ConfigFile` | declaration | Static, template, or inline config declaration. |
| `ConfigSet` | declaration | Ordered multi-file server config with one primary file. |
| `ConfigTemplate` | declaration | Lazily loaded template completed with `.fill()`. |
| `Environment` | declaration | Explicit execution realm, namespace, cluster, and DNS policy. |
| `GB` | size | Decimal gigabyte. |
| `GiB` | size | Binary gibibyte. |
| `KB` | size | Decimal kilobyte. |
| `KiB` | size | Binary kibibyte. |
| `MB` | size | Decimal megabyte. |
| `MiB` | size | Binary mebibyte. |
| `OutputExpectation` | native | Immutable stdout or stderr assertion contract. |
| `Identity` | declaration | Least-privilege process, container, or Kubernetes identity. |
| `Readiness` | declaration | Server readiness contract. |
| `Resource` | declaration | Versioned provider-managed infrastructure. |
| `Server` | declaration | Managed server declaration. |
| `Task` | declaration | Supervised build, preparation, init, or finalization action. |
| `Tool` | declaration | First-class named test tool with reusable execution policy. |
| `Volume` | declaration | Temporary, persistent, host, device, or provider-backed storage. |
| `artifact` | factory | Declare an input produced by a versioned provider extension. |
| `binary` | factory | Declare a captured executable and optional image. |
| `case` | decorator | Turn a pytest function into an isolated managed case. |
| `client` | factory | Declare a client with `command` or `binary` + `args`. |
| `configs` | factory | Group multiple server config files. |
| `file_artifact` | factory | Capture and checksum an existing file. |
| `environment` | factory | Declare an explicit execution realm. |
| `expect_output` | native | Declare exact, substring, exclusion, and regex stream checks. |
| `get_case` | introspection | Return the validated contract attached by `@case`. |
| `immediate` | factory | Declare spawn-only readiness. |
| `identity` | factory | Declare a portable least-privilege identity. |
| `is_case` | introspection | Check whether a function is a managed BriXTest case. |
| `load_template` | factory | Declare a lazily loaded on-disk template. |
| `noise` | factory | Generate deterministic high-entropy input. |
| `resource` | factory | Declare infrastructure owned by a resource provider. |
| `server` | factory | Declare a server with `command` or `binary` + `args`. |
| `server_config` | factory | Supply inline config text and its filename. |
| `static_config` | factory | Capture an on-disk config without rendering. |
| `task` | factory | Declare a finite managed lifecycle action. |
| `tcp` | factory | Probe a named TCP port for readiness. |
| `template_config` | factory | Compact on-disk template declaration. |
| `text_artifact` | factory | Materialize UTF-8 input text. |
| `tool` | factory | Declare a named client-side tool. |
| `volume` | factory | Declare managed storage. |
| `Command` | resource | Reusable shell-free invocation and execution policy. |
| `Endpoint` | resource | Backend-neutral named network endpoint. |
| `Execution` | resource | Canonical reusable execution declaration for servers and tools. |
| `Lifecycle` | resource | Portable server startup and shutdown policy. |
| `LogPolicy` | resource | Bounded capture, redaction, and retention policy. |
| `Mount` | resource | Confined artifact, config, credential, path, or temporary projection. |
| `Placement` | resource | Backend, image, scheduling, and security placement hints. |
| `Probe` | resource | Portable TCP, HTTP, exec, log, or custom readiness probe. |
| `Reference` | resource | Typed reference to a materialized resource or endpoint value. |
| `ResourceLimits` | resource | CPU, memory, and process ceilings. |
| `artifact_ref` | factory | Reference an artifact path without a magic placeholder string. |
| `binary_ref` | factory | Reference a captured binary path. |
| `command` | factory | Declare a reusable command for `server`, `client`, or `run.execute`. |
| `config_ref` | factory | Reference a captured server config path. |
| `credential_ref` | factory | Reference a role-approved credential path. |
| `endpoint` | factory | Declare a named TCP or UDP endpoint. |
| `exec_probe` | factory | Declare shell-free command readiness. |
| `execution` | factory | Declare canonical shell-free execution defaults. |
| `http_endpoint` | factory | Declare an HTTP or HTTPS endpoint. |
| `http_probe` | factory | Declare HTTP or HTTPS readiness. |
| `mount` | factory | Project one declared input into a resource environment. |
| `native_test` | native | Create one independently collected, compiled, supervised C/C++ pytest item. |
| `param` | factory | Reference the current pytest parameter value in a declaration. |
| `probe` | factory | Declare a backend-neutral readiness probe. |
| `ref` | factory | Create an advanced typed runtime reference. |
| `run_root_ref` | factory | Reference the unique retained root for the current attempt. |
| `server_ref` | factory | Reference a server host, port, URL, config, or log. |
| `workspace_ref` | factory | Reference the confined writable case workspace. |
| `ExtensionInfo` | extensions | Versioned extension metadata. |
| `ExtensionRegistry` | extensions | Lazy, validated extension registry. |
| `get_extension` | extensions | Load one validated extension implementation. |
| `installed_extensions` | extensions | Inspect extensions without importing implementations. |
| `register_extension` | extensions | Register a process-local extension implementation. |
| `CaseManager` | runtime | Advanced owner for one managed attempt. |
| `BackendContext` | runtime | Stable capability facade supplied to backend extensions. |
| `CommandResult` | runtime | Decoded output, status, argv, and elapsed time. |
| `Run` | runtime | Single fixture facade used by test bodies. |
| `Service` | runtime | Backend-neutral running server endpoint. |
| `Replica` | runtime | Immutable status and direct address for one realized server replica. |
| `ServiceFilesystem` | runtime | Confined binary-safe server filesystem operations. |
| `MaterializedArtifact` | runtime | Checksum-backed artifact with direct IO helpers. |
| `CapturedBinary` | runtime | Immutable run-local executable snapshot. |
| `ProviderContext` | runtime | Confined run identity supplied to managed-resource providers. |
| `ProviderInstance` | runtime | Owned provider resource, outputs, and provenance metadata. |
| `ProviderPlan` | runtime | Side-effect-free typed infrastructure plan fragment. |
| `ConfiguredClient` | runtime | Bound named client with captured text output. |
| `ConfiguredTool` | runtime | Bound first-class tool with captured text output. |
| `ArtifactProviderContext` | runtime | Confined paths supplied to artifact providers. |
| `ToolExecutionContext` | runtime | Stable run context and immutable identity catalog supplied to tool executors. |
| `ToolExecutionRequest` | runtime | Fully rendered shell-free executor request. |
| `ServerLaunchContext` | runtime | Stable run identity and paths supplied to server launchers. |
| `ServerLaunchPlan` | runtime | Supervised process plan returned by a server launcher. |
| `ServerLaunchRequest` | runtime | Fully rendered server invocation awaiting placement translation. |
| `MetricRecorder` | metrics | Thread-safe numeric metrics and tags. |
| `MetricSample` | metrics | One immutable metric observation. |
| `MetricTimer` | metrics | Context manager for timed observations. |
| `Isolation` | isolation | Immutable helper-isolation declaration. |
| `docker` | isolation | Digest-pinned Docker helper. |
| `kubernetes` | isolation | Bundled helper executed in a digest-pinned Kubernetes Job. |
| `nsenter` | isolation | Namespace-entered helper. |
| `podman` | isolation | Digest-pinned Podman helper. |
| `process` | isolation | Direct supervised helper process. |
| `runc` | isolation | Helper in a derived OCI bundle. |
| `Credential` | credentials | Custom credential declaration. |
| `MaterializedCredential` | credentials | Role-approved credential with direct IO helpers. |
| `checksum_credential` | credentials | Checksum derived from an artifact. |
| `credential` | credentials | Text or copied-file credential. |
| `signed_credential` | credentials | HMAC-signed custom payload. |
| `AuthRecipe` | authentication | Common authentication-recipe identity. |
| `KerberosAuth` | authentication | Kerberos realm declaration. |
| `MaterializedAuth` | authentication | Auth files, role environment, and controlled `issue()`, `rotate()`, and `revoke()` operations. |
| `TLSAuth` | authentication | CA, CRL, host, and client identity declaration. |
| `TokenAuth` | authentication | Bearer-token stack with optional supervised OIDC/JWKS authority. |
| `VOMSAuth` | authentication | VOMS/GSI stack declaration. |
| `decode_token` | authentication | Decode token structure without verification. |
| `issue_token` | authentication | Issue an HS256, ES256, or RS256 test token. |
| `kerberos_auth` | authentication | Declare a Kerberos stack. |
| `tls_auth` | authentication | Declare a TLS stack. |
| `token_auth` | authentication | Declare a static or `managed=True` token stack with optional restart rotation. |
| `verify_token` | authentication | Verify token signature and claims. |
| `voms_auth` | authentication | Declare a VOMS/GSI stack. |
| `HostMapping` | network | Backend-neutral hostname declaration. |
| `host_mapping` | network | Declare virtual DNS and optional role-scoped libc/NSS mappings. |
| `CollectorSpec` | evidence | Evidence-collector declaration. |
| `collector` | evidence | Third-party collector declaration. |
| `kubernetes_events` | evidence | Kubernetes event collector. |
| `process_tree` | evidence | Process/cgroup resource collector. |
| `prometheus` | evidence | Prometheus endpoint collector. |
| `structured_logs` | evidence | Bounded JSON-lines collector. |
| `BriXTestError` | errors | Base for catch-all framework errors. |
| `CaseRunError` | errors | Managed case lifecycle failure. |
| `HelperProcessError` | errors | Helper timeout or abnormal exit. |
| `SpecError` | errors | Invalid declaration or API value. |
| `TemplateError` | errors | Unresolved strict-template fields. |
<!-- PUBLIC-API:END -->

The same contract is available without source inspection:

```console
brixtest api                  # browse the complete human-readable surface
brixtest api Run              # inspect one class and all stable members
brixtest api --group runtime  # focus on one category
brixtest api --json           # feed tooling a versioned JSON document
```

Python tooling can call `api_contract()` and receives a recursively immutable,
JSON-compatible mapping. Its schema includes every top-level symbol and
implementation module, compact function and constructor call shapes, every
stable readable attribute, every class method/property and its call shape, and
all public pytest options, fixtures, and markers. Every method and property has
its own help text, so IDE hovers and `help(...)` are useful throughout the
surface instead of falling back to class-level documentation.

## The `run` fixture

The fixture deliberately groups the common workflow into discoverable verbs:

| Operation | Result |
|---|---|
| `run.server(name)` | `Service` with ports, URLs, config, log, and identity. |
| `run.client(name)` | `ConfiguredClient`; `.run()` returns captured text output. |
| `run.tool(name)` | `ConfiguredTool`; `.run()` invokes the named tool. |
| `run.command(*argv, ...)` | `CommandResult`; never invokes a shell. |
| `run.execute(execution(...), *args)` | Execute reusable invocation defaults. |
| `run.artifact(name)` | `MaterializedArtifact`. |
| `run.artifact_text/bytes/json/path(name)` | Decoded content or path directly. |
| `run.open_artifact(name, mode)` | Open artifact handle. |
| `run.binary(name)` | `CapturedBinary`. |
| `run.volume(name)` | Backend-local path for a declared managed volume. |
| `run.task(name)` | Completed supervised task `CommandResult`. |
| `run.task_output(task, name)` | Checksum-verified declared task output path. |
| `run.credential(name)` | `MaterializedCredential`. |
| `run.auth(name)` | `MaterializedAuth`. |
| `run.resolve/reverse(value)` | Declared backend-neutral test DNS. |
| `run.metrics` | `MetricRecorder`. |
| `run.step(name, **attributes)` | Correlated timing span. |
| `run.attach*` | Content-addressed output evidence. |

`artifact_file()` remains as a compatibility alias for `artifact_path()`.
`CommandResult.check()` supports fluent assertions, while
`check_returncode()` follows the standard-library convention.

Plural properties such as `run.servers`, `run.clients`, `run.artifacts`,
`run.tools`, `run.binaries`, `run.credentials`, `run.auth_stacks`,
`run.tasks`, and `run.volumes` return snapshot
mappings for discovery. `run.as_dict()` provides a JSON-safe, secret-free run
catalogue. Both `run.command(...)` and `run.client(...).run(...)` return the
same `CommandResult` API.

`CommandResult.json()` decodes JSON stdout directly. Materialized artifacts
provide `read_json()` and `verify()`; captured binaries and credentials also
provide `verify()` for checksum assertions. Declaration mappings and nested
values are immutable snapshots, so later changes to an input dictionary cannot
silently alter a collected test design. Public frozen value objects remain
hashable and their `dataclasses.asdict(...)` output remains JSON-compatible.

Use `get_case(test_function)` to inspect the immutable declaration contract;
`CaseDefinition.resource_names` and `.as_dict()` provide stable tooling views
without relying on the decorator's private storage attribute.

`Service.endpoint(role)` exposes a portable address record, and
`Service.read_config(destination)` reads any captured file in a multi-config
server. Endpoint schemes make `Service.url()` choose HTTP/HTTPS without test
code knowing how the backend published the service. `Service.fs` provides
confined binary-safe reads, writes, metadata, directory, permission, symlink,
and `user.*` xattr operations without test-side shell or encoding workarounds.
The same facade uses confined native/shared-mount operations for local and OCI
services and a framework-managed shared-volume sidecar for Kubernetes.
`Service.replicas` contains immutable
`Replica` values with each realized process or Pod's direct in-environment
address, UID, readiness, restart count, start time, and container provenance;
the existing `Service` endpoint remains the backend's load-balanced address.

## Pytest integration surface

- `run`, `metrics`, and `brixtest_metrics` are fixtures available to managed
  functions.
- `@pytest.mark.brixtest_budget(...)` turns a metric aggregate into a test
  assertion.
- All `--brixtest-*` options are documented by `pytest --help` and in the
  focused guides linked from the documentation index.
- Planning, helper selection, server readiness/teardown, tool result, artifact
  materialization, and final-result hooks are documented in
  [Extensions](extensions.md).
