# Compatibility and migration policy

The `from brixtest import ...` manifest and pytest integration manifest are the
stable API. BriXTest follows Semantic Versioning and retains deprecated author
spellings for at least one minor release. Deprecations use Python's
`DeprecationWarning` so normal test output remains quiet while migration tools
can enable them explicitly.

## Canonical 0.16 API

- Use `native_test()` for one independently collected C/C++ program and
  `expect_output()` for declarative stream checks.
- Keep fixture generation in normal resources/tasks; native declarations remain
  one shell-free compile invocation plus at most one executable invocation.

## Canonical 0.15 API

- Prefer declaration-owned references such as `origin.url("http")`,
  `payload.ref()`, and `token.ref()` plus `param(...)` for pytest values.
- Select process, Docker, or Podman placement independently per local server;
  use `backend="minikube"` for the supported Docker-backed local cluster.
- Use running `Service` health, bounded log, signal/restart/wait, and diagnostic
  command methods instead of backend-specific subprocess calls.
- Package new placement mechanics as `brixtest.launchers` extensions and test
  them with `check_launcher_contract`.

Existing explicit `*_ref(...)` helpers, placeholders, and whole-case backend
declarations remain supported.

## Canonical 0.14 API

- Use `Execution` and `execution(...)`; `Command` and `command(...)` remain
  compatibility spellings.
- Use `run.tool(tool).run(...)` for declared tools.
- Use `run.execute(execution, ...)` for reusable, unnamed execution policy.
- Use `run.command(*argv)` for a direct one-off command.
- Use `@case(...)` and the `run` fixture for all new suites.

The older JSON catalogue, `Project`, `brix`, `fleet`, and `workspace` fixture
architecture remains available to the compatibility suite but is no longer the
author model. `activate_project()` emits a deprecation warning. It will not be
removed before a separately announced major release.

Runtime extensions must migrate to the shared v1 registry. The earlier
`brixtest.evidence.plugins` import remains as a forwarding compatibility facade;
new packages should use `brixtest.extensions` and the public context types.

Run the contract browser before and after an upgrade:

```console
brixtest api --json > brixtest-api.json
pytest -W default::DeprecationWarning
```
