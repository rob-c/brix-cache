# Native C and C++ tests

BriXTest can turn one C or C++ program into one ordinary pytest item. It does
not hide a catalogue of native programs behind a batch runner: every
declaration has its own node ID, helper process, pytest result, timeout,
captured streams, metrics, provenance, and exact rerun command.

```python
from brixtest import expect_output, native_test


test_path_rules = native_test(
    "path-rules",
    sources=("c/test_path_rules.c", "../src/path_rules.c"),
    cwd="..",
    include_dirs=("src",),
    defines={"BRIX_STANDALONE": 1},
    standard="c11",
    stdout=expect_output("PASS", excludes=("FAIL",)),
)
```

Pytest collects that declaration as `test_path_rules`. Normal selection,
markers, parametrization, xdist scheduling, `-x`, skip/xfail,
report hooks, and `pytest test_native.py::test_path_rules` all continue to work.
Compilation and execution happen only in BriXTest's supervised helper, never
in the controller interpreter.

Typed parameter references retain normal pytest parametrization and produce
one independently reported native item per value:

```python
import pytest

from brixtest import native_test, param


test_modes = native_test(
    "modes",
    sources=("c/test_modes.c",),
    args=(param("mode"),),
    stdout="PASS",
)
test_modes = pytest.mark.parametrize("mode", ("read", "write"))(test_modes)
```

## Declaration model

`native_test(name, *, sources=...)` accepts the following groups of options:

| Concern | Options |
|---|---|
| Language | `language="auto"`, `"c"`, or `"c++"`; optional `standard` |
| Compiler | `compiler`; otherwise `CC`/`CXX`, then common compiler names |
| Inputs | `sources`, `include_dirs`, `defines`, `objects`, `libraries` |
| Raw tool flags | `compile_args`, `link_args`, `pkg_config` packages |
| Availability | `required_files`, `required_commands`, `missing="skip"|"fail"` |
| Invocation | `args`, `env`, `input`, `cwd`, `expected_exit_codes` |
| Assertions | `stdout`, `stderr`, or `expect_output(...)` |
| Bounds | `compile_timeout`, `timeout`, `output_limit`, `case_timeout` |
| BriXTest lifecycle | `resources`, `observe`, `trials`, `warmup`, `backend`, `isolation`, `keep` |

All commands are exact argument vectors. No shell is involved. Relative paths
are anchored at the declaring test file by default; set `cwd=".."` when a
test directory needs repository-root paths. `sources` are mandatory author
inputs and a missing source fails. `objects`, `required_files`, required
commands, compiler, and pkg-config packages are environmental prerequisites;
they follow `missing`, which defaults to a normal pytest skip.

`compile_args` defaults to `-Wall -Wextra -Werror`. Set it explicitly for
third-party code that uses another warning policy. `libraries=("crypto",
"pthread")` becomes exact `-lcrypto -lpthread` arguments; use `link_args` for
options such as `-pthread`, archive paths, linker switches, or framework flags.

## Output contracts

A string is shorthand for a required substring:

```python
test_small = native_test(
    "small",
    sources=("c/small.c",),
    stdout="ALL PASS",
)
```

Use `expect_output` when the stream has a richer contract:

```python
stdout = expect_output(
    "success", "security-negative",
    excludes=("FAIL", "AddressSanitizer"),
    regex=(r"[0-9]+ checks",),
)

stderr = expect_output(exact="", strip=True)
```

`contains` and `excludes` require every supplied token. Every regular
expression must match. `exact` compares the whole selected stream; `strip=True`
strips leading and trailing whitespace first. A mismatch reports the complete
bounded stream and the unmet clauses in the normal pytest traceback.

Expected non-zero programs are ordinary tests too:

```python
test_rejects_bad_input = native_test(
    "rejects-bad-input",
    sources=("c/parser.c",),
    args=("--invalid",),
    expected_exit_codes=(2,),
    stderr=expect_output("invalid input", excludes=("segmentation fault",)),
)
```

Set `execute=False` for a compile/link-closure test. Output expectations are
rejected for compile-only declarations because no program stream exists.

## Existing server and artifact resources

Native cases consume the same resources as Python cases. Typed references are
rendered immediately before the program runs, so a compiled client can receive
allocated server ports, URLs, artifact paths, credentials, and pytest
parameters without backend-specific code.

```python
from brixtest import http_endpoint, native_test, server

origin = server(
    "origin",
    command=("python3", "-m", "http.server", "{port}"),
    endpoints=(http_endpoint("http"),),
)

test_http_client = native_test(
    "http-client",
    sources=("c/http_client.c",),
    resources=(origin,),
    args=(origin.url("http"),),
    stdout="served page received",
)
```

The native build runs after declared resources are materialized and servers
are ready. References in `args`, `env`, and `compile_env` therefore use the same
backend-neutral rendering as `run.command()`.

## Objects, sanitizers, and coverage builds

`objects` is for prebuilt object or archive inputs whose existence is an
availability condition. When `inherit_instrumentation=True` (the default),
BriXTest inspects object symbols with `nm` and adds the matching ASan, UBSan,
TSan, or gcov link runtime flags. This allows a harness to link against either
a plain or instrumented build tree without duplicating detection code.

Use `env` for runtime sanitizer policy when required by the test:

```python
test_object_contract = native_test(
    "object-contract",
    sources=("c/object_contract.c",),
    objects=("../objs/addon/cache.o",),
    cwd="..",
    env={"ASAN_OPTIONS": "detect_leaks=0"},
    stdout="PASS",
)
```

The framework never disables sanitizer diagnostics implicitly. Its normal
evidence analysis still promotes sanitizer reports from managed streams to
findings.

## Provenance and isolation

Every native case records compile/run duration and output-binary size metrics.
The executable is copied into the content-addressed evidence store. A JSON
build attachment records exact compiler argv, source and object SHA-256 values,
binary SHA-256 and size, inherited instrumentation, run argv, exit codes, and
durations. Compile and run stdout/stderr also use BriXTest's structured command
log archive on both success and failure.

Process, nsenter, Docker, Podman, runc, and Kubernetes helper isolation keep the
same declaration. OCI helpers receive declared source/include/object inputs as
read-only mounts. Kubernetes helper bundles include every explicitly declared
input that is inside the pytest root, including normally skipped build objects.
An input outside that root is rejected during remote bundle planning instead
of being silently absent. The selected helper image must provide the requested
compiler and development libraries; ordinary availability policy then skips or
fails explicitly.

## Porting the repository's existing patterns

The native surface directly covers the established test styles:

- standalone one- or multi-translation-unit C suites;
- C++ clients linked to external libraries;
- nginx-object link closures with generated or checked-in stub sources;
- optional pkg-config packages and fallback direct libraries;
- compile-only symbol-closure checks;
- expected-success, expected-error, and security-negative argv modes;
- stdout/stderr tokens, exclusions, exact output, and regular expressions;
- per-test runtime fixtures supplied through env, argv, artifacts, or servers;
- plain, sanitizer, and coverage object trees.

Fixture-forging or other preparation remains an ordinary BriXTest `task` or
resource. A native declaration describes one compiler invocation and at most
one executable invocation; it deliberately does not grow an embedded shell or
a second orchestration language.
