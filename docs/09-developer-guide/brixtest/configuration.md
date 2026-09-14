# Configuration files and templates

Server instances belong to tests, while reusable server templates belong on
disk. A test fills its user-owned fields and hands BriXTest the resulting
declaration; BriXTest fills runtime fields only after allocating resources.

```python
from brixtest import binary, configs, http_endpoint, http_probe, load_template, server

nginx = binary("nginx", "/build/objs/nginx")
config = load_template("configs/nginx.conf.in").fill(
    filename="nginx.conf",
    document_root="/srv/example",
)
logging_config = load_template("configs/logging.conf.in").fill(
    filename="logging.conf", level="info",
)
origin = server(
    "origin",
    binary=nginx,
    args=["-c", "{config}", "-g", "daemon off;"],
    configs=configs(config, logging_config, primary="nginx.conf"),
    endpoints=[http_endpoint(), http_endpoint("admin")],
    env={"RUN_WORKSPACE": "{workspace}"},
    probe=http_probe(timeout=20),
)
```

`load_template(path).fill(filename=..., **values)` is the recommended authoring
flow. `server_config(text, filename=...)` accepts already-generated text, while
`static_config(path)` captures an unrendered file and `template_config(path)` is
the compact compatibility form. Rendering is literal `{placeholder}`
replacement rather than Python `str.format`, so unrelated config-language
braces remain intact. Misspelled user fields and unresolved runtime fields fail
before spawn.

Every run snapshots the original source, declaration-completed text, and exact
final file supplied to the server. Their SHA-256 values, final filename, actual
allocated ports, and content-addressed config artifact are recorded with the
server instance in JSON, SQLite, reports, and remote evidence exports.
Relative config, artifact, and binary source paths resolve from the declaring
test module's directory; absolute paths are also accepted and always copied
into the run before use.

## Declaration fields

| Field | Meaning |
|---|---|
| `name` | Stable lowercase resource name used by `run.server()`. |
| `command` | Argument vector of strings and/or `Binary` objects; never a shell. |
| `binary`, `args` | Concise, mutually exclusive alternative to `command`. |
| `config` | Required template, static-file, or text-content declaration. |
| `configs` | Ordered multi-file config set and selected primary. |
| `ports` | Role names or role-to-fixed-port mapping; `None` means allocate. |
| `endpoints` | Named protocol/scheme/port declarations; preferred for new tests. |
| `env` | String environment values rendered from the same placeholder map. |
| `readiness` | `tcp(role, timeout=...)` or `immediate()`. |
| `probe` | TCP, HTTP(S), exec, log, immediate, or installed probe driver. |
| `depends_on` | Other server declarations/names in the same case. |
| `binaries` | Additional binaries captured even if not in argv. |
| `image` | Digest-pinned Kubernetes image when command binaries do not name it. |
| `scope` | `case`/`function`, `class`, `module`, `package`, or `session`. |
| `mounts` | Confined resource projections with stable path placeholders. |
| `lifecycle` | Foreground/background and controlled shutdown behaviour. |
| `placement` | Kubernetes image, scheduling, limits, and security context. |
| `logs` | Capture, byte bound, failure-tail length, and literal redaction. |
| `cwd`, `metadata` | Confined working subdirectory and immutable provenance labels. |

`client()` accepts `name`, `env`, `timeout`, `binaries`, mounts, logs, cwd,
input, expected exit statuses, output bound, mode, and retry count, plus either an
explicit `command` vector or the concise `binary` and `args` pair. As with
servers, the two command forms are mutually exclusive.
`case()` accepts `servers`, `clients`, `artifacts`, `binaries`, `credentials`,
`auth`, `hosts`, `observe`, `warmup`, `trials`, a whole-helper
`timeout`, `backend`, `isolation`, and `keep` (`never`, `failed`, or `always`).
Helper isolation is deliberately separate from the backend that places servers.
See [Dynamic server topology and correlation](dynamic-topology.md) for lifetime,
sharing, and dependency rules.

## Suite environment and executable overrides

Values supplied with `--brixtest-env NAME=VALUE` exist before test collection
and are inherited by helper, local servers, and clients. Use the narrower
`--brixtest-server-env` and `--brixtest-client-env` overlays when a value should
be scoped to only those process types. Each option is repeatable; malformed or
duplicate names fail configuration.

`--brixtest-binary NAME=/absolute/executable` replaces any `Binary` declaration
with that name. BriXTest validates the override, captures it and its discovered
dynamic libraries, hashes the copies, and rewrites every server/client argv to
the captured path. This is the supported path for ASan, debug, dynamic, or
candidate nginx builds. The declaration remains the source of library-capture
policy, image identity, and stable logical name.

Programs that load data or plugins outside the normal ELF dependency graph can
declare exact image destinations without adding orchestration to the test:

```python
kdc = binary(
    "krb5kdc", "/usr/sbin/krb5kdc",
    runtime_files={
        "/usr/lib64/krb5/plugins/kdb/db2.so":
            "/usr/lib64/krb5/plugins/kdb/db2.so",
    },
)
```

The same mechanism captures libc/NSS inputs required by a host-built daemon
when its generated image intentionally starts from `scratch`:

```python
nginx = binary(
    "nginx", "/usr/sbin/nginx",
    runtime_files={"/etc/passwd": "/etc/passwd", "/etc/group": "/etc/group"},
)
```

`runtime_files` maps normalized absolute image paths to local source paths.
BriXTest snapshots each source with the executable, verifies its checksum for
the lifetime of the run, preserves its non-special permission bits in generated
images, includes it in image fingerprints and SBOM evidence, and archives it
for an exact rerun. Missing files, relative/traversing destinations, image-only
binaries, and collisions with another staged input fail before image creation.

For sanitizer suites, `--brixtest-sanitizer asan`, `ubsan`, or `asan-ubsan`
applies fail-fast runtime settings consistently to the helper, servers, and
clients. Combine it with `--brixtest-binary nginx=/candidate/nginx`; no test
source changes are needed.

Repeatable complete-suite variants belong in a JSON profile. Relative binary
paths are resolved beside the profile; explicit command-line options override
profile values:

```json
{
  "backend": "local",
  "isolation": {"kind": "process"},
  "binaries": {"nginx": "../build/asan/objs/nginx"},
  "sanitizer": "asan",
  "test_env": {"TEST_MODE": "candidate"},
  "server_env": {"NGINX_DEBUG": "1"},
  "client_env": {},
  "images": {
    "base_image": "registry.example/runtime@sha256:<digest>",
    "registry": "registry.example/brixtest"
  }
}
```

Run it with `pytest --brixtest-profile profiles/asan.json`. The retained rerun
command records the resolved profile path along with the selected isolation.

For `backend="minikube"`, a `Binary` that has a local `path` but no image is
automatically packaged from its immutable executable/library capture. The
generated scratch image contains the captured ELF interpreter and libraries,
uses a tag derived from their checksums, is loaded into the selected
Docker-backed Minikube profile, and runs with `imagePullPolicy: Never`.
`--brixtest-binary nginx=/build/asan/objs/nginx` also selects this path even
when the declaration normally names a prebuilt image, making an ASan or dynamic
nginx substitution use the same suite source from beginning to end. With a
configured `images.registry`, the capture is pushed with `docker push` and
remote Kubernetes uses the resulting content-addressed tag. Registry
authentication remains owned by the selected Docker and cluster contexts;
BriXTest never embeds registry credentials in declarations or evidence.

Remote Kubernetes requires either that configured registry for local captures
or an explicitly supplied digest-pinned image. Explicit `image@sha256:...`
declarations pass through unchanged. The same defaults can live in project
pytest configuration:

Kubernetes server Pods use the maintained digest-pinned Python runtime for the
restricted `service.fs` sidecar. Operators may replace it with
`BRIXTEST_KUBERNETES_FILESYSTEM_IMAGE=image@sha256:<digest>`; the replacement
must provide `python3`, and mutable tags are rejected before resource creation.

```ini
[pytest]
brixtest_base_image = registry.example/runtime@sha256:<digest>
brixtest_registry = registry.example/brixtest
```

Profile `images` values take precedence over project defaults. Base images
must be digest pinned; registries are a host plus an optional repository prefix
without a URL scheme or tag.

## Template values

| Placeholder | Value |
|---|---|
| `{name}`, `{host}`, `{port}` | Current server and its primary/readiness port. |
| `{role_port}` | Current server's named port, such as `{http_port}`. |
| `{config}` | Immutable rendered config path (command/env only). |
| `{config_destination}` | Named rendered config path; punctuation becomes `_`. |
| `{run_root}`, `{workspace}`, `{artifacts}` | Run-scoped paths. |
| `{artifact_name}` | Materialized path for the named artifact. |
| `{artifact_name_dir}` | Directory containing the materialized artifact. |
| `{binary_name}` | Captured local path for the named binary. |
| `{credential_name}`, `{credential_name_dir}` | Role-appropriate custom credential path and directory. |
| `{auth_name}` | Root of the named authentication bundle. |
| `{auth_name_file}` | Named authentication file, such as `{auth_tls_ca_cert}`. |
| `{auth_name_metadata}` | Recipe metadata, such as `{auth_kerberos_realm}`. |
| `{host_name}`, `{host_name_address}` | Declared canonical hostname and address. |
| `{server_name_host}` | Backend-neutral reachable host for a declared server. |
| `{server_name_role_port}` | Reachable named port. |
| `{server_name_url}` | Reachable HTTP URL using that server's primary role. |
| `{server_name_config}`, `{server_name_log}` | Captured config and log paths. |
| `{param_name}` | Current pytest parameter value. |
| `{mount_target}` | Run-local projection path; punctuation becomes `_`. |

## Clients

Clients are named argument-vector prefixes:

```json
curl = client(
    "curl",
    command=[curl_binary, "--fail", "--silent", "{server_origin_url}"],
    env={"SSL_CERT_FILE": "{artifact_ca}"},
    timeout=20,
)
```

A test calls `run.client(curl).run()`. Output is captured as text and returned
as the same `CommandResult` used by `run.command(...)`; non-zero exit status
raises by default, and the timeout comes from config unless
the call overrides it. Execution always uses `shell=False`, so shell operators,
substitutions, and redirects are literal arguments rather than executable text.

## Pytest configuration

The following ini values are stable and mirror their command-line overrides:

```ini
[pytest]
brixtest_backend = local
brixtest_isolation = process
brixtest_runs = .brixtest-runs
brixtest_helper_plugins = project_pytest_adapter
brixtest_safe_imports = hypothesis
brixtest_profile = profiles/local.json
```

Kubernetes helper isolation additionally accepts
`--brixtest-kubernetes-context`, `--brixtest-kubernetes-namespace`, and
`--brixtest-kubernetes-service-account`. These options are rejected unless
`--brixtest-isolation=kubernetes` is selected. The normal
`--brixtest-isolation-image` value supplies its digest-pinned Python runtime.

Use `brixtest doctor` for execution-tool diagnostics and `brixtest plugins`
to inspect extension discovery without running a test.
