"""Pytest configuration and validated suite-wide BriXTest overrides."""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Dict, Mapping, Sequence

import pytest

from brixtest.errors import SpecError
from brixtest.isolation import Isolation, docker, nsenter, podman, process, runc
from brixtest.metrics import metric_sessions_root
from brixtest.pytest_state import METRICS_SESSION
from brixtest.summary import default_runs_root

HELPER_ENV = "BRIXTEST_HELPER"
RESULT_ENV = "BRIXTEST_HELPER_RESULT"
SESSION_ENV = "BRIXTEST_METRICS_SESSION"
SERVER_ENV = "BRIXTEST_SERVER_ENV_JSON"
CLIENT_ENV = "BRIXTEST_CLIENT_ENV_JSON"
BINARY_ENV = "BRIXTEST_BINARY_OVERRIDES_JSON"
TEST_KEYS_ENV = "BRIXTEST_TEST_ENV_KEYS_JSON"
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_BINARY_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")

PUBLIC_PYTEST_OPTIONS = frozenset({
    "--brixtest-backend", "--brixtest-runs", "--brixtest-describe",
    "--brixtest-isolation", "--brixtest-isolation-image",
    "--brixtest-nsenter-target", "--brixtest-nsenter-namespace",
    "--brixtest-runc-bundle", "--brixtest-container-python",
    "--brixtest-isolation-arg", "--brixtest-allow-mutable-image",
    "--brixtest-binary", "--brixtest-sanitizer", "--brixtest-env",
    "--brixtest-server-env", "--brixtest-client-env", "--brixtest-fail-fast",
    "--no-brixtest-fail-fast", "--brixtest-metrics", "--brixtest-metrics-dir",
    "--brixtest-metrics-json", "--brixtest-metrics-html", "--brixtest-metrics-top",
    "--brixtest-sqlite", "--brixtest-search-url", "--brixtest-search-index",
    "--brixtest-search-manage-schema", "--brixtest-otlp-endpoint",
    "--brixtest-parquet", "--brixtest-s3", "--brixtest-attachment-max-bytes",
    "--brixtest-helper-log-max-bytes",
    "--brixtest-helper-plugin",
    "--brixtest-safe-import",
    "--brixtest-profile",
})
INTERNAL_PYTEST_OPTIONS = frozenset({"--brixtest-helper"})
PUBLIC_PYTEST_FIXTURES = frozenset({"run", "metrics", "brixtest_metrics"})
PUBLIC_PYTEST_MARKERS = frozenset({"brixtest", "brixtest_budget"})
PUBLIC_PYTEST_INI = frozenset({
    "brixtest_backend", "brixtest_isolation", "brixtest_runs",
    "brixtest_helper_plugins",
    "brixtest_safe_imports",
    "brixtest_profile",
})
PUBLIC_PYTEST_HOOKS = frozenset({
    "pytest_brixtest_plan", "pytest_brixtest_helper_plugins",
    "pytest_brixtest_result", "pytest_brixtest_server_ready",
    "pytest_brixtest_server_stopped", "pytest_brixtest_tool_result",
    "pytest_brixtest_artifact_materialized",
})


def pytest_addoption(parser) -> None:
    parser.addini(
        "brixtest_backend", "default BriXTest backend", default="",
    )
    parser.addini(
        "brixtest_safe_imports",
        "space-separated pure-Python module roots trusted during collection", default="",
    )
    parser.addini(
        "brixtest_isolation", "default BriXTest helper isolation", default="",
    )
    parser.addini(
        "brixtest_runs", "directory for BriXTest runs and evidence", default="",
    )
    parser.addini(
        "brixtest_helper_plugins",
        "space-separated pytest plugins explicitly allowed inside helpers", default="",
    )
    parser.addini(
        "brixtest_profile", "JSON suite profile with backend, isolation, binary, and environment overrides",
        default="",
    )
    group = parser.getgroup("brixtest")
    group.addoption("--brixtest-helper", action="store_true", default=False,
                    help="internal: execute one BriXTest case in its helper process")
    group.addoption(
        "--brixtest-helper-plugin", action="append", default=[], metavar="MODULE",
        help="load a trusted pytest plugin inside managed helpers (repeatable)",
    )
    group.addoption(
        "--brixtest-safe-import", action="append", default=[], metavar="MODULE_ROOT",
        help="allow a trusted pure-Python module root at managed-test module scope",
    )
    group.addoption(
        "--brixtest-profile", metavar="PATH",
        help="load one validated JSON suite profile before command-line overrides",
    )
    group.addoption(
        "--brixtest-backend", metavar="NAME",
        help="override every @case server backend (built-in or installed)",
    )
    group.addoption("--brixtest-runs", metavar="PATH",
                    help="directory for retained runs, logs, and summaries")
    group.addoption("--brixtest-describe", action="store_true", default=False,
                    help="describe managed cases without starting them")
    group.addoption("--brixtest-isolation",
                    choices=("process", "nsenter", "docker", "podman", "runc"),
                    help="override helper isolation for every managed case")
    group.addoption("--brixtest-isolation-image", metavar="IMAGE",
                    help="digest-pinned image used by Docker or Podman")
    group.addoption("--brixtest-nsenter-target", type=int, metavar="PID",
                    help="namespace owner PID used by nsenter")
    group.addoption(
        "--brixtest-nsenter-namespace", action="append", default=[],
        choices=("mount", "uts", "ipc", "net", "pid", "user", "cgroup", "time"),
        help="namespace to enter (repeatable; defaults to common namespaces)",
    )
    group.addoption("--brixtest-runc-bundle", metavar="PATH",
                    help="OCI bundle used as the runc template")
    group.addoption("--brixtest-container-python", default="python3", metavar="PATH",
                    help="Python executable inside Docker, Podman, or runc")
    group.addoption("--brixtest-isolation-arg", action="append", default=[], metavar="ARG",
                    help="additional runtime argument (repeatable)")
    group.addoption("--brixtest-allow-mutable-image", action="store_true", default=False,
                    help="explicitly permit a non-digest container image")
    group.addoption("--brixtest-binary", action="append", default=[], metavar="NAME=PATH",
                    help="replace and snapshot a declared binary (repeatable)")
    group.addoption("--brixtest-sanitizer", choices=("asan", "ubsan", "asan-ubsan"),
                    help="apply fail-fast sanitizer settings to test, server, and client processes")
    group.addoption("--brixtest-env", action="append", default=[], metavar="NAME=VALUE",
                    help="set helper/test environment before collection (repeatable)")
    group.addoption("--brixtest-server-env", action="append", default=[], metavar="NAME=VALUE",
                    help="overlay every server environment (repeatable)")
    group.addoption("--brixtest-client-env", action="append", default=[], metavar="NAME=VALUE",
                    help="overlay every configured client environment (repeatable)")
    group.addoption("--brixtest-fail-fast", action="store_true", dest="brixtest_fail_fast",
                    default=True, help="stop after the first failure (default)")
    group.addoption("--no-brixtest-fail-fast", action="store_false",
                    dest="brixtest_fail_fast", help="continue after failures")
    group.addoption("--brixtest-metrics", choices=("off", "summary", "all"),
                    default="summary", help="terminal metrics display")
    group.addoption("--brixtest-metrics-dir", metavar="PATH",
                    help="parent directory for per-session results")
    group.addoption("--brixtest-metrics-json", metavar="PATH",
                    help="also write the completed session as JSON")
    group.addoption("--brixtest-metrics-html", metavar="PATH",
                    help="also write a self-contained HTML report")
    group.addoption("--brixtest-metrics-top", type=int, default=20, metavar="N",
                    help="maximum aggregate terminal rows (default: 20)")
    group.addoption("--brixtest-sqlite", metavar="PATH",
                    help="SQLite archive path (default: SESSION/archive.sqlite3)")
    group.addoption("--brixtest-search-url", metavar="URL",
                    help="Elasticsearch/OpenSearch base URL or _bulk endpoint")
    group.addoption("--brixtest-search-index", default="brixtest", metavar="PREFIX",
                    help="search index prefix (default: brixtest)")
    group.addoption("--brixtest-search-manage-schema", action="store_true", default=False,
                    help="install/update the search data-stream template and retention policy")
    group.addoption("--brixtest-otlp-endpoint", metavar="URL",
                    help="export metrics, traces, and logs via OTLP/HTTP JSON")
    group.addoption("--brixtest-parquet", metavar="PATH",
                    help="write the normalized evidence dataset as Parquet")
    group.addoption("--brixtest-s3", metavar="S3_URI",
                    help="upload a complete immutable session package to s3://bucket/prefix")
    group.addoption("--brixtest-attachment-max-bytes", type=int, default=1 << 30,
                    metavar="N", help="maximum size of one output attachment")
    group.addoption(
        "--brixtest-helper-log-max-bytes", type=int, default=8 << 20,
        metavar="N", help="maximum live helper log size (default: 8 MiB)",
    )


def _assignments(values: Sequence[str], field: str, pattern: re.Pattern) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for raw in values:
        if "=" not in raw:
            raise SpecError(field, raw, "must use NAME=VALUE")
        name, value = raw.split("=", 1)
        if pattern.fullmatch(name) is None:
            raise SpecError(field, name, "has an invalid name")
        if "\x00" in value or "\n" in value or "\r" in value:
            raise SpecError(field, name, "values cannot contain NUL or newlines")
        if name in result:
            raise SpecError(field, name, "is assigned more than once")
        result[name] = value
    return result


def is_helper(config) -> bool:
    return bool(config.getoption("--brixtest-helper") or os.environ.get(HELPER_ENV))


def _serialize(name: str, values: Mapping[str, str]) -> None:
    os.environ[name] = json.dumps(dict(sorted(values.items())), separators=(",", ":"))


def _profile(config) -> Mapping[str, object]:
    raw_path = config.getoption("--brixtest-profile") or config.getini("brixtest_profile")
    if not raw_path:
        return {}
    path = Path(raw_path)
    if not path.is_absolute():
        path = Path(config.rootpath) / path
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise SpecError("suite profile", str(path), "cannot load JSON: %s" % exc) from exc
    if not isinstance(value, Mapping):
        raise SpecError("suite profile", str(path), "must contain a JSON object")
    allowed = {
        "backend", "isolation", "binaries", "sanitizer",
        "test_env", "server_env", "client_env",
    }
    unexpected = sorted(set(value) - allowed)
    if unexpected:
        raise SpecError("suite profile", unexpected, "contains unknown fields")
    for field in ("binaries", "test_env", "server_env", "client_env"):
        selected = value.get(field, {})
        if not isinstance(selected, Mapping) or not all(
            isinstance(key, str) and isinstance(item, str)
            for key, item in selected.items()
        ):
            raise SpecError("suite profile.%s" % field, selected, "must map strings to strings")
    if value.get("sanitizer") not in (None, "asan", "ubsan", "asan-ubsan"):
        raise SpecError("suite profile.sanitizer", value.get("sanitizer"), "has an unknown sanitizer")
    if value.get("backend") is not None and (
        not isinstance(value["backend"], str) or _BINARY_NAME.fullmatch(value["backend"]) is None
    ):
        raise SpecError("suite profile.backend", value.get("backend"), "has an invalid backend name")
    isolation_value = value.get("isolation")
    if isolation_value is not None and not isinstance(isolation_value, Mapping):
        raise SpecError("suite profile.isolation", isolation_value, "must be an isolation object")
    result = dict(value)
    result["_path"] = str(path.resolve())
    return result


def _profile_environment(profile: Mapping[str, object], field: str) -> Dict[str, str]:
    values = dict(profile.get(field, {}))
    return _assignments(
        ["%s=%s" % item for item in values.items()],
        "suite profile.%s" % field, _ENV_NAME,
    )


def _configure_overrides(config, profile: Mapping[str, object]) -> None:
    test_env = _profile_environment(profile, "test_env")
    test_env.update(_assignments(
        config.getoption("--brixtest-env"), "test environment", _ENV_NAME
    ))
    server_env = _profile_environment(profile, "server_env")
    server_env.update(_assignments(
        config.getoption("--brixtest-server-env"), "server environment", _ENV_NAME
    ))
    client_env = _profile_environment(profile, "client_env")
    client_env.update(_assignments(
        config.getoption("--brixtest-client-env"), "client environment", _ENV_NAME
    ))
    sanitizer = config.getoption("--brixtest-sanitizer") or profile.get("sanitizer")
    if sanitizer in ("asan", "asan-ubsan"):
        for values in (test_env, server_env, client_env):
            values.setdefault("ASAN_OPTIONS", "abort_on_error=1:halt_on_error=1:detect_leaks=1")
    if sanitizer in ("ubsan", "asan-ubsan"):
        for values in (test_env, server_env, client_env):
            values.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
    binaries = dict(profile.get("binaries", {}))
    invalid_binary_names = sorted(name for name in binaries if _BINARY_NAME.fullmatch(name) is None)
    if invalid_binary_names:
        raise SpecError("suite profile.binaries", invalid_binary_names, "has invalid binary names")
    binaries.update(_assignments(
        config.getoption("--brixtest-binary"), "binary override", _BINARY_NAME
    ))
    for name, raw in binaries.items():
        path = Path(raw).expanduser()
        if not path.is_absolute() and name in profile.get("binaries", {}):
            path = Path(str(profile["_path"])).parent / path
        path = path.resolve()
        if not path.is_file() or not os.access(str(path), os.X_OK):
            raise SpecError("binary override", raw, "must be an executable regular file")
        binaries[name] = str(path)
    if not is_helper(config) or test_env or server_env or client_env or binaries:
        os.environ.update(test_env)
        os.environ[TEST_KEYS_ENV] = json.dumps(sorted(test_env), separators=(",", ":"))
        _serialize(SERVER_ENV, server_env)
        _serialize(CLIENT_ENV, client_env)
        _serialize(BINARY_ENV, binaries)


def pytest_configure(config) -> None:
    try:
        profile = _profile(config)
    except SpecError as exc:
        raise pytest.UsageError("brixtest: %s" % exc) from exc
    setattr(config, "_brixtest_profile", profile)
    backend = (
        config.getoption("--brixtest-backend") or profile.get("backend")
        or config.getini("brixtest_backend")
    )
    runs = config.getoption("--brixtest-runs") or config.getini("brixtest_runs")
    if backend:
        if _BINARY_NAME.fullmatch(backend) is None:
            raise pytest.UsageError(
                "brixtest: backend name must match [a-z][a-z0-9_-]*"
            )
        os.environ["BRIXTEST_BACKEND"] = backend
    if runs:
        os.environ["BRIXTEST_RUNS"] = str(Path(runs).resolve())
    attachment_limit = config.getoption("--brixtest-attachment-max-bytes")
    if attachment_limit < 1:
        raise pytest.UsageError("brixtest: --brixtest-attachment-max-bytes must be >= 1")
    os.environ["BRIXTEST_ATTACHMENT_MAX_BYTES"] = str(attachment_limit)
    helper_log_limit = config.getoption("--brixtest-helper-log-max-bytes")
    if helper_log_limit < 1:
        raise pytest.UsageError("brixtest: --brixtest-helper-log-max-bytes must be >= 1")
    try:
        _configure_overrides(config, profile)
    except SpecError as exc:
        raise pytest.UsageError("brixtest: %s" % exc) from exc
    if config.getoption("brixtest_fail_fast") and not config.option.maxfail:
        config.option.maxfail = 1

    session_value = os.environ.get(SESSION_ENV)
    inherited = is_helper(config) or hasattr(config, "workerinput")
    if not inherited or not session_value:
        parent_option = config.getoption("--brixtest-metrics-dir")
        parent = (Path(parent_option).resolve() if parent_option
                  else metric_sessions_root(default_runs_root()))
        session_id = "%s-%s" % (
            time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), uuid.uuid4().hex[:10]
        )
        session_value = str(parent / session_id)
        os.environ[SESSION_ENV] = session_value
    config.stash[METRICS_SESSION] = Path(session_value).resolve()
    config.addinivalue_line("markers", "brixtest: case runs in a supervised helper")
    config.addinivalue_line(
        "markers", "brixtest_budget(name, min=None, max=None, aggregate='last', "
        "labels=None): enforce a managed-case metric bound",
    )


def selected_isolation(config, definition) -> Isolation:
    kind = config.getoption("--brixtest-isolation") or config.getini("brixtest_isolation")
    profile = getattr(config, "_brixtest_profile", {})
    profile_isolation = profile.get("isolation") if isinstance(profile, Mapping) else None
    if not kind and isinstance(profile_isolation, Mapping):
        try:
            values = dict(profile_isolation)
            bundle = values.get("bundle")
            if bundle and not Path(str(bundle)).is_absolute() and profile.get("_path"):
                values["bundle"] = Path(str(profile["_path"])).parent / str(bundle)
            return Isolation(**values).resolved(definition.source.parent)
        except TypeError as exc:
            raise SpecError(
                "suite profile.isolation", profile_isolation,
                "contains unknown constructor fields: %s" % exc,
            ) from exc
    if not kind:
        related = (
            config.getoption("--brixtest-isolation-image"),
            config.getoption("--brixtest-nsenter-target"),
            config.getoption("--brixtest-nsenter-namespace"),
            config.getoption("--brixtest-runc-bundle"),
            config.getoption("--brixtest-isolation-arg"),
            config.getoption("--brixtest-allow-mutable-image"),
            config.getoption("--brixtest-container-python") != "python3",
        )
        if any(related):
            raise SpecError(
                "isolation override", related,
                "runtime-specific options require --brixtest-isolation",
            )
        return definition.isolation.resolved(definition.source.parent)
    extra = tuple(config.getoption("--brixtest-isolation-arg"))
    python = config.getoption("--brixtest-container-python")
    image = config.getoption("--brixtest-isolation-image")
    target = config.getoption("--brixtest-nsenter-target")
    namespaces = config.getoption("--brixtest-nsenter-namespace")
    bundle = config.getoption("--brixtest-runc-bundle")
    if image and kind not in ("docker", "podman"):
        raise SpecError("isolation.image", image, "is valid only for docker or podman")
    if config.getoption("--brixtest-allow-mutable-image") and kind not in ("docker", "podman"):
        raise SpecError("mutable image opt-out", kind, "is valid only for docker or podman")
    if (target or namespaces) and kind != "nsenter":
        raise SpecError("nsenter options", kind, "require --brixtest-isolation=nsenter")
    if bundle and kind != "runc":
        raise SpecError("runc bundle", bundle, "requires --brixtest-isolation=runc")
    if extra and kind not in ("docker", "podman", "runc"):
        raise SpecError("isolation arguments", extra, "are valid only for container runtimes")
    if kind == "process":
        return process()
    if kind == "nsenter":
        return nsenter(
            target or 0,
            namespaces=tuple(namespaces) if namespaces else (
                "mount", "uts", "ipc", "net", "pid", "cgroup"
            ),
        )
    if kind == "docker":
        return docker(image or "", python=python,
                      extra_args=extra,
                      allow_mutable=config.getoption("--brixtest-allow-mutable-image"))
    if kind == "podman":
        return podman(image or "", python=python,
                      extra_args=extra,
                      allow_mutable=config.getoption("--brixtest-allow-mutable-image"))
    if not bundle:
        raise SpecError("isolation.bundle", bundle, "--brixtest-runc-bundle is required")
    return runc(Path(bundle), python=python, extra_args=extra).resolved(
        definition.source.parent
    )


def replay_options(config, isolation: Isolation) -> list[str]:
    """Return stable, non-secret pytest arguments for a repeatable case run."""
    args = ["-p", "brixtest.pytest_plugin", "-x", "--tb=long"]
    args.extend((
        "--brixtest-helper-log-max-bytes",
        str(config.getoption("--brixtest-helper-log-max-bytes")),
    ))
    backend = config.getoption("--brixtest-backend")
    runs = config.getoption("--brixtest-runs")
    if backend:
        args.extend(("--brixtest-backend", backend))
    if runs:
        args.extend(("--brixtest-runs", str(Path(runs).resolve())))
    profile = getattr(config, "_brixtest_profile", {})
    if isinstance(profile, Mapping) and profile.get("_path"):
        args.extend(("--brixtest-profile", str(profile["_path"])))
    sanitizer = config.getoption("--brixtest-sanitizer")
    if sanitizer:
        args.extend(("--brixtest-sanitizer", sanitizer))
    args.extend(isolation.cli_args())
    for option in (
        "--brixtest-binary", "--brixtest-env", "--brixtest-server-env",
        "--brixtest-client-env", "--brixtest-helper-plugin",
        "--brixtest-safe-import",
    ):
        for value in config.getoption(option):
            args.extend((option, value))
    return args
