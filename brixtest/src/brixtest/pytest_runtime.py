"""Controller-side helper supervision and failure diagnostics."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Mapping, Set

from brixtest import pytest_options
from brixtest.archive import archive_case_logs
from brixtest.design import CaseDefinition
from brixtest.errors import SpecError
from brixtest.evidence.collectors import _add_owned_children, _process_parents
from brixtest.isolation import build_launch
from brixtest.metrics import evaluate_budget
from brixtest.pytest_state import METRICS_SESSION, SHARED_TOPOLOGY
from brixtest.runtime.logcapture import BoundedLogPump

_HELPER_ENV = pytest_options.HELPER_ENV
_RESULT_ENV = pytest_options.RESULT_ENV

def _safe_name(nodeid: str) -> str:
    digest = hashlib.sha256(nodeid.encode()).hexdigest()[:10]
    stem = "".join(char if char.isalnum() else "-" for char in nodeid)[-60:]
    return "%s-%s-%s" % (time.strftime("%Y%m%dT%H%M%S"), stem.strip("-"), digest)


def _case_root(item) -> Path:
    base = Path(os.environ.get(
        "BRIXTEST_RUNS", str(Path(tempfile.gettempdir()) / "brixtest-runs")
    )).resolve()
    base.mkdir(parents=True, exist_ok=True)
    return base / ("%s-%s" % (_safe_name(item.nodeid), uuid.uuid4().hex[:8]))


def _children(root: int) -> Set[int]:
    """Best-effort Linux descendant snapshot taken before the helper is killed."""
    parents = _process_parents()
    owned = {root: "helper"}
    changed = True
    while changed:
        changed = _add_owned_children(parents, owned)
    return set(owned) - {root}


def _signal_process(pid: int, signum: int) -> None:
    try:
        os.killpg(pid, signum)
    except (ProcessLookupError, PermissionError):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signum)


def _signal_tree(proc: subprocess.Popen, signum: int) -> None:
    descendants = _children(proc.pid)
    for pid in sorted(descendants, reverse=True):
        _signal_process(pid, signum)
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signum)


def _helper_environment(item, run_root, result_path, attempt_id, trial, warmup) -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        _HELPER_ENV: "1", "BRIXTEST_CONTROLLER_PID": str(os.getpid()),
        _RESULT_ENV: str(result_path), "BRIXTEST_CASE_RUN": str(run_root),
        "BRIXTEST_ATTEMPT_ID": attempt_id, "BRIXTEST_TRIAL": str(trial),
        "BRIXTEST_WARMUP": "1" if warmup else "0",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    })
    topology = item.config.stash.get(SHARED_TOPOLOGY, None)
    if topology is not None:
        env["BRIXTEST_SHARED_SERVERS_JSON"] = json.dumps(topology.for_test(item.nodeid))
    package_root = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = os.pathsep.join(
        value for value in (package_root, env.get("PYTHONPATH", "")) if value
    )
    return env


def _helper_argv(item) -> list[str]:
    argv = [
        sys.executable, "-m", "pytest", item.nodeid,
        "-p", "brixtest.pytest_plugin", "--brixtest-helper", "-q", "--tb=long",
    ]
    plugins = _helper_plugins(item)
    for plugin in plugins:
        argv.extend(("-p", plugin))
    for module_root in _safe_import_roots(item, plugins):
        argv.extend(("--brixtest-safe-import", module_root))
    return argv


def _hook_plugin_names(selected: object) -> list[str]:
    if isinstance(selected, str):
        return [selected]
    if selected is None:
        return []
    return list(selected)


def _helper_plugins(item) -> list[str]:
    plugins = list(item.config.getoption("--brixtest-helper-plugin"))
    plugins.extend(item.config.getini("brixtest_helper_plugins").split())
    selected = item.ihook.pytest_brixtest_helper_plugins(config=item.config, item=item)
    for value in selected:
        plugins.extend(_hook_plugin_names(value))
    plugins = list(dict.fromkeys(plugins))
    for plugin in plugins:
        _validate_plugin_name(plugin)
    return plugins


def _validate_plugin_name(plugin: str) -> None:
    valid = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
    if valid.fullmatch(plugin) is None:
        raise SpecError("helper plugin", plugin, "must be an importable pytest plugin name")


def _safe_import_roots(item, plugins: list[str]) -> list[str]:
    safe = list(item.config.getoption("--brixtest-safe-import"))
    safe.extend(item.config.getini("brixtest_safe_imports").split())
    safe.extend(plugin.split(".", 1)[0] for plugin in plugins)
    return list(dict.fromkeys(safe))


def _wait_helper(process, timeout: float) -> bool:
    try:
        process.wait(timeout=timeout)
        return False
    except subprocess.TimeoutExpired:
        _signal_tree(process, signal.SIGTERM)
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            _signal_tree(process, signal.SIGKILL)
            process.wait()
        return True


def _cleanup_helper(launch, process, pump) -> None:
    for cleanup in launch.cleanup:
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                cleanup, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5.0, check=False,
            )
    if not pump.join(timeout=1.0):
        _signal_tree(process, signal.SIGTERM)
        if not pump.join(timeout=0.5):
            _signal_tree(process, signal.SIGKILL)
            pump.join(timeout=0.5)


def _helper_output(path: Path) -> str:
    try:
        payload = path.read_bytes()
    except OSError:
        payload = b""
    if len(payload) <= (1 << 20):
        return payload.decode("utf-8", errors="replace")
    return "[BriXTest helper output truncated to final 1 MiB]\n" + payload[-(1 << 20):].decode(
        "utf-8", errors="replace",
    )


def _helper_payload(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        return {}


def _run_helper(
    item, definition: CaseDefinition, run_root: Path, *, attempt_id: str,
    trial: int, warmup: bool,
):
    control = run_root.parent / ".brixtest-control" / uuid.uuid4().hex
    control.mkdir(parents=True, exist_ok=False)
    result_path = control / "result.json"
    result_path.write_text("{}\n")
    helper_log = control / "helper.log"
    env = _helper_environment(item, run_root, result_path, attempt_id, trial, warmup)
    argv = _helper_argv(item)
    isolation = pytest_options.selected_isolation(item.config, definition)
    env["BRIXTEST_ISOLATION_KIND"] = isolation.kind
    launch = build_launch(
        isolation, argv, env, cwd=Path(item.config.rootpath),
        readonly_roots=(Path(item.config.rootpath), Path(__file__).resolve().parents[1]),
        writable_root=run_root.parent, control_dir=control,
        host_aliases=definition.hosts,
    )
    started = time.time()
    process = subprocess.Popen(
        launch.argv, cwd=str(launch.cwd), env=launch.env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    assert process.stdout is not None
    helper_limit = int(item.config.getoption("--brixtest-helper-log-max-bytes"))
    pump = BoundedLogPump(process.stdout, helper_log, helper_limit)
    pump.start()
    timed_out = _wait_helper(process, definition.timeout)
    _cleanup_helper(launch, process, pump)
    output = _helper_output(helper_log)
    payload = _helper_payload(result_path)
    with contextlib.suppress(OSError):
        result_path.unlink()
    logs = archive_case_logs(
        item.config.stash[METRICS_SESSION], item.nodeid, run_root,
        helper_log=helper_log, attempt_id=attempt_id,
    )
    shutil.rmtree(control, ignore_errors=True)
    return (
        process.returncode, output, payload, timed_out, started, time.time(),
        isolation.kind, logs,
    )


def _record_controller_failure(
    run_root: Path, item, definition: CaseDefinition, outcome: str, error: str,
    started: float, stopped: float,
) -> None:
    path = run_root / "summary.json"
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        payload = {
            "schema": 1, "nodeid": item.nodeid, "source": str(definition.source),
            "backend": os.environ.get("BRIXTEST_BACKEND", definition.backend),
            "run_root": str(run_root), "servers": {}, "artifacts": {},
            "binaries": {},
        }
    payload.update({
        "outcome": outcome, "error": error,
        "wall_seconds": round(stopped - started, 6),
    })
    try:
        run_root.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except OSError:
        pass


def _resource_log_tails(
    run_root: Path, definition: CaseDefinition, *, limit: int = 64 << 10,
) -> str:
    """Return bounded, labelled tails from resource logs for failure diagnostics."""
    roots = (run_root / "runtime" / "logs", run_root / "runtime" / "client-logs")
    sections = []
    used = 0
    policies = _log_policies(run_root, definition)
    for path in _resource_log_paths(roots):
        section = _log_tail_section(path, run_root, policies)
        if not section:
            continue
        encoded = section.encode("utf-8", errors="replace")
        if used + len(encoded) > limit:
            sections.append("[additional resource log tails omitted]")
            return "\n".join(sections)
        sections.append(section)
        used += len(encoded)
    return "\n".join(sections)


def _resource_log_paths(roots):
    for root in roots:
        if root.is_dir():
            yield from sorted(root.rglob("*.log"))


def _log_policies(run_root: Path, definition: CaseDefinition) -> dict:
    policies = {
        run_root / "runtime" / "logs" / (item.name + ".log"): item.logs
        for item in definition.servers
    }
    for item in definition.clients:
        client_root = run_root / "runtime" / "client-logs" / item.name
        for path in client_root.glob("*.log") if client_root.is_dir() else ():
            policies[path] = item.logs
    return policies


def _log_tail_section(path: Path, run_root: Path, policies: Mapping[Path, object]) -> str:
    lines = getattr(policies.get(path), "tail_lines", 40)
    if lines == 0:
        return ""
    try:
        tail = "\n".join(path.read_text(errors="replace").splitlines()[-lines:])
    except OSError:
        return ""
    if not tail:
        return ""
    return "--- %s ---\n%s" % (path.relative_to(run_root), tail)


def _cleanup_timed_out_kubernetes(definition: CaseDefinition, run_root: Path) -> None:
    selected = os.environ.get("BRIXTEST_BACKEND", definition.backend)
    if selected not in ("kubernetes", "minikube"):
        return
    namespace = "brixtest-%s" % run_root.name.lower().replace("_", "-")[-40:]
    kubectl = os.environ.get("BRIXTEST_KUBECTL", "kubectl")
    try:
        argv = [kubectl]
        if selected == "minikube":
            argv.extend((
                "--context", os.environ.get("BRIXTEST_MINIKUBE_PROFILE", "brixtest"),
            ))
        argv.extend(("delete", "namespace", namespace, "--wait=false"))
        subprocess.run(
            argv,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5.0, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _budget_failure(marker, metrics: Mapping[str, object]) -> str:
    try:
        if len(marker.args) != 1 or not isinstance(marker.args[0], str):
            raise SpecError(
                "brixtest_budget", marker.args,
                "needs exactly one positional metric name",
            )
        unexpected = set(marker.kwargs) - {"min", "max", "aggregate", "labels"}
        if unexpected:
            raise SpecError(
                "brixtest_budget options", sorted(unexpected),
                "known: min, max, aggregate, labels",
            )
        return evaluate_budget(
            metrics, marker.args[0], minimum=marker.kwargs.get("min"),
            maximum=marker.kwargs.get("max"),
            aggregate=marker.kwargs.get("aggregate", "last"),
            labels=marker.kwargs.get("labels"),
        ) or ""
    except SpecError as exc:
        return str(exc)


def _budget_failures(item, metrics: Mapping[str, object]) -> list[str]:
    return [
        failure
        for marker in item.iter_markers("brixtest_budget")
        if (failure := _budget_failure(marker, metrics))
    ]
