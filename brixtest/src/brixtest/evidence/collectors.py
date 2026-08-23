"""Built-in low-overhead resource, Prometheus, log, and Kubernetes collectors."""

from __future__ import annotations

import contextlib
import dataclasses
import json
import math
import os
import re
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable, Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.util.http import http_url
from brixtest.util.immutable import freeze_mapping

_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,95}$")


@dataclasses.dataclass(frozen=True)
class CollectorSpec:
    """Immutable declaration for a built-in or extension evidence collector."""
    kind: str
    name: str
    interval: float = 0.5
    options: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_collector_name(self.name)
        _validate_collector_kind(self.kind)
        _validate_interval(self.interval)
        if not isinstance(self.options, Mapping):
            raise SpecError("collector options", self.options, "must be a mapping")
        object.__setattr__(self, "options", freeze_mapping(self.options))


def _validate_collector_name(value: object) -> None:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise SpecError("collector name", value, "must be a lowercase metric-safe name")


def _validate_collector_kind(value: object) -> None:
    if not isinstance(value, str) or value not in (
        "process", "prometheus", "structured-logs", "kubernetes", "plugin",
    ):
        raise SpecError("collector kind", value, "is not supported")


def _validate_interval(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise SpecError("collector interval", value, "must be > 0")


def process_tree(*, interval: float = 0.5, name: str = "process") -> CollectorSpec:
    """Collect helper/server process-tree and cgroup resource metrics."""
    return CollectorSpec("process", name, interval)


def prometheus(
    url: str, *, interval: float = 1.0, name: str = "prometheus",
    allow: Sequence[str] = (), timeout: float = 2.0,
) -> CollectorSpec:
    """Sample a Prometheus text endpoint with an optional metric allowlist."""
    url = http_url(url, "prometheus.url", allow_server_reference=True)
    _validate_metric_allowlist(allow)
    _validate_prometheus_timeout(timeout)
    return CollectorSpec("prometheus", name, interval, {
        "url": str(url), "allow": tuple(allow), "timeout": float(timeout),
    })


def _validate_metric_allowlist(allow: Sequence[str]) -> None:
    if isinstance(allow, (str, bytes)) or not all(
        isinstance(value, str) and value for value in allow
    ):
        raise SpecError("prometheus.allow", allow, "must contain metric-name strings")


def _validate_prometheus_timeout(timeout: object) -> None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise SpecError("prometheus.timeout", timeout, "must be > 0")


def structured_logs(
    *paths: str, name: str = "structured-logs", max_line_bytes: int = 1 << 20,
) -> CollectorSpec:
    """Collect bounded JSON-lines logs from run-relative path patterns."""
    _validate_log_paths(paths)
    _validate_line_limit(max_line_bytes)
    return CollectorSpec("structured-logs", name, 1.0, {
        "paths": tuple(paths), "max_line_bytes": int(max_line_bytes),
    })


def _validate_log_paths(paths: Sequence[str]) -> None:
    if not paths or not all(isinstance(path, str) and path for path in paths):
        raise SpecError("structured log paths", paths, "must contain at least one path")


def _validate_line_limit(max_line_bytes: object) -> None:
    if isinstance(max_line_bytes, bool) or not isinstance(max_line_bytes, int) \
            or max_line_bytes < 1:
        raise SpecError("structured log max_line_bytes", max_line_bytes, "must be >= 1")


def kubernetes_events(*, interval: float = 2.0, name: str = "kubernetes") -> CollectorSpec:
    """Collect Kubernetes events for the case's managed namespace."""
    return CollectorSpec("kubernetes", name, interval)


def plugin(name: str, **options: object) -> CollectorSpec:
    """Declare a lazily resolved third-party collector by entry-point name."""
    interval = options.pop("interval", 1.0)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)):
        raise SpecError("collector interval", interval, "must be a number > 0")
    return CollectorSpec("plugin", name, float(interval), options)


def _descendants(roots: Mapping[str, int]) -> dict[int, str]:
    parents = _process_parents()
    owned = {pid: name for name, pid in roots.items()}
    changed = True
    while changed:
        changed = _add_owned_children(parents, owned)
    return owned


def _process_parents() -> dict[int, int]:
    parents: dict[int, int] = {}
    proc = Path("/proc")
    if not proc.is_dir():
        return parents
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rpartition(")")[2].split()
            parents[int(entry.name)] = int(fields[1])
        except (OSError, ValueError, IndexError):
            continue
    return parents


def _add_owned_children(parents: Mapping[int, int], owned: dict[int, str]) -> bool:
    changed = False
    for pid, parent in parents.items():
        if pid not in owned and parent in owned:
            owned[pid] = owned[parent]
            changed = True
    return changed


def _proc_values(pid: int) -> dict[str, float]:
    values: dict[str, float] = {}
    try:
        fields = Path("/proc/%d/stat" % pid).read_text().rpartition(")")[2].split()
        clock = float(os.sysconf("SC_CLK_TCK"))
        page = float(os.sysconf("SC_PAGE_SIZE"))
        values.update({
            "cpu_seconds": (float(fields[11]) + float(fields[12])) / clock,
            "minor_faults": float(fields[7]), "major_faults": float(fields[9]),
            "threads": float(fields[17]), "rss_bytes": float(fields[21]) * page,
        })
    except (OSError, ValueError, IndexError):
        return {}
    try:
        io_values = {}
        for line in Path("/proc/%d/io" % pid).read_text().splitlines():
            key, _, raw = line.partition(":")
            io_values[key] = float(raw.strip())
        values["read_bytes"] = io_values.get("read_bytes", 0.0)
        values["write_bytes"] = io_values.get("write_bytes", 0.0)
    except (OSError, ValueError):
        pass
    with contextlib.suppress(OSError):
        values["file_descriptors"] = float(len(list(Path("/proc/%d/fd" % pid).iterdir())))
    try:
        for line in Path("/proc/%d/status" % pid).read_text().splitlines():
            key, _, raw = line.partition(":")
            if key in ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"):
                values[key] = float(raw.strip())
    except (OSError, ValueError):
        pass
    return values


def _cgroup_values(pid: int) -> dict[str, float]:
    root = _cgroup_root(pid)
    if root is None:
        return {}
    values = _cgroup_basic_values(root)
    values.update(_cgroup_cpu_values(root))
    return values


def _cgroup_root(pid: int):
    try:
        row = next(line for line in Path("/proc/%d/cgroup" % pid).read_text().splitlines()
                   if line.startswith("0::"))
        relative = row.partition("::")[2].lstrip("/")
        return Path("/sys/fs/cgroup") / relative
    except (OSError, StopIteration):
        return None


def _cgroup_basic_values(root: Path) -> dict[str, float]:
    values = {}
    for name, metric in (("memory.current", "cgroup_memory_bytes"),
                         ("memory.peak", "cgroup_memory_peak_bytes"),
                         ("pids.current", "cgroup_pids")):
        with contextlib.suppress(OSError, ValueError):
            values[metric] = float((root / name).read_text().strip())
    return values


def _cgroup_cpu_values(root: Path) -> dict[str, float]:
    try:
        cpu = dict(line.split() for line in (root / "cpu.stat").read_text().splitlines())
        return {
            "cgroup_cpu_seconds": float(cpu.get("usage_usec", 0)) / 1_000_000.0,
            "cgroup_throttled_seconds": float(cpu.get("throttled_usec", 0)) / 1_000_000.0,
        }
    except (OSError, ValueError):
        return {}


def _prometheus_rows(text: str, allow: Sequence[str]) -> list[tuple[str, float, dict]]:
    permitted = set(allow)
    rows = []
    for line in text.splitlines():
        row = _prometheus_row(line, permitted)
        if row is not None:
            rows.append(row)
    return rows


def _prometheus_row(line: str, permitted: set[str]):
    parts = _prometheus_parts(line)
    if parts is None:
        return None
    metric, raw = parts
    name = metric.partition("{")[0]
    if not _metric_permitted(name, permitted):
        return None
    value = _finite_float(raw)
    if value is None:
        return None
    return name.replace("_", ".")[:96], value, {"source": "prometheus"}


def _prometheus_parts(line: str):
    if not line or line.startswith("#"):
        return None
    metric, separator, raw = line.rpartition(" ")
    return (metric, raw) if separator else None


def _metric_permitted(name: str, permitted: set[str]) -> bool:
    return not permitted or name in permitted


def _finite_float(raw: str):
    try:
        value = float(raw)
    except ValueError:
        return None
    if not math.isfinite(value):
        return None
    return value


def _add_process_values(totals: dict, owner: str, values: Mapping[str, float]) -> None:
    for field, value in values.items():
        totals[(owner, field)] = totals.get((owner, field), 0.0) + value


def _process_cgroup(pid: int) -> str:
    try:
        return Path("/proc/%d/cgroup" % pid).read_text()
    except OSError:
        return ""


class CollectorManager:
    """Own collector threads and convert every failure into evidence."""

    def __init__(
        self, specs: Sequence[CollectorSpec], *, root: Path,
        pid_provider: Callable[[], Mapping[str, int]],
        metric: Callable[..., object], event: Callable[[str, Mapping[str, object]], None],
        namespace_provider: Callable[[], str],
    ) -> None:
        self.specs = tuple(specs)
        self.root = Path(root)
        self.pid_provider = pid_provider
        self.metric = metric
        self.event = event
        self.namespace_provider = namespace_provider
        self.resources: list[dict] = []
        self.logs: list[dict] = []
        self.findings: list[dict] = []
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._started = time.perf_counter()
        self._known_pids: dict[str, int] = {}
        self._cgroup_baselines: dict[tuple[str, str], float] = {}

    def start(self) -> None:
        for spec in self.specs:
            if spec.kind == "structured-logs":
                continue
            thread = threading.Thread(target=self._loop, args=(spec,), daemon=True,
                                      name="brixtest-%s" % spec.name)
            thread.start()
            self._threads.append(thread)

    def _loop(self, spec: CollectorSpec) -> None:
        while not self._stop.is_set():
            try:
                self._sample(spec)
            except Exception as exc:
                self.findings.append({
                    "kind": "collector-error", "severity": "warning",
                    "collector": spec.name, "detail": "%s: %s" % (type(exc).__name__, exc),
                })
                return
            self._stop.wait(spec.interval)

    def _emit_resource(self, name: str, value: float, unit: str, labels: Mapping[str, str]) -> None:
        row = {
            "name": name, "value": float(value), "unit": unit,
            "labels": dict(labels),
            "at_seconds": round(time.perf_counter() - self._started, 9),
        }
        self.resources.append(row)
        self.event("resource", row)
        self.metric(name, value, unit=unit, kind="gauge", labels=labels)

    def _sample(self, spec: CollectorSpec) -> None:
        if spec.kind == "process":
            self._sample_processes()
            return
        if spec.kind == "prometheus":
            self._sample_prometheus(spec)
            return
        if spec.kind == "kubernetes":
            self._sample_kubernetes(spec)
            return
        if spec.kind == "plugin":
            from brixtest.extensions import get_extension
            get_extension("collector", spec.name)(self, spec)

    def _process_crashes(self, roots) -> None:
        for owner, pid in self._known_pids.items():
            if roots.get(owner) != pid or Path("/proc/%d" % pid).exists():
                continue
            finding = {
                "kind": "process-crash", "name": "process.crash",
                "severity": "error", "process": owner,
                "pid": pid, "detail": "managed process disappeared before teardown",
            }
            if finding not in self.findings:
                self.findings.append(finding)
                self.event("finding", finding)

    def _process_totals(self, roots) -> dict[tuple[str, str], float]:
        totals: dict[tuple[str, str], float] = {}
        seen_cgroups = set()
        for pid, owner in _descendants(roots).items():
            _add_process_values(totals, owner, _proc_values(pid))
            cgroup = _process_cgroup(pid)
            if cgroup in seen_cgroups:
                continue
            seen_cgroups.add(cgroup)
            self._add_cgroup_values(totals, owner, pid, cgroup)
        return totals

    def _add_cgroup_values(self, totals, owner: str, pid: int, cgroup: str) -> None:
        for field, value in _cgroup_values(pid).items():
            measured = self._relative_cgroup_value(cgroup, field, value)
            totals[(owner, field)] = totals.get((owner, field), 0.0) + measured

    def _relative_cgroup_value(self, cgroup: str, field: str, value: float) -> float:
        if field not in ("cgroup_cpu_seconds", "cgroup_throttled_seconds"):
            return value
        baseline = self._cgroup_baselines.setdefault((cgroup, field), value)
        return max(0.0, value - baseline)

    def _sample_processes(self) -> None:
        roots = dict(self.pid_provider())
        self._process_crashes(roots)
        self._known_pids.update(roots)
        units = {
            "cpu_seconds": "s", "minor_faults": "count", "major_faults": "count",
            "threads": "count", "rss_bytes": "bytes", "read_bytes": "bytes",
            "write_bytes": "bytes", "file_descriptors": "count",
            "voluntary_ctxt_switches": "count", "nonvoluntary_ctxt_switches": "count",
            "cgroup_memory_bytes": "bytes", "cgroup_memory_peak_bytes": "bytes",
            "cgroup_pids": "count", "cgroup_cpu_seconds": "s",
            "cgroup_throttled_seconds": "s",
        }
        for (owner, field), value in sorted(self._process_totals(roots).items()):
            self._emit_resource("process.%s" % field, value, units[field], {"process": owner})

    def _sample_prometheus(self, spec) -> None:
        url = http_url(spec.options.get("url", ""), "prometheus.url")
        with urllib.request.urlopen(  # noqa: S310 - URL scheme validated above
            url, timeout=float(spec.options.get("timeout", 2.0)),
        ) as response:
            text = response.read(8 << 20).decode("utf-8", errors="replace")
        for name, value, labels in _prometheus_rows(text, spec.options.get("allow", ())):
            self._emit_resource(name, value, "", labels)

    def _sample_kubernetes(self, spec) -> None:
        namespace = self.namespace_provider()
        if not namespace:
            return
        result = subprocess.run(
            [os.environ.get("BRIXTEST_KUBECTL", "kubectl"), "get", "events",
             "-n", namespace, "-o", "json"],
            capture_output=True, text=True, timeout=max(2.0, spec.interval), check=False,
        )
        if result.returncode == 0:
            payload = json.loads(result.stdout)
            items = payload.get("items", []) if isinstance(payload, Mapping) else []
            self._emit_resource("kubernetes.events", len(items), "count", {})
            self.event("kubernetes-events", {"items": items})

    def _collect_logs(self) -> None:
        for spec in self.specs:
            if spec.kind != "structured-logs":
                continue
            limit = int(spec.options.get("max_line_bytes", 1 << 20))
            for raw in spec.options.get("paths", ()):
                for path in self.root.glob(str(raw)):
                    self._collect_log_path(path, limit)

    def _collect_log_path(self, path: Path, limit: int) -> None:
        if not path.is_file() or path.is_symlink():
            return
        try:
            with path.open("rb") as handle:
                for number, line in enumerate(handle, 1):
                    self._collect_log_line(path, number, line, limit)
        except OSError as exc:
            self.findings.append({
                "kind": "log-read-error", "severity": "warning",
                "path": str(path), "detail": str(exc),
            })

    def _collect_log_line(self, path: Path, number: int, line: bytes, limit: int) -> None:
        if len(line) > limit:
            self.findings.append({
                "kind": "oversized-log-record", "severity": "warning",
                "path": str(path), "line": number,
            })
            return
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, ValueError):
            return
        if isinstance(value, Mapping):
            self.logs.append({"path": str(path), "line": number, "record": dict(value)})

    def close(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=2.0)
        self._collect_logs()

    def snapshot(self) -> dict:
        return {
            "resources": [dict(row) for row in self.resources],
            "logs": [dict(row) for row in self.logs],
            "findings": [dict(row) for row in self.findings],
        }
