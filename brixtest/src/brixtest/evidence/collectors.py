"""Built-in low-overhead resource, Prometheus, log, and Kubernetes collectors."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable, Mapping, Sequence

from brixtest.errors import SpecError
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
        if not isinstance(self.name, str) or _NAME.fullmatch(self.name) is None:
            raise SpecError("collector name", self.name, "must be a lowercase metric-safe name")
        if not isinstance(self.kind, str) or self.kind not in (
            "process", "prometheus", "structured-logs", "kubernetes", "plugin",
        ):
            raise SpecError("collector kind", self.kind, "is not supported")
        if isinstance(self.interval, bool) or not isinstance(self.interval, (int, float)) \
                or self.interval <= 0:
            raise SpecError("collector interval", self.interval, "must be > 0")
        if not isinstance(self.options, Mapping):
            raise SpecError("collector options", self.options, "must be a mapping")
        object.__setattr__(self, "options", freeze_mapping(self.options))


def process_tree(*, interval: float = 0.5, name: str = "process") -> CollectorSpec:
    """Collect helper/server process-tree and cgroup resource metrics."""
    return CollectorSpec("process", name, interval)


def prometheus(
    url: str, *, interval: float = 1.0, name: str = "prometheus",
    allow: Sequence[str] = (), timeout: float = 2.0,
) -> CollectorSpec:
    """Sample a Prometheus text endpoint with an optional metric allowlist."""
    if not isinstance(url, str) or not url:
        raise SpecError("prometheus.url", url, "must be non-empty text")
    if isinstance(allow, (str, bytes)) or not all(
        isinstance(value, str) and value for value in allow
    ):
        raise SpecError("prometheus.allow", allow, "must contain metric-name strings")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise SpecError("prometheus.timeout", timeout, "must be > 0")
    return CollectorSpec("prometheus", name, interval, {
        "url": str(url), "allow": tuple(allow), "timeout": float(timeout),
    })


def structured_logs(
    *paths: str, name: str = "structured-logs", max_line_bytes: int = 1 << 20,
) -> CollectorSpec:
    """Collect bounded JSON-lines logs from run-relative path patterns."""
    if not paths or not all(isinstance(path, str) and path for path in paths):
        raise SpecError("structured log paths", paths, "must contain at least one path")
    if isinstance(max_line_bytes, bool) or not isinstance(max_line_bytes, int) \
            or max_line_bytes < 1:
        raise SpecError("structured log max_line_bytes", max_line_bytes, "must be >= 1")
    return CollectorSpec("structured-logs", name, 1.0, {
        "paths": tuple(paths), "max_line_bytes": int(max_line_bytes),
    })


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
    parents = {}
    proc = Path("/proc")
    if not proc.is_dir():
        return {pid: name for name, pid in roots.items()}
    for entry in proc.iterdir():
        if entry.name.isdigit():
            try:
                fields = (entry / "stat").read_text().rpartition(")")[2].split()
                parents[int(entry.name)] = int(fields[1])
            except (OSError, ValueError, IndexError):
                pass
    owned = {pid: name for name, pid in roots.items()}
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if pid not in owned and parent in owned:
                owned[pid] = owned[parent]
                changed = True
    return owned


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
    try:
        values["file_descriptors"] = float(len(list(Path("/proc/%d/fd" % pid).iterdir())))
    except OSError:
        pass
    try:
        for line in Path("/proc/%d/status" % pid).read_text().splitlines():
            key, _, raw = line.partition(":")
            if key in ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"):
                values[key] = float(raw.strip())
    except (OSError, ValueError):
        pass
    return values


def _cgroup_values(pid: int) -> dict[str, float]:
    try:
        row = next(line for line in Path("/proc/%d/cgroup" % pid).read_text().splitlines()
                   if line.startswith("0::"))
        relative = row.partition("::")[2].lstrip("/")
        root = Path("/sys/fs/cgroup") / relative
    except (OSError, StopIteration):
        return {}
    values = {}
    for name, metric in (("memory.current", "cgroup_memory_bytes"),
                         ("memory.peak", "cgroup_memory_peak_bytes"),
                         ("pids.current", "cgroup_pids")):
        try:
            values[metric] = float((root / name).read_text().strip())
        except (OSError, ValueError):
            pass
    try:
        cpu = dict(line.split() for line in (root / "cpu.stat").read_text().splitlines())
        values["cgroup_cpu_seconds"] = float(cpu.get("usage_usec", 0)) / 1_000_000.0
        values["cgroup_throttled_seconds"] = float(cpu.get("throttled_usec", 0)) / 1_000_000.0
    except (OSError, ValueError):
        pass
    return values


def _prometheus_rows(text: str, allow: Sequence[str]) -> list[tuple[str, float, dict]]:
    permitted = set(allow)
    rows = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        metric, separator, raw = line.rpartition(" ")
        if not separator:
            continue
        name = metric.partition("{")[0]
        if permitted and name not in permitted:
            continue
        try:
            value = float(raw)
        except ValueError:
            continue
        if value == value and abs(value) != float("inf"):
            rows.append((name.replace("_", ".")[:96], value, {"source": "prometheus"}))
    return rows


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
            roots = dict(self.pid_provider())
            for owner, pid in self._known_pids.items():
                if roots.get(owner) == pid and not Path("/proc/%d" % pid).exists():
                    finding = {
                        "kind": "process-crash", "severity": "error",
                        "process": owner, "pid": pid,
                        "detail": "managed process disappeared before teardown",
                    }
                    if finding not in self.findings:
                        self.findings.append(finding)
                        self.event("finding", finding)
            self._known_pids.update(roots)
            totals: dict[tuple[str, str], float] = {}
            units = {
                "cpu_seconds": "s", "minor_faults": "count", "major_faults": "count",
                "threads": "count", "rss_bytes": "bytes", "read_bytes": "bytes",
                "write_bytes": "bytes", "file_descriptors": "count",
                "voluntary_ctxt_switches": "count",
                "nonvoluntary_ctxt_switches": "count",
                "cgroup_memory_bytes": "bytes", "cgroup_memory_peak_bytes": "bytes",
                "cgroup_pids": "count", "cgroup_cpu_seconds": "s",
                "cgroup_throttled_seconds": "s",
            }
            seen_cgroups = set()
            for pid, owner in _descendants(roots).items():
                for field, value in _proc_values(pid).items():
                    totals[(owner, field)] = totals.get((owner, field), 0.0) + value
                try:
                    cgroup = Path("/proc/%d/cgroup" % pid).read_text()
                except OSError:
                    cgroup = ""
                if cgroup not in seen_cgroups:
                    seen_cgroups.add(cgroup)
                    for field, value in _cgroup_values(pid).items():
                        if field in ("cgroup_cpu_seconds", "cgroup_throttled_seconds"):
                            baseline_key = (cgroup, field)
                            baseline = self._cgroup_baselines.setdefault(
                                baseline_key, value,
                            )
                            value = max(0.0, value - baseline)
                        totals[(owner, field)] = totals.get((owner, field), 0.0) + value
            for (owner, field), value in sorted(totals.items()):
                self._emit_resource("process.%s" % field, value, units[field], {"process": owner})
            return
        if spec.kind == "prometheus":
            url = str(spec.options.get("url", ""))
            with urllib.request.urlopen(url, timeout=float(spec.options.get("timeout", 2.0))) as response:
                text = response.read(8 << 20).decode("utf-8", errors="replace")
            for name, value, labels in _prometheus_rows(text, spec.options.get("allow", ())):
                self._emit_resource(name, value, "", labels)
            return
        if spec.kind == "kubernetes":
            namespace = self.namespace_provider()
            if not namespace:
                return
            kubectl = os.environ.get("BRIXTEST_KUBECTL", "kubectl")
            result = subprocess.run(
                [kubectl, "get", "events", "-n", namespace, "-o", "json"],
                capture_output=True, text=True, timeout=max(2.0, spec.interval), check=False,
            )
            if result.returncode == 0:
                payload = json.loads(result.stdout)
                items = payload.get("items", []) if isinstance(payload, Mapping) else []
                self._emit_resource("kubernetes.events", len(items), "count", {})
                self.event("kubernetes-events", {"items": items})
            return
        if spec.kind == "plugin":
            from brixtest.extensions import get_extension
            get_extension("collector", spec.name)(self, spec)

    def _collect_logs(self) -> None:
        for spec in self.specs:
            if spec.kind != "structured-logs":
                continue
            limit = int(spec.options.get("max_line_bytes", 1 << 20))
            for raw in spec.options.get("paths", ()):
                for path in self.root.glob(str(raw)):
                    if not path.is_file() or path.is_symlink():
                        continue
                    try:
                        with path.open("rb") as handle:
                            for number, line in enumerate(handle, 1):
                                if len(line) > limit:
                                    self.findings.append({
                                        "kind": "oversized-log-record", "severity": "warning",
                                        "path": str(path), "line": number,
                                    })
                                    continue
                                try:
                                    value = json.loads(line)
                                except (UnicodeDecodeError, ValueError):
                                    continue
                                if isinstance(value, Mapping):
                                    self.logs.append({"path": str(path), "line": number,
                                                      "record": dict(value)})
                    except OSError as exc:
                        self.findings.append({
                            "kind": "log-read-error", "severity": "warning",
                            "path": str(path), "detail": str(exc),
                        })

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
