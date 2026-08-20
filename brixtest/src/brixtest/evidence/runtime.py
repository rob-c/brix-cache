"""Per-attempt evidence facade used by the managed case runtime."""

from __future__ import annotations

import dataclasses
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional, Sequence, Union

from brixtest.evidence.artifacts import ContentStore
from brixtest.evidence.collectors import CollectorManager, CollectorSpec
from brixtest.evidence.journal import EvidenceJournal
from brixtest.evidence.model import stable_id, utc_now
from brixtest.evidence.provenance import capture
from brixtest.evidence.spans import SpanRecorder


class EvidenceRuntime:
    """Coordinates evidence while keeping its storage out of test code."""

    def __init__(
        self, *, root: Path, session_dir: Path, nodeid: str, source_root: Path,
        backend: str, isolation: str, collectors: Sequence[CollectorSpec],
    ) -> None:
        self.root = Path(root)
        self.session_dir = Path(session_dir)
        self.nodeid = nodeid
        self.source_root = Path(source_root)
        self.backend = backend
        self.isolation = isolation
        self.collector_specs = tuple(collectors)
        self.started_at = time.time()
        self.started_perf = time.perf_counter()
        self.attempt_id = os.environ.get("BRIXTEST_ATTEMPT_ID") or stable_id(
            os.environ.get("BRIXTEST_METRICS_SESSION", ""), nodeid, os.getpid(), self.started_at
        )
        self.trial = int(os.environ.get("BRIXTEST_TRIAL", "0"))
        self.warmup = os.environ.get("BRIXTEST_WARMUP") == "1"
        self.journal = EvidenceJournal(
            self.root / "evidence" / "journal.jsonl", attempt_id=self.attempt_id
        )
        max_bytes = int(os.environ.get("BRIXTEST_ATTACHMENT_MAX_BYTES", str(1 << 30)))
        self.artifacts = ContentStore(
            self.session_dir / "objects", self.root, max_bytes=max_bytes
        )
        self.spans = SpanRecorder(self.event)
        self.collectors: Optional[CollectorManager] = None
        self._provenance: dict = {}
        self._findings: list[dict] = []
        self._servers: list[dict] = []
        self._outcome = "running"
        self._begun = False

    def elapsed(self) -> float:
        return time.perf_counter() - self.started_perf

    def begin(self) -> None:
        if self._begun:
            return
        self._begun = True
        self.event("attempt-start", {
            "nodeid": self.nodeid, "trial": self.trial, "warmup": self.warmup,
            "backend": self.backend, "isolation": self.isolation,
        })

    def event(self, event: str, data: Mapping[str, object]) -> None:
        if self._begun or event == "attempt-start":
            self.journal.append(event, data, elapsed=self.elapsed())

    def metric_event(self, event: str, data: Mapping[str, object]) -> None:
        self.event(event, data)

    def set_servers(self, rows: Sequence[Mapping[str, object]]) -> None:
        self._servers = [dict(row) for row in rows]
        for row in self._servers:
            self.event("server-instance", row)

    def attach(
        self, path: Union[str, Path], *, name: str = "", media_type: str = "",
        description: str = "", role: str = "output",
    ) -> dict:
        item = self.artifacts.attach(
            path, name=name, media_type=media_type, description=description, role=role
        )
        self.event("artifact", item)
        return item

    def attach_text(self, name: str, text: str, **metadata: object) -> dict:
        item = self.artifacts.attach_text(name, text, **metadata)
        self.event("artifact", item)
        return item

    def attach_json(self, name: str, value: object, **metadata: object) -> dict:
        item = self.artifacts.attach_json(name, value, **metadata)
        self.event("artifact", item)
        return item

    def start_collectors(self, manager, metric) -> None:
        if not self.collector_specs or self.collectors is not None:
            return

        def pids() -> dict[str, int]:
            result = {"test-helper": os.getpid()}
            backend = getattr(manager, "_backend", None)
            if backend is not None:
                result.update(backend.process_pids())
            return result

        def namespace() -> str:
            kubernetes = getattr(manager, "_kubernetes", None)
            return str(getattr(kubernetes, "namespace", ""))

        values = {
            "run_root": self.root, "workspace": manager.workspace,
            **{"server_%s_url" % name: service.url()
               for name, service in manager._services.items()},
        }
        resolved = []
        for spec in self.collector_specs:
            options = {}
            for key, value in spec.options.items():
                if isinstance(value, str):
                    try:
                        options[key] = value.format_map(values)
                    except KeyError:
                        options[key] = value
                elif isinstance(value, tuple):
                    options[key] = tuple(
                        item.format_map(values) if isinstance(item, str) else item for item in value
                    )
                else:
                    options[key] = value
            resolved.append(dataclasses.replace(spec, options=options))
        self.collectors = CollectorManager(
            resolved, root=self.root, pid_provider=pids,
            metric=metric.record, event=self.event, namespace_provider=namespace,
        )
        self.collectors.start()

    def close_collectors(self) -> None:
        if self.collectors is not None:
            self.collectors.close()

    def finalize(
        self, *, outcome: str, binaries: Mapping[str, object], configs: Mapping[str, Path],
        environment_names: Sequence[str], extra: Mapping[str, object] = {},
    ) -> None:
        self._outcome = outcome
        self.close_collectors()
        self._provenance = capture(
            source_root=self.source_root, backend=self.backend, isolation=self.isolation,
            binaries=binaries, configs=configs, environment_names=environment_names,
            extra=extra,
        )
        if outcome not in ("passed", "skipped"):
            self._findings.append({
                "kind": "test-failure", "severity": "error",
                "detail": "attempt outcome is %s" % outcome,
            })
        self._derive_resource_findings()
        if outcome == "passed" and self.error_findings():
            outcome = "failed"
            self._outcome = outcome
        self.event("provenance", self._provenance)
        for finding in self._findings:
            self.event("finding", finding)
        self.event("attempt-stop", {"outcome": outcome, "wall_seconds": self.elapsed()})

    def error_findings(self) -> list[dict]:
        collected = self.collectors.findings if self.collectors is not None else []
        return [dict(row) for row in list(collected) + self._findings
                if row.get("severity") == "error"]

    def _derive_resource_findings(self) -> None:
        if self.collectors is None:
            return
        resources = self.collectors.resources
        rss = {}
        for row in resources:
            if row.get("name") == "process.rss_bytes":
                owner = str(row.get("labels", {}).get("process", "unknown"))
                rss.setdefault(owner, []).append(float(row.get("value", 0)))
        for owner, values in rss.items():
            if len(values) >= 4 and values[-1] > values[0] * 1.25 \
                    and values[-1] - values[0] > (8 << 20):
                self._findings.append({
                    "kind": "possible-memory-leak", "severity": "warning",
                    "process": owner, "start_bytes": values[0], "end_bytes": values[-1],
                })
        signatures = {
            "AddressSanitizer": "asan-error",
            "LeakSanitizer": "asan-leak",
            "runtime error:": "ubsan-error",
        }
        for path in self.root.rglob("*"):
            if not path.is_file() or path.is_symlink() \
                    or not ("log" in path.name.lower() or path.suffix in (".out", ".err")):
                continue
            try:
                with path.open("rb") as handle:
                    content = handle.read(8 << 20).decode("utf-8", errors="replace")
            except OSError:
                continue
            for signature, kind in signatures.items():
                if signature in content:
                    self._findings.append({
                        "kind": kind, "severity": "error", "path": str(path),
                        "detail": "%s reported by a managed process" % signature,
                    })

    def snapshot(self) -> dict:
        collected = self.collectors.snapshot() if self.collectors is not None else {
            "resources": [], "logs": [], "findings": []
        }
        return {
            "attempt_id": self.attempt_id,
            "trial": self.trial,
            "warmup": self.warmup,
            "outcome": self._outcome,
            "started_at": (
                utc_now() if not self._begun
                else datetime.fromtimestamp(self.started_at, timezone.utc).isoformat()
            ),
            "wall_seconds": round(self.elapsed(), 9),
            "run_root": str(self.root),
            "resources": collected["resources"],
            "spans": self.spans.snapshot(),
            "artifacts": self.artifacts.items,
            "servers": [dict(row) for row in self._servers],
            "logs": collected["logs"],
            "findings": collected["findings"] + [dict(row) for row in self._findings],
            "provenance": dict(self._provenance),
            "journal": str(self.journal.path),
        }
