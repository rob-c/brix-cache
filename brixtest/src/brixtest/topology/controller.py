"""Supervise collection-derived session servers outside test helpers."""

from __future__ import annotations

import json
import multiprocessing
import os
import signal
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional, Sequence

from brixtest.archive import archive_server_log
from brixtest.errors import CaseRunError, SpecError
from brixtest.topology.model import PoolPlan, derive, instance_id, pool_key


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(".%s.%d" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
    os.replace(str(temporary), str(path))


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _health_error(manager) -> str:
    backend = getattr(manager, "_backend", None)
    if backend is not None:
        for name in manager._started:
            process = backend._procs.get(name)
            if process is not None and process.poll() is not None:
                return "server %s exited unexpectedly with status %s" % (
                    name, process.returncode,
                )
    kubernetes = getattr(manager, "_kubernetes", None)
    if kubernetes is not None:
        for name, process in kubernetes._forwards.items():
            if process.poll() is not None:
                return "server %s Kubernetes port-forward exited unexpectedly" % name
    return ""


def _serve(plan: PoolPlan, root: Path, session_dir: Path, control: Path, parent_pid: int) -> None:
    os.environ["BRIXTEST_SHARED_POOL_OWNER"] = "1"
    os.environ.pop("BRIXTEST_SHARED_SERVERS_JSON", None)
    os.environ["BRIXTEST_METRICS_SESSION"] = str(session_dir)
    os.environ["BRIXTEST_ATTEMPT_ID"] = "shared-" + plan.key
    started = time.time()
    manager = None
    try:
        from brixtest.runtime.manager import CaseManager
        manager = CaseManager(plan.definition, "@shared/%s" % plan.key, root=root)
        run = manager.start()
        observed = {
            str(row.get("name", "")): row
            for row in manager.evidence.snapshot().get("servers", [])
        }
        services = {}
        for server in plan.definition.servers:
            service = run.server(server.name)
            metadata = observed.get(server.name, {})
            services[server.name] = {
                "instance_id": instance_id(plan.key, server.name),
                "pool_id": plan.key,
                "name": server.name,
                "scope": plan.scope,
                "host": service.host,
                "ports": dict(service.ports),
                "config": str(service.config),
                "config_filename": metadata.get(
                    "config_filename", service.config_filename or service.config.name
                ),
                "config_sha256": metadata.get("config_sha256", service.config_sha256),
                "config_source_sha256": metadata.get(
                    "config_source_sha256", service.config_source_sha256
                ),
                "config_declared_sha256": metadata.get(
                    "config_declared_sha256", service.config_declared_sha256
                ),
                "config_artifact": metadata.get("config_artifact", {}),
                "configs": {name: str(path) for name, path in service.configs.items()},
                "schemes": dict(service.schemes),
                "protocols": dict(service.protocols),
                "metadata": dict(service.metadata),
                "log": str(service.log),
                "workdir": str(service.workdir),
                "started_at": _iso(started), "started_at_epoch": started,
            }
        _write(control / "ready.json", {"pool_id": plan.key, "services": services})
        while not (control / "stop").exists():
            try:
                os.kill(parent_pid, 0)
            except OSError:
                break
            health_error = _health_error(manager)
            if health_error:
                raise CaseRunError("@shared/%s" % plan.key, "monitor", health_error)
            time.sleep(0.1)
        manager.set_outcome("passed")
        manager.close()
        _write(control / "result.json", {
            "outcome": "passed", "started_at": _iso(started),
            "started_at_epoch": started, "stopped_at": _iso(time.time()),
            "stopped_at_epoch": time.time(),
            "metrics": manager.metrics.snapshot(), "evidence": manager.evidence.snapshot(),
        })
    except BaseException as exc:
        if manager is not None:
            try:
                manager.set_outcome("failed")
                manager.close()
            except Exception:
                pass
        failure = {
            "outcome": "failed", "error": "%s: %s" % (type(exc).__name__, exc),
            "traceback": traceback.format_exc(), "started_at": _iso(started),
            "started_at_epoch": started, "stopped_at": _iso(time.time()),
            "stopped_at_epoch": time.time(),
        }
        if manager is not None:
            failure.update({
                "metrics": manager.metrics.snapshot(),
                "evidence": manager.evidence.snapshot(),
            })
        _write(control / "error.json", failure)


class _Pool:
    def __init__(self, plan: PoolPlan, session_dir: Path) -> None:
        self.plan = plan
        self.root = Path(session_dir) / "topology" / plan.key / "run"
        self.control = Path(session_dir) / "topology" / plan.key / "control"
        self.process = None
        self.manifest: dict = {}
        self.stopped = False
        self.result: dict = {}

    def start(self) -> None:
        if self.process is not None:
            return
        if pool_key(
            self.plan.definition, self.plan.scope, self.plan.domain,
        ) != self.plan.key:
            raise SpecError(
                "shared topology", self.plan.key,
                "a server declaration or config changed after collection",
            )
        self.control.mkdir(parents=True, exist_ok=True)
        try:
            context = multiprocessing.get_context("fork")
        except ValueError as exc:
            raise SpecError("shared topology", self.plan.key, "requires fork-capable Python") from exc
        self.process = context.Process(
            target=_serve,
            args=(self.plan, self.root, self.control.parent.parent.parent,
                  self.control, os.getpid()),
            name="brixtest-shared-%s" % self.plan.key, daemon=True,
        )
        self.process.start()
        deadline = time.monotonic() + max(30.0, min(300.0, self.plan.definition.timeout))
        ready = self.control / "ready.json"
        error = self.control / "error.json"
        while time.monotonic() < deadline:
            if ready.is_file():
                self.manifest = json.loads(ready.read_text())
                return
            if error.is_file() or not self.process.is_alive():
                detail = json.loads(error.read_text()) if error.is_file() else {}
                raise CaseRunError("@shared/%s" % self.plan.key, "setup",
                                   str(detail.get("traceback", detail.get("error", "supervisor exited"))))
            time.sleep(0.05)
        self.stop(force=True)
        raise CaseRunError("@shared/%s" % self.plan.key, "setup", "startup timed out")

    def stop(self, *, force: bool = False) -> dict:
        if self.stopped:
            return dict(self.result)
        if self.process is None:
            self.stopped = True
            return {}
        (self.control / "stop").touch()
        self.process.join(timeout=0.5 if force else 15.0)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=2.0)
        if self.process.is_alive() and self.process.pid:
            os.kill(self.process.pid, signal.SIGKILL)
            self.process.join(timeout=1.0)
        result_path = self.control / "result.json"
        error_path = self.control / "error.json"
        result = json.loads(result_path.read_text()) if result_path.is_file() else {}
        if error_path.is_file():
            result.update(json.loads(error_path.read_text()))
        self.result = result
        self.stopped = True
        return dict(result)

    def check(self) -> None:
        error_path = self.control / "error.json"
        if error_path.is_file() or (self.process is not None and not self.process.is_alive()):
            detail = json.loads(error_path.read_text()) if error_path.is_file() else {}
            raise CaseRunError(
                "@shared/%s" % self.plan.key, "monitor",
                str(detail.get("traceback", detail.get("error", "supervisor exited"))),
            )


class SharedTopology:
    """One session's derived pools and test-to-instance relationships."""

    def __init__(
        self, plans: Sequence[PoolPlan], session_dir: Path, *,
        case_session_dir: Optional[Path] = None,
    ) -> None:
        self.session_dir = Path(session_dir)
        self.case_session_dir = Path(case_session_dir or session_dir)
        self.pools = {plan.key: _Pool(plan, session_dir) for plan in plans}
        self._item_keys = {
            nodeid: tuple(plan.key for plan in plans if nodeid in plan.tests)
            for plan in plans for nodeid in plan.tests
        }
        self._remaining = {
            plan.key: set(plan.tests) for plan in plans
        }
        self.closed = False

    @classmethod
    def build(
        cls, rows: Sequence[tuple[str, object]], session_dir: Path, *,
        case_session_dir: Optional[Path] = None,
    ) -> "SharedTopology":
        selected = Path(session_dir)
        namespace = selected.name if selected.parent.name == "workers" else ""
        return cls(
            derive(rows, namespace=namespace), selected,
            case_session_dir=case_session_dir,
        )

    def ensure_started(self, keys: Sequence[str]) -> None:
        started = []
        try:
            for key in keys:
                pool = self.pools[key]
                if pool.process is not None:
                    continue
                pool.start()
                started.append(pool)
        except BaseException:
            for pool in reversed(started):
                pool.stop(force=True)
            raise

    def for_test(self, nodeid: str) -> dict:
        keys = self._item_keys.get(nodeid, ())
        self.ensure_started(keys)
        services = {}
        for key in keys:
            self.pools[key].check()
            for name, row in self.pools[key].manifest.get("services", {}).items():
                if name in services and services[name]["instance_id"] != row["instance_id"]:
                    raise SpecError("shared server", name, "test resolves two different instances")
                services[name] = row
        return {"services": services}

    def finished(self, nodeid: str) -> None:
        """Release non-session pools after their final collected consumer."""
        for key in self._item_keys.get(nodeid, ()):
            remaining = self._remaining[key]
            remaining.discard(nodeid)
            pool = self.pools[key]
            if not remaining and pool.plan.scope != "session":
                pool.stop()

    def close(self) -> list[dict]:
        if self.closed:
            path = self.session_dir / "topology.json"
            return json.loads(path.read_text()).get("pools", []) if path.is_file() else []
        self.closed = True
        completed = set()
        for path in (self.case_session_dir / "cases").glob("*.json"):
            try:
                completed.add(str(json.loads(path.read_text()).get("nodeid", "")))
            except (OSError, ValueError, TypeError):
                pass
        records = []
        for key, pool in reversed(tuple(self.pools.items())):
            result = pool.stop()
            services = pool.manifest.get("services", {})
            for row in services.values():
                log = archive_server_log(
                    self.case_session_dir, Path(str(row["log"])), str(row["instance_id"]),
                    server_name=str(row["name"]),
                )
                row["log_artifact"] = log
                row["stopped_at"] = result.get("stopped_at", _iso(time.time()))
                row["stopped_at_epoch"] = result.get("stopped_at_epoch", time.time())
            records.append({
                "pool_id": key,
                "tests": sorted(set(pool.plan.tests) & completed),
                "scheduled_tests": list(pool.plan.tests), "services": services,
                "result": result,
            })
        self._link_case_records(records)
        _write(self.session_dir / "topology.json", {
            "generated_at": _iso(time.time()), "pools": records,
        })
        return records

    def _link_case_records(self, records: Sequence[Mapping[str, object]]) -> None:
        links = {}
        for pool in records:
            services = list(pool.get("services", {}).values())
            for nodeid in pool.get("tests", []):
                links.setdefault(str(nodeid), []).extend(services)
        for path in (self.case_session_dir / "cases").glob("*.json"):
            try:
                record = json.loads(path.read_text())
            except (OSError, ValueError, TypeError):
                continue
            shared = links.get(str(record.get("nodeid", "")), [])
            if not shared:
                continue
            record["server_instances"] = shared
            for attempt in record.get("attempts", []):
                existing = {row.get("instance_id"): row for row in attempt.get("servers", [])}
                for row in shared:
                    existing[row.get("instance_id")] = row
                attempt["servers"] = list(existing.values())
            _write(path, record)


def merge_worker_topologies(session_dir: Path) -> list[dict]:
    """Merge worker-local pool records into the controller's session archive."""
    root = Path(session_dir)
    paths = [root / "topology.json", *sorted((root / "workers").glob("*/topology.json"))]
    pools = []
    for path in paths:
        try:
            payload = json.loads(path.read_text())
        except (OSError, ValueError, TypeError):
            continue
        if isinstance(payload, dict) and isinstance(payload.get("pools"), list):
            pools.extend(payload["pools"])
    unique = {
        str(row.get("pool_id", "")): row for row in pools
        if isinstance(row, dict) and row.get("pool_id")
    }
    merged = [unique[key] for key in sorted(unique)]
    _write(root / "topology.json", {
        "generated_at": _iso(time.time()), "pools": merged,
    })
    return merged
