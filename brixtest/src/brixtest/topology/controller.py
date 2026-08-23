"""Supervise collection-derived session servers outside test helpers."""

from __future__ import annotations

import contextlib
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
    temporary.replace(path)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _health_error(manager) -> str:
    backend = getattr(manager, "_backend", None)
    local_error = _local_health_error(manager, backend)
    if local_error:
        return local_error
    kubernetes = getattr(manager, "_kubernetes", None)
    return _kubernetes_health_error(kubernetes)


def _local_health_error(manager, backend) -> str:
    if backend is None:
        return ""
    for name in manager._started:
        process = backend._procs.get(name)
        if process is not None and process.poll() is not None:
            return "server %s exited unexpectedly with status %s" % (
                name, process.returncode,
            )
    return ""


def _kubernetes_health_error(kubernetes) -> str:
    if kubernetes is None:
        return ""
    for name, process in kubernetes._forwards.items():
        if process.poll() is not None:
            return "server %s Kubernetes port-forward exited unexpectedly" % name
    return ""


def _service_records(plan: PoolPlan, manager, run, started: float) -> dict:
    observed = {
        str(row.get("name", "")): row
        for row in manager.evidence.snapshot().get("servers", [])
    }
    return {
        server.name: _service_record(plan, server, run.server(server.name), observed, started)
        for server in plan.definition.servers
    }


def _service_record(plan, server, service, observed, started: float) -> dict:
    metadata = observed.get(server.name, {})
    return {
        "instance_id": instance_id(plan.key, server.name), "pool_id": plan.key,
        "name": server.name, "scope": plan.scope, "host": service.host,
        "ports": dict(service.ports), "config": str(service.config),
        "config_filename": metadata.get(
            "config_filename", service.config_filename or service.config.name,
        ),
        "config_sha256": metadata.get("config_sha256", service.config_sha256),
        "config_source_sha256": metadata.get(
            "config_source_sha256", service.config_source_sha256,
        ),
        "config_declared_sha256": metadata.get(
            "config_declared_sha256", service.config_declared_sha256,
        ),
        "config_artifact": metadata.get("config_artifact", {}),
        "configs": {name: str(path) for name, path in service.configs.items()},
        "schemes": dict(service.schemes), "protocols": dict(service.protocols),
        "metadata": dict(service.metadata), "log": str(service.log),
        "workdir": str(service.workdir), "started_at": _iso(started),
        "started_at_epoch": started,
    }


def _monitor(manager, plan: PoolPlan, control: Path, parent_pid: int) -> None:
    while not (control / "stop").exists():
        try:
            os.kill(parent_pid, 0)
        except OSError:
            return
        health_error = _health_error(manager)
        if health_error:
            raise CaseRunError("@shared/%s" % plan.key, "monitor", health_error)
        time.sleep(0.1)


def _result_payload(manager, started: float) -> dict:
    stopped = time.time()
    return {
        "outcome": "passed", "started_at": _iso(started), "started_at_epoch": started,
        "stopped_at": _iso(stopped), "stopped_at_epoch": stopped,
        "metrics": manager.metrics.snapshot(), "evidence": manager.evidence.snapshot(),
    }


def _failure_payload(manager, exc: BaseException, started: float) -> dict:
    stopped = time.time()
    failure = {
        "outcome": "failed", "error": "%s: %s" % (type(exc).__name__, exc),
        "traceback": traceback.format_exc(), "started_at": _iso(started),
        "started_at_epoch": started, "stopped_at": _iso(stopped),
        "stopped_at_epoch": stopped,
    }
    if manager is not None:
        failure.update({
            "metrics": manager.metrics.snapshot(), "evidence": manager.evidence.snapshot(),
        })
    return failure


def _close_failed_manager(manager) -> None:
    if manager is None:
        return
    try:
        manager.set_outcome("failed")
        manager.close()
    except Exception:
        return


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
        services = _service_records(plan, manager, run, started)
        _write(control / "ready.json", {"pool_id": plan.key, "services": services})
        _monitor(manager, plan, control, parent_pid)
        manager.set_outcome("passed")
        manager.close()
        _write(control / "result.json", _result_payload(manager, started))
    except BaseException as exc:
        _close_failed_manager(manager)
        _write(control / "error.json", _failure_payload(manager, exc, started))


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
        self._validate_plan()
        self.control.mkdir(parents=True, exist_ok=True)
        context = self._spawn_context()
        self.process = self._new_process(context)
        self.process.start()
        self._await_ready()

    def _validate_plan(self) -> None:
        actual = pool_key(self.plan.definition, self.plan.scope, self.plan.domain)
        if actual != self.plan.key:
            raise SpecError(
                "shared topology", self.plan.key,
                "a server declaration or config changed after collection",
            )

    def _spawn_context(self):
        try:
            return multiprocessing.get_context("spawn")
        except ValueError as exc:
            raise SpecError(
                "shared topology", self.plan.key,
                "requires a spawn multiprocessing context",
            ) from exc

    def _new_process(self, context):
        return context.Process(
            target=_serve,
            args=(self.plan, self.root, self.control.parent.parent.parent,
                  self.control, os.getpid()),
            name="brixtest-shared-%s" % self.plan.key, daemon=True,
        )

    def _await_ready(self) -> None:
        deadline = time.monotonic() + max(30.0, min(300.0, self.plan.definition.timeout))
        ready = self.control / "ready.json"
        error = self.control / "error.json"
        while time.monotonic() < deadline:
            if ready.is_file():
                self.manifest = json.loads(ready.read_text())
                return
            if error.is_file() or not self.process.is_alive():
                raise self._startup_error(error)
            time.sleep(0.05)
        self.stop(force=True)
        raise CaseRunError("@shared/%s" % self.plan.key, "setup", "startup timed out")

    def _startup_error(self, error: Path) -> CaseRunError:
        detail = json.loads(error.read_text()) if error.is_file() else {}
        message = detail.get("traceback", detail.get("error", "supervisor exited"))
        return CaseRunError("@shared/%s" % self.plan.key, "setup", str(message))

    def stop(self, *, force: bool = False) -> dict:
        if self.stopped:
            return dict(self.result)
        if self.process is None:
            self.stopped = True
            return {}
        (self.control / "stop").touch()
        self._stop_process(force)
        result = self._read_result()
        self.result = result
        self.stopped = True
        return dict(result)

    def _stop_process(self, force: bool) -> None:
        self.process.join(timeout=0.5 if force else 15.0)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=2.0)
        if self.process.is_alive() and self.process.pid:
            os.kill(self.process.pid, signal.SIGKILL)
            self.process.join(timeout=1.0)

    def _read_result(self) -> dict:
        result_path = self.control / "result.json"
        error_path = self.control / "error.json"
        result = json.loads(result_path.read_text()) if result_path.is_file() else {}
        if error_path.is_file():
            result.update(json.loads(error_path.read_text()))
        return result

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
        self.case_session_dir = _case_session_path(case_session_dir, session_dir)
        self.pools = {plan.key: _Pool(plan, session_dir) for plan in plans}
        self._item_keys = _item_pool_keys(plans)
        self._remaining = _remaining_tests(plans)
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
            with contextlib.suppress(OSError, ValueError, TypeError):
                completed.add(str(json.loads(path.read_text()).get("nodeid", "")))
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
        links = _server_links(records)
        for path in (self.case_session_dir / "cases").glob("*.json"):
            _link_case_path(path, links)


def _case_session_path(selected: Optional[Path], fallback: Path) -> Path:
    return Path(fallback) if selected is None else Path(selected)


def _item_pool_keys(plans: Sequence[PoolPlan]) -> dict[str, tuple[str, ...]]:
    nodeids = {nodeid for plan in plans for nodeid in plan.tests}
    return {
        nodeid: tuple(plan.key for plan in plans if nodeid in plan.tests)
        for nodeid in nodeids
    }


def _remaining_tests(plans: Sequence[PoolPlan]) -> dict[str, set[str]]:
    return {plan.key: set(plan.tests) for plan in plans}


def _server_links(records: Sequence[Mapping[str, object]]) -> dict[str, list]:
    links = {}
    for pool in records:
        services = list(pool.get("services", {}).values())
        for nodeid in pool.get("tests", []):
            links.setdefault(str(nodeid), []).extend(services)
    return links


def _link_case_path(path: Path, links: Mapping[str, list]) -> None:
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        return
    shared = links.get(str(record.get("nodeid", "")), [])
    if not shared:
        return
    record["server_instances"] = shared
    for attempt in record.get("attempts", []):
        _merge_attempt_servers(attempt, shared)
    _write(path, record)


def _merge_attempt_servers(attempt: dict, shared: Sequence[object]) -> None:
    existing = {row.get("instance_id"): row for row in attempt.get("servers", [])}
    for row in shared:
        existing[row.get("instance_id")] = row
    attempt["servers"] = list(existing.values())


def merge_worker_topologies(session_dir: Path) -> list[dict]:
    """Merge worker-local pool records into the controller's session archive."""
    root = Path(session_dir)
    paths = [root / "topology.json", *sorted((root / "workers").glob("*/topology.json"))]
    pools = []
    for path in paths:
        pools.extend(_topology_pools(path))
    unique = _unique_pools(pools)
    merged = [unique[key] for key in sorted(unique)]
    _write(root / "topology.json", {
        "generated_at": _iso(time.time()), "pools": merged,
    })
    return merged


def _topology_pools(path: Path) -> list:
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        return []
    if not isinstance(payload, dict):
        return []
    pools = payload.get("pools")
    return pools if isinstance(pools, list) else []


def _unique_pools(pools: Sequence[object]) -> dict[str, dict]:
    return {
        str(row["pool_id"]): row
        for row in pools
        if isinstance(row, dict) and row.get("pool_id")
    }
