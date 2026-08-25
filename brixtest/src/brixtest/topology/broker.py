"""Authenticated controller-owned topology broker for pytest-xdist workers."""

from __future__ import annotations

import copyreg
import ctypes
import hashlib
import multiprocessing
import os
import pickle
import secrets
import signal
import threading
import tempfile
import time
import traceback
from multiprocessing.connection import Client, Listener
from multiprocessing import AuthenticationError
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Optional, Sequence

from brixtest.errors import CaseRunError, SpecError
from brixtest.topology.controller import SharedTopology

_MAX_MESSAGE = 64 << 20
_SHARED_SCOPES = ("class", "module", "package", "session")


def _reduce_mapping_proxy(value):
    return dict, (dict(value),)


copyreg.pickle(MappingProxyType, _reduce_mapping_proxy)


def _message(value: object) -> bytes:
    payload = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
    if len(payload) > _MAX_MESSAGE:
        raise SpecError("topology broker message", len(payload), "exceeds the 64 MiB limit")
    return payload


def _receive(connection) -> object:
    return pickle.loads(connection.recv_bytes(_MAX_MESSAGE))


def _response(connection, value: object) -> None:
    connection.send_bytes(_message(value))


def _parent_death_signal() -> None:
    if not sys_platform_linux():
        return
    signal.signal(signal.SIGTERM, _terminate_on_parent_death)
    with _ignored_os_error():
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(1, signal.SIGTERM, 0, 0, 0)


def _terminate_on_parent_death(signum, frame) -> None:
    raise SystemExit("topology controller exited")


def sys_platform_linux() -> bool:
    import sys

    return sys.platform.startswith("linux")


class _ignored_os_error:
    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace) -> bool:
        return kind is not None and issubclass(kind, OSError)


class _BrokerState:
    def __init__(self, session_dir: Path) -> None:
        self.session_dir = Path(session_dir)
        self.rows: dict[str, object] = {}
        self.registrations: set[str] = set()
        self.expected_workers = 0
        self.shared: Optional[SharedTopology] = None
        self.workers: dict[str, SharedTopology] = {}
        self.closed = False

    def register(self, worker: str, expected: int, rows) -> dict:
        if self.shared is not None:
            raise SpecError("topology broker", worker, "cannot register after execution begins")
        if not worker or expected < 1:
            raise SpecError("topology broker registration", worker, "has invalid worker identity")
        self.expected_workers = max(self.expected_workers, expected)
        for nodeid, definition in rows:
            previous = self.rows.get(nodeid)
            if previous is not None and previous != definition:
                raise SpecError(
                    "topology broker collection", nodeid,
                    "workers produced different BriXTest declarations",
                )
            self.rows[nodeid] = definition
        self.registrations.add(worker)
        return {
            "workers": len(self.registrations), "expected": self.expected_workers,
            "tests": len(self.rows),
        }

    def _ready(self) -> None:
        if len(self.registrations) < self.expected_workers:
            raise SpecError(
                "topology broker collection", sorted(self.registrations),
                "not every xdist worker published its plan before execution",
            )

    def _shared(self) -> SharedTopology:
        self._ready()
        if self.shared is None:
            directory = self.session_dir / "topology-broker" / "shared"
            self.shared = SharedTopology.build(
                sorted(self.rows.items()), directory,
                case_session_dir=self.session_dir, scopes=_SHARED_SCOPES,
            )
        return self.shared

    def _worker(self, worker: str) -> SharedTopology:
        selected = self.workers.get(worker)
        if selected is None:
            directory = self.session_dir / "topology-broker" / "workers" / worker
            selected = SharedTopology.build(
                sorted(self.rows.items()), directory,
                case_session_dir=self.session_dir, scopes=("worker",),
                namespace=worker,
            )
            self.workers[worker] = selected
        return selected

    def resolve(self, worker: str, nodeid: str) -> dict:
        shared = self._shared().for_test(nodeid)
        local = self._worker(worker).for_test(nodeid)
        services = {**shared.get("services", {}), **local.get("services", {})}
        return {"services": services}

    def finished(self, worker: str, nodeid: str) -> None:
        self._shared().finished(nodeid)
        self._worker(worker).finished(nodeid)

    def close(self) -> list[dict]:
        if self.closed:
            return []
        self.closed = True
        records = []
        failures = []
        if self.shared is not None:
            _close_topology(self.shared, records, failures)
        for topology in self.workers.values():
            _close_topology(topology, records, failures)
        _write_merged_topology(self.session_dir, records)
        if failures:
            raise CaseRunError(
                "@topology", "close", "\n\n".join(failures),
            )
        return records


def _close_topology(topology, records: list, failures: list[str]) -> None:
    try:
        records.extend(topology.close())
    except Exception:
        failures.append(traceback.format_exc())


def _write_merged_topology(session_dir: Path, records: Sequence[Mapping[str, object]]) -> None:
    from brixtest.topology.controller import _iso, _write

    _write(Path(session_dir) / "topology.json", {
        "generated_at": _iso(time.time()), "pools": list(records),
    })


def _dispatch(state: _BrokerState, request: object) -> tuple[object, bool]:
    if not isinstance(request, Mapping):
        raise SpecError("topology broker request", request, "must be a mapping")
    operation = request.get("operation")
    if operation == "ping":
        return {"pid": os.getpid()}, False
    if operation == "register":
        return state.register(
            str(request.get("worker", "")), int(request.get("expected", 0)),
            request.get("rows", ()),
        ), False
    if operation == "resolve":
        return state.resolve(
            str(request.get("worker", "")), str(request.get("nodeid", "")),
        ), False
    if operation == "finished":
        state.finished(str(request.get("worker", "")), str(request.get("nodeid", "")))
        return {}, False
    if operation == "close":
        return state.close(), True
    raise SpecError("topology broker operation", operation, "is not supported")


def _serve(address: str, token: bytes, session_dir: Path, parent_pid: int) -> None:
    _parent_death_signal()
    listener = Listener(address, family="AF_UNIX", authkey=token)
    state = _BrokerState(session_dir)
    try:
        closed = False
        while not closed:
            try:
                connection = listener.accept()
            except AuthenticationError:
                continue
            try:
                request = _receive(connection)
                result, closed = _dispatch(state, request)
                _response(connection, {"ok": True, "result": result})
            except BaseException as exc:
                _response(connection, {
                    "ok": False, "error": "%s: %s" % (type(exc).__name__, exc),
                    "traceback": traceback.format_exc(),
                })
            finally:
                connection.close()
            if os.getppid() != parent_pid:
                break
    finally:
        listener.close()
        if not state.closed:
            state.close()


def _rpc(
    address: str, token: str, request: Mapping[str, object], timeout: float,
) -> object:
    result: dict[str, object] = {}

    def invoke() -> None:
        try:
            connection = Client(address, family="AF_UNIX", authkey=bytes.fromhex(token))
            try:
                response = _receive_after_send(connection, request)
            finally:
                connection.close()
            result["response"] = response
        except BaseException as exc:
            result["error"] = exc

    worker = threading.Thread(target=invoke, name="brixtest-topology-rpc", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise CaseRunError("@topology", "broker", "request timed out after %.1fs" % timeout)
    if "error" in result:
        raise CaseRunError("@topology", "broker", str(result["error"]))
    response = result.get("response", {})
    if not isinstance(response, Mapping) or response.get("ok") is not True:
        detail = response.get("traceback", response.get("error", "invalid response")) \
            if isinstance(response, Mapping) else "invalid response"
        raise CaseRunError("@topology", "broker", str(detail))
    return response.get("result")


def _receive_after_send(connection, request: Mapping[str, object]) -> object:
    connection.send_bytes(_message(request))
    return _receive(connection)


class RemoteTopology:
    """Worker facade for the controller's authenticated topology broker."""

    def __init__(self, address: str, token: str, worker: str) -> None:
        self.address, self.token, self.worker = address, token, worker

    def register(self, rows, expected: int) -> None:
        _rpc(self.address, self.token, {
            "operation": "register", "worker": self.worker,
            "expected": expected, "rows": rows,
        }, 30.0)

    def for_test(self, nodeid: str) -> dict:
        value = _rpc(self.address, self.token, {
            "operation": "resolve", "worker": self.worker, "nodeid": nodeid,
        }, 330.0)
        return dict(value) if isinstance(value, Mapping) else {}

    def finished(self, nodeid: str) -> None:
        _rpc(self.address, self.token, {
            "operation": "finished", "worker": self.worker, "nodeid": nodeid,
        }, 30.0)


class TopologyBroker:
    """Controller lifecycle for the broker process and all shared resources."""

    def __init__(self, session_dir: Path) -> None:
        self.session_dir = Path(session_dir)
        address_id = hashlib.sha256(str(self.session_dir).encode()).hexdigest()[:24]
        self.address = str(
            Path(tempfile.gettempdir()) / ("brixtest-topology-%s.sock" % address_id)
        )
        self.token = secrets.token_hex(32)
        self.process = None
        self.closed = False
        self.records: list[dict] = []

    def start(self) -> None:
        if self.process is not None:
            return
        self.session_dir.mkdir(parents=True, exist_ok=True)
        context = multiprocessing.get_context("spawn")
        self.process = context.Process(
            target=_serve,
            args=(self.address, bytes.fromhex(self.token), self.session_dir, os.getpid()),
            name="brixtest-topology-broker", daemon=False,
        )
        self.process.start()
        self._await_ready()

    def _await_ready(self) -> None:
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if self.process is None or not self.process.is_alive():
                raise CaseRunError("@topology", "broker", "controller broker exited")
            if Path(self.address).exists():
                try:
                    _rpc(self.address, self.token, {"operation": "ping"}, 2.0)
                    return
                except CaseRunError:
                    pass
            time.sleep(0.05)
        self._terminate()
        raise CaseRunError("@topology", "broker", "startup timed out")

    def worker_settings(self, worker: str, expected: int) -> Mapping[str, object]:
        self.start()
        return {
            "address": self.address, "token": self.token,
            "worker": worker, "expected": expected,
        }

    def close(self) -> list[dict]:
        if self.closed:
            return list(self.records)
        self.closed = True
        try:
            if self.process is not None and self.process.is_alive():
                value = _rpc(self.address, self.token, {"operation": "close"}, 120.0)
                self.records = list(value) if isinstance(value, list) else []
        finally:
            self._terminate()
        return list(self.records)

    def _terminate(self) -> None:
        if self.process is None:
            return
        self.process.join(timeout=3.0)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=3.0)
        Path(self.address).unlink(missing_ok=True)


__all__ = ["RemoteTopology", "TopologyBroker"]
