"""Resource control, observation, and teardown behavior for CaseManager."""

from __future__ import annotations

import contextlib
import dataclasses
import os
import resource
import shutil
import time
from itertools import chain
from pathlib import Path
from typing import Mapping, Optional, Sequence

from brixtest.archive import archive_case_logs
from brixtest.clients.configured import ConfiguredClient
from brixtest.design import Binary, Client
from brixtest.errors import CaseRunError, SpecError
from brixtest.runtime.api import Run, Service
from brixtest.runtime.case_summary import finalize_evidence
from brixtest.runtime.commands import CommandResult
from brixtest.runtime.filesystem import NativeFilesystem, ServiceFilesystem
from brixtest.runtime.filesystem_remote import RemoteFilesystem
from brixtest.runtime.launchers import ServerLaunchContext
from brixtest.runtime.topology import owned_servers


class CaseManagerOperationsMixin:
    @staticmethod
    def _client_image(declaration: Client) -> str:
        if declaration.placement.image:
            return declaration.placement.image
        images = {
            item.image for item in chain(declaration.binaries, declaration.command)
            if isinstance(item, Binary) and item.image
        }
        return next(iter(images)) if len(images) == 1 else ""

    def _observe_client(
        self, name: str, elapsed: float, returncode: Optional[int], error: str
    ) -> None:
        labels = {"client": name}
        self.metrics.count("client.calls", labels=labels)
        self.metrics.observe("client.duration", elapsed, unit="s", labels=labels)
        if returncode is not None:
            self.metrics.gauge("client.returncode", returncode, labels=labels)
        if error:
            self.metrics.count(
                "client.errors", labels={"client": name, "error": error.lower()}
            )

    def _observe_tool_result(self, name: str, result: CommandResult) -> None:
        """Publish one completed tool invocation to trusted helper plugins."""
        if self._pytest_hook is None:
            return
        declaration = next(
            (item for item in self.definition.clients if item.name == name), name,
        )
        self._pytest_hook.pytest_brixtest_tool_result(
            run=Run(self), tool=declaration, result=result,
        )

    def _set_pytest_hook(self, hook: object) -> None:
        self._pytest_hook = hook

    def _observe_command(
        self, elapsed: float, returncode: Optional[int], error: str,
    ) -> None:
        self.metrics.count("command.calls")
        self.metrics.observe("command.duration", elapsed, unit="s")
        if returncode is not None:
            self.metrics.gauge("command.returncode", returncode)
        if error:
            self.metrics.count("command.errors", labels={"error": error.lower()})


    def _finalize_metrics(self) -> None:
        if self._metrics_finalized:
            return
        self._metrics_finalized = True
        self.metrics.gauge(
            "case.wall_time", time.time() - self._started_at, unit="s"
        )
        self.metrics.gauge(
            "process.cpu_time", time.process_time() - self._started_cpu, unit="s"
        )
        usage = resource.getrusage(resource.RUSAGE_SELF)
        self.metrics.gauge("process.max_rss", usage.ru_maxrss, unit="KiB")
        self.metrics.tag("outcome", self._outcome)

    def service(self, name: str) -> Service:
        """Resolve one running service by declaration name."""
        try:
            return self._services[name]
        except KeyError:
            raise SpecError("server", name, "known: %s" % ", ".join(sorted(self._services))) from None

    def _service_signal(self, name: str, signal_name: str) -> None:
        """Route an explicit signal through the owning backend."""
        if self._backend is not None:
            plan = self._server_launch_plans.get(name)
            if plan is not None and plan.launcher in ("docker", "podman"):
                self.commands.run(
                    plan.launcher, "kill", "--signal", signal_name,
                    str(plan.metadata.get("container_name", "")),
                    timeout=10.0,
                )
            else:
                self._backend.signal(name, signal_name)
            self.metrics.count(
                "server.signals", labels={"server": name, "signal": signal_name},
            )
            return
        kubernetes = getattr(self, "_kubernetes", None)
        if kubernetes is not None:
            kubernetes.signal(name, signal_name)
            self.metrics.count(
                "server.signals", labels={"server": name, "signal": signal_name},
            )
            return
        raise SpecError("server control", name, "backend does not expose signal control")

    def _service_wait(self, name: str, timeout: Optional[float]) -> Optional[int]:
        """Wait for a local supervised server without blocking indefinitely."""
        if timeout is not None and (
            isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0
        ):
            raise SpecError("server wait timeout", timeout, "must be a number >= 0 or None")
        if self._backend is None:
            raise SpecError(
                "server wait", name,
                "process exit waiting is available for process, Docker, and Podman servers",
            )
        return self._backend.wait(name, timeout)

    def _service_read_log(
        self, name: str, *, encoding: str = "utf-8", errors: str = "replace",
    ) -> str:
        """Read current output through the owning backend before final archival."""
        kubernetes = getattr(self, "_kubernetes", None)
        if kubernetes is not None:
            return kubernetes.read_log(name)
        return self.service(name).log.read_text(encoding=encoding, errors=errors)

    def _service_restart(self, name: str) -> Service:
        """Restart one server through its original immutable launch plan."""
        if self._backend is not None:
            spec = self.registry.get_spec(name)
            declaration = next(
                item for item in owned_servers(self.definition) if item.name == name
            )
            self._backend.stop(name)
            launcher = self._server_launchers.get(name)
            plan = self._server_launch_plans.get(name)
            if launcher is not None and plan is not None:
                launcher.cleanup(
                    ServerLaunchContext(self.nodeid, self.root, self.workspace), plan,
                )
            with self.metrics.timer("server.restart", labels={"server": name}):
                endpoint = self._backend.start(spec)
            service = self._service(endpoint, declaration)
            self._services[name] = service
            return service
        kubernetes = getattr(self, "_kubernetes", None)
        if kubernetes is not None:
            with self.metrics.timer("server.restart", labels={"server": name}):
                kubernetes.restart(name)
            service = dataclasses.replace(
                self.service(name), replicas=kubernetes.refreshed_replicas(name),
            )
            object.__setattr__(service, "_controller", self)
            self._services[name] = service
            return service
        raise SpecError("server restart", name, "backend does not expose restart control")

    def _service_command(
        self, name: str, argv: Sequence[object], *, timeout: float,
        check: bool,
    ) -> CommandResult:
        """Run one shell-free diagnostic command in the server environment."""
        service = self.service(name)
        if not argv:
            raise SpecError("server command", argv, "needs at least one argv item")
        plan = self._server_launch_plans.get(name)
        if plan is not None and plan.launcher in ("docker", "podman"):
            container_name = str(plan.metadata.get("container_name", ""))
            command = (plan.launcher, "exec", container_name, *argv)
            return self.commands.run(
                *command, timeout=timeout, check=check, cwd=self.workspace,
            )
        kubernetes = getattr(self, "_kubernetes", None)
        if kubernetes is not None:
            target = kubernetes._server_target(name)
            command = (*kubernetes.command_prefix(target.context), "-n", target.namespace,
                       "exec", kubernetes._workload_resource(name),
                       "-c", kubernetes._container_name(name), "--", *argv)
            return self.commands.run(
                *command, timeout=timeout, check=check, cwd=self.workspace,
            )
        spec = self.registry.get_spec(name)
        return self.commands.run(
            *argv, timeout=timeout, check=check, cwd=service.workdir,
            env=dict(spec.env),
        )

    def _service_filesystem(self, name: str) -> ServiceFilesystem:
        """Return a cached confined filesystem facade for any service backend."""
        held = self._filesystems.get(name)
        if held is not None:
            return held
        service = self.service(name)
        kubernetes = getattr(self, "_kubernetes", None)
        if kubernetes is not None:
            transport = self._kubernetes_filesystem(name, service, kubernetes)
            return self._cache_filesystem(name, transport)
        roots = (
            service.workdir,
            *(Path(value) for value in service.metadata.get("filesystem_roots", ())),
        )
        transport = NativeFilesystem(
            roots, observer=lambda operation, payload: self._observe_filesystem(
                name, operation, payload,
            ),
        )
        return self._cache_filesystem(name, transport)

    def _kubernetes_filesystem(self, name, service, kubernetes) -> RemoteFilesystem:
        roots = service.metadata.get("filesystem_roots", ())
        target = kubernetes._server_target(name)
        command = (
            *kubernetes.command_prefix(target.context), "-n", target.namespace,
            "exec", "-i", kubernetes._workload_resource(name),
            "-c", "brixtest-filesystem", "--",
        )
        return RemoteFilesystem(
            command, tuple(str(value) for value in roots),
            observer=lambda operation, payload: self._observe_filesystem(
                name, operation, payload,
            ),
        )

    def _cache_filesystem(self, name: str, transport: object) -> ServiceFilesystem:
        facade = ServiceFilesystem(transport)
        self._filesystems[name] = facade
        return facade

    def _observe_filesystem(
        self, server: str, operation: str, payload: Mapping[str, object],
    ) -> None:
        self.metrics.count(
            "server.filesystem.operations",
            labels={"server": server, "operation": operation},
        )
        self.evidence.event("filesystem-operation", {
            "server": server, **dict(payload),
        })

    def client(self, name: str) -> ConfiguredClient:
        """Resolve one configured client by declaration name."""
        try:
            return self._clients[name]
        except KeyError:
            raise SpecError("client", name, "known: %s" % ", ".join(sorted(self._clients))) from None

    def set_outcome(self, outcome: str) -> None:
        """Record the test outcome that will be written during finalization."""
        self._outcome = outcome

    def close(self) -> None:
        """Stop resources, finalize evidence, and apply the retention policy."""
        errors = []
        self._capture_teardown(
            lambda: self._managed.run_phase("finalize"), errors,
        )
        self.evidence.close_collectors()
        self._teardown_runtime_resources(errors)
        self._capture_teardown(self.security.close, errors)
        if errors:
            self._outcome = "teardown-failed"
        self._ports.close()
        self._finalize_metrics()
        evidence_error = finalize_evidence(self)
        if evidence_error:
            errors.append(evidence_error)
        error = "; ".join(errors)
        self._write_summary(error=error)
        self._archive_case_logs()
        self._apply_retention()
        if error:
            raise CaseRunError(self.nodeid, "teardown", error)

    def _teardown_runtime_resources(self, errors: list[str]) -> None:
        kubernetes = getattr(self, "_kubernetes", None)
        if kubernetes is None:
            self._capture_teardown(self._stop_case_backend, errors)
            self._capture_teardown(self._collect_case_backend, errors)
            self._capture_teardown(self._close_providers, errors)
            return
        self._capture_teardown(kubernetes.quiesce, errors)
        self._capture_teardown(self._close_providers, errors)
        self._capture_teardown(self._stop_case_backend, errors)
        self._capture_teardown(self._collect_case_backend, errors)

    @staticmethod
    def _capture_teardown(action, errors: list[str]) -> None:
        try:
            action()
        except Exception as exc:
            errors.append(str(exc))

    def _stop_case_backend(self) -> None:
        self._case_backend.stop(self.backend_context)

    def _collect_case_backend(self) -> None:
        collected = self._case_backend.collect(self.backend_context)
        if not isinstance(collected, Mapping):
            raise SpecError(
                "case backend collect", type(collected).__name__, "must return a mapping",
            )
        if collected:
            self.evidence.attach_json(
                "backend-result.json", collected, role="backend-result",
                description="case backend collection result",
            )

    def _close_providers(self) -> None:
        errors = self._providers.close()
        if errors:
            raise RuntimeError("; ".join(errors))

    def _archive_case_logs(self) -> None:
        session = os.environ.get("BRIXTEST_METRICS_SESSION")
        if session and os.environ.get("BRIXTEST_SHARED_POOL_OWNER") != "1":
            archive_case_logs(Path(session), self.nodeid, self.root)

    def _apply_retention(self) -> None:
        remove = self.definition.keep == "never"
        remove = remove or (self.definition.keep == "failed" and self._outcome == "passed")
        if remove:
            shutil.rmtree(self.root, ignore_errors=True)

    def _stop_started(self) -> None:
        if self._backend is None:
            return
        errors = []
        for name in reversed(self._started):
            self._stop_server(name, errors)
        self._started.clear()
        if errors:
            raise RuntimeError("; ".join(errors))

    def _stop_server(self, name: str, errors: list[str]) -> None:
        self._stop_backend_server(name, errors)
        self._cleanup_server_launcher(name, errors)
        declaration = self._server_declaration(name)
        if declaration is not None:
            self._apply_log_policy(self._backend.logs(name), declaration.logs)

    def _stop_backend_server(self, name: str, errors: list[str]) -> None:
        try:
            self._backend.stop(name)
        except Exception as exc:
            errors.append("%s: %s" % (name, exc))

    def _cleanup_server_launcher(self, name: str, errors: list[str]) -> None:
        launcher = self._server_launchers.get(name)
        plan = self._server_launch_plans.get(name)
        if launcher is None or plan is None:
            return
        try:
            launcher.cleanup(
                ServerLaunchContext(self.nodeid, self.root, self.workspace), plan,
            )
        except Exception as exc:
            errors.append("%s launcher: %s" % (name, exc))

    def _server_declaration(self, name: str):
        return next(
            (item for item in self.definition.servers if item.name == name), None
        )

    @staticmethod
    def _apply_log_policy(path: Path, policy: object) -> None:
        """Apply the resource's bounded/redacted archival policy in-place."""
        if not getattr(policy, "capture", True):
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
            return
        try:
            payload = path.read_bytes()
        except OSError:
            return
        text = payload.decode("utf-8", errors="replace")
        for secret in getattr(policy, "redact", ()):
            text = text.replace(secret, "[REDACTED]")
        payload = text.encode("utf-8")
        limit = int(getattr(policy, "max_bytes", len(payload) or 1))
        if len(payload) > limit:
            marker = b"[brixtest: earlier log bytes omitted]\n"
            tail = max(0, limit - len(marker))
            payload = marker[:limit] + (payload[-tail:] if tail else b"")
        path.write_bytes(payload)
