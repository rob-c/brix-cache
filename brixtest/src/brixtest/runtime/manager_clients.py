"""Configured-client preparation for managed BriXTest cases."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence

from brixtest.clients.configured import ClientSpec, ConfiguredClient, ConfiguredTool
from brixtest.design import Binary, Tool
from brixtest.runtime.executors import ToolExecutionContext, tool_executor


def _client_command_part(manager, value: object, containerized: bool) -> str:
    if containerized and isinstance(value, Binary) and value.image_path:
        return str(value.image_path)
    if isinstance(value, Binary):
        return str(manager.binary_store.get(value.name).path)
    return str(value)


def _mount_environment(mounts: Mapping[str, object]) -> Dict[str, str]:
    return {
        key.upper(): str(path) for key, path in mounts.items()
        if not key.rpartition("_")[2].isdigit()
    }


def _apply_library_path(env: Dict[str, object], libraries: Sequence[str]) -> None:
    if not libraries:
        return
    inherited = os.environ.get("LD_LIBRARY_PATH", "")
    suffix = [inherited] if inherited else []
    env["LD_LIBRARY_PATH"] = ":".join([*libraries, *suffix])


def _apply_binary_path(env: Dict[str, object], binary_dirs: Sequence[str]) -> None:
    if not binary_dirs:
        return
    inherited = env.get("PATH", os.environ.get("PATH", ""))
    suffix = [inherited] if inherited else []
    env["PATH"] = os.pathsep.join([*binary_dirs, *suffix])


def _configured_type(declaration):
    return ConfiguredTool if isinstance(declaration, Tool) else ConfiguredClient


class CaseManagerClientsMixin:
    """Build local or remote configured-client facades from declarations."""

    def _client_executor(self, declaration):
        backend = declaration.placement.backend
        name = "local" if backend == "inherit" else backend
        executor = tool_executor(name)
        executor.validate(declaration)
        kubernetes = getattr(self, "_kubernetes", None)
        metadata = self._client_executor_metadata(name, kubernetes, declaration)
        return name, executor, kubernetes, metadata

    @staticmethod
    def _client_executor_metadata(name: str, kubernetes, declaration) -> Mapping:
        if name == "kubernetes" and kubernetes is not None:
            return kubernetes.client_metadata(declaration)
        return {}

    def _client_mount_values(
        self, declaration, remote: bool, metadata: Mapping[str, object],
    ) -> Mapping[str, object]:
        if remote:
            return dict(metadata.get("mount_values", {}))
        return self._project_mounts("client-%s" % declaration.name, declaration.mounts)

    def _client_command(self, declaration, containerized: bool) -> tuple[str, ...]:
        return tuple(
            _client_command_part(self, value, containerized)
            for value in declaration.command
        )

    def _client_security_environment(self, remote: bool) -> Mapping[str, str]:
        if remote:
            return self.security.environment(
                "client", credential_base=Path("/brixtest/secure/credentials"),
                auth_base=Path("/brixtest/secure/auth"),
            )
        return self.security.environment("client")

    @staticmethod
    def _remove_remote_secrets(
        env: Dict[str, object], metadata: Mapping[str, object],
    ) -> None:
        for secret_name in metadata.get("secret_environment", {}):
            env.pop(str(secret_name), None)

    def _client_environment(
        self, declaration, mounts, remote: bool, metadata,
        libraries: Sequence[str], binary_dirs: Sequence[str],
    ) -> Dict[str, object]:
        from brixtest.runtime.manager import _environment

        env = dict(declaration.env)
        env.update(self._client_security_environment(remote))
        env.update(_mount_environment(mounts))
        env.update(_environment("BRIXTEST_CLIENT_ENV_JSON"))
        if remote:
            self._remove_remote_secrets(env, metadata)
            return env
        _apply_library_path(env, libraries)
        _apply_binary_path(env, binary_dirs)
        return env

    def _client_workdir(self, declaration, remote: bool) -> Path:
        if remote:
            workspace = Path("/brixtest/workspace")
            return workspace / declaration.cwd if declaration.cwd else workspace
        path = self.workspace / declaration.cwd if declaration.cwd else self.workspace
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _client_execution_context(
        self, kubernetes, metadata: Mapping[str, object],
    ) -> ToolExecutionContext:
        return ToolExecutionContext(
            nodeid=self.nodeid, root=self.root, workspace=self.workspace,
            backend=self.backend_name,
            namespace=str(metadata.get(
                "namespace", getattr(kubernetes, "namespace", ""),
            )),
            metadata={
                "kubectl": str(getattr(kubernetes, "kubectl", "kubectl")),
                "kubectl_context": str(metadata.get(
                    "context", getattr(kubernetes, "context", ""),
                )),
            },
            identities={item.name: item for item in self.definition.identities},
        )

    @staticmethod
    def _client_values(
        values: Mapping[str, object], remote_values: Optional[Mapping[str, object]],
        remote: bool,
    ) -> Dict[str, object]:
        if remote and remote_values is not None:
            return dict(remote_values)
        return dict(values)

    def _client_archive_dir(self, declaration) -> Optional[Path]:
        if not declaration.logs.capture:
            return None
        return self.root / "runtime" / "client-logs" / declaration.name

    def _configured_client(
        self, declaration, values: Mapping[str, object], libraries: Sequence[str],
        binary_dirs: Sequence[str], remote_values: Optional[Mapping[str, object]],
    ):
        executor_name, executor, kubernetes, metadata = self._client_executor(declaration)
        remote = executor_name == "kubernetes"
        containerized = executor_name in ("kubernetes", "docker", "podman")
        client_values = self._client_values(values, remote_values, remote)
        mounts = self._client_mount_values(declaration, remote, metadata)
        client_values.update(mounts)
        spec = ClientSpec(
            declaration.name,
            self._client_command(declaration, containerized),
            env=self._client_environment(
                declaration, mounts, remote, metadata, libraries, binary_dirs,
            ),
            cwd=str(self._client_workdir(declaration, remote)),
            timeout=declaration.timeout,
            input=declaration.input,
            expected_exit_codes=declaration.expected_exit_codes,
            output_limit=min(declaration.output_limit, declaration.logs.max_bytes),
            mode=declaration.mode,
            retries=declaration.retries,
            encoding=declaration.encoding,
            log_redact=declaration.logs.redact,
            placement=declaration.placement,
            image=self._client_image(declaration),
        )
        client_type = _configured_type(declaration)
        return client_type(
            spec, client_values, observer=self._observe_client,
            archive_dir=self._client_archive_dir(declaration),
            executor=executor,
            execution_context=self._client_execution_context(kubernetes, metadata),
            executor_metadata=metadata,
            result_observer=self._observe_tool_result,
        )

    def _prepare_clients(
        self, common: Mapping[str, object], libraries: Sequence[str],
        binary_dirs: Sequence[str] = (),
        *, remote_values: Optional[Mapping[str, object]] = None,
    ) -> None:
        values = dict(common)
        self._service_values(values)
        for declaration in self.definition.clients:
            self._clients[declaration.name] = self._configured_client(
                declaration, values, libraries, binary_dirs, remote_values,
            )
