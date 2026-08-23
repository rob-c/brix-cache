"""Kubernetes projection preparation shared by the case manager."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Mapping, Sequence

from brixtest.credentials import Credential
from brixtest.design import Artifact, Client, ConfigFile, Server, Volume
from brixtest.errors import SpecError
from brixtest.resources import Reference
from brixtest.runtime.kubernetes_manifests import _resource_name, secure_secret_resource


def _projection_path(owner, source: object) -> Path:
    if hasattr(source, "path"):
        return Path(str(source.path)).resolve()
    candidate = Path(str(source))
    return candidate.resolve() if candidate.is_absolute() else (
        owner.source_root / candidate
    ).resolve()


def _server_mount_source(
    owner, server: Server, source: object, kind: str, configs: Mapping[str, Path],
) -> Path:
    if _is_artifact_source(kind, source):
        return owner.artifact_store.get(
            source.name if isinstance(source, Artifact) else str(source)
        ).path
    if _is_credential_source(kind, source):
        return owner.security.credential(
            source.name if isinstance(source, Credential) else str(source)
        ).path
    if _is_config_source(kind, source):
        return _server_config_source(server, source, configs)
    return _projection_path(owner, source)


def _is_artifact_source(kind: str, source: object) -> bool:
    return kind == "artifact" or isinstance(source, Artifact)


def _is_credential_source(kind: str, source: object) -> bool:
    return kind == "credential" or isinstance(source, Credential)


def _is_config_source(kind: str, source: object) -> bool:
    return kind == "config" or isinstance(source, ConfigFile)


def _server_config_source(
    server: Server, source: object, configs: Mapping[str, Path],
) -> Path:
    destination = source.destination if isinstance(source, ConfigFile) else str(source)
    try:
        return configs[destination]
    except KeyError:
        raise SpecError(
            "server %s mount.source" % server.name, destination,
            "config mounts must belong to the mounted server",
        ) from None


def _client_mount_source(owner, client: Client, source: object, kind: str) -> Path:
    if _is_artifact_source(kind, source):
        return owner.artifact_store.get(
            source.name if isinstance(source, Artifact) else str(source)
        ).path
    if _is_credential_source(kind, source):
        return owner.security.credential(
            source.name if isinstance(source, Credential) else str(source)
        ).path
    if _is_config_source(kind, source):
        raise SpecError(
            "client %s mount" % client.name, str(source),
            "client configs should be declared as artifacts",
        )
    return _projection_path(owner, source)


def _regular_projection(path: Path, field: str) -> Path:
    if not path.is_file() or path.is_symlink():
        raise SpecError(
            field, str(path), "Kubernetes projections require regular non-symlink files"
        )
    return path


def _check_projection_size(paths: Sequence[Path], field: str) -> None:
    total = sum(path.stat().st_size for path in paths)
    if total > 768 << 10:
        raise SpecError(
            field, total,
            "embedded Kubernetes projections are limited to 768 KiB; use an image, PVC, or backend extension",
        )

class KubernetesPreparationMixin:
    def _mount_files(
        self, server: Server, captured: Sequence[object], values: Dict[str, object],
    ) -> tuple[Mapping[str, Path], tuple[str, ...], tuple[tuple[object, Volume], ...]]:
        """Resolve small read-only files and writable temporary projections."""
        owner = self.owner
        configs = {
            declaration.destination: item.rendered
            for declaration, item in zip(server.configs.files, captured)
        }
        files: Dict[str, Path] = {}
        temporary = []
        managed = []
        for index, declaration in enumerate(server.mounts):
            target = declaration.target
            remote = "/brixtest/mounts/%s" % target
            values["mount_%s" % owner.config_store.placeholder(target)] = remote
            values["mount_%d" % index] = remote
            if isinstance(declaration.source, Volume):
                managed.append((declaration, declaration.source))
                continue
            if declaration.kind == "tmp":
                temporary.append(target)
                continue
            if not declaration.read_only:
                raise SpecError(
                    "server %s mount" % server.name, target,
                    "Kubernetes writable projections must use kind='tmp'",
                )
            path = _server_mount_source(
                owner, server, declaration.source, declaration.kind, configs,
            )
            if not path.is_file():
                raise SpecError(
                    "server %s mount.source" % server.name, str(declaration.source),
                    "Kubernetes projections require regular files",
                )
            files[target] = path
        _check_projection_size(tuple(files.values()), "server %s mounts" % server.name)
        return files, tuple(temporary), tuple(managed)
    def _prepare_client_resources(self, client: Client) -> None:
        """Project only files required by one Kubernetes-executed client."""
        owner = self.owner
        files: Dict[str, Path] = {}
        temporary = []
        values: Dict[str, object] = {}
        self._client_declared_mounts(client, files, temporary, values)
        self._client_referenced_artifacts(client, files, values)
        _check_projection_size(tuple(files.values()), "client %s mounts" % client.name)
        mount_secret, mount_items = self._client_mount_secret(client, files)
        self._client_runtime[client.name] = {
            "secure_secret": self._client_secure_secret,
            "secure_items": tuple(self._client_secure_items),
            "secret_environment": dict(self._client_secret_environment),
            "mount_secret": mount_secret, "mount_items": tuple(mount_items),
            "temporary_mounts": tuple(temporary), "mount_values": values,
            "host_aliases": tuple(
                {"ip": item.address, "hostnames": list(item.hostnames)}
                for item in owner.definition.hosts
            ),
        }

    def _client_declared_mounts(self, client, files, temporary, values) -> None:
        owner = self.owner
        for index, declaration in enumerate(client.mounts):
            target = declaration.target
            remote = Path("/brixtest/mounts") / target
            values["mount_%s" % owner.config_store.placeholder(target)] = remote
            values["mount_%d" % index] = remote
            if declaration.kind == "tmp":
                temporary.append(target)
                continue
            if not declaration.read_only:
                raise SpecError(
                    "client %s mount" % client.name, target,
                    "Kubernetes writable projections must use kind='tmp'",
                )
            source = declaration.source
            selected = _client_mount_source(owner, client, source, declaration.kind)
            files[target] = _regular_projection(selected, "client %s mount" % client.name)
            if _is_artifact_source(declaration.kind, source):
                artifact = owner.artifact_store.get(
                    source.name if isinstance(source, Artifact) else str(source)
                )
                values["artifact_%s" % artifact.name] = remote
                values["artifact_%s_dir" % artifact.name] = remote.parent

    def _client_referenced_artifacts(self, client, files, values) -> None:
        owner = self.owner
        referenced = [
            value.name for value in (*client.command, *client.env.values())
            if isinstance(value, Reference) and value.kind == "artifact"
        ]
        for name in sorted(set(referenced)):
            artifact = owner.artifact_store.get(name)
            target = "auto/artifacts/%s/%s" % (name, artifact.path.name)
            remote = Path("/brixtest/mounts") / target
            files[target] = _regular_projection(
                artifact.path, "client %s mount" % client.name,
            )
            values["artifact_%s" % name] = remote
            values["artifact_%s_dir" % name] = remote.parent

    def _client_mount_secret(self, client, files) -> tuple[str, Sequence[dict]]:
        if not files:
            return "", ()
        mount_secret = "%s-tool-mounts" % _resource_name(client.name)
        document, mount_items = secure_secret_resource(
            self.namespace, files, name=mount_secret,
        )
        self._apply([document])
        return mount_secret, mount_items
    def client_metadata(self, client: Client) -> Mapping[str, object]:
        try:
            return self._client_runtime[client.name]
        except KeyError:
            raise SpecError(
                "Kubernetes client", client.name,
                "was not prepared for Kubernetes execution",
            ) from None

    @staticmethod
    def _internal_ports(servers: Sequence[Server]) -> Dict[str, Dict[str, int]]:
        out: Dict[str, Dict[str, int]] = {}
        for index, server in enumerate(servers):
            roles = {}
            for offset, (role, requested) in enumerate(server.ports.items()):
                roles[role] = requested or (18000 + index * 100 + offset)
            if "primary" not in roles:
                role = (
                    server.probe.endpoint if server.probe.kind != "none"
                    else next(iter(server.ports))
                )
                roles["primary"] = roles[role]
            out[server.name] = roles
        return out
