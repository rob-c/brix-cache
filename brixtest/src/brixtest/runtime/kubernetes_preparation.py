"""Kubernetes projection preparation shared by the case manager."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence

from brixtest.credentials import Credential
from brixtest.design import Artifact, Client, ConfigFile, Server, Volume
from brixtest.errors import SpecError
from brixtest.resources import Reference
from brixtest.runtime.kubernetes_manifests import _resource_name, secure_secret_resource
from brixtest.runtime.kubernetes_identity import identity_resources
from brixtest.util.configtext import render_cfg_strict

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


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


def _references(value: object) -> tuple[Reference, ...]:
    found = []
    pending = [value]
    while pending:
        selected = pending.pop()
        if isinstance(selected, Reference):
            found.append(selected)
        elif dataclasses.is_dataclass(selected):
            pending.extend(
                getattr(selected, field.name) for field in dataclasses.fields(selected)
            )
        elif isinstance(selected, Mapping):
            pending.extend(selected.values())
        elif isinstance(selected, Sequence) and not isinstance(selected, (str, bytes)):
            pending.extend(selected)
    return tuple(found)


def _referenced_names(
    declaration: object, kind: str, catalog=(), source_root: Optional[Path] = None,
) -> tuple[str, ...]:
    names = {value.name for value in _references(declaration) if value.kind == kind}
    if catalog and source_root is not None:
        placeholders = _declaration_placeholders(declaration, source_root)
        names.update(
            item.name for item in catalog
            if _resource_placeholder(kind, item.name, placeholders)
        )
    return tuple(sorted(names))


def _declaration_placeholders(declaration: object, source_root: Path) -> set[str]:
    values = []
    pending = [declaration]
    while pending:
        selected = pending.pop()
        if isinstance(selected, str):
            values.append(selected)
        else:
            pending.extend(_placeholder_children(selected))
    _add_config_text(declaration, source_root, values)
    return {match for value in values for match in _PLACEHOLDER.findall(value)}


def _placeholder_children(value: object) -> Sequence[object]:
    if dataclasses.is_dataclass(value):
        return tuple(
            getattr(value, field.name) for field in dataclasses.fields(value)
        )
    if isinstance(value, Mapping):
        return tuple(value.values())
    if isinstance(value, Sequence) and not isinstance(value, bytes):
        return value
    return ()


def _add_config_text(declaration: object, source_root: Path, values: list[str]) -> None:
    from brixtest.config.material import material
    configs = getattr(getattr(declaration, "configs", None), "files", ())
    values.extend(material(item, source_root).declared_text for item in configs)


def _resource_placeholder(kind: str, name: str, placeholders: set[str]) -> bool:
    base = "%s_%s" % (kind, name)
    return base in placeholders or "%s_dir" % base in placeholders


def _artifact_remote_path(name: str, path: Path) -> tuple[str, Path]:
    target = "auto/artifacts/%s/%s" % (name, path.name)
    return target, Path("/brixtest/mounts") / target

class KubernetesPreparationMixin:
    @staticmethod
    def _render_probe_command(server: Server, values: Mapping[str, object]) -> tuple[str, ...]:
        return tuple(
            render_cfg_strict(
                str(part), values, template="server %s probe" % server.name,
            )
            for part in server.probe.command
        )

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
        self._server_referenced_artifacts(server, files, values)
        _check_projection_size(tuple(files.values()), "server %s mounts" % server.name)
        return files, tuple(temporary), tuple(managed)

    def _server_referenced_artifacts(self, server, files, values) -> None:
        owner = self.owner
        for name in _referenced_names(
            server, "artifact", owner.definition.artifacts, owner.source_root,
        ):
            artifact = owner.artifact_store.get(name)
            target, remote = _artifact_remote_path(name, artifact.path)
            files[target] = _regular_projection(
                artifact.path, "server %s reference" % server.name,
            )
            values["artifact_%s" % name] = remote
            values["artifact_%s_dir" % name] = remote.parent

    def _prepare_client_resources(self, client: Client) -> None:
        """Project only files required by one Kubernetes-executed client."""
        owner = self.owner
        target = self.environments.for_client(client.name)
        files: Dict[str, Path] = {}
        temporary = []
        values: Dict[str, object] = {}
        self._client_declared_mounts(client, files, temporary, values)
        self._client_referenced_artifacts(client, files, values)
        self._client_referenced_binaries(client, values)
        _check_projection_size(tuple(files.values()), "client %s mounts" % client.name)
        mount_secret, mount_items = self._client_mount_secret(client, files, target)
        identity = self._client_identity(client)
        if identity is not None:
            self._apply(
                identity_resources(identity, target.namespace), context=target.context,
            )
        self._client_runtime[client.name] = {
            "secure_secret": self._client_secure_secret,
            "secure_items": tuple(self._client_secure_items),
            "secret_environment": dict(self._client_secret_environment),
            "mount_secret": mount_secret, "mount_items": tuple(mount_items),
            "temporary_mounts": tuple(temporary), "mount_values": values,
            "identity": identity,
            "namespace": target.namespace, "context": target.context,
            "host_aliases": tuple(
                {"ip": item.address, "hostnames": list(item.hostnames)}
                for item in owner.definition.hosts
                if item.libc and "client" in item.targets
            ),
        }

    def _client_identity(self, client: Client):
        return next((
            item for item in self.owner.definition.identities
            if item.name == client.placement.identity
        ), None)

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
        for name in _referenced_names(
            client, "artifact", owner.definition.artifacts, owner.source_root,
        ):
            artifact = owner.artifact_store.get(name)
            target, remote = _artifact_remote_path(name, artifact.path)
            files[target] = _regular_projection(
                artifact.path, "client %s mount" % client.name,
            )
            values["artifact_%s" % name] = remote
            values["artifact_%s_dir" % name] = remote.parent

    def _client_referenced_binaries(self, client, values) -> None:
        declared = {item.name: item for item in self.owner.definition.binaries}
        for name in _referenced_names(
            client, "binary", self.owner.definition.binaries, self.owner.source_root,
        ):
            binary = declared[name]
            if not binary.image_path:
                raise SpecError(
                    "client %s binary reference" % client.name, name,
                    "requires image_path inside its Kubernetes image",
                )
            values["binary_%s" % name] = binary.image_path
            values["binary_%s_dir" % name] = str(Path(binary.image_path).parent)

    def _client_mount_secret(self, client, files, target) -> tuple[str, Sequence[dict]]:
        if not files:
            return "", ()
        mount_secret = "%s-tool-mounts" % _resource_name(client.name)
        document, mount_items = secure_secret_resource(
            target.namespace, files, name=mount_secret,
        )
        self._apply([document], context=target.context)
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
