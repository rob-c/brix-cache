"""Pure topology derivation from immutable user test declarations."""

from __future__ import annotations

import dataclasses
import hashlib
import os
import re
import shutil
from pathlib import Path
from typing import Mapping, Sequence

from brixtest.config.material import identity as config_identity
from brixtest.design import Artifact, Binary, CaseDefinition, Server
from brixtest.evidence.model import canonical_json
from brixtest.errors import SpecError
from brixtest.resources import Reference

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _jsonable(value: object) -> object:
    if dataclasses.is_dataclass(value):
        return _jsonable(dataclasses.asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in sorted(value.items(), key=lambda row: str(row[0]))}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {"sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value)}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _config_identity(server: Server, source: Path) -> dict:
    return {
        "primary": server.configs.primary,
        "files": [config_identity(item, source.parent) for item in server.configs.files],
    }


def _file_digest(value: object, source_root: Path, *, executable: bool = False) -> dict:
    raw = str(value)
    if executable and os.sep not in raw:
        found = shutil.which(raw)
        candidate = Path(found) if found else source_root / raw
    else:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = source_root / candidate
    resolved = candidate.resolve()
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        raise SpecError("topology input", raw, "cannot read: %s" % exc) from exc
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def _binary_identity(value: Binary, source_root: Path) -> dict:
    local = _file_digest(value.path, source_root, executable=True) if value.path else None
    libraries = [
        _file_digest(path, source_root) for path in value.libraries
    ]
    return {
        "name": value.name, "local": local, "libraries": libraries,
        "discover_libraries": value.discover_libraries,
        "image": value.image, "image_path": value.image_path,
    }


def _artifact_identity(value: Artifact, source_root: Path) -> dict:
    source = _file_digest(value.source, source_root) if value.kind == "file" else None
    return {
        "name": value.name, "kind": value.kind, "size": value.size,
        "seed": value.seed, "source": source,
        "text_sha256": hashlib.sha256(value.text.encode()).hexdigest()
        if value.kind == "text" else None,
        "filename": value.filename,
    }


def _secret_identity(value: object) -> dict:
    """Identify a security declaration without retaining its secret in payloads."""
    body = canonical_json(_jsonable(value)).encode()
    return {
        "name": getattr(value, "name", ""),
        "kind": getattr(value, "kind", ""),
        "declaration_sha256": hashlib.sha256(body).hexdigest(),
    }


def _references(value: object) -> tuple[Reference, ...]:
    found: list[Reference] = []

    def visit(item: object) -> None:
        if isinstance(item, Reference):
            found.append(item)
        elif dataclasses.is_dataclass(item):
            for field in dataclasses.fields(item):
                visit(getattr(item, field.name))
        elif isinstance(item, Mapping):
            for key, nested in item.items():
                visit(key)
                visit(nested)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                visit(nested)

    visit(value)
    return tuple(found)


def _placeholder_names(server: Server, source: Path) -> set[str]:
    values: list[str] = []

    def visit(item: object) -> None:
        if isinstance(item, Reference):
            values.append(str(item))
        elif isinstance(item, str):
            values.append(item)
        elif dataclasses.is_dataclass(item):
            for field in dataclasses.fields(item):
                visit(getattr(item, field.name))
        elif isinstance(item, Mapping):
            for nested in item.values():
                visit(nested)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                visit(nested)

    visit(server)
    for config in server.configs.files:
        from brixtest.config.material import material
        values.append(material(config, source.parent).declared_text)
    return {match for value in values for match in _PLACEHOLDER.findall(value)}


def _pool_resources(definition: CaseDefinition, servers: Sequence[Server]) -> dict:
    """Select only inputs that can influence the shared server processes."""
    source_root = definition.source.parent
    refs = tuple(reference for server in servers for reference in _references(server))
    placeholders = set().union(*(
        _placeholder_names(server, definition.source) for server in servers
    )) if servers else set()

    binary_names = {
        binary.name for server in servers
        for binary in (*server.binaries, *(item for item in server.command if isinstance(item, Binary)))
    }
    binary_names.update(ref.name for ref in refs if ref.kind == "binary")
    binary_names.update(
        item.name for item in definition.binaries
        if "binary_%s" % item.name in placeholders
    )

    credential_names = {
        item.name for item in definition.credentials if "server" in item.targets
    }
    credential_names.update(ref.name for ref in refs if ref.kind == "credential")
    artifact_names = {ref.name for ref in refs if ref.kind == "artifact"}
    for server in servers:
        for declared_mount in server.mounts:
            source = declared_mount.source
            if isinstance(source, Artifact):
                artifact_names.add(source.name)
            elif getattr(source, "kind", None) in ("text", "file", "checksum", "signed"):
                credential_names.add(source.name)
            elif declared_mount.kind == "artifact":
                artifact_names.add(str(source))
            elif declared_mount.kind == "credential":
                credential_names.add(str(source))
    selected_credentials = tuple(
        item for item in definition.credentials if item.name in credential_names
    )
    artifact_names.update(
        item.artifact.name for item in selected_credentials if item.artifact is not None
    )
    artifact_names.update(
        item.name for item in definition.artifacts
        if "artifact_%s" % item.name in placeholders
    )
    parameters = {
        name: value for name, value in definition.parameters.items()
        if "param_%s" % name in placeholders
    }
    return {
        "binaries": tuple(item for item in definition.binaries if item.name in binary_names),
        "artifacts": tuple(item for item in definition.artifacts if item.name in artifact_names),
        "credentials": selected_credentials,
        # Authentication and DNS are injected globally into each server environment.
        "auth": tuple(definition.auth),
        "hosts": tuple(definition.hosts),
        "parameters": parameters,
        "source_root": source_root,
    }


def _server_identity(server: Server, source: Path) -> dict:
    """Exclude config source paths: effective content is the identity."""
    return {
        "name": server.name,
        "command": _jsonable(server.command),
        "config": _config_identity(server, source),
        "ports": _jsonable(server.ports),
        "env": _jsonable(server.env),
        "readiness": _jsonable(server.readiness),
        "depends_on": _jsonable(server.depends_on),
        "binaries": _jsonable(server.binaries),
        "image": server.image,
        "scope": server.scope,
        "endpoints": _jsonable(server.endpoints),
        "probe": _jsonable(server.probe),
        "mounts": _jsonable(server.mounts),
        "lifecycle": _jsonable(server.lifecycle),
        "placement": _jsonable(server.placement),
        "logs": _jsonable(server.logs),
        "cwd": server.cwd,
        "metadata": _jsonable(server.metadata),
    }


_SHARED_SCOPES = ("class", "module", "package", "session")


def shared_servers(
    definition: CaseDefinition, scope: str = "session",
) -> tuple[Server, ...]:
    return tuple(server for server in definition.servers if server.scope == scope)


def pool_key(
    definition: CaseDefinition, scope: str = "session", domain: str = "session",
) -> str:
    servers = shared_servers(definition, scope)
    if not servers:
        return ""
    selected = _pool_resources(definition, servers)
    payload = {
        "scope": scope,
        "domain": domain,
        "backend": definition.backend,
        "servers": [_server_identity(server, definition.source) for server in servers],
        "artifacts": [
            _artifact_identity(item, selected["source_root"])
            for item in selected["artifacts"]
        ],
        "binaries": [
            _binary_identity(item, selected["source_root"])
            for item in selected["binaries"]
        ],
        "credentials": [_secret_identity(item) for item in selected["credentials"]],
        "auth": [_secret_identity(item) for item in selected["auth"]],
        "hosts": _jsonable(selected["hosts"]),
        "parameters": _jsonable(selected["parameters"]),
    }
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:24]


def pool_definition(
    definition: CaseDefinition, scope: str = "session",
) -> CaseDefinition:
    servers = shared_servers(definition, scope)
    names = {server.name for server in servers}
    for server in servers:
        missing = sorted(set(server.depends_on) - names)
        if missing:
            raise SpecError(
                "shared topology", server.name,
                "%s server dependencies must share its lifetime: %s"
                % (scope, ", ".join(missing)),
            )
    selected = _pool_resources(definition, servers)
    return dataclasses.replace(
        definition, servers=servers, clients=(),
        artifacts=selected["artifacts"], binaries=selected["binaries"],
        credentials=selected["credentials"], auth=selected["auth"],
        hosts=selected["hosts"], parameters=selected["parameters"],
        warmup=0, trials=1, keep="always",
    )


def instance_id(key: str, server_name: str) -> str:
    return hashlib.sha256((key + "\0" + server_name).encode()).hexdigest()


@dataclasses.dataclass(frozen=True)
class PoolPlan:
    key: str
    definition: CaseDefinition
    tests: tuple[str, ...]
    scope: str = "session"
    domain: str = "session"


def _scope_domain(nodeid: str, scope: str) -> str:
    parts = nodeid.split("::")
    module = parts[0]
    if scope == "session":
        return "session"
    if scope == "package":
        return str(Path(module).parent)
    if scope == "module":
        return module
    if scope == "class":
        return "%s::%s" % (module, parts[1]) if len(parts) >= 3 else nodeid
    raise SpecError("server scope", scope, "does not have a shared topology domain")


def derive(
    rows: Sequence[tuple[str, CaseDefinition]], namespace: str = "",
) -> tuple[PoolPlan, ...]:
    grouped: dict[tuple[str, str, str], list[tuple[str, CaseDefinition]]] = {}
    for nodeid, definition in rows:
        for scope in _SHARED_SCOPES:
            domain = _scope_domain(nodeid, scope)
            if namespace:
                domain = "%s\0worker:%s" % (domain, namespace)
            key = pool_key(definition, scope, domain)
            if key:
                grouped.setdefault((key, scope, domain), []).append((nodeid, definition))
    plans = []
    for (key, scope, domain), uses in sorted(grouped.items()):
        definition = pool_definition(uses[0][1], scope)
        plans.append(PoolPlan(
            key, definition, tuple(sorted(nodeid for nodeid, _ in uses)), scope, domain,
        ))
    return tuple(plans)
