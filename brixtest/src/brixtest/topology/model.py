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
from brixtest.errors import SpecError
from brixtest.evidence.model import canonical_json
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
    return _json_scalar(value)


def _json_scalar(value: object) -> object:
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
        "runtime_files": {
            destination: _file_digest(source, source_root)
            for destination, source in sorted(value.runtime_files.items())
        },
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
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, Reference):
            found.append(item)
            continue
        pending.extend(_nested_items(item, include_mapping_keys=True))
    return tuple(found)


def _nested_items(item: object, *, include_mapping_keys: bool) -> list[object]:
    if dataclasses.is_dataclass(item):
        return [getattr(item, field.name) for field in dataclasses.fields(item)]
    if isinstance(item, Mapping):
        values = list(item.values())
        return [*item.keys(), *values] if include_mapping_keys else values
    if isinstance(item, (list, tuple)):
        return list(item)
    return []


def _placeholder_values(item: object, values: list[str]) -> None:
    pending = [item]
    while pending:
        current = pending.pop()
        if isinstance(current, (Reference, str)):
            values.append(str(current))
            continue
        pending.extend(_nested_items(current, include_mapping_keys=False))


def _placeholder_names(server: Server, source: Path) -> set[str]:
    values: list[str] = []
    _placeholder_values(server, values)
    for config in server.configs.files:
        from brixtest.config.material import material
        values.append(material(config, source.parent).declared_text)
    return {match for value in values for match in _PLACEHOLDER.findall(value)}


def _pool_binary_names(definition, servers, refs, placeholders) -> set[str]:
    names = _server_binary_names(servers)
    names.update(ref.name for ref in refs if ref.kind == "binary")
    names.update(_placeholder_binary_names(definition, placeholders))
    return names


def _server_binary_names(servers: Sequence[Server]) -> set[str]:
    return {
        binary.name for server in servers
        for binary in (*server.binaries, *(item for item in server.command if isinstance(item, Binary)))
    }


def _placeholder_binary_names(definition, placeholders: set[str]) -> set[str]:
    return {
        item.name for item in definition.binaries if "binary_%s" % item.name in placeholders
    }


def _pool_declared_names(definition, servers, refs) -> tuple[set[str], set[str]]:
    credentials = _server_credential_names(definition)
    credentials.update(_reference_names(refs, "credential"))
    artifacts = _reference_names(refs, "artifact")
    _add_server_mount_names(servers, credentials, artifacts)
    return credentials, artifacts


def _server_credential_names(definition) -> set[str]:
    return {item.name for item in definition.credentials if "server" in item.targets}


def _reference_names(refs: Sequence[Reference], kind: str) -> set[str]:
    return {ref.name for ref in refs if ref.kind == kind}


def _add_server_mount_names(
    servers: Sequence[Server], credentials: set[str], artifacts: set[str],
) -> None:
    for server in servers:
        for mount in server.mounts:
            _add_mount_name(mount, credentials, artifacts)


def _add_mount_name(mount, credentials: set[str], artifacts: set[str]) -> None:
    source = mount.source
    if isinstance(source, Artifact):
        artifacts.add(source.name)
        return
    if getattr(source, "kind", None) in ("text", "file", "checksum", "signed"):
        credentials.add(source.name)
        return
    if mount.kind == "artifact":
        artifacts.add(str(source))
    elif mount.kind == "credential":
        credentials.add(str(source))


def _pool_artifacts(definition, credentials, names, placeholders) -> set[str]:
    names.update(item.artifact.name for item in credentials if item.artifact is not None)
    names.update(
        item.name for item in definition.artifacts if "artifact_%s" % item.name in placeholders
    )
    return names


def _pool_resources(definition: CaseDefinition, servers: Sequence[Server]) -> dict:
    """Select only inputs that can influence the shared server processes."""
    source_root = definition.source.parent
    refs = _server_references(servers)
    placeholders = _pool_placeholders(servers, definition.source)

    binary_names = _pool_binary_names(definition, servers, refs, placeholders)
    credential_names, artifact_names = _pool_declared_names(definition, servers, refs)
    selected_credentials = _named_items(definition.credentials, credential_names)
    artifact_names = _pool_artifacts(
        definition, selected_credentials, artifact_names, placeholders,
    )
    parameters = _pool_parameters(definition.parameters, placeholders)
    managed = _pool_managed_resources(definition, servers)
    return {
        "binaries": _named_items(definition.binaries, binary_names),
        "artifacts": _named_items(definition.artifacts, artifact_names),
        "credentials": selected_credentials,
        "auth": tuple(definition.auth),
        "hosts": tuple(definition.hosts),
        "parameters": parameters,
        "source_root": source_root,
        **managed,
    }


def _pool_managed_resources(definition, servers) -> dict[str, tuple[object, ...]]:
    return {
        "volumes": _named_items(definition.volumes, _pool_volume_names(servers)),
        "identities": _named_items(definition.identities, _pool_identity_names(servers)),
        "environments": _named_items(
            definition.environments, _pool_environment_names(servers),
        ),
    }


def _pool_volume_names(servers) -> set[str]:
    return {
        mount.source.name for server in servers for mount in server.mounts
        if getattr(mount.source, "resource_kind", "") == "volume"
    }


def _pool_identity_names(servers) -> set[str]:
    return {server.placement.identity for server in servers}


def _pool_environment_names(servers) -> set[str]:
    return {server.placement.environment for server in servers}


def _server_references(servers: Sequence[Server]) -> tuple[Reference, ...]:
    return tuple(reference for server in servers for reference in _references(server))


def _named_items(items: Sequence[object], names: set[str]) -> tuple[object, ...]:
    return tuple(item for item in items if item.name in names)


def _pool_placeholders(servers: Sequence[Server], source: Path) -> set[str]:
    if not servers:
        return set()
    return set().union(*(_placeholder_names(server, source) for server in servers))


def _pool_parameters(parameters, placeholders: set[str]) -> dict:
    return {
        name: value for name, value in parameters.items()
        if "param_%s" % name in placeholders
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


_SHARED_SCOPES = ("class", "module", "package", "session", "worker")


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
        "volumes": _jsonable(selected["volumes"]),
        "identities": _jsonable(selected["identities"]),
        "environments": _jsonable(selected["environments"]),
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
        volumes=selected["volumes"], identities=selected["identities"],
        environments=selected["environments"],
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
    if scope == "worker":
        return "worker"
    if scope == "package":
        return str(Path(module).parent)
    if scope == "module":
        return module
    if scope == "class":
        return "%s::%s" % (module, parts[1]) if len(parts) >= 3 else nodeid
    raise SpecError("server scope", scope, "does not have a shared topology domain")


def derive(
    rows: Sequence[tuple[str, CaseDefinition]], namespace: str = "",
    scopes: Sequence[str] = _SHARED_SCOPES,
) -> tuple[PoolPlan, ...]:
    grouped = _grouped_pools(rows, namespace, scopes)
    return tuple(_pool_plan(key, scope, domain, uses)
                 for (key, scope, domain), uses in sorted(grouped.items()))


def _grouped_pools(
    rows: Sequence[tuple[str, CaseDefinition]], namespace: str,
    scopes: Sequence[str],
) -> dict[tuple[str, str, str], list[tuple[str, CaseDefinition]]]:
    grouped: dict[tuple[str, str, str], list[tuple[str, CaseDefinition]]] = {}
    for nodeid, definition in rows:
        for key, scope, domain in _row_pool_keys(
            nodeid, definition, namespace, scopes,
        ):
            grouped.setdefault((key, scope, domain), []).append((nodeid, definition))
    return grouped


def _row_pool_keys(
    nodeid: str, definition: CaseDefinition, namespace: str,
    scopes: Sequence[str],
):
    for scope in scopes:
        if scope not in _SHARED_SCOPES:
            raise SpecError("topology scope", scope, "is not a shared server scope")
        domain = _scope_domain(nodeid, scope)
        if namespace:
            domain = "%s\0worker:%s" % (domain, namespace)
        key = pool_key(definition, scope, domain)
        if key:
            yield key, scope, domain


def _pool_plan(key: str, scope: str, domain: str, uses) -> PoolPlan:
    definition = pool_definition(uses[0][1], scope)
    tests = tuple(sorted(nodeid for nodeid, _ in uses))
    return PoolPlan(key, definition, tests, scope, domain)
