"""Bridge collection-derived server instances into isolated case helpers."""

from __future__ import annotations

import dataclasses
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from brixtest.errors import SpecError
from brixtest.evidence.model import stable_id


def owned_servers(definition) -> tuple:
    """Return declarations whose lifetime belongs to this helper process."""
    owner = os.environ.get("BRIXTEST_SHARED_POOL_OWNER") == "1"
    if owner:
        return tuple(definition.servers)
    return tuple(
        server for server in definition.servers if server.scope in ("case", "function")
    )


def injected_services(service_type) -> dict:
    """Recreate backend-neutral Service values passed by the session supervisor."""
    try:
        payload = json.loads(os.environ.get("BRIXTEST_SHARED_SERVERS_JSON", "{}"))
    except (TypeError, ValueError) as exc:
        raise SpecError("shared server manifest", "invalid JSON", str(exc)) from exc
    rows = payload.get("services", {}) if isinstance(payload, dict) else {}
    if not isinstance(rows, dict):
        raise SpecError("shared server manifest", rows, "services must be an object")
    services = {}
    for name, row in rows.items():
        if not isinstance(row, dict):
            raise SpecError("shared server", name, "manifest entry must be an object")
        services[str(name)] = _injected_service(service_type, str(name), row)
    return services


def _dict_value(row: dict, name: str) -> dict:
    value = row.get(name, {})
    return dict(value) if isinstance(value, dict) else {}


def _path_mapping(row: dict, name: str) -> dict[str, Path]:
    return {key: Path(str(value)) for key, value in _dict_value(row, name).items()}


def _text_mapping(row: dict, name: str) -> dict[str, str]:
    return {key: str(value) for key, value in _dict_value(row, name).items()}


def _injected_service(service_type, name: str, row: dict):
    return service_type(
        name=name, host=str(row["host"]),
        ports={str(role): int(port) for role, port in row["ports"].items()},
        config=Path(str(row["config"])), log=Path(str(row["log"])),
        workdir=Path(str(row["workdir"])), instance_id=str(row["instance_id"]),
        scope=str(row.get("scope", "session")),
        started_at=float(row.get("started_at_epoch", 0)), pool_id=str(row.get("pool_id", "")),
        config_filename=str(row.get("config_filename", "")),
        config_sha256=str(row.get("config_sha256", "")),
        config_source_sha256=str(row.get("config_source_sha256", "")),
        config_declared_sha256=str(row.get("config_declared_sha256", "")),
        config_artifact=_dict_value(row, "config_artifact"),
        configs=_path_mapping(row, "configs"), schemes=_text_mapping(row, "schemes"),
        protocols=_text_mapping(row, "protocols"), hosts=_text_mapping(row, "hosts"),
        metadata=_dict_value(row, "metadata"),
    )


def instance_for(attempt_id: str, server_name: str) -> str:
    return stable_id("case-server", attempt_id, server_name)


def _log_source(manager, service) -> str:
    try:
        return str(service.log.relative_to(manager.root))
    except ValueError:
        return str(service.log)


def _ensure_config_artifact(manager, name: str, service):
    artifact = dict(service.config_artifact)
    try:
        service.config.relative_to(manager.root)
    except ValueError:
        return service, artifact
    if artifact:
        return service, artifact
    artifact = manager.evidence.attach(
        service.config, name="%s-%s" % (name, service.config.name),
        role="server-config", description="effective config used to launch %s" % name,
    )
    controller = getattr(service, "_controller", None)
    service = dataclasses.replace(service, config_artifact=artifact)
    if controller is not None:
        object.__setattr__(service, "_controller", controller)
    manager._services[name] = service
    return service, artifact


def _config_records(manager, name: str, service) -> list[dict]:
    captured = _captured_config_map(manager, name)
    return [
        _config_record(manager, name, destination, path, captured.get(destination))
        for destination, path in service.configs.items()
    ]


def _captured_config_map(manager, name: str) -> dict:
    if name not in manager.config_store._sets:
        return {}
    return {item.filename: item for item in manager.config_store.all(name)}


def _config_record(manager, name: str, destination: str, path: Path, item) -> dict:
    attachment = _config_attachment(manager, name, destination, path)
    return {
        "destination": destination, "path": str(path),
        "rendered_sha256": _rendered_checksum(item, attachment),
        "source_sha256": item.source_sha256 if item else "",
        "declared_sha256": item.declared_sha256 if item else "",
        "artifact": attachment,
    }


def _config_attachment(manager, name: str, destination: str, path: Path) -> dict:
    try:
        path.relative_to(manager.root)
    except ValueError:
        return {}
    return manager.evidence.attach(
        path, name="%s-%s" % (name, Path(destination).name),
        role="server-config", description="captured config %s" % destination,
    )


def _rendered_checksum(item, attachment: dict) -> str:
    return item.rendered_sha256 if item else str(attachment.get("sha256", ""))


def _service_record(name: str, service, artifact, configs, log_source: str) -> dict:
    started = (
        datetime.fromtimestamp(service.started_at, timezone.utc).isoformat()
        if service.started_at else ""
    )
    return {
        "instance_id": service.instance_id, "pool_id": service.pool_id,
        "name": name, "scope": service.scope, "host": service.host,
        "ports": dict(service.ports), "config": str(service.config),
        "config_filename": service.config_filename or service.config.name,
        "config_sha256": service.config_sha256 or artifact.get("sha256", ""),
        "config_source_sha256": service.config_source_sha256,
        "config_declared_sha256": service.config_declared_sha256,
        "config_artifact": artifact, "configs": configs,
        "schemes": dict(service.schemes), "protocols": dict(service.protocols),
        "hosts": dict(service.hosts),
        "metadata": dict(service.metadata), "log": str(service.log),
        "log_source": log_source, "workdir": str(service.workdir),
        "started_at": started, "started_at_epoch": service.started_at,
    }


def service_records(manager) -> list[dict]:
    """Describe every server used by a case, including externally owned ones."""
    records = []
    for name, current in sorted(manager._services.items()):
        log_source = _log_source(manager, current)
        captured, artifact = _ensure_config_artifact(manager, name, current)
        configs = _config_records(manager, name, captured)
        records.append(_service_record(name, captured, artifact, configs, log_source))
    return records
