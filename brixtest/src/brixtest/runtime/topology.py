"""Bridge collection-derived server instances into isolated case helpers."""

from __future__ import annotations

import dataclasses
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from brixtest.evidence.model import stable_id
from brixtest.errors import SpecError


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
        services[str(name)] = service_type(
            name=str(name), host=str(row["host"]),
            ports={str(role): int(port) for role, port in row["ports"].items()},
            config=Path(str(row["config"])), log=Path(str(row["log"])),
            workdir=Path(str(row["workdir"])),
            instance_id=str(row["instance_id"]), scope=str(row.get("scope", "session")),
            started_at=float(row.get("started_at_epoch", 0)),
            pool_id=str(row.get("pool_id", "")),
            config_filename=str(row.get("config_filename", "")),
            config_sha256=str(row.get("config_sha256", "")),
            config_source_sha256=str(row.get("config_source_sha256", "")),
            config_declared_sha256=str(row.get("config_declared_sha256", "")),
            config_artifact=(
                dict(row.get("config_artifact", {}))
                if isinstance(row.get("config_artifact", {}), dict) else {}
            ),
            configs={
                str(destination): Path(str(path))
                for destination, path in row.get("configs", {}).items()
            } if isinstance(row.get("configs", {}), dict) else {},
            schemes={
                str(role): str(scheme)
                for role, scheme in row.get("schemes", {}).items()
            } if isinstance(row.get("schemes", {}), dict) else {},
            protocols={
                str(role): str(protocol)
                for role, protocol in row.get("protocols", {}).items()
            } if isinstance(row.get("protocols", {}), dict) else {},
            metadata=(
                dict(row.get("metadata", {}))
                if isinstance(row.get("metadata", {}), dict) else {}
            ),
        )
    return services


def instance_for(attempt_id: str, server_name: str) -> str:
    return stable_id("case-server", attempt_id, server_name)


def service_records(manager) -> list[dict]:
    """Describe every server used by a case, including externally owned ones."""
    records = []
    for name, service in sorted(manager._services.items()):
        try:
            log_source = str(service.log.relative_to(manager.root))
        except ValueError:
            log_source = str(service.log)
        config_artifact = dict(service.config_artifact)
        try:
            service.config.relative_to(manager.root)
            local_config = True
        except ValueError:
            local_config = False
        if local_config and not config_artifact:
            config_artifact = manager.evidence.attach(
                service.config, name="%s-%s" % (name, service.config.name),
                role="server-config", description="effective config used to launch %s" % name,
            )
            controller = getattr(service, "_controller", None)
            service = dataclasses.replace(service, config_artifact=config_artifact)
            if controller is not None:
                object.__setattr__(service, "_controller", controller)
            manager._services[name] = service
        config_records = []
        captured = {
            item.filename: item for item in manager.config_store.all(name)
        } if name in manager.config_store._sets else {}
        for destination, path in service.configs.items():
            item = captured.get(destination)
            attachment = {}
            try:
                path.relative_to(manager.root)
                attachment = manager.evidence.attach(
                    path, name="%s-%s" % (name, Path(destination).name),
                    role="server-config", description="captured config %s" % destination,
                )
            except ValueError:
                pass
            config_records.append({
                "destination": destination, "path": str(path),
                "rendered_sha256": item.rendered_sha256 if item else attachment.get("sha256", ""),
                "source_sha256": item.source_sha256 if item else "",
                "declared_sha256": item.declared_sha256 if item else "",
                "artifact": attachment,
            })
        records.append({
            "instance_id": service.instance_id,
            "pool_id": service.pool_id,
            "name": name,
            "scope": service.scope,
            "host": service.host,
            "ports": dict(service.ports),
            "config": str(service.config),
            "config_filename": service.config_filename or service.config.name,
            "config_sha256": service.config_sha256 or config_artifact.get("sha256", ""),
            "config_source_sha256": service.config_source_sha256,
            "config_declared_sha256": service.config_declared_sha256,
            "config_artifact": config_artifact,
            "configs": config_records,
            "schemes": dict(service.schemes),
            "protocols": dict(service.protocols),
            "metadata": dict(service.metadata),
            "log": str(service.log),
            "log_source": log_source,
            "workdir": str(service.workdir),
            "started_at": (
                datetime.fromtimestamp(service.started_at, timezone.utc).isoformat()
                if service.started_at else ""
            ),
            "started_at_epoch": service.started_at,
        })
    return records
