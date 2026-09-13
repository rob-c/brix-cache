"""Resolve local binary captures into run-owned Minikube images."""

from __future__ import annotations

import os
from typing import Mapping, Optional, Sequence

from brixtest.design import Binary, Server
from brixtest.errors import SpecError
from brixtest.runtime.images import OCIImageStore
from brixtest.runtime.kubernetes_preparation import _referenced_names
from brixtest.testing.config import BrixTestConfig


def _server_binaries(owner, server: Server) -> tuple[Binary, ...]:
    selected = _command_binaries(server)
    selected.update(_referenced_binaries(owner, server))
    return tuple(selected[name] for name in sorted(selected))


def _command_binaries(server: Server) -> dict[str, Binary]:
    selected = {item.name: item for item in server.binaries}
    selected.update({
        item.name: item for item in server.command if isinstance(item, Binary)
    })
    return selected


def _referenced_binaries(owner, server: Server) -> dict[str, Binary]:
    definition = getattr(owner, "definition", None)
    declared = {
        item.name: item for item in getattr(definition, "binaries", ())
    }
    return {
        name: declared[name] for name in _referenced_names(
            server, "binary", getattr(definition, "binaries", ()),
            getattr(owner, "source_root", None),
        )
    }


def _needs_generated(owner, declaration: Binary) -> bool:
    captured = owner.binary_store.get(declaration.name)
    return declaration.path is not None and (
        declaration.image is None or captured.overridden
    )


def _base_image(server: Server, binaries: Sequence[Binary], config: Optional[BrixTestConfig] = None) -> str:
    direct = server.placement.image or server.image
    if direct:
        return direct
    images = {item.image for item in binaries if item.image}
    if len(images) > 1:
        raise SpecError(
            "server %s generated image" % server.name, sorted(images),
            "needs at most one explicit base image",
        )
    if config is not None and config.oci_base_image:
        return config.oci_base_image
    return os.environ.get("BRIXTEST_OCI_BASE_IMAGE", "")


def _selected_server_binaries(owner, servers: Sequence[Server]) -> dict[str, tuple[Binary, ...]]:
    selected = {}
    for server in servers:
        values = tuple(
            item for item in _server_binaries(owner, server)
            if _needs_generated(owner, item)
        )
        if values:
            selected[server.name] = values
    return selected


def _registry(config: Optional[BrixTestConfig] = None) -> str:
    if config is not None and config.oci_registry:
        return config.oci_registry
    return os.environ.get("BRIXTEST_OCI_REGISTRY", "")


def _require_image_target(owner, registry: str) -> None:
    if owner.backend_name == "minikube" or registry:
        return
    raise SpecError(
        "generated OCI images", owner.backend_name,
        "local Binary capture needs backend='minikube' or a configured "
        "BriXTest OCI registry for remote Kubernetes",
    )


def _build_server_image(store, owner, server: Server, declarations: Sequence[Binary], config=None):
    captured = tuple(owner.binary_store.get(item.name) for item in declarations)
    return store.build(
        server.name, captured,
        base_image=_base_image(server, _server_binaries(owner, server), config=config),
    )


def prepare_server_images(
    backend, servers: Sequence[Server], config: Optional[BrixTestConfig] = None,
) -> tuple[Mapping[str, str], Mapping[str, Mapping[str, str]]]:
    """Build images only for servers that consume local-only/overridden binaries.
    
    Args:
        backend: The backend owning the servers.
        servers: Sequence of server declarations.
        config: Optional configuration object. If not provided, reads from environment.
    """
    owner = backend.owner
    selected = _selected_server_binaries(owner, servers)
    if not selected:
        return {}, {}
    registry = _registry(config)
    _require_image_target(owner, registry)
    store = OCIImageStore(
        owner, backend.context or "brixtest", registry=registry,
    )
    images = {}
    paths = {}
    by_name = {server.name: server for server in servers}
    for name, declarations in selected.items():
        server = by_name[name]
        generated = _build_server_image(store, owner, server, declarations, config=config)
        images[name] = generated.tag
        paths[name] = generated.paths
    return images, paths
