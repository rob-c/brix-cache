"""Registry model for pytest-owned nginx test servers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import inspect
import json
import os
from pathlib import Path
from typing import Any

from settings import HOST, REGISTRY_MANIFEST, REGISTRY_ROOT, TEST_ROOT


@dataclass(frozen=True)
class NginxInstanceSpec:
    name: str
    template: str
    port: int | None = None
    protocol: str = "root"
    host: str | None = None  # endpoint/readiness address; None = settings.HOST
    data_root: str | None = None
    extra_ports: dict[str, int] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    template_values: dict[str, Any] = field(default_factory=dict)
    readiness: str = "tcp"
    requires: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    allow_remote_skip: bool = True
    reason: str = ""
    kind: str = "nginx"


@dataclass(frozen=True)
class CommandSpec:
    name: str
    argv: tuple[str, ...]
    env: dict[str, str] = field(default_factory=dict)
    timeout: float | None = None
    requires: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class ServerEndpoint:
    name: str
    host: str
    port: int | None
    protocol: str
    data_root: str
    extra_ports: dict[str, int]
    prefix: str
    config: str
    pidfile: str

    @property
    def url(self) -> str:
        if self.port is None:
            return ""
        host = f"[{self.host}]" if ":" in self.host else self.host
        scheme = {
            "root": "root",
            "roots": "roots",
            "http": "http",
            "https": "https",
            "s3": "http",
        }.get(self.protocol, self.protocol)
        suffix = "/" if scheme in {"root", "roots"} else ""
        return f"{scheme}://{host}:{self.port}{suffix}"


_SPECS: dict[str, NginxInstanceSpec] = {}
_COMMAND_SPECS: dict[str, CommandSpec] = {}
_REGISTRATION_SITES: dict[str, str] = {}
_MANIFEST: dict[str, Any] | None = None


def clear_registry() -> None:
    _SPECS.clear()
    _COMMAND_SPECS.clear()
    _REGISTRATION_SITES.clear()


def register_nginx(spec: NginxInstanceSpec) -> NginxInstanceSpec:
    if spec.name in _SPECS:
        prior = _REGISTRATION_SITES.get(spec.name, "unknown location")
        raise ValueError(f"server already registered: {spec.name} (first registered at {prior})")
    _SPECS[spec.name] = spec
    _REGISTRATION_SITES[spec.name] = _caller_site()
    return spec


def register_xrootd(spec: NginxInstanceSpec) -> NginxInstanceSpec:
    return register_nginx(spec)


def unregister(name: str) -> None:
    """Remove a single spec (per-test throwaway instances only).

    Session-scoped specs stay registered for the whole run; this exists so the
    per-test lifecycle harness can register uniquely-named instances and leave
    the registry exactly as it found it.
    """
    _SPECS.pop(name, None)
    _REGISTRATION_SITES.pop(name, None)


def replace_spec(spec: NginxInstanceSpec) -> NginxInstanceSpec:
    """Swap an already-registered spec in place, keeping its reserved port.

    Used by the lifecycle harness to change template values across a reload:
    the endpoint (and any OS-assigned port) must stay stable while the config
    contents change.
    """
    if spec.name not in _SPECS:
        raise KeyError(f"server not registered: {spec.name}")
    _SPECS[spec.name] = spec
    return spec


def register_command_suite(spec: CommandSpec) -> CommandSpec:
    if spec.name in _COMMAND_SPECS:
        prior = _REGISTRATION_SITES.get(f"cmd:{spec.name}", "unknown location")
        raise ValueError(
            f"command suite already registered: {spec.name} (first registered at {prior})"
        )
    _COMMAND_SPECS[spec.name] = spec
    _REGISTRATION_SITES[f"cmd:{spec.name}"] = _caller_site()
    return spec


def registered_specs() -> list[NginxInstanceSpec]:
    return [_SPECS[name] for name in dependency_order()]


def declared_ports(spec: NginxInstanceSpec) -> set[int]:
    """Every fixed port a spec statically claims: its own ``port`` plus any
    ``extra_ports`` values.

    Auto-assigned specs (``port is None``) contribute only their ``extra_ports``.
    A port reused *within one spec* — e.g. an XrdHttp instance that re-exposes
    its own listen port under an ``extra_ports`` template key — counts once, so
    only genuine cross-service reuse shows up as a conflict.
    """
    ports: set[int] = set()
    if spec.port is not None:
        ports.add(spec.port)
    ports.update(p for p in spec.extra_ports.values() if p is not None)
    return ports


def port_conflicts(
    specs: list[NginxInstanceSpec] | tuple[NginxInstanceSpec, ...] | None = None
) -> dict[int, list[str]]:
    """Map each fixed port claimed by more than one distinct spec to its
    claimant names (an empty dict means the fleet is collision-free).

    The registry pins most fleet instances to a hardcoded port so the 414
    fixed-port test files stay valid; a copy-paste slip that points two
    *different* services at the same port would let them race for the socket at
    start-all (whoever binds first wins, the other dies) — a silent, confusing
    failure. This surfaces every such collision statically, before any launch.
    """
    owners: dict[int, set[str]] = {}
    for spec in (specs if specs is not None else registered_specs()):
        for port in declared_ports(spec):
            owners.setdefault(port, set()).add(spec.name)
    return {port: sorted(names) for port, names in owners.items() if len(names) > 1}


def registered_command_suites() -> list[CommandSpec]:
    return [_COMMAND_SPECS[name] for name in sorted(_COMMAND_SPECS)]


def dependency_order() -> list[str]:
    ordered: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        if name in visiting:
            raise ValueError(f"cycle in server registry at {name}")
        spec = _SPECS.get(name)
        if spec is None:
            raise KeyError(f"unknown server dependency: {name}")
        visiting.add(name)
        for dep in spec.requires:
            visit(dep)
        visiting.remove(name)
        visited.add(name)
        ordered.append(name)

    for name in sorted(_SPECS):
        visit(name)
    return ordered


def dependency_closure(names) -> set[str]:
    """Every spec name reachable from ``names`` by following ``requires`` edges.

    Declaring a leaf spec implicitly declares the servers it subscribes up to
    (a cluster data-server's redirector, a KRB5 role's KDC), so the declaration
    gate credits the whole closure — a test that declares ``cluster-ds`` need not
    also spell out ``cluster-redir``.  Unknown names are returned as-is (the gate
    reports them; it does not resolve them) rather than raising, so a stale marker
    surfaces as a violation instead of crashing collection.
    """
    closure: set[str] = set()

    def add(name: str) -> None:
        if name in closure:
            return
        closure.add(name)
        spec = _SPECS.get(name)
        if spec is not None:
            for dep in spec.requires:
                add(dep)

    for name in names:
        add(name)
    return closure


def selected_specs(pytest_items, always_on=()) -> list[NginxInstanceSpec]:
    """Return dependency-ordered specs requested by collected pytest items.

    Tests opt into a subset with either ``@pytest.mark.registry_server("name")``
    or ``@pytest.mark.registry_servers("a", "b")``.  ``always_on`` names the
    servers that must boot regardless of any marker — the always-on backbone
    (core specs, reached through session fixtures) plus any dedicated spec a
    conftest fixture references — so subset selection never drops shared
    infrastructure the way a naive closure-of-declared would.

    With neither markers nor an ``always_on`` set (the pre-declaration state of
    the tree) every spec is returned, preserving the migration-safe behavior.
    """
    requested: set[str] = set(always_on)
    for item in pytest_items:
        for marker_name in ("registry_server", "registry_servers"):
            marker = item.get_closest_marker(marker_name)
            if marker:
                requested.update(str(arg) for arg in marker.args)

    if not requested:
        return registered_specs()

    closure = dependency_closure(requested)
    return [spec for spec in registered_specs() if spec.name in closure]


def endpoint_for(spec: NginxInstanceSpec) -> ServerEndpoint:
    data_root = spec.data_root or os.path.join(TEST_ROOT, f"data-{spec.name}")
    prefix = os.path.join(REGISTRY_ROOT, spec.name)
    port = spec.port
    if port is None:
        raise ValueError(
            f"server spec {spec.name!r} has no port. The dynamic free_port "
            f"fallback was removed in Phase 5 — every registered server must "
            f"declare a fixed port: a settings constant / fleet_ports ledger "
            f"entry (see fleet_lifecycle_ports for lifecycle-subject names) or "
            f"an explicit port= on the spec."
        )
    return ServerEndpoint(
        name=spec.name,
        host=spec.host or HOST,
        port=port,
        protocol=spec.protocol,
        data_root=data_root,
        extra_ports=dict(spec.extra_ports),
        prefix=prefix,
        config=os.path.join(prefix, "conf", "nginx.conf"),
        pidfile=os.path.join(prefix, "logs", "nginx.pid"),
    )


def build_manifest(
    extra: dict[str, Any] | None = None,
    specs: list[NginxInstanceSpec] | tuple[NginxInstanceSpec, ...] | None = None,
) -> dict[str, Any]:
    servers = {}
    for spec in (specs if specs is not None else registered_specs()):
        endpoint = endpoint_for(spec)
        servers[spec.name] = {
            "spec": asdict(spec),
            "endpoint": asdict(endpoint),
            "url": endpoint.url,
        }
    manifest = {
        "version": 1,
        "test_root": TEST_ROOT,
        "registry_root": REGISTRY_ROOT,
        "servers": servers,
    }
    if extra:
        manifest.update(extra)
    return manifest


def write_manifest(manifest: dict[str, Any] | None = None, path: str = REGISTRY_MANIFEST) -> dict[str, Any]:
    doc = manifest or build_manifest()
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    return doc


manifest_write = write_manifest


def read_manifest(path: str = REGISTRY_MANIFEST) -> dict[str, Any]:
    global _MANIFEST
    _MANIFEST = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_manifest(_MANIFEST)
    return _MANIFEST


manifest_read = read_manifest


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("version") != 1:
        raise ValueError("unsupported server registry manifest version")
    if not isinstance(manifest.get("servers"), dict):
        raise ValueError("server registry manifest lacks a servers object")


def get_server(name: str) -> ServerEndpoint:
    spec = _SPECS.get(name)
    if spec is not None:
        return endpoint_for(spec)
    manifest = _MANIFEST
    if manifest is None and os.path.exists(REGISTRY_MANIFEST):
        manifest = read_manifest()
    if manifest is not None:
        try:
            return ServerEndpoint(**manifest["servers"][name]["endpoint"])
        except KeyError as exc:
            raise KeyError(f"server not in registry manifest: {name}") from exc
    raise KeyError(f"server not registered: {name}")


server = get_server


def _caller_site() -> str:
    for frame in inspect.stack()[2:]:
        filename = frame.filename
        if not filename.endswith("server_registry.py"):
            return f"{filename}:{frame.lineno}"
    return "unknown location"
