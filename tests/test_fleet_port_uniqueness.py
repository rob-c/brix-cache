"""Fleet port-collision guards — static uniqueness + a live EADDRINUSE proof.

Two fleet servers pinned to the same listen port collide the moment ``start-all``
brings them up concurrently: whichever binds first wins the socket, the other
dies with ``bind() to 0.0.0.0:<port> failed (98: Address already in use)``.  The
race makes the loser look like a flaky startup rather than the copy-paste port
slip it actually is.

``test_server_registry_lint.py`` already guards *spec-vs-spec* collisions via
``server_registry.port_conflicts``.  This file adds the two gaps that guard left
open:

* the mesh planes — ``cms_mesh_lib.PORTS`` and ``hybrid_mesh_lib.PORTS`` boot
  alongside the registry fleet under ``start-all`` but are not registry specs, so
  a fleet port that drifts into a mesh range is invisible to the spec-only check;
* a *runtime* demonstration that the failure is real and detectable — squat a
  port, start a server on it, and watch nginx refuse to bind with the exact
  ``Address already in use`` message the static guards exist to prevent.
"""

from __future__ import annotations

import os
import socket

import pytest

import settings


# --------------------------------------------------------------------------- #
# Static guard: every listen port is owned by exactly one service, across the   #
# registry fleet AND both mesh planes that share the start-all lifecycle.        #
# --------------------------------------------------------------------------- #
def _port_owners() -> dict[int, list[str]]:
    """Map every statically-declared listen port to its claimant(s).

    Spans the three planes that ``manage_test_servers start-all`` brings up in
    one shared ``/tmp/xrd-test`` session: the registry fleet specs plus the CMS
    and hybrid interop meshes.  Within-spec reuse (a service re-exposing its own
    listen port under an ``extra_ports`` key) is folded to a single owner by
    ``declared_ports``, so only genuine cross-service reuse surfaces.
    """
    import cms_mesh_lib
    import fleet_specs
    import hybrid_mesh_lib
    from server_registry import declared_ports

    owners: dict[int, set[str]] = {}

    def claim(port: int | None, who: str) -> None:
        if port is None:
            return
        owners.setdefault(int(port), set()).add(who)

    # The ``cms-mesh``/``hybrid-mesh`` fleet specs are ``external`` orchestrators
    # that boot a mesh plane and pin their port to that mesh's real front door
    # (``_CMS_PORTS["a_mgr"]`` / ``_HYBRID_PORTS["a_data"]``, imported straight
    # from the mesh libs) so ``endpoint("…-mesh").port`` is a stable fixed number.
    # They are a registry HANDLE to the same socket the mesh loop below claims
    # authoritatively — not a second listener — so counting them fleet-side would
    # be a spurious self-collision.  The mesh-plane loops own those ports.
    _MESH_ORCHESTRATORS = {"cms-mesh", "hybrid-mesh"}
    for spec in fleet_specs._all_specs():
        if spec.name in _MESH_ORCHESTRATORS:
            continue
        for port in declared_ports(spec):
            claim(port, f"fleet:{spec.name}")
    for key, port in cms_mesh_lib.PORTS.items():
        claim(port, f"cms-mesh:{key}")
    for key, port in hybrid_mesh_lib.PORTS.items():
        claim(port, f"hybrid-mesh:{key}")

    return {port: sorted(who) for port, who in owners.items() if len(who) > 1}


def test_fleet_and_mesh_ports_are_globally_unique():
    """No listen port is claimed by two distinct services across all planes.

    Extends the spec-only lint check to the CMS and hybrid meshes, which boot in
    the same session and would otherwise race the fleet for a shared socket.  A
    duplicate here is exactly the ``Address already in use`` bind failure that
    ``test_duplicate_listen_port_reports_address_already_in_use`` reproduces.
    """
    conflicts = _port_owners()
    assert not conflicts, (
        "listen-port collisions between distinct services — each one races for "
        "the socket at start-all and the loser dies with 'bind() ... (98: "
        "Address already in use)':\n"
        + "\n".join(
            f"  port {port}: {', '.join(names)}"
            for port, names in sorted(conflicts.items())
        )
    )


def test_xrdhttp_https_endpoint_aliases_the_single_tls_listener():
    """davs:// and https:// are the *same* XrdHttp port, so they must stay equal.

    The reference xrootd daemon opens a single TLS listener (``xrd.protocol
    XrdHttp:{HTTP_PORT}``); ``XRDHTTP_HTTPS_PORT`` is a davs call-site alias whose
    default derives from ``XRDHTTP_HTTP_PORT`` precisely so the two cannot drift
    onto different numbers and point ``test_xrdhttp_auth`` at a dead port.  This
    pins that intended aliasing so a future edit re-introducing an independent
    literal is caught here rather than as a mystery davs connection refusal.
    """
    assert settings.XRDHTTP_HTTPS_PORT == settings.XRDHTTP_HTTP_PORT


# --------------------------------------------------------------------------- #
# Runtime proof: a genuine port collision surfaces as EADDRINUSE from nginx.     #
# --------------------------------------------------------------------------- #
def test_duplicate_listen_port_reports_address_already_in_use(tmp_path, monkeypatch):
    """Starting a server on an already-bound port fails with 'Address already in use'.

    Squats a free port with a plain listening socket (no ``SO_REUSEPORT``), then
    drives the real ``RegistryLauncher`` to start an nginx instance pinned to that
    same port.  ``nginx -t`` passes (config validation opens no listeners); the
    master then tries to bind, hits the squatter, and exits non-zero — which the
    launcher raises as a ``RegistryCommandFailure`` carrying nginx's bind error.
    This is the concrete failure the static uniqueness guards above prevent.
    """
    from server_launcher import RegistryCommandFailure, RegistryLauncher
    from server_registry import (
        NginxInstanceSpec,
        clear_registry,
        register_nginx,
    )

    if not os.access(settings.NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {settings.NGINX_BIN}")

    # Squat a free port with a real listener.  Bind the wildcard address nginx
    # itself binds (0.0.0.0) and do NOT set SO_REUSEPORT, so the second bind is
    # guaranteed to collide rather than load-balance.
    squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        squatter.bind(("", 0))
        squatted_port = squatter.getsockname()[1]
        squatter.listen(1)

        clear_registry()
        monkeypatch.setattr("server_registry.REGISTRY_ROOT", str(tmp_path / "registry"))
        monkeypatch.setattr("server_launcher.REGISTRY_STRICT_TEMPLATES", True)
        spec = register_nginx(
            NginxInstanceSpec(
                name="port-collision-probe",
                template="nginx_registry_smoke.conf",
                port=squatted_port,
                data_root=str(tmp_path / "data"),
                reason="deliberate port collision to prove EADDRINUSE detection",
            )
        )
        launcher = RegistryLauncher()

        with pytest.raises(RegistryCommandFailure) as excinfo:
            launcher.start(spec)

        assert "Address already in use" in str(excinfo.value), (
            "expected nginx to refuse the squatted port with an EADDRINUSE bind "
            f"error, got:\n{excinfo.value}"
        )
        assert str(squatted_port) in str(excinfo.value)
    finally:
        squatter.close()
        clear_registry()
