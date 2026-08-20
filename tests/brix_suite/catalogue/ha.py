"""The high-availability pair and its shared-state peers.

Split out of ``fleet_specs_part2.py`` (TS-4 item 7).  This module is the
reason the item exists: as a shard it referenced ``_data`` from a parent
namespace it did not import, so ``import fleet_specs_part2;
ha_specs()`` raised ``NameError: _data`` for anything that reached it
without going through ``fleet_specs``.
"""

from __future__ import annotations

import brix_suite.settings as S
from brix_suite.registry import NginxInstanceSpec

from brix_suite.catalogue._shared import _data

__all__ = ["ha_specs"]


def ha_specs() -> list[NginxInstanceSpec]:
    """HA cluster: two nginx instances on the SHARED export + an haproxy in front.

    Unlike the dedicated roles these serve the main ``$TEST_ROOT/data`` export
    (bash captured the global ``DATA_DIR`` before the subshell), so they are NOT
    tagged ``dedicated`` — no per-instance data tree, no export rehoming. haproxy
    is optional: it skips cleanly when the binary is absent (bash gated on
    ``have_cmd haproxy``).
    """
    shared_data = _data("data")
    ha1 = NginxInstanceSpec(
        name="ha-nginx1", template="nginx_ha_instance.conf", port=S.HA_NGINX1_PORT,
        protocol="root", data_root=shared_data, readiness="tcp", tags=("ha",),
        reason="HA cluster member 1 (shared export).",
    )
    ha2 = NginxInstanceSpec(
        name="ha-nginx2", template="nginx_ha_instance.conf", port=S.HA_NGINX2_PORT,
        protocol="root", data_root=shared_data, readiness="tcp", tags=("ha",),
        reason="HA cluster member 2 (shared export).",
    )
    haproxy = NginxInstanceSpec(
        name="ha-haproxy", template="haproxy.cfg", port=S.HA_HAPROXY_PORT,
        protocol="root", data_root=shared_data, kind="haproxy", readiness="tcp",
        requires=("ha-nginx1", "ha-nginx2"),
        template_values={
            "BIND_HOST": "127.0.0.1",  # net-literal-allow: generated local HA config
            "MAP_A_HOST": "127.0.0.1", "MAP_A_PORT": str(S.HA_NGINX1_PORT),  # net-literal-allow: generated local HA config
            "MAP_B_HOST": "127.0.0.1", "MAP_B_PORT": str(S.HA_NGINX2_PORT),  # net-literal-allow: generated local HA config
        },
        tags=("ha",),
        reason="HA failover front (haproxy over ha-nginx1/2).",
    )
    return [ha1, ha2, haproxy]
