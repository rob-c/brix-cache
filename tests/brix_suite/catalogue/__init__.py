"""The declarative catalogue of the registry-native test fleet.

The pure-Python successor to the bash ``start_all_dedicated`` table in
``tests/lib/dedicated.sh`` and the reference-server launchers in
``tests/lib/{refxrootd,xrdhttp}.sh``.  Every fixed-role instance the old
fleet brought up is an :class:`InstanceSpec` here, registered by
:func:`register_full_fleet` and launched by ``RegistryLauncher``.

Ports are pinned to the ``settings`` constants (not OS-assigned) so
endpoints stay byte-identical to the pre-migration fleet — the 414 test
files that import those fixed ports need no change.

TS-4 item 7 assembled this package out of three flat modules.
``fleet_specs.py`` had grown past the file-size line and was split by
*exec*: ``fleet_specs_part2.py`` was compiled into its parent's
namespace, which is why the shard referenced ``_data``, ``_ded`` and
``_CRL_DIR`` without importing them — and why importing the shard on its
own raised ``NameError`` from ``ha_specs()``.  The split is by topic now,
with ordinary imports:

    _shared     paths, the ``_ded``/``_xrd_backend`` constructors, the
                krb5 link gate
    core        the shared nginx + reference xrootd servers
    backends    stock-xrootd anon backends (upstream/proxy targets)
    support     stub procs, the CMS and hybrid meshes, the krb5 tier
    ha          the high-availability pair
    dedicated   the fixed-role dedicated nginx table
    values      session-wide template values for config rendering

Every public name the three flat modules exported is re-exported here, so
``fleet_specs``, ``fleet_specs_part2`` and ``fleet_values`` can be §10.2
shims onto this one namespace.
"""

from __future__ import annotations

# ``InstanceSpec`` and its historical alias are re-exported because the flat
# ``fleet_specs`` module carried them as attributes; the topic modules below
# spell only the alias, which is what every spec literal in the catalogue uses.
from brix_suite.registry import (  # noqa: F401 — re-exported
    InstanceSpec,
    NginxInstanceSpec,
    register_nginx,
)

from brix_suite.catalogue._shared import (  # noqa: F401 — re-exported
    _CRL_DIR,
    _CRL_RELOAD_DIR,
    _JWKS_REFRESH_JSON,
    _STAGE_HOOK,
    _TESTS_DIR,
    _data,
    _ded,
    _nginx_has_krb5,
    _xrd_backend,
    _xrdcp_bin,
)
from brix_suite.catalogue.backends import xrootd_backend_specs
from brix_suite.catalogue.core import core_specs
from brix_suite.catalogue.dedicated import dedicated_specs
from brix_suite.catalogue.ha import ha_specs
from brix_suite.catalogue.support import support_specs
from brix_suite.catalogue.values import _int, session_template_values  # noqa: F401

__all__ = [
    "core_specs",
    "dedicated_specs",
    "ha_specs",
    "register_full_fleet",
    "session_template_values",
    "support_specs",
    "xrootd_backend_specs",
]


def register_full_fleet() -> None:
    """Register every fixed-role fleet instance with the server registry.

    Idempotent: a name already present (e.g. re-entry within a session) is
    skipped rather than raising, so repeated calls are safe.
    """
    # Deliberately the canonical module, not the ``server_registry`` shim the
    # pre-TS-4 body imported: the shim only exists for the flat ``tests/``
    # tree, and the catalogue must import cleanly without it on ``sys.path``.
    from brix_suite.registry import _SPECS  # noqa: PLC0415 — presence check only

    for spec in _all_specs():
        if spec.name in _SPECS:
            continue
        register_nginx(spec)


def _all_specs() -> list[NginxInstanceSpec]:
    specs: list[NginxInstanceSpec] = []
    specs += core_specs()
    specs += xrootd_backend_specs()
    specs += support_specs()
    specs += dedicated_specs()
    specs += ha_specs()
    return specs
