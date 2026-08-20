"""Paths, port helpers and spec constructors the catalogue shares.

Split out of the grown ``fleet_specs.py`` (TS-4 item 7).  These names were
what made ``fleet_specs_part2.py`` un-importable on its own: the shard
referred to them, the parent defined them, and only the ``exec`` in
``fleet_specs.py`` put them in one namespace.  They are ordinary imports
now.
"""

from __future__ import annotations

import os
import subprocess

import brix_suite.settings as S
from brix_suite.settings import TEST_ROOT
# The flat ``tests/`` tree, NOT this package's directory.  The stub-server
# argv below name scripts that live there, and the obvious
# ``dirname(__file__)`` would have quietly started resolving into
# ``brix_suite/catalogue`` — a path that exists, so every proc spec would
# have been handed an argv pointing at a file that does not.
from brix_suite.settings import TESTS_DIR as _TESTS_DIR
from brix_suite.registry import NginxInstanceSpec

__all__ = [
    "_CRL_DIR", "_CRL_RELOAD_DIR", "_JWKS_REFRESH_JSON", "_STAGE_HOOK",
    "_TESTS_DIR", "_data", "_ded", "_module_env", "_nginx_has_krb5",
    "_xrd_backend", "_xrdcp_bin",
]


def _data(name: str) -> str:
    return os.path.join(TEST_ROOT, name)


def _module_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for a ``python -m brix_suite.servers.*`` proc spec.

    ``-m`` puts the *current directory* on ``sys.path``, not the script's
    directory, so the stubs that used to self-locate from ``__file__`` need
    ``tests/`` named explicitly or the child dies on ``ModuleNotFoundError``
    before it binds — a start failure, but a confusing one.  Prepend rather
    than assign: a lane may already be running with a ``PYTHONPATH`` of its
    own and clobbering it would break the run in a different place.
    """
    existing = os.environ.get("PYTHONPATH", "")
    path = _TESTS_DIR + (os.pathsep + existing if existing else "")
    env = {"PYTHONPATH": path}
    if extra:
        env.update(extra)
    return env


# fleet_prep-owned session artifact locations (created before instances start,
# mirroring the top of bash ``start_all_dedicated``): CRL drop dirs and the
# jwks-refresh signing directory.  Encoded here so the CRL/jwks-refresh specs can
# reference them; ``fleet_prep.prepare`` (stage 4) is what actually populates them.
_CRL_DIR = _data("crls")
_CRL_RELOAD_DIR = _data("crl-reload")
_JWKS_REFRESH_JSON = os.path.join(TEST_ROOT, "tokens", "jwks-refresh", "jwks.json")
_STAGE_HOOK = os.path.join(TEST_ROOT, "dedicated", "prepare-command", "stage_hook.py")


def _xrdcp_bin() -> str:
    import shutil

    return shutil.which(os.environ.get("XRDCP_BIN", "xrdcp")) or "xrdcp"


def _ded(
    name: str,
    template: str,
    port: int,
    *,
    env: dict[str, str] | None = None,
    requires: tuple[str, ...] = (),
    reason: str = "",
    host: str | None = None,
) -> NginxInstanceSpec:
    """A fixed-role nginx from bash ``start_dedicated_nginx``.

    ``data_root`` is ``$TEST_ROOT/data-<name>``; readiness is a bare TCP-listen
    probe (bash set ``SKIP_XRDFS_CHECK=1`` for every dedicated instance, so the
    fleet never blocked on an xrdfs handshake here).  Per-instance overrides
    (``CMS_PORT``, ``UPSTREAM_PORT``, ``NGINX_S3_PORT``, …) ride in ``env`` exactly
    as they did in the bash subshell — ``session_template_values`` reads them.
    """
    return NginxInstanceSpec(
        name=name,
        template=template,
        port=port,
        protocol="root",
        host=host,
        data_root=_data(f"data-{name}"),
        readiness="tcp",
        env=dict(env or {}),
        requires=requires,
        tags=("dedicated",),
        reason=reason or f"Dedicated nginx role: {name}.",
    )


def _xrd_backend(name: str, port: int, *, reason: str = "") -> NginxInstanceSpec:
    """A stock-xrootd anonymous backend from bash ``start_extra_ref_anon``.

    Renders the same committed ``xrootd_ref.conf`` template the core anon
    reference uses, on its own ``data-<name>`` export.  These are the real
    upstream backends the ``upstream-*`` / proxy nginx roles forward to.
    """
    return NginxInstanceSpec(
        name=name,
        template="xrootd_ref.conf",
        port=port,
        protocol="root",
        data_root=_data(f"data-{name}"),
        kind="xrootd",
        readiness="tcp",
        tags=("dedicated",),
        reason=reason or f"Reference xrootd backend: {name}.",
    )


def _nginx_has_krb5() -> bool:
    """True iff the test nginx binary is linked against libkrb5.

    Mirrors bash ``start_krb5_tier``'s ``ldd $NGINX_BIN | grep libkrb5`` gate:
    when nginx was built without Kerberos, the whole krb5 tier is omitted so the
    fleet never tries to bring up a KDC + acceptor it cannot use.
    """
    if not os.path.exists(S.NGINX_BIN):
        return False
    # Probe the launcher's frozen copy, never the live build-tree binary: ldd
    # on objs/nginx caught mid-relink by a concurrent make reads a half-written
    # file, the gate flips False, and the krb5 specs silently vanish from the
    # registry (seen live as test_fleet_ports' unknown-spec-name failure).
    from server_launcher import _nginx_bin  # noqa: PLC0415 — lazy, avoids cycle
    try:
        out = subprocess.run(["ldd", _nginx_bin()], capture_output=True, text=True).stdout
    except OSError:
        return False
    return "libkrb5.so" in out
