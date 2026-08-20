"""The scenario registry and the two entry points every consumer calls.

``_BUILDERS`` is the single place a scenario name becomes a builder; adding a
scenario means adding a row here and a function in :mod:`scenarios`.
"""

from __future__ import annotations

from pathlib import Path

from brix_suite.security.x509.cadir import (
    CA_DN,
    Scenario,
)
from brix_suite.security.x509.scenarios import (
    _cad_expired_ca,
    _cad_md5_only,
    _cad_sha1_only,
    _crl_expired,
    _crl_revoked_eec,
    _px_limited_to_full,
    _px_noncritical_pci,
    _px_rfc3820_ok,
    _sp_in_namespace,
    _sp_no_policy,
    _sp_out_of_namespace,
    _sp_proxy_cn_exempt,
    _sp_wrong_ca_block,
)

# --------------------------------------------------------------------------
# Catalogue + entry points
# --------------------------------------------------------------------------

_BUILDERS = {
    "sp_in_namespace": _sp_in_namespace,
    "sp_out_of_namespace": _sp_out_of_namespace,
    "sp_wrong_ca_block": _sp_wrong_ca_block,
    "sp_no_policy": _sp_no_policy,
    "sp_proxy_cn_exempt": _sp_proxy_cn_exempt,
    "px_rfc3820_ok": _px_rfc3820_ok,
    "px_limited_to_full": _px_limited_to_full,
    "px_noncritical_pci": _px_noncritical_pci,
    "crl_revoked_eec": _crl_revoked_eec,
    "crl_expired": _crl_expired,
    "cad_md5_only": _cad_md5_only,
    "cad_sha1_only": _cad_sha1_only,
    "cad_expired_ca": _cad_expired_ca,
}

BASELINE_SPEC = {"builder": "sp_in_namespace"}


def forge_scenario(root: Path, name: str, spec: dict | None = None) -> Scenario:
    """Materialise scenario `name` under root.  spec may override the builder."""
    builder_name = (spec or {}).get("builder", name)
    return _BUILDERS[builder_name](Path(root))


def forge_all(root: Path) -> dict[str, Scenario]:
    """Materialise every catalogued scenario; returns name→Scenario."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    return {name: builder(root) for name, builder in _BUILDERS.items()}


def rewrite_signing_policy(sc: Scenario, globs_quoted: str) -> None:
    """Rewrite the scenario's signing-policy cond_subjects (hot-reload test)."""
    pol = sc.ca_dir / "signing-policy"
    pol.write_text(
        f"access_id_CA    X509    '{CA_DN}'\n"
        f"pos_rights      globus  CA:sign\n"
        f"cond_subjects   globus  '{globs_quoted}'\n",
        encoding="utf-8")
