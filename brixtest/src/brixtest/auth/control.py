"""Live issuance, rotation, and revocation for materialized auth stacks."""

from __future__ import annotations

import hashlib
import json
import secrets
import shutil
import stat
import time
from pathlib import Path
from typing import Mapping, Optional, Sequence, TYPE_CHECKING

from brixtest.auth.pki import OpenSSL
from brixtest.auth.token import issue_token
from brixtest.auth.token_keys import write_keyset
from brixtest.errors import SpecError

if TYPE_CHECKING:
    from brixtest.auth.store import MaterializedAuth


def write_token_state(root: Path, recipe) -> Path:
    """Persist the non-secret inputs required for controlled token issuance."""
    state = root / "authority-state.json"
    _write_json(state, {
        "schema": 1, "version": 1, "algorithm": recipe.algorithm,
        "key_id": recipe.key_id, "key_bits": recipe.key_bits,
        "issuer": recipe.issuer, "audience": recipe.audience,
        "subject": recipe.subject, "scopes": list(recipe.scopes),
        "claims": dict(recipe.claims), "lifetime": recipe.lifetime,
    })
    return state


def issue(item: "MaterializedAuth", *, subject: str = "", scopes: Sequence[str] = ()) -> str:
    """Issue and retain one token from the authority's current signing version."""
    state = _token_state(item)
    signing = _signing_material(item, state)
    selected_scopes = tuple(scopes) or tuple(state["scopes"])
    token = issue_token(
        **signing, issuer=str(state["issuer"]), audience=str(state["audience"]),
        subject=subject or str(state["subject"]), scopes=selected_scopes,
        claims=state["claims"], lifetime=int(state["lifetime"]),
        algorithm=str(state["algorithm"]), key_id=str(state["key_id"]),
    )
    issued = item.root / "issued"
    issued.mkdir(exist_ok=True)
    path = issued / ("token-%06d.jwt" % (len(tuple(issued.glob("token-*.jwt"))) + 1))
    path.write_text(token)
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    _event(item, "issued", {
        "version": state["version"], "key_id": state["key_id"],
        "token_sha256": _sha256(path), "subject": subject or state["subject"],
    })
    return token


def rotate(item: "MaterializedAuth", *, key_id: str = "") -> Mapping[str, object]:
    """Replace token signing material and publish the next verifiable version."""
    state = _token_state(item)
    version = int(state["version"]) + 1
    selected_key_id = key_id or "%s-v%d" % (state["key_id"], version)
    algorithm = str(state["algorithm"])
    if algorithm == "HS256":
        _replace_secret(item.path("secret"))
    else:
        write_keyset(item.root, algorithm, int(state["key_bits"]), selected_key_id)
    state.update({"version": version, "key_id": selected_key_id})
    _write_json(item.path("state"), state)
    public = _public_checksums(item)
    payload = {"version": version, "key_id": selected_key_id, **public}
    _event(item, "rotated", payload)
    return payload


def revoke(item: "MaterializedAuth", certificate: str = "client_cert") -> Path:
    """Revoke one issued TLS/GSI certificate and atomically republish its CRL."""
    if item.kind not in ("tls", "voms"):
        raise SpecError("auth revoke", item.kind, "requires a TLS or VOMS authority")
    if certificate not in ("client_cert", "host_cert", "voms_cert"):
        raise SpecError(
            "auth revoke certificate", certificate,
            "must be client_cert, host_cert, or voms_cert",
        )
    selected = item.path(certificate)
    openssl = OpenSSL()
    openssl.run(
        "ca", "-batch", "-config", str(item.root / "openssl.cnf"),
        "-revoke", str(selected),
    )
    crl = item.path("crl")
    temporary = item.root / "ca.crl.next"
    openssl.run(
        "ca", "-batch", "-config", str(item.root / "openssl.cnf"),
        "-gencrl", "-out", str(temporary),
    )
    temporary.replace(crl)
    _publish_crl(openssl, crl, item.path("trust_dir"))
    _event(item, "revoked", {
        "certificate": certificate, "certificate_sha256": _sha256(selected),
        "crl_sha256": _sha256(crl),
    })
    return crl


def record_availability(item: "MaterializedAuth", state: str) -> None:
    """Append a managed-service availability transition without secret data."""
    _event(item, state, {"kind": item.kind})


def _token_state(item: "MaterializedAuth") -> dict[str, object]:
    if item.kind != "token":
        raise SpecError("auth token control", item.kind, "requires a token authority")
    return json.loads(item.path("state").read_text())


def _signing_material(item: "MaterializedAuth", state: Mapping[str, object]) -> dict:
    if state["algorithm"] == "HS256":
        return {"secret": item.path("secret").read_text()}
    return {"private_key": item.path("private_key").read_bytes()}


def _replace_secret(path: Path) -> None:
    path.write_text(secrets.token_urlsafe(32))
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _publish_crl(openssl: OpenSSL, crl: Path, trust: Path) -> None:
    crl_hash = openssl.run("crl", "-in", str(crl), "-noout", "-hash")
    destination = trust / (crl_hash + ".r0")
    temporary = trust / (crl_hash + ".r0.next")
    shutil.copy2(crl, temporary)
    temporary.replace(destination)


def _public_checksums(item: "MaterializedAuth") -> dict[str, str]:
    names = ("public_key", "jwks") if item.kind == "token" else ("crl", "ca_cert")
    return {
        "%s_sha256" % name: _sha256(item.path(name))
        for name in names if name in item.files
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _event(item: "MaterializedAuth", action: str, values: Mapping[str, object]) -> None:
    payload = {"action": action, "time": time.time(), **values}
    with (item.root / "authority-events.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def _write_json(path: Path, value: Mapping[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".next")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


__all__ = ["issue", "record_availability", "revoke", "rotate", "write_token_state"]
