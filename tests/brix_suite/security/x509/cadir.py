"""Hashed CA directories, ``.signing_policy`` text, and the ``Scenario`` box.

The head of ``x509forge_part2.py``, moved verbatim: everything between a
``Cert`` and a scenario builder that wants somewhere to put one.
"""

from __future__ import annotations

import functools
import json
import subprocess

from dataclasses import dataclass, field
from pathlib import Path

from brix_suite.security.x509.primitives import Cert

# --------------------------------------------------------------------------
# DER helpers (proxyCertInfo has no native cryptography builder)
# --------------------------------------------------------------------------

@functools.lru_cache(maxsize=8192)
def _openssl_hashes_cached(pem: bytes) -> tuple[str, str]:
    """Compute (subject_hash, subject_hash_old) for a CA cert, forking openssl.

    Keyed on the cert PEM bytes: the subject hash is a pure function of the
    certificate's subject DN, so identical content always yields identical
    hashes.  build_all(ALL_CLAUSES) places the same handful of CAs across
    hundreds of clause rows; without this memo each placement forked openssl
    twice, and the resulting fork-storm pushed the conformance corpus past the
    per-test timeout under load.  openssl reads the cert from stdin so no temp
    path is needed (and the cache key is content, not a per-run temp path).
    """
    def h(flag: str) -> str:
        r = subprocess.run(
            ["openssl", "x509", "-noout", flag],
            input=pem, capture_output=True, check=True)
        return r.stdout.decode().strip()
    return h("-subject_hash"), h("-subject_hash_old")


def _openssl_hashes(cert_path: Path) -> tuple[str, str]:
    return _openssl_hashes_cached(cert_path.read_bytes())


def write_hashed_ca_dir(ca_dir: Path, ca: Cert, *, policy_text: str | None = None,
                        crls: dict[str, bytes] | None = None,
                        links: str = "both") -> None:
    """Write ca.pem + hash links (+ optional signing_policy + CRLs) into ca_dir.

    links: "both" (new+old hash), "new", or "old" — for CAD hash-link tests.
    """
    ca_dir.mkdir(parents=True, exist_ok=True)
    ca_pem = ca_dir / "ca.pem"
    ca_pem.write_bytes(ca.pem)

    new_hash, old_hash = _openssl_hashes(ca_pem)
    chosen = {"both": {new_hash, old_hash}, "new": {new_hash},
              "old": {old_hash}}[links]
    policy_file = _write_policy(ca_dir, policy_text)
    _write_hash_links(ca_dir, chosen, policy_file)
    _write_crls(ca_dir, new_hash, crls)


def _write_policy(ca_dir, policy_text):
    if policy_text is None:
        return None
    policy_file = ca_dir / "signing-policy"
    policy_file.write_text(policy_text, encoding="utf-8")
    return policy_file


def _write_hash_links(ca_dir, hashes, policy_file):
    for cert_hash in hashes:
        _symlink("ca.pem", ca_dir / f"{cert_hash}.0")
        if policy_file is not None:
            _symlink("signing-policy", ca_dir / f"{cert_hash}.signing_policy")


def _write_crls(ca_dir, cert_hash, crls):
    for suffix, pem in (crls or {}).items():
        (ca_dir / f"{cert_hash}.{suffix}").write_bytes(pem)


def _symlink(target: str, link: Path) -> None:
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(target)


def signing_policy_text(ca_dn: str, globs: list[str], *, granted: bool = True) -> str:
    quoted = " ".join(f'"{g}"' for g in globs)
    rights = "pos_rights" if granted else "neg_rights"
    return (
        f"access_id_CA    X509    '{ca_dn}'\n"
        f"{rights}      globus  CA:sign\n"
        f"cond_subjects   globus  '{quoted}'\n"
    )


# --------------------------------------------------------------------------
# Scenario model
# --------------------------------------------------------------------------

@dataclass
class Scenario:
    name: str
    dir: Path
    ca_dir: Path
    credentials: dict[str, Path] = field(default_factory=dict)
    manifest: list[dict] = field(default_factory=list)
    objects: dict = field(default_factory=dict)   # in-memory Certs (CA, EECs)

    def write_credential(self, name: str, chain: list[Cert],
                         key_of: Cert) -> Path:
        """Write a cred file: leaf-first cert chain + private key."""
        p = self.dir / f"{name}.pem"
        blob = b"".join(c.pem for c in chain) + key_of.key_pem
        p.write_bytes(blob)
        p.chmod(0o600)
        self.credentials[name] = p
        return p

    def add_manifest(self, credential: str, expected: str, *,
                     surface: str = "both", reason: str = "",
                     spec_ref: str = "") -> None:
        self.manifest.append({
            "scenario": self.name, "credential": credential,
            "surface": surface, "expected": expected,
            "reason": reason, "spec_ref": spec_ref,
        })

    def finalize(self) -> "Scenario":
        (self.dir / "manifest.json").write_text(
            json.dumps(self.manifest, indent=2), encoding="utf-8")
        return self


CA_DN = "/DC=test/DC=xrootd/CN=Test XRootD CA"


def _scenario(root: Path, name: str) -> Scenario:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    return Scenario(name=name, dir=d, ca_dir=d / "ca")
