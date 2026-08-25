"""ARCHIVE -- the pre-TS-5 flat ``x509forge_part3.py``, byte-for-byte.

Kept as the rollback anchor and as the diffing baseline for
``tests/test_ci_ts5_x509_move.py``, which hashes every moved function body
against the copy here.  Nothing in the live suite imports this file; it is not
a shim and it is not composed.
"""

from __future__ import annotations

def _expression_1_next(rows):
    return (
        "\n".join("\t".join([r["id"], r["cred"], r["expected"], r["surface"],
                                       r["group"]]) for r in rows)
    )


def _expression_2(dn, suffix, self):
    return (
        dn or self.dn(suffix)
    )

def _expression_3(policy_globs, ca_dn):
    return (
        signing_policy_text(ca_dn, policy_globs)
                          if policy_globs is not None else None
    )

def _expression_4(extra_crls):
    return (
        dict(extra_crls or {})
    )

def _expression_5(ca, self, name, policy, links, crls):
    return (
        _place_ca_in_dir(self.shared_ca, ca, name=name, policy_text=policy,
                                 crls=crls or None, links=links)
    )

def _expression_1(rows, c, cred):
    return (
        rows.append(dict(id=c.id, clause=c.clause, title=c.title, cred=cred or "",
                                 expected=c.expected, surface=c.surface, group=c.group,
                                 reason=c.reason))
    )


def _guard_ca_1(empty_crl, revoke, crls, ca):
    if empty_crl or revoke is not None:
        crls["r0"] = make_crl(ca, revoked=revoke or [])

def _guard_build_all_2(root):
    if root.exists():
        shutil.rmtree(root)


"""x509forge — manufacture hostile PKI scenario trees for WLCG conformance.

Each scenario materialises a complete hashed CA directory (CA certs with both
SHA-1 and MD5 hash links, <hash>.signing_policy, .r0/.r1 CRLs) plus one or more
client credentials and a manifest.json.  The manifest is the single source of
truth consumed by every test layer (C unit, pytest e2e, differential), so a
verdict can never drift between layers.

The builders lean on the `cryptography` package, with a raw-DER escape hatch
(via x509.UnrecognizedExtension) for artifacts cryptography will not emit
directly — non-critical proxyCertInfo, bogus policy OIDs, and the like.

A scenario spec is a plain dict; forge_scenario(root, name, spec) turns it into
a Scenario.  See BASELINE_SPEC and the *_SPECS tables for the catalogue used by
the test suite.
"""

import functools
import datetime
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    CertificateBuilder,
    CertificateRevocationListBuilder,
    Name,
    NameAttribute,
    RevokedCertificateBuilder,
)
from cryptography.x509.oid import NameOID

# A fixed epoch keeps validity windows reproducible without Date.now(); tests
# that need "expired" pass explicit deltas relative to this.
_EPOCH = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_DAY = datetime.timedelta(days=1)

# Policy-language OIDs.
OID_PROXY_CERT_INFO = "1.3.6.1.5.5.7.1.14"
OID_PPL_INHERIT_ALL = "1.3.6.1.5.5.7.21.1"   # full / impersonation
OID_PPL_INDEPENDENT = "1.3.6.1.5.5.7.21.2"   # independent
OID_GLOBUS_LIMITED = "1.3.6.1.4.1.3536.1.1.1.9"


# --------------------------------------------------------------------------
# DER helpers (proxyCertInfo has no native cryptography builder)
# --------------------------------------------------------------------------

def _cad_expired_ca(root: Path) -> Scenario:
    sc = _scenario(root, "cad_expired_ca")
    ca = make_ca(CA_DN, not_after_days=-1)   # already expired
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    write_hashed_ca_dir(sc.ca_dir, ca)
    sc.write_credential("eec", [eec, ca], eec)
    sc.add_manifest("eec", "reject", reason="trust anchor expired", spec_ref="RFC 5280")
    return sc.finalize()


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


# ==========================================================================
# Forge v2 — clause-indexed registry + the fixed-fleet materialiser
# ==========================================================================
#
# A Clause is one conformance test.  Its build(ctx) function uses the ForgeCtx
# to register CA material (into one big shared multi-CA dir, exactly like a real
# /etc/grid-security/certificates) and write the credential the test presents.
# build_all() materialises every clause and emits manifest.json + manifest.tsv,
# the single source of truth consumed by the conformance fleet and the C oracle.

# Server config-groups.  Every config-group server points at the SAME shared/ca
# directory; the credential's group selects which config evaluates it.  The
# bundle group uses a single concatenated CA file instead of a hashed dir.
GROUPS = {
    "sp_on_crl_off":     dict(signing_policy="on",      crl_mode="off"),
    "sp_off_crl_off":    dict(signing_policy="off",     crl_mode="off"),
    "sp_require_crl_off": dict(signing_policy="require", crl_mode="off"),
    "sp_on_crl_try":     dict(signing_policy="on",      crl_mode="try",     crl="ca"),
    "sp_on_crl_require": dict(signing_policy="on",      crl_mode="require", crl="ca"),
    "sp_off_crl_try":    dict(signing_policy="off",     crl_mode="try",     crl="ca"),
    "bundle":            dict(signing_policy="off",     crl_mode="off",     cafile="bundle.pem"),
}


@dataclass
class Clause:
    id: str
    clause: str
    title: str
    expected: str                       # "accept" | "reject"
    build: "callable"                   # (ctx: ForgeCtx) -> cred_name | None
    surface: str = "davs"               # davs | c-oracle | config
    group: str = "sp_on_crl_off"
    reason: str = ""


def _place_ca_in_dir(ca_dir: Path, ca: Cert, *, name: str,
                     policy_text: str | None = None,
                     crls: dict[str, bytes] | None = None,
                     links: str = "both") -> None:
    """Place one CA into a multi-CA hashed dir as <name>.pem + <hash>.N links,
    <hash>.signing_policy, <hash>.rN — without a shared ca.pem (so hundreds of
    CAs coexist).  Picks the next free .N slot for a hash collision."""
    ca_dir.mkdir(parents=True, exist_ok=True)
    cert_file = ca_dir / f"{name}.pem"
    cert_file.write_bytes(ca.pem)
    new_hash, old_hash = _openssl_hashes(cert_file)
    chosen = {"both": [new_hash, old_hash], "new": [new_hash],
              "old": [old_hash]}[links]
    for hh in dict.fromkeys(chosen):     # preserve order, dedup if equal
        slot = 0
        while (ca_dir / f"{hh}.{slot}").exists():
            slot += 1
        _symlink(f"{name}.pem", ca_dir / f"{hh}.{slot}")
        if policy_text is not None:
            pf = ca_dir / f"{name}.signing_policy"
            pf.write_text(policy_text, encoding="utf-8")
            _symlink(f"{name}.signing_policy", ca_dir / f"{hh}.signing_policy")
        if crls:
            for suffix, pem in crls.items():
                (ca_dir / f"{hh}.{suffix}").write_bytes(pem)


class ForgeCtx:
    """Handed to each Clause.build(); registers CA material + writes creds."""

    def __init__(self, root: Path, clause: Clause):
        self.root = Path(root)
        self.clause = clause
        self.shared_ca = self.root / "shared" / "ca"
        self.creds = self.root / "creds"
        self.creds.mkdir(parents=True, exist_ok=True)
        self._n = 0

    def _uid(self, suffix: str = "") -> str:
        self._n += 1
        return f"{self.clause.id}-{self._n}{('-' + suffix) if suffix else ''}"

    def dn(self, suffix: str = "") -> str:
        """A unique CA DN for this clause (avoids cross-test hash collisions)."""
        return f"/DC=test/DC=x509conf/CN=CA {self._uid(suffix)}"

    def ca(self, *, suffix: str = "", policy_globs: list | None = None,
           revoke: list | None = None, empty_crl: bool = False,
           links: str = "both", place: bool = True, to_bundle: bool = False,
           extra_crls: dict | None = None, dn: str | None = None,
           **ca_kw) -> Cert:
        """Mint a uniquely-named CA and (by default) place it in the shared dir.

        policy_globs → writes a <hash>.signing_policy granting those globs.
        revoke/empty_crl → writes a <hash>.r0 CRL. place=False mints without
        placing (unknown-CA tests). to_bundle appends to the bundle file."""
        ca_dn = _expression_2(dn, suffix, self)
        ca = make_ca(ca_dn, **ca_kw)
        name = self._uid(suffix)
        if not place:
            return ca
        if to_bundle:
            bundle = self.shared_ca.parent / "bundle.pem"
            bundle.parent.mkdir(parents=True, exist_ok=True)
            with open(bundle, "ab") as fh:
                fh.write(ca.pem)
            return ca
        policy = (_expression_3(policy_globs, ca_dn))
        crls = _expression_4(extra_crls)
        _guard_ca_1(empty_crl, revoke, crls, ca)
        _expression_5(ca, self, name, policy, links, crls)
        return ca

    def cred(self, chain: list[Cert], key_of: Cert | None = None) -> str:
        """Write leaf-first chain + key; return the credential filename."""
        key_of = key_of or chain[0]
        name = f"{self.clause.id}.pem"
        blob = b"".join(c.pem for c in chain) + key_of.key_pem
        (self.creds / name).write_bytes(blob)
        return name

    def raw_cred(self, pem: bytes) -> str:
        name = f"{self.clause.id}.pem"
        (self.creds / name).write_bytes(pem)
        return name


def build_all(root: Path, clauses: list) -> Path:
    """Materialise every Clause and emit manifest.json + manifest.tsv."""
    root = Path(root)
    _guard_build_all_2(root)
    (root / "shared" / "ca").mkdir(parents=True, exist_ok=True)
    (root / "creds").mkdir(parents=True, exist_ok=True)

    rows = []
    errors = []
    for c in clauses:
        ctx = ForgeCtx(root, c)
        try:
            cred = c.build(ctx)
        except Exception as exc:                      # noqa: BLE001
            errors.append((c.id, f"{type(exc).__name__}: {exc}"))
            continue
        _expression_1(rows, c, cred)

    (root / "manifest.json").write_text(json.dumps(rows, indent=2),
                                        encoding="utf-8")
    tsv = _expression_1_next(rows)
    (root / "manifest.tsv").write_text(tsv + "\n", encoding="utf-8")
    if errors:
        (root / "build_errors.tsv").write_text(
            "\n".join(f"{i}\t{e}" for i, e in errors) + "\n", encoding="utf-8")
    return root


def build_report(root: Path, clauses: list) -> dict:
    """build_all + a summary dict {materialized, errors:[(id,msg)]}."""
    build_all(root, clauses)
    errs = []
    ef = Path(root) / "build_errors.tsv"
    if ef.exists():
        for line in ef.read_text().splitlines():
            if "\t" in line:
                i, m = line.split("\t", 1)
                errs.append((i, m))
    n = len(json.loads((Path(root) / "manifest.json").read_text()))
    return {"materialized": n, "errors": errs}


if __name__ == "__main__":   # manual: python3 tests/x509forge.py /tmp/x509conf
    import sys
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/x509conf")
    forged = forge_all(out)
    for nm, sc in forged.items():
        print(f"{nm}: {len(sc.manifest)} manifest entries → {sc.dir}")
