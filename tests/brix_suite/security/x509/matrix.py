"""The clause matrix: build many scenarios from an orthogonal clause list.

The tail of ``x509forge_part3.py``, moved verbatim.  ``GROUPS`` names the
orthogonal axes; ``ForgeCtx`` materialises one point in that space.
"""

from __future__ import annotations

import json
import shutil

from dataclasses import dataclass
from pathlib import Path

from brix_suite.security.x509.cadir import (
    _openssl_hashes,
    _symlink,
    signing_policy_text,
)
from brix_suite.security.x509.primitives import (
    Cert,
    make_ca,
    make_crl,
)

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
        ca_dn = dn or self.dn(suffix)
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
        policy = (signing_policy_text(ca_dn, policy_globs)
                  if policy_globs is not None else None)
        crls = dict(extra_crls or {})
        if empty_crl or revoke is not None:
            crls["r0"] = make_crl(ca, revoked=revoke or [])
        _place_ca_in_dir(self.shared_ca, ca, name=name, policy_text=policy,
                         crls=crls or None, links=links)
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
    if root.exists():
        shutil.rmtree(root)
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
        rows.append(dict(id=c.id, clause=c.clause, title=c.title, cred=cred or "",
                         expected=c.expected, surface=c.surface, group=c.group,
                         reason=c.reason))

    (root / "manifest.json").write_text(json.dumps(rows, indent=2),
                                        encoding="utf-8")
    tsv = "\n".join("\t".join([r["id"], r["cred"], r["expected"], r["surface"],
                               r["group"]]) for r in rows)
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
