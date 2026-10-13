#!/usr/bin/env python3
"""Generate the Phase-118 C clause catalogue from its normative Markdown tables."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROW_RE = re.compile(
    r"^\| (?P<id>[A-Z][A-Z0-9]+-\d{3})(?: †)? "
    r"\| (?P<text>.*?) \| (?P<ref>.*?) \| (?P<oracle>.*?) \| (?P<src>.*?) \|$"
)

REFS = {
    "spec": "BRIX_CONFORM_REF_SPEC",
    "xrootd": "BRIX_CONFORM_REF_XROOTD",
    "client": "BRIX_CONFORM_REF_CLIENT",
    "cons": "BRIX_CONFORM_REF_CONS",
    "—": "BRIX_CONFORM_REF_NONE",
}

READ_FAMILIES = {
    "FRM", "HSK", "PROT", "LOG", "SIG", "OPN", "RD", "PGR", "STA",
    "DIR", "LOC", "FAT", "PRP", "QRY", "RDV", "RDR", "WAI", "ATN",
    "CHU", "BND", "ENV", "ERR", "TLS", "CLM", "HTR", "HTC", "HTE",
    "DAV", "S3", "CMS", "CAC", "XPR",
}
MUTATE_FAMILIES = {"PGW", "WRT", "WVC", "SYN", "TRN", "CKP", "MKD", "MV", "RM", "CHM", "TPC"}

# Families describe protocol ownership, not operational safety.  Mixed families
# therefore need clause-level overrides so a future live probe cannot acquire
# mutation or disruption authority merely by being filed beside read probes.
MUTATE_CLAUSES = {
    "OPN-008", "OPN-009", "OPN-010", "OPN-011", "OPN-012", "OPN-014",
    "OPN-015", "OPN-016", "OPN-017", "OPN-021", "OPN-022", "OPN-023",
    "OPN-024", "OPN-025", "OPN-026", "RD-017", "PGR-029",
    "STA-005", "STA-006", "STA-011", "STA-012",
    "QRY-011",
    "FAT-001", "FAT-002", "FAT-003", "FAT-004", "FAT-005", "FAT-006",
    "FAT-007", "FAT-009", "PRP-001", "PRP-002", "PRP-003", "PRP-004",
    "PRP-005", "PRP-007", "ERR-005", "ERR-006", "ERR-007", "ERR-013",
    "ERR-014", "ERR-044", "CLM-004", "CLM-007", "CLM-009", "HTR-017",
    "HTC-001", "HTC-002", "HTC-003", "HTC-004", "HTC-005", "DAV-005",
    "DAV-006", "DAV-007", "DAV-008", "DAV-009", "DAV-010", "S3-009",
    "S3-011", "S3-012", "S3-013", "S3-014", "CAC-006", "CAC-010",
    "XPR-006", "XPR-009",
}

DISRUPT_CLAUSES = {
    "FRM-012", "FRM-021", "OPN-020", "OPN-032", "OPN-033", "PGR-021",
    "PGR-027", "PRP-006", "WAI-004", "BND-004", "DAV-011", "CMS-003",
    "CMS-004", "CAC-005", "CAC-009", "TPC-009",
}


def c_string(value: str) -> str:
    """Return a deterministic ASCII-safe C string literal for generated data."""
    value = re.sub(r"\*\*(.*?)\*\*", r"\1", value)
    value = value.replace("†", "").replace("`", "")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def oracle_expr(value: str) -> str:
    """Map compound Markdown oracle spellings onto a bitmask expression."""
    if value == "—":
        return "BRIX_CONFORM_ORACLE_NONE"
    parts = []
    for token in value.split("+"):
        name = token.strip().split()[0]
        if name in {"O1", "O2", "O3", "O4"}:
            parts.append(f"BRIX_CONFORM_ORACLE_{name}")
    return " | ".join(parts) if parts else "BRIX_CONFORM_ORACLE_NONE"


def probe_class(clause_id: str, family: str) -> str:
    """Assign the most restrictive safe probe class for one clause."""
    if family == "ADV" or clause_id in DISRUPT_CLAUSES:
        return "BRIX_CONFORM_PROBE_DISRUPT"
    if family in MUTATE_FAMILIES or clause_id in MUTATE_CLAUSES:
        return "BRIX_CONFORM_PROBE_MUTATE"
    if family in READ_FAMILIES:
        return "BRIX_CONFORM_PROBE_READ"
    raise ValueError(f"unclassified family {family}")


def is_retracted(text: str) -> bool:
    """Return whether the normative row explicitly withdraws the assertion."""
    return re.sub(r"\*\*(.*?)\*\*", r"\1", text).startswith("Retracted:")


def negative_fixture(clause_id: str, family: str, reference: str,
                     oracle: str, text: str) -> str:
    """Name the deterministic red-path fixture required by Phase 118 section 40."""
    if is_retracted(text):
        return f"not-applicable/retracted/{clause_id}"
    family_faults = {
        "ERR": "fault-proxy/error-code-rewrite",
        "TLS": "controlled-peer/tls-policy-downgrade",
        "CLM": "controlled-peer/capability-behaviour-mismatch",
        "XPR": "fault-proxy/one-plane-mismatch",
        "ADV": "fault-proxy/hostile-input-liveness",
        "CAC": "controlled-cache/state-corruption",
        "TPC": "controlled-tpc/scope-or-integrity-violation",
    }
    if family in family_faults:
        kind = family_faults[family]
    elif "O2" in oracle:
        kind = "fault-proxy/payload-or-geometry-corruption"
    elif "O3" in oracle:
        kind = "controlled-peer/wrong-wire-answer"
    elif "O1" in oracle:
        kind = "controlled-peer/inconsistent-observation"
    else:
        kind = "calibration-peer/ecosystem-divergence"
    return f"{kind}/{clause_id}"


def generate(source: Path) -> str:
    """Extract every individually addressed ledger row and render C initializers."""
    rows = []
    seen = set()
    for line in source.read_text(encoding="utf-8").splitlines():
        match = ROW_RE.match(line)
        if match is None:
            continue
        clause_id = match.group("id")
        if clause_id in seen:
            raise ValueError(f"duplicate clause id {clause_id}")
        seen.add(clause_id)
        family = clause_id.split("-", 1)[0]
        ref = REFS.get(match.group("ref"))
        if ref is None:
            raise ValueError(f"unknown reference {match.group('ref')} in {clause_id}")
        rows.append(
            "BRIX_CONFORM_CLAUSE(" + ", ".join(
                [
                    c_string(clause_id), c_string(family), ref,
                    oracle_expr(match.group("oracle")),
                    probe_class(clause_id, family),
                    c_string(negative_fixture(clause_id, family,
                                              match.group("ref"),
                                              match.group("oracle"),
                                              match.group("text"))),
                    c_string(match.group("text")),
                    c_string(match.group("src")),
                ]
            ) + ")"
        )
    if len(rows) != 527:
        raise ValueError(f"expected 527 Phase-118 clauses, found {len(rows)}")
    unknown_overrides = (MUTATE_CLAUSES | DISRUPT_CLAUSES) - seen
    if unknown_overrides:
        raise ValueError(f"unknown probe-class overrides: {sorted(unknown_overrides)}")
    header = [
        "/* Generated by tools/ci/generate_conform_ledger.py; do not edit. */",
        "/* Source: docs/refactor/phase-118-security-assessment-toolkit.md. */",
    ]
    return "\n".join(header + rows) + "\n"


def main() -> int:
    """Generate or verify the checked-in clause include."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = generate(args.source)
    if args.check:
        if not args.output.exists() or args.output.read_text(encoding="utf-8") != rendered:
            print(f"stale conform ledger: regenerate {args.output}")
            return 1
        print("conform ledger: OK (527 clauses)")
        return 0
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
