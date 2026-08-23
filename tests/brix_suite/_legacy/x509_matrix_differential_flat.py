"""ARCHIVE — the flat ``tests/x509_matrix_differential.py`` before TS-5.

Kept verbatim so the move can be checked body-by-body (AST hash) rather than
taken on trust.  Not imported by anything: ``FINDINGS`` walks ``parents[1]``
from the *flat* location, so from ``_legacy/`` it would name ``tests/docs/``.
The live module is ``brix_suite.security.x509_matrix_vectors``.
"""

from __future__ import annotations

"""Matrix differential — replay the davs clause matrix against stock XRootD.

For every davs-surface clause the manifest defines, this records three verdicts:
  spec   — the clause's expected value (spec-first ground truth)
  ours   — our module's verdict (ConformanceFleet, the live davs wire)
  xrootd — stock XRootD's XrdHttp verdict against the same shared CA directory

It ASSERTS ours == spec everywhere (the same truth the C oracle + wire matrix
enforce) and RECORDS every xrootd != spec divergence into the generated
docs/10-reference/conformance/differential-findings.md — the behavioural
corroboration of the source-level write-up.

XrdHttp ignores our signing_policy/crl_mode directives (it does TLS-layer
verification only), so ONE stock server on the shared multi-CA dir suffices for
all davs cases.  Opt-in via TEST_X509_DIFF=1; skip-clean without an xrootd
binary.
"""

import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import ephemeral_port
import x509forge
from clauses import ALL_CLAUSES
from wlcg_conformance_fleet import ConformanceFleet
from settings import HOST

FINDINGS = (Path(__file__).resolve().parents[1]
            / "docs/10-reference/conformance/differential-findings.md")


def _xrootd_bin():
    return shutil.which(os.environ.get("TEST_REF_BIN", "xrootd"))


class _XrdHttp:
    """A stock XRootD XrdHttp server verifying client certs against a CA dir."""

    def __init__(self, work: Path, ca_dir: Path):
        self.work = Path(work)
        self.ca_dir = ca_dir
        self.work.mkdir(parents=True, exist_ok=True)
        # Native stock-XRootD upstream (differential ref) — ephemeral exemption.
        self.port, self.base = ephemeral_port.free_ports(2)
        self.proc = None

    def start(self):
        cert, key = self.work / "s.pem", self.work / "s.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "3650",
             "-subj", "/CN=localhost"], check=True, capture_output=True)  # net-literal-allow: throwaway TLS server cert subject CN (curl -k, no verify)
        cfg = self.work / "xrootd.cfg"
        cfg.write_text(f"""\
xrd.port {self.base}
xrd.protocol http:{self.port} libXrdHttp.so
http.cadir {self.ca_dir}
http.cert {cert}
http.key {key}
all.export /
xrd.trace none
""")
        logf = open(self.work / "xrootd.log", "w")
        self.proc = subprocess.Popen(
            [_xrootd_bin(), "-c", str(cfg), "-n", "diff"],
            stdout=logf, stderr=subprocess.STDOUT)
        for _ in range(60):
            r = subprocess.run(
                ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "2", f"https://{HOST}:{self.port}/"],
                capture_output=True, text=True)
            if r.stdout.strip() not in ("", "000"):
                return True
            time.sleep(0.25)
        return False

    def verdict(self, cred: Path):
        r = subprocess.run(
            ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "8", "--cert", str(cred), "--key", str(cred),
             f"https://{HOST}:{self.port}/"], capture_output=True, text=True)
        code = r.stdout.strip()
        if not code or code == "000":
            return "unavailable"
        return "accept" if code.startswith("2") else "reject"

    def stop(self):
        if self.proc:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def run(root: Path) -> int:
    root = Path(root)
    davs = _load_davs_cases(root)
    fleet = ConformanceFleet(root)
    fleet.start()
    xrd = _start_reference_server(root)
    try:
        rows, mismatches = _evaluate_cases(root, davs, fleet, xrd)
    finally:
        _stop_servers(fleet, xrd)
    _write(rows)
    return _report_result(rows, mismatches)


def _load_davs_cases(root):
    if not (root / "manifest.json").exists():
        x509forge.build_all(root, ALL_CLAUSES)
    manifest = json.loads((root / "manifest.json").read_text())
    return [record for record in manifest if record["surface"] == "davs"]


def _start_reference_server(root):
    if not _xrootd_bin():
        return None
    server = _XrdHttp(root / "xrd", root / "shared" / "ca")
    return server if server.start() else None


def _evaluate_cases(root, davs, fleet, xrd):
    rows, mismatches = [], []
    for record in davs:
        row = _evaluate_case(root, record, fleet, xrd)
        rows.append(row)
        if row[3] != row[2]:
            mismatches.append((row[0], row[2], row[3]))
    return rows, mismatches



def _evaluate_case(root, record, fleet, xrd):
    accepted = fleet.verdict(record["cred"], record["group"])[0]
    ours = "accept" if accepted else "reject"
    credential = root / "creds" / record["cred"]
    reference = xrd.verdict(credential) if xrd else "unavailable"
    return (record["id"], record["clause"], record["expected"], ours,
            reference, record["title"])


def _stop_servers(fleet, xrd):
    fleet.stop()
    if xrd:
        xrd.stop()


def _report_result(rows, mismatches):
    if mismatches:
        _print_mismatches(mismatches)
        return 1
    diverged = _divergent_rows(rows)
    print(f"differential OK: {len(rows)} davs cases, ours==spec everywhere; "
          f"{len(diverged)} stock-XRootD divergence(s) recorded in {FINDINGS}")
    return 0


def _print_mismatches(mismatches):
    print("DIFFERENTIAL FAILURE — ours != spec:")
    for identifier, spec, ours in mismatches:
        print(f"  {identifier}: spec={spec} ours={ours}")


def _divergent_rows(rows):
    return [row for row in rows if row[4] not in ("unavailable", row[2])]


def _write(rows):
    diverged = _divergent_rows(rows)
    lines = _findings_header(rows, diverged)
    _append_divergences(lines, diverged)
    FINDINGS.parent.mkdir(parents=True, exist_ok=True)
    FINDINGS.write_text("\n".join(lines), encoding="utf-8")


def _findings_header(rows, diverged):
    return [
        "# WLCG x509 differential — nginx-xrootd vs stock XRootD (XrdHttp)",
        "",
        "Generated by `TEST_X509_DIFF=1 tests/run_x509_matrix_differential.sh`.",
        "",
        "`spec` = clause ground truth; `ours` = this module (live davs wire); "
        "`xrootd` = stock XRootD XrdHttp against the same hashed CA directory.",
        "A row where `xrootd` differs from `spec` (⚠) is a behavioural divergence "
        "— almost always XrdHttp accepting a credential our module rejects, "
        "because XrdHttp does TLS-layer verification only (no signing_policy, no "
        "GSI proxy validation, CRL via the TLS context only).",
        "",
        f"**Summary:** {len(rows)} davs cases; ours == spec on all of them; "
        f"{len(diverged)} stock-XRootD divergences recorded.",
        "",
        "## Divergences (xrootd != spec)",
        "",
        "| id | clause | spec | ours | xrootd | title |",
        "|---|---|---|---|---|---|",
    ]


def _append_divergences(lines, diverged):
    for identifier, clause, spec, ours, xrootd, title in diverged:
        lines.append(
            f"| {identifier} | {clause} | {spec} | {ours} | "
            f"{xrootd} ⚠ | {title} |"
        )
    if not diverged:
        lines.append("| _(none / xrootd unavailable)_ | | | | | |")
    lines.append("")


if __name__ == "__main__":
    import sys
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/x509matrixdiff")
    raise SystemExit(run(out))
