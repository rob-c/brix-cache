"""x509_differential — replay forge scenarios against our module and stock XRootD.

For every davs-surface scenario the forge produces, this computes:
  * spec   — the manifest's expected verdict (spec-first ground truth)
  * ours   — our module's verdict (WlcgInstance davs://)
  * xrootd — stock XRootD's verdict (XrdHttp), when it can be stood up

It ASSERTS ours == spec (a mismatch is a hard failure — the same truth as the
unit/e2e layers) and RECORDS every xrootd != spec divergence into a generated
findings report, without failing on them.  Those divergences are the
upstream-bug evidence: a place stock XRootD accepts what the WLCG trust model
forbids (or vice-versa).

Gated by TEST_X509_DIFF=1 (the wrapper script enforces this).  The stock-XRootD
leg is best-effort: if no `xrootd` binary is present, or XrdHttp cannot be stood
up for a scenario, that cell is recorded as "unavailable" and the run still
succeeds as long as ours == spec everywhere.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import ephemeral_port
import x509forge
from wlcg_fleet import WlcgInstance
from settings import HOST

FINDINGS = (Path(__file__).resolve().parents[1]
            / "docs/10-reference/wlcg-x509-differential-findings.md")

# Scenarios exercised on the davs surface (proxies are excluded — the WebDAV
# surface refuses all proxy chains by design, so they are not a fair diff).
DAVS_SCENARIOS = [
    "sp_in_namespace", "sp_out_of_namespace", "sp_wrong_ca_block",
    "sp_no_policy", "cad_sha1_only", "cad_md5_only", "cad_expired_ca",
    "crl_revoked_eec",
]


def _our_verdict(tmp: Path, sc, cred_name, *, signing_policy="on",
                 crl="", crl_mode="try") -> str:
    inst = WlcgInstance(tmp, ca_dir=sc.ca_dir, signing_policy=signing_policy,
                        crl=crl, crl_mode=crl_mode)
    inst.start()
    try:
        accepted, _ = inst.attempt_davs(sc.credentials[cred_name])
        return "accept" if accepted else "reject"
    finally:
        inst.stop()


# --------------------------------------------------------------------------
# Stock XRootD (XrdHttp) leg — best effort
# --------------------------------------------------------------------------

def _xrootd_bin() -> str | None:
    return shutil.which(os.environ.get("TEST_REF_BIN", "xrootd"))


def _xrootd_verdict(work: Path, sc, cred_name) -> str:
    """Stand up a stock XrdHttp server verifying client certs against the
    scenario CA dir; return 'accept'/'reject'/'unavailable'."""
    xrootd = _xrootd_bin()
    if xrootd is None:
        return "unavailable"

    # Native stock-XRootD upstream (differential ref) — ephemeral exemption.
    port, base_port = ephemeral_port.free_ports(2)
    data = work / "data"
    data.mkdir(parents=True, exist_ok=True)
    server_cert, server_key = _server_cert(work)
    cfg = work / "xrootd.cfg"
    # xrd.port moves the base xroot protocol off the default 1094 (which a
    # running fleet holds); only the http port matters for this diff.
    cfg.write_text(f"""\
xrd.port {base_port}
xrd.protocol http:{port} libXrdHttp.so
http.cadir {sc.ca_dir}
http.cert {server_cert}
http.key {server_key}
all.export /
xrd.trace none
""")
    logf = open(work / "xrootd.log", "w")
    proc = subprocess.Popen(
        [xrootd, "-c", str(cfg), "-n", "diff"],
        stdout=logf, stderr=subprocess.STDOUT)
    try:
        # Wait for a REAL HTTP response (curl prints "000" on connection refused
        # while the server is still binding — that must not end the wait).
        for _ in range(60):
            probe = subprocess.run(
                ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "2", f"https://{HOST}:{port}/"],
                capture_output=True, text=True)
            if probe.stdout.strip() not in ("", "000"):
                break
            time.sleep(0.25)
        else:
            return "unavailable"

        r = subprocess.run(
            ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "8", "--cert", str(sc.credentials[cred_name]),
             "--key", str(sc.credentials[cred_name]),
             f"https://{HOST}:{port}/"],
            capture_output=True, text=True)
        code = r.stdout.strip()
        if not code or code == "000":
            return "unavailable"
        return "accept" if code.startswith("2") else "reject"
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


_SRV = None


def _server_cert(work: Path):
    global _SRV
    if _SRV:
        return _SRV
    d = work.parent / "_diff_server"
    d.mkdir(parents=True, exist_ok=True)
    cert, key = d / "s.pem", d / "s.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "3650",
         "-subj", "/CN=localhost"], check=True, capture_output=True)  # net-literal-allow: throwaway TLS server cert subject CN (curl -k, no verify)
    _SRV = (cert, key)
    return _SRV


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def run(root: Path) -> int:
    root.mkdir(parents=True, exist_ok=True)
    rows = []
    mismatches = []

    for name in DAVS_SCENARIOS:
        sc = x509forge.forge_scenario(root / name, name)
        manifest = json.loads((sc.dir / "manifest.json").read_text())
        crl = str(sc.ca_dir) if name.startswith("crl") else ""
        for m in manifest:
            if m["surface"] not in ("davs", "both"):
                continue
            cred = m["credential"]
            spec = m["expected"]
            ours = _our_verdict(root / f"{name}-{cred}-ours", sc, cred,
                                crl=crl)
            xrd = _xrootd_verdict(root / f"{name}-{cred}-xrd", sc, cred)
            rows.append((name, cred, spec, ours, xrd, m["reason"]))
            if ours != spec:
                mismatches.append((name, cred, spec, ours))

    _write_findings(rows)

    if mismatches:
        print("DIFFERENTIAL FAILURE — ours != spec:")
        for name, cred, spec, ours in mismatches:
            print(f"  {name}/{cred}: spec={spec} ours={ours}")
        return 1

    diverged = [r for r in rows if r[4] not in ("unavailable", r[2])]
    print(f"differential OK: {len(rows)} scenarios, ours==spec everywhere; "
          f"{len(diverged)} stock-XRootD divergence(s) recorded in {FINDINGS}")
    return 0


def _write_findings(rows):
    lines = [
        "# WLCG x509 differential findings — nginx-xrootd vs stock XRootD",
        "",
        "Generated by `TEST_X509_DIFF=1 tests/run_x509_differential.sh`.",
        "",
        "`spec` is the RFC/IGTF ground truth; `ours` is this module; `xrootd` is",
        "stock XRootD (XrdHttp).  A row where `xrootd` differs from `spec` is a",
        "candidate upstream divergence.  `unavailable` = the stock server could",
        "not be stood up for that case in this environment.",
        "",
        "**Caveat (fairness to XRootD):** the stock server is configured with an",
        "equivalent hashed CA directory (`http.cadir`) and the same server cert,",
        "but no extra CRL or signing_policy directives.  A ⚠ row therefore means",
        "XrdHttp did not enforce that check *in this baseline configuration* — it",
        "may enforce it when explicitly configured.  The value of the row is that",
        "our module enforces it by default where XrdHttp does not.",
        "",
        "| scenario | credential | spec | ours | xrootd | note |",
        "|---|---|---|---|---|---|",
    ]
    for name, cred, spec, ours, xrd, reason in rows:
        flag = " ⚠" if xrd not in ("unavailable", spec) else ""
        lines.append(f"| {name} | {cred} | {spec} | {ours} | {xrd}{flag} "
                     f"| {reason} |")
    lines.append("")
    FINDINGS.parent.mkdir(parents=True, exist_ok=True)
    FINDINGS.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    import sys
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/x509diff")
    raise SystemExit(run(out))
