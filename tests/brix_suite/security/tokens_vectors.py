"""WLCG token conformance — Layer 3 differential driver.

WHAT: Runs a representative set of token scenarios against OUR root:// server
      and (when available) a SciTokens-configured stock XRootD, comparing both
      to the spec-defined expected verdict.
WHY:  Correctness is spec-first. Our verdict MUST equal the spec (a mismatch
      fails the tier). Stock XRootD is a comparison target only — where it
      diverges from spec we record a finding, we do not fail.
HOW:  Mints via tokenforge, probes our port with lib.tokenconf.root_ztn, and
      probes stock XRootD via xrdfs+ztn when a stock port is supplied. Writes a
      findings table to docs/10-reference/wlcg-token-differential-findings.md.

Moved verbatim from ``tests/token_differential.py`` at TS-5 (archive:
``brix_suite/_legacy/token_differential_flat.py``).  Three deliberate
deviations, all forced by the new location and all pinned by
``test_ci_ts5_differentials_move.py``:

* ``FINDINGS`` walks three parents instead of one ``..``.  It names a file in
  the *repo's* ``docs/10-reference/``, and the module is now three directories
  deeper; left alone the driver would have written its findings table into
  ``tests/brix_suite/docs/10-reference/`` — a directory ``_write_findings``
  creates for itself, so nothing would have raised and the published report
  would simply have stopped being updated.
* the self-locate inserts the ``tests/`` directory (``parents[2]``) rather than
  this file's own directory.  ``lib.tokenconf`` and the fleet modules have not
  moved yet; without that entry they are unimportable from here.
* the ``tokenforge`` and ``settings`` imports name their canonical packages.
  The §10.2 shims make each pair one module object, so this is a spelling
  change, not a behaviour change.

The ``__main__`` guard the flat file ended with is now :func:`main`, called by
name from the shim.  ``cmdscripts/token_differential.py`` starts this driver as
``python3 tests/token_differential.py [stock_port]`` — an *absolute path* — and
its pytest wrapper SKIPs unless ``TEST_TOKEN_DIFF=1``, so a stranded entry point
here would have exited 0, written no findings, and been reported as a pass.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from brix_suite.security.tokens import TokenForge
from lib.tokenconf import root_ztn, ensure_conformance_data
from brix_suite.settings import NGINX_TOKEN_PORT, SERVER_HOST, TOKENS_DIR

FINDINGS = os.path.join(
    str(Path(__file__).resolve().parents[3]), "docs", "10-reference",
    "wlcg-token-differential-findings.md")

# (case_id, mint recipe (method, args), request path, spec verdict)
CASES = [
    ("DIFF-01", ("generate", []), "/test.txt", "accept"),
    ("DIFF-02", ("alg_none", []), "/test.txt", "reject"),
    ("DIFF-03", ("temporal", [-3600]), "/test.txt", "reject"),
    ("DIFF-04", ("for_issuer", ["https://evil.example.com"]),
     "/test.txt", "reject"),
    ("DIFF-05", ("scope", ["storage.read:/atlas"]), "/cms/ok.txt", "reject"),
    ("DIFF-06", ("aud_value", [["nginx-xrootd", "other"]]),
     "/test.txt", "accept"),
    ("DIFF-07", ("alg_hs256_confusion", []), "/test.txt", "reject"),
]


def _mint(forge, recipe):
    method, args = recipe
    return getattr(forge, method)(*args)


def run(stock_port=None, stock_host=SERVER_HOST):
    ensure_conformance_data()
    forge = TokenForge(TOKENS_DIR)
    rows = []
    ours_mismatch = []
    xrootd_divergence = []

    for case_id, recipe, path, spec in CASES:
        tok = _mint(forge, recipe)
        ours = root_ztn(tok, path, port=NGINX_TOKEN_PORT)
        xrd = _stock_verdict(tok, path, stock_host, stock_port) \
            if stock_port else "n/a"
        rows.append((case_id, recipe[0], ours, xrd, spec))
        if ours != spec:
            ours_mismatch.append((case_id, ours, spec))
        if xrd not in ("n/a", spec):
            xrootd_divergence.append((case_id, xrd, spec))

    _write_findings(rows, stock_port is not None, xrootd_divergence)
    return ours_mismatch, xrootd_divergence


def _stock_verdict(token, path, host, port):
    """Present the token to a stock xrootd via xrdfs+ztn; accept/reject."""
    import subprocess
    import tempfile
    tf = tempfile.NamedTemporaryFile("w", suffix=".jwt", delete=False)
    tf.write(token)
    tf.close()
    env = dict(os.environ)
    env["BEARER_TOKEN_FILE"] = tf.name  # WLCG ztn client convention
    try:
        r = subprocess.run(
            ["xrdfs", f"{host}:{port}", "stat", path],
            env=env, capture_output=True, timeout=15)
        return "accept" if r.returncode == 0 else "reject"
    except Exception:
        return "error"
    finally:
        os.unlink(tf.name)


def _write_findings(rows, stock_ran, divergences):
    os.makedirs(os.path.dirname(FINDINGS), exist_ok=True)
    lines = [
        "# WLCG Token Differential — Findings (generated golden)",
        "",
        "Layer-3 differential tier output. Our verdict is asserted against the",
        "spec (a mismatch fails the tier). Stock XRootD is a comparison target",
        "only; `xrootd != spec` rows are recorded as findings, not failures.",
        "Regenerate with `TEST_TOKEN_DIFF=1 tests/run_token_differential.sh`.",
        "",
    ]
    if not stock_ran:
        lines += [
            "**Stock-XRootD column not populated.** A SciTokens-configured",
            "stock `xrootd` was not available/configured on this run, so only",
            "the ours-vs-spec assertion executed. The `libXrdSecztn` and",
            "`libXrdAccSciTokens` plugins may be present but a server-side",
            "issuer config (SciTokens `[Issuer]` block mapping our test issuer",
            "to our JWKS) is site-specific; supply it via the harness to",
            "populate the `xrootd` column.",
            "",
        ]
    lines += ["| Case | Scenario | Ours | XRootD | Spec |",
              "|---|---|---|---|---|"]
    for cid, scen, ours, xrd, spec in rows:
        lines.append(f"| {cid} | {scen} | {ours} | {xrd} | {spec} |")
    lines.append("")
    if divergences:
        lines.append("## Divergences (xrootd != spec)")
        for cid, xrd, spec in divergences:
            lines.append(f"- {cid}: xrootd={xrd}, spec={spec}")
    else:
        lines.append("_No stock-XRootD divergences recorded on this run._")
    lines.append("")
    with open(os.path.abspath(FINDINGS), "w") as fh:
        fh.write("\n".join(lines))


def main(argv=None):
    """The flat file's ``__main__`` block, given a name it can be called by.

    Kept behaviourally identical: one optional positional argument, the port of
    a SciTokens-configured stock XRootD, and an exit code that is 1 only when
    *our* verdict disagrees with the spec.  Stock divergences are printed, never
    fatal — that asymmetry is the whole point of the tier.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    port = int(argv[0]) if argv else None
    mismatch, diverge = run(stock_port=port)
    if mismatch:
        print("FAIL: our verdict != spec for:", mismatch)
        return 1
    print(f"OK: ours==spec for all {len(CASES)} cases"
          + (f"; {len(diverge)} xrootd divergence(s)" if diverge else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
