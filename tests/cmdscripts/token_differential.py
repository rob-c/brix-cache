"""Opt-in WLCG token differential runner."""

from __future__ import annotations

from pathlib import Path
import os
import shutil

from cmdscripts.compile_run import REPO_ROOT, result, run


def run_checks(base: Path) -> list[tuple[bool, str]]:
    if os.environ.get("TEST_TOKEN_DIFF", "0") != "1":
        return [result(True, "SKIP differential tier disabled; set TEST_TOKEN_DIFF=1 to run")]
    stock_port = os.environ.get("STOCK_XROOTD_PORT", "")
    xrootd_bin = os.environ.get("XROOTD_BIN", os.environ.get("BRIX_BIN", "/usr/bin/xrootd"))
    args = ["python3", "tests/token_differential.py"]
    if stock_port:
        if shutil.which("xrdfs") is None or not os.access(xrootd_bin, os.X_OK):
            stock_port = ""
        else:
            args.append(stock_port)
    proc = run(args, cwd=REPO_ROOT, env={"PYTHONPATH": "tests"})
    label = "ours-vs-spec" + (f" + stock xrootd @ {stock_port}" if stock_port else "")
    return [result(proc.returncode == 0, f"token differential {label} exited {proc.returncode}: {(proc.stderr or proc.stdout)[-3000:]}")]


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="token_diff.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("findings: docs/10-reference/wlcg-token-differential-findings.md")
        return 0
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
