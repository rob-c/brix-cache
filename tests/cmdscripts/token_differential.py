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
    stock_port = _usable_stock_port(stock_port, xrootd_bin)
    args = _differential_args(stock_port)
    proc = run(args, cwd=REPO_ROOT, env={"PYTHONPATH": "tests"})
    label = _comparison_label(stock_port)
    return [result(proc.returncode == 0, f"token differential {label} exited {proc.returncode}: {(proc.stderr or proc.stdout)[-3000:]}")]


def _usable_stock_port(stock_port: str, xrootd_bin: str) -> str:
    if not stock_port:
        return ""
    if shutil.which("xrdfs") is None:
        return ""
    return stock_port if os.access(xrootd_bin, os.X_OK) else ""


def _differential_args(stock_port: str) -> list[str]:
    args = ["python3", "tests/token_differential.py"]
    if stock_port:
        args.append(stock_port)
    return args


def _comparison_label(stock_port: str) -> str:
    if stock_port:
        return f"ours-vs-spec + stock xrootd @ {stock_port}"
    return "ours-vs-spec"


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
