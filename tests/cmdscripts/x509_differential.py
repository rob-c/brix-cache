"""Opt-in runner for the X509 module-vs-stock differential suite."""

from __future__ import annotations

from pathlib import Path
import os

from cmdscripts.compile_run import REPO_ROOT, result, run


def run_checks(base: Path) -> list[tuple[bool, str]]:
    if os.environ.get("TEST_X509_DIFF", "0") != "1":
        return [result(True, "SKIP run_x509_differential: set TEST_X509_DIFF=1 to run")]
    out = base / "x509diff"
    proc = run(
        ["python3", "tests/x509_differential.py", str(out)],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "tests"},
    )
    return [result(proc.returncode == 0, f"x509 differential exited {proc.returncode}: {(proc.stderr or proc.stdout)[-2000:]}")]


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="x509diff.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
