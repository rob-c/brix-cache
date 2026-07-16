"""Standalone guard-core unit test."""

from __future__ import annotations

from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run


def run_checks(base: Path) -> list[tuple[bool, str]]:
    binary = base / "guard_test"
    sources = sorted(str(path.relative_to(REPO_ROOT)) for path in (REPO_ROOT / "src/net/guard").glob("guard_*.c"))
    built = compile_binary(
        binary,
        ["-Wall", "-Wextra", "-std=c99", "-I", "src/net/guard", *sources],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return [result(False, f"compile guard core failed: {(built.stderr or built.stdout)[-2000:]}")]
    ran = run([str(binary)], cwd=REPO_ROOT)
    return [result(ran.returncode == 0, f"guard core exited {ran.returncode}: {(ran.stderr or ran.stdout)[-2000:]}")]


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="guard_core.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
