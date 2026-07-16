"""Build and run the shared cache CAS unit test."""

from __future__ import annotations

from pathlib import Path

from cmdscripts import run

REPO_ROOT = Path(__file__).resolve().parents[2]


def run_checks(base: Path) -> list[tuple[bool, str]]:
    out = base / "cas_ut"
    compile_result = run(
        [
            "gcc",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(REPO_ROOT / "shared"),
            "-o",
            str(out),
            str(REPO_ROOT / "shared" / "cache" / "cas_store_unittest.c"),
            str(REPO_ROOT / "shared" / "cache" / "cas_store.c"),
        ]
    )
    if compile_result.returncode != 0:
        return [(False, "CAS unit compile failed: " + (compile_result.stderr or compile_result.stdout)[-4000:])]

    run_result = run([str(out)])
    if run_result.returncode != 0:
        return [(False, "CAS unit binary failed: " + (run_result.stderr or run_result.stdout)[-4000:])]
    return [(True, "CAS store unit suite passed")]


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cache_unit.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_cache_unit: ALL PASS")
        return 0
    print("run_cache_unit: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
