"""brixMount dispatch core unit tests."""

from __future__ import annotations

from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run


def run_checks(base: Path) -> list[tuple[bool, str]]:
    binary = base / "brixmount_ut"
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "shared",
            "-I",
            "client/lib",
            "-I",
            "src",
            "-DBRIXMOUNT_NO_MAIN",
            "client/apps/fs/brixmount_unittest.c",
            "client/apps/fs/brixmount.c",
            "client/lib/cli/suggest.c",
            "client/lib/cli/cli_hint.c",
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return [result(False, f"compile brixmount unit failed: {(built.stderr or built.stdout)[-2000:]}")]
    ran = run([str(binary)], cwd=REPO_ROOT)
    return [result(ran.returncode == 0, f"brixmount unit exited {ran.returncode}: {(ran.stderr or ran.stdout)[-2000:]}")]


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="brixmount_unit.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
