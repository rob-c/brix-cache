"""CVMFS object decode and fetch orchestrator unit tests."""

from __future__ import annotations

from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run


def run_checks(base: Path) -> list[tuple[bool, str]]:
    binary = base / "cvmfs_fetch_ut"
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "shared",
            "shared/cvmfs/fetch/fetch_unittest.c",
            "shared/cvmfs/fetch/fetch.c",
            "shared/cvmfs/object/object.c",
            "shared/cvmfs/failover/failover.c",
            "shared/cvmfs/grammar/hash.c",
            "shared/cache/cas_store.c",
            "-lcrypto",
            "-lz",
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return [result(False, f"compile CVMFS fetch unit failed: {(built.stderr or built.stdout)[-2000:]}")]
    ran = run([str(binary)], cwd=REPO_ROOT)
    return [result(ran.returncode == 0, f"CVMFS fetch unit exited {ran.returncode}: {(ran.stderr or ran.stdout)[-2000:]}")]


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cvmfs_fetch.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
