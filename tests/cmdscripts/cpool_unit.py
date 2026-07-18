"""brix_cpool generic connection-pool engine unit tests (no network)."""

from __future__ import annotations

from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run


def run_checks(base: Path) -> list[tuple[bool, str]]:
    binary = base / "cpool_ut"
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-DXRDPROTO_NO_NGX",
            "-I",
            "client/lib",
            "-I",
            "src",
            "client/lib/net/cpool_unittest.c",
            "client/lib/net/cpool.c",
            "client/lib/core/types/status.c",
            "shared/xrdproto/build/kxr_names.o",
            "shared/xrdproto/build/error_mapping.o",
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return [result(False, f"compile cpool unit failed: {(built.stderr or built.stdout)[-2000:]}")]
    ran = run([str(binary)], cwd=REPO_ROOT)
    ok = ran.returncode == 0 and "ALL PASS" in (ran.stdout or "")
    return [result(ok, f"cpool unit exited {ran.returncode}: {(ran.stdout or '') + (ran.stderr or '')[-2000:]}")]


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cpool_unit.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
