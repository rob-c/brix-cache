"""Layer-1 WLCG token conformance unit tests."""

from __future__ import annotations

from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run


def run_checks(base: Path) -> list[tuple[bool, str]]:
    results: list[tuple[bool, str]] = []
    scope_bin = base / "token_scope_ut"
    scope_build = compile_binary(
        scope_bin,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/token_scope_unittest.c",
            "src/auth/token/scopes.c",
            "-lcrypto",
        ],
        cwd=REPO_ROOT,
    )
    if scope_build.returncode != 0:
        return [result(False, f"compile token_scope_unittest failed: {(scope_build.stderr or scope_build.stdout)[-2000:]}")]
    scope_run = run([str(scope_bin)], cwd=REPO_ROOT)
    results.append(result(scope_run.returncode == 0, f"token_scope_unittest exited {scope_run.returncode}: {(scope_run.stderr or scope_run.stdout)[-2000:]}"))

    conf_bin = base / "token_conformance_ut"
    conf_build = compile_binary(
        conf_bin,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/token_conformance_test.c",
            "src/auth/token/b64url.c",
            "src/auth/token/json.c",
            "-lcrypto",
            "-ljansson",
        ],
        cwd=REPO_ROOT,
    )
    if conf_build.returncode != 0:
        return [*results, result(False, f"compile token_conformance_test failed: {(conf_build.stderr or conf_build.stdout)[-2000:]}")]
    conf_run = run([str(conf_bin)], cwd=REPO_ROOT)
    results.append(result(conf_run.returncode == 0, f"token_conformance_test exited {conf_run.returncode}: {(conf_run.stderr or conf_run.stdout)[-2000:]}"))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="token_conformance.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("ALL TOKEN CONFORMANCE UNIT TESTS PASSED")
        return 0
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
