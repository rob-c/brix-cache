"""Python port of tests/fuzz/run_all.sh."""

from __future__ import annotations

from pathlib import Path
import os

from cmdscripts.compile_run import REPO_ROOT, result, run

FUZZ_DIR = REPO_ROOT / "tests" / "fuzz"
SAN = ["-O1", "-g", "-fsanitize=fuzzer,address,undefined"]


BUILD_ARGS = {
    "fuzz_safe_size": [
        "clang",
        *SAN,
        "-I",
        "../../src",
        "-I",
        "../../src/core/compat",
        "fuzz_safe_size.c",
        "-o",
        "fuzz_safe_size",
    ],
    "fuzz_b64url": [
        "clang",
        *SAN,
        "-I",
        "../../src",
        "-I",
        "../../src/auth/token",
        "fuzz_b64url.c",
        "../../src/auth/token/b64url.c",
        "-lcrypto",
        "-o",
        "fuzz_b64url",
    ],
    "fuzz_zip_dir": [
        "clang",
        *SAN,
        "-iquote",
        "../../src",
        "fuzz_zip_dir.c",
        "-lz",
        "-o",
        "fuzz_zip_dir",
    ],
}


def run_checks(base: Path, fuzz_time: str | None = None) -> list[tuple[bool, str]]:
    seconds = fuzz_time or os.environ.get("FUZZ_TIME", "60")
    results: list[tuple[bool, str]] = []
    for target, build_args in BUILD_ARGS.items():
        built = run(build_args, cwd=FUZZ_DIR)
        if built.returncode != 0:
            results.append(result(False, f"build {target} failed: {(built.stderr or built.stdout)[-2500:]}"))
            continue
        corpus = FUZZ_DIR / f"corpus_{target.removeprefix('fuzz_')}"
        corpus.mkdir(exist_ok=True)
        run([str(FUZZ_DIR / target), "-runs=0", str(corpus)], cwd=FUZZ_DIR)
        ran = run([str(FUZZ_DIR / target), f"-max_total_time={seconds}", str(corpus)], cwd=FUZZ_DIR)
        results.append(result(ran.returncode == 0, f"{target} fuzzed for {seconds}s: {(ran.stderr or ran.stdout)[-2500:]}"))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="fuzz_all.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print(f"all fuzz targets clean (FUZZ_TIME={os.environ.get('FUZZ_TIME', '60')}s each)")
        return 0
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
