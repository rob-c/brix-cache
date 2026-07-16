"""Python port of tests/unit/run_tests.sh."""

from __future__ import annotations

from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, result, run

UNIT_DIR = REPO_ROOT / "tests" / "unit"


IMPLS = {
    "test_b64url.c": "../../src/auth/token/b64url.c",
    "test_crc32c.c": "../../src/core/compat/crc32c.c",
    "test_crc64.c": "../../src/core/compat/crc64.c",
    "test_json.c": "../../src/auth/token/json.c",
    "test_scopes.c": "../../src/auth/token/scopes.c",
    "test_xml_compat.c": "../../src/core/compat/xml.c",
}


def pkg_config(args: list[str]) -> list[str]:
    proc = run(["pkg-config", *args], cwd=REPO_ROOT)
    if proc.returncode != 0:
        return []
    return proc.stdout.split()


def run_checks(base: Path) -> list[tuple[bool, str]]:
    cflags = ["-Wall", "-Wextra", "-I../../src", "-I../../src/token", "-I../../src/crypto", "-I../../src/compat", "-g"]
    ldflags = ["-lssl", "-lcrypto"]
    if run(["pkg-config", "--exists", "libxml-2.0"], cwd=REPO_ROOT).returncode == 0:
        cflags.extend(pkg_config(["--cflags", "libxml-2.0"]))
        cflags.append("-DBRIX_HAVE_LIBXML2=1")
        ldflags.extend(pkg_config(["--libs", "libxml-2.0"]))
    if run(["pkg-config", "--exists", "jansson"], cwd=REPO_ROOT).returncode != 0:
        return [result(False, "jansson library is required but was not found")]
    cflags.extend(pkg_config(["--cflags", "jansson"]))
    ldflags.extend(pkg_config(["--libs", "jansson"]))

    results: list[tuple[bool, str]] = []
    for source in sorted(UNIT_DIR.glob("test_*.c")):
        binary = base / source.stem
        args = ["gcc", *cflags, source.name]
        impl = IMPLS.get(source.name)
        if impl:
            args.append(impl)
        args.extend(["-o", str(binary), *ldflags])
        built = run(args, cwd=UNIT_DIR)
        if built.returncode != 0:
            results.append(result(False, f"compile {source.name} failed: {(built.stderr or built.stdout)[-2000:]}"))
            continue
        ran = run([str(binary)], cwd=UNIT_DIR)
        results.append(result(ran.returncode == 0, f"{source.stem} exited {ran.returncode}: {(ran.stderr or ran.stdout)[-2000:]}"))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="unit_tests.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("All unit tests passed.")
        return 0
    print("Some unit tests failed.")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
