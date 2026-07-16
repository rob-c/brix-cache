"""Python ports for auth-oriented C shell runners."""

from __future__ import annotations

from pathlib import Path
import os
import shutil

from cmdscripts.compile_run import REPO_ROOT, result, run

NGX_SRC = Path("/tmp/nginx-1.28.3")
OBJS = NGX_SRC / "objs"


def pkg_config(args: list[str], fallback: list[str] | None = None) -> list[str]:
    proc = run(["pkg-config", *args], cwd=REPO_ROOT)
    if proc.returncode != 0:
        return fallback or []
    return proc.stdout.split()


def find_obj(name: str) -> Path | None:
    matches = sorted((OBJS / "addon").rglob(name))
    return matches[0] if matches else None


def compile_and_run(binary: Path, args: list[str], env: dict[str, str] | None = None) -> tuple[bool, str]:
    built = run(["gcc", *args, "-o", str(binary)], cwd=REPO_ROOT)
    if built.returncode != 0:
        return False, f"compile failed: {(built.stderr or built.stdout)[-3000:]}"
    ran = run([str(binary)], cwd=REPO_ROOT, env=env)
    return ran.returncode == 0, f"exited {ran.returncode}: {(ran.stderr or ran.stdout)[-3000:]}"


def run_x509_conformance(base: Path) -> list[tuple[bool, str]]:
    fixtures = Path(os.environ.get("BRIX_X509_FIXTURES", str(base / "x509conf")))
    forged = run(
        ["python3", "-c", f"import x509forge, pathlib; x509forge.forge_all(pathlib.Path({str(fixtures)!r}))"],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "tests"},
    )
    if forged.returncode != 0:
        return [result(False, f"forge x509 fixtures failed: {(forged.stderr or forged.stdout)[-3000:]}")]
    ok, message = compile_and_run(
        base / "brix_x509conf",
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            *pkg_config(["--cflags", "openssl"]),
            "tests/c/x509_conformance_test.c",
            "src/auth/crypto/signing_policy.c",
            "src/auth/crypto/store_policy.c",
            *pkg_config(["--libs", "openssl"], ["-lssl", "-lcrypto"]),
        ],
        env={"BRIX_X509_FIXTURES": str(fixtures)},
    )
    return [result(ok, f"x509_conformance {message}")]


def run_x509_oracle(base: Path) -> list[tuple[bool, str]]:
    fixtures = Path(os.environ.get("BRIX_X509_FIXTURES", str(base / "x509oracle")))
    forged = run(
        [
            "python3",
            "-c",
            f"import x509forge, clauses, pathlib; x509forge.build_all(pathlib.Path({str(fixtures)!r}), clauses.ALL_CLAUSES)",
        ],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "tests"},
    )
    if forged.returncode != 0:
        return [result(False, f"forge x509 oracle fixtures failed: {(forged.stderr or forged.stdout)[-3000:]}")]
    ok, message = compile_and_run(
        base / "brix_x509_oracle",
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            *pkg_config(["--cflags", "openssl"]),
            "tests/c/x509_oracle.c",
            "src/auth/crypto/signing_policy.c",
            "src/auth/crypto/store_policy.c",
            *pkg_config(["--libs", "openssl"], ["-lssl", "-lcrypto"]),
        ],
        env={"BRIX_X509_FIXTURES": str(fixtures)},
    )
    return [result(ok, f"x509_oracle {message}")]


def run_cred_mint(base: Path) -> list[tuple[bool, str]]:
    if shutil.which("openssl") is None:
        return [result(True, "SKIP openssl not on PATH")]
    obj = find_obj("cred_mint.o")
    if obj is None:
        return [result(True, "SKIP build cred_mint.o first")]
    ok, message = compile_and_run(
        base / "test_cred_mint",
        [
            "-O",
            "-Wall",
            "-I",
            "src",
            "-I",
            str(NGX_SRC / "src/core"),
            "-I",
            str(NGX_SRC / "src/event"),
            "-I",
            str(NGX_SRC / "src/os/unix"),
            "-I",
            str(OBJS),
            "tests/c/test_cred_mint.c",
            str(obj),
            "-lcrypto",
        ],
    )
    return [result(ok, f"cred_mint {message}")]


def run_ucred(base: Path) -> list[tuple[bool, str]]:
    if shutil.which("openssl") is None:
        return [result(True, "SKIP openssl not on PATH")]
    cryptography = run(["python3", "-c", "import cryptography"], cwd=REPO_ROOT)
    if cryptography.returncode != 0:
        return [result(True, "SKIP python3 cryptography unavailable")]
    obj = find_obj("ucred.o")
    if obj is None:
        return [result(True, "SKIP build ucred.o first")]
    ok, message = compile_and_run(
        base / "test_ucred",
        [
            "-O",
            "-Wall",
            "-I",
            "src",
            "-I",
            str(NGX_SRC / "src/core"),
            "-I",
            str(NGX_SRC / "src/event"),
            "-I",
            str(NGX_SRC / "src/os/unix"),
            "-I",
            str(OBJS),
            "tests/c/test_ucred.c",
            str(obj),
            "-lcrypto",
        ],
    )
    return [result(ok, f"ucred {message}")]


RUNNERS = {
    "x509_conformance": run_x509_conformance,
    "x509_oracle": run_x509_oracle,
    "cred_mint": run_cred_mint,
    "ucred": run_ucred,
}


def run_checks(base: Path, names: list[str] | None = None) -> list[tuple[bool, str]]:
    selected = names or sorted(RUNNERS)
    results: list[tuple[bool, str]] = []
    for name in selected:
        work = base / name
        work.mkdir(parents=True, exist_ok=True)
        results.extend(RUNNERS[name](work))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    names = argv or sorted(RUNNERS)
    with tempfile.TemporaryDirectory(prefix="c_auth_units.") as tmp:
        results = run_checks(Path(tmp), names=names)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
