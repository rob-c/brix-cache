"""Python ports for auth-oriented C shell runners."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import tempfile

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


# Pin TMPDIR for every child process: conftest points the inherited TMPDIR into
# /tmp/xrd-test, which concurrent test sessions wipe/rotate mid-run — gcc loses
# its intermediate .s files mid-compile and forge temp dirs vanish.
HERMETIC_ENV = {"TMPDIR": "/tmp"}


def compile_and_run(binary: Path, args: list[str], env: dict[str, str] | None = None) -> tuple[bool, str]:
    child_env = {**HERMETIC_ENV, **(env or {})}
    built = run(["gcc", *args, "-o", str(binary)], cwd=REPO_ROOT, env=child_env)
    if built.returncode != 0:
        return False, f"compile failed: {(built.stderr or built.stdout)[-3000:]}"
    ran = run([str(binary)], cwd=REPO_ROOT, env=child_env)
    return ran.returncode == 0, f"exited {ran.returncode}: {(ran.stderr or ran.stdout)[-3000:]}"


# Single source of truth for the x509 harness link lines. Any file-split of
# these TUs must be reflected here ONCE; the x509_link runner below fails fast
# if the list goes stale (undefined-symbol link errors).
X509_POLICY_SOURCES = [
    "src/auth/crypto/signing_policy.c",
    "src/auth/crypto/store_policy.c",
    "src/auth/crypto/store_policy_store.c",
    "src/auth/crypto/store_policy_conformance.c",
]

X509_HARNESS_TUS = {
    "x509_conformance": "tests/c/x509_conformance_test.c",
    "x509_oracle": "tests/c/x509_oracle.c",
}


def x509_gcc_args(harness_tu: str, sources: list[str] | None = None) -> list[str]:
    return [
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        "src",
        *pkg_config(["--cflags", "openssl"]),
        harness_tu,
        *(X509_POLICY_SOURCES if sources is None else sources),
        *pkg_config(["--libs", "openssl"], ["-lssl", "-lcrypto"]),
    ]


def link_x509_harness(base: Path, name: str, sources: list[str] | None = None) -> tuple[bool, str]:
    built = run(
        ["gcc", *x509_gcc_args(X509_HARNESS_TUS[name], sources), "-o", str(base / f"link_{name}")],
        cwd=REPO_ROOT,
    )
    return built.returncode == 0, (built.stderr or built.stdout)[-3000:]


def run_x509_link(base: Path) -> list[tuple[bool, str]]:
    results: list[tuple[bool, str]] = []
    for name in sorted(X509_HARNESS_TUS):
        ok, detail = link_x509_harness(base, name)
        results.append(result(ok, f"x509_link {name} {'linked' if ok else f'FAILED: {detail}'}"))
    return results


def x509_fixture_dir(name: str) -> tuple[Path, str | None]:
    """Pick the forge output dir; returns (dir, owned-path-to-delete-or-None).

    Never place the corpus under TMPDIR: conftest points TMPDIR at the shared
    /tmp/xrd-test/tmp basetemp, and concurrent pytest sessions rotate each
    other's roots to garbage-* and rm_rf them mid-run — the forged CAs vanish
    and every accept clause fails closed as a reject.
    """
    override = os.environ.get("BRIX_X509_FIXTURES")
    if override:
        return Path(override), None
    made = tempfile.mkdtemp(prefix=f"brix_{name}.", dir="/tmp")
    return Path(made), made


def run_x509_conformance(base: Path) -> list[tuple[bool, str]]:
    fixtures, owned = x509_fixture_dir("x509conf")
    try:
        forged = run(
            ["python3", "-c", f"import x509forge, pathlib; x509forge.forge_all(pathlib.Path({str(fixtures)!r}))"],
            cwd=REPO_ROOT,
            env={"PYTHONPATH": "tests", **HERMETIC_ENV},
        )
        if forged.returncode != 0:
            return [result(False, f"forge x509 fixtures failed: {(forged.stderr or forged.stdout)[-3000:]}")]
        ok, message = compile_and_run(
            fixtures / "brix_x509conf",
            x509_gcc_args(X509_HARNESS_TUS["x509_conformance"]),
            env={"BRIX_X509_FIXTURES": str(fixtures)},
        )
        return [result(ok, f"x509_conformance {message}")]
    finally:
        if owned:
            shutil.rmtree(owned, ignore_errors=True)


def run_x509_oracle(base: Path) -> list[tuple[bool, str]]:
    fixtures, owned = x509_fixture_dir("x509oracle")
    try:
        forged = run(
            [
                "python3",
                "-c",
                f"import x509forge, clauses, pathlib; x509forge.build_all(pathlib.Path({str(fixtures)!r}), clauses.ALL_CLAUSES)",
            ],
            cwd=REPO_ROOT,
            env={"PYTHONPATH": "tests", **HERMETIC_ENV},
        )
        if forged.returncode != 0:
            return [result(False, f"forge x509 oracle fixtures failed: {(forged.stderr or forged.stdout)[-3000:]}")]
        ok, message = compile_and_run(
            fixtures / "brix_x509_oracle",
            x509_gcc_args(X509_HARNESS_TUS["x509_oracle"]),
            env={"BRIX_X509_FIXTURES": str(fixtures)},
        )
        return [result(ok, f"x509_oracle {message}")]
    finally:
        if owned:
            shutil.rmtree(owned, ignore_errors=True)


def run_cred_mint(base: Path) -> list[tuple[bool, str]]:
    if shutil.which("openssl") is None:
        return [result(True, "SKIP openssl not on PATH")]
    obj = find_obj("cred_mint.o")
    if obj is None:
        return [result(True, "SKIP build cred_mint.o first")]
    siblings = [str(s) for s in (find_obj("cred_mint_cert.o"),) if s]
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
            *siblings,
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
    siblings = [str(s) for s in (find_obj("ucred_parse.o"),) if s]
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
            *siblings,
            "-lcrypto",
        ],
    )
    return [result(ok, f"ucred {message}")]


RUNNERS = {
    "x509_link": run_x509_link,
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
