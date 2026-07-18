"""Table-driven ports for small standalone C unit shell runners."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run


@dataclass(frozen=True)
class CUnitSpec:
    name: str
    output: str
    args: tuple[str, ...]


SPECS: dict[str, CUnitSpec] = {
    "error_mapping": CUnitSpec(
        "error_mapping",
        "test_error_mapping",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DXRDPROTO_NO_NGX",
            "-I",
            "src",
            "tests/c/test_error_mapping.c",
            "src/core/compat/error_mapping.c",
        ),
    ),
    "fs_usage": CUnitSpec(
        "fs_usage",
        "test_fs_usage",
        ("-O", "-Wall", "-Werror", "tests/c/test_fs_usage.c"),
    ),
    "meta_advisory": CUnitSpec(
        "meta_advisory",
        "test_meta_advisory",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "tests/c/test_meta_advisory.c",
            "src/fs/backend/meta_advisory.c",
        ),
    ),
    "site_n2n": CUnitSpec(
        "site_n2n",
        "test_site_n2n",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "tests/c/test_site_n2n.c",
            "src/fs/backend/site_n2n.c",
        ),
    ),
    "stage_admit": CUnitSpec(
        "stage_admit",
        "test_stage_admit",
        ("-O", "-Wall", "-Werror", "tests/c/test_stage_admit.c"),
    ),
    "sd_ceph_compat": CUnitSpec(
        "sd_ceph_compat",
        "test_sd_ceph_compat",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "tests/c/test_sd_ceph_compat.c",
            "src/fs/backend/rados/sd_ceph_compat.c",
        ),
    ),
    "pathres": CUnitSpec(
        "pathres",
        "test_pathres_units",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DBRIX_PATH_OP_PATH_H",
            "-I",
            "src",
            "-include",
            "tests/c/pathres_shim.h",
            "tests/c/test_pathres_units.c",
            "src/core/compat/path.c",
        ),
    ),
    "seccomp": CUnitSpec(
        "seccomp",
        "test_seccomp",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-D_GNU_SOURCE",
            "-DBRIX_HAVE_SECCOMP=1",
            "-I",
            "src",
            "tests/c/test_seccomp.c",
            "src/core/seccomp/seccomp_core.c",
            "-lseccomp",
        ),
    ),
    "opaque_schema": CUnitSpec(
        "opaque_schema",
        "test_opaque_schema",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/test_opaque_schema.c",
            "src/protocols/root/path/opaque_validate.c",
        ),
    ),
    "negcache": CUnitSpec(
        "negcache",
        "test_negcache",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/test_negcache.c",
            "src/core/negcache/negcache_core.c",
        ),
    ),
    "wverify": CUnitSpec(
        "wverify",
        "test_wverify",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/test_wverify.c",
            "src/core/compat/wverify.c",
            "-lz",
        ),
    ),
    "cred_stage": CUnitSpec(
        "cred_stage",
        "test_cred_stage",
        (
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-D_GNU_SOURCE",
            "-I",
            "src",
            "tests/c/test_cred_stage.c",
            "src/core/compat/cred_stage.c",
        ),
    ),
    "sesslog": CUnitSpec(
        "sesslog",
        "brix_sesslog_ut",
        (
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "src",
            "tests/c/sesslog_unittest.c",
            "src/observability/sesslog/sesslog.c",
        ),
    ),
}


def run_one(name: str, base: Path) -> list[tuple[bool, str]]:
    spec = SPECS[name]
    binary = base / spec.output
    built = compile_binary(binary, list(spec.args), cwd=REPO_ROOT)
    if built.returncode != 0:
        return [result(False, f"compile {name} failed: {(built.stderr or built.stdout)[-2000:]}")]
    ran = run([str(binary)], cwd=REPO_ROOT)
    return [result(ran.returncode == 0, f"{name} exited {ran.returncode}: {(ran.stderr or ran.stdout)[-2000:]}")]


def run_checks(base: Path, names: list[str] | None = None) -> list[tuple[bool, str]]:
    selected = names or sorted(SPECS)
    results: list[tuple[bool, str]] = []
    for name in selected:
        results.extend(run_one(name, base / name))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    names = argv or sorted(SPECS)
    with tempfile.TemporaryDirectory(prefix="c_simple_units.") as tmp:
        base = Path(tmp)
        for name in names:
            (base / name).mkdir()
        results = run_checks(base, names=names)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
