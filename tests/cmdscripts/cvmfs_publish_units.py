"""CVMFS publishing-plane (phase-96) writer unit tests.

Compiles and runs the standalone C unit drivers for the Stratum-0 write path:
signers (sign.c), catalog writer (catalog_write.c), CAS object writer
(object_write.c) and the reflog/history databases — each verified against the
in-tree read stack as oracle.
"""

from __future__ import annotations

from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run

_COMMON = ["-Wall", "-Wextra", "-Werror", "-I", "shared"]

_UNITS = {
    "cvmfs_sign_ut": (
        [
            "shared/cvmfs/signature/sign_unittest.c",
            "shared/cvmfs/signature/sign.c",
            "shared/cvmfs/signature/manifest.c",
            "shared/cvmfs/signature/whitelist.c",
            "shared/cvmfs/signature/verify.c",
            "shared/cvmfs/object/object.c",
            "shared/cvmfs/grammar/hash.c",
        ],
        ["-lcrypto", "-lz"],
    ),
    "cvmfs_catw_ut": (
        [
            "shared/cvmfs/catalog/catalog_write_unittest.c",
            "shared/cvmfs/catalog/catalog_write.c",
            "shared/cvmfs/catalog/catalog.c",
            "shared/cvmfs/grammar/hash.c",
        ],
        ["-lsqlite3", "-lcrypto"],
    ),
    "cvmfs_objw_ut": (
        [
            "shared/cvmfs/object/object_write_unittest.c",
            "shared/cvmfs/object/object_write.c",
            "shared/cvmfs/object/object.c",
            "shared/cvmfs/grammar/hash.c",
            "shared/cache/cas_store.c",
            # cas_store.c dispatches through the packed-CAS backend, which rests
            # on the platform shims and the zlib/zstd pack codec.
            "shared/cache/cas_pack.c",
            "shared/cvmfs/platform/platform.c",
        ],
        ["-lcrypto", "-lz", "-lzstd"],
    ),
    "cvmfs_reflog_ut": (
        [
            "shared/cvmfs/reflog/reflog_unittest.c",
            "shared/cvmfs/reflog/reflog.c",
            "shared/cvmfs/history/history.c",
            "shared/cvmfs/object/object.c",
            "shared/cvmfs/grammar/hash.c",
        ],
        ["-lsqlite3", "-lcrypto", "-lz"],
    ),
}


def run_checks(base: Path) -> list[tuple[bool, str]]:
    results: list[tuple[bool, str]] = []
    for name, (sources, libs) in _UNITS.items():
        binary = base / name
        built = compile_binary(binary, _COMMON + sources + libs, cwd=REPO_ROOT)
        if built.returncode != 0:
            results.append(result(False, f"compile {name} failed: {(built.stderr or built.stdout)[-2000:]}"))
            continue
        ran = run([str(binary)], cwd=REPO_ROOT)
        results.append(result(ran.returncode == 0, f"{name} exited {ran.returncode}: {(ran.stderr or ran.stdout or '').strip()[-2000:]}"))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cvmfs_publish.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
