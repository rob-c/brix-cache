"""Build and run the sd_s3 read-path in-path-integrity unit test.

The test (tests/unit/test_sd_s3_read.c) drives sd_s3_pread through a mock HTTP
transport and asserts the guards that reject a hostile/broken middlebox's
shifted, whole-object'd, or emptied ranged-GET responses — corruption/truncation
the TCP checksum and libcurl cannot catch.  It is a unity build (the test TU
#includes sd_s3.c + sd_s3_sign.c) linked against the ngx-free compat kernels.
"""

from __future__ import annotations

from pathlib import Path

from cmdscripts import run

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"
UNIT = REPO_ROOT / "tests" / "unit"


def run_checks(base: Path) -> list[tuple[bool, str]]:
    out = base / "sd_s3_read_ut"
    compat = SRC / "core" / "compat"
    cmd = [
        "gcc", "-Wall", "-Wextra", "-g",
        "-I", str(SRC),
        "-I", str(SRC / "fs" / "backend" / "s3"),
        str(UNIT / "test_sd_s3_read.c"),
        str(compat / "crypto.c"),
        str(compat / "hex.c"),
        str(compat / "sigv4.c"),
        str(compat / "uri.c"),
        str(compat / "host_format.c"),
        "-o", str(out),
        "-lssl", "-lcrypto",
    ]
    built = run(cmd)
    if built.returncode != 0:
        return [(False, "sd_s3 read unit compile failed: "
                 + (built.stderr or built.stdout)[-4000:])]

    ran = run([str(out)])
    if ran.returncode != 0:
        return [(False, "sd_s3 read unit binary failed: "
                 + (ran.stderr or ran.stdout)[-4000:])]
    return [(True, "sd_s3 read-path integrity guards passed")]


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sd_s3_read_unit.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_sd_s3_read_unit: ALL PASS")
        return 0
    print("run_sd_s3_read_unit: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
