"""Build and run the unit tests for the newly implemented SD driver slots.

The slots closed in the storage-driver gap wave each encode a decision that is
invisible from the outside — classified the wrong way it is not a crash, it is
an unreadable object reported as ONLINE, a billable archive retrieval issued for
one that was already readable, or one object's descriptor handed out addressing
another object's bytes:

  http    the WLCG Tape REST API residency/recall pair (POST archiveinfo / POST
          stage), the API-base allowlist, and the advisory-metadata setattr
          landed alongside them
  remote  S3 GLACIER residency/recall (HEAD x-amz-storage-class / POST ?restore)
  block   zero-copy and read-ahead over an extent window (read_sendfile_fd,
          read_advise)

Every one is a unity build: the test TU #includes the driver .c and supplies the
handful of symbols it delegates to as mocks, so nothing leaves the process and
every scenario is exact.  They share this runner — and the pytest wrapper
parametrises over the same table — so a unit added here cannot end up built but
never run.
"""

from __future__ import annotations

from pathlib import Path

from cmdscripts import run

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"
UNIT = REPO_ROOT / "tests" / "unit"

# name -> (test TU, extra .c files it links, the line a passing run prints).
# The extra sources are the ngx-free compat kernels the driver reaches for; the
# remote and block units need none — their delegates are mocked in the TU.
UNITS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "http": (
        "test_sd_http_nearline.c",
        (
            "core/compat/json_min.c",
            "core/compat/json_iter.c",
            "fs/backend/meta_advisory.c",
            "fs/backend/meta_advisory_sd.c",
        ),
        "sd_http nearline/setattr suite: all checks passed",
    ),
    "remote": (
        "test_sd_remote_nearline.c",
        (),
        "sd_remote nearline suite: all checks passed",
    ),
    "block": (
        "test_sd_block_zerocopy.c",
        (),
        "sd_block zero-copy/advise suite: all checks passed",
    ),
}


def run_one(base: Path, name: str) -> list[tuple[bool, str]]:
    """Compile and run one unit; a list so the caller can concatenate them."""
    tu, extra, expect = UNITS[name]
    out = base / f"sd_{name}_slot_ut"
    cmd = [
        "gcc", "-Wall", "-Wextra", "-Werror", "-g",
        # The driver TUs are compiled with no nginx headers at all; the shim in
        # sd.h supplies the handful of types and NGX_* codes they use.  It has
        # to be on the command line rather than #defined in the test, because
        # the -I-resolved include chain of the separately compiled sources is
        # read before the test's own first line.
        "-DXRDPROTO_NO_NGX=1",
        "-I", str(SRC),
        "-I", str(SRC / "fs" / "backend"),
        str(UNIT / tu),
        *[str(SRC / rel) for rel in extra],
        "-o", str(out),
    ]
    built = run(cmd)
    if built.returncode != 0:
        return [(False, f"sd_{name} slot unit compile failed: "
                 + (built.stderr or built.stdout)[-4000:])]

    ran = run([str(out)])
    if ran.returncode != 0 or expect not in (ran.stdout or ""):
        return [(False, f"sd_{name} slot unit failed: "
                 + (ran.stdout or ran.stderr)[-4000:])]
    return [(True, expect)]


def run_checks(base: Path) -> list[tuple[bool, str]]:
    results: list[tuple[bool, str]] = []
    for name in UNITS:
        results.extend(run_one(base, name))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sd_slot_unit.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_sd_slot_unit: ALL PASS")
        return 0
    print("run_sd_slot_unit: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
