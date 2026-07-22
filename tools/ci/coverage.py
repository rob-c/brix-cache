#!/usr/bin/env python3
#
# WHAT: Build the brix module (objs/nginx) + client with gcov instrumentation,
#       run the test suite against that instrumented binary, and emit an lcov
#       line/branch-coverage report for src/ and client/ — with an OPTIONAL
#       enforced floor (COVERAGE_MIN).
#
# WHY:  QUALITY_ROADMAP §2.3.3/§3.4 called for coverage tracking; it was the one
#       genuinely-open quality-gate item (there was no gcov lane at all, so the
#       85%/90% targets were unmeasured). This stands the lane up. It ships
#       REPORT-ONLY by default: per the hyper-hardening B-1 lesson, a numeric
#       gate must not be flipped to blocking before a reviewed baseline exists —
#       run it, read the number, THEN set COVERAGE_MIN in CI.
#
# HOW:  1. operator_build build_coverage → ./configure --with-cc-opt='--coverage
#          -O0 -g' + make (nginx + client). Instrumented objects drop .gcno now,
#          .gcda as the binary runs.
#       2. Run $COVERAGE_TEST_CMD (default: the fast fleet tier) so real request
#          paths through src/ execute and populate .gcda.
#       3. lcov --capture over the nginx build dir + client, restrict to src/ +
#          client/, strip system headers, print the total line rate, genhtml.
#       4. If COVERAGE_MIN is set and the total line rate is below it, exit 1.
#
# USAGE:
#   tools/ci/coverage.py                       # build + fast-tier run + report
#   COVERAGE_TEST_CMD='pytest tests/test_root_basic.py' tools/ci/coverage.py
#   COVERAGE_MIN=85 tools/ci/coverage.py       # also enforce an 85% line floor
#
# Requires: lcov (geninfo/genhtml), gcov. Skips cleanly (exit 0) if absent so the
#           lane never hard-fails on a missing tool — it reports SKIP instead.

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def run_or_abort(cmd, **kwargs) -> subprocess.CompletedProcess:
    """Run a command; on non-zero exit, abort with that exit code (set -e)."""
    proc = subprocess.run(cmd, **kwargs)
    if proc.returncode != 0:
        sys.exit(proc.returncode)
    return proc


def main() -> int:
    # ROOT from this script's location (tools/ci/ → repo root), like the other
    # guards: the runner must work regardless of the caller's cwd (the pytest
    # guard wrapper runs with cwd inside the test fleet root, not the repo).
    root = str(Path(__file__).resolve().parents[2])

    nginx_src = os.environ.get("NGINX_SRC") or "/tmp/nginx-1.28.3"
    out_dir = os.environ.get("COVERAGE_OUT") or f"{root}/coverage"
    test_cmd = os.environ.get("COVERAGE_TEST_CMD") or \
        "python3 -m cmdscripts.operator_runtime suite --fast"

    if shutil.which("lcov") is None or shutil.which("gcov") is None:
        print("coverage: SKIP — lcov/gcov not installed (apt-get install -y lcov)")
        return 0
    if not os.access(f"{nginx_src}/configure", os.X_OK):
        print(f"coverage: SKIP — nginx source not found at {nginx_src} (set NGINX_SRC)")
        return 0

    os.makedirs(out_dir, exist_ok=True)

    print("coverage: 1/4 building gcov-instrumented nginx + client…")
    run_or_abort(
        ["python3", "-m", "cmdscripts.operator_build", "build_coverage"],
        cwd=f"{root}/tests",
    )

    # Zero any stale counters from a prior run so the number reflects THIS suite only.
    with open(os.devnull, "wb") as devnull:
        subprocess.run(
            ["lcov", "--directory", f"{nginx_src}/objs",
             "--directory", f"{root}/client", "--zerocounters"],
            stdout=devnull, stderr=devnull,
        )

    print("coverage: 2/4 running suite against the instrumented binary…")
    print(f"          $COVERAGE_TEST_CMD = {test_cmd}")
    suite_rc = subprocess.run(test_cmd, shell=True, cwd=f"{root}/tests").returncode
    if suite_rc != 0:
        print(f"coverage: WARNING — test command exited {suite_rc}; "
              "coverage reflects whatever ran")

    print("coverage: 3/4 capturing counters with lcov…")
    raw = f"{out_dir}/coverage.raw.info"
    info = f"{out_dir}/coverage.info"
    run_or_abort([
        "lcov", "--capture", "--quiet",
        "--directory", f"{nginx_src}/objs", "--directory", f"{root}/client",
        "--rc", "geninfo_unexecuted_blocks=1",
        "--output-file", raw,
    ])
    # Keep only OUR sources; drop nginx core, system headers, and generated code.
    run_or_abort([
        "lcov", "--quiet", "--extract", raw,
        f"{root}/src/*", f"{root}/client/*", "--output-file", info,
    ])
    Path(raw).unlink(missing_ok=True)

    print("coverage: 4/4 rendering html + summary…")
    subprocess.run(["genhtml", "--quiet", "--output-directory",
                    f"{out_dir}/html", info])

    # Total line rate (percent) straight from lcov's summary.
    summary = subprocess.run(
        ["lcov", "--summary", info],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    ).stdout
    for line in summary.splitlines():
        if re.search(r"lines|functions|branches", line):
            print(line)
    pct = ""
    for line in summary.splitlines():
        if "lines" in line:
            fields = re.split(r"[:%]", line)
            if len(fields) >= 2:
                pct = fields[1].replace(" ", "")
            break
    print(f"coverage: total line coverage = {pct or 'unknown'}%  "
          f"(html: {out_dir}/html/index.html)")

    coverage_min = os.environ.get("COVERAGE_MIN")
    if coverage_min:
        if not pct:
            print(f"coverage: FAIL — COVERAGE_MIN={coverage_min} set but line rate "
                  "could not be parsed", file=sys.stderr)
            return 1
        # Integer compare on the floor (bash has no float); require ceil(PCT) >= MIN.
        if float(pct) < float(coverage_min):
            print(f"coverage: FAIL — line coverage {pct}% < floor {coverage_min}%",
                  file=sys.stderr)
            return 1
        print(f"coverage: OK — line coverage {pct}% >= floor {coverage_min}%")

    return 0


if __name__ == "__main__":
    sys.exit(main())
