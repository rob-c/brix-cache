#!/usr/bin/env python3
#
# WHAT: Build the brix module (objs/nginx) + client with gcov instrumentation,
#       run the test suite against that instrumented binary, and emit an lcov
#       line/branch-coverage report for src/ and client/ and enforce the line
#       floor selected from the reviewed fast-tier baseline (COVERAGE_MIN).
#
# WHY:  QUALITY_ROADMAP §2.3.3/§3.4 called for coverage tracking; it was the one
#       genuinely-open quality-gate item (there was no gcov lane at all, so the
#       85%/90% targets were unmeasured). This stands the lane up. It ships
#       The CI lane sets COVERAGE_MIN=67 after the 2026-09-03 instrumented
#       fast-tier baseline measured 68.9%. Local callers may omit the variable
#       when they only need a report, but a failing test command always fails.
#
# HOW:  1. operator_build build_coverage → ./configure --with-cc-opt='--coverage
#          -O0 -g' + make (nginx + client). Instrumented objects drop .gcno now,
#          .gcda as the binary runs.
#       2. Run $COVERAGE_TEST_CMD (default: the fast fleet tier) so real request
#          paths through src/ execute and populate .gcda.
#       3. lcov --capture over the nginx build dir + client, restrict to src/ +
#          client/, strip system headers, print the total line rate, genhtml.
#       4. Fail when the suite failed or the total line rate is below an enabled
#          COVERAGE_MIN floor. Counter capture still runs after a suite failure
#          so CI retains the diagnostic report.
#
# USAGE:
#   tools/ci/coverage.py                       # build + fast-tier run + report
#   COVERAGE_TEST_CMD='pytest tests/test_root_basic.py' tools/ci/coverage.py
#   COVERAGE_MIN=85 tools/ci/coverage.py       # also enforce an 85% line floor
#
# Requires: lcov (geninfo/genhtml), gcov. The generic local runner skips when
#           absent; the workflow installs both before invoking it.

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
    root, nginx_src, out_dir, test_cmd = _settings()
    reason = _skip_reason(nginx_src)
    if reason:
        print(reason)
        return 0
    return _collect(root, nginx_src, out_dir, test_cmd)


def _settings():
    root = str(Path(__file__).resolve().parents[2])
    nginx_src = os.environ.get("NGINX_SRC") or "/tmp/nginx-1.28.3"
    out_dir = os.environ.get("COVERAGE_OUT") or f"{root}/coverage"
    test_cmd = os.environ.get("COVERAGE_TEST_CMD") or \
        "python3 -m cmdscripts.operator_runtime suite --fast"
    return root, nginx_src, out_dir, test_cmd


def _skip_reason(nginx_src: str) -> str:
    if shutil.which("lcov") is None or shutil.which("gcov") is None:
        return "coverage: SKIP — lcov/gcov not installed (apt-get install -y lcov)"
    if not os.access(f"{nginx_src}/configure", os.X_OK):
        return f"coverage: SKIP — nginx source not found at {nginx_src} (set NGINX_SRC)"
    return ""


def _collect(root: str, nginx_src: str, out_dir: str, test_cmd: str) -> int:

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
        print(f"coverage: FAIL — test command exited {suite_rc}; "
              "capturing partial counters for diagnostics", file=sys.stderr)

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

    summary = _coverage_summary(info)
    pct = _line_rate(summary)
    print(f"coverage: total line coverage = {pct or 'unknown'}%  "
          f"(html: {out_dir}/html/index.html)")
    return _coverage_verdict(
        suite_rc, pct, os.environ.get("COVERAGE_MIN"))


def _coverage_summary(info: str) -> str:
    """Print and return lcov's line/function/branch summary."""
    summary = subprocess.run(
        ["lcov", "--summary", info],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    ).stdout
    for line in summary.splitlines():
        if re.search(r"lines|functions|branches", line):
            print(line)
    return summary


def _line_rate(summary: str) -> str:
    """Extract the total line percentage from lcov output."""
    for line in summary.splitlines():
        if "lines" not in line:
            continue
        fields = re.split(r"[:%]", line)
        return fields[1].replace(" ", "") if len(fields) >= 2 else ""
    return ""


def _enforce_floor(pct: str, coverage_min) -> int:
    if not coverage_min:
        return 0
    if not pct:
        print(f"coverage: FAIL — COVERAGE_MIN={coverage_min} set but line rate "
              "could not be parsed", file=sys.stderr)
        return 1
    if float(pct) < float(coverage_min):
        print(f"coverage: FAIL — line coverage {pct}% < floor {coverage_min}%",
              file=sys.stderr)
        return 1
    print(f"coverage: OK — line coverage {pct}% >= floor {coverage_min}%")
    return 0


def _coverage_verdict(suite_rc: int, pct: str, coverage_min) -> int:
    """Combine suite correctness with the optional coverage ratchet."""
    floor_rc = _enforce_floor(pct, coverage_min)
    if suite_rc != 0:
        return suite_rc
    return floor_rc


if __name__ == "__main__":
    sys.exit(main())
