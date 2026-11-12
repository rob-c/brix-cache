#!/usr/bin/env python3
import sys as _brix_log_sys
from pathlib import Path as _BrixLogPath
_brix_log_sys.path.insert(0, str(_BrixLogPath(__file__).resolve().parents[2]))
from tools.logging_support import diagnostic as _brix_diagnostic

#
# WHAT: Build the brix module (objs/nginx) + client with gcov instrumentation,
#       run the test suite against that instrumented binary, and emit an lcov
#       line/branch-coverage report for src/ and client/ and enforce the line
#       floor selected by COVERAGE_MIN.
#
# WHY:  Enforce the measured production coverage floor without losing counters
#       from standalone C tests. CI sets COVERAGE_MIN=90 after the 2026-11-10
#       full-suite measurement reached 90.1229% (BUILD.md §18). Local callers
#       may omit the variable when they only need a report, but a failing
#       test command always fails.
#
# HOW:  1. operator_build build_coverage → ./configure --with-cc-opt='--coverage
#          -O0 -g' + make (nginx + client). Instrumented objects drop .gcno now,
#          .gcda as the binary runs.
#       2. Capture the production inventory, then run $COVERAGE_TEST_CMD
#          (default: all functional fleet tiers). Standalone C test compiles
#          retain their own notes/counters outside disposable test roots.
#       3. lcov --capture over nginx + client + shared build dirs, restrict to src/ +
#          client/, strip system headers, print the total line rate, genhtml.
#       4. Fail when the suite failed or the total line rate is below an enabled
#          COVERAGE_MIN floor. Counter capture still runs after a suite failure
#          so CI retains the diagnostic report.
#
# USAGE:
#   tools/ci/coverage.py                       # build + full-suite run + report
#   COVERAGE_TEST_CMD='pytest tests/test_root_basic.py' tools/ci/coverage.py
#   COVERAGE_MIN=90 COVERAGE_PRIVILEGED=1 tools/ci/coverage.py  # disposable Linux host
#
# Requires: lcov (geninfo/genhtml), gcov. The generic local runner skips when
#           absent; the workflow installs both before invoking it.

import os
import argparse
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from tools.ci import coverage_compiler, coverage_merge


def run_or_abort(cmd, **kwargs) -> subprocess.CompletedProcess:
    """Run a command; on non-zero exit, abort with that exit code (set -e)."""
    proc = subprocess.run(cmd, **kwargs)
    if proc.returncode != 0:
        sys.exit(proc.returncode)
    return proc


def main(arguments=None) -> int:
    # ROOT from this script's location (tools/ci/ → repo root), like the other
    # guards: the runner must work regardless of the caller's cwd (the pytest
    # guard wrapper runs with cwd inside the test fleet root, not the repo).
    parser = argparse.ArgumentParser(description='Collect production line coverage')
    parser.add_argument('--stage', default='all',
                        choices=('all', 'prepare', 'ordinary', 'privileged', 'userns', 'report'))
    options = parser.parse_args(arguments)
    root, nginx_src, out_dir, test_cmd = _settings()
    reason = _skip_reason(nginx_src)
    if reason:
        print(reason)
        # An explicitly requested floor requires an actual measurement.
        return 1 if os.environ.get("COVERAGE_MIN") else 0
    if options.stage == 'all':
        return _collect(root, nginx_src, out_dir, test_cmd)
    from tools.ci import coverage_stages
    return coverage_stages.run(options.stage, root, nginx_src, out_dir, test_cmd)


def _settings():
    root = str(Path(__file__).resolve().parents[2])
    nginx_src = os.environ.get("NGINX_SRC") or "/tmp/nginx-1.28.3"
    out_dir = os.environ.get("COVERAGE_OUT") or f"{root}/coverage"
    test_cmd = os.environ.get("COVERAGE_TEST_CMD") or _default_test_command()
    return root, nginx_src, out_dir, test_cmd


def _default_test_command() -> str:
    """Include native C harness jobs while keeping build-mutating jobs separate."""
    separate = (
        "tests/test_ci_guards.py::test_ci_analyzer_runner_green",
        "tests/test_ci_guards.py::test_ci_coverage_runner_green",
        "tests/test_ci_asan_lane.py::test_ci_asan_runner_green",
    )
    return shlex.join(["python3", "-m", "cmdscripts.operator_runtime", "suite",
                       "--include-suite-jobs", "--",
                       *(f"--deselect={node}" for node in separate)])


def _skip_reason(nginx_src: str) -> str:
    if shutil.which("lcov") is None or shutil.which("gcov") is None:
        return "coverage: SKIP — lcov/gcov not installed (apt-get install -y lcov)"
    if not os.access(f"{nginx_src}/configure", os.X_OK):
        return f"coverage: SKIP — nginx source not found at {nginx_src} (set NGINX_SRC)"
    return ""


def _collect(root: str, nginx_src: str, out_dir: str, test_cmd: str) -> int:
    _build(root, out_dir)
    return _run_and_capture(root, nginx_src, out_dir, test_cmd)


def _build(root, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    print("coverage: 1/4 building gcov-instrumented nginx + client…")
    run_or_abort(
        ["python3", "-m", "cmdscripts.operator_build", "build_coverage"],
        cwd=f"{root}/tests",
    )


def _run_and_capture(root: str, nginx_src: str, out_dir: str, test_cmd: str) -> int:
    """Measure one complete test command against the current instrumented build."""
    directories, initial, unit_dir = _prepare_measurement(root, nginx_src, out_dir)
    environment = _measurement_environment(root, nginx_src, unit_dir)
    print("coverage: 2/4 running suite against the instrumented binary…")
    print(f"          $COVERAGE_TEST_CMD = {test_cmd}")
    suite_rc = _run_suites(root, test_cmd, environment)
    return _report(root, out_dir, directories, initial, unit_dir, suite_rc)


def _prepare_measurement(root, nginx_src, out_dir):
    # Freeze the production build's executable-line inventory before tests
    # compile extra harnesses or rebuild client objects with different options.
    initial = f"{out_dir}/coverage.initial.info"
    # libxrdproto compiles src/ kernels into shared/xrdproto/build. Their
    # client-side execution belongs to the same production-source inventory.
    directories = [f"{nginx_src}/objs", f"{root}/client", f"{root}/shared"]
    _capture(root, directories, initial, initial=True)
    unit_dir = Path(tempfile.mkdtemp(prefix="unit-counters-", dir=out_dir))
    _reset_counters(directories)
    return directories, initial, unit_dir


def _measurement_environment(root, nginx_src, unit_dir):
    return coverage_compiler.install(
        Path(root), unit_dir, _build_environment(nginx_src, os.environ))


def _report(root, out_dir, directories, initial, unit_dir, suite_rc):
    if suite_rc != 0:
        _brix_diagnostic('ERROR', 'tools/ci/coverage.py', '_collect', f"coverage: FAIL — test command exited {suite_rc}; "
              "capturing partial counters for diagnostics", file=sys.stderr)

    print("coverage: 3/4 capturing counters with lcov…")
    requests = f"{out_dir}/coverage.requests.info"
    info = f"{out_dir}/coverage.info"
    _capture(root, directories, requests)
    captures = [Path(requests)]
    if any(unit_dir.rglob("*.gcda")):
        units = f"{out_dir}/coverage.units.info"
        _capture(root, [str(unit_dir)], units)
        captures.append(Path(units))
    coverage_merge.merge_execution(Path(initial), captures, Path(info))

    print("coverage: 4/4 rendering html + summary…")
    run_or_abort(["genhtml", "--quiet", "--output-directory",
                  f"{out_dir}/html", info])

    _coverage_summary(info)
    pct = coverage_merge.line_rate(Path(info))
    print(f"coverage: total line coverage = {pct or 'unknown'}%  "
          f"(html: {out_dir}/html/index.html)")
    return _coverage_verdict(
        suite_rc, pct, os.environ.get("COVERAGE_MIN"))


def _reset_counters(directories):
    """Reset the same build directories used by inventory and execution capture."""
    arguments = [argument for directory in directories
                 for argument in ('--directory', directory)]
    with open(os.devnull, 'wb') as devnull:
        run_or_abort(['lcov', *arguments, '--zerocounters'],
                     stdout=devnull, stderr=devnull)


def _run_suites(root: str, test_cmd: str, environment: dict[str, str]) -> int:
    """Run ordinary tests, then the explicitly enabled root group without reset."""
    privileged = environment.get('COVERAGE_PRIVILEGED') == '1'
    if privileged:
        ready = subprocess.run(['sudo', '-n', 'true'], env=environment)
        if ready.returncode:
            return ready.returncode
    result = subprocess.run(test_cmd, shell=True, cwd=f'{root}/tests',
                            env=environment)
    if result.returncode or not privileged:
        return result.returncode
    helper = str(Path(root) / 'tools/ci/coverage_privileged.py')
    result = subprocess.run(['sudo', '-n', '-E', sys.executable, helper],
                            cwd=root, env=environment)
    if result.returncode:
        return result.returncode
    return _run_userns_group(root, environment)


def _run_userns_group(root, environment):
    """Append the standalone namespace root without resetting prior counters."""
    test_root = environment.get('TEST_ROOT', '/tmp/xrd-test') + '-userns'
    environment = {**environment, 'TEST_ROOT': test_root, 'TMPDIR': test_root + '/tmp'}
    Path(environment['TMPDIR']).mkdir(parents=True, exist_ok=True)
    helper = str(Path(root) / 'tools/ci/coverage_privileged.py')
    control = ['sudo', '-n', '-E', sys.executable, helper, '--counters-only']
    prepared = subprocess.run([*control, 'prepare'], cwd=root, env=environment)
    if prepared.returncode:
        return prepared.returncode
    directory = str(Path(root) / 'tests/userns')
    command = [sys.executable, '-m', 'pytest', directory,
               '--confcutdir=' + directory, '-c', directory + '/pytest.ini',
               '-n0', '-o', 'addopts=', '-ra', '-q', '-p', 'no:randomly',
               '-p', 'no:rerunfailures', '-p', 'no:brixtest', '-p', 'no:platformdirs']
    profile = environment.get('COVERAGE_USERNS_PROFILE')
    if profile:
        command = ['aa-exec', '-p', profile, '--', *command]
    try:
        result = subprocess.run(command, cwd=root, env=environment)
    finally:
        finished = subprocess.run([*control, 'finish'], cwd=root, env=environment)
    return result.returncode or finished.returncode


def _build_environment(nginx_src, environment):
    """Bind every test consumer to this static instrumented build's SDK/binary."""
    source = str(Path(nginx_src).resolve())
    objects = str(Path(source) / 'objs')
    binary = str(Path(objects) / 'nginx')
    return {**environment, 'NGINX_SRC': source, 'NGX_SRC': source,
            'TEST_NGINX_SRC': source, 'TEST_NGINX_OBJS': objects,
            'BRIX_NGINX_BUILD_DIR': objects, 'TEST_NGINX_BIN': binary,
            'NGINX_BIN': binary, 'TEST_NGINX_LOAD_MODULES': ''}


def _capture(root: str, directories: list[str], output: str, *, initial=False) -> None:
    """Capture one counter source with the same production-source filter."""
    populated = _capture_directories(directories, initial)
    if not populated:
        # A standalone-only run legitimately has no server/client-process
        # counters. Its unit capture still supplies the measured execution.
        Path(output).write_text('')
        return
    raw = output + ".raw"
    command = ["lcov", "--capture", "--quiet"]
    if initial:
        command.append("--initial")
    for directory in populated:
        command.extend(["--directory", directory])
    run_or_abort([*command, "--rc", "geninfo_unexecuted_blocks=1", "--output-file", raw])
    _extract_production(root, raw, output)
    _remove_test_drivers(root, output)
    Path(raw).unlink(missing_ok=True)


def _capture_directories(directories, initial):
    if initial:
        return _populated_directories(directories, '*.gcno')
    _counter_files(directories)
    return _populated_directories(directories, '*.gcda')


def _populated_directories(directories, suffix):
    return [directory for directory in directories
            if any(Path(directory).rglob(suffix))]


def _record_sources(tracefile):
    return [source for source, _rows in coverage_merge._records(Path(tracefile))]


def _matching_sources(sources, prefix):
    return [source for source in sources if source.startswith(prefix)]


def _extract_production(root: str, raw: str, output: str) -> None:
    """Use only matching patterns; an external-only capture has no project hits."""
    sources = _record_sources(raw)
    prefixes = (f'{root}/src/', f'{root}/client/')
    patterns = [prefix + '*' for prefix in prefixes
                if _matching_sources(sources, prefix)]
    if not patterns:
        Path(output).write_text('')
        return
    run_or_abort(['lcov', '--quiet', '--extract', raw, *patterns,
                  '--output-file', output])


def _remove_test_drivers(root: str, output: str) -> None:
    """Remove fixture records only when the exclusion actually matches input."""
    # Optional client smoke targets leave their own notes beside production
    # objects. Their driver code is test infrastructure, not the shipped client.
    # Linking prebuilt production objects may instrument only the new test main
    # in this stream. A successful extract then produces an empty file; LCOV's
    # remove command rejects that valid empty input. Corrupt profiles still fail
    # during capture above, and the fixed initial inventory keeps unhit lines.
    prefix = str(Path(root) / 'client/tests') + '/'
    sources = _record_sources(output)
    drivers = _matching_sources(sources, prefix)
    if drivers == sources:
        Path(output).write_text('')
        return
    if drivers:
        run_or_abort(["lcov", "--quiet", "--remove", output,
                      f"{root}/client/tests/*", "--output-file", output])


def _counter_files(directories):
    """Reject unrecognized/truncated GCC headers before LCOV can ignore them."""
    counters = [path for directory in directories
                for path in Path(directory).rglob('*.gcda')]
    for path in counters:
        with path.open('rb') as stream:
            header = stream.read(12)
        if len(header) < 12 or header[:4] not in (b'adcg', b'gcda'):
            _brix_diagnostic('ERROR', 'tools/ci/coverage.py', '_counter_files',
                            f'invalid gcov counter header: {path}', file=sys.stderr)
            raise SystemExit(1)
    return counters


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
        _brix_diagnostic('ERROR', 'tools/ci/coverage.py', '_enforce_floor', f"coverage: FAIL — COVERAGE_MIN={coverage_min} set but line rate "
              "could not be parsed", file=sys.stderr)
        return 1
    if float(pct) < float(coverage_min):
        _brix_diagnostic('ERROR', 'tools/ci/coverage.py', '_enforce_floor', f"coverage: FAIL — line coverage {pct}% < floor {coverage_min}%",
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
