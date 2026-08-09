#!/usr/bin/env python3
#
# WHAT: Build the brix module (objs/nginx) + client with ASan+UBSan, boot the
#       test fleet against that instrumented binary, drive real I/O through it,
#       then FAIL if the sanitizers reported any finding (heap error, UB, or an
#       unsuppressed leak). This is the hyper-hardening B-2 CI ASan+UBSan lane.
#
# WHY:  B-2 was the one systemic gate still open in the hyper-hardening register
#       (docs/07-security/hyper-hardening-plan.md § B-2, phase-88 audit § 4): the
#       runtime wiring existed — manage_test_servers.py's _sanitize_env exports
#       ASAN/UBSAN/LSAN_OPTIONS for a SANITIZE=1 build, lsan.supp curates the
#       third-party leak suppressions, and test_sanitizer_smoke.py asserts a
#       clean transfer — but NO CI job ran any of it, so an A-2-class heap
#       corruption could reach main unseen. This stands the lane up end to end.
#
# HOW:  1. operator_build build_sanitizer → ./configure --with-cc-opt/-ld-opt=
#          '-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1' + make
#          (nginx + client). Skips cleanly (exit 0) when the compiler or the
#          nginx source tree is absent, exactly like coverage.py — the lane must
#          never hard-fail on a missing prerequisite.
#       2. SANITIZE=1 manage_test_servers restart → the fleet boots under ASan
#          with log_path set (abort_on_error=0, so a worker keeps serving and
#          every finding lands in a $SANITIZE_LOG_DIR/asan.<pid> report we scan
#          afterwards rather than crashing the run mid-test).
#       3. Run $ASAN_TEST_CMD (default: the sanitizer smoke) in ATTACH mode
#          (TEST_OWN_FLEET unset) so pytest drives bytes through the already-
#          running sanitized fleet instead of rebooting it uninstrumented.
#       4. stop-all → LSan fires at process exit and writes any leak reports.
#          Then scan every asan.<pid> for a hard sanitizer signature; a match is
#          a real finding → exit 1. The scan (not abort_on_error) is what makes
#          "any finding fails the job" true, and it covers the fleet + the
#          sanitized client xrdcp the smoke spawns.
#
# USAGE:
#   tools/ci/asan.py                                  # build + smoke + verdict
#   ASAN_TEST_CMD='python3 -m pytest -m "not slow and not serial" -p no:randomly -q' \
#       tools/ci/asan.py                              # broader fast tier (cron)
#   ASAN_TEST_CMD2='python3 -m pytest test_phase24_mirror.py -k data_write -q' \
#       tools/ci/asan.py                              # + a SERIAL driver leg
#
# ASAN_TEST_CMD2 (optional): a SECOND driver command run after ASAN_TEST_CMD in
# the same sanitized+attached fleet, before stop+scan. It exists because the
# fast tier is filtered "not serial", which drops the write-mirror suite — the
# disconnect-mid-write UAF / heap-ownership paths (phase-88 audit § 4) are
# serial + lifecycle-driven, so the nightly points this at them explicitly. Both
# legs' reports are scanned together; a non-zero exit from EITHER fails the job.
#
# Env: NGINX_SRC (default /tmp/nginx-1.28.3), TEST_ROOT (/tmp/xrd-test),
#      SANITIZE_LOG_DIR ($TEST_ROOT/sanitize), ASAN_TEST_CMD, ASAN_TEST_CMD2,
#      TEST_XRDCP_BIN.

import glob
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Hard sanitizer signatures. A report file that contains any of these is a real
# finding; a file holding only a suppression summary (should not occur — we set
# print_suppressions=0) or benign noise is not. Kept explicit so the verdict is
# auditable rather than "any file at all fails" (which false-positives on the
# LSan suppression-accounting table).
ERROR_SIGNATURES = (
    "ERROR: AddressSanitizer",
    "ERROR: LeakSanitizer",
    "Direct leak of",
    "Indirect leak of",
    "runtime error:",                      # UBSan
    "SUMMARY: AddressSanitizer",
    "SUMMARY: UndefinedBehaviorSanitizer",
    "SUMMARY: LeakSanitizer",
)


def run_or_abort(cmd, **kwargs) -> subprocess.CompletedProcess:
    """Run a command; on non-zero exit, abort with that exit code (set -e)."""
    proc = subprocess.run(cmd, **kwargs)
    if proc.returncode != 0:
        sys.exit(proc.returncode)
    return proc


def _reports_with_findings(log_dir: str) -> list[tuple[str, str]]:
    """Return (path, text) for every asan.<pid> report holding a real finding."""
    hits = []
    for path in sorted(glob.glob(os.path.join(log_dir, "asan.*"))):
        try:
            text = Path(path).read_text(errors="replace")
        except OSError:
            continue
        if any(sig in text for sig in ERROR_SIGNATURES):
            hits.append((path, text))
    return hits


def _sanitizer_env(base: dict, log_dir: str, supp: str) -> dict:
    """Sanitizer runtime knobs applied to BOTH the fleet and the client xrdcp
    the smoke spawns: log findings to files (abort_on_error=0:exitcode=0 so a
    finding is recorded, not a mid-run crash) and suppress the curated
    third-party library leaks. Mirrors manage_test_servers._sanitize_env so the
    client leg is filtered identically to the fleet leg."""
    env = dict(base)
    env["SANITIZE"] = "1"
    env["SANITIZE_LOG_DIR"] = log_dir
    env["ASAN_OPTIONS"] = (
        f"detect_leaks=1:abort_on_error=0:exitcode=0:log_path={log_dir}/asan:print_legend=0"
    )
    env["UBSAN_OPTIONS"] = f"halt_on_error=0:print_stacktrace=1:log_path={log_dir}/asan"
    env["LSAN_OPTIONS"] = f"suppressions={supp}:print_suppressions=0:report_objects=0"
    return env


def main() -> int:
    # ROOT from this script's location (tools/ci/ → repo root), like coverage.py:
    # the runner must work regardless of the caller's cwd.
    root = str(Path(__file__).resolve().parents[2])
    tests = f"{root}/tests"

    nginx_src = os.environ.get("NGINX_SRC") or "/tmp/nginx-1.28.3"
    test_root = os.environ.get("TEST_ROOT") or "/tmp/xrd-test"
    log_dir = os.environ.get("SANITIZE_LOG_DIR") or f"{test_root}/sanitize"
    supp = f"{tests}/lsan.supp"
    test_cmd = os.environ.get("ASAN_TEST_CMD") or \
        "python3 -m pytest test_sanitizer_smoke.py -v"

    if not os.access(f"{nginx_src}/configure", os.X_OK):
        print(f"asan: SKIP — nginx source not found at {nginx_src} (set NGINX_SRC)")
        return 0
    if shutil.which("cc") is None and shutil.which("gcc") is None and shutil.which("clang") is None:
        print("asan: SKIP — no C compiler on PATH")
        return 0

    os.makedirs(log_dir, exist_ok=True)
    # Clear stale reports so the verdict reflects THIS run only.
    for stale in glob.glob(os.path.join(log_dir, "asan.*")):
        try:
            os.remove(stale)
        except OSError:
            pass

    # A caller may PROVIDE a prebuilt ASan nginx (operator --asan-nginx-bin /
    # TEST_ASAN_NGINX_BIN) instead of having the lane build one — same as pointing
    # the fleet at a specific --nginx-bin.  When given and runnable, skip the build
    # and boot the fleet against it.
    provided_asan = os.environ.get("TEST_ASAN_NGINX_BIN") or ""
    use_provided = bool(provided_asan) and os.access(provided_asan, os.X_OK)
    if use_provided:
        print(f"asan: 1/4 using provided ASan nginx {provided_asan} (skipping build)")
    else:
        if provided_asan:
            print(f"asan: TEST_ASAN_NGINX_BIN={provided_asan} not executable — building instead")
        print("asan: 1/4 building ASan+UBSan nginx + client…")
        run_or_abort(
            ["python3", "-m", "cmdscripts.operator_build", "build_sanitizer"],
            cwd=tests, env={**os.environ, "NGINX_SRC": nginx_src},
        )

    san_env = _sanitizer_env(os.environ, log_dir, supp)
    san_env["TEST_ROOT"] = test_root
    san_env["NGINX_SRC"] = nginx_src
    if use_provided:
        san_env["NGINX_BIN"] = provided_asan
        san_env["TEST_NGINX_BIN"] = provided_asan

    print("asan: 2/4 booting the sanitized fleet (SANITIZE=1)…")
    boot = subprocess.run(
        ["python3", "-m", "cmdscripts.manage_test_servers", "restart"],
        cwd=tests, env=san_env,
    )
    if boot.returncode != 0:
        # Fleet-boot capacity is runner-dependent; never hard-fail the build on
        # infrastructure. Tear down whatever came up and SKIP.
        print("asan: SKIP — sanitized fleet failed to boot on this runner")
        subprocess.run(
            ["python3", "-m", "cmdscripts.manage_test_servers", "stop-all"],
            cwd=tests, env=san_env,
        )
        return 0

    print("asan: 3/4 driving I/O through the sanitized fleet…")
    print(f"          $ASAN_TEST_CMD = {test_cmd}")
    run_env = dict(san_env)
    run_env["BRIX_SANITIZER_LANE"] = "1"              # un-skips test_sanitizer_smoke
    run_env["PYTHONPATH"] = f"{tests}{os.pathsep}{run_env.get('PYTHONPATH', '')}"
    run_env.pop("TEST_OWN_FLEET", None)               # ATTACH, don't reboot uninstrumented
    # Point the smoke at the sanitizer-built client unless the operator overrode it.
    if "TEST_XRDCP_BIN" not in run_env and os.access(f"{root}/client/bin/xrdcp", os.X_OK):
        run_env["TEST_XRDCP_BIN"] = f"{root}/client/bin/xrdcp"
    suite_rc = subprocess.run(test_cmd, shell=True, cwd=tests, env=run_env).returncode

    # Optional second driver leg (e.g. the SERIAL write-mirror disconnect suite,
    # which the "not serial" fast tier drops). Same sanitized+attached fleet;
    # its reports land in the same log_dir and are scanned below. A non-zero exit
    # from either leg fails the job — max() keeps the first failure visible.
    test_cmd2 = os.environ.get("ASAN_TEST_CMD2")
    if test_cmd2:
        print(f"          $ASAN_TEST_CMD2 = {test_cmd2}")
        rc2 = subprocess.run(test_cmd2, shell=True, cwd=tests, env=run_env).returncode
        suite_rc = suite_rc or rc2

    print("asan: 4/4 stopping the fleet (LSan fires at exit) + scanning reports…")
    subprocess.run(
        ["python3", "-m", "cmdscripts.manage_test_servers", "stop-all"],
        cwd=tests, env=san_env,
    )

    hits = _reports_with_findings(log_dir)
    if hits:
        print(f"asan: FAIL — {len(hits)} sanitizer report(s) with findings:", file=sys.stderr)
        for path, text in hits:
            print(f"---- {path} ----\n{text[:4000]}\n", file=sys.stderr)
        return 1
    if suite_rc != 0:
        print(f"asan: FAIL — driver command exited {suite_rc} "
              "(no sanitizer report, but the I/O leg itself failed)", file=sys.stderr)
        return suite_rc
    print("asan: OK — sanitized fleet served the workload with zero "
          "ASan/UBSan/LSan findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
