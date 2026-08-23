"""Python ports for heavy operator/build shell entrypoints."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import signal
import sys

from cmdscripts.compile_run import REPO_ROOT, result, run
from fleet_orphans import owns
# Separate line, deliberately: `test_fleet_teardown_orphans` pins the
# literal `from fleet_orphans import owns` in this file, so that this
# reaper cannot quietly stop routing ownership through the shared rule.
from fleet_orphans import lane_harnesses


def nproc() -> str:
    return str(os.cpu_count() or 4)


def _teardown_refusal(test_root, claimants):
    owners = ", ".join(
        "%d %s" % (pid, command[:60]) for pid, command in claimants[:3]
    )
    message = "refusing brutal teardown of %s: claimed by %d live harness(es): %s"
    return result(False, message % (test_root, len(claimants), owners))


def _stop_registered_servers(test_root):
    run(
        [sys.executable, "-m", "cmdscripts.manage_test_servers", "stop-all"],
        cwd=REPO_ROOT / "tests",
        env={"TEST_ROOT": str(test_root)},
    )


def _process_cmdline(pid):
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None
    return raw.replace(b"\0", b" ").decode("utf-8", "ignore")


def _signal_process(test_root, pid):
    command = _process_cmdline(pid)
    if command is None or not owns(test_root, command):
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return False
    return True


def _process_ids(name):
    found = run(["pgrep", "-x", name], cwd=REPO_ROOT)
    for value in found.stdout.split():
        try:
            yield int(value)
        except ValueError:
            continue


def _signal_owned_processes(test_root):
    names = ("nginx", "xrootd", "krb5kdc", "kadmind", "haproxy")
    return sum(
        _signal_process(test_root, pid)
        for name in names
        for pid in _process_ids(name)
    )


def _remove_state_directories(test_root):
    for child in ("data", "pki", "tokens", "logs", "tmp", "krb5"):
        shutil.rmtree(test_root / child, ignore_errors=True)


def _remove_data_lanes(test_root):
    if not test_root.exists():
        return
    for child in test_root.glob("data-*"):
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)


def _remove_control_files(test_root):
    if not test_root.exists():
        return
    for path in test_root.glob("*/*"):
        if path.suffix in {".pid", ".conf"}:
            path.unlink(missing_ok=True)


def brutal_teardown(test_root: Path, force: bool = False) -> list[tuple[bool, str]]:
    """Stop-all, SIGTERM whatever survived, then wipe ``test_root``'s state.

    Scoped to ``test_root`` and nothing else.  This used to also signal any
    daemon whose cmdline merely CONTAINED ``/tmp/xrd`` or ``/tmp/hsproto``,
    which made a clean of one lane a SIGTERM of every concurrent lane on the box
    (``/tmp/xrd`` is a substring of ``/tmp/xrd-test-<anything>``) — and, because
    the shared markers ignored the argument entirely, the throwaway ``tmp_path``
    the in-suite test passes did not protect the live fleet either.
    ``fleet_orphans.owns`` is the ownership rule the reaper itself uses.

    Refuses a lane a live harness other than this one declares, unless
    ``force``.  ``kill_orphans`` gained that gate after a lane root read off a
    `ps` listing turned out to be a concurrent run's and was reaped; this door
    is the wider one, because it does not stop at signalling — it deletes
    the lane's ``data``, ``pki``, ``tokens``, ``logs`` and ``tmp``, so the same
    mistake here destroys another session's artefacts rather than just its
    processes.  A refusal is returned as a failing check rather than raised:
    this is a checks runner, and a red line naming the claimant is what an
    operator can act on.
    """
    claimants = [] if force else lane_harnesses(test_root)
    if claimants:
        return [_teardown_refusal(test_root, claimants)]
    _stop_registered_servers(test_root)
    killed = _signal_owned_processes(test_root)
    _remove_state_directories(test_root)
    _remove_data_lanes(test_root)
    _remove_control_files(test_root)
    return [result(True, f"brutal teardown completed for {test_root}; signalled {killed} leaked process(es)")]


def build_sanitizer(nginx_src: Path) -> list[tuple[bool, str]]:
    configure = nginx_src / "configure"
    if not configure.is_file() or not os.access(configure, os.X_OK):
        return [result(False, f"nginx source not found at {nginx_src}")]
    san = "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
    client_ldflags = f"-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack {san}"
    configured = run(
        [
            "./configure",
            "--with-stream",
            "--with-stream_ssl_module",
            "--with-http_ssl_module",
            "--with-http_dav_module",
            "--with-threads",
            f"--add-module={REPO_ROOT}",
            f"--with-cc-opt={san}",
            f"--with-ld-opt={san}",
        ],
        cwd=nginx_src,
    )
    if configured.returncode != 0:
        return [result(False, f"sanitizer configure failed: {(configured.stderr or configured.stdout)[-3000:]}")]
    built = run(["make", f"-j{nproc()}"], cwd=nginx_src)
    if built.returncode != 0:
        return [result(False, f"sanitizer nginx build failed: {(built.stderr or built.stdout)[-3000:]}")]
    client = run(
        ["make", f"-j{nproc()}", f"CFLAGS={san}", f"LDFLAGS={client_ldflags}"],
        cwd=REPO_ROOT / "client",
    )
    if client.returncode != 0:
        return [result(False, f"sanitizer client build failed: {(client.stderr or client.stdout)[-3000:]}")]
    return [result(True, f"sanitizer build complete: {nginx_src / 'objs' / 'nginx'}")]


def _command_tail(process, limit):
    return (process.stderr or process.stdout)[-limit:]


def _run_build_steps(steps):
    for command, cwd, failure_message in steps:
        process = run(command, cwd=cwd)
        if process.returncode != 0:
            return result(False, f"{failure_message}: {_command_tail(process, 3000)}")
    return None


def _coverage_steps(nginx_src, flags):
    configure = [
        "./configure",
        "--with-stream",
        "--with-stream_ssl_module",
        "--with-http_ssl_module",
        "--with-http_dav_module",
        "--with-threads",
        f"--add-module={REPO_ROOT}",
        f"--with-cc-opt={flags}",
        f"--with-ld-opt={flags}",
    ]
    return (
        (configure, nginx_src, "coverage configure failed"),
        (["make", f"-j{nproc()}"], nginx_src, "coverage nginx build failed"),
        (["make", "clean"], REPO_ROOT / "client", "coverage client clean failed"),
        (
            ["make", f"-j{nproc()}", f"CFLAGS={flags}", f"LDFLAGS={flags}"],
            REPO_ROOT / "client",
            "coverage client build failed",
        ),
    )


def build_coverage(nginx_src: Path) -> list[tuple[bool, str]]:
    """Configure+build objs/nginx and the client with gcov instrumentation.

    Mirrors build_sanitizer: --coverage (== -fprofile-arcs -ftest-coverage) with
    -O0 -g so line/branch mapping is accurate. The instrumented binary drops
    .gcno next to each object at build time and .gcda at run time; tools/ci/
    coverage.sh drives lcov over both trees afterwards.
    """
    configure = nginx_src / "configure"
    if not configure.is_file() or not os.access(configure, os.X_OK):
        return [result(False, f"nginx source not found at {nginx_src}")]
    failure = _run_build_steps(_coverage_steps(nginx_src, "--coverage -O0 -g"))
    if failure is not None:
        return [failure]
    return [result(True, f"coverage build complete: {nginx_src / 'objs' / 'nginx'} (gcov-instrumented)")]


def _dynamic_prerequisite(nginx_src):
    if not (nginx_src / "configure").is_file() or not (nginx_src / "src/core/nginx.c").is_file():
        return result(True, f"SKIP nginx source not found at {nginx_src}")
    if shutil.which("rsync") is None:
        return result(True, "SKIP rsync not available")
    return None


def _copy_nginx_source(nginx_src, build_root, destination):
    shutil.rmtree(build_root, ignore_errors=True)
    destination.mkdir(parents=True)
    copied = run(
        ["rsync", "-a", "--exclude", "objs", "--exclude", "Makefile",
         f"{nginx_src}/", f"{destination}/"],
        cwd=REPO_ROOT,
    )
    if copied.returncode != 0:
        return result(True, f"SKIP rsync of nginx source failed: {_command_tail(copied, 2000)}")
    return None


def _configure_dynamic(destination):
    configured = run(
        [
            "./configure",
            "--with-compat",
            "--with-threads",
            "--with-stream=dynamic",
            "--with-stream_ssl_module",
            "--with-http_ssl_module",
            "--with-http_dav_module",
            f"--add-dynamic-module={REPO_ROOT}",
        ],
        cwd=destination,
        env={"BRIX_LZ4_LIBS": os.environ.get("BRIX_LZ4_LIBS", "-l:liblz4.so.1")},
    )
    if configured.returncode != 0:
        message = f"SKIP configure --add-dynamic-module failed: {_command_tail(configured, 3000)}"
        return result(True, message)
    return None


def _compile_dynamic(destination):
    built = run(["make", f"-j{nproc()}"], cwd=destination)
    if built.returncode != 0:
        return result(False, f"dynamic nginx build failed: {_command_tail(built, 3000)}")
    modules = run(["make", "modules", f"-j{nproc()}"], cwd=destination)
    if modules.returncode != 0:
        return result(False, f"dynamic module build failed: {_command_tail(modules, 3000)}")
    return None


def _missing_codec_dependencies(text):
    expected = ("libz.so", "libzstd", "liblzma", "libbrotlienc", "libbrotlidec", "libbz2")
    return [library for library in expected if library not in text]


def _validate_dynamic(destination):
    stream_so = destination / "objs" / "ngx_stream_brix_module.so"
    if not stream_so.is_file():
        return result(False, "stream module .so not produced")
    needed = run(["readelf", "-d", str(stream_so)], cwd=destination)
    text = needed.stdout + needed.stderr
    missing = _missing_codec_dependencies(text)
    if missing:
        message = f"codec DT_NEEDED entries missing from stream module: {', '.join(missing)}"
        return result(False, message)
    ldd = run(["ldd", str(stream_so)], cwd=destination)
    if "not found" in (ldd.stdout + ldd.stderr):
        return result(False, "stream module .so has unresolved shared library")
    return None


def _first_failure(stages):
    for stage in stages:
        failure = stage()
        if failure is not None:
            return failure
    return None


def build_dynamic_modules(nginx_src: Path, build_root: Path) -> list[tuple[bool, str]]:
    destination = build_root / "nginx"
    stages = (
        lambda: _dynamic_prerequisite(nginx_src),
        lambda: _copy_nginx_source(nginx_src, build_root, destination),
        lambda: _configure_dynamic(destination),
        lambda: _compile_dynamic(destination),
        lambda: _validate_dynamic(destination),
    )
    failure = _first_failure(stages)
    if failure is not None:
        return [failure]
    return [result(True, "dynamic module build produced stream module with codec deps")]


def run_checks(base: Path, names: list[str] | None = None) -> list[tuple[bool, str]]:
    selected = names or ["brutal_teardown", "build_dynamic_modules", "build_sanitizer"]
    results: list[tuple[bool, str]] = []
    for name in selected:
        if name == "brutal_teardown":
            # Operate on the caller-supplied `base`, NOT os.environ["TEST_ROOT"].
            # The in-suite test (test_cmd_operator_build) calls this with a
            # throwaway tmp_path; reading the live TEST_ROOT instead made this
            # check STOP-ALL + SIGTERM + rmtree the SHARED fleet mid-run — the
            # root cause of the fleet-availability cascade.  The operator CLI
            # (entry()) passes the real TEST_ROOT as base, so the standalone
            # `operator_build brutal_teardown` utility still cleans a wedged run.
            results.extend(brutal_teardown(base))
        elif name == "build_sanitizer":
            results.extend(build_sanitizer(Path(os.environ.get("NGINX_SRC", "/tmp/nginx-1.28.3"))))
        elif name == "build_coverage":
            results.extend(build_coverage(Path(os.environ.get("NGINX_SRC", "/tmp/nginx-1.28.3"))))
        elif name == "build_dynamic_modules":
            results.extend(build_dynamic_modules(Path(os.environ.get("NGINX_SRC", "/tmp/nginx-1.28.3")), base / "xrd-build-matrix"))
        else:
            results.append(result(False, f"unknown operator build port: {name}"))
    return results


def _entry_results(names):
    import tempfile

    if "brutal_teardown" in names:
        return run_checks(
            Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test")), names=names)
    with tempfile.TemporaryDirectory(prefix="operator_build.") as tmp:
        return run_checks(Path(tmp), names=names)


def _print_results(results):
    for passed, message in results:
        label = "ok  " if passed else "FAIL"
        print(f"  {label} {message}")


def _exit_code(results):
    return 0 if all(passed for passed, _message in results) else 1


def entry(argv: list[str]) -> int:
    names = argv or ["brutal_teardown", "build_dynamic_modules", "build_sanitizer"]
    results = _entry_results(names)
    _print_results(results)
    return _exit_code(results)


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
