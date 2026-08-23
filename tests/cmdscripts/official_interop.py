"""Direct Python ports of the official-XRootD interop shell suites.

This module covers:
* tests/run_official_xrootd_tests.sh (noauth / host / stress adapted suites)
* tests/run_cross_compatible_tests.sh (cross-backend pytest lanes)

The official suites exercise a RUNNING nginx+xrootd anonymous listener
(NGINX_ANON_PORT, default 11094 — the managed fleet's anon port) with the stock
XRootD client tools, mirroring how the official tests/XRootD/*.sh drive a native
server. Execution is opt-in via the phase-81 live knob; import stays cheap.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys

from cmdscripts.compile_run import REPO_ROOT
from cmdscripts.live_common import LiveRun
from settings import NGINX_ANON_PORT, SERVER_HOST

BRIX_SRC = Path(os.environ.get("BRIX_SRC", "/tmp/brix-src"))
TEST_DIR = BRIX_SRC / "tests/XRootD"

REQUIRED_TOOLS = ("xrdfs", "xrdcp", "xrdadler32")

# Same client-timeout defaults the shell harness exported.
_XRD_ENV_DEFAULTS = {
    "XRD_REQUESTTIMEOUT": "60",
    "XRD_STREAMTIMEOUT": "30",
    "XRD_TIMEOUTRESOLUTION": "1",
    "XRD_LOGLEVEL": "Warning",
}


def anon_port() -> int:
    return NGINX_ANON_PORT


def _host_url() -> str:
    return f"root://{SERVER_HOST}:{anon_port()}/"


def _missing_tools() -> list[str]:
    return [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]


def _client_env() -> dict[str, str]:
    env = dict(_XRD_ENV_DEFAULTS)
    env.update({key: os.environ[key] for key in _XRD_ENV_DEFAULTS if key in os.environ})
    env["SOURCE_DIR"] = str(TEST_DIR)
    return env


def _failed_labels(items):
    return [text for ok, text in items if not ok]


def _print_failed_labels(failed):
    for text in failed:
        print(f"    - FAIL {text}")


def _checks(items: list[tuple[bool, str]]) -> int:
    failed = _failed_labels(items)
    passed = len(items) - len(failed)
    print(f"  results: {passed} passed, {len(failed)} failed")
    _print_failed_labels(failed)
    return int(bool(failed))


class _Suite:
    """Incremental pass/fail tracking mirroring the shell run_subtest helper."""

    def __init__(self, run: LiveRun) -> None:
        self.run = run
        self.env = _client_env()
        self.results: list[tuple[bool, str]] = []

    def subtest(self, label: str, argv: list, *, expect_ok: bool = True) -> subprocess.CompletedProcess:
        proc = self.run.call(argv, env=self.env, check=False)
        ok = (proc.returncode == 0) if expect_ok else (proc.returncode != 0)
        self.record(label, ok)
        return proc

    def record(self, label: str, ok: bool) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
        self.results.append((ok, label))


def _adler32(path: Path, env: dict[str, str]) -> str:
    """First field of `xrdadler32 < path`, exactly like the shell pipeline."""
    with path.open("rb") as stream:
        proc = subprocess.run(
            ["xrdadler32"], stdin=stream, capture_output=True, text=True,
            env={**os.environ, **env},
        )
    return (proc.stdout.split() or [""])[0]


def _random_size(base: int) -> int:
    """`base * (RANDOM + 1)` bytes — RANDOM is bash's 0..32767."""
    return base * (random.randrange(32768) + 1)


def _tag(kind: str) -> str:
    return f"{kind}-{os.getpid()}-{random.randrange(32768)}"


# --------------------------------------------------------------------------- #
# noauth: file upload/download + checksum (adapted from tests/XRootD/noauth.sh)
# --------------------------------------------------------------------------- #
def _clients_available() -> bool:
    missing = _missing_tools()
    if not missing:
        return True
    print(f"SKIP: missing client tools: {', '.join(missing)}")
    return False


def _noauth_create_files(local, names):
    print(f"Creating {len(names)} random test files ...")
    for name in names:
        (local / f"{name}.ref").write_bytes(os.urandom(_random_size(1024)))


def _noauth_transfer(suite, host, remote, local, names):
    for name in names:
        suite.subtest(f"noauth: xrdcp upload {name}",
                      ["xrdcp", "-np", local / f"{name}.ref",
                       f"{host}{remote}/{name}.ref"])
    suite.subtest("noauth: xrdfs ls -l",
                  ["xrdfs", host, "ls", "-l", f"{remote}/"])
    for name in names:
        suite.subtest(f"noauth: xrdcp download {name}",
                      ["xrdcp", "-np", f"{host}{remote}/{name}.ref",
                       local / f"{name}.dat"])


def _noauth_checksums(suite, local, names):
    for name in names:
        ref = _adler32(local / f"{name}.ref", suite.env)
        got = _adler32(local / f"{name}.dat", suite.env)
        suite.record(f"noauth: adler32 verify {name}", bool(ref) and ref == got)


def _noauth_cleanup(suite, host, remote, names):
    for name in names:
        suite.subtest(f"noauth: rm {name}",
                      ["xrdfs", host, "rm", f"{remote}/{name}.ref"])
    suite.subtest("noauth: rmdir", ["xrdfs", host, "rmdir", remote])


def noauth() -> int:
    if not _clients_available():
        return 0
    host = _host_url()
    tag = _tag("noauth")
    remote = f"/official-tests/{tag}"
    with LiveRun("official_noauth") as run:
        suite = _Suite(run)
        local = run.mkdir(tag)

        suite.subtest("noauth: stat /", ["xrdfs", host, "stat", "/"])
        for param in ("version", "sitename", "role"):
            suite.subtest(f"noauth: query config {param}", ["xrdfs", host, "query", "config", param])
        suite.subtest("noauth: mkdir -p", ["xrdfs", host, "mkdir", "-p", remote])

        names = [f"{i:02d}" for i in range(1, 6)]
        _noauth_create_files(local, names)
        _noauth_transfer(suite, host, remote, local, names)
        _noauth_checksums(suite, local, names)

        suite.subtest("noauth: ls -R /", ["xrdfs", host, "ls", "-R", "/"])
        target = f"{remote}/{names[0]}.ref"
        suite.subtest("noauth: stat file", ["xrdfs", host, "stat", target])
        suite.subtest("noauth: truncate", ["xrdfs", host, "truncate", target, "64"])
        _noauth_cleanup(suite, host, remote, names)
        return _checks(suite.results)


# --------------------------------------------------------------------------- #
# host: simple copy + diff (adapted from tests/XRootD/host.sh)
# --------------------------------------------------------------------------- #
def host() -> int:
    missing = _missing_tools()
    if missing:
        print(f"SKIP: missing client tools: {', '.join(missing)}")
        return 0
    srcfile = TEST_DIR / "host.cfg"
    if not srcfile.is_file():
        print(f"SKIP: host.cfg not found under {TEST_DIR}")
        return 0
    host_url = _host_url()
    tag = _tag("host")
    remote = f"/official-tests/{tag}"
    with LiveRun("official_host") as run:
        suite = _Suite(run)
        local = run.mkdir(tag)
        suite.subtest("host: mkdir -p", ["xrdfs", host_url, "mkdir", "-p", remote])
        suite.subtest("host: xrdcp upload", ["xrdcp", "-f", srcfile, f"{host_url}{remote}/host.cfg"])
        suite.subtest("host: xrdcp download", ["xrdcp", "-f", f"{host_url}{remote}/host.cfg", local / "host.cfg"])
        suite.subtest("host: cat remote file", ["xrdfs", host_url, "cat", f"{remote}/host.cfg"])
        round_trip = (local / "host.cfg").exists() and (local / "host.cfg").read_bytes() == srcfile.read_bytes()
        suite.record("host: diff round-trip", round_trip)
        suite.subtest("host: rm", ["xrdfs", host_url, "rm", f"{remote}/host.cfg"])
        run.call(["xrdfs", host_url, "rmdir", remote], env=suite.env, check=False)
        return _checks(suite.results)


# --------------------------------------------------------------------------- #
# stress: parallel bulk round-trip (inspired by noauth + stress patterns)
# --------------------------------------------------------------------------- #
def _parallel(argvs, env):
    procs = [subprocess.Popen([str(arg) for arg in argv], env=env,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
             for argv in argvs]
    return [proc.wait() for proc in procs]


def _stress_files(local, names):
    for name in names:
        (local / f"{name}.ref").write_bytes(os.urandom(_random_size(4096)))


def _checksum_mismatches(local, names, env):
    bad = 0
    for name in names:
        ref = _adler32(local / f"{name}.ref", env)
        dat = local / f"{name}.dat"
        got = _adler32(dat, env) if dat.exists() else ""
        if not ref or ref != got:
            bad += 1
            print(f"  MISMATCH: file {name} ref={ref} got={got}")
    return bad


def _stress_upload_commands(local, host_url, remote, names):
    return [["xrdcp", "-np", local / f"{name}.ref",
             f"{host_url}{remote}/{name}.ref"] for name in names]


def _stress_download_commands(local, host_url, remote, names):
    return [["xrdcp", "-np", f"{host_url}{remote}/{name}.ref",
             local / f"{name}.dat"] for name in names]


def _stress_remove_commands(host_url, remote, names):
    return [["xrdfs", host_url, "rm", f"{remote}/{name}.ref"]
            for name in names]


def stress() -> int:
    if not _clients_available():
        return 0
    host_url = _host_url()
    tag = _tag("stress")
    remote = f"/official-tests/{tag}"
    nfiles = int(os.environ.get("OFFICIAL_STRESS_NFILES", "20"))
    names = [f"{i:02d}" for i in range(1, nfiles + 1)]
    with LiveRun("official_stress") as run:
        suite = _Suite(run)
        local = run.mkdir(tag)
        env = {**os.environ, **suite.env}
        run.call(["xrdfs", host_url, "mkdir", "-p", remote], env=suite.env, check=False)

        print(f"Stress: uploading {nfiles} files in parallel ...")
        _stress_files(local, names)
        _parallel(_stress_upload_commands(local, host_url, remote, names), env)
        _parallel(_stress_download_commands(local, host_url, remote, names), env)

        bad = _checksum_mismatches(local, names, suite.env)
        suite.record(f"stress: {nfiles - bad}/{nfiles} round-trip checksums match", bad == 0)

        _parallel(_stress_remove_commands(host_url, remote, names), env)
        run.call(["xrdfs", host_url, "rmdir", remote], env=suite.env, check=False)
        return _checks(suite.results)


def all_suites() -> int:
    return max(noauth(), host(), stress())


# --------------------------------------------------------------------------- #
# cross-compatible: run the conformance pytest lanes against both backends
# (port of tests/run_cross_compatible_tests.sh)
# --------------------------------------------------------------------------- #
NATIVE_TESTS = [
    "tests/test_file_api.py",
    "tests/test_query.py",
    "tests/test_protocol_edge_cases.py",
    "tests/test_privilege_escalation.py",
]

XRDHTTP_TESTS = [
    "tests/test_xrdhttp_webdav.py",
    "tests/test_xrdhttp_conformance.py",
]


def _run_backend(backend: str, files: list[str], extra: list[str]) -> int:
    print(f"\n== Running cross-compatible tests against {backend} ==")
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test")).resolve()
    basetemp = test_root / "artifacts" / "official-interop" / backend
    basetemp.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "TEST_CROSS_BACKEND": backend,
        # This command is invoked by a test inside the already-running suite.
        # The child must attach to that fleet and must never stop or rebuild it.
        "TEST_SKIP_SERVER_SETUP": "1",
        "TEST_OWN_FLEET": "0",
    }
    return subprocess.call(
        [
            sys.executable, "-m", "pytest", *files,
            "--basetemp", str(basetemp),
            "-p", "no:randomly", "-p", "no:rerunfailures",
            "-o", "addopts=", *extra,
        ],
        cwd=str(REPO_ROOT), env=env,
    )


def _native_cross_lanes(extra):
    failed = 0
    for backend in ("nginx", "xrootd"):
        if _run_backend(backend, NATIVE_TESTS, extra) != 0:
            failed = 1
    return failed


def _http_cross_lane(rel, extra):
    if not (REPO_ROOT / rel).is_file():
        print(f"SKIP: {rel} not found")
        return
    for backend in ("nginx", "xrootd"):
        _run_backend(backend, [rel], extra)


def cross_compatible(extra: list[str] | None = None) -> int:
    extra = list(extra or [])
    failed = _native_cross_lanes(extra)
    print("\n== Running XrdHttp/WebDAV cross-compatible tests ==")
    for rel in XRDHTTP_TESTS:
        _http_cross_lane(rel, extra)
    return failed


SCENARIOS = {
    "noauth": noauth,
    "host": host,
    "stress": stress,
    "all": all_suites,
    "cross-compatible": cross_compatible,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("extra", nargs="*", help="extra pytest args (cross-compatible only)")
    ns = parser.parse_args(argv)
    if ns.scenario == "cross-compatible":
        return cross_compatible(ns.extra)
    return SCENARIOS[ns.scenario]()


if __name__ == "__main__":
    raise SystemExit(main())
