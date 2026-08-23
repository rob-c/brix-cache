"""Direct Python ports for the tap-proxy / env-proxy live shell scenarios.

Ports ``run_tap_proxy.sh``, ``run_tap_proxy_gsi.sh``,
``run_tap_proxy_gsi_hybrid.sh``, and ``run_proxy_env_live.sh``.  Each public
scenario keeps the shell test's own acceptance sequence and assertions; the
shared code below only removes repeated PKI/nginx/process plumbing.
"""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import shutil
import socket as socket_module
import struct
import subprocess
import sys
import time

from cmdscripts.gsi_trust_live import ensure_shared_pki
from cmdscripts.c_regression_units import _gcov_flags
from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from fleet_ports import cmdscript_ports
from lib_py.util import wait_tcp
from settings import BIND_HOST, CA_CERT, CA_DIR, HOST, SERVER_CERT, SERVER_HOST, SERVER_KEY, TEST_ROOT

_PORTS = cmdscript_ports("tap_proxy_live")

XRDFS = REPO_ROOT / "client" / "bin" / "xrdfs"
OUR_XRDCP = Path(os.environ.get("OUR_XRDCP", REPO_ROOT / "client" / "bin" / "xrdcp"))
STOCK_XRDCP = Path("/usr/bin/xrdcp")
PROXY_STD = Path(TEST_ROOT) / "pki" / "user" / "proxy_std.pem"
USERCERT = Path(TEST_ROOT) / "pki" / "user" / "usercert.pem"


def _fusermount(mnt: Path) -> None:
    for tool in ("fusermount3", "fusermount"):
        if shutil.which(tool) and subprocess.run(
            [tool, "-u", str(mnt)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0:
            return


def _spawn_logged(run: LiveRun, argv: list[str], env: dict[str, str], stderr_path: Path) -> subprocess.Popen:
    proc = subprocess.Popen(
        [str(item) for item in argv],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=stderr_path.open("wb"),
    )
    run.processes.append(proc)
    return proc


def _await_mount(path: Path, expect: str, timeout: float = 30.0) -> str:
    """Poll a FUSE-backed file until it reads the expected content (or times out).

    The mount is spawned asynchronously and populates lazily over the network, so
    the file is not readable the instant the process starts.  Polling to a
    deadline replaces a fixed sleep that raced the mount coming up under
    concurrent load; on a healthy system this returns within a second, so it adds
    no wall-clock cost to the passing path.  Returns the last content or error
    read, so a timed-out check still reports a meaningful diagnostic.
    """
    deadline = time.monotonic() + timeout
    got = ""
    while True:
        try:
            got = path.read_text().rstrip("\n")
            if got == expect:
                return got
        except OSError as exc:
            got = f"<error: {exc}>"
        if time.monotonic() >= deadline:
            return got
        time.sleep(0.25)


def _missing_proxy_build_tool() -> str | None:
    missing = next((tool for tool in ("gcc", "pkg-config")
                    if shutil.which(tool) is None), None)
    return f"{missing} not installed" if missing else None


def _missing_fuse_development() -> str | None:
    fuse_cflags = subprocess.run(
        ["pkg-config", "--cflags", "fuse3"], capture_output=True, text=True)
    fuse_libs = subprocess.run(
        ["pkg-config", "--libs", "fuse3"], capture_output=True, text=True)
    missing = any((fuse_cflags.returncode, fuse_libs.returncode))
    return "fuse3 development package not installed" if missing else None


def _missing_fusermount() -> str | None:
    available = any(shutil.which(tool) for tool in ("fusermount3", "fusermount"))
    return None if available else "fusermount not installed"


def _missing_fuse_device() -> str | None:
    return None if Path("/dev/fuse").exists() else "/dev/fuse not available"


def _missing_proxy_library() -> str | None:
    libraries = ("client/libbrix.a", "shared/xrdproto/libxrdproto.a")
    missing_library = next(
        (name for name in libraries if not (REPO_ROOT / name).exists()), None)
    if missing_library is None:
        return None
    return (f"{missing_library} not built "
            f"(run make -C client lib && make -C shared/xrdproto)")


def _proxy_env_unavailable() -> str | None:
    checks = (_missing_proxy_build_tool, _missing_fuse_development,
              _missing_fusermount, _missing_fuse_device,
              _missing_proxy_library)
    for check in checks:
        reason = check()
        if reason:
            return reason
    return None


def _proxy_fuse_flags() -> tuple[list[str], list[str]]:
    cflags = subprocess.run(
        ["pkg-config", "--cflags", "fuse3"], capture_output=True, text=True,
        check=False)
    libraries = subprocess.run(
        ["pkg-config", "--libs", "fuse3"], capture_output=True, text=True,
        check=False)
    return cflags.stdout.split(), libraries.stdout.split()


def _proxy_build_specs(run, fuse_cflags, fuse_libs):
    mkrepo = run.root / "brix_mkrepo"
    harness = run.root / "proxy_harness"
    brixcvmfs = run.root / "brixcvmfs"
    client_lib = REPO_ROOT / "client/libbrix.a"
    protocol_lib = REPO_ROOT / "shared/xrdproto/libxrdproto.a"
    return (
        (mkrepo, ["gcc", "-Wall", "-I", "shared", "-o", str(mkrepo),
                  "tests/cvmfs/brix_mkrepo.c", "shared/cvmfs/grammar/hash.c",
                  "shared/cvmfs/object/object.c", "shared/cvmfs/catalog/catalog.c",
                  "-lsqlite3", "-lcrypto", "-lz"]),
        (harness, ["gcc", "-Wall", "-Wextra", "-Werror", "-I", "shared",
                   "-o", str(harness), "tests/cvmfs/proxy_tunnel_harness.c",
                   "shared/net/proxy_connect.c"]),
        (brixcvmfs, ["gcc", "-Wall", "-Wextra", "-Werror", "-I", "shared",
                     "-I", "client/lib", "-I", "src", "-DXRDPROTO_NO_NGX",
                     *fuse_cflags, "-o", str(brixcvmfs),
                     "client/apps/fs/brixcvmfs.c",
                     "client/apps/fs/brixcvmfs_transport.c",
                     "client/apps/fs/brixcvmfs_prefetch.c",
                     "client/apps/fs/brixcvmfs_ops.c",
                     "client/apps/fs/brixcvmfs_mount.c", *CVMFS_CORE,
                     "client/libbrix.a", "shared/xrdproto/libxrdproto.a",
                     *fuse_libs, "-lcurl", "-lsqlite3", "-lcrypto", "-lz",
                     *_gcov_flags([client_lib, protocol_lib]),
                     *BRIX_CONN_LDLIBS]),
    )


def _build_proxy_tools(run, specs) -> bool:
    print("== build ==")
    for target, argv in specs:
        result = run.call(argv, cwd=REPO_ROOT, check=False)
        if result.returncode:
            output = result.stderr or result.stdout
            print(f"  FAIL build {target.name}: {output[-500:]}")
            return False
    return True


def _check_tunnel(run, harness, proxy_log, origin_port, proxy_port, checks):
    print("== (A) CONNECT tunnel handshake ==")
    tunnel = run.call(
        [harness, HOST, str(proxy_port), SERVER_HOST, str(origin_port),
         "/cvmfs/test.cern.ch/.cvmfspublished"],
        check=False)
    checks.append((
        all((tunnel.returncode == 0,
             _grep(proxy_log, f"CONNECT {SERVER_HOST}:{origin_port}"))),
        "CONNECT tunnel used + 200 ok",
    ))


def _direct_proxy_environment() -> dict[str, str]:
    excluded = ("http_proxy", "https_proxy", "all_proxy")
    return {key: value for key, value in os.environ.items() if key not in excluded}


def _check_brix_connection(run, proxy_log, origin_port, proxy_port, checks):
    print("== (A2) real brix_tcp_connect: direct path unchanged + proxy path tunnels ==")
    libbrix = REPO_ROOT / "client/libbrix.a"
    if not libbrix.exists():
        print("  SKIP: client/libbrix.a not built (run make -C client lib)")
        return
    executable = run.root / "brix_conn"
    protocol_lib = REPO_ROOT / "shared/xrdproto/libxrdproto.a"
    link = run.call(
        ["gcc", "-Wall", "-Iclient/lib", "-Isrc", "-Ishared",
         "-DXRDPROTO_NO_NGX", "-o", str(executable),
         "tests/cvmfs/brix_connect_harness.c", str(libbrix),
         "shared/xrdproto/libxrdproto.a",
         *_gcov_flags([libbrix, protocol_lib]), *BRIX_CONN_LDLIBS],
        cwd=REPO_ROOT, check=False)
    if link.returncode:
        print(f"  SKIP: libbrix harness link failed "
              f"({(link.stderr or '').splitlines()[-1:]})")
        return
    environment = _direct_proxy_environment()
    proxy_log.write_text("")
    direct = subprocess.run(
        [str(executable), SERVER_HOST, str(origin_port)], env=environment,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    checks.append((
        all((direct.returncode == 0, proxy_log.stat().st_size == 0)),
        "direct connect ok (no proxy, path unchanged)",
    ))
    proxy_log.write_text("")
    proxied = subprocess.run(
        [str(executable), SERVER_HOST, str(origin_port)],
        env={**environment, "http_proxy": f"http://{HOST}:{proxy_port}"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    checks.append((
        all((proxied.returncode == 0,
             _grep(proxy_log, f"CONNECT {SERVER_HOST}:{origin_port}"))),
        "proxied connect tunnels ok",
    ))


def _mount_environment(run, repository, origin_port, public_key):
    excluded = ("no_proxy", "NO_PROXY")
    environment = {
        key: value for key, value in os.environ.items() if key not in excluded
    }
    environment.update({
        "BRIXCVMFS_SERVER":
            f"http://{SERVER_HOST}:{origin_port}/cvmfs/{repository}",
        "BRIXCVMFS_PUBKEY": str(public_key),
        "BRIXCVMFS_TMP": str(run.root / "tmp"),
    })
    return environment


def _check_proxy_mount(run, executable, repository, mount, cache, environment,
                       proxy_log, origin_port, proxy_port, expected, checks):
    print("== (B) brixcvmfs via http_proxy (report + mount) ==")
    proxy_log.write_text("")
    error_log = run.root / "mount_b.err"
    _spawn_logged(
        run, [executable, repository, mount, "-o", "fresh,auto_unmount", "-f"],
        {**environment, "http_proxy": f"http://{HOST}:{proxy_port}",
         "BRIXCVMFS_CACHE": str(cache)},
        error_log)
    content = _await_mount(mount / "hello", expected)
    checks.extend((
        (content == expected, f"content via proxy [{content}]"),
        (_grep(error_log, f"using HTTP proxy {HOST}:{proxy_port}"),
         "reported proxy use ok"),
        (_grep(proxy_log, f"GET-forward {SERVER_HOST}:{origin_port}"),
         "proxy actually forwarded ok"),
    ))
    _fusermount(mount)
    time.sleep(1)


def _check_direct_mount(run, executable, repository, mount, environment,
                        proxy_log, proxy_port, expected, checks):
    print("== (C) no_proxy forces direct ==")
    proxy_log.write_text("")
    cache = run.mkdir("cache2")
    error_log = run.root / "mount_c.err"
    _spawn_logged(
        run, [executable, repository, mount, "-o", "auto_unmount", "-f"],
        {**environment, "http_proxy": f"http://{HOST}:{proxy_port}",
         "no_proxy": f"{SERVER_HOST},{HOST}",
         "BRIXCVMFS_CACHE": str(cache)},
        error_log)
    content = _await_mount(mount / "hello", expected)
    checks.extend((
        (content == expected, f"direct mount content [{content}]"),
        (proxy_log.stat().st_size == 0, "no_proxy honored (direct) ok"),
    ))
    _fusermount(mount)
    time.sleep(1)


def _run_proxy_checks(run, tools, paths, ports, repository, expected, checks):
    mkrepo, harness, brixcvmfs = tools
    web, mount, cache, public_key, proxy_log = paths
    origin_port, proxy_port = ports
    run.call([mkrepo, repository, web, public_key])
    run.spawn(["python3", "-m", "http.server", str(origin_port)], cwd=web)
    run.spawn(["python3", REPO_ROOT / "tests/cvmfs/tiny_proxy.py",
               str(proxy_port), proxy_log])
    time.sleep(1.5)
    _check_tunnel(
        run, harness, proxy_log, origin_port, proxy_port, checks)
    _check_brix_connection(
        run, proxy_log, origin_port, proxy_port, checks)
    environment = _mount_environment(run, repository, origin_port, public_key)
    _check_proxy_mount(
        run, brixcvmfs, repository, mount, cache, environment, proxy_log,
        origin_port, proxy_port, expected, checks)
    _check_direct_mount(
        run, brixcvmfs, repository, mount, environment, proxy_log,
        proxy_port, expected, checks)


def proxy_env_live(nginx: Path | None = None) -> int:
    reason = _proxy_env_unavailable()
    if reason:
        return _skip(reason)
    fuse_cflags, fuse_libs = _proxy_fuse_flags()
    repository = "test.cern.ch"
    expected = "Hello from a LIVE CVMFS-brix mount!"
    with LiveRun("proxyenv", nginx) as run:
        web = run.mkdir("web")
        mount = run.mkdir("mnt")
        cache = run.mkdir("cache")
        run.mkdir("tmp")
        public_key = run.root / "pub.pem"
        proxy_log = run.root / "proxy.log"
        proxy_log.touch()
        specs = _proxy_build_specs(run, fuse_cflags, fuse_libs)
        if not _build_proxy_tools(run, specs):
            return 1
        tools = tuple(target for target, _ in specs)
        checks: list[tuple[bool, str]] = []
        try:
            _run_proxy_checks(
                run, tools, (web, mount, cache, public_key, proxy_log),
                _PORTS[6:8], repository, expected, checks)
        finally:
            _fusermount(mount)
        return _result(checks)


SCENARIOS = {
    "proxy-env-live": proxy_env_live,
    "tap-proxy": tap_proxy,
    "tap-proxy-gsi": tap_proxy_gsi,
    "tap-proxy-gsi-hybrid": tap_proxy_gsi_hybrid,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"tap-proxy scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
