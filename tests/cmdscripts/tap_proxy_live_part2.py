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


def proxy_env_live(nginx: Path | None = None) -> int:  # noqa: ARG001 — no nginx in this scenario
    for tool in ("gcc", "pkg-config"):
        if shutil.which(tool) is None:
            return _skip(f"{tool} not installed")
    fuse_cflags = subprocess.run(["pkg-config", "--cflags", "fuse3"], capture_output=True, text=True)
    fuse_libs = subprocess.run(["pkg-config", "--libs", "fuse3"], capture_output=True, text=True)
    if fuse_cflags.returncode or fuse_libs.returncode:
        return _skip("fuse3 development package not installed")
    if shutil.which("fusermount3") is None and shutil.which("fusermount") is None:
        return _skip("fusermount not installed")
    if not Path("/dev/fuse").exists():
        return _skip("/dev/fuse not available")
    # brixcvmfs now links the prebuilt client static libs; without them the
    # standalone build can't resolve the connection stack — skip, don't hard-fail.
    for lib in ("client/libbrix.a", "shared/xrdproto/libxrdproto.a"):
        if not (REPO_ROOT / lib).exists():
            return _skip(f"{lib} not built (run make -C client lib && make -C shared/xrdproto)")

    repo = "test.cern.ch"
    expect = "Hello from a LIVE CVMFS-brix mount!"
    with LiveRun("proxyenv", nginx) as run:
        hport, pport = _PORTS[6:8]  # was free_ports(2)
        web, mnt, cache, tmp = run.mkdir("web"), run.mkdir("mnt"), run.mkdir("cache"), run.mkdir("tmp")
        pub = run.root / "pub.pem"
        plog = run.root / "proxy.log"
        plog.touch()
        mkrepo, harness, brixcvmfs = run.root / "brix_mkrepo", run.root / "proxy_harness", run.root / "brixcvmfs"

        checks: list[tuple[bool, str]] = []
        print("== build ==")
        builds = [
            (mkrepo, ["gcc", "-Wall", "-I", "shared", "-o", str(mkrepo), "tests/cvmfs/brix_mkrepo.c",
                      "shared/cvmfs/grammar/hash.c", "shared/cvmfs/object/object.c",
                      "shared/cvmfs/catalog/catalog.c", "-lsqlite3", "-lcrypto", "-lz"]),
            (harness, ["gcc", "-Wall", "-Wextra", "-Werror", "-I", "shared", "-o", str(harness),
                       "tests/cvmfs/proxy_tunnel_harness.c", "shared/net/proxy_connect.c"]),
            # brixcvmfs.c now pulls in the client/lib connection stack
            # (net/cpool.h -> client/lib/brix.h -> src wire structs; uses
            # brix_cpool_*), so the standalone build needs the same include roots
            # and static libs the canonical client/Makefile brixMount recipe uses:
            # -Iclient/lib -Isrc -DXRDPROTO_NO_NGX + libbrix.a + libxrdproto.a.
            (brixcvmfs, ["gcc", "-Wall", "-Wextra", "-Werror",
                         "-I", "shared", "-I", "client/lib", "-I", "src",
                         "-DXRDPROTO_NO_NGX", *fuse_cflags.stdout.split(),
                         "-o", str(brixcvmfs),
                         # phase-38: brixcvmfs is split by concern (front-end +
                         # transport/prefetch/ops/mount siblings) — none are
                         # archived, so list all five app sources here.
                         "client/apps/fs/brixcvmfs.c",
                         "client/apps/fs/brixcvmfs_transport.c",
                         "client/apps/fs/brixcvmfs_prefetch.c",
                         "client/apps/fs/brixcvmfs_ops.c",
                         "client/apps/fs/brixcvmfs_mount.c",
                         *CVMFS_CORE,
                         "client/libbrix.a", "shared/xrdproto/libxrdproto.a",
                         *fuse_libs.stdout.split(), "-lcurl", "-lsqlite3", "-lcrypto", "-lz",
                         *BRIX_CONN_LDLIBS]),
        ]
        for target, argv in builds:
            result = run.call(argv, cwd=REPO_ROOT, check=False)
            if result.returncode:
                print(f"  FAIL build {target.name}: {(result.stderr or result.stdout)[-500:]}")
                return 1

        run.call([mkrepo, repo, web, pub])
        run.spawn(["python3", "-m", "http.server", str(hport)], cwd=web)
        run.spawn(["python3", REPO_ROOT / "tests" / "cvmfs" / "tiny_proxy.py", str(pport), plog])
        time.sleep(1.5)

        try:
            print("== (A) CONNECT tunnel handshake ==")
            tunnel = run.call(
                [harness, HOST, str(pport), SERVER_HOST, str(hport), f"/cvmfs/{repo}/.cvmfspublished"],
                check=False,
            )
            checks.append(
                (
                    tunnel.returncode == 0 and _grep(plog, f"CONNECT {SERVER_HOST}:{hport}"),
                    "CONNECT tunnel used + 200 ok",
                )
            )

            print("== (A2) real brix_tcp_connect: direct path unchanged + proxy path tunnels ==")
            libbrix = REPO_ROOT / "client" / "libbrix.a"
            if libbrix.exists():
                brix_conn = run.root / "brix_conn"
                link = run.call(
                    ["gcc", "-Wall", "-Iclient/lib", "-Isrc", "-Ishared", "-DXRDPROTO_NO_NGX",
                     "-o", str(brix_conn), "tests/cvmfs/brix_connect_harness.c",
                     str(libbrix), "shared/xrdproto/libxrdproto.a", *BRIX_CONN_LDLIBS],
                    cwd=REPO_ROOT,
                    check=False,
                )
                if link.returncode:
                    print(f"  SKIP: libbrix harness link failed ({(link.stderr or '').splitlines()[-1:]})")
                else:
                    direct_env = {k: v for k, v in os.environ.items()
                                  if k not in ("http_proxy", "https_proxy", "all_proxy")}
                    plog.write_text("")
                    direct = subprocess.run([str(brix_conn), SERVER_HOST, str(hport)], env=direct_env,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    checks.append(
                        (
                            direct.returncode == 0 and plog.stat().st_size == 0,
                            "direct connect ok (no proxy, path unchanged)",
                        )
                    )
                    plog.write_text("")
                    proxied = subprocess.run(
                        [str(brix_conn), SERVER_HOST, str(hport)],
                        env={**direct_env, "http_proxy": f"http://{HOST}:{pport}"},
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    checks.append(
                        (
                            proxied.returncode == 0 and _grep(plog, f"CONNECT {SERVER_HOST}:{hport}"),
                            "proxied connect tunnels ok",
                        )
                    )
            else:
                print("  SKIP: client/libbrix.a not built (run make -C client lib)")

            mount_env = {k: v for k, v in os.environ.items() if k not in ("no_proxy", "NO_PROXY")}
            mount_env.update(
                {
                    "BRIXCVMFS_SERVER": f"http://{SERVER_HOST}:{hport}/cvmfs/{repo}",
                    "BRIXCVMFS_PUBKEY": str(pub),
                    "BRIXCVMFS_TMP": str(tmp),
                }
            )

            print("== (B) brixcvmfs via http_proxy (report + mount) ==")
            plog.write_text("")
            err = run.root / "mount_b.err"
            _spawn_logged(
                run,
                [brixcvmfs, repo, mnt, "-o", "fresh,auto_unmount", "-f"],
                {**mount_env, "http_proxy": f"http://{HOST}:{pport}", "BRIXCVMFS_CACHE": str(cache)},
                err,
            )
            got = _await_mount(mnt / "hello", expect)
            checks.append((got == expect, f"content via proxy [{got}]"))
            checks.append((_grep(err, f"using HTTP proxy {HOST}:{pport}"), "reported proxy use ok"))
            checks.append((_grep(plog, f"GET-forward {SERVER_HOST}:{hport}"), "proxy actually forwarded ok"))
            _fusermount(mnt)
            time.sleep(1)

            print("== (C) no_proxy forces direct ==")
            plog.write_text("")
            cache2 = run.mkdir("cache2")
            err2 = run.root / "mount_c.err"
            _spawn_logged(
                run,
                [brixcvmfs, repo, mnt, "-o", "auto_unmount", "-f"],
                {
                    **mount_env,
                    "http_proxy": f"http://{HOST}:{pport}",
                    "no_proxy": f"{SERVER_HOST},{HOST}",
                    "BRIXCVMFS_CACHE": str(cache2),
                },
                err2,
            )
            got = _await_mount(mnt / "hello", expect)
            checks.append((got == expect, f"direct mount content [{got}]"))
            checks.append((plog.stat().st_size == 0, "no_proxy honored (direct) ok"))
            _fusermount(mnt)
            time.sleep(1)
        finally:
            _fusermount(mnt)
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
