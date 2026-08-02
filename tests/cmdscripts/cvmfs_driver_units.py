"""Python ports of CVMFS core/client/brixcvmfs shell runners."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST


CVMFS_CORE_DEPS = [
    "shared/cvmfs/grammar/classify.c",
    "shared/cvmfs/grammar/hash.c",
    "shared/cvmfs/signature/manifest.c",
    "shared/cvmfs/signature/whitelist.c",
    "shared/cvmfs/signature/verify.c",
    "shared/cvmfs/config/repo.c",
    "shared/cvmfs/object/object.c",
    "shared/cvmfs/failover/failover.c",
]

CVMFS_CLIENT_DEPS = [
    "shared/cvmfs/client/client.c",
    # phase-87 G1: negative-lookup filter (resolve hook in client.c, lifecycle
    # + verified paths-walk build in client_negfilter.c).
    "shared/cvmfs/client/client_negfilter.c",
    # phase-87 G6: mmap path index (fast-path hooks in client.c, lifecycle in
    # client_pathidx.c, format/lookup in pathidx.c).
    "shared/cvmfs/client/client_pathidx.c",
    "shared/cvmfs/index/pathidx.c",
    "shared/cvmfs/filter/xorf.c",
    "shared/cvmfs/walk/walk.c",
    "shared/cvmfs/fetch/fetch.c",
    "shared/cvmfs/object/object.c",
    "shared/cvmfs/failover/failover.c",
    "shared/cvmfs/catalog/catalog.c",
    "shared/cvmfs/grammar/hash.c",
    "shared/cvmfs/grammar/classify.c",
    "shared/cvmfs/signature/manifest.c",
    "shared/cvmfs/signature/whitelist.c",
    "shared/cvmfs/signature/verify.c",
    "shared/cvmfs/config/repo.c",
    # phase-87 G4/G5: cas_store dispatches to the packed backend when armed.
    "shared/cache/cas_store.c",
    "shared/cache/cas_pack.c",
    "shared/cvmfs/platform/platform.c",
]

CVMFS_WALK_DEPS = [
    "shared/cvmfs/walk/walk.c",
    "shared/cvmfs/fetch/fetch.c",
    "shared/cvmfs/object/object.c",
    "shared/cvmfs/failover/failover.c",
    "shared/cvmfs/catalog/catalog.c",
    "shared/cvmfs/grammar/hash.c",
    "shared/cache/cas_store.c",
    "shared/cache/cas_pack.c",
    "shared/cvmfs/platform/platform.c",
]

BRIXCVMFS_CORE_DEPS = [
    "shared/cvmfs/client/client.c",
    "shared/cvmfs/client/client_negfilter.c",
    "shared/cvmfs/client/client_pathidx.c",
    "shared/cvmfs/index/pathidx.c",
    "shared/cvmfs/filter/xorf.c",
    "shared/cvmfs/walk/walk.c",
    "shared/cvmfs/fetch/fetch.c",
    # phase-87 G2: -o bundle batch prefetch (ingest + wire framing).
    "shared/cvmfs/fetch/fetch_bundle.c",
    "shared/cvmfs/bundle/bundle.c",
    # phase-87 G3: -o dict shared-dictionary transfer coding.
    "shared/cvmfs/dict/dict.c",
    "shared/cvmfs/object/object.c",
    "shared/cvmfs/failover/failover.c",
    "shared/cvmfs/catalog/catalog.c",
    "shared/cvmfs/grammar/hash.c",
    "shared/cvmfs/grammar/classify.c",
    "shared/cvmfs/signature/manifest.c",
    "shared/cvmfs/signature/whitelist.c",
    "shared/cvmfs/signature/verify.c",
    "shared/cvmfs/config/repo.c",
    "shared/cvmfs/config/cvmfs_conf.c",
    "shared/cache/cas_store.c",
    "shared/cache/cas_pack.c",
    "shared/cvmfs/platform/platform.c",
    "shared/net/proxy_env.c",
    # phase-86: brixcvmfs now pools its libcurl handles through brix_cpool.
    "client/lib/net/cpool.c",
    "client/lib/core/types/status.c",
    "shared/xrdproto/build/kxr_names.o",
    "shared/xrdproto/build/error_mapping.o",
]

# Phase-38: the brixcvmfs driver is split by concern (front-end + transport/
# prefetch/ops/mount siblings, bound through brixcvmfs_split.h). None of the
# siblings live in an archive, so every standalone-compile site must list all
# five .c files. This is the single truth — the whitelist/trust fuse suites that
# filter BRIXCVMFS_CORE_DEPS to shared/*.c must prepend these app sources too.
BRIXCVMFS_DRIVER_SRCS = [
    "client/apps/fs/brixcvmfs.c",
    "client/apps/fs/brixcvmfs_transport.c",
    "client/apps/fs/brixcvmfs_prefetch.c",
    "client/apps/fs/brixcvmfs_ops.c",
    "client/apps/fs/brixcvmfs_mount.c",
]


def _tail(proc: subprocess.CompletedProcess) -> str:
    return (proc.stderr or proc.stdout or "")[-3000:]


def _pkg_config(args: Iterable[str]) -> tuple[bool, list[str], str]:
    proc = run(["pkg-config", *args], cwd=REPO_ROOT)
    if proc.returncode != 0:
        return False, [], _tail(proc)
    flags = proc.stdout.split()
    return True, flags, ""


def _fuse3_flags() -> tuple[bool, list[str], list[str], str]:
    exists = run(["pkg-config", "--exists", "fuse3"], cwd=REPO_ROOT)
    if exists.returncode != 0:
        return False, [], [], "SKIP: fuse3 not present"
    ok_cflags, cflags, cmsg = _pkg_config(["--cflags", "fuse3"])
    ok_libs, libs, lmsg = _pkg_config(["--libs", "fuse3"])
    if not ok_cflags or not ok_libs:
        return False, [], [], cmsg or lmsg or "pkg-config fuse3 failed"
    return True, cflags, libs, ""


def _compile_brixcvmfs(binary: Path) -> subprocess.CompletedProcess | str:
    ok, cflags, libs, message = _fuse3_flags()
    if not ok:
        return message
    return compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DXRDPROTO_NO_NGX",
            "-I",
            "client/lib",
            "-I",
            "src",
            "-I",
            "shared",
            *cflags,
            *BRIXCVMFS_DRIVER_SRCS,
            *BRIXCVMFS_CORE_DEPS,
            *libs,
            "-pthread",
            "-lcurl",
            "-lsqlite3",
            "-lcrypto",
            "-lz",
            "-lzstd",
        ],
        cwd=REPO_ROOT,
    )


def core_unit(base: Path) -> tuple[bool, str]:
    binary = base / "cvmfs_core_ut"
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "shared",
            "-I",
            "src",
            "shared/cvmfs/cvmfs_core_unittest.c",
            *CVMFS_CORE_DEPS,
            "-lcrypto",
            "-lz",
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return result(False, f"compile CVMFS core unit failed: {_tail(built)}")
    ran = run([str(binary)], cwd=REPO_ROOT)
    return result(ran.returncode == 0, f"CVMFS core unit exited {ran.returncode}: {_tail(ran)}")


def client_unit(base: Path) -> tuple[bool, str]:
    binary = base / "cvmfs_client_ut"
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "shared",
            "-I",
            "src",
            "shared/cvmfs/client/client_unittest.c",
            *CVMFS_CLIENT_DEPS,
            "-lsqlite3",
            "-lcrypto",
            "-lz",
            "-lzstd",
            "-pthread",
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return result(False, f"compile CVMFS client unit failed: {_tail(built)}")
    ran = run([str(binary)], cwd=REPO_ROOT)
    return result(ran.returncode == 0, f"CVMFS client unit exited {ran.returncode}: {_tail(ran)}")


def xorf_unit(base: Path) -> tuple[bool, str]:
    binary = base / "cvmfs_xorf_ut"
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "shared",
            "-I",
            "src",  # core/fnv.h (FNV-1a constants)
            "shared/cvmfs/filter/xorf_unittest.c",
            "shared/cvmfs/filter/xorf.c",
            "shared/cvmfs/grammar/hash.c",
            "-lcrypto",
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return result(False, f"compile CVMFS xorf unit failed: {_tail(built)}")
    ran = run([str(binary)], cwd=REPO_ROOT)
    return result(ran.returncode == 0, f"CVMFS xorf unit exited {ran.returncode}: {_tail(ran)}")


def bundle_unit(base: Path) -> tuple[bool, str]:
    binary = base / "cvmfs_bundle_ut"
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "shared",
            "shared/cvmfs/bundle/bundle_unittest.c",
            "shared/cvmfs/bundle/bundle.c",
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return result(False, f"compile CVMFS bundle unit failed: {_tail(built)}")
    ran = run([str(binary)], cwd=REPO_ROOT)
    return result(ran.returncode == 0, f"CVMFS bundle unit exited {ran.returncode}: {_tail(ran)}")


def dict_unit(base: Path) -> tuple[bool, str]:
    binary = base / "cvmfs_dict_ut"
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "shared",
            "shared/cvmfs/dict/dict_unittest.c",
            "shared/cvmfs/dict/dict.c",
            "shared/cvmfs/object/object.c",
            "shared/cvmfs/grammar/hash.c",
            "-lzstd",
            "-lcrypto",
            "-lz",
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return result(False, f"compile CVMFS dict unit failed: {_tail(built)}")
    ran = run([str(binary)], cwd=REPO_ROOT)
    return result(ran.returncode == 0, f"CVMFS dict unit exited {ran.returncode}: {_tail(ran)}")


def pack_unit(base: Path) -> tuple[bool, str]:
    binary = base / "cas_pack_ut"
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "shared",
            "shared/cache/cas_pack_unittest.c",
            "shared/cache/cas_pack.c",
            "shared/cache/cas_store.c",
            "shared/cvmfs/platform/platform.c",
            "-lz",
            "-lzstd",
            "-pthread",
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return result(False, f"compile cas_pack unit failed: {_tail(built)}")
    ran = run([str(binary)], cwd=REPO_ROOT)
    return result(ran.returncode == 0, f"cas_pack unit exited {ran.returncode}: {_tail(ran)}")


def pathidx_unit(base: Path) -> tuple[bool, str]:
    binary = base / "pathidx_ut"
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "shared",
            "shared/cvmfs/index/pathidx_unittest.c",
            "shared/cvmfs/index/pathidx.c",
            "shared/cvmfs/grammar/hash.c",
            "shared/cvmfs/platform/platform.c",
            "-lz",
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return result(False, f"compile pathidx unit failed: {_tail(built)}")
    ran = run([str(binary)], cwd=REPO_ROOT)
    return result(ran.returncode == 0, f"pathidx unit exited {ran.returncode}: {_tail(ran)}")


def walk_unit(base: Path) -> tuple[bool, str]:
    binary = base / "cvmfs_walk_ut"
    built = compile_binary(
        binary,
        [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "shared",
            "shared/cvmfs/walk/walk_unittest.c",
            *CVMFS_WALK_DEPS,
            "-lsqlite3",
            "-lcrypto",
            "-lz",
            "-lzstd",
            "-pthread",
        ],
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return result(False, f"compile CVMFS walk unit failed: {_tail(built)}")
    ran = run([str(binary)], cwd=REPO_ROOT)
    return result(ran.returncode == 0, f"CVMFS walk unit exited {ran.returncode}: {_tail(ran)}")


def brixcvmfs_build(base: Path) -> tuple[bool, str]:
    binary = base / "brixcvmfs"
    built = _compile_brixcvmfs(binary)
    if isinstance(built, str):
        return result(True, built)
    if built.returncode != 0:
        return result(False, f"compile brixcvmfs failed: {_tail(built)}")
    usage = run([str(binary)], cwd=REPO_ROOT)
    size = binary.stat().st_size
    return result(True, f"brixcvmfs built ({size} bytes); usage rc={usage.returncode}")


def _wait_http(port: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def brixcvmfs_check(base: Path) -> tuple[bool, str]:
    ok, _, _, message = _fuse3_flags()
    if not ok:
        return result(True, message)

    repo = "test.cern.ch"
    web = base / "web"
    cache = base / "cache"
    tmp = base / "tmp"
    pub = base / "repo.pub"
    bad_pub = base / "repo.bad.pub"
    for path in (web, cache, tmp):
        path.mkdir(parents=True, exist_ok=True)

    mkrepo = base / "brix_mkrepo"
    mkrepo_built = compile_binary(
        mkrepo,
        [
            "-Wall",
            "-I",
            "shared",
            "tests/cvmfs/brix_mkrepo.c",
            "shared/cvmfs/grammar/hash.c",
            "shared/cvmfs/object/object.c",
            "shared/cvmfs/catalog/catalog.c",
            "-lsqlite3",
            "-lcrypto",
            "-lz",
        ],
        cwd=REPO_ROOT,
    )
    if mkrepo_built.returncode != 0:
        return result(False, f"compile brix_mkrepo failed: {_tail(mkrepo_built)}")

    brixcvmfs = base / "brixcvmfs"
    built = _compile_brixcvmfs(brixcvmfs)
    if isinstance(built, str):
        return result(True, built)
    if built.returncode != 0:
        return result(False, f"compile brixcvmfs failed: {_tail(built)}")

    repo_created = run([str(mkrepo), repo, str(web), str(pub)], cwd=REPO_ROOT)
    if repo_created.returncode != 0:
        return result(False, f"brix_mkrepo failed: {_tail(repo_created)}")

    try:
        port = cmdscript_ports("cvmfs_driver_units")[0]
    except PermissionError as exc:
        return result(True, f"SKIP: local sockets unavailable for brixcvmfs --check: {exc}")
    server = subprocess.Popen(
        ["python3", "-m", "http.server", str(port), "--bind", BIND_HOST],
        cwd=str(web),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        if not _wait_http(port):
            return result(False, f"python http.server failed to listen on {port}")
        env = {
            "BRIXCVMFS_SERVER": f"http://{HOST}:{port}/cvmfs/{repo}",
            "BRIXCVMFS_CACHE": str(cache),
            "BRIXCVMFS_TMP": str(tmp),
        }
        healthy = run([str(brixcvmfs), "--check", repo], cwd=REPO_ROOT, env={**env, "BRIXCVMFS_PUBKEY": str(pub)})
        if healthy.returncode != 0 or "HEALTHY" not in healthy.stdout:
            return result(False, f"healthy brixcvmfs --check failed: {_tail(healthy)}")

        genrsa = subprocess.Popen(["openssl", "genrsa"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False)
        pubout = subprocess.Popen(
            ["openssl", "rsa", "-pubout", "-out", str(bad_pub)],
            stdin=genrsa.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
        if genrsa.stdout is not None:
            genrsa.stdout.close()
        _, rsa_err = genrsa.communicate()
        _, pub_err = pubout.communicate()
        if genrsa.returncode != 0 or pubout.returncode != 0:
            return result(False, f"bad-key generation failed: {(rsa_err or pub_err).decode(errors='replace')[-1000:]}")

        bad = run([str(brixcvmfs), "--check", repo], cwd=REPO_ROOT, env={**env, "BRIXCVMFS_PUBKEY": str(bad_pub)})
        if bad.returncode == 0:
            return result(False, "brixcvmfs --check accepted a wrong public key")
        return result(True, "BRIXCVMFS --check OK; bad key rejected")
    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=3)


RUNNERS = {
    "core": core_unit,
    "client": client_unit,
    "walk": walk_unit,
    "xorf": xorf_unit,
    "bundle": bundle_unit,
    "dict": dict_unit,
    "pack": pack_unit,
    "pathidx": pathidx_unit,
    "build": brixcvmfs_build,
    "check": brixcvmfs_check,
}


def run_checks(base: Path, names: Iterable[str] | None = None) -> list[tuple[bool, str]]:
    selected = list(names or RUNNERS)
    results = []
    for name in selected:
        if name not in RUNNERS:
            results.append(result(False, f"unknown CVMFS driver runner: {name}"))
            continue
        work = base / name
        work.mkdir(parents=True, exist_ok=True)
        results.append(RUNNERS[name](work))
    return results


def entry(argv: list[str]) -> int:
    selected = argv or list(RUNNERS)
    with tempfile.TemporaryDirectory(prefix="cvmfs_driver.") as tmp:
        results = run_checks(Path(tmp), selected)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
