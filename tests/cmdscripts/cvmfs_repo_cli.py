"""`brixcvmfs repo` CLI (phase-96 S3) — mkfs/info/resign lifecycle checks.

Builds the repo tool standalone (BRIXCVMFS_REPO_STANDALONE — no FUSE, no
client archive), mints a repository as an unprivileged user, and validates the
full local trust chain plus fail-closed behaviour and tamper rejection.

The separate `check_oracle` lane additionally builds the full brixcvmfs client
and runs `brixcvmfs --check` against the minted repo served over HTTP — the
read stack acting as end-to-end oracle for the write stack.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run

FQRN = "unit.brix.io"

# The repo tool: CLI + the phase-96 writers + the read stack it verifies with.
REPO_CLI_SOURCES = [
    "client/apps/fs/brixcvmfs_repo.c",
    "client/apps/fs/brixcvmfs_publish.c",
    "client/apps/fs/brixcvmfs_admin.c",
    "shared/cvmfs/publish/admin.c",
    "shared/cvmfs/publish/changeset.c",
    "shared/cvmfs/publish/publish.c",
    "shared/cvmfs/publish/publish_dirtab.c",
    "shared/cvmfs/publish/publish_counters.c",
    "shared/cvmfs/publish/fsck.c",
    "shared/cvmfs/signature/sign.c",
    "shared/cvmfs/signature/manifest.c",
    "shared/cvmfs/signature/whitelist.c",
    "shared/cvmfs/signature/verify.c",
    "shared/cvmfs/catalog/catalog_write.c",
    "shared/cvmfs/catalog/catalog.c",
    "shared/cvmfs/object/object_write.c",
    "shared/cvmfs/object/object.c",
    "shared/cvmfs/reflog/reflog.c",
    "shared/cvmfs/history/history.c",
    "shared/cvmfs/grammar/hash.c",
    "shared/cache/cas_store.c",
    "shared/cache/cas_pack.c",
    "shared/cvmfs/platform/platform.c",
]
REPO_CLI_LIBS = ["-lcrypto", "-lz", "-lzstd", "-lsqlite3"]


def _build_repotool(base: Path) -> tuple[Path | None, str]:
    binary = base / "repotool"
    built = compile_binary(
        binary,
        ["-Wall", "-Wextra", "-Werror", "-I", "shared", "-DBRIXCVMFS_REPO_STANDALONE"]
        + REPO_CLI_SOURCES + REPO_CLI_LIBS,
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return None, (built.stderr or built.stdout)[-2000:]
    return binary, ""


def _flip_byte(path: Path, offset: int = 20) -> bytes:
    """Corrupt one byte of `path` in place; return the original for restore."""
    original = path.read_bytes()
    tampered = bytearray(original)
    tampered[offset] ^= 0x01
    path.write_bytes(bytes(tampered))
    return original


def run_checks(base: Path) -> list[tuple[bool, str]]:
    results: list[tuple[bool, str]] = []
    repotool, err = _build_repotool(base)
    results.append(result(repotool is not None, f"repotool builds standalone {err}"))
    if repotool is None:
        return results

    repo = base / "web" / "cvmfs" / FQRN
    repo.parent.mkdir(parents=True)         # mkfs creates only the leaf dir
    if not _check_mkfs(repotool, repo, results):
        return results
    _check_info_and_resign(repotool, repo, results)
    _check_tamper_rejections(repotool, repo, results)
    return results


def _check_mkfs(repotool, repo, results):
    mkfs = run([str(repotool), "mkfs", FQRN, str(repo)])
    results.append(result(mkfs.returncode == 0, f"repo mkfs succeeds: {mkfs.stderr.strip()}"))
    for artifact in (".cvmfspublished", ".cvmfswhitelist", ".cvmfsreflog",
                     f"keys/{FQRN}.pub", f"keys/{FQRN}.masterkey", "data"):
        results.append(result((repo / artifact).exists(), f"mkfs emits {artifact}"))
    return mkfs.returncode == 0


def _check_info_and_resign(repotool, repo, results):
    _check_repo_info(repotool, repo, results)
    _check_repo_resign(repotool, repo, results)


def _check_repo_info(repotool, repo, results):
    info = run([str(repotool), "info", str(repo)])
    results.append(result(info.returncode == 0 and "trust chain ..... OK" in info.stdout,
                          f"repo info verifies the full trust chain: {info.stdout.strip()[-200:]}"))
    results.append(result("revision ........ 1" in info.stdout, "info reports revision 1"))

    again = run([str(repotool), "mkfs", FQRN, str(repo)])
    results.append(result(again.returncode != 0 and "already published" in again.stderr,
                          "mkfs over a published repo is refused (fail-closed)"))


def _check_repo_resign(repotool, repo, results):
    before = (repo / ".cvmfswhitelist").read_bytes()
    time.sleep(1.1)     # signing is deterministic; expiry/timestamp move per-second
    resign = run([str(repotool), "resign", str(repo)])
    after = (repo / ".cvmfswhitelist").read_bytes()
    results.append(result(resign.returncode == 0 and after != before,
                          "resign rewrites the whitelist"))
    info2 = run([str(repotool), "info", str(repo)])
    results.append(result(info2.returncode == 0 and "trust chain ..... OK" in info2.stdout,
                          "trust chain still verifies after resign"))


def _check_tamper_rejections(repotool, repo, results):
    for artifact in (".cvmfspublished", ".cvmfswhitelist"):
        original = _flip_byte(repo / artifact)
        broken = run([str(repotool), "info", str(repo)])
        (repo / artifact).write_bytes(original)
        results.append(result(broken.returncode != 0,
                              f"tampered {artifact} fails info (security-negative)"))

    # security-negative: reflog tamper must break the manifest 'Y' binding
    original = _flip_byte(repo / ".cvmfsreflog", offset=40)
    broken = run([str(repotool), "info", str(repo)])
    (repo / ".cvmfsreflog").write_bytes(original)
    results.append(result(broken.returncode != 0 and "reflog checksum" in broken.stderr,
                          "tampered reflog fails the Y-checksum binding (security-negative)"))

    healthy = run([str(repotool), "info", str(repo)])
    results.append(result(healthy.returncode == 0, "repo healthy again after restores"))


def run_check_oracle(base: Path) -> list[tuple[bool, str]]:
    """Full-stack oracle: serve the minted repo over HTTP and let the READ
    client (`brixcvmfs --check`) judge the WRITE plane's output."""
    from cmdscripts.brixcvmfs_live import LiveSkip, _fuse3_flags
    from fleet_ports import cmdscript_ports
    from settings import BIND_HOST, SERVER_HOST
    from lib_py.util import wait_tcp

    results: list[tuple[bool, str]] = []
    cflags, fuse_libs = _fuse3_flags()          # raises LiveSkip when absent
    _require_prebuilt_objects(LiveSkip)
    repotool, err = _build_repotool(base)
    results.append(result(repotool is not None, f"repotool builds standalone {err}"))
    if repotool is None:
        return results

    from cmdscripts.brixcvmfs_live import (BRIXCVMFS_APP_SPLIT, BRIXCVMFS_CORE,
                                           CPOOL_STANDALONE_DEPS)
    client, built = _build_oracle_client(
        base, cflags, fuse_libs, BRIXCVMFS_APP_SPLIT,
        BRIXCVMFS_CORE, CPOOL_STANDALONE_DEPS,
    )
    results.append(result(built.returncode == 0,
                          f"brixcvmfs client builds {_build_tail(built)}"))
    if built.returncode != 0:
        return results
    web, repo = _mint_oracle_repo(base, repotool, results)
    port = cmdscript_ports("cvmfs_repo_cli")[0]
    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", BIND_HOST],
        cwd=web, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_tcp(BIND_HOST, port, 10):
            results.append(result(False, f"http.server did not listen on {port}"))
            return results
        _exercise_oracle(base, client, repo, port, SERVER_HOST, results)
    finally:
        _stop_server(server)
    return results


def _require_prebuilt_objects(skip):
    objects = ("shared/xrdproto/build/kxr_names.o",
               "shared/xrdproto/build/error_mapping.o")
    for prebuilt in objects:
        if not os.path.isfile(os.path.join(REPO_ROOT, prebuilt)):
            raise skip(f"prebuilt {prebuilt} not present (build client first)")


def _build_oracle_client(base, cflags, fuse_libs, app_split, core, cpool):
    client = base / "brixcvmfs"
    built = compile_binary(
        client,
        ["-Wall", "-Wextra", "-Werror", "-I", "shared", "-I", "client/lib", "-I", "src",
         "-DXRDPROTO_NO_NGX", *cflags,
         "client/apps/fs/brixcvmfs.c", *app_split, *cpool, *core,
         *fuse_libs, "-lcurl", "-lsqlite3", "-lcrypto", "-lz", "-lzstd"],
        cwd=REPO_ROOT,
    )
    return client, built


def _build_tail(built):
    return (built.stderr or "")[-1500:] if built.returncode else ""


def _mint_oracle_repo(base, repotool, results):
    web = base / "web"
    repo = web / "cvmfs" / FQRN
    repo.parent.mkdir(parents=True)         # mkfs creates only the leaf dir
    mkfs = run([str(repotool), "mkfs", FQRN, str(repo)])
    results.append(result(mkfs.returncode == 0, "repo mkfs for the served tree"))
    return web, repo


def _exercise_oracle(base, client, repo, port, server_host, results):
    env = dict(os.environ)
    env["BRIXCVMFS_SERVER"] = f"http://{server_host}:{port}/cvmfs/{FQRN}"
    env["BRIXCVMFS_PUBKEY"] = str(repo / "keys" / f"{FQRN}.pub")
    env["BRIXCVMFS_TMP"] = str(base / "tmp")
    env["BRIXCVMFS_CACHE"] = str(base / "cache")
    (base / "tmp").mkdir(exist_ok=True)
    (base / "cache").mkdir(exist_ok=True)
    check = run([str(client), "--check", FQRN], env=env)
    details = (check.stdout + check.stderr).strip()[-300:]
    results.append(result(check.returncode == 0,
                          f"read client accepts minted repo: {details}"))
    original = _flip_byte(repo / ".cvmfswhitelist")
    broken = run([str(client), "--check", FQRN], env=env)
    (repo / ".cvmfswhitelist").write_bytes(original)
    results.append(result(broken.returncode != 0,
                          "tampered whitelist fails --check"))


def _stop_server(server):
    server.terminate()
    try:
        server.wait(5)
    except subprocess.TimeoutExpired:
        server.kill()


def entry(argv: list[str]) -> int:
    import tempfile

    lanes = {"units": run_checks, "check-oracle": run_check_oracle}
    lane = argv[0] if argv else "units"
    with tempfile.TemporaryDirectory(prefix="cvmfs_repo_cli.") as tmp:
        results = lanes[lane](Path(tmp))
    _print_results(results)
    return 0 if all(ok for ok, _ in results) else 1


def _print_results(results):
    for passed, message in results:
        label = "ok  " if passed else "FAIL"
        print(f"  {label} {message}")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
