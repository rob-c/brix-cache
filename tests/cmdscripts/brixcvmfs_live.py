"""Direct Python ports of the brixMount/brixcvmfs FUSE and scvmfs live shell scenarios.

Ported shell scripts (kept in place; these are their Python replacements):
  tests/run_mount_cvmfs_live.sh      -> mount-cvmfs-live
  tests/run_brixmount_live.sh        -> brixmount-live
  tests/run_brixcvmfs_live.sh        -> brixcvmfs-live
  tests/run_brixcvmfs_atlas_live.sh  -> atlas-live
  tests/run_brixcvmfs_clever_live.sh -> clever-live
  tests/run_brixcvmfs_overlay.sh     -> overlay
  tests/run_scvmfs.sh                -> scvmfs

Every scenario mounts FUSE (or drives a live TLS listener) and therefore must
be opt-in gated by the collector; each unmounts in a finally block so an
aborted run never leaves an orphaned mount that wedges the fleet.
"""

from __future__ import annotations

import argparse
import base64
import glob
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from cmdscripts.c_regression_units import _gcov_flags
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, SERVER_HOST

_PORTS = cmdscript_ports("brixcvmfs_live")


class LiveSkip(RuntimeError):
    """A prerequisite (FUSE, network, keys, root) is missing; skip cleanly."""


REPO = "test.cern.ch"

# CORE list from the shell scripts (brixcvmfs + full client stack).
BRIXCVMFS_CORE = [
    "shared/cvmfs/client/client.c",
    "shared/cvmfs/client/client_negfilter.c",
    "shared/cvmfs/client/client_pathidx.c",
    "shared/cvmfs/index/pathidx.c",
    "shared/cvmfs/filter/xorf.c",
    "shared/cvmfs/fetch/fetch.c",
    "shared/cvmfs/fetch/fetch_bundle.c",
    "shared/cvmfs/bundle/bundle.c",
    "shared/cvmfs/dict/dict.c",
    "shared/cvmfs/object/object.c",
    "shared/cvmfs/failover/failover.c",
    "shared/cvmfs/catalog/catalog.c",
    "shared/cvmfs/walk/walk.c",
    "shared/cvmfs/grammar/hash.c",
    "shared/cvmfs/grammar/classify.c",
    "shared/cvmfs/signature/manifest.c",
    "shared/cvmfs/signature/whitelist.c",
    "shared/cvmfs/signature/verify.c",
    "shared/cvmfs/config/repo.c",
    "shared/cvmfs/config/cvmfs_conf.c",
    "shared/cache/cas_store.c", "shared/cache/cas_pack.c",
    "shared/cvmfs/platform/platform.c",
    "shared/net/proxy_env.c",
]

# brixcvmfs.c is one translation unit of a private multi-file split bound through
# brixcvmfs_split.h: its ops table (brixcvmfs_ops), cache-dir prep
# (brixcvmfs_prepare_cache_dir), prefetch engine (pf_start) and transport live in
# sibling TUs.  Mirror the canonical client/Makefile BRIXMOUNT_OBJS core so both
# the standalone binary and the brixMount umbrella resolve every split symbol.
# (rw/rw_ext + autofs frontends are added per-binary via no_main_frontends.)
BRIXCVMFS_APP_SPLIT = [
    "client/apps/fs/brixcvmfs_transport.c",
    "client/apps/fs/brixcvmfs_prefetch.c",
    "client/apps/fs/brixcvmfs_ops.c",
    "client/apps/fs/brixcvmfs_mount.c",
]

MKREPO_DEPS = [
    "shared/cvmfs/grammar/hash.c",
    "shared/cvmfs/object/object.c",
    "shared/cvmfs/catalog/catalog.c",
]

# phase-86: brixcvmfs pools its libcurl handles through brix_cpool (net/cpool.h).
# The STANDALONE binary has no client archive, so it must compile the pool, its
# brix_status dependency, and the two prebuilt XRootD name/error-mapping objects
# that brix_status references. The brixMount umbrella pulls the same symbols in
# transitively from client/libbrix.a (see _umbrella_link_deps), so these are
# added only on the standalone path to avoid duplicate-symbol link errors.
CPOOL_STANDALONE_DEPS = [
    "client/lib/net/cpool.c",
    "client/lib/core/types/status.c",
    "shared/xrdproto/build/kxr_names.o",
    "shared/xrdproto/build/error_mapping.o",
]


def _checks(checks: list[tuple[bool, str]]) -> int:
    for passed, message in checks:
        print(f"  {'ok  ' if passed else 'FAIL'} {message}")
    return 0 if all(item[0] for item in checks) else 1


def _fuse3_flags() -> tuple[list[str], list[str]]:
    if shutil.which("pkg-config") is None:
        raise LiveSkip("pkg-config not installed")
    exists = subprocess.run(["pkg-config", "--exists", "fuse3"], capture_output=True)
    if exists.returncode != 0:
        raise LiveSkip("fuse3 development files not present")
    if not os.path.exists("/dev/fuse"):
        raise LiveSkip("/dev/fuse not available (sandbox or missing fuse module)")
    if shutil.which("fusermount3") is None and shutil.which("fusermount") is None:
        raise LiveSkip("no fusermount/fusermount3 helper on PATH")
    cflags = subprocess.run(["pkg-config", "--cflags", "fuse3"], capture_output=True, text=True).stdout.split()
    libs = subprocess.run(["pkg-config", "--libs", "fuse3"], capture_output=True, text=True).stdout.split()
    return cflags, libs


def _gcc(run: LiveRun, output: Path, args: list) -> Path:
    link_inputs = [Path(arg) for arg in args
                   if isinstance(arg, str) and arg.endswith((".a", ".o"))]
    run.call(["gcc", *args, *_gcov_flags(link_inputs), "-o", output],
             cwd=REPO_ROOT)
    return output


def _build_mkrepo(run: LiveRun) -> Path:
    return _gcc(
        run,
        run.root / "brix_mkrepo",
        ["-Wall", "-I", "shared", "tests/cvmfs/brix_mkrepo.c", *MKREPO_DEPS, "-lsqlite3", "-lcrypto", "-lz"],
    )


# Prebuilt client archives the brixMount umbrella links against. brixmount.c
# includes cli/cli_hint.h -> brix.h, which pulls in the whole client wire stack
# (protocols/root/... under -I src) and references symbols that live in these
# static libraries. Rather than re-list that ever-growing transitive source set,
# link the same archives the production build links — mirroring the
# $(BINDIR)/brixMount recipe in client/Makefile (CLIENT_LIB + PROTO_LIB).
_UMBRELLA_ARCHIVES = ["client/libbrix.a", "shared/xrdproto/libxrdproto.a"]


def _client_link_libs() -> list[str]:
    """Return the optional libraries used by the prebuilt client archives.

    The live brixMount build links ``libbrix.a`` directly, so it must supply
    the same optional dependencies as ``client/Makefile``'s ``LDLIBS``.  Keep
    this probe-driven: an archive from a feature-minimal checkout should remain
    linkable rather than acquiring a hard dependency on every optional library.
    """
    packages = ("krb5", "libzstd", "liblzma", "libbrotlienc", "libbrotlidec",
                "bzip2", "liburing")
    libs: list[str] = []
    for package in packages:
        _extend_unique(libs, _package_libraries(package))
    if _package_exists("liblz4"):
        libs.append("-l:liblz4.so.1")
    if "-lbz2" not in libs and glob.glob("/usr/lib/*/libbz2.so*"):
        # bzip2 ships no .pc file on Debian/Ubuntu, but libxrdproto's
        # codec_bzip2.o needs it wherever the runtime library exists — the
        # pkg-config probe alone leaves the umbrella link undefined-reference.
        libs.append("-lbz2")
    return libs


def _package_libraries(package):
    result = subprocess.run(["pkg-config", "--libs", package],
                            capture_output=True, text=True)
    return result.stdout.split() if result.returncode == 0 else []


def _package_exists(package):
    result = subprocess.run(["pkg-config", "--exists", package],
                            capture_output=True)
    return result.returncode == 0


def _extend_unique(target, values):
    for value in values:
        if value not in target:
            target.append(value)


def _umbrella_link_deps() -> tuple[list[str], list[str], list[str], list[str]]:
    """(includes, defines, sources, archives) needed to link the brixMount
    umbrella. Skips cleanly if the prebuilt client archives are absent (e.g. a
    checkout where the client hasn't been built yet)."""
    for lib in _UMBRELLA_ARCHIVES:
        if not os.path.isfile(os.path.join(REPO_ROOT, lib)):
            raise LiveSkip(f"prebuilt {lib} not present (build the client first)")
    return (
        ["client/lib", "src"],                       # brix.h + wire headers
        ["-DXRDPROTO_NO_NGX"],                        # ngx-free proto shim
        ["client/apps/fs/brixcvmfs_rw.c",             # brixcvmfs_rw core
         "client/apps/fs/brixcvmfs_rw_ext.c",         # brixcvmfs_rw_main ref
         "client/apps/fs/brixautofs.c",               # brixautofs core
         "client/apps/fs/brixautofs_ext.c",           # brixautofs_main ref
         "client/apps/oci/brixoci.c",                 # brixoci_main personality
         "client/apps/oci/brixoci_copy.c",            # brixoci transfer core
         "client/apps/oci/brixoci_convert.c",         # brixoci convert --estargz
         "client/apps/oci/brixoci_gc.c",              # brixoci layout GC
         "client/apps/rpm/brixrpm.c",                 # brixrpm personality
         "client/apps/rpm/brixrpm_createrepo.c",      # brixrpm createrepo core
         "shared/cvmfs/catalog/catalog_write.c",
         "shared/cvmfs/catalog/xattr_pack.c"],        # cvmfs_xattr_* pack/unpack
        list(_UMBRELLA_ARCHIVES),
    )


def _build_brixcvmfs(run: LiveRun, *, no_main_frontends: list[str] | None = None, extra_sources: list[str] | None = None, extra_includes: list[str] | None = None, name: str = "brixcvmfs") -> Path:
    """Build brixcvmfs (or a brixMount umbrella when front-end sources are given)."""
    cflags, libs = _fuse3_flags()
    includes = list(extra_includes or [])
    sources = list(extra_sources or [])
    defines, archives, syslibs = _link_dependencies(
        no_main_frontends, includes, sources
    )
    args = _compiler_arguments(
        includes, defines, cflags, no_main_frontends, sources, archives,
        libs, syslibs,
    )
    return _gcc(run, run.root / name, args)


def _link_dependencies(frontends, includes, sources):
    if _is_umbrella(frontends):
        return _prepare_umbrella_dependencies(includes, sources)
    _extend_unique(includes, ("client/lib", "src"))
    _extend_unique(sources, CPOOL_STANDALONE_DEPS)
    return ["-DXRDPROTO_NO_NGX"], [], []


def _is_umbrella(frontends):
    if not frontends:
        return False
    return any("brixmount.c" in frontend for frontend in frontends)


def _prepare_umbrella_dependencies(includes, sources):
    umbrella_includes, defines, umbrella_sources, archives = _umbrella_link_deps()
    _extend_unique(includes, umbrella_includes)
    _extend_unique(sources, umbrella_sources)
    return defines, archives, ["-lssl", "-pthread", *_client_link_libs()]


def _compiler_arguments(includes, defines, cflags, frontends, sources,
                        archives, libs, syslibs):
    args = ["-Wall", "-Wextra", "-Werror", "-I", "shared"]
    for include in includes:
        args += ["-I", include]
    args += defines
    args += cflags
    if frontends:
        args += ["-DBRIXCVMFS_NO_MAIN", *frontends]
    args += ["client/apps/fs/brixcvmfs.c", *BRIXCVMFS_APP_SPLIT, *sources, *BRIXCVMFS_CORE, *archives,
             *libs, "-lcurl", "-lsqlite3", "-lcrypto", "-lz", "-lzstd", *syslibs]
    return args


def _make_repo(run: LiveRun, mkrepo: Path, web: Path, pub: Path) -> str:
    """Generate the signed mock repo; return the expected /hello content."""
    return run.call([mkrepo, REPO, web, pub], cwd=REPO_ROOT).stdout.strip()


def _serve(run: LiveRun, web: Path) -> int:
    port = _PORTS[0]  # was free_port()
    run.spawn([sys.executable, "-m", "http.server", str(port), "--bind", BIND_HOST], cwd=web)
    from lib_py.util import wait_tcp

    if not wait_tcp(BIND_HOST, port, 10):
        raise LiveFailure(f"mock repo http.server did not listen on {port}")
    return port


def _repo_env(run: LiveRun, port: int, pub: Path, *, cache: Path | None = None, tmp: Path | None = None) -> dict[str, str]:
    env = {
        "BRIXCVMFS_SERVER": f"http://{SERVER_HOST}:{port}/cvmfs/{REPO}",
        "BRIXCVMFS_PUBKEY": str(pub),
        "BRIXCVMFS_TMP": str(tmp if tmp is not None else run.mkdir("tmp")),
    }
    if cache is not None:
        env["BRIXCVMFS_CACHE"] = str(cache)
    return env


def _unmount(mnt: Path) -> None:
    """fusermount3 -u / fusermount -u with a lazy umount fallback. Never raises."""
    for argv in (["fusermount3", "-u"], ["fusermount", "-u"], ["umount", "-l"]):
        if shutil.which(argv[0]) is None:
            continue
        proc = subprocess.run([*argv, str(mnt)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if proc.returncode == 0:
            return


def _wait_mounted(mnt: Path, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.ismount(str(mnt)):
            return True
        time.sleep(0.2)
    return os.path.ismount(str(mnt))


def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _listing(mnt: Path) -> list[str]:
    try:
        return sorted(os.listdir(mnt))
    except OSError:
        return []


def _overlay_xattr(path: Path) -> str | None:
    try:
        return os.getxattr(str(path), "user.overlay").decode()
    except OSError:
        return None


def mount_cvmfs_live(nginx: Path | None = None) -> int:
    """mount.cvmfs helper drives brixMount (autofs / mount -t cvmfs code path)."""
    _fuse3_flags()
    with LiveRun("mountcvmfs_live", nginx) as run:
        mkrepo = _build_mkrepo(run)
        brixmount = _build_brixcvmfs(run, no_main_frontends=["client/apps/fs/brixmount.c"], name="brixMount")
        web, mnt, cache = run.mkdir("web"), run.mkdir("mnt"), run.mkdir("cache")
        pub = run.root / "repo.pub"
        expect = _make_repo(run, mkrepo, web, pub)
        port = _serve(run, web)
        env = {**_repo_env(run, port, pub, cache=cache), "BRIXMOUNT_BIN": str(brixmount)}
        try:
            print("== mount via mount.cvmfs helper (daemonizing) ==")
            run.call(["sh", "deploy/cvmfs/mount.cvmfs", REPO, mnt, "-o", "auto_unmount"], cwd=REPO_ROOT, env=env)
            mounted = _wait_mounted(mnt)
            listing = _listing(mnt)
            got = _read(mnt / "hello")
            print(f"   ls:{listing} got:[{got}]")
            print("== auto.cvmfs program map emits an -fstype=cvmfs entry ==")
            automap = run.call(["sh", "deploy/cvmfs/auto.cvmfs", REPO], cwd=REPO_ROOT).stdout
            print(f"   map: {automap.strip()}")
        finally:
            _unmount(mnt)
        return _checks([
            (mounted, "mount.cvmfs helper produced a live mount"),
            (listing == ["hello"] and got == expect, "readdir + content through the helper mount"),
            ("fstype=cvmfs" in automap, "auto.cvmfs map contains -fstype=cvmfs"),
        ])


def brixmount_live(nginx: Path | None = None) -> int:
    """brixMount umbrella mounts a signed mock repo end-to-end over HTTP."""
    _fuse3_flags()
    with LiveRun("brixmount_live", nginx) as run:
        mkrepo = _build_mkrepo(run)
        brixmount = _build_brixcvmfs(run, no_main_frontends=["client/apps/fs/brixmount.c"], name="brixMount")
        web, mnt, cache = run.mkdir("web"), run.mkdir("mnt"), run.mkdir("cache")
        pub = run.root / "repo.pub"
        expect = _make_repo(run, mkrepo, web, pub)
        port = _serve(run, web)
        env = _repo_env(run, port, pub, cache=cache)
        try:
            print("== serve + mount via umbrella ==")
            run.spawn([brixmount, "cvmfs", REPO, mnt, "-o", "auto_unmount", "-f"], env=env)
            mounted = _wait_mounted(mnt)
            listing = _listing(mnt)
            got = _read(mnt / "hello")
            print(f"   ls:{listing} got:[{got}]")
        finally:
            _unmount(mnt)
        print("== unknown-type rejection ==")
        bogus = run.call([brixmount, "bogus", "x", "/tmp"], check=False)
        return _checks([
            (mounted, "umbrella produced a live mount"),
            (listing == ["hello"] and got == expect, "readdir + content through brixMount cvmfs"),
            (bogus.returncode == 2, f"unknown mount type rejected with rc 2 (got {bogus.returncode})"),
        ])


def brixcvmfs_live(nginx: Path | None = None) -> int:
    """Full brix stack over a real network + kernel FUSE mount of a signed repo."""
    _fuse3_flags()
    with LiveRun("brixcvmfs_live", nginx) as run:
        mkrepo = _build_mkrepo(run)
        brixcvmfs = _build_brixcvmfs(run)
        web, mnt, cache = run.mkdir("web"), run.mkdir("mnt"), run.mkdir("cache")
        pub = run.root / "repo.pub"
        expect = _make_repo(run, mkrepo, web, pub)
        print(f"   expected content: [{expect}]")
        port = _serve(run, web)
        env = _repo_env(run, port, pub, cache=cache)
        try:
            print("== mount ==")
            run.spawn([brixcvmfs, REPO, mnt, "-o", "auto_unmount", "-f"], env=env)
            mounted = _wait_mounted(mnt)
            listing = _listing(mnt)
            print(f"== readdir ==\n   ls: {listing}")
            got = _read(mnt / "hello")
            print(f"== read file ==\n   got: [{got}]")
            try:
                size = (mnt / "hello").stat().st_size
            except OSError:
                size = -1
            print(f"== stat ==\n   size: {size}")
        finally:
            _unmount(mnt)
        return _checks([
            (mounted, "brixcvmfs produced a live mount"),
            (listing == ["hello"], "readdir shows the repo root"),
            (got == expect, "file content byte-exact through FUSE"),
        ])

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "brixcvmfs_live_part2.py",
                    "brixcvmfs_live_part3.py")
