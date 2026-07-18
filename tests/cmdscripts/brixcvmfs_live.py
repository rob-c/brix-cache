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
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from settings import free_port


class LiveSkip(RuntimeError):
    """A prerequisite (FUSE, network, keys, root) is missing; skip cleanly."""


REPO = "test.cern.ch"

# CORE list from the shell scripts (brixcvmfs + full client stack).
BRIXCVMFS_CORE = [
    "shared/cvmfs/client/client.c",
    "shared/cvmfs/fetch/fetch.c",
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
    "shared/cache/cas_store.c",
    "shared/net/proxy_env.c",
]

MKREPO_DEPS = [
    "shared/cvmfs/grammar/hash.c",
    "shared/cvmfs/object/object.c",
    "shared/cvmfs/catalog/catalog.c",
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
    run.call(["gcc", *args, "-o", output], cwd=REPO_ROOT)
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
        ["client/apps/fs/brixcvmfs_rw.c",             # brixcvmfs_rw_main ref
         "client/apps/fs/brixautofs.c"],              # brixautofs_main ref
        list(_UMBRELLA_ARCHIVES),
    )


def _build_brixcvmfs(run: LiveRun, *, no_main_frontends: list[str] | None = None, extra_sources: list[str] | None = None, extra_includes: list[str] | None = None, name: str = "brixcvmfs") -> Path:
    """Build brixcvmfs (or a brixMount umbrella when front-end sources are given)."""
    cflags, libs = _fuse3_flags()
    includes = list(extra_includes or [])
    sources = list(extra_sources or [])
    defines: list = []
    archives: list = []
    syslibs: list = []

    # The brixMount umbrella (main() owned by brixmount.c) needs the prebuilt
    # client archives + their include/define/source deps; the standalone
    # brixcvmfs binary does not.
    is_umbrella = bool(no_main_frontends) and any("brixmount.c" in f for f in no_main_frontends)
    if is_umbrella:
        u_includes, defines, u_sources, archives = _umbrella_link_deps()
        for inc in u_includes:
            if inc not in includes:
                includes.append(inc)
        for src in u_sources:
            if src not in sources:
                sources.append(src)
        syslibs = ["-lssl", "-pthread"]

    args: list = ["-Wall", "-Wextra", "-Werror", "-I", "shared"]
    for include in includes:
        args += ["-I", include]
    args += defines
    args += cflags
    if no_main_frontends:
        args += ["-DBRIXCVMFS_NO_MAIN", *no_main_frontends]
    args += ["client/apps/fs/brixcvmfs.c", *sources, *BRIXCVMFS_CORE, *archives,
             *libs, "-lcurl", "-lsqlite3", "-lcrypto", "-lz", *syslibs]
    return _gcc(run, run.root / name, args)


def _make_repo(run: LiveRun, mkrepo: Path, web: Path, pub: Path) -> str:
    """Generate the signed mock repo; return the expected /hello content."""
    return run.call([mkrepo, REPO, web, pub], cwd=REPO_ROOT).stdout.strip()


def _serve(run: LiveRun, web: Path) -> int:
    port = free_port()
    run.spawn([sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"], cwd=web)
    from lib_py.util import wait_tcp

    if not wait_tcp("127.0.0.1", port, 10):
        raise LiveFailure(f"mock repo http.server did not listen on {port}")
    return port


def _repo_env(run: LiveRun, port: int, pub: Path, *, cache: Path | None = None, tmp: Path | None = None) -> dict[str, str]:
    env = {
        "BRIXCVMFS_SERVER": f"http://localhost:{port}/cvmfs/{REPO}",
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


def atlas_live(nginx: Path | None = None) -> int:
    """Mount live atlas.cern.ch from a Stratum-1, descend a nested catalog, read."""
    stratum1 = os.environ.get("ATLAS_S1", "http://s1cern-cvmfs.openhtc.io/cvmfs/atlas.cern.ch")
    keys = Path(os.environ.get("CVMFS_KEYS", "/etc/cvmfs/keys/cern.ch"))
    reachable = subprocess.run(
        ["curl", "-fsS", "-o", os.devnull, "--max-time", "8", f"{stratum1}/.cvmfspublished"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if reachable.returncode != 0:
        raise LiveSkip(f"atlas Stratum-1 unreachable ({stratum1})")
    if not keys.exists():
        raise LiveSkip(f"cern.ch key not present ({keys})")
    _fuse3_flags()
    with LiveRun("atlas_live", nginx) as run:
        brixcvmfs = _build_brixcvmfs(run)
        mnt, cache, tmp = run.mkdir("mnt"), run.mkdir("cache"), run.mkdir("tmp")
        env = {
            "BRIXCVMFS_SERVER": stratum1,
            "BRIXCVMFS_PUBKEY": str(keys),
            "BRIXCVMFS_CACHE": str(cache),
            "BRIXCVMFS_TMP": str(tmp),
        }
        try:
            run.spawn([brixcvmfs, "atlas.cern.ch", mnt, "-o", "noclever", "-f"], env=env)
            mounted = _wait_mounted(mnt, timeout=20)
            top = _listing(mnt)
            print(f"== top-level (root catalog) ==\n{top}")
            has_repo = any("repo" in entry for entry in top)
            print("== nested catalog descent + real file read ==")
            small = _find_small_file(mnt / "repo", max_depth=4, max_size=20 * 1024, budget=40.0)
            read_ok = False
            if small is not None:
                try:
                    head = subprocess.run(["head", "-c", "1", str(small)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
                    read_ok = head.returncode == 0
                except subprocess.TimeoutExpired:
                    read_ok = False
                if read_ok:
                    try:
                        size = small.stat().st_size
                    except OSError:
                        size = -1
                    print(f"   read {str(small)[len(str(mnt)):]} ({size} bytes) OK")
            if not read_ok:
                print("FAIL: could not read a real atlas file")
        finally:
            _unmount(mnt)
        return _checks([
            (mounted, "atlas.cern.ch mounted from the Stratum-1"),
            (has_repo, "root catalog lists /repo"),
            (read_ok, "nested catalog descent read a real file"),
        ])


def _find_small_file(root: Path, *, max_depth: int, max_size: int, budget: float) -> Path | None:
    deadline = time.monotonic() + budget
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack and time.monotonic() < deadline:
        directory, depth = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        for entry in entries:
            if time.monotonic() >= deadline:
                return None
            try:
                if entry.is_file(follow_symlinks=False) and entry.stat(follow_symlinks=False).st_size < max_size:
                    return Path(entry.path)
                if entry.is_dir(follow_symlinks=False) and depth + 1 < max_depth:
                    stack.append((Path(entry.path), depth + 1))
            except OSError:
                continue
    return None


def clever_live(nginx: Path | None = None) -> int:
    """Default-on clever overlay: cache in <mnt>/.brixcache, hidden while mounted,
    populated by reads, persisting after unmount; DPI hardening (-o fresh,tls)."""
    _fuse3_flags()
    with LiveRun("clever_live", nginx) as run:
        mkrepo = _build_mkrepo(run)
        brixcvmfs = _build_brixcvmfs(run)
        web, mnt = run.mkdir("web"), run.mkdir("mnt")
        pub = run.root / "repo.pub"
        expect = _make_repo(run, mkrepo, web, pub)
        port = _serve(run, web)
        # NOTE: no BRIXCVMFS_CACHE (that would force non-clever). -o fresh,tls
        # exercises hardening; tls falls back to http against the mock server.
        env = _repo_env(run, port, pub)
        try:
            print("== clever mount (default; cache -> <mnt>/.brixcache), DPI hardening on ==")
            run.spawn([brixcvmfs, REPO, mnt, "-o", "fresh,tls,retries=3,auto_unmount", "-f"], env=env)
            mounted = _wait_mounted(mnt, timeout=15)
            time.sleep(1)
            print("== while mounted: overlay hides .brixcache, shows cvmfs tree ==")
            listing = _listing(mnt)
            print(f"   ls -a: {listing}")
            hello_visible = "hello" in listing
            cache_hidden = ".brixcache" not in listing
            got = _read(mnt / "hello")
        finally:
            print("== unmount ==")
            _unmount(mnt)
        time.sleep(1)
        print("== after unmount: .brixcache visible + populated + persists ==")
        cache_dir = mnt / ".brixcache"
        cached = [p for p in cache_dir.rglob("*") if p.is_file() and ".tmp." not in p.name] if cache_dir.is_dir() else []
        print(f"   cached objects: {len(cached)}")
        return _checks([
            (mounted, "clever mount came up"),
            (hello_visible, "hello visible through the overlay"),
            (cache_hidden, ".brixcache hidden by the overlay while mounted"),
            (got == expect, "content byte-exact through the clever mount"),
            (cache_dir.is_dir(), ".brixcache present after unmount"),
            (len(cached) >= 1, "overlay cache populated and persistent"),
        ])


def overlay(nginx: Path | None = None) -> int:
    """cvmfs-rw writable overlay: create/modify/delete land in .brixwrites/upper,
    win over the lower repo, persist across remounts; ro mount stays EROFS."""
    _fuse3_flags()
    with LiveRun("brixcvmfs_ov", nginx) as run:
        mkrepo = _build_mkrepo(run)
        brixcvmfs_rw = _build_brixcvmfs(
            run,
            extra_sources=["client/apps/fs/brixcvmfs_rw.c", "client/lib/fs/overlay.c"],
            extra_includes=["client/lib"],
            name="brixcvmfs_rw",
        )
        brixmount_ov = _build_brixcvmfs(
            run,
            no_main_frontends=["client/apps/fs/brixmount.c"],
            extra_sources=["client/apps/fs/brixcvmfs_rw.c", "client/lib/fs/overlay.c"],
            extra_includes=["client/lib"],
            name="brixmount_ov",
        )
        web, mnt, tmp = run.mkdir("web"), run.mkdir("mnt"), run.mkdir("tmp")
        pub = run.root / "repo.pub"
        expect = _make_repo(run, mkrepo, web, pub)
        port = _serve(run, web)
        env = _repo_env(run, port, pub, tmp=tmp)
        checks: list[tuple[bool, str]] = []

        def mount(argv: list) -> None:
            run.spawn([*argv, "-o", "auto_unmount", "-f"], env=env)
            _wait_mounted(mnt, timeout=15)
            time.sleep(1)

        def umnt() -> None:
            _unmount(mnt)
            time.sleep(1)

        def write(path: Path, text: str) -> bool:
            try:
                path.write_text(text + "\n")
                return True
            except OSError:
                return False

        try:
            print("== rw mount: lower reads work ==")
            mount([brixcvmfs_rw, "--rw", REPO, mnt])
            checks.append((_read(mnt / "hello") == expect, "lower read through rw mount"))

            print("== create a new file ==")
            checks.append((write(mnt / "newfile", "local"), "create accepted"))
            checks.append((_read(mnt / "newfile") == "local", "new-file readback"))
            listing = _listing(mnt)
            checks.append(("newfile" in listing, "newfile listed"))
            checks.append((".brixwrites" in listing, ".brixwrites visible"))
            checks.append((".brixcache" not in listing, ".brixcache not leaked"))
            checks.append((_overlay_xattr(mnt / "newfile") == "new", "user.overlay(newfile) == new"))

            print("== modify a lower file (copy-up) ==")
            checks.append((write(mnt / "hello", "changed"), "modify accepted"))
            checks.append((_read(mnt / "hello") == "changed", "modified readback"))
            checks.append((_overlay_xattr(mnt / "hello") == "modified", "user.overlay(hello) == modified"))

            print("== nested mkdir + write ==")
            try:
                (mnt / "newdir/sub").mkdir(parents=True)
                mkdir_ok = True
            except OSError:
                mkdir_ok = False
            checks.append((mkdir_ok, "mkdir -p newdir/sub"))
            write(mnt / "newdir/sub/f", "nested")
            checks.append((_read(mnt / "newdir/sub/f") == "nested", "nested readback"))

            print("== rename a (copied-up) lower file: whiteout stays behind ==")
            try:
                os.rename(mnt / "hello", mnt / "hello.moved")
                mv_ok = True
            except OSError:
                mv_ok = False
            checks.append((mv_ok, "rename hello -> hello.moved"))
            checks.append((_read(mnt / "hello.moved") == "changed", "moved content intact"))
            checks.append((_read(mnt / "hello") is None, "hello unreadable after mv"))
            checks.append(("hello" not in _listing(mnt), "hello not listed after mv"))

            print("== reserved names refused ==")
            checks.append((not write(mnt / ".brix.wh.x", ""), "reserved whiteout name refused"))

            print("== unmount: overlay tree on disk ==")
            umnt()
            upper = mnt / ".brixwrites/upper"
            checks.append(((upper / "newfile").is_file(), "upper/newfile on disk"))
            checks.append(((upper / ".brix.wh.hello").is_file(), "whiteout marker on disk"))
            checks.append(((upper / "hello.moved").is_file(), "upper/hello.moved on disk"))

            print("== unmounted --overlay-list works on the raw tree ==")
            raw = run.call([brixmount_ov, "--overlay-list", mnt], env=env, check=False)
            raw_lines = raw.stdout.splitlines()
            checks.append(("upper newfile" in raw_lines, "raw list: upper newfile"))
            checks.append(("deleted hello" in raw_lines, "raw list: deleted hello"))
            checks.append(("dir newdir" in raw_lines, "raw list: dir newdir"))
            non_overlay = run.call([brixmount_ov, "--overlay-list", tmp], env=env, check=False)
            checks.append((non_overlay.returncode != 0, "--overlay-list rejects a non-overlay dir"))

            print("== remount via brixMount cvmfs-rw: local changes persist ==")
            mount([brixmount_ov, "cvmfs-rw", REPO, mnt])
            checks.append((_read(mnt / "newfile") == "local", "newfile persisted"))
            checks.append((_read(mnt / "hello.moved") == "changed", "hello.moved persisted"))
            checks.append((_read(mnt / "newdir/sub/f") == "nested", "nested persisted"))
            checks.append((_read(mnt / "hello") is None, "deleted hello stayed deleted"))

            print("== mounted --overlay-list classifies through the passthrough ==")
            mounted_list = run.call([brixmount_ov, "--overlay-list", mnt], env=env, check=False)
            mounted_lines = mounted_list.stdout.splitlines()
            checks.append(("new newfile" in mounted_lines, "mounted list: new newfile"))
            checks.append(("deleted hello" in mounted_lines, "mounted list: deleted hello"))
            checks.append(("new hello.moved" in mounted_lines, "mounted list: new hello.moved"))

            print("== mounted --overlay-reset restores pristine lower ==")
            reset = run.call([brixmount_ov, "--overlay-reset", mnt], env=env, check=False)
            checks.append((reset.returncode == 0, "--overlay-reset rc 0"))
            checks.append((_read(mnt / "hello") == expect, "hello restored to lower content"))
            checks.append((_read(mnt / "newfile") is None, "newfile gone after reset"))
            umnt()

            print("== regression: plain ro mount stays EROFS, pristine lower ==")
            mount([brixcvmfs_rw, REPO, mnt])
            checks.append((_read(mnt / "hello") == expect, "ro lower content pristine"))
            checks.append((not write(mnt / "rofail", ""), "ro mount refuses writes"))
            checks.append((".brixwrites" not in _listing(mnt), "ro mount hides .brixwrites"))
        finally:
            _unmount(mnt)
        return _checks(checks)


def scvmfs(nginx: Path | None = None) -> int:
    """Experimental scvmfs:// secure protocol: TLS parity, transport-neg,
    bearer authz negatives, and config-time layering enforcement."""
    with LiveRun("scvmfs", nginx) as run:
        if not run.nginx.exists():
            raise LiveSkip(f"nginx binary not found: {run.nginx}")
        if shutil.which("openssl") is None:
            raise LiveSkip("openssl not installed")
        run.mkdir("cache")
        run.mkdir("logs")
        mock_port, tls_port = free_port(), free_port()

        # throwaway TLS identity for the listener
        run.call([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-keyout", run.root / "key.pem", "-out", run.root / "crt.pem",
        ])
        # minimal issuer registry for the bearer negatives: one REAL RSA key
        # that simply never signed our test tokens.
        run.call(["openssl", "genrsa", "-out", run.root / "reg.pem", "2048"])
        modulus_out = run.call(["openssl", "rsa", "-in", run.root / "reg.pem", "-noout", "-modulus"]).stdout
        modulus_hex = modulus_out.strip().split("=", 1)[1]
        n_b64 = base64.urlsafe_b64encode(bytes.fromhex(modulus_hex)).rstrip(b"=").decode()
        run.write(
            run.root / "jwks.json",
            json.dumps({"keys": [{"kty": "RSA", "kid": "t1", "alg": "RS256", "use": "sig", "n": n_b64, "e": "AQAB"}]}),
        )
        run.write(
            run.root / "scitokens.cfg",
            "[Global]\naudience = https://wlcg.cern.ch/jwt/v1/any\n\n"
            f"[Issuer test]\nissuer = https://tokens.example\nbase_path = /cvmfs\njwks_file = {run.root}/jwks.json\n",
        )

        run.spawn([sys.executable, REPO_ROOT / "tests/cvmfs/mock_stratum1.py", "--port", str(mock_port), "--objects", "4", "--seed", "55"])
        from lib_py.util import wait_tcp

        if not wait_tcp("127.0.0.1", mock_port, 10):
            raise LiveFailure(f"mock Stratum-1 did not listen on {mock_port}")
        objects = json.loads(run.call(["curl", "-sS", f"http://127.0.0.1:{mock_port}/ctl/objects"]).stdout)
        obj = objects[0]

        def mkconf(authz: str, extra: str) -> Path:
            return run.write(
                run.root / "nginx.conf",
                f"""daemon on; error_log {run.root}/logs/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen 127.0.0.1:{tls_port} ssl;
    ssl_certificate     {run.root}/crt.pem;
    ssl_certificate_key {run.root}/key.pem;
    location /cvmfs/ {{
        brix_storage_backend http://127.0.0.1:{mock_port};
        brix_cache_store posix:{run.root}/cache;
        brix_cvmfs on;
        brix_scvmfs on;
        brix_scvmfs_authz {authz};
{extra}
    }}
}} }}
""",
            )

        # 1: TLS parity (authz none)
        config = mkconf("none", "")
        run.start_nginx(run.root, config, tls_port)
        tls_body = run.curl_bytes(f"https://127.0.0.1:{tls_port}{obj}", "-k")
        ref_body = run.curl_bytes(f"http://127.0.0.1:{mock_port}{obj}")
        # 2: plain HTTP to the TLS port is refused, not served
        plain_status = run.curl_status(f"http://127.0.0.1:{tls_port}{obj}")
        # 3: bearer authz-negs
        run.stop_nginx(run.root)
        config = mkconf("bearer", f"        brix_scvmfs_token_issuers {run.root}/scitokens.cfg;")
        run.start_nginx(run.root, config, tls_port)
        missing_status = run.curl_status(f"https://127.0.0.1:{tls_port}{obj}", "-k")
        garbage_status = run.curl_status(f"https://127.0.0.1:{tls_port}{obj}", "-k", "-H", "Authorization: Bearer not.a.token")
        # positive bearer acceptance is exercised by the fleet token fixtures,
        # not by this port (parity with the shell script's scope).
        # 4: layering enforced at config time
        bad = run.write(
            run.root / "bad.conf",
            f"""events {{ worker_connections 32; }}
http {{ server {{ listen 127.0.0.1:{tls_port} ssl;
    ssl_certificate {run.root}/crt.pem; ssl_certificate_key {run.root}/key.pem;
    location / {{ brix_scvmfs on; }} }} }}
""",
        )
        layering = run.call([run.nginx, "-t", "-c", bad, "-p", run.root], check=False)
        return _checks([
            (tls_body == ref_body, "scvmfs TLS parity byte-exact"),
            (plain_status == 400, f"plain HTTP on scvmfs listener refused (got {plain_status})"),
            (missing_status == 401 and garbage_status == 401, f"bearer: missing/garbage token -> 401 ({missing_status}/{garbage_status})"),
            (layering.returncode != 0, "scvmfs without cvmfs rejected by nginx -t"),
        ])


SCENARIOS = {
    "mount-cvmfs-live": mount_cvmfs_live,
    "brixmount-live": brixmount_live,
    "brixcvmfs-live": brixcvmfs_live,
    "atlas-live": atlas_live,
    "clever-live": clever_live,
    "overlay": overlay,
    "scvmfs": scvmfs,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveSkip as exc:
        print(f"SKIP: {exc}")
        return 0
    except LiveFailure as exc:
        print(f"brixcvmfs live scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
