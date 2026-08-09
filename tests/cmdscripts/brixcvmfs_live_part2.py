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
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, SERVER_HOST

_PORTS = cmdscript_ports("brixcvmfs_live")


def negfilter_live(nginx: Path | None = None) -> int:
    """G1 negative-lookup filter: sidecar persisted, tamper -> verified rebuild."""
    _fuse3_flags()
    with LiveRun("negfilter_live", nginx) as run:
        mkrepo = _build_mkrepo(run)
        brixcvmfs = _build_brixcvmfs(run)
        web, mnt, cache = run.mkdir("web"), run.mkdir("mnt"), run.mkdir("cache")
        pub = run.root / "repo.pub"
        expect = _make_repo(run, mkrepo, web, pub)
        port = _serve(run, web)
        env = _repo_env(run, port, pub, cache=cache)
        sidecar = cache / "negfilter.bxf"
        mount_opts = "negfilter,noclever,auto_unmount"

        def _mount_and_probe() -> tuple[bool, str | None, bool]:
            try:
                run.spawn([brixcvmfs, REPO, mnt, "-o", mount_opts, "-f"], env=env)
                mounted = _wait_mounted(mnt)
                got = _read(mnt / "hello")
                absent = not (mnt / "nope").exists()
                return mounted, got, absent
            finally:
                _unmount(mnt)

        print("== mount 1: -o negfilter builds + persists the sidecar ==")
        mounted1, got1, absent1 = _mount_and_probe()
        side_ok = sidecar.is_file() and sidecar.stat().st_size > 44
        print(f"   ls hello:[{got1}] absent-ok:{absent1} sidecar:{side_ok}")

        print("== tamper the sidecar, remount: fail-closed rebuild ==")
        original = sidecar.read_bytes() if side_ok else b""
        if side_ok:
            tampered = bytearray(original)
            tampered[len(tampered) // 2] ^= 0xFF   # flip a fingerprint bit
            sidecar.write_bytes(bytes(tampered))
        mounted2, got2, absent2 = _mount_and_probe()
        # the tampered image must have been refused and REPLACED by a fresh build
        rewritten = side_ok and sidecar.is_file() and sidecar.read_bytes() != bytes(tampered)
        print(f"   hello:[{got2}] absent-ok:{absent2} sidecar-rewritten:{rewritten}")

        return _checks([
            (mounted1 and got1 == expect and absent1,
             "negfilter mount serves member + absent paths correctly"),
            (side_ok, "sidecar negfilter.bxf persisted in the cache"),
            (mounted2 and got2 == expect and absent2,
             "tampered sidecar refused: mount still serves correctly (security-neg)"),
            (rewritten, "tampered sidecar replaced by a fresh verified build"),
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
        # brixcvmfs_rw_ext.c carries the rw fuse-ops table + setup/main (the
        # weak-symbol strong overrides); omitting it links cleanly but leaves
        # brixcvmfs_rw_main NULL → "rw overlay driver not linked" at runtime.
        rw_sources = ["client/apps/fs/brixcvmfs_rw.c", "client/apps/fs/brixcvmfs_rw_ext.c",
                      "client/lib/fs/overlay.c", "client/lib/fs/overlay_copyup.c"]
        brixcvmfs_rw = _build_brixcvmfs(
            run,
            extra_sources=rw_sources,
            extra_includes=["client/lib"],
            name="brixcvmfs_rw",
        )
        brixmount_ov = _build_brixcvmfs(
            run,
            no_main_frontends=["client/apps/fs/brixmount.c"],
            extra_sources=rw_sources,
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


