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
        print("== mount 1: -o negfilter builds + persists the sidecar ==")
        first = _negfilter_mount_probe(run, brixcvmfs, mnt, mount_opts, env)
        side_ok = sidecar.is_file() and sidecar.stat().st_size > 44
        print(f"   ls hello:[{first[1]}] absent-ok:{first[2]} sidecar:{side_ok}")
        print("== tamper the sidecar, remount: fail-closed rebuild ==")
        tampered = _tamper_sidecar(sidecar, side_ok)
        second = _negfilter_mount_probe(run, brixcvmfs, mnt, mount_opts, env)
        rewritten = _sidecar_rewritten(sidecar, side_ok, tampered)
        print(f"   hello:[{second[1]}] absent-ok:{second[2]} sidecar-rewritten:{rewritten}")
        return _negfilter_results(first, second, expect, side_ok, rewritten)


def _negfilter_mount_probe(run, binary, mount, options, env):
    try:
        run.spawn([binary, REPO, mount, "-o", options, "-f"], env=env)
        return _wait_mounted(mount), _read(mount / "hello"), not (mount / "nope").exists()
    finally:
        _unmount(mount)


def _tamper_sidecar(sidecar, side_ok):
    if not side_ok:
        return bytearray()
    tampered = bytearray(sidecar.read_bytes())
    tampered[len(tampered) // 2] ^= 0xFF
    sidecar.write_bytes(bytes(tampered))
    return tampered


def _sidecar_rewritten(sidecar, side_ok, tampered):
    return side_ok and sidecar.is_file() and sidecar.read_bytes() != bytes(tampered)


def _negfilter_results(first, second, expected, side_ok, rewritten):
    return _checks([
        (first[0] and first[1] == expected and first[2],
         "negfilter mount serves member + absent paths correctly"),
        (side_ok, "sidecar negfilter.bxf persisted in the cache"),
        (second[0] and second[1] == expected and second[2],
         "tampered sidecar refused and rebuilt"),
        (rewritten, "tampered sidecar replaced by a verified build"),
    ])


def atlas_live(nginx: Path | None = None) -> int:
    """Mount live atlas.cern.ch from a Stratum-1, descend a nested catalog, read."""
    stratum1 = os.environ.get("ATLAS_S1", "http://s1cern-cvmfs.openhtc.io/cvmfs/atlas.cern.ch")
    keys = Path(os.environ.get("CVMFS_KEYS", "/etc/cvmfs/keys/cern.ch"))
    _require_atlas(stratum1, keys)
    _fuse3_flags()
    with LiveRun("atlas_live", nginx) as run:
        brixcvmfs = _build_brixcvmfs(run)
        mnt, cache, tmp = run.mkdir("mnt"), run.mkdir("cache"), run.mkdir("tmp")
        env = {"BRIXCVMFS_SERVER": stratum1, "BRIXCVMFS_PUBKEY": str(keys),
               "BRIXCVMFS_CACHE": str(cache), "BRIXCVMFS_TMP": str(tmp)}
        mounted, has_repo, read_ok = _mount_atlas(run, brixcvmfs, mnt, env)
        return _checks([(mounted, "atlas.cern.ch mounted from the Stratum-1"),
                        (has_repo, "root catalog lists /repo"),
                        (read_ok, "nested catalog descent read a real file")])


def _require_atlas(stratum1, keys):
    reachable = subprocess.run(
        ["curl", "-fsS", "-o", os.devnull, "--max-time", "8", f"{stratum1}/.cvmfspublished"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if reachable.returncode != 0:
        raise LiveSkip(f"atlas Stratum-1 unreachable ({stratum1})")
    if not keys.exists():
        raise LiveSkip(f"cern.ch key not present ({keys})")


def _mount_atlas(run, binary, mount, env):
    try:
        run.spawn([binary, "atlas.cern.ch", mount, "-o", "noclever", "-f"], env=env)
        mounted = _wait_mounted(mount, timeout=20)
        listing = _listing(mount)
        print(f"== top-level (root catalog) ==\n{listing}")
        small = _find_small_file(
            mount / "repo", max_depth=4, max_size=20 * 1024, budget=40.0
        )
        read_ok = _read_atlas_file(small, mount)
        return mounted, any("repo" in entry for entry in listing), read_ok
    finally:
        _unmount(mount)


def _read_atlas_file(path, mount):
    if path is None:
        print("FAIL: could not find a small atlas file")
        return False
    try:
        result = subprocess.run(
            ["head", "-c", "1", str(path)], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=20,
        )
    except subprocess.TimeoutExpired:
        return False
    if result.returncode == 0:
        print(f"   read {str(path)[len(str(mount)):]} OK")
        return True
    return False


def _find_small_file(root: Path, *, max_depth: int, max_size: int, budget: float) -> Path | None:
    deadline = time.monotonic() + budget
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack and time.monotonic() < deadline:
        directory, depth = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        found = _inspect_atlas_entries(entries, depth, max_depth, max_size, deadline, stack)
        if found is not None:
            return found
    return None


def _inspect_atlas_entries(entries, depth, max_depth, max_size, deadline, stack):
    for entry in entries:
        if time.monotonic() >= deadline:
            return None
        found = _inspect_atlas_entry(entry, depth, max_depth, max_size, stack)
        if found is not None:
            return found
    return None


def _inspect_atlas_entry(entry, depth, max_depth, max_size, stack):
    try:
        if entry.is_file(follow_symlinks=False):
            if entry.stat(follow_symlinks=False).st_size < max_size:
                return Path(entry.path)
        elif entry.is_dir(follow_symlinks=False) and depth + 1 < max_depth:
            stack.append((Path(entry.path), depth + 1))
    except OSError:
        pass
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


from split_continuation import load as _load_continuation


_load_continuation(globals(), __file__, "brixcvmfs_live_overlay.py")
