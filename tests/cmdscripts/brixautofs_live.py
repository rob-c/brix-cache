"""Live scenarios for the `brixMount autofs` automount umbrella daemon.

The umbrella mounts a FUSE fs on a /cvmfs-style directory and fork/execs
`brixMount cvmfs <fqrn> …` as a real nested mount on first access. These
scenarios drive it as a regular user against the signed mock repo from the
brixcvmfs live harness. FUSE-mounting, so opt-in gated like the rest of the
live ports; every mount is torn down in a finally block.
"""

from __future__ import annotations

import argparse
import errno
import os
import signal
import sys
import time
from pathlib import Path

from cmdscripts.brixcvmfs_live import (
    LiveSkip,
    REPO,
    _build_brixcvmfs,
    _build_mkrepo,
    _checks,
    _fuse3_flags,
    _listing,
    _make_repo,
    _read,
    _repo_env,
    _serve,
    _unmount,
    _wait_mounted,
)
from cmdscripts.live_common import LiveFailure, LiveRun


def _mountinfo_opts(path: Path) -> str | None:
    """Per-mount option string (field 6) for `path`, or None if not mounted."""
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split(" ")
        if len(fields) > 5 and fields[4] == str(path):
            return fields[5]
    return None


def _stat_errno(path: Path) -> int:
    """errno from stat(2) on `path`, 0 on success."""
    try:
        os.stat(path)
        return 0
    except OSError as exc:
        return exc.errno or -1


def _wait_gone(paths: list[Path], timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(_mountinfo_opts(p) is None for p in paths):
            return True
        time.sleep(0.2)
    return all(_mountinfo_opts(p) is None for p in paths)


def _build_umbrella(run: LiveRun) -> Path:
    return _build_brixcvmfs(
        run, no_main_frontends=["client/apps/fs/brixmount.c"], name="brixMount"
    )


def automount(nginx: Path | None = None) -> int:
    """First-access automount end-to-end: ghost listing, symlink-farm child
    mount on first resolution, hardened child options, junk-name rejection,
    clean SIGTERM teardown."""
    _fuse3_flags()
    with LiveRun("brixautofs_live", nginx) as run:
        mkrepo = _build_mkrepo(run)
        brixmount = _build_umbrella(run)
        web, cachebase, mnt = run.mkdir("web"), run.mkdir("cache"), run.mkdir("cvmfs")
        pub = run.root / "repo.pub"
        expect = _make_repo(run, mkrepo, web, pub)
        port = _serve(run, web)

        # etc root: the repo is "configured" via a config.d entry (ghost list);
        # the children resolve server/key/tmp from the inherited env.
        etc = run.mkdir("etc")
        run.write(etc / "config.d" / f"{REPO}.conf", f"# {REPO} test entry\n")
        env = {**_repo_env(run, port, pub), "BRIXMOUNT_BIN": str(brixmount)}

        checks: list[tuple[bool, str]] = []
        repo_link = mnt / REPO                    # symlink served by the umbrella
        repo_farm = cachebase / ".mnt" / REPO     # where the child really mounts
        umbrella = None
        try:
            print("== umbrella up (regular user, idle=0) ==")
            umbrella = run.spawn(
                [brixmount, "autofs", etc, mnt, "-f",
                 "-o", f"idle=0,timeout=30,cachebase={cachebase}"],
                env=env,
            )
            checks.append((_wait_mounted(mnt), "umbrella mounted"))

            print("== ghost listing shows the configured repo without mounting ==")
            ghost = _listing(mnt)
            print(f"   ls: {ghost}")
            checks.append((REPO in ghost, "configured repo ghost-listed"))
            checks.append((os.path.islink(repo_link), "ghost entry is a symlink"))
            checks.append((_mountinfo_opts(repo_farm) is None,
                           "readdir/lstat did not trigger a mount"))

            print("== first path resolution automounts the repo ==")
            got = _read(repo_link / "hello")
            print(f"   got: [{got}]")
            checks.append((got == expect, "content byte-exact through the automount"))
            checks.append((os.readlink(repo_link) == str(repo_farm),
                           "symlink points into the mount farm"))
            opts = _mountinfo_opts(repo_farm) or ""
            print(f"   child mount opts: {opts}")
            checks.append(("nosuid" in opts and "nodev" in opts,
                           "child mount hardened with nosuid,nodev"))

            print("== junk lookup names: fast ENOENT, no child spawned ==")
            start = time.monotonic()
            junk = [".hidden.cern.ch", "atlas", "a;b.cern.ch",
                    "A" * 40 + ".cern.ch", "a" * 255]
            junk_ok = True
            for name in junk:
                rc = _stat_errno(mnt / name)
                if rc != errno.ENOENT or _mountinfo_opts(cachebase / ".mnt" / name) is not None:
                    print(f"FAIL: {name!r} -> errno {rc}")
                    junk_ok = False
            elapsed = time.monotonic() - start
            checks.append((junk_ok, "invalid names all ENOENT with no mount"))
            checks.append((elapsed < 5.0, f"rejection is fast ({elapsed:.2f}s)"))
            spurious = set(os.listdir(cachebase)) - {REPO, ".mnt"}
            checks.append((not spurious, f"no spurious child cache dirs ({spurious or '{}'})"))
            farm_entries = set(os.listdir(cachebase / ".mnt"))
            checks.append((farm_entries == {REPO},
                           f"farm holds only the mounted repo ({farm_entries})"))

            print("== SIGTERM: child and umbrella both unmount ==")
            umbrella.send_signal(signal.SIGTERM)
            checks.append((_wait_gone([repo_farm, mnt]), "both mounts gone after SIGTERM"))
            try:
                umbrella.wait(10)
                exited = True
            except Exception:
                exited = False
            checks.append((exited, "umbrella process exited"))
        finally:
            _unmount(repo_farm)
            _unmount(mnt)
        return _checks(checks)


def automount_strict(nginx: Path | None = None) -> int:
    """CVMFS_STRICT_MOUNT=yes from the config cascade: only CVMFS_REPOSITORIES
    entries mount; a valid-shaped but unlisted repo is refused without a spawn."""
    _fuse3_flags()
    with LiveRun("brixautofs_strict", nginx) as run:
        mkrepo = _build_mkrepo(run)
        brixmount = _build_umbrella(run)
        web, cachebase, mnt = run.mkdir("web"), run.mkdir("cache"), run.mkdir("cvmfs")
        pub = run.root / "repo.pub"
        _make_repo(run, mkrepo, web, pub)   # repo IS servable; only strict blocks it
        port = _serve(run, web)

        # strict mode via the stock cascade file; the mock repo is NOT listed.
        etc = run.mkdir("etc")
        run.write(etc / "default.local",
                  "CVMFS_STRICT_MOUNT=yes\n"
                  "CVMFS_REPOSITORIES=listed.example.org\n")
        env = {**_repo_env(run, port, pub), "BRIXMOUNT_BIN": str(brixmount)}

        checks: list[tuple[bool, str]] = []
        repo_link = mnt / REPO
        repo_farm = cachebase / ".mnt" / REPO
        try:
            run.spawn(
                [brixmount, "autofs", etc, mnt, "-f",
                 "-o", f"idle=0,timeout=30,cachebase={cachebase}"],
                env=env,
            )
            checks.append((_wait_mounted(mnt), "strict umbrella mounted"))

            print("== ghost listing = CVMFS_REPOSITORIES ==")
            ghost = _listing(mnt)
            print(f"   ls: {ghost}")
            checks.append(("listed.example.org" in ghost,
                           "CVMFS_REPOSITORIES entry ghost-listed"))

            print("== unlisted (but valid + servable) repo refused ==")
            start = time.monotonic()
            rc = _stat_errno(repo_link)
            elapsed = time.monotonic() - start
            checks.append((rc == errno.ENOENT, f"unlisted repo -> ENOENT (errno {rc})"))
            checks.append((elapsed < 5.0, f"strict refusal is fast ({elapsed:.2f}s)"))
            checks.append((_mountinfo_opts(repo_farm) is None, "no child mount appeared"))
            checks.append((set(os.listdir(cachebase)) <= {".mnt"}
                           and not os.listdir(cachebase / ".mnt"),
                           "no child cache dir or farm mountpoint created"))
        finally:
            _unmount(repo_farm)
            _unmount(mnt)
        return _checks(checks)


SCENARIOS = {
    "automount": automount,
    "automount-strict": automount_strict,
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
        print(f"brixautofs live scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
