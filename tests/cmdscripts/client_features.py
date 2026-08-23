"""Direct Python port of tests/run_client_features.sh.

E2e checks for the 2026-07-05 client feature set, driven through the repo's own
client binaries (client/bin/xrdcp, xrdfs, xrdcksum, xrddiag). Local-only checks
always run; fleet checks auto-skip when no server answers on
${XRD_TEST_URL:-root://localhost:11094} (probed via wait41-brix, like the shell
`have_fleet`).

Routing note (inherited): brix_copy -r requires one remote + one local endpoint;
local->local recursive is rejected. Dry-run on a single non-recursive file works
local->local because transfer_one short-circuits before calling brix_copy. All
recursive filter tests are therefore fleet-gated.
"""

from __future__ import annotations

import argparse
import calendar
import json
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import time

from cmdscripts.compile_run import REPO_ROOT
from cmdscripts.live_common import LiveRun
from settings import NGINX_ANON_PORT, SERVER_HOST

def _phase_section_mirror_delete_1(s, rdst_rel, rdst2_rel, rdst3_rel):
    for rel in (f"/tmp/{s.tag}-mdsrc", rdst_rel, rdst2_rel, rdst3_rel):
        s.rm_remote(rel, recursive=True)

def _phase_section_journal_2(j):
    for name, text in (("a.txt", "alpha\n"), ("b.txt", "bravo\n"), ("c.txt", "charlie\n")):
        (j / "src" / name).write_text(text)


def _proc_output(proc):
    return (
        (proc.stdout or "") + (proc.stderr or "")
    )

def _expression_2(proc):
    return (
        (proc.stdout or "") + (proc.stderr or "")
    )

def _expression_3(proc):
    return (
        (proc.stdout or "") + (proc.stderr or "")
    )

def _expression_4(s, dl_out):
    return (
        s.check("--remove-source download: local dst has content",
                    dl_out.exists() and dl_out.read_text() == "download-move\n")
    )

def _expression_5(proc):
    return (
        (proc.stdout or "") + (proc.stderr or "")
    )


BIN = REPO_ROOT / "client/bin"
USAGE_ERROR = 50


class Session:
    """One client-features run: temp workspace, client tools, results ledger."""

    def __init__(self, run: LiveRun, url: str | None = None) -> None:
        self.run = run
        self.work = run.root
        self.url = url or os.environ.get(
            "XRD_TEST_URL", f"root://{SERVER_HOST}:{NGINX_ANON_PORT}")
        self.xrdcp = BIN / "xrdcp"
        self.xrdfs = BIN / "xrdfs"
        self.xrdcksum = BIN / "xrdcksum"
        self.xrddiag = BIN / "xrddiag"
        self.tag = f"cfeat-{os.getpid()}-{random.randrange(32768)}"
        self.results: list[tuple[bool, str]] = []
        self._fleet: bool | None = None

    # -- results -----------------------------------------------------------
    def check(self, label: str, ok: bool) -> bool:
        print(f"  {'ok' if ok else 'FAIL'}: {label}")
        self.results.append((bool(ok), label))
        return bool(ok)

    def skip(self, message: str) -> None:
        print(f"  SKIP {message}")

    # -- command helpers -----------------------------------------------------
    def call(self, argv: list, *, input: str | bytes | None = None) -> subprocess.CompletedProcess:
        return self.run.call(argv, input=input, check=False)

    def cp(self, *args, input: str | bytes | None = None) -> subprocess.CompletedProcess:
        return self.call([self.xrdcp, *args], input=input)

    def fs(self, *args, input: str | bytes | None = None) -> subprocess.CompletedProcess:
        return self.call([self.xrdfs, self.url, *args], input=input)

    def fs_stat_ok(self, path: str) -> bool:
        return self.fs("stat", path).returncode == 0

    def put(self, text: str, remote_path: str) -> subprocess.CompletedProcess:
        """`printf text | xrdcp - URL//remote_path`."""
        return self.cp("-", f"{self.url}//{remote_path}", input=text)

    def have_fleet(self) -> bool:
        if self._fleet is None:
            wait41 = BIN / "wait41-brix"
            proc = self.call([wait41, self.url]) if wait41.exists() else None
            self._fleet = bool(proc and proc.returncode == 0)
        return self._fleet

    def rm_remote(self, path: str, recursive: bool = False) -> None:
        args = ["rm", "-r", path] if recursive else ["rm", path]
        self.fs(*args)


def _touch(path: Path, date: str) -> None:
    """`touch -d 'YYYY-MM-DD HH:MM:SS'` equivalent (UTC-stable)."""
    stamp = calendar.timegm(time.strptime(date, "%Y-%m-%d %H:%M:%S"))
    os.utime(path, (stamp, stamp))


def _seed_src_tree(base: Path) -> Path:
    """The shared src tree (a.root, b.log, sub/c.root) used by several sections."""
    src = base / "src"
    (src / "sub").mkdir(parents=True, exist_ok=True)
    (src / "a.root").write_text("A\n")
    (src / "b.log").write_text("B\n")
    (src / "sub" / "c.root").write_text("C\n")
    (base / "dst").mkdir(exist_ok=True)
    return src


# --------------------------------------------------------------------------- #
def section_dryrun_filters(s: Session) -> None:
    print("== dry-run (local) ==")
    src = _seed_src_tree(s.work)
    dst = s.work / "dst"

    s.cp("--dry-run", src / "a.root", dst / "a.root")
    s.check("dry-run leaves dst absent", not (dst / "a.root").exists())

    print("== recursive filters (fleet) ==")
    if not s.have_fleet():
        s.skip(f"recursive filter tests (no fleet at {s.url})")
        return

    rsrc = f"{s.url}//tmp/{s.tag}-src"
    s.cp("-r", "-s", "-f", f"{src}/", f"{rsrc}/")

    dst_excl = s.work / "dst_excl"
    dst_excl.mkdir()
    s.cp("-r", "-s", "--exclude", "*.log", f"{rsrc}/", dst_excl)
    s.check("exclude: .root copied",
            (dst_excl / "a.root").exists() and (dst_excl / "sub/c.root").exists())
    s.check("exclude: .log filtered", not (dst_excl / "b.log").exists())

    dst_incl = s.work / "dst_incl"
    dst_incl.mkdir()
    s.cp("-r", "-s", "--include", "*.log", f"{rsrc}/", dst_incl)
    s.check("include: only .log copied",
            (dst_incl / "b.log").exists() and not (dst_incl / "a.root").exists())

    # security: exclude beats include — a.* excluded even though * is included.
    dst_both = s.work / "dst_both"
    dst_both.mkdir()
    s.cp("-r", "-s", "--include", "*", "--exclude", "a.*", f"{rsrc}/", dst_both)
    s.check("exclude beats include",
            not (dst_both / "a.root").exists() and (dst_both / "b.log").exists())

    # dry-run upload (root://) — must not create the remote directory.
    dryup = f"/tmp/{s.tag}-dryup"
    s.cp("-r", "-s", "--dry-run", f"{src}/", f"{s.url}//{dryup}/")
    s.check("dry-run upload: remote dir not created", not s.fs_stat_ok(dryup))

    s.rm_remote(f"/tmp/{s.tag}-src", recursive=True)
    s.rm_remote(f"/tmp/{s.tag}-dryup", recursive=True)


# --------------------------------------------------------------------------- #
def section_sync_modes(s: Session) -> None:
    print("== sync modes (local) ==")
    sd = s.work / "sync"
    sd.mkdir(exist_ok=True)
    src, stale = sd / "src", sd / "stale"
    src.write_text("AAAA\n")
    stale.write_text("BBBB\n")

    s.cp("--sync", src, stale)
    s.check("--sync (size): same-size stale dst skipped", stale.read_text() == "BBBB\n")

    out = s.cp("--sync-check", "cksum", "--dry-run", src, stale).stdout
    s.check("--sync-check cksum: stale dst recopied (gate opens)", "[dry-run] copy" in out)

    same = sd / "same"
    same.write_bytes(src.read_bytes())
    out = s.cp("--sync-check", "cksum", "--dry-run", src, same).stdout
    s.check("--sync-check cksum: identical dst skipped", "[dry-run] copy" not in out)

    _touch(stale, "2020-01-01 00:00:00")
    out = s.cp("--sync-check", "mtime", "--dry-run", src, stale).stdout
    s.check("--sync-check mtime: newer src recopied", "[dry-run] copy" in out)

    _touch(stale, "2030-01-01 00:00:00")
    out = s.cp("--sync-check", "mtime", "--dry-run", src, stale).stdout
    s.check("--sync-check mtime: newer dst skipped", "[dry-run] copy" not in out)

    rc = s.cp("--sync-check", "bogus", src, stale).returncode
    s.check("--sync-check bogus exits 50", rc == USAGE_ERROR)

    print("== sync modes (fleet) ==")
    if not s.have_fleet():
        s.skip(f"fleet sync tests (no fleet at {s.url})")
        return

    rs = f"/tmp/{s.tag}-sync"
    s.cp("-s", "-f", src, f"{s.url}/{rs}")
    dl = sd / "dl"
    dl.write_text("BBBB\n")

    s.cp("-s", "--sync", f"{s.url}/{rs}", dl)
    s.check("fleet --sync (size): stale local dst kept", dl.read_text() == "BBBB\n")

    s.cp("-s", "--sync-check", "cksum", f"{s.url}/{rs}", dl)
    s.check("fleet --sync-check cksum: stale dst recopied", dl.read_text() == "AAAA\n")

    # Recursive download honors --sync-check cksum via the walker.
    rt = f"/tmp/{s.tag}-synctree"
    tree = sd / "tree"
    tree.mkdir(exist_ok=True)
    (tree / "f").write_text("AAAA\n")
    s.cp("-r", "-s", "-f", f"{tree}/", f"{s.url}/{rt}/")
    outdir = sd / "out"
    outdir.mkdir(exist_ok=True)
    (outdir / "f").write_text("BBBB\n")
    s.cp("-r", "-s", "--sync", f"{s.url}/{rt}/", outdir)
    s.check("fleet -r --sync (size): stale tree file kept", (outdir / "f").read_text() == "BBBB\n")
    s.cp("-r", "-s", "--sync-check", "cksum", f"{s.url}/{rt}/", outdir)
    s.check("fleet -r --sync-check cksum: stale tree file recopied", (outdir / "f").read_text() == "AAAA\n")

    s.rm_remote(rs)
    s.rm_remote(rt, recursive=True)


# --------------------------------------------------------------------------- #
def _mirror_delete_usage(s, src, dst):
    rc = s.cp("-r", "--delete", f"{src}/", f"{dst}/").returncode
    s.check("--delete without --sync exits 50", rc == USAGE_ERROR)

    rc = s.cp("--sync", "--delete", src / "a.root", f"{dst}/").returncode
    s.check("--delete without -r exits 50", rc == USAGE_ERROR)

    # --delete (mirror) and --remove-source (move) are contradictory.
    rc = s.cp("-r", "--sync", "--delete", "--remove-source", f"{src}/", f"{dst}/").returncode
    s.check("--delete + --remove-source exits 50", rc == USAGE_ERROR)


def section_mirror_delete(s: Session) -> None:
    print("== mirror delete (--delete) ==")
    src = _seed_src_tree(s.work)
    dst = s.work / "dst"
    _mirror_delete_usage(s, src, dst)

    print("== mirror delete (fleet) ==")
    if not s.have_fleet():
        s.skip(f"fleet mirror-delete tests (no fleet at {s.url})")
        return

    rsrc = f"{s.url}//tmp/{s.tag}-mdsrc"
    s.cp("-r", "-s", "-f", f"{src}/", f"{rsrc}/")

    # Upload direction: extra file must disappear; seeded files survive.
    rdst_rel = f"/tmp/{s.tag}-mddst"
    rdst = f"{s.url}/{rdst_rel}"
    s.cp("-s", src / "a.root", f"{rdst}/a.root")
    s.cp("-s", src / "b.log", f"{rdst}/b.log")
    s.cp("-s", src / "a.root", f"{rdst}/extra.root")
    s.cp("-r", "-s", "--sync", "--delete", f"{src}/", f"{rdst}/")
    s.check("--delete upload: synced file survives", s.fs_stat_ok(f"{rdst_rel}/a.root"))
    s.check("--delete upload: extra removed", not s.fs_stat_ok(f"{rdst_rel}/extra.root"))

    # Security: excluded extra must NOT be deleted (outside the sync scope).
    rdst2_rel = f"/tmp/{s.tag}-mddst2"
    rdst2 = f"{s.url}/{rdst2_rel}"
    s.cp("-s", src / "a.root", f"{rdst2}/a.root")
    s.cp("-s", src / "a.root", f"{rdst2}/keep.dat")
    s.cp("-r", "-s", "--sync", "--delete", "--exclude", "keep.dat", f"{src}/", f"{rdst2}/")
    s.check("--delete upload: excluded extra survives", s.fs_stat_ok(f"{rdst2_rel}/keep.dat"))

    # --dry-run --delete: the extra file must still be present after the run.
    rdst3_rel = f"/tmp/{s.tag}-mddst3"
    rdst3 = f"{s.url}/{rdst3_rel}"
    s.cp("-s", src / "a.root", f"{rdst3}/a.root")
    s.cp("-s", src / "a.root", f"{rdst3}/phantom.root")
    dry_out = s.cp("-r", "-s", "--sync", "--delete", "--dry-run", f"{src}/", f"{rdst3}/").stdout
    s.check("--dry-run --delete: prints delete line", "[dry-run] delete" in dry_out)
    s.check("--dry-run --delete: phantom file unchanged", s.fs_stat_ok(f"{rdst3_rel}/phantom.root"))

    _phase_section_mirror_delete_1(s, rdst_rel, rdst2_rel, rdst3_rel)


# --------------------------------------------------------------------------- #
def section_remove_source(s: Session) -> None:
    print("== --remove-source ==")
    rs = s.work / "rs"
    rs.mkdir(exist_ok=True)

    # Security: web/S3 source + --remove-source must exit 50.
    rc = s.cp("--remove-source", "s3://bucket/obj", f"{rs}/").returncode
    s.check("--remove-source s3:// exits 50", rc == USAGE_ERROR)
    rc = s.cp("--remove-source", "https://example.com/f", f"{rs}/").returncode
    s.check("--remove-source https:// exits 50", rc == USAGE_ERROR)

    (rs / "dry.txt").write_text("dry-run test\n")
    out = s.cp("--dry-run", "--remove-source", rs / "dry.txt", rs / "dry_out.txt").stdout
    s.check("--dry-run --remove-source: src intact", (rs / "dry.txt").exists())
    s.check("--dry-run --remove-source: prints (then remove source)", "(then remove source)" in out)

    print("== --remove-source (fleet) ==")
    if not s.have_fleet():
        s.skip(f"fleet --remove-source tests (no fleet at {s.url})")
        return

    rsbase = f"/tmp/{s.tag}-rs"

    # Upload move: local source gone, remote destination present.
    (rs / "up.txt").write_text("upload-move\n")
    s.cp("-s", "--remove-source", rs / "up.txt", f"{s.url}//{rsbase}/up.txt")
    s.check("--remove-source upload: local src removed", not (rs / "up.txt").exists())
    s.check("--remove-source upload: remote dst exists", s.fs_stat_ok(f"{rsbase}/up.txt"))

    # Download move: remote source gone, local destination byte-exact.
    (rs / "dl_seed.txt").write_text("download-move\n")
    s.cp("-s", "-f", rs / "dl_seed.txt", f"{s.url}//{rsbase}/dl.txt")
    s.cp("-s", "--remove-source", f"{s.url}//{rsbase}/dl.txt", rs / "dl_out.txt")
    dl_out = rs / "dl_out.txt"
    _expression_4(s, dl_out)
    s.check("--remove-source download: remote src removed", not s.fs_stat_ok(f"{rsbase}/dl.txt"))

    # Recursive move: local tree gone, remote files exist, no spurious warning.
    rmvtree = rs / "rmv-tree"
    (rmvtree / "sub").mkdir(parents=True, exist_ok=True)
    (rmvtree / "f1.txt").write_text("file-1\n")
    (rmvtree / "f2.txt").write_text("file-2\n")
    (rmvtree / "sub" / "f_sub.txt").write_text("file-sub\n")
    proc = s.cp("-r", "-s", "--remove-source", f"{rmvtree}/", f"{s.url}//{rsbase}/rmvtree/")
    rmverr = _expression_5(proc)
    s.check("-r --remove-source: local tree removed", not rmvtree.is_dir())
    s.check("-r --remove-source: remote file 1 exists", s.fs_stat_ok(f"{rsbase}/rmvtree/f1.txt"))
    s.check("-r --remove-source: no spurious warning", "could not remove source" not in rmverr)

    s.rm_remote(rsbase, recursive=True)


# --------------------------------------------------------------------------- #
def _journal_ok_count(journal):
    if not journal.exists():
        return 0
    return sum(1 for line in journal.read_text().splitlines()
               if line.startswith("ok "))


def section_journal(s: Session) -> None:
    print("== --journal / --resume ==")
    j = s.work / "jrn"
    (j / "src").mkdir(parents=True, exist_ok=True)

    # (d) --resume without --from must exit 50 — always local, no fleet needed.
    rc = s.cp("--resume", j / "src" / "a.txt", f"{j}/src/").returncode
    s.check("journal (d): --resume without --from exits 50", rc == USAGE_ERROR)

    print("== --journal / --resume (fleet) ==")
    if not s.have_fleet():
        s.skip(f"journal fleet tests (no fleet at {s.url})")
        return

    jbase = f"/tmp/{s.tag}-jrn"
    rdst = f"{s.url}/{jbase}"
    s.fs("mkdir", jbase)

    _phase_section_journal_2(j)
    manifest = j / "manifest.txt"
    journal = j / "j.journal"
    manifest.write_text("".join(f"{j}/src/{n}\n" for n in ("a.txt", "b.txt", "c.txt")))

    # (a) first run: 3 files copied, journal written with 3 "ok " lines.
    proc = s.cp("--from", manifest, "--journal", journal, f"{rdst}/")
    out = _proc_output(proc)
    s.check("journal (a): 3 copied, 0 skipped", "3 copied, 0 skipped, 0 failed" in out)
    ok_lines = _journal_ok_count(journal)
    s.check("journal (a): journal has 3 ok lines", ok_lines == 3)

    # (b) add 4th file; rerun with the same journal -> 1 copied, 3 skipped.
    (j / "src" / "d.txt").write_text("delta\n")
    manifest.write_text("".join(f"{j}/src/{n}\n" for n in ("a.txt", "b.txt", "c.txt", "d.txt")))
    proc = s.cp("--from", manifest, "--journal", journal, f"{rdst}/")
    out = _expression_2(proc)
    s.check("journal (b): 1 copied, 3 skipped", "1 copied, 3 skipped, 0 failed" in out)
    s.check("journal (b): d.txt was uploaded", s.fs_stat_ok(f"{jbase}/d.txt"))

    # (c) hostile/malformed journal line must be silently ignored (never crash).
    journal.write_text("garbage-not-an-ok-line\n" + journal.read_text())
    proc = s.cp("--from", manifest, "--journal", journal, f"{rdst}/")
    out = _expression_3(proc)
    s.check("journal (c): 0 copied, 4 skipped (corrupt line tolerated)",
            "0 copied, 4 skipped, 0 failed" in out)

    s.rm_remote(jbase, recursive=True)


# --------------------------------------------------------------------------- #

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "client_features_part2.py",
                    "client_features_part3.py")
