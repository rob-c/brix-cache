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
from settings import SERVER_HOST

BIN = REPO_ROOT / "client/bin"
USAGE_ERROR = 50


class Session:
    """One client-features run: temp workspace, client tools, results ledger."""

    def __init__(self, run: LiveRun, url: str | None = None) -> None:
        self.run = run
        self.work = run.root
        self.url = url or os.environ.get("XRD_TEST_URL", f"root://{SERVER_HOST}:11094")
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
def section_mirror_delete(s: Session) -> None:
    print("== mirror delete (--delete) ==")
    src = _seed_src_tree(s.work)
    dst = s.work / "dst"

    rc = s.cp("-r", "--delete", f"{src}/", f"{dst}/").returncode
    s.check("--delete without --sync exits 50", rc == USAGE_ERROR)

    rc = s.cp("--sync", "--delete", src / "a.root", f"{dst}/").returncode
    s.check("--delete without -r exits 50", rc == USAGE_ERROR)

    # --delete (mirror) and --remove-source (move) are contradictory.
    rc = s.cp("-r", "--sync", "--delete", "--remove-source", f"{src}/", f"{dst}/").returncode
    s.check("--delete + --remove-source exits 50", rc == USAGE_ERROR)

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

    for rel in (f"/tmp/{s.tag}-mdsrc", rdst_rel, rdst2_rel, rdst3_rel):
        s.rm_remote(rel, recursive=True)


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
    s.check("--remove-source download: local dst has content",
            dl_out.exists() and dl_out.read_text() == "download-move\n")
    s.check("--remove-source download: remote src removed", not s.fs_stat_ok(f"{rsbase}/dl.txt"))

    # Recursive move: local tree gone, remote files exist, no spurious warning.
    rmvtree = rs / "rmv-tree"
    (rmvtree / "sub").mkdir(parents=True, exist_ok=True)
    (rmvtree / "f1.txt").write_text("file-1\n")
    (rmvtree / "f2.txt").write_text("file-2\n")
    (rmvtree / "sub" / "f_sub.txt").write_text("file-sub\n")
    proc = s.cp("-r", "-s", "--remove-source", f"{rmvtree}/", f"{s.url}//{rsbase}/rmvtree/")
    rmverr = (proc.stdout or "") + (proc.stderr or "")
    s.check("-r --remove-source: local tree removed", not rmvtree.is_dir())
    s.check("-r --remove-source: remote file 1 exists", s.fs_stat_ok(f"{rsbase}/rmvtree/f1.txt"))
    s.check("-r --remove-source: no spurious warning", "could not remove source" not in rmverr)

    s.rm_remote(rsbase, recursive=True)


# --------------------------------------------------------------------------- #
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

    for name, text in (("a.txt", "alpha\n"), ("b.txt", "bravo\n"), ("c.txt", "charlie\n")):
        (j / "src" / name).write_text(text)
    manifest = j / "manifest.txt"
    journal = j / "j.journal"
    manifest.write_text("".join(f"{j}/src/{n}\n" for n in ("a.txt", "b.txt", "c.txt")))

    # (a) first run: 3 files copied, journal written with 3 "ok " lines.
    proc = s.cp("--from", manifest, "--journal", journal, f"{rdst}/")
    out = (proc.stdout or "") + (proc.stderr or "")
    s.check("journal (a): 3 copied, 0 skipped", "3 copied, 0 skipped, 0 failed" in out)
    ok_lines = sum(1 for line in journal.read_text().splitlines() if line.startswith("ok ")) if journal.exists() else 0
    s.check("journal (a): journal has 3 ok lines", ok_lines == 3)

    # (b) add 4th file; rerun with the same journal -> 1 copied, 3 skipped.
    (j / "src" / "d.txt").write_text("delta\n")
    manifest.write_text("".join(f"{j}/src/{n}\n" for n in ("a.txt", "b.txt", "c.txt", "d.txt")))
    proc = s.cp("--from", manifest, "--journal", journal, f"{rdst}/")
    out = (proc.stdout or "") + (proc.stderr or "")
    s.check("journal (b): 1 copied, 3 skipped", "1 copied, 3 skipped, 0 failed" in out)
    s.check("journal (b): d.txt was uploaded", s.fs_stat_ok(f"{jbase}/d.txt"))

    # (c) hostile/malformed journal line must be silently ignored (never crash).
    journal.write_text("garbage-not-an-ok-line\n" + journal.read_text())
    proc = s.cp("--from", manifest, "--journal", journal, f"{rdst}/")
    out = (proc.stdout or "") + (proc.stderr or "")
    s.check("journal (c): 0 copied, 4 skipped (corrupt line tolerated)",
            "0 copied, 4 skipped, 0 failed" in out)

    s.rm_remote(jbase, recursive=True)


# --------------------------------------------------------------------------- #
def section_xrdfs_rm(s: Session) -> None:
    print("== xrdfs rm -r ==")
    if not s.have_fleet():
        s.skip(f"fleet rm -r tests (no fleet at {s.url})")
        return

    # xrdfs one-shot connects before dispatch — exit-50 validation needs a live server.
    s.check("rm: no path exits 50", s.fs("rm").returncode == USAGE_ERROR)
    # Security: rm -r / must exit 50 (export root guard).
    s.check("rm -r /: exits 50 (export root guard)", s.fs("rm", "-r", "/").returncode == USAGE_ERROR)

    base = f"/tmp/{s.tag}-rm"
    s.fs("mkdir", "-p", f"{base}/sub")
    s.put("hello\n", f"{base}/a")
    s.put("world\n", f"{base}/sub/b")

    s.check("rm -r tree: exit 0", s.fs("rm", "-r", base).returncode == 0)
    s.check("rm -r tree: root is gone", not s.fs_stat_ok(base))

    s.check("rm -r /: fleet live, still exits 50", s.fs("rm", "-r", "/").returncode == USAGE_ERROR)
    s.check("rm -r /: root still accessible", s.fs_stat_ok("/"))

    s.check("rm -r missing: nonzero", s.fs("rm", "-r", f"/tmp/{s.tag}-rm-no-such").returncode != 0)

    fbase = f"/tmp/{s.tag}-rmf"
    s.put("data\n", fbase)
    s.check("rm -r plain file: exit 0", s.fs("rm", "-r", fbase).returncode == 0)
    s.check("rm -r plain file: gone", not s.fs_stat_ok(fbase))

    vbase = f"/tmp/{s.tag}-rmv"
    s.fs("mkdir", "-p", f"{vbase}/d")
    s.put("v\n", f"{vbase}/d/f")
    proc = s.fs("rm", "-r", "-v", vbase)
    s.check("rm -r -v: exit 0", proc.returncode == 0)
    s.check("rm -r -v: prints removed lines",
            any(line.startswith("removed ") for line in (proc.stdout or "").splitlines()))

    # Symlink guard: rm -r must remove the LINK, not the target's contents.
    sbase = f"/tmp/{s.tag}-rmsym"
    sa, sd = f"{sbase}/A", f"{sbase}/D"
    s.fs("mkdir", "-p", sa)
    s.fs("mkdir", "-p", sd)
    s.put("precious\n", f"{sa}/file.txt")
    link = s.fs("ln", "-s", sa, f"{sd}/B")
    if link.returncode == 0:
        s.check("rm -r dir-with-symlink: exit 0", s.fs("rm", "-r", sd).returncode == 0)
        s.check("rm -r dir-with-symlink: D gone", not s.fs_stat_ok(sd))
        s.check("rm -r dir-with-symlink: A/file.txt intact", s.fs_stat_ok(f"{sa}/file.txt"))
        s.rm_remote(sa, recursive=True)
    else:
        detail = (link.stdout or "") + (link.stderr or "")
        s.skip(f"symlink rm test (server does not support ln -s: {detail.strip()})")
    s.rm_remote(sbase, recursive=True)


# --------------------------------------------------------------------------- #
def _valid_json(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def section_xrdfs_json(s: Session) -> None:
    print("== xrdfs --json (fleet) ==")
    if not s.have_fleet():
        s.skip(f"xrdfs json tests (no fleet at {s.url})")
        return

    base = f"/tmp/{s.tag}-json"
    s.fs("mkdir", "-p", base)
    s.put("hello\n", f"{base}/sample.txt")

    # stat -j: valid JSON with is_dir key (and octal mode when present).
    doc = _valid_json(s.fs("stat", "-j", f"{base}/sample.txt").stdout)
    ok = (isinstance(doc, dict) and doc.get("is_dir") in (True, False)
          and ("mode" not in doc or re.match(r"^0[0-7]{3}$", str(doc["mode"])) is not None))
    s.check("stat -j: valid JSON with is_dir", ok)

    arr = _valid_json(s.fs("ls", "-j", base).stdout)
    s.check("ls -j: valid JSON array", isinstance(arr, list))

    arr = _valid_json(s.fs("du", "-j", base).stdout)
    ok = (isinstance(arr, list) and len(arr) > 0
          and all(key in arr[0] for key in ("bytes", "files", "dirs")))
    s.check("du -j: valid JSON array with bytes/files/dirs", ok)

    # security: hostile filename (double-quote) must not break ls -j JSON.
    weird = f'{base}/we"ird.txt'
    s.put("weird\n", weird)
    if s.fs_stat_ok(weird):
        parsed = _valid_json(s.fs("ls", "-j", base).stdout)
        s.check("ls -j: hostile filename (double-quote) produces valid JSON", parsed is not None)
    else:
        print("  skip: server rejects quote-in-name; hostile-name JSON check not exercisable")

    # error path: stat -j on a missing path — nonzero exit AND no JSON on stdout.
    proc = s.fs("stat", "-j", f"{base}/no-such-file")
    s.check("stat -j missing: nonzero exit", proc.returncode != 0)
    s.check("stat -j missing: no output on stdout", not (proc.stdout or "").strip())


# --------------------------------------------------------------------------- #
def _spawn_tail(s: Session, seconds: int, path: str, cap: Path, err: Path) -> subprocess.Popen:
    """`timeout N xrdfs URL tail -f path > cap 2> err` (exit 124 on timeout)."""
    return subprocess.Popen(
        ["timeout", str(seconds), str(s.xrdfs), s.url, "tail", "-f", path],
        stdout=cap.open("wb"), stderr=err.open("wb"),
    )


def section_tail_follow(s: Session) -> None:
    print("== tail -f (follow mode) ==")
    if not s.have_fleet():
        s.skip(f"tail -f tests (no fleet at {s.url})")
        return

    base = f"/tmp/{s.tag}-tailf"
    cap, err = s.work / "tailf.cap", s.work / "tailf.err"

    # success: initial content + appended bytes reach stdout.
    s.put("line1\nline2\n", base)
    follower = _spawn_tail(s, 5, base, cap, err)
    time.sleep(1)
    s.cp("-f", "-", f"{s.url}//{base}", input="line1\nline2\nline3_appended\n")
    follower.wait()
    s.check("tail -f: appended line appears in output",
            cap.exists() and b"line3_appended" in cap.read_bytes())

    # error: missing path exits nonzero quickly (before the timeout).
    proc = s.run.call(["timeout", "3", s.xrdfs, s.url, "tail", "-f", f"{base}-missing"], check=False)
    s.check("tail -f missing: fast nonzero exit", proc.returncode not in (0, 124))

    # truncation resilience: stderr notice + process outlives the truncation.
    cap2, err2 = s.work / "tailf2.cap", s.work / "tailf2.err"
    s.cp("-f", "-", f"{s.url}//{base}", input="aaa\nbbb\nccc\n")
    follower = _spawn_tail(s, 5, base, cap2, err2)
    time.sleep(1)
    s.cp("-f", "-", f"{s.url}//{base}", input="x\n")
    rc = follower.wait()
    s.check("tail -f truncation: stderr notice", err2.exists() and b"truncated" in err2.read_bytes())
    s.check("tail -f truncation: process ran to timeout (exit 124)", rc == 124)

    s.rm_remote(base)


# --------------------------------------------------------------------------- #
def section_cat_compress(s: Session) -> None:
    print("== cat -z (codec validation) ==")
    if not s.have_fleet():
        s.skip(f"cat -z tests (no fleet at {s.url})")
        return

    # Security: codec with injection chars must exit 50.
    rc = s.fs("cat", "-z", "gz&evil=1", "/some/path").returncode
    s.check("cat -z bad codec: exits 50", rc == USAGE_ERROR)

    fpath = f"/tmp/{s.tag}-catz"
    s.put("hello compress\n", fpath)

    # Transparency contract: cat -z gzip must produce the same bytes as cat.
    plain = s.fs("cat", fpath).stdout
    compressed = s.fs("cat", "-z", "gzip", fpath).stdout
    s.check("cat -z gzip: byte-identical to plain cat", plain == compressed)

    rc = s.fs("cat", "-z", "gzip", f"/tmp/{s.tag}-catz-nosuchfile").returncode
    s.check("cat -z gzip missing: nonzero exit", rc != 0)

    s.rm_remote(fpath)


# --------------------------------------------------------------------------- #
_MANIFEST_LINE = re.compile(r"^[0-9a-f]+  ")


def section_cksum_tree(s: Session) -> None:
    print("== xrdcksum tree + check (local) ==")
    t = s.work / "ckst"
    (t / "src" / "sub").mkdir(parents=True, exist_ok=True)
    (t / "out").mkdir(exist_ok=True)
    (t / "src" / "a.dat").write_text("alpha\n")
    (t / "src" / "sub" / "b.dat").write_text("bravo\n")
    (t / "src" / "sub" / "c.dat").write_text("charlie\n")
    manifest = t / "manifest"

    rc = s.call([s.xrdcksum, "tree", t / "src", "-o", manifest]).returncode
    s.check("tree: exit 0 on clean local tree", rc == 0)
    lines = manifest.read_text().splitlines() if manifest.exists() else []
    s.check("tree: manifest has 3 lines", len(lines) == 3)
    s.check("tree: each line has two-space separator",
            any(re.match(r"^[0-9a-f]+  [^/]", line) for line in lines))

    rc = s.call([s.xrdcksum, "check", manifest, t / "src"]).returncode
    s.check("check: exit 0 when all match", rc == 0)

    # tamper one file -> exit 1 and FAILED names the rel path.
    (t / "src" / "a.dat").write_text("TAMPERED\n")
    proc = s.call([s.xrdcksum, "check", manifest, t / "src"])
    out_lines = (proc.stdout or "").splitlines()
    s.check("check: exit 1 on mismatch", proc.returncode == 1)
    s.check("check: FAILED line names the file", any(line.startswith("FAILED a.dat") for line in out_lines))
    s.check("check: two OK lines for untampered", sum(1 for line in out_lines if line.startswith("OK ")) == 2)

    # security-negative: escaping rel path -> malformed, exit 2, guard untouched.
    guard = s.work / f"guard_{os.getpid()}"
    guard.write_text("canary")
    bad_manifest = t / "bad_manifest"
    bad_manifest.write_text(manifest.read_text() + f"03e51f2a  ../../guard_{os.getpid()}\n")
    rc = s.call([s.xrdcksum, "check", bad_manifest, t / "src"]).returncode
    s.check("check: exit 2 on malformed manifest line", rc == 2)
    s.check("security: escape line rejected, guard file untouched", guard.read_text() == "canary")

    # e2e --algo: generate manifest with crc32c, verify with same algo.
    (t / "src" / "a.dat").write_text("alpha\n")
    algo_manifest = t / "algo_manifest"
    rc = s.call([s.xrdcksum, "tree", t / "src", "--algo", "crc32c", "-o", algo_manifest]).returncode
    s.check("tree --algo crc32c: exit 0", rc == 0)
    algo_lines = algo_manifest.read_text().splitlines() if algo_manifest.exists() else []
    s.check("tree --algo crc32c: manifest has 3 lines", len(algo_lines) == 3)
    rc = s.call([s.xrdcksum, "check", algo_manifest, t / "src", "--algo", "crc32c"]).returncode
    s.check("check --algo crc32c: exit 0 on clean tree", rc == 0)

    # security-negative: newline-embedding filename must be skipped, not forged.
    nl = s.work / "cknl"
    (nl / "src").mkdir(parents=True, exist_ok=True)
    (nl / "src" / "good.dat").write_text("ok\n")
    badname = "evil\n0000  hack"
    created = False
    try:
        (nl / "src" / badname).write_text("x\n")
        created = (nl / "src" / badname).exists()
    except OSError:
        created = False
    if created:
        nl_manifest = nl / "manifest"
        rc = s.call([s.xrdcksum, "tree", nl / "src", "-o", nl_manifest]).returncode
        s.check("tree: newline-name run exits 2", rc == 2)
        nl_text = nl_manifest.read_text() if nl_manifest.exists() else ""
        s.check("tree: forged name not in manifest", "hack" not in nl_text)
        s.check("tree: manifest parses cleanly line-by-line",
                all(_MANIFEST_LINE.match(line) for line in nl_text.splitlines()))
    else:
        s.skip("newline-name test (filesystem rejected the name)")

    print("== xrdcksum tree (fleet, remote) ==")
    if not s.have_fleet():
        s.skip(f"remote tree tests (no fleet at {s.url})")
        return

    rdir = f"/tmp/{s.tag}-cktree"
    orig = t / "orig"
    (orig / "sub").mkdir(parents=True, exist_ok=True)
    (orig / "a.dat").write_text("alpha\n")
    (orig / "sub" / "b.dat").write_text("bravo\n")
    (orig / "sub" / "c.dat").write_text("charlie\n")
    rc = s.cp("-r", f"{orig}/", f"{s.url}//{rdir}/").returncode
    s.check("fleet tree: upload succeeded", rc == 0)

    remote_manifest = t / "remote_manifest"
    rc = s.call([s.xrdcksum, "tree", f"{s.url}//{rdir}", "-o", remote_manifest]).returncode
    s.check("fleet tree: remote tree exits 0", rc == 0)

    local_manifest = t / "local_manifest"
    s.call([s.xrdcksum, "tree", orig, "-o", local_manifest])
    remote_sorted = sorted(remote_manifest.read_text().splitlines()) if remote_manifest.exists() else ["remote"]
    local_sorted = sorted(local_manifest.read_text().splitlines()) if local_manifest.exists() else ["local"]
    s.check("fleet tree: remote manifest matches local", remote_sorted == local_sorted)

    # Trailing-slash root must produce the SAME manifest as the no-slash form.
    slash_manifest = t / "remote_slash_manifest"
    rc = s.call([s.xrdcksum, "tree", f"{s.url}//{rdir}/", "-o", slash_manifest]).returncode
    s.check("fleet tree: trailing-slash root exits 0", rc == 0)
    slash_sorted = sorted(slash_manifest.read_text().splitlines()) if slash_manifest.exists() else ["slash"]
    s.check("fleet tree: trailing slash == no slash", slash_sorted == remote_sorted)

    s.rm_remote(rdir, recursive=True)


# --------------------------------------------------------------------------- #
def _write_fixture(path: Path, *, m_record: bool = True, f_record: bytes | None = None,
                   raw_tail: bytes = b"") -> None:
    """Build an .xrdcap capture fixture (layout from capture.c)."""
    blob = b"XRDCAP1\n"
    if m_record:
        key, value = b"tool", b"fixture"
        blob += b"M" + bytes([len(key)]) + key + struct.pack(">H", len(value)) + value
    if f_record is not None:
        blob += f_record
    blob += raw_tail
    path.write_bytes(blob)


def section_diag_json(s: Session) -> None:
    print("== xrddiag --json ==")

    # Replay fixture tests (no fleet needed: pure file decode).
    fix = s.work / "fix.xrdcap"
    wire = bytes(24)  # one zeroed 24-byte request header
    _write_fixture(fix, f_record=b"F" + b">" + b"\x01" + struct.pack(">HHI", 1, 3000, len(wire)) + wire)
    rc = s.call([s.xrddiag, "replay", fix]).returncode
    s.check("replay: valid fixture decodes (exit 0)", rc == 0)

    # Truncated F record: dir + isreq + 1 byte of the 2-byte sid.
    trunc = s.work / "trunc.xrdcap"
    _write_fixture(trunc, m_record=False, raw_tail=b"F" + b">" + b"\x01" + b"\x00")
    rc = s.call([s.xrddiag, "replay", trunc]).returncode
    s.check("replay: truncated fixture exits nonzero", rc != 0)

    # M-record truncation: klen claims more key bytes than remain.
    mtrunc = s.work / "mtrunc.xrdcap"
    _write_fixture(mtrunc, m_record=False, raw_tail=b"M" + bytes([16]) + b"key")
    rc = s.call([s.xrddiag, "replay", mtrunc]).returncode
    s.check("replay: M-record-truncated fixture exits nonzero", rc != 0)

    # check --json with unreachable endpoint (no fleet needed).
    proc = s.call([s.xrddiag, "check", "--json", f"root://{SERVER_HOST}:1"])
    s.check("check --json unreachable: nonzero exit", proc.returncode != 0)
    s.check("check --json unreachable: no stdout on error", not (proc.stdout or "").strip())

    print("== xrddiag --json (fleet) ==")
    if not s.have_fleet():
        s.skip(f"xrddiag fleet JSON tests (no fleet at {s.url})")
        return

    doc = _valid_json(s.call([s.xrddiag, "check", "--json", s.url]).stdout)
    s.check("check --json fleet: valid JSON", doc is not None)
    s.check("check --json fleet: has connect_ok field", isinstance(doc, dict) and "connect_ok" in doc)

    arr = _valid_json(s.call([s.xrddiag, "topology", "--json", s.url]).stdout)
    s.check("topology --json fleet: valid JSON array", isinstance(arr, list))
    s.check("topology --json fleet: element 0 has node field",
            isinstance(arr, list) and (not arr or "node" in arr[0]))


# --------------------------------------------------------------------------- #
def section_xrdfs_uring(s: Session) -> None:
    print("== xrdfs download/upload --io-uring (fleet) ==")
    if not s.have_fleet():
        s.skip(f"xrdfs uring tests (no fleet at {s.url})")
        return

    tag = f"cfeat-uring-{os.getpid()}"
    seed = s.work / "uring_seed.dat"
    seed.write_text("xrdfs-uring-test-data-1234567890\n")
    s.fs("upload", seed, f"/tmp/{tag}")

    dl_off = s.work / "dl_off.dat"
    rc = s.fs("download", "--io-uring", "off", f"/tmp/{tag}", dl_off).returncode
    s.check("download --io-uring off: exit 0", rc == 0)
    s.check("download --io-uring off: byte-exact",
            dl_off.exists() and dl_off.read_bytes() == seed.read_bytes())

    dl_auto = s.work / "dl_auto.dat"
    rc = s.fs("download", "--io-uring", "auto", f"/tmp/{tag}", dl_auto).returncode
    s.check("download --io-uring auto: exit 0", rc == 0)
    s.check("download --io-uring auto: byte-exact",
            dl_off.exists() and dl_auto.exists() and dl_auto.read_bytes() == dl_off.read_bytes())

    rc = s.fs("download", "--io-uring", "bogus", f"/tmp/{tag}", s.work / "dl_bogus.dat").returncode
    s.check("download --io-uring bogus: exits 50", rc == USAGE_ERROR)

    # --io-uring on: either succeeds byte-exact, or fails cleanly with no
    # partial/corrupt output file left at the final path.
    dl_on = s.work / "dl_on.dat"
    if dl_on.exists():
        dl_on.unlink()
    on_rc = s.fs("download", "--io-uring", "on", f"/tmp/{tag}", dl_on).returncode
    if on_rc == 0:
        s.check("download --io-uring on: success -> byte-exact",
                dl_on.exists() and dl_on.read_bytes() == seed.read_bytes())
    else:
        s.check("download --io-uring on: clean fail -> no partial output", not dl_on.exists())

    rc = s.fs("upload", "--io-uring", "off", seed, f"/tmp/{tag}-up").returncode
    s.check("upload --io-uring off: exit 0", rc == 0)
    up_rt = s.work / "up_rt.dat"
    s.fs("download", f"/tmp/{tag}-up", up_rt)
    s.check("upload --io-uring off: round-trip byte-exact",
            up_rt.exists() and up_rt.read_bytes() == seed.read_bytes())

    s.rm_remote(f"/tmp/{tag}")
    s.rm_remote(f"/tmp/{tag}-up")


# --------------------------------------------------------------------------- #
SECTIONS = {
    "dryrun-filters": section_dryrun_filters,
    "sync-modes": section_sync_modes,
    "mirror-delete": section_mirror_delete,
    "remove-source": section_remove_source,
    "journal": section_journal,
    "xrdfs-rm": section_xrdfs_rm,
    "xrdfs-json": section_xrdfs_json,
    "tail-follow": section_tail_follow,
    "cat-compress": section_cat_compress,
    "cksum-tree": section_cksum_tree,
    "diag-json": section_diag_json,
    "xrdfs-uring": section_xrdfs_uring,
}


def missing_binaries() -> list[str]:
    return [str(BIN / name) for name in ("xrdcp", "xrdfs", "xrdcksum", "xrddiag")
            if not (BIN / name).exists()]


def run_sections(names: list[str], url: str | None = None) -> int:
    missing = missing_binaries()
    if missing:
        print(f"SKIP: client binaries missing: {', '.join(missing)}")
        return 0
    with LiveRun("client-features") as run:
        session = Session(run, url)
        for name in names:
            SECTIONS[name](session)
        passed = sum(1 for ok, _ in session.results if ok)
        failed = len(session.results) - passed
        print(f"client-features: {passed} pass, {failed} fail")
        for ok, label in session.results:
            if not ok:
                print(f"  FAIL: {label}")
        return 0 if failed == 0 else 1


def _scenario(name: str):
    return lambda url=None: run_sections([name], url)


SCENARIOS = {name: _scenario(name) for name in SECTIONS}
SCENARIOS["all"] = lambda url=None: run_sections(list(SECTIONS), url)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", nargs="?", default="all", choices=SCENARIOS)
    parser.add_argument("--url", default=None, help="fleet endpoint (default $XRD_TEST_URL or root://localhost:11094)")  # net-literal-allow: argparse help text describing default endpoint
    ns = parser.parse_args(argv)
    return SCENARIOS[ns.scenario](ns.url)


if __name__ == "__main__":
    raise SystemExit(main())
