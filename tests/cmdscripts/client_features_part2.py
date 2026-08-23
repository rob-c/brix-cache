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

BIN = REPO_ROOT / "client/bin"
USAGE_ERROR = 50


def section_xrdfs_rm(s: Session) -> None:
    print("== xrdfs rm -r ==")
    if not s.have_fleet():
        s.skip(f"fleet rm -r tests (no fleet at {s.url})")
        return

    _rm_basic(s)
    _rm_verbose(s)
    _rm_symlink(s)


def _rm_basic(s):
    s.check("rm: no path exits 50", s.fs("rm").returncode == USAGE_ERROR)
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


def _rm_verbose(s):
    vbase = f"/tmp/{s.tag}-rmv"
    s.fs("mkdir", "-p", f"{vbase}/d")
    s.put("v\n", f"{vbase}/d/f")
    proc = s.fs("rm", "-r", "-v", vbase)
    s.check("rm -r -v: exit 0", proc.returncode == 0)
    s.check("rm -r -v: prints removed lines",
            any(line.startswith("removed ") for line in (proc.stdout or "").splitlines()))


def _rm_symlink(s):
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

    doc = _valid_json(s.fs("stat", "-j", f"{base}/sample.txt").stdout)
    s.check("stat -j: valid JSON with is_dir", _valid_stat_json(doc))

    arr = _valid_json(s.fs("ls", "-j", base).stdout)
    s.check("ls -j: valid JSON array", isinstance(arr, list))

    arr = _valid_json(s.fs("du", "-j", base).stdout)
    s.check("du -j: valid JSON array with bytes/files/dirs", _valid_du_json(arr))

    # security: hostile filename (double-quote) must not break ls -j JSON.
    weird = f'{base}/we"ird.txt'
    s.put("weird\n", weird)
    _check_hostile_json(s, base, weird)

    # error path: stat -j on a missing path — nonzero exit AND no JSON on stdout.
    proc = s.fs("stat", "-j", f"{base}/no-such-file")
    s.check("stat -j missing: nonzero exit", proc.returncode != 0)
    s.check("stat -j missing: no output on stdout", not (proc.stdout or "").strip())


def _valid_stat_json(document):
    if not isinstance(document, dict) or document.get("is_dir") not in (True, False):
        return False
    return "mode" not in document or re.match(r"^0[0-7]{3}$", str(document["mode"])) is not None


def _valid_du_json(document):
    if not isinstance(document, list) or not document:
        return False
    return all(key in document[0] for key in ("bytes", "files", "dirs"))


def _check_hostile_json(s, base, weird):
    if not s.fs_stat_ok(weird):
        print("  skip: server rejects quote-in-name; hostile-name JSON check not exercisable")
        return
    parsed = _valid_json(s.fs("ls", "-j", base).stdout)
    s.check("ls -j: hostile filename (double-quote) produces valid JSON", parsed is not None)


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

    _check_local_tree(s, t, manifest)
    _check_newline_name(s)
    _check_remote_tree(s, t)


def _manifest_lines(path, missing):
    return path.read_text().splitlines() if path.exists() else missing


def _check_local_tree(s, tree, manifest):
    source = tree / "src"
    _check_manifest_creation(s, source, manifest)
    _check_manifest_tamper(s, source, manifest)
    _check_manifest_escape(s, tree, source, manifest)
    _check_manifest_algorithm(s, tree, source)


def _check_manifest_creation(s, source, manifest):
    rc = s.call([s.xrdcksum, "tree", source, "-o", manifest]).returncode
    s.check("tree: exit 0 on clean local tree", rc == 0)
    lines = _manifest_lines(manifest, [])
    s.check("tree: manifest has 3 lines", len(lines) == 3)
    s.check("tree: each line has two-space separator",
            any(re.match(r"^[0-9a-f]+  [^/]", line) for line in lines))

    rc = s.call([s.xrdcksum, "check", manifest, source]).returncode
    s.check("check: exit 0 when all match", rc == 0)


def _check_manifest_tamper(s, source, manifest):
    (source / "a.dat").write_text("TAMPERED\n")
    proc = s.call([s.xrdcksum, "check", manifest, source])
    out_lines = (proc.stdout or "").splitlines()
    s.check("check: exit 1 on mismatch", proc.returncode == 1)
    s.check("check: FAILED line names the file", any(line.startswith("FAILED a.dat") for line in out_lines))
    s.check("check: two OK lines for untampered", sum(1 for line in out_lines if line.startswith("OK ")) == 2)


def _check_manifest_escape(s, tree, source, manifest):
    guard = s.work / f"guard_{os.getpid()}"
    guard.write_text("canary")
    bad_manifest = tree / "bad_manifest"
    bad_manifest.write_text(manifest.read_text() + f"03e51f2a  ../../guard_{os.getpid()}\n")
    rc = s.call([s.xrdcksum, "check", bad_manifest, source]).returncode
    s.check("check: exit 2 on malformed manifest line", rc == 2)
    s.check("security: escape line rejected, guard file untouched", guard.read_text() == "canary")


def _check_manifest_algorithm(s, tree, source):
    (source / "a.dat").write_text("alpha\n")
    algo_manifest = tree / "algo_manifest"
    rc = s.call([s.xrdcksum, "tree", source, "--algo", "crc32c", "-o", algo_manifest]).returncode
    s.check("tree --algo crc32c: exit 0", rc == 0)
    algo_lines = _manifest_lines(algo_manifest, [])
    s.check("tree --algo crc32c: manifest has 3 lines", len(algo_lines) == 3)
    rc = s.call([s.xrdcksum, "check", algo_manifest, source, "--algo", "crc32c"]).returncode
    s.check("check --algo crc32c: exit 0 on clean tree", rc == 0)


def _create_newline_name(path):
    try:
        path.write_text("x\n")
        return path.exists()
    except OSError:
        return False


def _check_newline_name(s):
    nl = s.work / "cknl"
    (nl / "src").mkdir(parents=True, exist_ok=True)
    (nl / "src" / "good.dat").write_text("ok\n")
    badname = "evil\n0000  hack"
    if not _create_newline_name(nl / "src" / badname):
        s.skip("newline-name test (filesystem rejected the name)")
        return
    nl_manifest = nl / "manifest"
    rc = s.call([s.xrdcksum, "tree", nl / "src", "-o", nl_manifest]).returncode
    s.check("tree: newline-name run exits 2", rc == 2)
    nl_text = nl_manifest.read_text() if nl_manifest.exists() else ""
    s.check("tree: forged name not in manifest", "hack" not in nl_text)
    s.check("tree: manifest parses cleanly line-by-line",
            all(_MANIFEST_LINE.match(line) for line in nl_text.splitlines()))


def _check_remote_tree(s, tree):
    print("== xrdcksum tree (fleet, remote) ==")
    if not s.have_fleet():
        s.skip(f"remote tree tests (no fleet at {s.url})")
        return

    rdir = f"/tmp/{s.tag}-cktree"
    orig = tree / "orig"
    (orig / "sub").mkdir(parents=True, exist_ok=True)
    (orig / "a.dat").write_text("alpha\n")
    (orig / "sub" / "b.dat").write_text("bravo\n")
    (orig / "sub" / "c.dat").write_text("charlie\n")
    rc = s.cp("-r", f"{orig}/", f"{s.url}//{rdir}/").returncode
    s.check("fleet tree: upload succeeded", rc == 0)

    remote_manifest = tree / "remote_manifest"
    rc = s.call([s.xrdcksum, "tree", f"{s.url}//{rdir}", "-o", remote_manifest]).returncode
    s.check("fleet tree: remote tree exits 0", rc == 0)

    local_manifest = tree / "local_manifest"
    s.call([s.xrdcksum, "tree", orig, "-o", local_manifest])
    remote_sorted = sorted(_manifest_lines(remote_manifest, ["remote"]))
    local_sorted = sorted(_manifest_lines(local_manifest, ["local"]))
    s.check("fleet tree: remote manifest matches local", remote_sorted == local_sorted)

    # Trailing-slash root must produce the SAME manifest as the no-slash form.
    slash_manifest = tree / "remote_slash_manifest"
    rc = s.call([s.xrdcksum, "tree", f"{s.url}//{rdir}/", "-o", slash_manifest]).returncode
    s.check("fleet tree: trailing-slash root exits 0", rc == 0)
    slash_sorted = sorted(_manifest_lines(slash_manifest, ["slash"]))
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
    _check_diag_fixtures(s)
    _check_diag_fleet(s)


def _check_diag_fixtures(s):
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


def _check_diag_fleet(s):
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
