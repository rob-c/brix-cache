"""Phase-96 Wave B — `brixcvmfs repo transaction/abort/publish` (S4–S7).

Drives the standalone repotool through full publish transactions against a
freshly minted repository and verifies the on-disk results independently in
Python (manifest parse, zlib-inflated catalogs via sqlite3, CAS sha1 checks):

  S4  transaction lifecycle: two publishes, crash-safety re-run, lock refusal,
      corrupted-root refusal (fail-closed).
  S5  incremental catalogs: touching one nested subtree rewrites only that
      catalog chain; upper-tree symlinks are recorded, never followed.
  S6  .cvmfsdirtab: split to NESTED_MOUNT, dissolve back, malformed/unsafe
      pattern refusals (line-numbered).
  S7  chunking: split + byte-exact reassembly, floor refusal, per-chunk CAS
      verifiability.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
import zlib
from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT
from cmdscripts.cvmfs_repo_cli import _build_repotool

sys.path.insert(0, str(REPO_ROOT / "tests" / "cvmfs"))
from repo_forge import md5path  # noqa: E402

FQRN = "txn.brix.io"

FLAG_DIR = 1
FLAG_DIR_NESTED_MOUNT = 2
FLAG_FILE = 4
FLAG_LINK = 8
FLAG_FILE_CHUNK = 64


# ---- verification helpers (independent of the C read stack) ----------------

def parse_manifest(repo: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in (repo / ".cvmfspublished").read_bytes().split(b"\n"):
        if line == b"--":
            break
        if line:
            fields[chr(line[0])] = line[1:].decode()
    return fields


def cas_path(repo: Path, hex_: str, suffix: str = "") -> Path:
    return repo / "data" / hex_[:2] / (hex_[2:] + suffix)


def open_catalog(repo: Path, hex_: str, base: Path) -> sqlite3.Connection:
    plain = zlib.decompress(cas_path(repo, hex_, "C").read_bytes())
    db = base / f"peek.{hex_}.db"
    db.write_bytes(plain)
    return sqlite3.connect(db)


def lookup(cat: sqlite3.Connection, path: str):
    m1, m2 = md5path(path)
    return cat.execute(
        "SELECT flags, size, symlink, hash FROM catalog"
        " WHERE md5path_1=? AND md5path_2=?", (m1, m2)).fetchone()


def nested_rows(cat: sqlite3.Connection) -> dict[str, str]:
    return {p: h for p, h in cat.execute("SELECT path, sha1 FROM nested_catalogs")}


def repotool(binary: Path, *args: str, env: dict | None = None):
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run([str(binary), *args], capture_output=True, text=True,
                         env=full_env)


def _mkfs(binary: Path, repo: Path):
    return repotool(binary, "mkfs", FQRN, str(repo))


def _upper(repo: Path) -> Path:
    return repo / ".brixtxn" / "upper"


# ---- S4: transaction lifecycle ---------------------------------------------

def check_s4(binary: Path, base: Path, results: list) -> None:
    repo = base / "s4"
    ck = lambda name, ok, msg="": results.append((bool(ok), f"s4:{name} {msg}".rstrip()))

    ck("mkfs", _mkfs(binary, repo).returncode == 0)
    ck("txn-open", repotool(binary, "transaction", str(repo)).returncode == 0)

    up = _upper(repo)
    (up / "docs").mkdir()
    (up / "docs" / "guide.md").write_bytes(b"guide-v1\n")
    (up / "hello.txt").write_bytes(b"hello world\n")
    os.symlink("hello.txt", up / "link")

    # security: a second transaction must be refused while the lock is live
    second = repotool(binary, "transaction", str(repo))
    ck("second-txn-refused", second.returncode != 0
       and "in a transaction" in second.stderr, second.stderr)

    # crash hook: engine must _exit(66) BEFORE the manifest swap
    crash = repotool(binary, "publish", str(repo), env={"BRIXCVMFS_PUBLISH_CRASH": "1"})
    ck("crash-exit-66", crash.returncode == 66, str(crash.returncode))
    ck("crash-rev-intact", parse_manifest(repo)["S"] == "1")
    ck("crash-txn-survives", up.is_dir())

    # the same transaction re-runs cleanly (CAS puts are idempotent)
    pub = repotool(binary, "publish", str(repo))
    ck("publish-1", pub.returncode == 0, pub.stderr)
    man = parse_manifest(repo)
    ck("rev-2", man["S"] == "2", man["S"])

    cat = open_catalog(repo, man["C"], base)
    row = lookup(cat, "/hello.txt")
    ck("file-row", row is not None and row[0] == FLAG_FILE and row[1] == 12)
    if row is not None:
        stored = cas_path(repo, row[3].hex()).read_bytes()
        ck("file-bytes", zlib.decompress(stored) == b"hello world\n")
        ck("file-cas-id", hashlib.sha1(stored).hexdigest() == row[3].hex())
    link = lookup(cat, "/link")
    ck("link-row", link is not None and link[0] == FLAG_LINK
       and link[2] == "hello.txt")
    ck("dir-row", (lookup(cat, "/docs") or (0,))[0] == FLAG_DIR)
    ck("rev-prop", cat.execute(
        "SELECT value FROM properties WHERE key='revision'").fetchone()[0] == "2")
    cat.close()

    # revision 3: modify one file, whiteout another
    ck("txn-2", repotool(binary, "transaction", str(repo)).returncode == 0)
    (up / "docs").mkdir()
    (up / "docs" / "guide.md").write_bytes(b"guide-v2\n")
    (up / ".brix.wh.hello.txt").write_bytes(b"")
    pub2 = repotool(binary, "publish", str(repo))
    ck("publish-2", pub2.returncode == 0, pub2.stderr)
    man2 = parse_manifest(repo)
    ck("rev-3", man2["S"] == "3", man2["S"])
    cat2 = open_catalog(repo, man2["C"], base)
    ck("deleted-gone", lookup(cat2, "/hello.txt") is None)
    grow = lookup(cat2, "/docs/guide.md")
    ck("modified", grow is not None
       and zlib.decompress(cas_path(repo, grow[3].hex()).read_bytes()) == b"guide-v2\n")
    ck("prev-rev-prop", cat2.execute(
        "SELECT value FROM properties WHERE key='previous_revision'").fetchone()[0]
       == man["C"])
    cat2.close()

    # info (full local trust chain) stays green after real publishes
    info = repotool(binary, "info", str(repo))
    ck("info-green", info.returncode == 0, info.stderr)

    # security: corrupt the live root catalog CAS object → publish refuses
    ck("txn-3", repotool(binary, "transaction", str(repo)).returncode == 0)
    (_upper(repo) / "x.txt").write_bytes(b"x\n")
    victim = cas_path(repo, man2["C"], "C")
    original = victim.read_bytes()
    victim.write_bytes(original[:20] + bytes([original[20] ^ 0xFF]) + original[21:])
    bad = repotool(binary, "publish", str(repo))
    ck("tamper-refused", bad.returncode != 0 and "verification" in bad.stderr,
       bad.stderr)
    ck("tamper-rev-intact", parse_manifest(repo)["S"] == "3")
    victim.write_bytes(original)
    ck("abort", repotool(binary, "abort", str(repo)).returncode == 0)
    ck("abort-clears", not (repo / ".brixtxn").exists())


# ---- S5 + S6: dirtab nesting, incremental rewrite, symlink containment -----

def check_s5_s6(binary: Path, base: Path, results: list) -> None:
    repo = base / "s5"
    ck = lambda name, ok, msg="": results.append((bool(ok), f"s5s6:{name} {msg}".rstrip()))
    dirtab = base / "dirtab"
    dirtab.write_text("/sub\n/other\n")

    ck("mkfs", _mkfs(binary, repo).returncode == 0)
    ck("txn", repotool(binary, "transaction", str(repo)).returncode == 0)
    up = _upper(repo)
    for d in ("sub", "other"):
        (up / d).mkdir()
        (up / d / "data.txt").write_bytes(f"{d}-v1\n".encode())
    pub = repotool(binary, "publish", str(repo), "--dirtab", str(dirtab))
    ck("publish", pub.returncode == 0, pub.stderr)

    man = parse_manifest(repo)
    root = open_catalog(repo, man["C"], base)
    nested = nested_rows(root)
    ck("two-mounts", sorted(nested) == ["/other", "/sub"], str(nested))
    ck("mount-flag", (lookup(root, "/sub") or (0,))[0]
       == FLAG_DIR | FLAG_DIR_NESTED_MOUNT)
    ck("content-in-child", lookup(root, "/sub/data.txt") is None)
    sub = open_catalog(repo, nested["/sub"], base)
    ck("child-row", lookup(sub, "/sub/data.txt") is not None)
    sub.close()
    root.close()

    # S5: touch only /sub → /other's catalog object must be reused untouched
    ck("txn-2", repotool(binary, "transaction", str(repo)).returncode == 0)
    (up / "sub").mkdir()
    (up / "sub" / "data.txt").write_bytes(b"sub-v2\n")
    pub2 = repotool(binary, "publish", str(repo), "--dirtab", str(dirtab))
    ck("publish-2", pub2.returncode == 0, pub2.stderr)
    root2 = open_catalog(repo, parse_manifest(repo)["C"], base)
    nested2 = nested_rows(root2)
    ck("sub-rewritten", nested2["/sub"] != nested["/sub"])
    ck("other-untouched", nested2["/other"] == nested["/other"])
    root2.close()

    # S5 security: upper symlinks (file AND dir targets outside the repo) are
    # recorded as LINK rows — never followed, never ingested
    ck("txn-3", repotool(binary, "transaction", str(repo)).returncode == 0)
    outside = base / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"outside-secret\n")
    os.symlink(outside / "secret.txt", up / "filelink")
    os.symlink(outside, up / "dirlink")
    pub3 = repotool(binary, "publish", str(repo), "--dirtab", str(dirtab))
    ck("publish-3", pub3.returncode == 0, pub3.stderr)
    root3 = open_catalog(repo, parse_manifest(repo)["C"], base)
    for name in ("/filelink", "/dirlink"):
        row = lookup(root3, name)
        ck(f"symlink{name}", row is not None and row[0] == FLAG_LINK)
    ck("dirlink-not-descended", lookup(root3, "/dirlink/secret.txt") is None)
    secret = zlib.compress(b"outside-secret\n")
    ck("target-not-ingested",
       not cas_path(repo, hashlib.sha1(secret).hexdigest()).exists())
    root3.close()

    # S6 dissolve: /sub no longer in the dirtab → re-inlined as a plain dir
    dirtab.write_text("/other\n")
    ck("txn-4", repotool(binary, "transaction", str(repo)).returncode == 0)
    (up / "keep.txt").write_bytes(b"keep\n")
    pub4 = repotool(binary, "publish", str(repo), "--dirtab", str(dirtab))
    ck("publish-4", pub4.returncode == 0, pub4.stderr)
    root4 = open_catalog(repo, parse_manifest(repo)["C"], base)
    ck("dissolved-flag", (lookup(root4, "/sub") or (0,))[0] == FLAG_DIR)
    row = lookup(root4, "/sub/data.txt")
    ck("dissolved-inline", row is not None
       and zlib.decompress(cas_path(repo, row[3].hex()).read_bytes()) == b"sub-v2\n")
    ck("dissolved-nested-gone", "/sub" not in nested_rows(root4))
    ck("other-still-mounted", "/other" in nested_rows(root4))
    root4.close()

    # S6 security: malformed / unsafe dirtab patterns → line-numbered refusal
    for pattern, tag in (("sub\n", "relative"), ("/a/../b\n", "dotdot")):
        bad_tab = base / f"dirtab.{tag}"
        bad_tab.write_text("# comment\n" + pattern)
        ck(f"txn-{tag}", repotool(binary, "transaction", str(repo)).returncode == 0)
        (up / "z.txt").write_bytes(b"z\n")
        bad = repotool(binary, "publish", str(repo), "--dirtab", str(bad_tab))
        ck(f"refused-{tag}", bad.returncode != 0 and "dirtab line 2" in bad.stderr,
           bad.stderr)
        ck(f"abort-{tag}", repotool(binary, "abort", str(repo)).returncode == 0)


# ---- S7: chunking ----------------------------------------------------------

def check_s7(binary: Path, base: Path, results: list) -> None:
    repo = base / "s7"
    ck = lambda name, ok, msg="": results.append((bool(ok), f"s7:{name} {msg}".rstrip()))
    payload = bytes(range(256)) * 40 + b"tail"          # 10244 B → 3 × 4096 chunks

    ck("mkfs", _mkfs(binary, repo).returncode == 0)
    ck("txn", repotool(binary, "transaction", str(repo)).returncode == 0)
    (_upper(repo) / "big.bin").write_bytes(payload)

    # error: --chunk-size below the 4096 floor is refused outright
    low = repotool(binary, "publish", str(repo), "--chunk-size", "1024")
    ck("floor-refused", low.returncode != 0 and "floor" in low.stderr, low.stderr)
    ck("floor-rev-intact", parse_manifest(repo)["S"] == "1")

    pub = repotool(binary, "publish", str(repo), "--chunk-size", "4096")
    ck("publish", pub.returncode == 0, pub.stderr)
    cat = open_catalog(repo, parse_manifest(repo)["C"], base)
    row = lookup(cat, "/big.bin")
    ck("chunk-flags", row is not None
       and row[0] == FLAG_FILE | FLAG_FILE_CHUNK and row[1] == len(payload))
    m1, m2 = md5path("/big.bin")
    chunks = cat.execute(
        "SELECT offset, size, hash FROM chunks WHERE md5path_1=? AND md5path_2=?"
        " ORDER BY offset", (m1, m2)).fetchall()
    cat.close()
    ck("chunk-count", len(chunks) == 3, str(len(chunks)))
    ck("chunk-sizes", [c[1] for c in chunks] == [4096, 4096, 2052])

    # byte-exact reassembly + per-chunk CAS verifiability
    rebuilt = b""
    stored_all = []
    for off, size, h in chunks:
        stored = cas_path(repo, h.hex(), "P").read_bytes()
        stored_all.append((h.hex(), stored))
        ck(f"chunk-cas-{off}", hashlib.sha1(stored).hexdigest() == h.hex())
        plain = zlib.decompress(stored)
        ck(f"chunk-len-{off}", len(plain) == size)
        rebuilt += plain
    ck("reassembly", rebuilt == payload)

    # security: tampering one chunk breaks exactly that chunk's CAS identity
    hex0, stored0 = stored_all[0]
    tampered = stored0[:10] + bytes([stored0[10] ^ 0x55]) + stored0[11:]
    ck("tamper-detected", hashlib.sha1(tampered).hexdigest() != hex0)
    for hexn, storedn in stored_all[1:]:
        ck(f"others-intact-{hexn[:8]}",
           hashlib.sha1(storedn).hexdigest() == hexn)


def run_checks(base: Path) -> list[tuple[bool, str]]:
    binary, err = _build_repotool(base)
    if binary is None:
        return [(False, f"repotool build failed: {err}")]
    results: list[tuple[bool, str]] = []
    check_s4(binary, base, results)
    check_s5_s6(binary, base, results)
    check_s7(binary, base, results)
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    del argv
    with tempfile.TemporaryDirectory(prefix="cvmfs_publish_txn.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
