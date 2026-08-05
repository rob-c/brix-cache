"""Phase-96 Wave D — `brixcvmfs repo gc` + `brixcvmfs repo tag` (S10–S12).

Drives the standalone repotool through revision history, garbage collection
and tag/rollback flows, verifying every on-disk result independently in
Python (reflog sqlite, manifest fields, CAS reachability walks):

  S10 reflog: N publishes → N catalog refs; missing reflog → gc refused
      ("reflog required"); checksum mismatch → gc refused, nothing swept.
  S11 gc: 5 revisions keep 2 → EXACTLY the unreachable objects vanish and
      kept revisions stay fully fetchable; refused during a transaction;
      mark-skip mutation (BRIX_CVMFS_GC_MUTATION) proves the guard has teeth;
      tag-pinned revisions are never swept.
  S12 tags: tag → rollback republishes the tagged tree at a NEW revision;
      unknown tag refused; history-object tamper → CAS mismatch → refused.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from pathlib import Path

from cmdscripts.cvmfs_repo_cli import _build_repotool
from cmdscripts.cvmfs_publish_txn import (
    cas_path, open_catalog, parse_manifest, repotool, _upper)

FQRN = "admin.brix.io"


# ---- helpers ----------------------------------------------------------------

def publish_rev(binary: Path, repo: Path, files: dict[str, bytes],
                *extra: str) -> tuple[int, str]:
    rc = repotool(binary, "transaction", str(repo))
    if rc.returncode != 0:
        return rc.returncode, rc.stderr
    for rel, content in files.items():
        target = _upper(repo) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    rc = repotool(binary, "publish", str(repo), *extra)
    return rc.returncode, rc.stderr


def reflog_catalogs(repo: Path) -> list[str]:
    """Catalog refs, newest first (the exact order gc's keep-N uses)."""
    with sqlite3.connect(repo / ".cvmfsreflog") as db:
        return [h for (h,) in db.execute(
            "SELECT hash FROM refs WHERE type=0"
            " ORDER BY timestamp DESC, rowid DESC")]


def reflog_noncatalog(repo: Path) -> set[str]:
    suffix = {1: "X", 2: "H", 3: "M"}
    with sqlite3.connect(repo / ".cvmfsreflog") as db:
        return {h + suffix[t] for h, t in db.execute(
            "SELECT hash, type FROM refs WHERE type!=0")}


def cas_names(repo: Path) -> set[str]:
    """Every CAS object currently on disk as '<40hex><suffix>' names."""
    return {f.parent.name + f.name
            for f in (repo / "data").glob("*/*") if f.is_file()}


def reachable(repo: Path, root_hex: str, base: Path) -> set[str]:
    """All CAS names reachable from a root catalog (the Python mark oracle)."""
    out: set[str] = set()
    stack = [root_hex]
    while stack:
        h = stack.pop()
        if h + "C" in out:
            continue
        out.add(h + "C")
        cat = open_catalog(repo, h, base)
        for (blob,) in cat.execute(
                "SELECT hash FROM catalog WHERE hash IS NOT NULL"):
            out.add(bytes(blob).hex())
        for (blob,) in cat.execute("SELECT hash FROM chunks"):
            out.add(bytes(blob).hex() + "P")
        for (sha,) in cat.execute("SELECT sha1 FROM nested_catalogs"):
            stack.append(sha)
        cat.close()
    return out


def catalog_rows(repo: Path, root_hex: str, base: Path) -> list[tuple]:
    """Content rows of a root catalog — the tree-identity fingerprint."""
    cat = open_catalog(repo, root_hex, base)
    rows = cat.execute(
        "SELECT md5path_1, md5path_2, hash, size, flags, name, symlink"
        " FROM catalog ORDER BY md5path_1, md5path_2").fetchall()
    cat.close()
    return rows


def build_history(binary: Path, base: Path, name: str,
                  revisions: int = 5) -> tuple[Path | None, str]:
    """Fresh repo with `revisions` publishes; each rewrites shared.txt (making
    the previous copy unreachable) and adds a chunked + a plain file."""
    repo = base / name
    rc = repotool(binary, "mkfs", FQRN, str(repo))
    if rc.returncode != 0:
        return None, rc.stderr
    for i in range(1, revisions + 1):
        code, err = publish_rev(binary, repo, {
            "shared.txt": f"shared-payload-rev-{i}\n".encode() * 64,
            f"plain{i}.txt": f"plain-{i}\n".encode(),
            f"big{i}.bin": bytes([i]) * 12000,
        }, "--chunk-size", "4096")
        if code != 0:
            return None, err
    return repo, ""


# ---- S10 + S11: gc ----------------------------------------------------------

def check_gc_success(binary: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"gc:{name} {msg}".rstrip()))
    repo, err = build_history(binary, base, "gc-ok")
    ck("build", repo is not None, err)
    if repo is None:
        return

    cats = reflog_catalogs(repo)
    ck("s10-reflog-count", len(cats) == 6, f"{len(cats)} refs")  # mkfs + 5
    man = parse_manifest(repo)
    ck("s10-newest-is-root", cats[0] == man["C"])
    ck("s10-manifest-Y", man.get("Y") == hashlib.sha1(
        (repo / ".cvmfsreflog").read_bytes()).hexdigest())

    before = cas_names(repo)
    expected_mark = (reachable(repo, cats[0], base)
                     | reachable(repo, cats[1], base)
                     | reflog_noncatalog(repo)
                     | {man["X"] + "X"})
    gc = repotool(binary, "gc", str(repo), "--keep", "2", "--grace", "0")
    ck("run", gc.returncode == 0, gc.stderr)

    after = cas_names(repo)
    ck("exact-sweep", after == before & expected_mark,
       f"unexpected {sorted(after ^ (before & expected_mark))[:4]}")
    ck("kept-fetchable", expected_mark & before <= after)
    ck("reflog-pruned", reflog_catalogs(repo) == cats[:2])
    ck("manifest-Y-refreshed", parse_manifest(repo)["Y"] == hashlib.sha1(
        (repo / ".cvmfsreflog").read_bytes()).hexdigest())
    ck("fsck-clean", repotool(binary, "fsck", str(repo)).returncode == 0)


def check_gc_refusals(binary: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"gc:{name} {msg}".rstrip()))
    repo, err = build_history(binary, base, "gc-refuse", revisions=2)
    ck("build", repo is not None, err)
    if repo is None:
        return

    # error: refused while a transaction holds the lock
    assert repotool(binary, "transaction", str(repo)).returncode == 0
    gc = repotool(binary, "gc", str(repo), "--keep", "1")
    ck("txn-refused", gc.returncode != 0 and "gc refused" in gc.stderr, gc.stderr)
    assert repotool(binary, "abort", str(repo)).returncode == 0

    # error: no retention spec at all
    gc = repotool(binary, "gc", str(repo))
    ck("no-spec-refused", gc.returncode != 0, gc.stderr)

    # S10 error: reflog missing → "reflog required"
    before = cas_names(repo)
    reflog = (repo / ".cvmfsreflog").read_bytes()
    (repo / ".cvmfsreflog").unlink()
    gc = repotool(binary, "gc", str(repo), "--keep", "1", "--grace", "0")
    ck("missing-reflog-refused",
       gc.returncode != 0 and "reflog required" in gc.stderr, gc.stderr)
    ck("missing-reflog-no-sweep", cas_names(repo) == before)

    # S10 security-neg: checksum mismatch vs manifest 'Y' → refuse, no sweep
    tampered = bytearray(reflog)
    tampered[600] ^= 0x01
    (repo / ".cvmfsreflog").write_bytes(bytes(tampered))
    gc = repotool(binary, "gc", str(repo), "--keep", "1", "--grace", "0")
    ck("tamper-refused",
       gc.returncode != 0 and "checksum mismatch" in gc.stderr, gc.stderr)
    ck("tamper-no-sweep", cas_names(repo) == before)
    (repo / ".cvmfsreflog").write_bytes(reflog)


def check_gc_mutation_guard(binary: Path, base: Path, results: list) -> None:
    """Security-neg: prove the 'kept objects survive' guard has teeth — with
    the mark phase sabotaged (chunk marking skipped), kept-revision chunks
    MUST vanish; without sabotage they MUST survive."""
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"gc:mutation-{name} {msg}".rstrip()))
    repo, err = build_history(binary, base, "gc-mut", revisions=3)
    ck("build", repo is not None, err)
    if repo is None:
        return
    twin = base / "gc-mut-twin"
    shutil.copytree(repo, twin)

    chunks = {n for n in cas_names(repo) if n.endswith("P")}
    ck("has-chunks", len(chunks) > 0, f"{len(chunks)}")

    ok = repotool(binary, "gc", str(repo), "--keep", "3", "--grace", "0")
    ck("clean-run", ok.returncode == 0, ok.stderr)
    ck("clean-chunks-survive", chunks <= cas_names(repo))

    bad = repotool(binary, "gc", str(twin), "--keep", "3", "--grace", "0",
                   env={"BRIX_CVMFS_GC_MUTATION": "skip-chunk-mark"})
    ck("sabotaged-run", bad.returncode == 0, bad.stderr)
    ck("guard-catches-sabotage", not (chunks & cas_names(twin)),
       "chunks survived a skipped mark phase — guard is toothless")


def check_gc_tag_pinning(binary: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"gc:pin-{name} {msg}".rstrip()))
    repo, err = build_history(binary, base, "gc-pin", revisions=3)
    ck("build", repo is not None, err)
    if repo is None:
        return
    pinned_root = parse_manifest(repo)["C"]
    ck("tag", repotool(binary, "tag", "add", str(repo), "pinned").returncode == 0)
    for i in (7, 8, 9):
        code, err = publish_rev(binary, repo, {f"late{i}.txt": b"x" * 100})
        assert code == 0, err
    gc = repotool(binary, "gc", str(repo), "--keep", "1", "--grace", "0")
    ck("run", gc.returncode == 0, gc.stderr)
    ck("pinned-survives", (cas_path(repo, pinned_root, "C")).exists())
    rb = repotool(binary, "tag", "rollback", str(repo), "pinned")
    ck("rollback-after-gc", rb.returncode == 0, rb.stderr)
    ck("fsck-clean", repotool(binary, "fsck", str(repo)).returncode == 0)


# ---- S12: tags --------------------------------------------------------------

def check_tag_success(binary: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"tag:{name} {msg}".rstrip()))
    repo, err = build_history(binary, base, "tag-ok", revisions=2)
    ck("build", repo is not None, err)
    if repo is None:
        return

    tagged_man = parse_manifest(repo)
    add = repotool(binary, "tag", "add", str(repo), "good", "-m", "known good")
    ck("add", add.returncode == 0, add.stderr)
    lst = repotool(binary, "tag", "list", str(repo))
    ck("list", lst.returncode == 0 and "good" in lst.stdout
       and tagged_man["C"] in lst.stdout, lst.stdout)
    ck("manifest-H", "H" in parse_manifest(repo))

    code, err = publish_rev(binary, repo, {"bad.txt": b"regression\n"})
    ck("later-publish", code == 0, err)

    rb = repotool(binary, "tag", "rollback", str(repo), "good")
    ck("rollback", rb.returncode == 0, rb.stderr)
    man = parse_manifest(repo)
    ck("revision-never-rewinds",
       int(man["S"]) == int(tagged_man["S"]) + 2, man["S"])
    ck("new-root-object", man["C"] != tagged_man["C"])
    ck("tree-matches-tagged",
       catalog_rows(repo, man["C"], base)
       == catalog_rows(repo, tagged_man["C"], base))
    ck("catalog-revision-consistent", any(
        v == man["S"] for (v,) in open_catalog(repo, man["C"], base).execute(
            "SELECT value FROM properties WHERE key='revision'")))
    ck("fsck-clean", repotool(binary, "fsck", str(repo)).returncode == 0)


def check_tag_refusals(binary: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"tag:{name} {msg}".rstrip()))
    repo, err = build_history(binary, base, "tag-refuse", revisions=1)
    ck("build", repo is not None, err)
    if repo is None:
        return

    # error: rollback to a tag that does not exist
    assert repotool(binary, "tag", "add", str(repo), "real").returncode == 0
    rb = repotool(binary, "tag", "rollback", str(repo), "nosuch")
    ck("unknown-refused",
       rb.returncode != 0 and "unknown tag" in rb.stderr, rb.stderr)

    # security-neg: history object tamper → CAS hash mismatch → refused
    hist = cas_path(repo, parse_manifest(repo)["H"], "H")
    original = hist.read_bytes()
    tampered = bytearray(original)
    tampered[20] ^= 0x01
    hist.write_bytes(bytes(tampered))
    for verb in (("tag", "list"), ("tag", "rollback")):
        args = (*verb, str(repo)) + (("real",) if verb[1] == "rollback" else ())
        r = repotool(binary, *args)
        ck(f"tamper-{verb[1]}-refused",
           r.returncode != 0 and "CAS verification" in r.stderr, r.stderr)
    hist.write_bytes(original)
    ck("restore-works",
       repotool(binary, "tag", "rollback", str(repo), "real").returncode == 0)


# ---- entry ------------------------------------------------------------------

def run_gc_checks(base: Path) -> list[tuple[bool, str]]:
    binary, err = _build_repotool(base)
    if binary is None:
        return [(False, f"repotool build failed: {err}")]
    results: list[tuple[bool, str]] = []
    check_gc_success(binary, base, results)
    check_gc_refusals(binary, base, results)
    check_gc_mutation_guard(binary, base, results)
    check_gc_tag_pinning(binary, base, results)
    return results


def run_tag_checks(base: Path) -> list[tuple[bool, str]]:
    binary, err = _build_repotool(base)
    if binary is None:
        return [(False, f"repotool build failed: {err}")]
    results: list[tuple[bool, str]] = []
    check_tag_success(binary, base, results)
    check_tag_refusals(binary, base, results)
    return results
