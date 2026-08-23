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
    cats, manifest = _check_gc_reflog(repo, base, ck)
    _check_gc_sweep(binary, repo, base, cats, manifest, ck)


def _check_gc_reflog(repo, base, check):
    catalogs = reflog_catalogs(repo)
    check("s10-reflog-count", len(catalogs) == 6, f"{len(catalogs)} refs")
    manifest = parse_manifest(repo)
    check("s10-newest-is-root", catalogs[0] == manifest["C"])
    digest = hashlib.sha1((repo / ".cvmfsreflog").read_bytes()).hexdigest()
    check("s10-manifest-Y", manifest.get("Y") == digest)
    return catalogs, manifest


def _check_gc_sweep(binary, repo, base, catalogs, manifest, check):
    before = cas_names(repo)
    expected_mark = (reachable(repo, catalogs[0], base)
                     | reachable(repo, catalogs[1], base)
                     | reflog_noncatalog(repo)
                     | {manifest["X"] + "X"})
    gc = repotool(binary, "gc", str(repo), "--keep", "2", "--grace", "0")
    check("run", gc.returncode == 0, gc.stderr)
    after = cas_names(repo)
    expected = before & expected_mark
    check("exact-sweep", after == expected,
          f"unexpected {sorted(after ^ expected)[:4]}")
    check("kept-fetchable", expected_mark & before <= after)
    check("reflog-pruned", reflog_catalogs(repo) == catalogs[:2])
    digest = hashlib.sha1((repo / ".cvmfsreflog").read_bytes()).hexdigest()
    check("manifest-Y-refreshed", parse_manifest(repo)["Y"] == digest)
    check("fsck-clean", repotool(binary, "fsck", str(repo)).returncode == 0)


def check_gc_refusals(binary: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"gc:{name} {msg}".rstrip()))
    repo, err = build_history(binary, base, "gc-refuse", revisions=2)
    ck("build", repo is not None, err)
    if repo is None:
        return
    _check_gc_basic_refusals(binary, repo, ck)
    before, reflog = _check_missing_reflog(binary, repo, ck)
    _check_tampered_reflog(binary, repo, before, reflog, ck)


def _check_gc_basic_refusals(binary, repo, check):
    assert repotool(binary, "transaction", str(repo)).returncode == 0
    gc = repotool(binary, "gc", str(repo), "--keep", "1")
    check("txn-refused", gc.returncode != 0 and "gc refused" in gc.stderr, gc.stderr)
    assert repotool(binary, "abort", str(repo)).returncode == 0
    gc = repotool(binary, "gc", str(repo))
    check("no-spec-refused", gc.returncode != 0, gc.stderr)


def _check_missing_reflog(binary, repo, check):
    before = cas_names(repo)
    reflog = (repo / ".cvmfsreflog").read_bytes()
    (repo / ".cvmfsreflog").unlink()
    gc = repotool(binary, "gc", str(repo), "--keep", "1", "--grace", "0")
    check("missing-reflog-refused",
          gc.returncode != 0 and "reflog required" in gc.stderr, gc.stderr)
    check("missing-reflog-no-sweep", cas_names(repo) == before)
    return before, reflog


def _check_tampered_reflog(binary, repo, before, reflog, check):
    tampered = bytearray(reflog)
    tampered[600] ^= 0x01
    (repo / ".cvmfsreflog").write_bytes(bytes(tampered))
    gc = repotool(binary, "gc", str(repo), "--keep", "1", "--grace", "0")
    check("tamper-refused",
          gc.returncode != 0 and "checksum mismatch" in gc.stderr, gc.stderr)
    check("tamper-no-sweep", cas_names(repo) == before)
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
    _check_clean_gc(binary, repo, chunks, ck)
    _check_sabotaged_gc(binary, twin, chunks, ck)


def _check_clean_gc(binary, repo, chunks, check):
    result = repotool(binary, "gc", str(repo), "--keep", "3", "--grace", "0")
    check("clean-run", result.returncode == 0, result.stderr)
    check("clean-chunks-survive", chunks <= cas_names(repo))


def _check_sabotaged_gc(binary, twin, chunks, check):
    result = repotool(binary, "gc", str(twin), "--keep", "3", "--grace", "0",
                      env={"BRIX_CVMFS_GC_MUTATION": "skip-chunk-mark"})
    check("sabotaged-run", result.returncode == 0, result.stderr)
    check("guard-catches-sabotage", not chunks & cas_names(twin),
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
    _check_tag_add_list(binary, repo, tagged_man, ck)
    _check_tag_rollback(binary, repo, base, tagged_man, ck)


def _check_tag_add_list(binary, repo, tagged_manifest, check):
    add = repotool(binary, "tag", "add", str(repo), "good", "-m", "known good")
    check("add", add.returncode == 0, add.stderr)
    lst = repotool(binary, "tag", "list", str(repo))
    listed = lst.returncode == 0 and "good" in lst.stdout
    check("list", listed and tagged_manifest["C"] in lst.stdout, lst.stdout)
    check("manifest-H", "H" in parse_manifest(repo))


def _check_tag_rollback(binary, repo, base, tagged_manifest, check):
    code, err = publish_rev(binary, repo, {"bad.txt": b"regression\n"})
    check("later-publish", code == 0, err)
    rb = repotool(binary, "tag", "rollback", str(repo), "good")
    check("rollback", rb.returncode == 0, rb.stderr)
    manifest = parse_manifest(repo)
    check("revision-never-rewinds",
          int(manifest["S"]) == int(tagged_manifest["S"]) + 2, manifest["S"])
    check("new-root-object", manifest["C"] != tagged_manifest["C"])
    current_rows = catalog_rows(repo, manifest["C"], base)
    check("tree-matches-tagged",
          current_rows == catalog_rows(repo, tagged_manifest["C"], base))
    check("catalog-revision-consistent", any(
        value == manifest["S"] for (value,) in open_catalog(repo, manifest["C"], base).execute(
            "SELECT value FROM properties WHERE key='revision'")))
    check("fsck-clean", repotool(binary, "fsck", str(repo)).returncode == 0)


def check_tag_refusals(binary: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"tag:{name} {msg}".rstrip()))
    repo, err = build_history(binary, base, "tag-refuse", revisions=1)
    ck("build", repo is not None, err)
    if repo is None:
        return
    _check_unknown_tag(binary, repo, ck)
    _check_tampered_history(binary, repo, ck)


def _check_unknown_tag(binary, repo, check):
    assert repotool(binary, "tag", "add", str(repo), "real").returncode == 0
    rb = repotool(binary, "tag", "rollback", str(repo), "nosuch")
    check("unknown-refused",
          rb.returncode != 0 and "unknown tag" in rb.stderr, rb.stderr)


def _check_tampered_history(binary, repo, check):
    hist = cas_path(repo, parse_manifest(repo)["H"], "H")
    original = hist.read_bytes()
    tampered = bytearray(original)
    tampered[20] ^= 0x01
    hist.write_bytes(bytes(tampered))
    for verb in (("tag", "list"), ("tag", "rollback")):
        args = (*verb, str(repo)) + (("real",) if verb[1] == "rollback" else ())
        result = repotool(binary, *args)
        check(f"tamper-{verb[1]}-refused",
              result.returncode != 0 and "CAS verification" in result.stderr,
              result.stderr)
    hist.write_bytes(original)
    check("restore-works",
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
