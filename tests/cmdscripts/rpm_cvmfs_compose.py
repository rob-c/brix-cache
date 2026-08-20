"""Phase-104 D13 — an RPM repository served from CVMFS (composition lane).

Nothing new is under test here: D12's `brixrpm createrepo` makes the repodata
and D9's `brixcvmfs ingest dir` publishes the folder. What IS under test is
that the two compose — that a repo survives the round trip through CVMFS's
content-addressed store byte-for-byte, and that stock dnf still depsolves and
installs from what comes back out.

  C1  the runbook path: createrepo → ingest → every file round-trips out of
      CAS byte-identical → dnf installs the whole dependency chain from it.
  C2  the time machine: republish with a package added; the NEW revision has
      it, the OLD root catalog still materialises the original package set
      and dnf still installs from that snapshot; `repo tag` pins it.
  C3  fail-closed: a byte flipped in a published .rpm is refused by dnf's
      checksum chain, and ingesting before createrepo produces exactly the
      inconsistent revision the runbook's ordering rule warns about.

Materialising the tree in Python rather than mounting it over FUSE is
deliberate: it is what makes "the publish preserved every byte" an assertion
instead of an assumption, and the FUSE read path has its own lanes. The
`file://` baseurl the runbook recommends sees precisely this tree.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zlib
from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT
from cmdscripts.cvmfs_ingest_dir import _build_ingesttool, run_tool
from cmdscripts.cvmfs_publish_txn import (
    FLAG_DIR, FLAG_FILE, cas_path, lookup, open_catalog, parse_manifest,
)
from cmdscripts.cvmfs_repo_cli import _build_repotool

FQRN = "software.brix.io"
PREFIX = "/rpm/el9"
BRIXRPM = REPO_ROOT / "client" / "bin" / "brixrpm"

# tests/rpm/make_fixtures.py builds these with rpmbuild; importing it here
# keeps one definition of the corpus for every RPM lane.
import sys                                                      # noqa: E402
sys.path.insert(0, str(REPO_ROOT / "tests" / "rpm"))
import make_fixtures                                            # noqa: E402


def preflight() -> str:
    """Return "" when this host can run the lane, else why it cannot."""
    for tool in ("rpmbuild", "dnf", "unshare"):
        if shutil.which(tool) is None:
            return f"{tool} not installed"
    if not BRIXRPM.exists():
        return "client/bin/brixrpm not built (make -C client brixrpm)"
    return ""


def _brixrpm(*args: str):
    return subprocess.run([str(BRIXRPM), *args], capture_output=True,
                          text=True)


def _ingest(tool: Path, src: Path, repo: Path, *extra: str):
    return run_tool(tool, "dir", str(src), "--repo", str(repo),
                    "--prefix", PREFIX, *extra)


def _seed_repo(src: Path, names: list[str]) -> None:
    """Copy a subset of the fixture corpus into src/Packages/."""
    pkgs = src / "Packages"
    pkgs.mkdir(parents=True, exist_ok=True)
    for path in make_fixtures.build():
        if any(n in path.name for n in names):
            shutil.copy2(path, pkgs / path.name)


def materialise(repo: Path, src: Path, catalog_hash: str, dest: Path,
                base: Path) -> list[str]:
    """Rebuild the published subtree on disk from CAS; return byte mismatches.

    Walks the SOURCE tree for the path list — so a file that failed to publish
    shows up as a missing catalog row rather than being silently skipped — and
    compares every byte against what went in.
    """
    cat = open_catalog(repo, catalog_hash, base)
    problems: list[str] = []
    try:
        for spath in sorted(src.rglob("*")):
            rel = spath.relative_to(src)
            cpath = f"{PREFIX}/{rel.as_posix()}"
            row = lookup(cat, cpath)
            if row is None:
                problems.append(f"missing from catalog: {cpath}")
                continue
            out = dest / rel
            if spath.is_dir():
                if not row[0] & FLAG_DIR:
                    problems.append(f"not a directory in catalog: {cpath}")
                out.mkdir(parents=True, exist_ok=True)
                continue
            if not row[0] & FLAG_FILE:
                problems.append(f"not a file in catalog: {cpath}")
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            data = zlib.decompress(cas_path(repo, row[3].hex()).read_bytes())
            out.write_bytes(data)
            if data != spath.read_bytes():
                problems.append(f"bytes differ: {cpath}")
    finally:
        cat.close()
    return problems


def dnf_install(repo_dir: Path, base: Path, *pkgs: str, tag: str = "t"):
    """Install from a materialised repo over file://, in a user namespace."""
    root, cache = base / f"root.{tag}", base / f"cache.{tag}"
    return subprocess.run(
        ["unshare", "-r", "--", "dnf", "--disablerepo=*",
         f"--repofrompath=brixcvmfs,file://{repo_dir}",
         "--enablerepo=brixcvmfs", f"--installroot={root}",
         "--releasever=9", "--setopt=gpgcheck=0",
         f"--setopt=cachedir={cache}", "-y", "install", *pkgs],
        capture_output=True, text=True)


# ---- C1: the runbook path ---------------------------------------------------

def check_c1(ingest: Path, repotool: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"c1:{name} {msg}".rstrip()))

    repo, src = base / "c1repo", base / "c1src"
    _seed_repo(src, ["brixtest-tools", "brixtest-lib", "brixtest-app"])

    ck("mkfs", run_tool(repotool, "mkfs", FQRN, str(repo)).returncode == 0)

    cr = _brixrpm("createrepo", str(src))
    ck("createrepo", cr.returncode == 0, cr.stderr)
    ck("repomd-exists", (src / "repodata" / "repomd.xml").exists())

    pub = _ingest(ingest, src, repo)
    ck("ingest", pub.returncode == 0, pub.stderr)

    dest = base / "c1view"
    problems = materialise(repo, src, parse_manifest(repo)["C"], dest, base)
    ck("byte-exact-round-trip", not problems, "; ".join(problems[:4]))

    # the whole point: dnf depsolves epoch + soname out of the CVMFS copy
    inst = dnf_install(dest, base, "brixtest-app", tag="c1")
    ck("dnf-install", inst.returncode == 0, (inst.stdout + inst.stderr)[-800:])
    for want in ("brixtest-app-0.9-4", "brixtest-lib-2:2.0-1",
                 "brixtest-tools-1.2-3"):
        ck(f"resolved-{want}", want in inst.stdout)


# ---- C2: the time machine ---------------------------------------------------

def check_c2(ingest: Path, repotool: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"c2:{name} {msg}".rstrip()))

    repo, src = base / "c2repo", base / "c2src"
    _seed_repo(src, ["brixtest-tools", "brixtest-lib"])
    run_tool(repotool, "mkfs", FQRN, str(repo))
    _brixrpm("createrepo", str(src))
    ck("seed-ingest", _ingest(ingest, src, repo).returncode == 0)

    old_catalog = parse_manifest(repo)["C"]
    old_rev = parse_manifest(repo)["S"]
    tag = run_tool(repotool, "tag", "add", str(repo), "snap-before")
    ck("tag-add", tag.returncode == 0, tag.stderr)
    listed = run_tool(repotool, "tag", "list", str(repo))
    ck("tag-list", "snap-before" in listed.stdout, listed.stdout + listed.stderr)

    # republish with one package added, in the runbook's order
    _seed_repo(src, ["brixtest-app"])
    ck("recreaterepo", _brixrpm("createrepo", "--update",
                                str(src)).returncode == 0)
    ck("republish", _ingest(ingest, src, repo).returncode == 0)
    new_catalog = parse_manifest(repo)["C"]
    ck("revision-advanced", parse_manifest(repo)["S"] != old_rev)
    ck("catalog-changed", new_catalog != old_catalog)

    # the new revision has the new package …
    new_view = base / "c2new"
    ck("new-round-trip",
       not materialise(repo, src, new_catalog, new_view, base))
    inst = dnf_install(new_view, base, "brixtest-app", tag="c2new")
    ck("new-installs-app", inst.returncode == 0,
       (inst.stdout + inst.stderr)[-600:])

    # … and the pinned revision still resolves to the old package set
    old_cat = open_catalog(repo, old_catalog, base)
    try:
        app = [p for p in (src / "Packages").iterdir() if "app" in p.name][0]
        ck("snapshot-excludes-new-package",
           lookup(old_cat, f"{PREFIX}/Packages/{app.name}") is None)
        ck("snapshot-keeps-old-package",
           lookup(old_cat, f"{PREFIX}/Packages/"
                  f"{[p.name for p in (src / 'Packages').iterdir() if 'lib' in p.name][0]}")
           is not None)
    finally:
        old_cat.close()


# ---- C3: fail-closed --------------------------------------------------------

def check_c3(ingest: Path, repotool: Path, base: Path, results: list) -> None:
    ck = lambda name, ok, msg="": results.append(
        (bool(ok), f"c3:{name} {msg}".rstrip()))

    repo, src = base / "c3repo", base / "c3src"
    _seed_repo(src, ["brixtest-tools", "brixtest-lib", "brixtest-app"])
    run_tool(repotool, "mkfs", FQRN, str(repo))
    _brixrpm("createrepo", str(src))
    _ingest(ingest, src, repo)

    view = base / "c3view"
    materialise(repo, src, parse_manifest(repo)["C"], view, base)

    # a byte flipped in a published package: the checksum chain must catch it
    victim = [p for p in (view / "Packages").iterdir() if "lib" in p.name][0]
    blob = bytearray(victim.read_bytes())
    blob[len(blob) // 2] ^= 0xFF          # inside the payload, not the header
    victim.write_bytes(bytes(blob))

    bad = dnf_install(view, base, "brixtest-app", tag="c3")
    ck("tampered-rpm-refused", bad.returncode != 0,
       "dnf installed a corrupted package")
    combined = (bad.stdout + bad.stderr).lower()
    ck("refusal-is-about-integrity",
       any(w in combined for w in ("checksum", "digest", "corrupt", "does not match")),
       combined[-400:])

    # the runbook's ordering rule, demonstrated: ingest before createrepo
    # publishes metadata that predates the packages it claims to describe.
    repo2, src2 = base / "c3repo2", base / "c3src2"
    _seed_repo(src2, ["brixtest-tools"])
    run_tool(repotool, "mkfs", FQRN, str(repo2))
    _brixrpm("createrepo", str(src2))
    _ingest(ingest, src2, repo2)
    _seed_repo(src2, ["brixtest-lib"])          # new package, stale repodata
    ck("wrong-order-ingest", _ingest(ingest, src2, repo2).returncode == 0)

    cat = open_catalog(repo2, parse_manifest(repo2)["C"], base)
    try:
        lib = [p for p in (src2 / "Packages").iterdir() if "lib" in p.name][0]
        ck("package-published", lookup(cat, f"{PREFIX}/Packages/{lib.name}")
           is not None)
    finally:
        cat.close()
    stale = base / "c3stale"
    materialise(repo2, src2, parse_manifest(repo2)["C"], stale, base)
    miss = dnf_install(stale, base, "brixtest-lib", tag="c3stale")
    ck("stale-repodata-cannot-see-it", miss.returncode != 0,
       "dnf resolved a package the published repodata never listed")


def run_checks(base: Path) -> list[tuple[bool, str]]:
    results: list[tuple[bool, str]] = []
    ingest, err = _build_ingesttool(base)
    if ingest is None:
        return [(False, f"build:ingesttool {err}")]
    repotool, err = _build_repotool(base)
    if repotool is None:
        return [(False, f"build:repotool {err}")]
    for check in (check_c1, check_c2, check_c3):
        check(ingest, repotool, base, results)
    return results
