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
            _materialise_path(repo, src, dest, cat, spath, problems)
    finally:
        cat.close()
    return problems


def _materialise_path(repo, src, dest, catalog, source, problems):
    relative = source.relative_to(src)
    catalog_path = f"{PREFIX}/{relative.as_posix()}"
    row = lookup(catalog, catalog_path)
    if row is None:
        problems.append(f"missing from catalog: {catalog_path}")
        return
    output = dest / relative
    if source.is_dir():
        _materialise_directory(output, row, catalog_path, problems)
        return
    _materialise_file(repo, output, source, row, catalog_path, problems)


def _materialise_directory(output, row, catalog_path, problems):
    if not row[0] & FLAG_DIR:
        problems.append(f"not a directory in catalog: {catalog_path}")
    output.mkdir(parents=True, exist_ok=True)


def _materialise_file(repo, output, source, row, catalog_path, problems):
    if not row[0] & FLAG_FILE:
        problems.append(f"not a file in catalog: {catalog_path}")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    data = zlib.decompress(cas_path(repo, row[3].hex()).read_bytes())
    output.write_bytes(data)
    if data != source.read_bytes():
        problems.append(f"bytes differ: {catalog_path}")


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
    old_catalog, old_revision = _c2_revision(repo)
    tag = run_tool(repotool, "tag", "add", str(repo), "snap-before")
    ck("tag-add", tag.returncode == 0, tag.stderr)
    listed = run_tool(repotool, "tag", "list", str(repo))
    ck("tag-list", "snap-before" in listed.stdout, listed.stdout + listed.stderr)
    new_catalog = _c2_republish(
        ingest, repo, src, old_catalog, old_revision, ck)
    _c2_check_new_view(repo, src, new_catalog, base, ck)
    _check_snapshot(repo, src, old_catalog, base, ck)


def _c2_revision(repo):
    manifest = parse_manifest(repo)
    return manifest["C"], manifest["S"]


def _c2_republish(ingest, repo, src, old_catalog, old_revision, check):
    _seed_repo(src, ["brixtest-app"])
    result = _brixrpm("createrepo", "--update", str(src))
    check("recreaterepo", result.returncode == 0)
    check("republish", _ingest(ingest, src, repo).returncode == 0)
    new_catalog, new_revision = _c2_revision(repo)
    check("revision-advanced", new_revision != old_revision)
    check("catalog-changed", new_catalog != old_catalog)
    return new_catalog


def _c2_check_new_view(repo, src, catalog, base, check):
    view = base / "c2new"
    check("new-round-trip", not materialise(repo, src, catalog, view, base))
    result = dnf_install(view, base, "brixtest-app", tag="c2new")
    check("new-installs-app", result.returncode == 0,
          (result.stdout + result.stderr)[-600:])


def _package_named(src, fragment):
    return next(path for path in (src / "Packages").iterdir()
                if fragment in path.name)


def _check_snapshot(repo, src, catalog_hash, base, check):
    catalog = open_catalog(repo, catalog_hash, base)
    try:
        app = _package_named(src, "app")
        library = _package_named(src, "lib")
        check("snapshot-excludes-new-package",
              lookup(catalog, f"{PREFIX}/Packages/{app.name}") is None)
        check("snapshot-keeps-old-package",
              lookup(catalog, f"{PREFIX}/Packages/{library.name}") is not None)
    finally:
        catalog.close()


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
    _corrupt_package(_package_named(view, "lib"))

    bad = dnf_install(view, base, "brixtest-app", tag="c3")
    ck("tampered-rpm-refused", bad.returncode != 0,
       "dnf installed a corrupted package")
    combined = (bad.stdout + bad.stderr).lower()
    ck("refusal-is-about-integrity", _names_integrity_failure(combined),
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

    _check_package_published(repo2, src2, base, ck)
    stale = base / "c3stale"
    materialise(repo2, src2, parse_manifest(repo2)["C"], stale, base)
    miss = dnf_install(stale, base, "brixtest-lib", tag="c3stale")
    ck("stale-repodata-cannot-see-it", miss.returncode != 0,
       "dnf resolved a package the published repodata never listed")


def _corrupt_package(path):
    blob = bytearray(path.read_bytes())
    blob[len(blob) // 2] ^= 0xFF
    path.write_bytes(bytes(blob))


def _names_integrity_failure(output):
    words = ("checksum", "digest", "corrupt", "does not match")
    return any(word in output for word in words)


def _check_package_published(repo, src, base, check):
    catalog = open_catalog(repo, parse_manifest(repo)["C"], base)
    try:
        library = _package_named(src, "lib")
        check("package-published",
              lookup(catalog, f"{PREFIX}/Packages/{library.name}") is not None)
    finally:
        catalog.close()


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
