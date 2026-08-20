# tests/rpm/make_fixtures.py — build the canonical RPM corpus for the
# phase-104 D12 lanes (`brixrpm createrepo` / `inspect`).
#
# WHAT: three small real packages covering the shapes the primary.xml writer
#       has to get right — noarch without epoch and a rich file list, an
#       arch'd package WITH an epoch that Provides a versioned soname, and a
#       consumer that Requires it (so dnf has something to depsolve) with a
#       changelog (so other.xml is non-empty for at least one package).
# WHY:  fixtures are BUILT, not downloaded (phase-104 cross-cutting rule).
#       rpmbuild is the only producer trusted to emit real rpm.org container
#       bytes — a hand-rolled writer would only ever test our own beliefs.
# HOW:  one spec per package into a private rpmbuild topdir, results copied
#       flat into <out>/. Idempotent: an up-to-date corpus is left alone, so
#       repeat pytest runs pay the ~3 s build once.
#
# Standalone: `python3 tests/rpm/make_fixtures.py [outdir]`.
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# name -> (spec body, produced file name). Kept deliberately tiny; every byte
# here shows up in someone's XML diff.
_COMMON = """\
BuildArch:      %(arch)s
License:        MIT
URL:            https://example.invalid/brixtest
Group:          Development/Tools
Summary:        %(summary)s
Vendor:         BriX Test Corpus
Packager:       BriX <brix@example.invalid>

%%description
%(desc)s
"""

SPECS = {
    # noarch, no epoch, rich file list: /etc config, two bin/ paths (both
    # visible in primary.xml), a doc path that is NOT (the createrepo filter).
    "brixtest-tools": dict(
        version="1.2", release="3", arch="noarch", epoch=None,
        summary="BriX test corpus: tools",
        desc="Tools package with a rich file list, & a literal ampersand\n"
             "plus <angle brackets> so the XML escaper is exercised.",
        provides=[], requires=[], changelog=False,
        files=[
            ("/etc/brixtest/tools.conf", "mode=0644", "key = value\n"),
            ("/usr/bin/brixtest-tool", "mode=0755", "#!/bin/sh\nexit 0\n"),
            ("/usr/sbin/brixtest-admin", "mode=0755", "#!/bin/sh\nexit 0\n"),
            ("/usr/share/brixtest/README", "mode=0644", "not in primary\n"),
        ],
    ),
    # arch'd, epoch 2, provides a versioned soname and requires the noarch one.
    "brixtest-lib": dict(
        version="2.0", release="1", arch="x86_64", epoch=2,
        summary="BriX test corpus: library",
        desc="Arch'd library carrying an epoch and a versioned Provides.",
        provides=["libbrixtest.so.1()(64bit)"],
        requires=["brixtest-tools >= 1.2"],
        changelog=False,
        files=[
            ("/usr/lib64/libbrixtest.so.1", "mode=0755", "\x7fELF-not-really\n"),
            ("/etc/brixtest/lib.conf", "mode=0644", "tuning = 1\n"),
        ],
    ),
    # the depsolve target: requires the soname, and owns a changelog so
    # other.xml is non-empty for at least one package in the corpus.
    "brixtest-app": dict(
        version="0.9", release="4", arch="noarch", epoch=None,
        summary="BriX test corpus: application",
        desc="Application requiring the library by soname.",
        provides=[], requires=["libbrixtest.so.1()(64bit)"], changelog=True,
        files=[
            ("/usr/bin/brixtest-app", "mode=0755", "#!/bin/sh\nexit 0\n"),
        ],
    ),
}


def _spec_text(name: str, s: dict) -> str:
    out = [f"Name:           {name}\n",
           f"Version:        {s['version']}\n",
           f"Release:        {s['release']}\n"]
    if s["epoch"] is not None:
        out.append(f"Epoch:          {s['epoch']}\n")
    out.append(_COMMON % dict(arch=s["arch"], summary=s["summary"],
                              desc=s["desc"]))
    for p in s["provides"]:
        out.insert(3, f"Provides:       {p}\n")
    for r in s["requires"]:
        out.insert(3, f"Requires:       {r}\n")

    out.append("\n%install\nrm -rf %{buildroot}\n")
    for path, _mode, body in s["files"]:
        out.append(f"mkdir -p %{{buildroot}}$(dirname {path})\n")
        out.append(f"cat > %{{buildroot}}{path} <<'BRIXEOF'\n{body}BRIXEOF\n")

    out.append("\n%files\n")
    for path, mode, _body in s["files"]:
        attr = mode.split("=")[1]
        cfg = "%config(noreplace) " if path.startswith("/etc/") else ""
        out.append(f"%attr({attr},root,root) {cfg}{path}\n")

    if s["changelog"]:
        out.append("\n%changelog\n"
                   "* Mon Jan 06 2025 BriX <brix@example.invalid> - 0.9-4\n"
                   "- corpus entry with an <escaped> & ampersand\n")
    return "".join(out)


def rpm_name(name: str, s: dict) -> str:
    return f"{name}-{s['version']}-{s['release']}.{s['arch']}.rpm"


def build(out_dir: Path = FIXTURES, force: bool = False) -> list[Path]:
    """Build (or reuse) the corpus in out_dir; return the .rpm paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    want = {n: out_dir / rpm_name(n, s) for n, s in SPECS.items()}
    if not force and all(p.exists() for p in want.values()):
        return sorted(want.values())

    with tempfile.TemporaryDirectory(prefix="brixrpm-fixtures-") as td:
        top = Path(td)
        for sub in ("SPECS", "BUILD", "RPMS", "SRPMS", "BUILDROOT"):
            (top / sub).mkdir()
        for name, s in SPECS.items():
            spec = top / "SPECS" / f"{name}.spec"
            spec.write_text(_spec_text(name, s))
            subprocess.run(
                ["rpmbuild", "-bb", "--define", f"_topdir {top}",
                 "--define", "_build_id_links none", str(spec)],
                check=True, capture_output=True, text=True)
        for built in top.glob("RPMS/*/*.rpm"):
            shutil.copy2(built, out_dir / built.name)
    missing = [str(p) for p in want.values() if not p.exists()]
    if missing:
        raise RuntimeError(f"rpmbuild did not produce: {missing}")
    return sorted(want.values())


if __name__ == "__main__":
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else FIXTURES
    for p in build(dest, force="--force" in sys.argv):
        print(p)
