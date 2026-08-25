# tests/test_rpm_createrepo.py — `brixrpm createrepo` / `inspect` (phase-104
# D12.4). Three legs, per the standing rule:
#
#   success   — dnf itself depsolves and installs from a repo we generated,
#               `inspect --json` agrees with `rpm -qp`, and `--update` reparses
#               only what changed;
#   error     — malformed packages are skipped with a warning (fatal only under
#               --strict), and an empty directory is a valid empty repo;
#   security  — a corrupted-header corpus is either refused or contained, and a
#               package whose DIRNAMES imply `../` has those entries dropped.
#
# No port block and no server: createrepo is a local CLI and the depsolve
# oracle reads the repo over file://. HTTP-served repodata is D11's lane
# (test_rpm_mirror_dnf.py, block 14160), which is where dnf's own HTTP caching
# of repomd.xml is worth exercising.
#
# The dnf leg needs an installroot, which needs root — `unshare -r` (rootless
# user namespace) supplies it on any modern kernel, so no container is needed.
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

def _expression_1(qp, tag):
    return (
        [ln for ln in qp("[%%{%s}\n]" % tag).splitlines() if ln]
    )

def _expression_2(got, field):
    return (
        [d["name"] for d in got[field]]
    )


def _guard_test_inspect_agrees_with_rpm_qp_1():
    if not _have("rpm"):
        pytest.skip("rpm(1) not installed")

def _check_test_inspect_agrees_with_rpm_qp_2(sha, got):
    assert got["pkgid"] == sha

def _check_test_inspect_agrees_with_rpm_qp_1(mine, theirs, field):
    assert mine == theirs, "%s: %s != %s" % (field, mine, theirs)


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRIXRPM = os.path.join(REPO_ROOT, "client", "bin", "brixrpm")
# conftest chdir()s into a scratch dir at session start — resolve helpers
# against this file, never the cwd.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "rpm"))

import make_fixtures                      # noqa: E402
import rpm_corrupt                        # noqa: E402

pytestmark = pytest.mark.skipif(
    not os.path.exists(BRIXRPM),
    reason="client/bin/brixrpm not built (make -C client brixrpm)")

_have = shutil.which


def _run(*args, **kw):
    return subprocess.run([BRIXRPM, *args], capture_output=True, text=True,
                          **kw)


def _stats(proc):
    """Parse the trailing `N packages (P parsed, C cached, S skipped, X …)`.

    Asserting on the counters rather than on repodata contents keeps these
    tests reading like the CLI's contract: the stats line IS the contract.
    """
    for line in reversed(proc.stdout.splitlines()):
        if "packages (" in line:
            head, tail = line.rsplit(": ", 1)[-1], line.split("(", 1)[1]
            out = {"packages": int(head.split()[0])}
            for part in tail.rstrip(")").split(", "):
                n, name = part.split(None, 1)
                out[name.replace("-", "_")] = int(n)
            return out
    raise AssertionError("no stats line in:\n%s%s" % (proc.stdout, proc.stderr))


@pytest.fixture(scope="module")
def fixtures():
    """The three real rpmbuild'd packages (built once, reused)."""
    if not _have("rpmbuild"):
        pytest.skip("rpmbuild not installed")
    try:
        return make_fixtures.build()
    except (subprocess.CalledProcessError, RuntimeError) as exc:
        pytest.skip("rpmbuild could not produce the corpus: %s" % exc)


@pytest.fixture
def repo(tmp_path, fixtures):
    """A fresh repo dir holding a copy of the corpus under Packages/."""
    pkgs = tmp_path / "Packages"
    pkgs.mkdir()
    for src in fixtures:
        shutil.copy2(src, pkgs / src.name)
    return tmp_path


# ---------------------------------------------------------------- success ---

def test_dnf_installs_from_a_generated_repo(repo, tmp_path):
    """The oracle: dnf depsolves epoch + soname out of OUR repodata.

    Nothing we assert about primary.xml carries the weight of dnf agreeing to
    install from it — every field that matters is exercised by depsolving
    brixtest-app -> libbrixtest.so.1 -> brixtest-lib (epoch 2) -> brixtest-tools.
    """
    if not (_have("dnf") and _have("unshare")):
        pytest.skip("dnf and unshare(1) are required for the depsolve oracle")

    def _assert_test_dnf_installs_from_a_generated_repo_3():
        assert _run("createrepo", str(repo)).returncode == 0
        assert (repo / "repodata" / "repomd.xml").exists()

    _assert_test_dnf_installs_from_a_generated_repo_3()

    root, cache = tmp_path / "installroot", tmp_path / "dnfcache"
    proc = subprocess.run(
        ["unshare", "-r", "--", "dnf", "--disablerepo=*",
         "--repofrompath=brixtest,file://%s" % repo,
         "--enablerepo=brixtest", "--installroot=%s" % root,
         "--releasever=9", "--setopt=gpgcheck=0",
         "--setopt=cachedir=%s" % cache, "-y", "install", "brixtest-app"],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # all three arrive, and the epoch survives the round trip
    for want in ("brixtest-app-0.9-4", "brixtest-lib-2:2.0-1",
                 "brixtest-tools-1.2-3"):
        assert want in proc.stdout, proc.stdout


def test_inspect_agrees_with_rpm_qp(fixtures):
    """`inspect --json` vs rpm(1) on NEVRA, provides, requires and pkgid."""
    _guard_test_inspect_agrees_with_rpm_qp_1()
    pkg = next(p for p in fixtures if "brixtest-lib" in p.name)

    got = json.loads(_run("inspect", str(pkg), "--json").stdout)

    def qp(fmt):
        out = subprocess.run(["rpm", "-qp", "--qf", fmt, str(pkg)],
                             capture_output=True, text=True, check=True)
        return out.stdout

    def _assert_test_inspect_agrees_with_rpm_qp_1():
        assert got["name"] == "brixtest-lib"
        assert got["epoch"] == 2

    _assert_test_inspect_agrees_with_rpm_qp_1()
    def _assert_test_inspect_agrees_with_rpm_qp_2():
        assert got["arch"] == "x86_64"
        assert got["nevra"] == qp("%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}")

    _assert_test_inspect_agrees_with_rpm_qp_2()
    for field, tag in (("provides", "PROVIDES"), ("requires", "REQUIRES")):
        theirs = _expression_1(qp, tag)
        mine = _expression_2(got, field)
        _check_test_inspect_agrees_with_rpm_qp_1(mine, theirs, field)
    # pkgid is the sha256 of the whole file, not of any header region
    sha = subprocess.run(["sha256sum", str(pkg)], capture_output=True,
                         text=True, check=True).stdout.split()[0]
    _check_test_inspect_agrees_with_rpm_qp_2(sha, got)


def test_update_reparses_only_what_changed(repo):
    """The --update memo: a cold run parses all, a warm run parses none,
    and touching one package reparses exactly that one."""
    assert _stats(_run("createrepo", str(repo)))["parsed"] == 3

    warm = _stats(_run("createrepo", "--update", str(repo)))
    assert (warm["parsed"], warm["cached"]) == (0, 3)

    victim = next((repo / "Packages").iterdir())
    os.utime(victim, (0, 0))
    bumped = _stats(_run("createrepo", "--update", str(repo)))
    assert (bumped["parsed"], bumped["cached"]) == (1, 2)

    # without --update the memo is ignored entirely
    assert _stats(_run("createrepo", str(repo)))["cached"] == 0


def _rewrite_in_place(path):
    """Flip one payload byte, keeping length AND timestamps identical.

    This is the shape --paranoid exists for: a package rebuilt and copied with
    `cp -p`, an rsync without --checksum, a mirror leg that served something
    else. The payload is streamed for the pkgid and never decoded, so the
    package still parses — only its checksum moved.
    """
    st = os.stat(path)
    with open(path, "r+b") as fh:
        fh.seek(-1, os.SEEK_END)
        last = fh.read(1)
        fh.seek(-1, os.SEEK_END)
        fh.write(bytes([last[0] ^ 0xFF]))
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert os.stat(path).st_size == st.st_size
    assert os.stat(path).st_mtime_ns == st.st_mtime_ns


def _pkgids(repo):
    """Every package checksum primary.xml currently claims.

    Read out of the emitted metadata rather than off the files, because the
    question these tests ask is what the REPOSITORY says, which is exactly
    where a stale memo shows up.
    """
    root = ET.parse(str(repo / "repodata" / "repomd.xml")).getroot()
    ns = "{http://linux.duke.edu/metadata/repo}"
    href = next(d.find(ns + "location").get("href")
                for d in root.findall(ns + "data")
                if d.get("type") == "primary")
    with gzip.open(str(repo / href), "rb") as fh:
        body = fh.read()
    ids = set(re.findall(rb'pkgid="YES">([0-9a-f]{64})<', body))
    assert ids, "primary.xml named no package checksums"
    return ids


def test_paranoid_re_hashes_a_memo_hit_instead_of_trusting_mtime(repo):
    """The flag is a verification, not a rebuild: bytes that did not move are
    still served from the memo, so it costs one read pass and no reparse."""
    assert _stats(_run("createrepo", str(repo)))["parsed"] == 3

    warm = _stats(_run("createrepo", "--update", "--paranoid", str(repo)))
    assert (warm["parsed"], warm["cached"]) == (0, 3)
    assert "changed_in_place" not in warm

    # ...and it is deaf to mtime alone, which (size, mtime) is not: the same
    # bytes under a new timestamp are still a hit.
    victim = next((repo / "Packages").iterdir())
    os.utime(victim, (0, 0))
    touched = _stats(_run("createrepo", "--update", "--paranoid", str(repo)))
    assert (touched["parsed"], touched["cached"]) == (0, 3)


def test_paranoid_catches_a_package_rewritten_under_the_same_size_and_mtime(repo):
    """The detection this flag is for — counted, warned, and re-parsed."""
    assert _run("createrepo", str(repo)).returncode == 0
    before = _pkgids(repo)

    victim = next((repo / "Packages").iterdir())
    _rewrite_in_place(victim)

    proc = _run("createrepo", "--update", "--paranoid", str(repo))
    assert proc.returncode == 0
    st = _stats(proc)
    assert (st["parsed"], st["cached"], st["changed_in_place"]) == (1, 2, 1)
    assert "changed in place" in proc.stderr
    assert victim.name in proc.stderr

    after = _pkgids(repo)
    assert len(after - before) == 1, "the moved package was republished"
    assert len(before - after) == 1


def test_without_paranoid_the_same_rewrite_republishes_stale_metadata(repo):
    """Security-negative — the trust boundary --update alone accepts.

    (size, mtime) is a heuristic, and this is what believing it costs: the
    repository keeps advertising a checksum for bytes that are no longer
    there, so every dnf client that fetches the package fails verification
    against metadata we signed off on. The test asserts the wrong answer on
    purpose: it is the reason the flag exists, and it must not change
    silently.
    """
    assert _run("createrepo", str(repo)).returncode == 0
    before = _pkgids(repo)

    _rewrite_in_place(next((repo / "Packages").iterdir()))

    proc = _run("createrepo", "--update", str(repo))
    assert proc.returncode == 0
    assert _stats(proc)["cached"] == 3
    assert _pkgids(repo) == before        # stale, and nothing said so


def test_a_corrupt_memo_is_discarded_not_trusted(repo):
    """A damaged .brixrpm-cache costs a reparse, never a wrong answer."""
    _run("createrepo", "--update", str(repo))
    memo = repo / "repodata" / ".brixrpm-cache"
    memo.write_bytes(b"brixrpm-cache 1\npkg not-a-number x\n")

    proc = _run("createrepo", "--update", str(repo))
    assert proc.returncode == 0
    assert _stats(proc)["parsed"] == 3
    assert "cache" in proc.stderr.lower()


# ------------------------------------------------------------------ error ---

def test_empty_directory_is_a_valid_empty_repo(tmp_path):
    proc = _run("createrepo", str(tmp_path))
    assert proc.returncode == 0
    assert _stats(proc)["packages"] == 0
    assert (tmp_path / "repodata" / "repomd.xml").exists()


def test_unreadable_root_is_fatal(tmp_path):
    """A repo dir we cannot scan is an operator error, not a skip."""
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    (tmp_path / "locked").mkdir(mode=0o000)
    try:
        assert _run("createrepo", str(tmp_path / "locked")).returncode == 1
    finally:
        (tmp_path / "locked").chmod(0o755)


def test_usage_errors_exit_two():
    """Exit table: 0 ok, 1 operation failed, 2 usage."""
    assert _run("createrepo").returncode == 2
    assert _run("nosuchverb").returncode == 2
    assert _run("inspect", "/nonexistent.rpm").returncode == 1


# ------------------------------------------------------- security-negative ---

# Mutations that must be refused outright: the container is structurally
# unusable, so there is nothing to salvage.
REFUSED = ("bad_magic", "dirindex_out_of_range", "dl_absurd", "il_absurd",
           "not_an_rpm", "truncate_lead", "truncate_main_body",
           "truncate_sig_body")
# Mutations of a single index entry. The header still loads; the reader must
# refuse the individual tag AT ACCESS and carry on, so the package survives
# with a zeroed installed-size rather than garbage or a crash.
CONTAINED = ("offset_past_dl", "offset_wraps", "type_confusion", "count_wrap")


@pytest.fixture(scope="module")
def fuzzed(tmp_path_factory, fixtures):
    src = next(p for p in fixtures if "brixtest-lib" in p.name)
    out = tmp_path_factory.mktemp("fuzz")
    rpm_corrupt.write_corpus(src, out)
    return out


def test_every_mutation_is_accounted_for(fuzzed):
    """No mutation may quietly vanish: the corpus and the two expectation
    lists must cover each other exactly, so adding a mutation to
    rpm_corrupt.CORRUPTIONS forces a decision here."""
    made = {p.stem for p in fuzzed.iterdir() if p.suffix == ".rpm"}
    assert made == set(REFUSED) | set(CONTAINED)


def test_corrupt_headers_are_refused_or_contained(fuzzed):
    proc = _run("createrepo", str(fuzzed))
    assert proc.returncode == 0            # a bad package is not a bad repo
    st = _stats(proc)
    assert st["skipped"] == len(REFUSED)
    assert st["parsed"] == len(CONTAINED)
    for name in REFUSED:
        assert "%s.rpm" % name in proc.stderr, "%s was not reported" % name


@pytest.mark.parametrize("name", REFUSED)
def test_each_refusal_is_isolated(tmp_path, fuzzed, fixtures, name):
    """One bad package must not take a good one down with it — and --strict
    must turn that same skip into a hard failure."""
    shutil.copy2(fuzzed / ("%s.rpm" % name), tmp_path)
    good = next(p for p in fixtures if "brixtest-app" in p.name)
    shutil.copy2(good, tmp_path)

    proc = _run("createrepo", str(tmp_path))
    assert proc.returncode == 0
    assert _stats(proc) == {"packages": 1, "parsed": 1, "cached": 0,
                            "skipped": 1, "paths_sanitized": 0}
    assert _run("createrepo", "--strict", str(tmp_path)).returncode == 1


def test_contained_mutations_zero_the_field_they_broke(fuzzed):
    """Bounds are enforced at access: the unreadable SIZE degrades to 0."""
    import gzip
    import glob
    _run("createrepo", str(fuzzed))
    primary = glob.glob(str(fuzzed / "repodata" / "*-primary.xml.gz"))[0]
    xml = gzip.decompress(open(primary, "rb").read()).decode()
    sizes = [ln for ln in xml.splitlines() if "<size " in ln]
    assert len(sizes) == len(CONTAINED)
    for ln in sizes:
        assert 'installed="0"' in ln, ln       # refused, not guessed
        assert 'package="0"' not in ln         # stat(2) still supplied this


def test_path_traversal_entries_are_dropped(tmp_path, fixtures):
    """An equal-length `../` rewrite of DIRNAMES keeps every header offset
    valid, so the ONLY thing wrong is the path — which isolates the sanitizer:
    the package is kept, the offending entries never reach the XML."""
    import gzip
    import glob
    src = next(p for p in fixtures if "brixtest-lib" in p.name)
    (tmp_path / src.name).write_bytes(
        rpm_corrupt.traversal_dirnames(src.read_bytes()))

    proc = _run("createrepo", str(tmp_path))
    assert proc.returncode == 0
    st = _stats(proc)
    def _assert_test_path_traversal_entries_are_dropped_4():
        assert (st["packages"], st["skipped"]) == (1, 0)
        assert st["paths_sanitized"] >= 1

    _assert_test_path_traversal_entries_are_dropped_4()

    for kind in ("primary", "filelists"):
        path = glob.glob(str(tmp_path / "repodata" / ("*-%s.xml.gz" % kind)))[0]
        xml = gzip.decompress(open(path, "rb").read()).decode()
        assert ".." not in xml, "%s leaked a traversal path" % kind
