"""Release hygiene: one version, and every file that repeats it agrees.

WHAT: Asserts the real tree's release metadata is self-consistent and complete —
      the version in src/core/ident.h, the RPM spec (fallback + %changelog), the
      CHANGELOG, the security policy's supported-versions table, the bug-report
      template's placeholder, and the release-process documentation.

WHY:  The tree drifted: the server reported 1.3.0, the CHANGELOG stopped at
      1.0.8, and the only git tag (v6.1.0-ref) named a version the product has
      never had. Nothing failed, because nothing checked. tools/ci/check_version_sync.py
      polices the three build-critical copies; this module polices the rest —
      the operator-facing ones, where drift misleads rather than mislabels.

HOW:  Derive the version from ident.h (the single source of truth) and assert
      every consumer against it, so a release bump needs no edits here. The
      guard itself is exercised for real by tests/test_ci_guards.py.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

SPEC = ROOT / "packaging/rpm/nginx-mod-brix-cache.spec"
CHANGELOG = ROOT / "CHANGELOG.md"
SECURITY = ROOT / "SECURITY.md"
BUG_REPORT = ROOT / ".github/ISSUE_TEMPLATE/bug_report.yml"
RELEASE_DOC = ROOT / "docs/09-developer-guide/release-process.md"


@pytest.fixture(scope="module")
def version() -> str:
    """The single source of truth — everything below is asserted against it."""
    text = (ROOT / "src/core/ident.h").read_text()
    m = re.search(r'#define\s+BRIX_SERVER_VERSION_BARE\s+"([^"]+)"', text)
    assert m, "src/core/ident.h no longer defines BRIX_SERVER_VERSION_BARE"
    return m.group(1)


def test_version_is_a_three_part_release_number(version: str) -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), (
        f"version {version!r} is not MAJOR.MINOR.PATCH — the RPM version, the "
        f"git tag and docs/09-developer-guide/release-process.md all assume it is"
    )


# --- the build-critical copies (also enforced by check_version_sync.py) -------


def test_spec_fallback_matches_ident(version: str) -> None:
    """Only a bare `rpmbuild` reads this literal, so drift here mislabels an RPM
    rather than failing a build — nothing downstream would notice."""
    m = re.search(
        r"%global\s+upstream_version\s+.*%\{!\?version_override:([^}]+)\}",
        SPEC.read_text(),
    )
    assert m, "the spec no longer carries a %global upstream_version fallback"
    assert m.group(1) == version


def test_spec_changelog_has_an_entry_for_this_version(version: str) -> None:
    body = SPEC.read_text().split("%changelog", 1)[1]
    entries = re.findall(r"^\*\s+.*?-\s+(\d+(?:\.\d+)*)-\d+\s*$", body, re.M)
    assert entries, "the spec %changelog has no parseable entries"
    assert entries[0] == version, (
        f"newest spec %changelog entry is {entries[0]}, ident.h says {version}"
    )


def test_changelog_top_entry_is_this_version(version: str) -> None:
    entries = re.findall(r"^##\s+v(\d+(?:\.\d+)*)\b", CHANGELOG.read_text(), re.M)
    assert entries, "CHANGELOG.md has no '## vX.Y.Z' entries"
    assert entries[0] == version


def test_changelog_covers_the_shipped_history() -> None:
    """It stopped at 1.0.8 for four releases. Every version the RPM spec has
    shipped must have a CHANGELOG section, or the file is decorative."""
    changelog = set(re.findall(r"^##\s+v(\d+(?:\.\d+)*)\b", CHANGELOG.read_text(), re.M))
    body = SPEC.read_text().split("%changelog", 1)[1]
    shipped = set(re.findall(r"^\*\s+.*?-\s+(\d+(?:\.\d+)*)-\d+\s*$", body, re.M))
    missing = sorted(shipped - changelog)
    assert not missing, f"versions in the RPM %changelog with no CHANGELOG.md entry: {missing}"


def test_changelog_explains_the_versions_that_were_never_cut() -> None:
    """1.0.6, 1.1.0 and 1.2.x do not exist. A gap that is explained is not a
    mystery; an unexplained one reads as a lost entry."""
    text = CHANGELOG.read_text()
    assert "never cut" in text
    for skipped in ("1.1.0", "1.2.x"):
        assert skipped in text, f"the {skipped} gap is not accounted for"


# --- the operator-facing copies -----------------------------------------------


def test_security_policy_supports_the_current_minor(version: str) -> None:
    major, minor, _ = version.split(".")
    assert f"| {major}.{minor}.x | ✅" in SECURITY.read_text(), (
        f"SECURITY.md does not list {major}.{minor}.x as supported — an operator "
        f"reading it would think the current release is out of support"
    )


def test_bug_report_placeholder_names_the_current_version(version: str) -> None:
    """A stale placeholder teaches every reporter to file against an old
    version, which is exactly the field maintainers most need to be right."""
    assert version in BUG_REPORT.read_text()


# --- the process itself --------------------------------------------------------


def test_release_process_is_documented() -> None:
    text = RELEASE_DOC.read_text()
    for anchor in (
        "BRIX_SERVER_VERSION_BARE",
        "check_version_sync.py",
        "CHANGELOG.md",
        "%global upstream_version",
    ):
        assert anchor in text, f"release-process.md never mentions {anchor}"


def test_release_process_pins_the_tag_convention() -> None:
    text = RELEASE_DOC.read_text()
    assert "git tag -a vX.Y.Z" in text, "the annotated-tag command is not documented"
    assert "annotated" in text.lower()


def test_release_process_disowns_the_stray_reference_tag() -> None:
    """v6.1.0-ref is a lightweight tag on a mid-development commit naming an
    upstream XRootD line, not a release of this project. Left in place because
    deleting a published tag breaks fetchers — but it must be labelled."""
    text = RELEASE_DOC.read_text()
    assert "v6.1.0-ref" in text
    assert "not a release" in text.lower()
    assert "d9228d5d7" in text, "the commit the stray tag points at is not recorded"


def test_release_process_repeats_the_git_write_restriction() -> None:
    """Steps 7 and 8 are the only git *writes* in the repo's documented
    workflows; CLAUDE.md forbids an agent running them unprompted."""
    assert "without explicit approval" in RELEASE_DOC.read_text()


# --- negative: the guard is wired, not merely present -------------------------


def test_version_sync_guard_is_executable_and_wired() -> None:
    guard = ROOT / "tools/ci/check_version_sync.py"
    assert guard.is_file()
    assert guard.stat().st_mode & 0o111, "guard is not executable — CI cannot run it"
    assert "check_version_sync.py" in (ROOT / ".github/workflows/guards.yml").read_text()
    assert "check_version_sync.py" in (ROOT / "tools/ci/README.md").read_text()
