"""The repository's governance files must be real, not decorative.

SECURITY.md, CODEOWNERS, the Dependabot config and the issue/PR templates all
share one failure mode: they look present, GitHub silently ignores or misroutes
them, and nobody notices for a year. A CODEOWNERS line naming a path that no
longer exists assigns no reviewer. A Dependabot ``directory`` that does not
exist produces no update PRs — and no error either. A template with a YAML slip
falls back to a blank issue box.

So each of these is checked the same way the ``tools/ci`` guards check the code:
does the file parse, and do the things it points at actually exist?
"""

from __future__ import annotations

from pathlib import Path

import pytest

def _check_test_codeowners_has_a_catch_all_and_every_rule_has_an_owner_1(ownerless):
    assert not ownerless, f"CODEOWNERS entries with no owner: {ownerless}"

def _check_test_codeowners_has_a_catch_all_and_every_rule_has_an_owner_2(malformed):
    assert not malformed, f"CODEOWNERS owners must be @handle or an email: {malformed}"


yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parents[1]
GH = REPO / ".github"


# --- SECURITY.md --------------------------------------------------------------


def test_security_policy_exists_and_routes_reports_privately() -> None:
    body = (REPO / "SECURITY.md").read_text()
    assert "security/advisories/new" in body or "Report a vulnerability" in body, (
        "SECURITY.md must point at GitHub private vulnerability reporting"
    )
    assert "@" in body, "SECURITY.md must give a fallback contact address"
    assert "Do not open a public issue" in body


@pytest.mark.parametrize(
    "section",
    ["Reporting a vulnerability", "Supported versions", "Scope", "What to expect"],
)
def test_security_policy_covers_the_sections_a_reporter_needs(section: str) -> None:
    """A policy without a scope or a timeline tells a reporter nothing."""
    assert section in (REPO / "SECURITY.md").read_text(), (
        f"SECURITY.md has no '{section}' section"
    )


def test_security_policy_links_resolve() -> None:
    """Relative links in SECURITY.md point at files that exist.

    check_doc_links.py covers docs/ and the src READMEs; SECURITY.md sits
    outside its scan, and a dead hardening-guide link in the one document a
    reporter reads under pressure is worse than no link."""
    import re

    body = (REPO / "SECURITY.md").read_text()
    dead = [
        target
        for target in re.findall(r"\]\((?!https?:|#)([^)]+)\)", body)
        if not (REPO / target.split("#")[0]).exists()
    ]
    assert not dead, f"SECURITY.md links to non-existent paths: {dead}"


# --- CODEOWNERS ---------------------------------------------------------------


def _codeowner_rules() -> list[tuple[str, list[str], int]]:
    rules = []
    for lineno, raw in enumerate((GH / "CODEOWNERS").read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        pattern, *owners = line.split()
        rules.append((pattern, owners, lineno))
    return rules


def test_codeowners_has_a_catch_all_and_every_rule_has_an_owner() -> None:
    rules = _codeowner_rules()
    def _assert_test_codeowners_has_a_catch_all_and_every_rule_has_an_owner_1():
        assert rules, "CODEOWNERS is empty"
        assert any(p == "*" for p, _, _ in rules), (
            "CODEOWNERS has no `*` rule — paths not matched by any pattern get no "
            "reviewer at all, which is the failure this file exists to prevent"
        )

    _assert_test_codeowners_has_a_catch_all_and_every_rule_has_an_owner_1()
    ownerless = [(p, n) for p, owners, n in rules if not owners]
    _check_test_codeowners_has_a_catch_all_and_every_rule_has_an_owner_1(ownerless)
    malformed = [
        (p, n)
        for p, owners, n in rules
        for o in owners
        if not (o.startswith("@") or "@" in o)
    ]
    _check_test_codeowners_has_a_catch_all_and_every_rule_has_an_owner_2(malformed)


def test_codeowners_paths_exist() -> None:
    """A rule for a path that moved silently stops assigning a reviewer."""
    missing = [
        (pattern, lineno)
        for pattern, _owners, lineno in _codeowner_rules()
        if pattern != "*" and not (REPO / pattern.strip("/")).exists()
    ]
    assert not missing, (
        f"CODEOWNERS rules reference paths that do not exist: {missing}"
    )


@pytest.mark.parametrize(
    "path", ["src/auth", "src/fs", "src/protocols", "tools/ci", "requirements.txt"]
)
def test_codeowners_covers_the_sensitive_surfaces(path: str) -> None:
    """Auth, the VFS seam, the parsers, the guards and the dependency surface
    each carry an explicit rule — not just the catch-all — so that adding a
    second reviewer later is a one-line edit against the right area."""
    patterns = {p.strip("/") for p, _, _ in _codeowner_rules()}
    assert any(p == path or path.startswith(p + "/") for p in patterns if p != "*"), (
        f"no explicit CODEOWNERS rule covers {path}"
    )


# --- Dependabot ---------------------------------------------------------------


def _dependabot() -> dict:
    return yaml.safe_load((GH / "dependabot.yml").read_text())


def test_dependabot_config_is_version_2() -> None:
    assert _dependabot()["version"] == 2


@pytest.mark.parametrize("ecosystem", ["pip", "github-actions", "docker"])
def test_dependabot_covers_every_dependency_ecosystem(ecosystem: str) -> None:
    """Python packages, CI actions and base images are all supply chain.

    A workflow action runs with the job's secrets; a base image ships the libc
    the server links against. Updating only one of the three is not coverage."""
    found = {u["package-ecosystem"] for u in _dependabot()["updates"]}
    assert ecosystem in found, f"dependabot.yml does not watch {ecosystem}"


def test_dependabot_directories_exist() -> None:
    """Dependabot reports no error for a directory that isn't there — it just
    never opens a PR. That is indistinguishable from "no updates available"."""
    missing = []
    for update in _dependabot()["updates"]:
        dirs = update.get("directories") or [update.get("directory")]
        for d in dirs:
            target = REPO / d.lstrip("/")
            if not target.is_dir():
                missing.append((update["package-ecosystem"], d))
    assert not missing, f"dependabot.yml watches non-existent directories: {missing}"


def test_dependabot_docker_directories_contain_a_dockerfile() -> None:
    """A docker entry pointed at a directory with no Dockerfile is a no-op."""
    empty = []
    for update in _dependabot()["updates"]:
        if update["package-ecosystem"] != "docker":
            continue
        for d in update.get("directories") or [update.get("directory")]:
            target = REPO / d.lstrip("/")
            if not any(target.glob("Dockerfile*")):
                empty.append(d)
    assert not empty, f"dependabot docker dirs with no Dockerfile: {empty}"


# --- issue and PR templates ---------------------------------------------------

_TEMPLATES = sorted((GH / "ISSUE_TEMPLATE").glob("*.yml"))


def test_issue_templates_exist() -> None:
    names = {p.name for p in _TEMPLATES}
    assert {"config.yml", "bug_report.yml", "feature_request.yml"} <= names, (
        f"missing issue templates: {names}"
    )


@pytest.mark.parametrize("path", _TEMPLATES, ids=lambda p: p.name)
def test_issue_templates_parse(path: Path) -> None:
    """A YAML slip makes GitHub drop the template and offer a blank box."""
    doc = yaml.safe_load(path.read_text())
    assert isinstance(doc, dict), f"{path.name} is not a YAML mapping"
    if path.name == "config.yml":
        assert doc.get("blank_issues_enabled") is False
        assert doc.get("contact_links"), "config.yml lists no contact links"
        return
    assert doc.get("name") and doc.get("description"), (
        f"{path.name} needs a name and description or it cannot be chosen"
    )
    assert doc.get("body"), f"{path.name} has no fields"


def test_issue_chooser_routes_security_reports_away_from_public_issues() -> None:
    doc = yaml.safe_load((GH / "ISSUE_TEMPLATE/config.yml").read_text())
    blob = yaml.safe_dump(doc)
    assert "security" in blob.lower(), (
        "the issue chooser must offer a security route — otherwise the first "
        "place a reporter lands is a public issue box"
    )


def test_pull_request_template_states_the_actual_merge_bar() -> None:
    """The checklist must name this project's real gates, not generic ones."""
    body = (GH / "pull_request_template.md").read_text()
    for expected in ("security negative", "guard_set.py", "vfs-seam-allow", "600-line"):
        assert expected in body, f"PR template does not mention {expected!r}"
