"""A test module must not misname itself, and a README must not cite a phantom.

WHY THIS FILE EXISTS: `docs/04-protocols/native-client-tools.md` offered
`test_official_brix_resilience.py` (under `tests/`) as the evidence that this
repo's native client survives packet loss against a real `xrootd` server. No
such file has ever existed. Tracing it back on 2026-09-09 found the source: the
BriX symbol rebrand (`xrootd_` -> `brix_`, 2026-07-03) rewrote the *docstring*
of `tests/test_official_xrootd_resilience.py`, including the line where the
module names itself and the `Run:` command a reader would copy — but not the
filename. Every later citation copied the wrong name out of the docstring, into
`docs/09-developer-guide/testing/resilience/README.md`, into the remote suite's runner and its
`no_server_files` allowlist, and finally into a user-facing protocol page as
proof of a security-relevant claim.

The two halves are pinned here because a rename sweep will do this again:

  * a module's docstring title line names the module (the house style in 298 of
    them), so it must name *itself*;
  * a `test_*.py` cited in a relocated testing README under `docs/` must
    resolve somewhere in the repository.

Both checks carry a planted-input control, so neither can quietly go vacuous.
"""
import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.xdist_group("self-reference-hygiene")

REPO = Path(__file__).resolve().parents[1]
TESTS = REPO / "tests"
REMOTE = REPO / "k8s-tests" / "remote-suite" / "tests"

_MODULE = re.compile(r"\b(test_\w*\.py)\b")
_CITED = re.compile(r"`((?:[\w./-]*/)?(test_[\w-]*\.py))`")


def _title_reference(source: str) -> "str | None":
    """The `test_*.py` named on the first non-empty line of a module docstring."""
    try:
        doc = ast.get_docstring(ast.parse(source))
    except (SyntaxError, ValueError):
        return None
    if not doc:
        return None
    first = next((line for line in doc.splitlines() if line.strip()), "")
    found = _MODULE.search(first)
    return found.group(1) if found else None


def _self_named_modules() -> list[Path]:
    return sorted(TESTS.rglob("test_*.py"))


def _misnamed(paths) -> list[tuple[str, str]]:
    wrong = []
    for path in paths:
        named = _title_reference(path.read_text(errors="replace"))
        if named is not None and named != path.name:
            wrong.append((path.relative_to(REPO).as_posix(), named))
    return wrong


# --- half one: a module names itself ----------------------------------------

def test_no_test_module_misnames_itself():
    """A docstring title naming a *different* file is how a rename sweep leaves
    a phantom behind: every later citation is copied out of the docstring."""
    assert _misnamed(_self_named_modules()) == []


def test_the_house_style_is_actually_widespread():
    """Guards the check above against becoming vacuous — if the title-line
    convention were rare, the check would pass by finding nothing to look at."""
    titled = [
        path for path in _self_named_modules()
        if _title_reference(path.read_text(errors="replace")) is not None
    ]
    assert len(titled) >= 200, len(titled)


def test_the_self_name_check_catches_a_planted_mismatch(tmp_path):
    planted = tmp_path / "test_named_one_thing.py"
    planted.write_text('"""\ntest_named_something_else.py — a stale title.\n"""\n')
    assert _title_reference(planted.read_text()) == "test_named_something_else.py"


def test_a_module_whose_docstring_names_no_file_is_left_alone(tmp_path):
    planted = tmp_path / "test_prose_only.py"
    planted.write_text('"""Checks the widget behaves."""\n')
    assert _title_reference(planted.read_text()) is None


# --- half two: a README cites a file that exists ----------------------------

def _repo_basenames() -> set:
    listing = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True)
    return {Path(line).name for line in listing.stdout.splitlines()}


def _phantom_citations(readme: Path, known: set) -> list[str]:
    text = readme.read_text(errors="replace")
    return sorted(
        {basename for _, basename in _CITED.findall(text) if basename not in known}
    )


def _testing_readmes():
    """Locate the relocated testing guides without allowing an empty scan."""
    doc_roots = (REPO / "docs/09-developer-guide/testing",
                 REPO / "docs/platform/testing")
    readmes = sorted(path for root in doc_roots for path in root.rglob("README.md"))
    assert readmes, "the relocated testing README scan found no documents"
    return readmes


def test_every_test_module_cited_in_a_tests_readme_exists():
    """The resilience README carried the phantom for months. Resolution is
    by basename anywhere in the repo, because a README legitimately points at
    `k8s-tests/remote-suite/tests/` for the container-only suites."""
    known = _repo_basenames()
    phantoms = {
        readme.relative_to(REPO).as_posix(): _phantom_citations(readme, known)
        for readme in _testing_readmes()
    }
    assert {name: found for name, found in phantoms.items() if found} == {}


def test_the_readme_check_catches_a_planted_phantom(tmp_path):
    planted = tmp_path / "README.md"
    planted.write_text("see `tests/test_absolutely_not_here.py` for the proof.\n")
    assert _phantom_citations(planted, _repo_basenames()) == [
        "test_absolutely_not_here.py"
    ]


def test_the_readme_check_reads_the_repo_not_just_this_directory(tmp_path):
    """A citation into another suite's tree must not be reported as a phantom."""
    planted = tmp_path / "README.md"
    planted.write_text("see `test_minio_s3_forward.py` (it lives in k8s-tests).\n")
    assert _phantom_citations(planted, _repo_basenames()) == []


# --- the harness entries the phantom had silently broken --------------------

def _remote_suite_available() -> bool:
    return (REMOTE / "conftest.py").is_file()


def _remote_basenames() -> set:
    """Basenames of every test module in the remote suite, at any depth — the
    allowlist and the runner both key on the basename, and several of the
    modules they name live in `resilience/`."""
    return {path.name for path in REMOTE.rglob("test_*.py")}


def test_the_remote_suite_no_server_allowlist_names_only_real_modules():
    """An allowlist entry that matches no file grants nothing, silently. The
    phantom sat in `no_server_files` for months, so the exemption it was meant
    to give `test_official_xrootd_resilience.py` was never in force."""
    if not _remote_suite_available():
        pytest.skip("k8s-tests/remote-suite is not present")
    text = (REMOTE / "conftest.py").read_text(errors="replace")
    block = text.split("no_server_files = {", 1)[1].split("}", 1)[0]
    named = _MODULE.findall(block)
    assert named, "the allowlist parsed empty — this check would prove nothing"
    assert [n for n in named if n not in _remote_basenames()] == []


def test_the_remote_suite_runner_names_only_real_modules():
    """`run_suite.sh` named the phantom too, so the remote resilience lane asked
    pytest to collect a path that does not exist."""
    runner = REMOTE / "run_suite.sh"
    if not runner.is_file():
        pytest.skip("k8s-tests/remote-suite runner is not present")
    named = set(_MODULE.findall(runner.read_text(errors="replace")))
    assert named, "the runner named no test modules — this check would prove nothing"
    assert sorted(n for n in named if n not in _remote_basenames()) == []


def test_the_module_the_phantom_was_named_after_is_the_real_one():
    """The specific regression: the file exists under its real name, its title
    line agrees, and the `Run:` line a reader copies points at a real path."""
    real = TESTS / "test_official_xrootd_resilience.py"
    assert real.is_file()
    source = real.read_text(errors="replace")
    assert _title_reference(source) == real.name
    run_line = next(line for line in source.splitlines() if "-m pytest" in line)
    cited = _MODULE.search(run_line).group(1)
    assert (TESTS / cited).is_file(), run_line
