"""Every file the CI guard fleet needs at runtime must be committed.

A guard is only as reliable as its dependencies. ``tools/ci/check_*.py`` scripts
are small front-ends: ``check_complexity.py`` imports ``tools/readability.py``
for its lizard engine, ``check_brix_namespace.py`` loads
``tools/refactor/brix_rebrand.py`` by path, and ``tools/git-hooks/pre-push``
shells out to ``tools/ci/guard_set.py``. When the front-end is committed and the
engine is not, everything is green in the working tree that has both files and
red on CI, which builds from a fresh clone::

    ModuleNotFoundError: No module named 'readability'

That traceback names a Python import, not the real fault, so it reads as "the
guard itself is broken" and sends the reader hunting for a source regression
that does not exist. This module turns the mismatch into a direct statement of
what was never added.

The check deliberately looks at *presence on disk versus presence in the index*
rather than at import success: a developer running pytest always has the files,
so importability proves nothing about CI. ``git ls-files`` is the only thing
that answers the question CI actually asks.
"""

from __future__ import annotations

import ast
import io
import re
import subprocess
import tokenize
from pathlib import Path

import pytest

def _phase_import_refs_1(names, path, refs):
    for name in names:
        for cand in (ROOT / "tools" / f"{name}.py", path.parent / f"{name}.py"):
            _guard_import_refs_1(cand, refs)


def _expression_1(workflow):
    return (
        {m for m in _PATH_REF.findall(workflow) if m.endswith(".py")}
    )

def _expression_2(node):
    return (
        isinstance(node, ast.ImportFrom) and node.level == 0 and node.module
    )


def _guard_import_refs_1(cand, refs):
    if cand.is_file():
        refs.add(cand.relative_to(ROOT).as_posix())

def _check_test_ci_enforced_guards_are_themselves_committed_1(named):
    assert named, "guards.yml names no guard scripts — the wiring regressed"


ROOT = Path(__file__).resolve().parents[1]

# Repo-relative path literals: how the hook, the workflow and the path-loading
# guards name their helpers. Restricted to tools/ because that is the only tree
# the guard fleet executes out of. Data files count as dependencies too — an
# uncommitted ratchet backlog fails a guard just as hard as a missing engine.
_PATH_REF = re.compile(r"tools/[A-Za-z0-9_./-]+\.(?:py|sh|txt|json|ya?ml)")


def _tracked() -> set[str]:
    """Repo-relative posix paths git knows about — i.e. what a fresh clone gets."""
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    return {p for p in out.split("\0") if p}


def _scanned_sources() -> list[Path]:
    """The CI-executed surface: tracked files under tools/ plus the workflows."""
    tracked = _tracked()
    return [
        ROOT / p for p in sorted(tracked)
        if (p.startswith("tools/") and (p.endswith(".py") or "/git-hooks/" in p))
        or (p.startswith(".github/workflows/") and p.endswith(".yml"))
    ]


def _import_refs(path: Path) -> set[str]:
    """Imports of a sibling module that resolves to a real file under tools/.

    ``check_complexity.py`` does ``sys.path.insert(0, tools); import readability``
    — a plain module name that is invisible to the path-literal scan.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return set()

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif _expression_2(node):
            names.add(node.module.split(".")[0])

    refs = set()
    _phase_import_refs_1(names, path, refs)
    return refs


def _code_only(path: Path) -> str:
    """`path` with comments removed.

    Guards cite sibling tooling in prose constantly — ``check_brix_namespace.py``
    says it "mirrors brix_verify.sh semantics in pure Python" while importing
    nothing from it. Counting that as a dependency would demand committing a
    file the guard never executes, so only code may create an obligation.
    """
    src = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix == ".py":
        try:
            readline = io.StringIO(src).readline
            return "".join(
                tok.string for tok in tokenize.generate_tokens(readline)
                if tok.type not in (tokenize.COMMENT, tokenize.STRING)
                or tok.type == tokenize.STRING and not _is_docstring(tok)
            )
        except (tokenize.TokenError, IndentationError, SyntaxError):
            return src
    # Shell and YAML: drop `#` to end-of-line unless it sits inside quotes.
    return "\n".join(re.sub(r"""(?<!["'])#.*$""", "", ln) for ln in src.splitlines())


def _is_docstring(tok: tokenize.TokenInfo) -> bool:
    """A string token starting its own logical line — module/def docstring."""
    return tok.line.lstrip().startswith(("'", '"', "r'", 'r"', "f'", 'f"'))


def _refs(path: Path) -> set[str]:
    """Every tools/ helper `path` needs at runtime, by literal or by import."""
    refs = {m for m in _PATH_REF.findall(_code_only(path)) if (ROOT / m).is_file()}
    if path.suffix == ".py":
        refs |= _import_refs(path)
    return refs - {path.relative_to(ROOT).as_posix()}


def _untracked_deps(tracked: set[str]) -> dict[str, set[str]]:
    """dependency -> the CI-executed files that need it, for deps git lacks."""
    missing: dict[str, set[str]] = {}
    for src in _scanned_sources():
        for dep in _refs(src):
            if dep not in tracked:
                missing.setdefault(dep, set()).add(src.relative_to(ROOT).as_posix())
    return missing


def test_guard_runtime_dependencies_are_committed() -> None:
    """A committed guard may not depend on an uncommitted helper."""
    missing = _untracked_deps(_tracked())
    if missing:
        detail = "\n".join(
            f"  {dep}\n      needed by: {', '.join(sorted(users))}"
            for dep, users in sorted(missing.items())
        )
        pytest.fail(
            "CI builds from a fresh clone and will not have these files, so the "
            "guards that need them die on import instead of measuring anything:\n"
            f"{detail}\n\n"
            "Remedy: git add " + " ".join(sorted(missing)) + "\n"
            "(Deleting the dependency is the only other fix — an uncommitted "
            "engine cannot be enforced.)"
        )


def test_ci_enforced_guards_are_themselves_committed() -> None:
    """A guard named by guards.yml but absent from the index enforces nothing.

    The inverse failure: the workflow step runs, the file is missing, and the
    job dies on "no such file" — or worse, a `|| true` step passes silently.
    """
    tracked = _tracked()
    workflow = (ROOT / ".github/workflows/guards.yml").read_text(encoding="utf-8")
    named = _expression_1(workflow)
    _check_test_ci_enforced_guards_are_themselves_committed_1(named)

    absent = sorted(p for p in named if not (ROOT / p).is_file())
    untracked = sorted(p for p in named if (ROOT / p).is_file() and p not in tracked)
    def _assert_test_ci_enforced_guards_are_themselves_committed_1():
        assert not absent, f"guards.yml runs guards that do not exist: {absent}"
        assert not untracked, (
            "guards.yml runs guards that were never committed, so CI cannot run "
            f"them at all: {untracked}"
        )

    _assert_test_ci_enforced_guards_are_themselves_committed_1()


def test_untracked_dependency_is_reported_with_its_users() -> None:
    """Negative: hide a real dependency from the index and it must be flagged.

    Drives the detector against a synthetic index rather than the filesystem —
    no file is created or removed, so the probe cannot leave debris that another
    guard would then trip over.
    """
    tracked = _tracked()
    victim = "tools/ci/check_file_size.py"
    assert victim in tracked, "fixture drifted — pick another tracked guard"

    users = _untracked_deps(tracked - {victim}).get(victim)
    assert users, f"detector missed an untracked {victim}"
    assert ".github/workflows/guards.yml" in users, (
        "the report must name who needs the missing file, not just that it is "
        f"missing; got {sorted(users)}"
    )
