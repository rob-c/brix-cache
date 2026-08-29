"""Suite hygiene: shared-DATA_ROOT stagers must be pinned to one xdist worker.

The fast lane runs ``-n N --dist loadgroup``.  loadgroup keeps tests that share
an ``xdist_group`` on one worker, but an UNGROUPED module's cells are handed out
individually, so they routinely land on several workers at once.  Each of those
workers imports the module and runs its own copy of every module-scoped fixture
— including the teardown.  A fixture that stages a file into the *shared*
``DATA_ROOT`` and removes it on teardown therefore deletes that file out from
under the workers still using it, and their copies fail with NotFound.

This bit the suite for real: ``test_xrdcp_xrate_cksum``'s ``TestShaCksum`` cells
failed with ``xrdcp: No such file or directory (NotFound)`` in the parallel lane
while passing alone, and eleven other modules carried the same latent shape.

The rule this pins is narrow on purpose: it fires only for a module-scoped
fixture that both touches the shared ``DATA_ROOT`` *and* deletes something.  A
module with its own dedicated data root (``S3_MPU_DATA_ROOT`` and friends) is
not affected and must not be forced into needless serialization — the second
cell below is that non-vacuity control.

Run:
    PYTHONPATH=tests pytest tests/test_suite_parallel_hygiene.py -v
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.xdist_group("suite-parallel-hygiene")]

TESTS_DIR = Path(__file__).resolve().parent

# The one shared export root every fleet instance serves.  Dedicated roots have
# their own names and are matched by identifier, never by substring.
SHARED_ROOT = "DATA_ROOT"
DELETERS = {"remove", "unlink", "rmtree"}


def _decorator_name(deco: ast.AST) -> str:
    """The bare attribute/identifier a decorator call names, else ""."""
    if not isinstance(deco, ast.Call):
        return ""
    if isinstance(deco.func, ast.Attribute):
        return deco.func.attr
    return getattr(deco.func, "id", "")


def _declares_module_scope(deco: ast.Call) -> bool:
    """True if this decorator call passes ``scope="module"``."""
    return any(kw.arg == "scope" and isinstance(kw.value, ast.Constant)
               and kw.value.value == "module" for kw in deco.keywords)


def _is_module_scoped_fixture(node: ast.AST) -> bool:
    """True for ``@pytest.fixture(scope="module")`` in any decorator spelling."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    return any(_decorator_name(d) == "fixture" and _declares_module_scope(d)
               for d in node.decorator_list)


def _stages_in_shared_root(node: ast.AST) -> bool:
    """True if this fixture both names the shared root and deletes something."""
    names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    if SHARED_ROOT not in names:
        return False
    calls = {c.func.attr for c in ast.walk(node)
             if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
    return bool(calls & DELETERS)


def _offenders(source: str) -> list[str]:
    """Names of the module-scoped shared-root stagers in ``source``.

    An empty list means the module is clean — either it has no such fixture, or
    it already carries an ``xdist_group`` that pins its cells to one worker.
    """
    if "xdist_group" in source:
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:                      # not our problem; other guards own it
        return []
    return [n.name for n in ast.walk(tree)
            if _is_module_scoped_fixture(n) and _stages_in_shared_root(n)]


def test_no_unpinned_shared_data_root_stagers():
    """(success) Every shared-DATA_ROOT stager in the suite is worker-pinned."""
    found = {}
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        offenders = _offenders(path.read_text(encoding="utf-8", errors="replace"))
        if offenders:
            found[path.name] = offenders
    assert not found, (
        "these modules stage into the shared DATA_ROOT from a module-scoped "
        "fixture but are not pinned to one xdist worker, so a teardown on one "
        "worker deletes the file another worker is still reading — add "
        'pytest.mark.xdist_group("<module>") to pytestmark:\n'
        + "\n".join(f"  {mod}: {', '.join(fns)}" for mod, fns in found.items()))


def test_detector_fires_on_the_unpinned_shape():
    """(error) The detector is not vacuous: it flags the exact broken shape."""
    broken = (
        "import os, pytest\n"
        "from settings import DATA_ROOT\n"
        "@pytest.fixture(scope='module', autouse=True)\n"
        "def staged():\n"
        "    open(os.path.join(DATA_ROOT, 'x.bin'), 'wb').close()\n"
        "    yield\n"
        "    os.remove(os.path.join(DATA_ROOT, 'x.bin'))\n")
    assert _offenders(broken) == ["staged"]
    assert _offenders(broken + 'pytestmark = pytest.mark.xdist_group("g")\n') == []


def test_dedicated_roots_and_narrower_scopes_are_not_flagged():
    """(security-negative) The guard must not over-serialize the lane.

    A module with its own dedicated export root cannot race another worker over
    the shared one, and a function-scoped fixture gets a fresh copy per test.
    Flagging either would cost parallelism for no safety, so both stay clean.
    """
    dedicated = (
        "import os, pytest\n"
        "from settings import S3_MPU_DATA_ROOT\n"
        "@pytest.fixture(scope='module')\n"
        "def srv():\n"
        "    os.unlink(os.path.join(S3_MPU_DATA_ROOT, 'evil'))\n"
        "    yield\n")
    assert _offenders(dedicated) == []

    function_scoped = (
        "import os, pytest\n"
        "from settings import DATA_ROOT\n"
        "@pytest.fixture\n"
        "def staged(tmp_path):\n"
        "    yield\n"
        "    os.remove(os.path.join(DATA_ROOT, 'x.bin'))\n")
    assert _offenders(function_scoped) == []
