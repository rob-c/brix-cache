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

The second rule covers fixed-port lifecycle subjects.  A ``LifecycleHarness``
spec whose name is on the lifecycle ledger keeps its STABLE name and ledger
ports, so every worker that starts it shares one prefix, pidfile and listen
set.  When two tests of an ungrouped module start the same subject on two
workers at once, the loser's nginx fails bind(), the launcher adopts the
winner's live master, and the winner's ``close()`` then kills the instance out
from under the loser — ``ConnectionRefused`` mid-test, 5 runs in 6 for
``test_rate_limit_s3`` under ``-n3``.  The harness contract is that the owning
tests serialise with ``xdist_group``; this rule pins it for every subject that
more than one test starts (one starter per name cannot race itself).  A
``serial`` module is already pinned by the conftest and is not flagged.

Run:
    PYTHONPATH=tests pytest tests/test_suite_parallel_hygiene.py -v
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.xdist_group("suite-parallel-hygiene")]

TESTS_DIR = Path(__file__).resolve().parent

# The one shared export root every fleet instance serves.  Dedicated roots have
# their own names and are matched by identifier, never by substring.
SHARED_ROOT = "DATA_ROOT"
DELETERS = {"remove", "unlink", "rmtree"}

# Any of these marks pins a module's cells to one worker: an explicit group, the
# ``serial`` marker the conftest folds into the ``serial`` group, or a marker
# ``conftest_part3._needs_serial`` folds in the same way at collection
# (``privileged``, ``leak``).  The detector mirrors the conftest; race-hunt run
# 35 halted when a root-only module's subject joined the ledger and the
# detector, blind to the runtime pin, reported six unpinned starters.  Matched
# as ``pytest.mark.<name>`` in CODE, so a comment that merely mentions a group
# never counts as a pin.
RUNTIME_SERIAL_MARKS = {"privileged", "leak"}
PINNING_MARKS = {"xdist_group", "serial"} | RUNTIME_SERIAL_MARKS
# A split module exec's its helper into its own namespace, so a ``pytestmark``
# or fixture defined there belongs to the test module (same shape the conftest's
# interop-port scan follows).
_REEXPORT = re.compile(r"_?reexport\(\s*globals\(\)\s*,\s*[\"']([A-Za-z0-9_.]+)[\"']")


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


# --------------------------------------------------------------------------- #
# Rule 2 — fixed-port lifecycle subjects started by several tests are pinned  #
# --------------------------------------------------------------------------- #

def _module_source(path: Path) -> str:
    """The module's text plus every helper it ``reexport``s into itself."""
    text = path.read_text(encoding="utf-8", errors="replace")
    for name in _REEXPORT.findall(text):
        helper = path.with_name(name.rsplit(".", 1)[-1] + ".py")
        if helper.exists():
            text += "\n" + helper.read_text(encoding="utf-8", errors="replace")
    return text


def _is_fixture(node: ast.AST) -> bool:
    """True for ``@pytest.fixture`` in any spelling and any scope."""
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
        _decorator_name(d) == "fixture" or getattr(d, "attr", "") == "fixture"
        for d in node.decorator_list)


def _ledger_literals(node: ast.AST, ledger: set[str]) -> set[str]:
    """Lifecycle-ledger names spelled as string constants inside ``node``."""
    return {n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and n.value in ledger}


def _pinned(tree: ast.AST) -> bool:
    """True when the module carries ``pytest.mark.xdist_group`` / ``.serial``
    or a marker the conftest serialises at collection (``PINNING_MARKS``)."""
    return any(isinstance(n, ast.Attribute) and n.attr in PINNING_MARKS
               and getattr(n.value, "attr", "") == "mark"
               for n in ast.walk(tree))


def _names_started_by(test: ast.AST, by_fixture: dict[str, set[str]],
                      ledger: set[str], by_helper: dict[str, set[str]]) -> set[str]:
    """Subjects ``test`` starts: its own literals, its fixtures', its helpers'."""
    names = _ledger_literals(test, ledger)
    for arg in test.args.args:
        names |= by_fixture.get(arg.arg, set())
    for node in ast.walk(test):
        if isinstance(node, ast.Name):
            names |= by_helper.get(node.id, set())
    return names


def _param_cases(deco: ast.Call) -> int:
    """How many cases one ``@pytest.mark.parametrize`` decorator declares."""
    if len(deco.args) < 2 or not isinstance(deco.args[1], (ast.List, ast.Tuple)):
        return 0                             # computed argvalues: unknown, not 1
    return len(deco.args[1].elts)


def _item_count(test: ast.AST) -> int:
    """How many test ITEMS this function collects to.

    A parametrized function is ONE function and N items, and xdist hands items
    — not functions — to workers, so the two cases of a 2-way parametrize run
    concurrently on two workers exactly as two separate functions would.  The
    starter count must therefore be in items; counting functions is what let
    ``test_wlcg_conformance_proxy``'s single 2-way parametrized starter of the
    fixed-port ``lc-wlcg`` subject sit unpinned since the file was written.

    A parametrize whose argvalues are computed (a name, a call, a comprehension)
    contributes 0 cases, and 0 collapses the product to 0 — treated by the
    caller as "unknown, assume it can race" rather than silently as one item.
    """
    count = 1
    for deco in test.decorator_list:
        if _decorator_name(deco) == "parametrize":
            count *= _param_cases(deco)
    return count


def _functions(tree: ast.AST) -> list[ast.AST]:
    return [n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _fixture_subjects(functions: list[ast.AST], ledger: set[str]) -> dict[str, set[str]]:
    """fixture name -> the ledger subjects its body starts."""
    return {f.name: _ledger_literals(f, ledger) for f in functions if _is_fixture(f)}


def _subject_starters(tree: ast.AST, ledger: set[str],
                      by_helper: dict[str, set[str]]) -> dict[str, int]:
    """ledger name -> how many test ITEMS start it (directly, fixture, helper)."""
    functions = _functions(tree)
    by_fixture = _fixture_subjects(functions, ledger)
    imported = _imported_names(tree)
    visible = {n: s for n, s in by_helper.items() if n in imported}
    starters: dict[str, int] = {}
    for test in functions:
        if not test.name.startswith("test_"):
            continue
        items = _item_count(test)
        for name in _names_started_by(test, by_fixture, ledger, visible):
            starters[name] = starters.get(name, 0) + items
    return starters


def _unpinned_subjects(source: str, ledger: set[str],
                       by_helper: dict[str, set[str]] | None = None) -> dict[str, int]:
    """ledger name -> starter count, for every subject that can race itself.

    Empty when the module is pinned (group or serial), parses badly (another
    guard's problem), or starts each subject from at most one item.  A count of
    0 means a parametrize with computed argvalues: item count unknown, so it is
    reported rather than assumed safe.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    if _pinned(tree):
        return {}
    return {name: items
            for name, items in _subject_starters(tree, ledger, by_helper or {}).items()
            if items != 1}


def _imported_names(tree: ast.AST) -> set[str]:
    """Every bare name the module binds with ``import`` / ``from ... import``."""
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            bound |= {(alias.asname or alias.name).split(".")[0]
                      for alias in node.names}
    return bound


def _helper_subjects(ledger: set[str]) -> dict[str, set[str]]:
    """Exported helper name -> the ledger subjects CONSTRUCTING it claims.

    WHY this exists: rule 2 reads ledger names as string literals in the test
    module, and a subject claimed inside a helper CLASS is spelled nowhere the
    test module can see.  ``lc-wlcg`` is claimed in ``WlcgInstance.__init__``
    (brix_suite/mesh/wlcg_fleet.py), so the detector had never once seen it —
    the four hand-written ``xdist_group("lc-wlcg")`` pins were correct by
    authorship alone, and the fifth file that forgot one was never flagged.
    Silence from a guard that cannot see the subject is not evidence of a pin.

    HOW the port ledgers avoid poisoning this: only literals appearing INSIDE a
    top-level class or function body count.  ``fleet_ports_exclusive`` and its
    siblings spell every ledger name at module level in a dict, so they
    contribute nothing and no name is mapped to the whole ledger.
    """
    subjects: dict[str, set[str]] = {}
    for path in _helper_modules():
        for name, claimed in _module_claims(path, ledger).items():
            subjects.setdefault(name, set()).update(claimed)
    return subjects


def _helper_modules() -> list[Path]:
    """Every suite module that is a helper rather than a test module."""
    return [path for path in sorted(TESTS_DIR.rglob("*.py"))
            if not path.name.startswith("test_") and "_legacy" not in path.parts]


def _module_claims(path: Path, ledger: set[str]) -> dict[str, set[str]]:
    """Top-level name -> the ledger subjects its own body claims, for one file.

    A file the suite cannot parse contributes nothing rather than raising: this
    walk covers every helper module in the tree, and one unparseable file must
    not blind the detector to the rest of them.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return {}
    claims: dict[str, set[str]] = {}
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            claimed = _ledger_literals(node, ledger)
            if claimed:
                claims[node.name] = claimed
    return claims


def _lifecycle_ledger() -> set[str]:
    from fleet_lifecycle_ports import (  # noqa: PLC0415 — rebases on import
        LIFECYCLE_EXCLUSIVE_PORTS, LIFECYCLE_SHARED_PORTS)
    return set(LIFECYCLE_EXCLUSIVE_PORTS) | set(LIFECYCLE_SHARED_PORTS)


def test_no_unpinned_fixed_port_lifecycle_subjects():
    """(success) Every multi-starter lifecycle subject is worker-pinned."""
    ledger = _lifecycle_ledger()
    by_helper = _helper_subjects(ledger)
    found = {}
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        subjects = _unpinned_subjects(_module_source(path), ledger, by_helper)
        if subjects:
            found[path.name] = subjects
    assert not found, (
        "these modules start one fixed-port lifecycle subject from several "
        "tests without pinning them to one xdist worker, so two workers launch "
        "it on the same ports and one worker's close() kills the other's "
        'instance — add pytest.mark.xdist_group("<subject>") to pytestmark:\n'
        + "\n".join(f"  {mod}: {subjects}" for mod, subjects in found.items()))


def test_lifecycle_detector_fires_on_the_unpinned_shape():
    """(error) The detector flags the shape that raced: one function-scoped
    fixture starting a ledger subject, shared by two tests."""
    broken = (
        "import pytest\n"
        "@pytest.fixture\n"
        "def srv():\n"
        "    start('lc-fake')\n"
        "    yield\n"
        "def test_a(srv): pass\n"
        "def test_b(srv): pass\n")
    assert _unpinned_subjects(broken, {"lc-fake"}) == {"lc-fake": 2}
    # A comment that only talks about the pin is not a pin.
    assert _unpinned_subjects(
        broken + "# xdist_group: see the sibling module\n", {"lc-fake"}) == {"lc-fake": 2}
    assert _unpinned_subjects(
        broken + 'pytestmark = pytest.mark.xdist_group("g")\n', {"lc-fake"}) == {}
    assert _unpinned_subjects(
        broken + "pytestmark = pytest.mark.serial\n", {"lc-fake"}) == {}
    # A marker the conftest folds into ``serial`` at collection pins the same
    # way (run 35: a root-only module's subject joined the ledger); a comment
    # naming that marker does not.
    assert _unpinned_subjects(
        broken + "pytestmark = [pytest.mark.privileged]\n", {"lc-fake"}) == {}
    assert _unpinned_subjects(
        broken + "# privileged: root only, serial in practice\n", {"lc-fake"}) == {"lc-fake": 2}


def test_runtime_serial_marks_mirror_the_conftest():
    """(success) Every runtime pin the detector honours is one the conftest
    actually folds into ``serial`` — ``conftest_part3._needs_serial`` is the
    authority, and a mark dropped there must drop here too."""
    source = (TESTS_DIR / "conftest_part3.py").read_text(encoding="utf-8")
    body = source.split("def _needs_serial(", 1)[1].split("\ndef ", 1)[0]
    for mark in RUNTIME_SERIAL_MARKS:
        assert f'get_closest_marker("{mark}")' in body, (
            f"{mark!r} is in PINNING_MARKS but conftest_part3._needs_serial "
            "no longer serialises it: the detector would call an unpinned "
            "module pinned")


def test_single_starters_and_split_helpers_are_not_flagged():
    """(security-negative) The guard must not over-serialize the lane.

    One starter per subject cannot race itself, a ledger name that no test
    starts is inert, and a split module whose pin lives in its reexported
    helper is already serialised — none of these may cost parallelism.
    """
    one_each = (
        "import pytest\n"
        "def test_a(lifecycle): start(lifecycle, 'lc-one')\n"
        "def test_b(lifecycle): start(lifecycle, 'lc-two')\n")
    assert _unpinned_subjects(one_each, {"lc-one", "lc-two"}) == {}

    inert = "NAME = 'lc-one'\ndef test_a(): pass\ndef test_b(): pass\n"
    assert _unpinned_subjects(inert, {"lc-one"}) == {}

    split = TESTS_DIR / "test_cms_parity_wave.py"
    assert "xdist_group" not in split.read_text(encoding="utf-8")
    assert "xdist_group" in _module_source(split)


# --------------------------------------------------------------------------- #
# Rule 2 blind spots — a subject claimed in a helper, and items vs functions  #
# --------------------------------------------------------------------------- #

def test_helper_claimed_subjects_are_visible_to_the_detector():
    """(success) The real ``lc-wlcg`` claim inside ``WlcgInstance`` is seen.

    This is the anti-vacuity row for the helper map.  Before it existed the
    detector read ledger names only as literals in ``test_*.py``, and ``lc-wlcg``
    is spelled once, in ``WlcgInstance.__init__`` — so rule 2 was silent on five
    modules it could not see, and one of them was genuinely unpinned.  The row
    also pins the exclusion that keeps the map honest: the port ledgers spell
    every subject at module level, and must contribute no exported name at all.
    """
    ledger = _lifecycle_ledger()
    by_helper = _helper_subjects(ledger)
    assert by_helper.get("WlcgInstance") == {"lc-wlcg"}, (
        "WlcgInstance no longer claims lc-wlcg where this guard reads it — "
        "every wlcg conformance module would go back to being invisible")

    ledger_module = ast.parse((TESTS_DIR / "fleet_ports_exclusive.py")
                              .read_text(encoding="utf-8"))
    for node in ledger_module.body:
        name = getattr(node, "name", None)
        assert name not in by_helper, (
            f"{name} in the port ledger contributed subjects to the helper map: "
            "a module-level ledger dict must never map a name to the whole ledger")


def test_detector_counts_items_not_functions():
    """(error) A parametrized starter is N items, and the detector says N."""
    one_function = (
        "import pytest\n"
        "@pytest.mark.parametrize('case', ['a', 'b'])\n"
        "def test_a(case): start('lc-fake')\n")
    assert _unpinned_subjects(one_function, {"lc-fake"}) == {"lc-fake": 2}
    # One case is one item and cannot race itself.
    assert _unpinned_subjects(
        one_function.replace("['a', 'b']", "['a']"), {"lc-fake"}) == {}
    # Computed argvalues: the count is unknowable statically, so it is reported
    # (0) rather than silently assumed to be a single safe item.
    assert _unpinned_subjects(
        one_function.replace("['a', 'b']", "CASES"), {"lc-fake"}) == {"lc-fake": 0}
    # Stacked parametrize decorators multiply, as pytest does.
    stacked = (
        "import pytest\n"
        "@pytest.mark.parametrize('x', [1, 2])\n"
        "@pytest.mark.parametrize('y', [1, 2, 3])\n"
        "def test_a(x, y): start('lc-fake')\n")
    assert _unpinned_subjects(stacked, {"lc-fake"}) == {"lc-fake": 6}


def test_helper_credit_requires_a_real_import():
    """(security-negative) The helper map must not flag modules by mere mention.

    Crediting a test module with a helper's subject on a name match alone would
    serialise any module that happens to spell the identifier — in a comment, a
    docstring, or as its own unrelated local.  Only a module that actually binds
    the name by import can be running the helper's instance, so only that module
    may lose parallelism to it.
    """
    helper = {"WlcgInstance": {"lc-wlcg"}}
    imported = (
        "from wlcg_fleet import WlcgInstance\n"
        "def test_a(): WlcgInstance('a')\n"
        "def test_b(): WlcgInstance('b')\n")
    assert _unpinned_subjects(imported, {"lc-wlcg"}, helper) == {"lc-wlcg": 2}

    mentioned = (
        "# WlcgInstance is what the sibling module drives\n"
        '"""Two tests, no WlcgInstance."""\n'
        "def test_a(): pass\n"
        "def test_b(): pass\n")
    assert _unpinned_subjects(mentioned, {"lc-wlcg"}, helper) == {}

    shadowed = (
        "def WlcgInstance(prefix): return prefix\n"
        "def test_a(): WlcgInstance('a')\n"
        "def test_b(): WlcgInstance('b')\n")
    assert _unpinned_subjects(shadowed, {"lc-wlcg"}, helper) == {}
