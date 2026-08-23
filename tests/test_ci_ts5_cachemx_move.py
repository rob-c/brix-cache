"""TS-5, the cachemx cluster: the metric-conformance plumbing thirty suites share.

Five modules moved one-to-one out of the flat ``tests/`` tree into
:mod:`brix_suite.cachemx` — the private lifecycle stack and its plane drivers
(``_cachemx``), the exposition parser the grid suites scrape through
(``_cachemx_grid``), the two calibrated catalogue snapshots
(``_cachemx_catalog_data`` / ``_cachemx_catalog_schema``) and the partial-fill
and ``.cinfo`` readers (``_cache_partial_helpers``).

Three things decided what is tested here, and each is a way this move could
have looked fine and been wrong.

1. **Both ``__file__`` hops resolved to a directory that exists.**  ``_cachemx``
   and ``_cache_partial_helpers`` each derived the repo as two parents up from
   themselves, to reach the native clients at ``client/bin/``.  Two parents from
   ``tests/`` was the repo; two parents from ``tests/brix_suite/cachemx/`` is
   ``tests/brix_suite`` — a real directory, so nothing raises and no import
   fails.  ``_cachemx._require_binaries()`` would then have skipped the whole
   suite with *"native client binary missing"*, which reads as a host without a
   built client, and ``_cache_partial_helpers`` would have handed
   ``subprocess.run`` a path that is not there.  Both now come from
   :data:`brix_suite.settings.TESTS_DIR`, and the tests below re-evaluate the
   old expression from the new location to show what it would have produced.
   That is a demonstration, not an assertion about the fix: the point is that
   the wrong answer is a directory that *exists*, so "does it still import"
   could never have caught it.

2. **Nothing here may be started.**  ``_cachemx.start_stack()`` boots an origin
   plus a multi-plane cache matrix on the *fixed* shared-band ports in
   ``fleet_lifecycle_ports``, which is why every consuming file pins
   ``xdist_group("lc-cachemx")``.  A gate that started one would collide with a
   live suite — this run's or another session's — so the stack is exercised only
   on paths that return before a daemon exists.

3. **Two of the five are pure data.**  A snapshot dict that lost half its rows
   in a copy still imports, still has the right name and still passes any
   "does it resolve" check.  So the two catalogue modules are checked against
   each other for the invariants that bind them, not merely for existence.

The verbatim-move check is an AST body hash against ``brix_suite/_legacy/``.
It compares def/class bodies only, which is exactly right here: the fixes are
module-level constants and import lines, so every body must still hash
identically and any body that drifted cannot be argued away.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import os
import pathlib
import subprocess
import sys

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
REPO = TESTS.parent
CACHEMX = TESTS / "brix_suite" / "cachemx"
LEGACY = TESTS / "brix_suite" / "_legacy"

pytestmark = pytest.mark.timeout(120)

#: Every module in the cluster.  All five are plain modules — unlike the mesh
#: cluster there are no exec-composed shards here, so flat name and canonical
#: name line up one to one.
MODULES = [
    "_cachemx",
    "_cachemx_grid",
    "_cachemx_catalog_data",
    "_cachemx_catalog_schema",
    "_cache_partial_helpers",
]

#: The two that named the repo from their own location, and the constant each
#: derived from it.  Both are what makes this move worth a gate.
HOPPERS = [("_cachemx", "XRDCP"), ("_cache_partial_helpers", "XRDCINFO")]

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _walk_bodies(node, prefix):
    for child in node.body:
        if not isinstance(child, _DEFS):
            continue
        name = prefix + child.name
        blob = "".join(ast.dump(item, include_attributes=False)
                       for item in child.body)
        yield name, hashlib.sha256(blob.encode()).hexdigest()
        if isinstance(child, ast.ClassDef):
            yield from _walk_bodies(child, name + ".")


def _bodies(path: pathlib.Path) -> dict:
    """Hash every def/class body by its position-independent qualified name."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return dict(_walk_bodies(tree, ""))


def _suite_env(extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(TESTS), str(REPO / "brixtest" / "src"),
         env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    env["TEST_SKIP_SERVER_SETUP"] = "1"
    env.update(extra or {})
    return env


def _child(code, env_extra=None, timeout=90):
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, timeout=timeout, env=_suite_env(env_extra))


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", MODULES)
def test_every_flat_spelling_is_the_package_object(name):
    """``X`` and ``brix_suite.cachemx.X`` must be ONE module object.

    ``_cachemx`` is why this is a rule rather than a nicety: it holds the
    module-scoped stack the whole suite drives.  Two objects would mean two
    stacks, each believing it owns the same fixed ports, and a teardown walking
    bookkeeping the other half wrote.
    """
    out = _child(
        "import importlib\n"
        "a = importlib.import_module('%s')\n"
        "b = importlib.import_module('brix_suite.cachemx.%s')\n"
        "print(a is b, a.__name__)\n" % (name, name))
    assert out.returncode == 0, out.stderr
    same, mod = out.stdout.split()
    assert same == "True", "%s is a second object: %s" % (name, out.stdout)
    assert mod == "brix_suite.cachemx." + name


@pytest.mark.parametrize("name", MODULES)
def test_the_move_was_verbatim(name):
    """Every def/class body must hash identically to its archive."""
    before = _bodies(LEGACY / (name + "_flat.py"))
    after = _bodies(CACHEMX / (name + ".py"))
    assert sorted(before) == sorted(after), (
        "%s: definitions differ: added %s, lost %s"
        % (name, sorted(set(after) - set(before)),
           sorted(set(before) - set(after))))
    changed = [k for k in before if before[k] != after[k]]
    assert not changed, (
        "%s: bodies changed in a verbatim move: %s" % (name, changed))


@pytest.mark.parametrize("name,const", HOPPERS, ids=[n for n, _ in HOPPERS])
def test_the_native_clients_are_named_under_the_repo(name, const):
    """The constant must land on the real ``client/bin`` tree.

    Asserted as *is the binary there*, not as *does the string look right*: the
    consuming code only ever passes it to ``os.path.exists`` or straight into
    ``subprocess.run``, so a path that merely resembles the repo is the same
    failure as one that does not.
    """
    out = _child(
        "import importlib, os\n"
        "m = importlib.import_module('brix_suite.cachemx.%s')\n"
        "p = m.%s\n"
        "print(p, os.path.exists(p))\n" % (name, const))
    assert out.returncode == 0, out.stderr
    path, exists = out.stdout.split()
    assert path == str(REPO / "client" / "bin" / pathlib.Path(path).name), (
        "%s.%s no longer names the repo's client tree: %s" % (name, const, path))
    assert exists == "True", "%s.%s points at nothing: %s" % (name, const, path)


def test_the_grid_parser_shares_the_one_stack_module():
    """``_cachemx_grid.cx`` must be the same object as ``_cachemx``.

    The grid suites scrape through the parser and assert against counters the
    stack moved.  A second ``cx`` would parse one server's exposition while the
    assertions were written against another's.
    """
    out = _child(
        "import brix_suite.cachemx._cachemx_grid as g\n"
        "import brix_suite.cachemx._cachemx as cx\n"
        "print(g.cx is cx)\n")
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "True", "the grid parser bound a second stack"


def test_the_two_catalogue_snapshots_still_describe_the_same_families():
    """HELP and LABEL_KEYS must cover one family set, and CONDITIONAL be a subset.

    This is the check that a truncated copy cannot pass.  Both modules are
    literal dicts with no imports and no code, so every other property of the
    move — it resolves, it is one object, its bodies match (it has none) — holds
    just as well for half a file.
    """
    import _cachemx_catalog_data as data
    import _cachemx_catalog_schema as schema

    help_families = set(data.HELP)
    key_families = set(schema.LABEL_KEYS)
    assert help_families == key_families, (
        "the snapshots disagree: HELP-only %s, LABEL_KEYS-only %s"
        % (sorted(help_families - key_families)[:5],
           sorted(key_families - help_families)[:5]))
    assert help_families, "both snapshots are empty — the copy lost everything"
    assert schema.CONDITIONAL <= key_families, (
        "CONDITIONAL names families the schema does not: %s"
        % sorted(schema.CONDITIONAL - key_families))


def test_importing_the_package_does_not_start_or_import_the_stack():
    """``import brix_suite.cachemx`` must not drag ``_cachemx`` in.

    The package docstring promises this and the promise is load-bearing: the
    stack module builds specs against fixed shared-band ports at import, so any
    tool that touches the package for its own reasons would pay for a subsystem
    it is not using.
    """
    out = _child(
        "import sys, brix_suite.cachemx\n"
        "print(sorted(m for m in sys.modules if m.startswith('brix_suite.cachemx.')))\n")
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]", (
        "importing the package pulled in submodules: %s" % out.stdout.strip())


def _flat_imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            used.update(alias.name for alias in node.names if alias.name in MODULES)
        if isinstance(node, ast.ImportFrom) and node.module in MODULES:
            used.add(node.module)
    return used


def _consumer_paths():
    current = pathlib.Path(__file__).name
    return (path for path in sorted(TESTS.glob("*.py")) if path.name != current)


def test_every_consumer_of_the_flat_spelling_still_imports_it():
    """The flat names the thirty-odd suites use must resolve, from ``tests/``.

    Enumerated from the tree rather than written down, so a suite that starts
    importing one of these is covered the day it does.
    """
    used = set().union(*(_flat_imports(path) for path in _consumer_paths()))
    assert used, "no flat consumer found — this check has gone blind"
    out = _child("import importlib\n"
                 "for n in %r:\n"
                 "    importlib.import_module(n)\n"
                 "print('ok')\n" % sorted(used))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ok"


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

def test_a_missing_client_binary_skips_naming_the_path_it_wanted():
    """``_require_binaries`` must say *which* path was absent.

    This is the message that would have been the entire visible symptom of the
    unfixed hop, so it has to carry the path — "native client missing" alone
    would have sent a reader looking at their build instead of at this move.

    Caught as ``pytest.skip.Exception`` deliberately.  ``Skipped`` derives from
    ``BaseException``, so ``pytest.raises(Exception)`` does not catch it: the
    skip escapes and becomes *this test's* outcome, and the file reports a green
    ``1 skipped`` for a check that asserted nothing.  Written that way first,
    which is why the ``ran`` flag below exists — it fails loudly if the body
    ever stops reaching its assertions again.
    """
    import _cachemx as cx

    bogus = str(TESTS / "no-such-tree" / "bin" / "xrdcp")
    saved = cx.XRDCP
    cx.XRDCP = bogus
    ran = False
    try:
        with pytest.raises(pytest.skip.Exception) as excinfo:
            cx._require_binaries()
        ran = True
    finally:
        cx.XRDCP = saved
    assert ran, "the skip was not caught here"
    assert bogus in str(excinfo.value), (
        "the skip does not name the path: %s" % excinfo.value)


def test_the_package_spelling_needs_the_suite_root_on_the_path():
    """Without ``tests/`` on ``sys.path`` the import must fail loudly.

    ``_cachemx`` imports ``settings``, ``server_launcher`` and
    ``metrics_helpers`` by their flat spellings — they have not moved — so the
    package is not self-contained and must not pretend to be.  A silent partial
    import here would be worse than the ImportError.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "brixtest" / "src")
    env["TEST_SKIP_SERVER_SETUP"] = "1"
    out = subprocess.run(
        [sys.executable, "-c", "import brix_suite.cachemx._cachemx"],
        capture_output=True, text=True, timeout=90, env=env, cwd=str(REPO))
    assert out.returncode != 0, "the import succeeded without the suite root"
    assert "ModuleNotFoundError" in out.stderr, out.stderr


def test_a_cinfo_read_of_an_absent_record_reports_absent_not_a_crash():
    """The sidecar/xattr reader must return ``{'absent': True}``, not raise.

    Exercised against a real ``xrdcinfo`` on an empty directory, which is the
    one path through ``_cache_partial_helpers`` that runs a native client
    without a server — and therefore the only way to prove from a gate that its
    ``REPO`` now points somewhere executable.
    """
    import _cache_partial_helpers as cph

    if not os.path.exists(cph.XRDCINFO):
        pytest.skip("xrdcinfo not built at %s" % cph.XRDCINFO)
    got = cph.residency(str(TESTS), "definitely-not-a-cached-object")
    assert got == {"absent": True}, (
        "an absent record read back as %r" % (got,))


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,const", HOPPERS, ids=[n for n, _ in HOPPERS])
def test_the_old_hop_would_have_named_a_real_but_wrong_directory(name, const):
    """Demonstrate the hazard, do not merely assert the fix.

    Re-evaluate ``dirname(dirname(abspath(__file__)))`` from the module's NEW
    location.  The result must be a directory that exists — that is the whole
    point, since an exception would have made this move self-announcing — and
    must not be the repo, and must not hold the client tree the constant needs.
    """
    moved = CACHEMX / (name + ".py")
    would_be = os.path.dirname(os.path.dirname(os.path.abspath(str(moved))))

    assert os.path.isdir(would_be), (
        "the premise of this test is gone: %s no longer exists, so the old hop "
        "would have raised and the hazard would have been loud" % would_be)
    assert would_be != str(REPO), (
        "the old hop still lands on the repo — %s did not actually move" % name)
    assert not os.path.exists(os.path.join(would_be, "client", "bin")), (
        "%s now holds a client tree; the wrong answer has become plausible and "
        "this demonstration no longer demonstrates anything" % would_be)


def _imported_names(node) -> set[str]:
    return {(alias.asname or alias.name).split(".")[0] for alias in node.names}


def _bound_name(node) -> set[str]:
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return _imported_names(node)
    if isinstance(node, _DEFS):
        return {node.name}
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
        return {node.id}
    if isinstance(node, ast.arg):
        return {node.arg}
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return set(node.names)
    if isinstance(node, ast.ExceptHandler) and node.name:
        return {node.name}
    return set()


def _missing_names(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bound = set().union(*(_bound_name(node) for node in ast.walk(tree)))
    free = {node.id for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
    implicit = {"__file__", "__name__"}
    return sorted(free - bound - set(vars(builtins)) - implicit)


def test_no_module_reaches_a_name_it_never_binds():
    """No free name in the moved cluster is unresolvable.

    A move that drops an import line still parses, still imports where the
    dropped name is only used on an error path, and fails much later.  Scanning
    for names that are neither bound in the module, imported by it, nor a
    builtin catches that at rest.
    """
    found = ((name, _missing_names(CACHEMX / (name + ".py"))) for name in MODULES)
    problems = {name: missing for name, missing in found if missing}
    assert not problems, "unbound names after the move: %s" % problems


@pytest.mark.parametrize("name", MODULES)
def test_the_flat_spelling_kept_no_body_of_its_own(name):
    """A shim must forward, never carry a copy.

    Two copies of ``_cachemx`` would each build a stack for the same fixed
    ports; two copies of a catalogue snapshot would drift silently and be
    argued over. So the flat file must define nothing at all.
    """
    tree = ast.parse((TESTS / (name + ".py")).read_text(encoding="utf-8"))
    defined = [n.name for n in tree.body if isinstance(n, _DEFS)]
    assert not defined, (
        "%s.py still defines %s — it is a fork, not a shim" % (name, defined))
    body = (TESTS / (name + ".py")).read_text(encoding="utf-8")
    assert "_sys.modules[__name__] = _canonical" in body, (
        "%s.py does not self-replace; the two spellings are two objects" % name)
