"""TS-4 item 7 — the catalogue merge, pinned.

``fleet_specs.py`` + ``fleet_specs_part2.py`` + ``fleet_values.py`` became the
:mod:`brix_suite.catalogue` package.  Three things have to stay true:

* the three flat names and the package are ONE namespace — the fleet is a
  singleton and two namespaces would mean two fleets;
* the move was verbatim apart from two enumerated deviations, so a reviewer
  can trust that no spec quietly changed shape while crossing the seam;
* ``import fleet_specs_part2`` works, which it never did before — the shard
  was ``exec``'d into its parent's globals and raised ``NameError`` on its
  own (testsuite-modernization-plan §2.3).

Guard #3 (``check_shim_completeness.py``) already pins the *names*; this file
pins the *identity*, the *bytes*, and the behaviour under the import spellings
the tree actually uses.
"""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys

import pytest

def _check_test_the_legacy_archives_are_inert_1(present, archives):
    assert set(archives) <= present, sorted(set(archives) - present)

def _check_test_the_legacy_archives_are_inert_2(importers):
    assert importers == []


TESTS = pathlib.Path(__file__).resolve().parent
SRC = TESTS.parent / "brixtest" / "src"
CATALOGUE = TESTS / "brix_suite" / "catalogue"
LEGACY = TESTS / "brix_suite" / "_legacy"

#: The catalogue mutates ``brix_suite.registry._SPECS``.  Every probe therefore
#: runs in a child process: a test that registered the whole fleet into this
#: session's registry would hand the next test a fleet it did not ask for.
_PREAMBLE = "import sys; sys.path.insert(0, %r); sys.path.insert(0, %r)\n" % (
    str(TESTS), str(SRC))


#: The catalogue's size when it crossed the seam (TS-4, 2026-08-18).  A FLOOR,
#: not the current count: the catalogue is the living fleet table and grows
#: with every phase that adds a server (phase-115 W4.2 added ``ram-cache`` on
#: 2026-09-06, and the first lane to reach this file afterwards halted on four
#: copies of the literal 126).  A count below the floor is a lost spec; the
#: live count is read from the catalogue inside each probe, so one fact has
#: one home.
SPECS_AT_THE_MOVE = 126

#: Top-level definitions that are allowed to differ from the flat archive, with
#: the reason each one stopped being verbatim.  The archive is a fossil of the
#: move; the catalogue is live, so this ledger grows by one line per definition
#: the tree edits after the move — never by editing the archive to match.
DEVIATIONS = {
    # was dirname(abspath(__file__)); after the move that names the package,
    # not the flat tests/ tree (the TS-3 TESTS_DIR / TS-4 _caller_site class).
    "_TESTS_DIR",
    # imports _SPECS from the canonical registry, not via the server_registry shim.
    "register_full_fleet",
    # TS-5 servers-cluster: four stubs spawn python -m brix_suite.servers.* and
    # carry the PYTHONPATH that -m needs, instead of a path under tests/lib/.
    "support_specs",
    # phase-115 W4.2 (2026-09-06): the read-through shape over a RAM cache
    # store (`ram-cache`, nginx_ram_cache.conf) joined the dedicated fleet.
    "dedicated_specs",
    # Alma9 dynamic nginx keeps libkrb5 in the selected BriX module, so the
    # capability gate checks configured modules as well as the frozen binary.
    "_nginx_has_krb5",
}


def _probe(code: str) -> str:
    proc = subprocess.run([sys.executable, "-c", _PREAMBLE + code],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _toplevel_defs(path: pathlib.Path) -> dict:
    """Map top-level name -> its exact source text, functions and assignments."""
    source = path.read_text()
    found = {}
    for node in ast.parse(source).body:
        found.update(_definition_source(source, node))
    return found


def _definition_source(source, node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return {node.name: ast.get_source_segment(source, node)}
    if not isinstance(node, ast.Assign):
        return {}
    return {
        target.id: ast.get_source_segment(source, node)
        for target in node.targets
        if isinstance(target, ast.Name)
    }


def _flat_defs() -> dict:
    merged = {}
    for name in ("fleet_specs_flat.py", "fleet_specs_part2_flat.py",
                 "fleet_values_flat.py"):
        merged.update(_toplevel_defs(LEGACY / name))
    return merged


def _imported_names(path: pathlib.Path) -> set:
    """Names one module binds by ``from … import``, as the module sees them."""
    return {alias.asname or alias.name
            for node in ast.parse(path.read_text()).body
            if isinstance(node, ast.ImportFrom)
            for alias in node.names}


def _package_imported_names() -> set:
    """Names the catalogue binds by import, not by definition.

    ``_TESTS_DIR`` is the case: an assignment in the archive, an import from
    ``brix_suite.settings`` in the package.  The definition scanner cannot see
    it, so a presence check that ignored imports would call it deleted.
    """
    return set().union(*(_imported_names(p) for p in CATALOGUE.glob("*.py")))


def _package_defs() -> dict:
    merged = {}
    for path in sorted(CATALOGUE.glob("*.py")):
        for name, text in _toplevel_defs(path).items():
            merged.setdefault(name, text)
    return merged


# ---------------------------------------------------------------------------
# success


def test_the_shard_imports_on_its_own_now():
    """The §2.3 breakage, fixed.

    Before the merge this raised ``NameError: name '_data' is not defined``:
    ``ha_specs`` was compiled into ``fleet_specs``'s globals and closed over
    names its own file never imported.
    """
    assert _probe("import fleet_specs_part2 as p; print(len(p.ha_specs()))") == "3"


@pytest.mark.parametrize("order", [
    "import fleet_specs, fleet_specs_part2; import brix_suite.catalogue as c",
    "import fleet_specs_part2, fleet_specs; import brix_suite.catalogue as c",
    "import brix_suite.catalogue as c; import fleet_specs, fleet_specs_part2",
])
def test_all_three_names_are_one_module_in_any_import_order(order):
    out = _probe(order + "\nprint(fleet_specs is c, fleet_specs_part2 is c)")
    assert out == "True True"


def test_fleet_values_resolves_to_the_values_submodule():
    out = _probe("import fleet_values as v; import brix_suite.catalogue.values as w\n"
                 "print(v is w, len(v.session_template_values()) > 0)")
    assert out == "True True"


def test_the_move_was_verbatim_apart_from_the_named_deviations():
    """Every moved definition is byte-identical, or is in ``DEVIATIONS``.

    A post-move edit to the catalogue lands here first: the fix is one ledger
    line naming the definition and why, not a mirror edit into ``_legacy/``
    (the archive is inert by the test below and must stay a fossil).
    """
    flat, package = _flat_defs(), _package_defs()
    changed = {name for name, text in flat.items()
               if package.get(name) != text}
    assert changed == DEVIATIONS, (
        "verbatim-move violation, add a DEVIATIONS line or revert: %s"
        % sorted(changed - DEVIATIONS)
        if changed - DEVIATIONS else
        "a known deviation stopped deviating: %s" % sorted(DEVIATIONS - changed))
    # The floor exists to catch the way this test could pass while proving
    # nothing: `_flat_defs()` returning an empty mapping makes `changed` empty
    # too.  Pin the archive's size, not the verbatim remainder — the remainder
    # legitimately shrinks by one each time a deviation is declared above, so
    # a floor on it is a ratchet that would have to be loosened on purpose.
    assert len(flat) >= 19


def test_the_topic_split_lost_no_specs():
    out = _probe(
        "import brix_suite.catalogue as c\n"
        "print(len(c.core_specs()), len(c.xrootd_backend_specs()),"
        " len(c.support_specs()), len(c.dedicated_specs()), len(c.ha_specs()),"
        " len(c._all_specs()))")
    parts = [int(n) for n in out.split()]
    assert sum(parts[:-1]) == parts[-1]
    assert parts[-1] >= SPECS_AT_THE_MOVE


def test_every_catalogue_module_is_under_the_size_line():
    """The reason this is a package and not one 876-line file."""
    oversized = {p.name: len(p.read_text().splitlines())
                 for p in CATALOGUE.glob("*.py")
                 if len(p.read_text().splitlines()) > 600}
    assert not oversized, oversized


# ---------------------------------------------------------------------------
# error


def test_a_named_deviation_still_exists_on_both_sides():
    """The ledger excuses a changed definition, never a missing one.

    ``package.get(name) != text`` is also true when ``name`` is absent from the
    package, so deleting ``register_full_fleet`` from the catalogue would have
    read as "still deviating" and the verbatim pin would have stayed green.
    """
    flat = _flat_defs()
    package = set(_package_defs()) | _package_imported_names()
    missing = {name: (name in flat, name in package)
               for name in DEVIATIONS
               if name not in flat or name not in package}
    assert missing == {}, "stale DEVIATIONS entry (in archive, in package): %s" % missing


def test_the_exec_mechanism_is_gone():
    """No module in the catalogue may reach for ``split_continuation``.

    The shard mechanism is what made the standalone import fail; reintroducing
    it would reintroduce the bug behind a passing name check.
    """
    users = [p.name for p in CATALOGUE.glob("*.py")
             if "split_continuation" in p.read_text()]
    assert users == []
    assert "_load_continuations" not in (TESTS / "fleet_specs.py").read_text()


def test_registering_the_fleet_twice_is_a_no_op_not_an_error():
    out = _probe(
        "import fleet_specs\n"
        "from brix_suite.registry import registered_specs\n"
        "fleet_specs.register_full_fleet(); first = len(registered_specs())\n"
        "fleet_specs.register_full_fleet(); second = len(registered_specs())\n"
        "print(first, second, len(fleet_specs._all_specs()))")
    first, second, catalogue = (int(n) for n in out.split())
    assert first == second == catalogue
    assert catalogue >= SPECS_AT_THE_MOVE


def test_the_merged_fleet_declares_no_conflicting_ports():
    """A merge that duplicated a block would surface here, not in a soak."""
    out = _probe(
        "import fleet_specs\n"
        "from brix_suite.registry import port_conflicts, registered_specs\n"
        "fleet_specs.register_full_fleet()\n"
        "print(len(port_conflicts(registered_specs())))")
    assert out == "0"


# ---------------------------------------------------------------------------
# security-negative


def test_idempotence_is_the_catalogue_skipping_not_the_registry_going_soft():
    """A genuine duplicate must still be refused.

    ``register_full_fleet`` skips names it already placed.  If that skip had
    been implemented by relaxing the registry instead, two specs could claim
    one name and the second would silently win — the port they disagree on
    would be discovered by whichever server failed to bind.
    """
    out = _probe(
        "import fleet_specs\n"
        "from brix_suite.registry import register_nginx, registered_specs\n"
        "fleet_specs.register_full_fleet()\n"
        "dup = registered_specs()[0]\n"
        "try:\n"
        "    register_nginx(dup)\n"
        "    print('ACCEPTED')\n"
        "except Exception as exc:\n"
        "    print(type(exc).__name__, dup.name in str(exc))")
    kind, named = out.split()
    assert kind != "ACCEPTED"
    assert named == "True"


def test_registering_through_one_flat_name_is_visible_through_the_other():
    """One namespace means one fleet — the whole reason for the §10.2 shim."""
    out = _probe(
        "import fleet_specs_part2\n"
        "fleet_specs_part2.register_full_fleet()\n"
        "import fleet_specs, server_registry\n"
        "print(fleet_specs is fleet_specs_part2,"
        " len(server_registry.registered_specs()), len(fleet_specs._all_specs()))")
    same, registered, catalogue = out.split()
    assert same == "True"
    assert int(registered) == int(catalogue) >= SPECS_AT_THE_MOVE


def test_the_legacy_archives_are_inert():
    """Dead bytes kept for review must never become live imports.

    ``fleet_specs_flat.py`` still contains the pre-move body; if something
    imported it, the tree would hold two catalogues that drift apart silently.
    """
    # This file's three, named rather than globbed: `_legacy/` accumulates an
    # archive per moved module across the whole of TS-4, and a directory
    # listing would turn every later item into a failure here.  Each triad
    # checks the archives it created.
    archives = ["fleet_specs_flat", "fleet_specs_part2_flat", "fleet_values_flat"]
    present = {p.stem for p in LEGACY.glob("*_flat.py")}
    _check_test_the_legacy_archives_are_inert_1(present, archives)

    # Spelled as import statements, not as a substring: "_flat" on its own
    # matches ``_flatten`` in a dozen unrelated tests.
    importers = sorted(
        p.name for p in TESTS.rglob("*.py")
        if LEGACY not in p.parents
        and any(("import %s" % stem) in p.read_text() for stem in archives))
    _check_test_the_legacy_archives_are_inert_2(importers)
