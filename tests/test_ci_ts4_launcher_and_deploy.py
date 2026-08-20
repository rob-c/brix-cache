"""TS-4 item 4 — the launcher package, and why it is not wired in yet.

`brix_suite/launcher/` holds the composed `RegistryLauncher`: the six flat
`server_launcher*` modules moved into five topic modules with ordinary
imports instead of the `exec` chain.  It is **built and pinned but not
installed** — `server_launcher.py` is still the live module and no §10.2
shim points at the package.

The reason is measured, not stylistic, and the last test in this file is
the measurement.  The pinning suite rebinds names *in the launcher's
module dict* (`monkeypatch.setattr("server_launcher.Path", …)`, and the
same for `REGISTRY_STRICT_TEMPLATES`).  That works only while every method
of the class reads its globals out of one shared dict, which is what the
`exec` composition gave it.  Split into real modules, a rebind on the
package is invisible to the topic module that actually runs the code — so
installing the shim would break `test_server_registry_smoke.py` and
`test_fleet_port_uniqueness.py`, and NG1 forbids editing either before
TS-7.  It is the same patch-transparency property that kept `conftest.py`
parts 2/3/5 exec-composed at TS-2.

So this file pins the package as *ready*: same MRO, same methods,
byte-for-byte, plus the deploy-seam conformance that item 4's second half
asks for.  TS-7 flips it on and deletes the last test here.
"""

from __future__ import annotations

import ast
import pathlib
import sys

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
SRC = TESTS.parent / "brixtest" / "src"
LEGACY = TESTS / "brix_suite" / "_legacy"
PKG = TESTS / "brix_suite" / "launcher"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

#: live flat module -> the topic module holding the same bodies.
#:
#: Compared against the *live* flat tree, not the frozen `_legacy` archives.
#: The archives record what the move started from and are checked for
#: inertness further down; but the package is built and not yet installed,
#: so the invariant that actually matters between now and TS-7 is that it
#: has not drifted from the module the fleet really runs.  TS-4 item 5
#: flipped four kind ladders in the flat mixins after this package was
#: built, and pointing the comparison at the archives would have let that
#: divergence sit there until TS-7 installed a launcher missing them.
_MOVES = {
    "_server_launcher_part2_mixina.py": "start.py",
    "_server_launcher_part2_mixinb.py": "control.py",
    "_server_launcher_part2_mixinc.py": "internals.py",
    "server_launcher_part3.py": "harness.py",
    "server_launcher_errors.py": "errors.py",
}

#: The two bodies TS-4 deliberately rewrote.  Both are constructors, and
#: both were rewritten for the same reason: a default derived from
#: ``__file__`` or from a name defined in a sibling shard.
_DEVIATIONS = {"__init__"}


def _defs(path: pathlib.Path) -> dict:
    """Every method and top-level function in *path*, name -> source text."""
    source = path.read_text()
    tree = ast.parse(source)
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out[item.name] = ast.get_source_segment(source, item)
    for item in tree.body:
        if isinstance(item, ast.FunctionDef):
            out[item.name] = ast.get_source_segment(source, item)
    return out


# ---------------------------------------------------------------------------
# success


def test_the_package_composes_the_same_class():
    import brix_suite.launcher as launcher

    names = [cls.__name__ for cls in launcher.RegistryLauncher.__mro__]
    assert names == ["RegistryLauncher", "_LauncherStart", "_LauncherControl",
                     "_LauncherInternals", "object"]
    # The slice-letter names the pre-move tree spelled are aliases of the
    # topic-named classes, not subclasses: one object, two spellings.
    assert launcher._RegistryLauncherMixinA is launcher._LauncherStart
    assert launcher._RegistryLauncherMixinB is launcher._LauncherControl
    assert launcher._RegistryLauncherMixinC is launcher._LauncherInternals


@pytest.mark.parametrize("source,module", sorted(_MOVES.items()))
def test_every_moved_body_is_byte_identical(source, module):
    flat = _defs(TESTS / source)
    moved = _defs(PKG / module)
    assert flat, source

    missing = sorted(name for name in flat if name not in moved)
    assert missing == [], "%s lost %s" % (module, missing)

    changed = {name for name, text in flat.items() if moved[name] != text}
    assert changed <= _DEVIATIONS, (
        "%s: unannounced rewrite of %s" % (module, sorted(changed - _DEVIATIONS)))


def test_the_facade_carries_the_bodies_the_flat_assembly_carried():
    """`server_launcher.py` is an assembly script, not a module of bodies.

    Its only real definition is `launch_fleet_nginx`, so it gets its own
    check rather than a row in `_MOVES`: `_defs` on the flat file would
    also pick up the `_load_continuations` plumbing the package exists to
    delete.
    """
    flat = _defs(TESTS / "server_launcher.py")
    moved = _defs(PKG / "__init__.py")
    assert "launch_fleet_nginx" in flat
    assert moved["launch_fleet_nginx"] == flat["launch_fleet_nginx"]


def _code_only(path: pathlib.Path) -> str:
    """*path* with its comments removed.

    The move-hazard checks below look for the hazardous spelling, and the
    fixed constructors name that spelling in the comment explaining why they
    do not use it.  Grepping the raw text would therefore find the fix and
    call it the bug.
    """
    import io
    import tokenize

    source = path.read_text()
    kept = [tok for tok in tokenize.generate_tokens(io.StringIO(source).readline)
            if tok.type != tokenize.COMMENT]
    return tokenize.untokenize((t.type, t.string) for t in kept)


def test_the_two_rewritten_constructors_are_the_ones_we_claim():
    """Both defaults were derived from the file's own location or shard."""
    start = (PKG / "start.py").read_text()
    assert "self.tests_dir = tests_dir or TESTS_DIR" in start
    assert "dirname(__file__)" not in _code_only(PKG / "start.py")

    harness = (PKG / "harness.py").read_text()
    assert "from brix_suite.launcher import RegistryLauncher" in harness


def test_local_backend_honours_the_deploy_contract(tmp_path):
    """Item 4's second half: the §8.1 seam, proven behaviourally.

    ``check_backend_contract`` shipped with the core and had no caller —
    the seam was declared conformant, never measured.
    """
    import brix_suite.kinds  # noqa: F401 — import registers this fleet's six kinds
    from brixtest.config.lanes import Lane
    from brixtest.deploy import DeployBackend
    from brixtest.deploy.local import LocalBackend
    from brixtest.fleet.registry import InstanceSpec, Registry
    from brixtest.testing import check_backend_contract

    # ``proc`` rather than a synthetic kind: the seam is only worth measuring
    # against a kind the fleet really declares, and ``proc`` is the one whose
    # profile carries no pidfile, so obligations 2/4/6 exercise the
    # port-tracked path instead of the easy pidfile one.
    lane = Lane(root=tmp_path, port_base=28000, port_span=64)
    registry = Registry()
    spec = registry.register(InstanceSpec(
        name="contract-probe", kind="proc", ports={"main": 28001},
        command=("/bin/true",)))
    backend = LocalBackend(registry, lane)
    assert isinstance(backend, DeployBackend)

    assert check_backend_contract(backend, spec, lane) == []


# ---------------------------------------------------------------------------
# error


def test_no_topic_module_reaches_for_the_exec_mechanism():
    users = [p.name for p in PKG.glob("*.py")
             if "split_continuation" in p.read_text()]
    assert users == []


def test_the_exception_has_exactly_one_definition_site():
    """Two definitions of an exception type is a silent ``except`` miss.

    The raiser's class and the catcher's class would differ and nothing
    would say so — the handler simply would not fire.  The facade therefore
    re-exports the object from ``errors``, it does not redefine it.

    ``errors`` also imports nothing from inside the package, which is what
    let it be a module of its own before the move: a method in ``control``
    can raise a type that ``start`` catches without either importing the
    other.
    """
    import brix_suite.launcher as launcher
    import brix_suite.launcher.errors as errors

    assert launcher.RegistryCommandFailure is errors.RegistryCommandFailure

    tree = ast.parse((PKG / "errors.py").read_text())
    reached = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            reached.add(node.module.split(".")[0])
        elif isinstance(node, ast.Import):
            reached.update(a.name.split(".")[0] for a in node.names)
    assert not (reached & {"brix_suite", "server_launcher", "server_registry"})


# ---------------------------------------------------------------------------
# security-negative


def test_the_package_is_built_but_not_installed():
    """No §10.2 shim may point at it while the pinning suite still patches
    the flat namespace.  Installing one silently would leave two launchers
    in the tree — the flat one the fleet uses and the package one the tests
    think they patched."""
    flat = (TESTS / "server_launcher.py").read_text()
    assert "sys.modules[__name__]" not in flat
    assert "_load_continuations" in flat


def test_a_rebind_on_the_package_does_not_reach_the_topic_modules():
    """The measurement behind the deferral.

    ``test_server_registry_smoke.py`` does
    ``monkeypatch.setattr("server_launcher.REGISTRY_STRICT_TEMPLATES", True)``
    and expects the code that reads it — a method on what is now
    ``control.py`` — to see the new value.  Under one exec'd namespace it
    did.  Under real modules it does not, and nothing raises: the patch is
    applied, the assertion under test just never takes effect.  That silence
    is why this is pinned rather than left as a note.
    """
    import brix_suite.launcher as launcher
    import brix_suite.launcher.control as control
    import brix_suite.launcher.start as start

    sentinel = object()
    original = getattr(launcher, "REGISTRY_STRICT_TEMPLATES", None)
    launcher.REGISTRY_STRICT_TEMPLATES = sentinel
    try:
        assert start.REGISTRY_STRICT_TEMPLATES is not sentinel
        assert control.REGISTRY_STRICT_TEMPLATES is not sentinel
    finally:
        if original is None:
            del launcher.REGISTRY_STRICT_TEMPLATES
        else:
            launcher.REGISTRY_STRICT_TEMPLATES = original
