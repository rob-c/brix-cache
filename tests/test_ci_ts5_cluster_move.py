"""TS-5, the mesh cluster: two interop topologies that name their own ports.

The file is not called ``..._mesh_move.py``, and that is not a style choice.
``conftest_part3._SLOW_MODULE_HINTS`` auto-marks a module ``slow`` when its
*name* contains any of thirty-odd substrings, ``_mesh`` among them, and the PR
gate runs ``-m "not slow"``.  Under the obvious name all forty tests below were
deselected and the gate set still reported ``310 passed`` — a run that did
nothing and said so in green.  The classifier reads a filename as a workload,
which is wrong here (this file starts no mesh and takes ~2s) but is a defect in
the classifier, not in the name; the conftest that holds it is pre-TS-4 and
untouchable until TS-7, so the file is renamed and
``test_no_ci_gate_file_is_auto_marked_slow`` below keeps the next one from
landing in the same hole.

Nine modules moved one-to-one out of the flat ``tests/`` tree into
:mod:`brix_suite.mesh` — ``cms_mesh_lib`` and its two continuation shards,
``hybrid_mesh_lib``, ``mesh_config``, the two ``*_servers`` orchestrators the
spec catalogue drives, and the two WLCG fleets Appendix A groups here because
they stand up a server *set* rather than a single instance.

Four properties decided what is tested here, and each is a way this move could
have looked fine and been wrong.

1. **Both hazards resolved to a directory that exists.**  ``cms_mesh_lib``
   derived the repo as two parents up from itself and ``mesh_config`` derived
   the template directory as one; from ``tests/brix_suite/mesh/`` those hops
   land on ``tests/brix_suite`` and ``tests/`` — real directories, so nothing
   raises.  ``CLIENT_DIR`` would simply have stopped holding
   ``xrdsssadmin-brix`` and every sss topology would have *skipped*, which
   reads as "no keytab tool on this box" and not as "the move broke it".  Both
   are now named from :data:`brix_suite.settings.TESTS_DIR`, and the tests
   below re-evaluate the old expressions from the new location to show what
   they would have produced.

2. **The shards are not modules.**  ``cms_mesh_lib_part2/3`` are exec'd into
   the parent's namespace by ``split_continuation.load``, so each is a
   half-namespace on its own: the free-name scan has to union all three or it
   reports every name the parent binds as unbound.  That union is the check —
   run per-file it is noise, run over the cluster it is the thing that catches
   a dropped import.

3. **Nothing here may be started.**  ``stop_all()`` sweeps by *port*: it
   SIGKILLs whatever is listening anywhere in the mesh band and pkills by a
   ``MESH_DIR`` path pattern.  Called from a test it would take down a live
   mesh belonging to the run — or to another session.  So this file starts no
   mesh and calls no teardown; the orchestrators are exercised only on the
   argv paths that return before any daemon exists.

4. **The mesh band is fixed, not leased.**  A mesh node's config names its
   peers by port, so the numbers are topology, not allocation — which is why
   only one mesh of each kind fits on a host and why both specs carry
   ``allow_remote_skip=True``.  The bare numbers below are read from
   ``PORTS``, never written down again here.

The verbatim-move check is an AST body hash against ``brix_suite/_legacy/``.
It compares def/class bodies only, which is exactly right for this move: the
two fixes are module-level constants and import lines, so every body must
still hash identically, and any body that drifted cannot be argued away.
"""

from __future__ import annotations

import ast
import os
import pathlib
import subprocess
import sys

import pytest
from ts5_ast_checks import (
    assigned_literal,
    body_hashes,
    literal_call_problems,
    missing_name_groups,
    substring_matches,
)

TESTS = pathlib.Path(__file__).resolve().parent
REPO = TESTS.parent
MESH = TESTS / "brix_suite" / "mesh"
LEGACY = TESTS / "brix_suite" / "_legacy"

pytestmark = pytest.mark.timeout(120)

#: Every module in the cluster: (flat name, the module the flat name resolves
#: to).  The two shards are not modules — the flat spelling of either lands on
#: the composed parent, which is the only object that makes sense.
MODULES = [
    ("mesh_config", "mesh_config"),
    ("cms_mesh_lib", "cms_mesh_lib"),
    ("cms_mesh_lib_part2", "cms_mesh_lib"),
    ("cms_mesh_lib_part3", "cms_mesh_lib"),
    ("hybrid_mesh_lib", "hybrid_mesh_lib"),
    ("cms_mesh_servers", "cms_mesh_servers"),
    ("hybrid_mesh_servers", "hybrid_mesh_servers"),
    ("wlcg_fleet", "wlcg_fleet"),
    ("wlcg_conformance_fleet", "wlcg_conformance_fleet"),
]

#: The files that actually moved, each against its archive.
MOVED = [name for name, _ in MODULES]

#: The two orchestrators, and the spec name each answers to.
ORCHESTRATORS = [("cms_mesh_servers", "cms-mesh"),
                 ("hybrid_mesh_servers", "hybrid-mesh")]

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _bodies(path: pathlib.Path) -> dict:
    """sha256 of every def/class body, by qualified name, position-independent.

    ``include_attributes=False`` drops line numbers, which matters because the
    archives keep the ``__file__`` hops these modules dropped: every line below
    them differs by construction while the code does not.
    """

    return body_hashes(path)


def _suite_env(extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(TESTS), str(REPO / "brixtest" / "src"),
         env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    env["TEST_SKIP_SERVER_SETUP"] = "1"
    env.update(extra or {})
    return env


def _child(code, env_extra=None, cwd=None, timeout=90):
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, timeout=timeout,
                          env=_suite_env(env_extra), cwd=cwd)


def _run(argv, env_extra=None, cwd=None, timeout=90):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          env=_suite_env(env_extra), cwd=cwd)


def _mesh_module_groups():
    composed = {"cms_mesh_lib", "cms_mesh_lib_part2", "cms_mesh_lib_part3"}
    groups = [sorted(MESH / (name + ".py") for name in composed)]
    groups.extend([[MESH / (name + ".py")] for name in MOVED if name not in composed])
    return groups


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("flat,canonical", MODULES, ids=[m for m, _ in MODULES])
def test_every_flat_spelling_is_the_package_object(flat, canonical):
    """``X`` and ``brix_suite.mesh.X`` must be ONE module object.

    ``cms_mesh_lib`` is why this is a rule: it runs :func:`shutil.which` five
    times at import and records every launched instance in module state.  Two
    objects would mean two binary discoveries and, worse, a teardown that
    walks a bookkeeping list the launcher never wrote to.
    """
    out = _child(
        "import importlib\n"
        "a = importlib.import_module('%s')\n"
        "b = importlib.import_module('brix_suite.mesh.%s')\n"
        "print(a is b, a.__name__)\n" % (flat, canonical))
    assert out.returncode == 0, out.stderr
    same, name = out.stdout.split()
    assert same == "True", "%s is a second object: %s" % (flat, out.stdout)
    assert name == "brix_suite.mesh." + canonical


@pytest.mark.parametrize("name", MOVED)
def test_the_move_was_verbatim(name):
    """Every def/class body must hash identically to its archive."""
    before = _bodies(LEGACY / (name + "_flat.py"))
    after = _bodies(MESH / (name + ".py"))
    assert sorted(before) == sorted(after), (
        "%s: definitions differ: added %s, lost %s"
        % (name, sorted(set(after) - set(before)), sorted(set(before) - set(after))))
    changed = [k for k in before if before[k] != after[k]]
    assert not changed, "%s: bodies changed in a verbatim move: %s" % (name, changed)


def test_the_shards_still_compose_into_one_namespace():
    """Names defined in each shard must be reachable on the composed parent.

    ``split_continuation.load`` anchors on the parent's ``__file__``, so the
    three files had to move together; if one had been left behind the import
    would raise, and if the loader line had been dropped the module would
    import cleanly and be missing two thirds of its API.
    """
    out = _child(
        "import brix_suite.mesh.cms_mesh_lib as c\n"
        "print(all(hasattr(c, n) for n in "
        "('have_binaries', 'cfg_submanager', 'stop_all', 'wait_ready')))\n")
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "True", "the composed namespace is incomplete"


def test_the_template_directory_is_the_one_that_holds_the_templates():
    """``CONFIGS_DIR`` must be ``tests/configs/mesh``, and must render."""
    out = _child(
        "import brix_suite.mesh.mesh_config as m, os\n"
        "print(m.CONFIGS_DIR)\n"
        "print(os.path.isdir(m.CONFIGS_DIR))\n"
        "print(len(m.render('mesh_cms_datanode.conf', BIND_HOST='127.0.0.1',\n"
        "      DATA_PORT=1, ROOT='/x', CMS_MGR='y', PATHS='/p')))\n")
    assert out.returncode == 0, out.stderr
    configs, isdir, size = out.stdout.split("\n")[:3]
    assert pathlib.Path(configs) == TESTS / "configs" / "mesh"
    assert isdir == "True"
    assert int(size) > 0


def test_the_catalogue_names_the_package_and_carries_its_path():
    """Both mesh specs must start with ``-m`` AND carry ``PYTHONPATH``.

    ``-m`` puts the *current* directory on ``sys.path``, not the script's, and
    the mesh libs still reach ``server_launcher`` and ``split_continuation`` in
    the flat tree.  A spec with the new spelling and the old env would die on
    ``ModuleNotFoundError`` before binding anything — a start failure three
    levels from its cause.
    """
    out = _child(
        "import json\n"
        "from brix_suite.catalogue.support import support_specs\n"
        "print(json.dumps({s.name: [s.template_values['start_argv'],\n"
        "  sorted(s.env or {})] for s in support_specs() if 'mesh' in s.tags}))\n")
    assert out.returncode == 0, out.stderr
    import json

    specs = json.loads(out.stdout)
    for module, spec in ORCHESTRATORS:
        argv, env = specs[spec]
        assert argv[1:3] == ["-m", "brix_suite.mesh." + module], argv
        assert "PYTHONPATH" in env, "%s: -m spec without PYTHONPATH" % spec


def test_a_topology_can_be_configured_end_to_end_without_launching_one(tmp_path):
    """Builders + templates + locator, exercised together and started never.

    The one thing this file deliberately does not do is bring a mesh up.  The
    band is fixed and host-wide, and ``stop_all()`` sweeps it by *port* — it
    SIGKILLs whatever is listening in the range and pkills by a ``MESH_DIR``
    pattern — so a mesh started here would be visible to, and destroyable by,
    any other run on the box.  That is the ownership hazard the lane-claim gate
    exists for, and it is not one to re-enter for a move test.

    Configuring one is the part that can be proven safely, and it is the part
    the move could have broken: every builder reaches the templates through the
    relocated ``CONFIGS_DIR``, and a wrong locator would render nothing.
    """
    out = _child(
        "import os\n"
        "import brix_suite.mesh.cms_mesh_lib as c\n"
        "m = c.Mesh('probe')\n"
        "written = []\n"
        "written.append(m.write('mgr.conf', c.cfg_manager(21610, 21611)))\n"
        "written.append(m.write('sub.conf', c.cfg_submanager(21612, 21613,\n"
        "    m.datadir('sub'), '127.0.0.1:21611')))\n"
        "written.append(m.write('nds.conf', c.cfg_datanode(21614,\n"
        "    m.datadir('nds'), '127.0.0.1:21611', '/probe')))\n"
        "print('\\n'.join(written))\n"
        "print(all(os.path.getsize(p) > 0 for p in written))\n"
        "print(any('21611' in open(p).read() for p in written))\n",
        env_extra={"CMS_MESH_DIR": str(tmp_path / "mesh")})
    assert out.returncode == 0, out.stderr
    lines = out.stdout.strip().split("\n")
    paths, nonempty, substituted = lines[:3], lines[3], lines[4]
    assert all(pathlib.Path(p).is_file() for p in paths), paths
    assert all(str(tmp_path) in p for p in paths), (
        "a builder wrote outside the temp mesh root: %s" % paths)
    assert nonempty == "True" and substituted == "True", out.stdout


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", [m for m, _ in ORCHESTRATORS])
def test_an_unknown_subcommand_is_a_usage_error(module):
    """The one orchestrator path that returns before any daemon exists.

    ``start`` launches a mesh and ``stop`` sweeps the whole band by port, so
    neither may be run from a test; ``main`` is still worth exercising, and
    this is the branch that proves it is reachable under ``-m``.
    """
    out = _run([sys.executable, "-m", "brix_suite.mesh." + module, "wobble"],
               cwd=str(TESTS))
    assert out.returncode == 2, out.stdout + out.stderr
    assert "usage:" in out.stderr


@pytest.mark.parametrize("module", [m for m, _ in ORCHESTRATORS])
def test_the_module_spelling_needs_the_path_the_spec_supplies(module):
    """Without ``tests/`` on the path, ``-m`` from elsewhere must fail loudly.

    Asserted rather than assumed: this is the exact failure ``_module_env``
    exists to prevent, and it is better to have it written down here than
    rediscovered in a fleet log.
    """
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["TEST_SKIP_SERVER_SETUP"] = "1"
    out = subprocess.run(
        [sys.executable, "-m", "brix_suite.mesh." + module, "wobble"],
        capture_output=True, text=True, timeout=90, env=env, cwd=str(REPO))
    assert out.returncode != 2, "it found the package without being told where"
    assert "No module named" in out.stderr


def test_a_missing_template_names_the_directory_it_looked_in():
    """``render`` on an absent template must fail with the suite's own path."""
    out = _child(
        "import brix_suite.mesh.mesh_config as m\n"
        "try:\n"
        "    m.render('no_such_template.conf')\n"
        "except FileNotFoundError as exc:\n"
        "    print(exc.filename)\n")
    assert out.returncode == 0, out.stderr
    assert pathlib.Path(out.stdout.strip()).parent == TESTS / "configs" / "mesh"


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module,expr,attr", [
    ("cms_mesh_lib", "os.path.dirname(os.path.dirname(os.path.abspath(p)))", "REPO"),
    ("mesh_config", "os.path.dirname(p)", "CONFIGS_DIR"),
])
def test_the_old_hop_would_have_named_a_real_but_wrong_directory(module, expr, attr):
    """The hazard demonstrated, not asserted: the bad path exists.

    This is why neither fix could have been caught by "does it still import".
    Both old expressions resolve, from the new location, to a directory that is
    present on disk and is not the one the module means.
    """
    out = _child(
        "import os, brix_suite.mesh.%s as m\n"
        "p = m.__file__\n"
        "old = %s\n"
        "print(old)\n"
        "print(os.path.isdir(old))\n"
        "print(getattr(m, '%s'))\n" % (module, expr, attr))
    assert out.returncode == 0, out.stderr
    old, exists, live = out.stdout.strip().split("\n")
    assert exists == "True", "the demonstration is stale: %s is gone" % old
    assert not live.startswith(old + os.sep) and live != old, (
        "%s.%s still comes from the __file__ hop: %s" % (module, attr, live))


def test_no_module_reaches_a_name_it_never_binds():
    """The free-name scan, unioned across the three composed shards.

    A shard scanned alone reports every name its parent binds; scanned as one
    namespace it reports only the real thing — an import dropped along with the
    line that was its last user, which is a NameError at mesh-start time, when
    nobody is watching.
    """
    problems = missing_name_groups(_mesh_module_groups())
    assert not problems, "names used but never bound: %s" % problems


def test_every_template_a_mesh_renders_is_a_literal():
    """``render`` joins its argument onto ``CONFIGS_DIR`` without checking it.

    That is fine while every call site passes a committed filename, and it
    stops being fine the day one passes something a config or an env var
    reached.  The moved bodies are verbatim, so the guard is here rather than
    in ``render``: every first argument must be a string literal naming a
    committed template that is actually on disk, with no separator of its own
    — which also catches a call site that outlives the file it names.
    """
    templates = {p.name for p in (TESTS / "configs" / "mesh").iterdir()}
    assert templates, "no mesh templates on disk — the locator is wrong"
    offenders = literal_call_problems(sorted(MESH.glob("*.py")), "render", templates)
    assert not offenders, "render() reached a non-literal template: %s" % offenders


@pytest.mark.parametrize("name", MOVED)
def test_the_flat_spelling_kept_no_body_of_its_own(name):
    """Each flat file must be a shim, not a second copy of the module.

    A shim that grew a function is the failure mode §10.2 exists to prevent:
    two definitions of the same name, one of which is whichever the importer
    happened to reach first.
    """
    text = (TESTS / (name + ".py")).read_text(encoding="utf-8")
    tree = ast.parse(text)
    defs = [n.name for n in tree.body if isinstance(n, _DEFS)]
    assert not defs, "%s.py is not a shim: it defines %s" % (name, defs)
    assert text.rstrip().endswith("_sys.modules[__name__] = _canonical"), (
        "%s.py does not replace itself" % name)


def test_the_memoised_server_certificate_lives_in_exactly_one_module():
    """``wlcg_fleet``'s cert memo is module state reached across a spelling.

    ``_ensure_server_cert`` writes ``_SERVER_CERT``/``_SERVER_KEY`` through
    ``global`` and ``wlcg_conformance_fleet`` imports that private function by
    name.  If the two spellings were two objects the memo would exist twice and
    each importer would pay for its own ``openssl req`` — the kind of breakage
    that shows up as a slow suite, not a failing one.
    """
    out = _child(
        "import wlcg_fleet as flat\n"
        "import brix_suite.mesh.wlcg_fleet as pkg\n"
        "import brix_suite.mesh.wlcg_conformance_fleet as conf\n"
        "print(flat is pkg)\n"
        "print(conf._ensure_server_cert is pkg._ensure_server_cert)\n"
        "pkg._SERVER_CERT = 'sentinel'\n"
        "print(flat._SERVER_CERT)\n")
    assert out.returncode == 0, out.stderr
    same, shared, seen = out.stdout.split()
    assert same == "True" and shared == "True", out.stdout
    assert seen == "sentinel", "the memo does not live in one place"


def test_no_ci_gate_file_is_auto_marked_slow():
    """No ``test_ci_*.py`` may be deselected by the PR gate's own marker.

    These files are static gates measured in seconds; the ``slow`` families are
    multi-minute fleets.  A gate that lands in the slow tier does not fail — it
    silently stops running, and the tier that was supposed to enforce it reports
    a clean green.  That is how this file got its name.

    The hint tuple is read from the conftest rather than copied, so the check
    tracks the real classifier instead of a snapshot of it.
    """
    hints = assigned_literal(TESTS / "conftest_part3.py", "_SLOW_MODULE_HINTS")
    assert hints, "the slow-module classifier moved; this check is now blind"

    # Self-catch: the name this file had for one afternoon must still trip the
    # predicate.  Without it a hint tuple that quietly lost `_mesh` would leave
    # the check passing over a tree it no longer protects.
    assert any(h in "test_ci_ts5_mesh_move" for h in hints), (
        "the predicate no longer catches the name that caused this test")

    caught = substring_matches(sorted(TESTS.glob("test_ci_*.py")), hints)
    assert not caught, (
        "CI gate files auto-marked slow and dropped from `-m \"not slow\"`: %s"
        % caught)
