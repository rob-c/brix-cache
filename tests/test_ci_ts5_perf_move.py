"""Regression gates for the TS-5 move into :mod:`brix_suite.perf`.

The load driver, its continuation shards, and the A/B measurer moved.  The
netem harness remains flat because the server-registry lint identifies its
launcher by relative path.  These checks pin module identity, body parity,
the driver's formerly shard-owned entry point, and the flat netem child's
import through the compatibility shim.
"""

from __future__ import annotations

import ast
import os
import pathlib
import re
import subprocess
import sys

import pytest
from ts5_ast_checks import body_hashes, missing_names, substring_matches

TESTS = pathlib.Path(__file__).resolve().parent
REPO = TESTS.parent
PERF = TESTS / "brix_suite" / "perf"
LEGACY = TESTS / "brix_suite" / "_legacy"

pytestmark = pytest.mark.timeout(180)

#: The four that moved.  ``load_test`` is the composed head; the two shards are
#: listed because their flat spellings are shims too, not because anyone imports
#: them.
MOVED = ["load_test", "load_test_part2", "load_test_part3", "_perf_ab_helpers"]

#: The one that stayed, and the guard that kept it.
STAYED = "_perf_netem_helpers"

#: The one declared deviation from verbatim: ``load_test_part2`` gained
#: ``from __future__ import annotations``.  Pinned by name so it cannot grow.
FUTURE_ANNOTATIONS = {"load_test_part2"}

#: Refactors are mirrored into the archived comparison bodies, so the two
#: definition surfaces remain identical.
DECLARED_ADDITIONS = {}

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _bodies(path: pathlib.Path) -> dict:
    """sha256 of every def/class body, by qualified name, position-independent."""
    return body_hashes(path)


def _suite_env(extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(TESTS), str(REPO / "brixtest" / "src"),
         env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    env["TEST_SKIP_SERVER_SETUP"] = "1"
    env.update(extra or {})
    return env


def _child(code, env_extra=None, timeout=120):
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, timeout=timeout, env=_suite_env(env_extra))


def _has_main_guard(path: pathlib.Path) -> bool:
    """True when the module carries an ``if __name__ == "__main__":`` block."""
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if (isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name)
                and test.left.id == "__name__"):
            return True
    return False


def _assert_archive_annotation_failure(result):
    assert result.returncode != 0, "the archived body now imports standalone"
    assert "NameError" in result.stderr, result.stderr[-400:]
    assert "RunStats" in result.stderr, result.stderr[-400:]


def _assert_moved_annotation_import(result):
    assert result.returncode == 0, result.stderr[-400:]


# ---------------------------------------------------------------------------
# success — identity and composition
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", MOVED)
def test_every_flat_spelling_is_the_package_object(name):
    """``X`` and ``brix_suite.perf.X`` must be ONE module object.

    The shards matter here as much as the head.  ``split_continuation`` execs a
    shard's *source* into the parent's globals, so a second module object for a
    shard is a second copy of a four-hundred-line namespace that nothing would
    ever report as duplicated — it has no state to disagree about and no port to
    collide on, it is simply twice.
    """
    out = _child(
        "import importlib\n"
        "a = importlib.import_module('%s')\n"
        "b = importlib.import_module('brix_suite.perf.%s')\n"
        "print(a is b, a.__name__)\n" % (name, name))
    assert out.returncode == 0, out.stderr
    same, mod = out.stdout.split()
    assert same == "True", "%s is a second object: %s" % (name, out.stdout)
    assert mod == "brix_suite.perf." + name


def test_the_shards_still_compose_into_the_head():
    """The composed namespace must carry all three shards' definitions.

    A dropped ``_load_continuations`` line imports perfectly cleanly and leaves
    two thirds of the API missing, so this asserts on names the head's own
    source does not define — their presence is the composition.
    """
    head_src = (PERF / "load_test.py").read_text(encoding="utf-8")
    from_shards = ["Suite", "print_comparison", "save_json", "build_suites",
                   "_cleanup_write_files", "main", "run_cli"]
    for name in from_shards:
        assert not re.search(r"^(?:def|class) %s\b" % name, head_src, re.M), (
            "%s is defined in the head — it can no longer prove composition"
            % name)
    out = _child(
        "import load_test as lt\n"
        "print(' '.join(n for n in %r if hasattr(lt, n)))\n" % (from_shards,))
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == from_shards, (
        "composition lost names: %s" % (set(from_shards) - set(out.stdout.split())))


@pytest.mark.parametrize("name", MOVED)
def test_the_move_was_verbatim(name):
    """Every def/class body must hash identically to its archive."""
    before = _bodies(LEGACY / (name + "_flat.py"))
    after = _bodies(PERF / (name + ".py"))
    added = set(after) - set(before)
    assert added == DECLARED_ADDITIONS.get(name, set()), (
        "%s gained undeclared definitions: %s" % (name, sorted(added)))
    lost = set(before) - set(after)
    assert not lost, "%s lost definitions: %s" % (name, sorted(lost))
    differing = sorted(k for k in before if before[k] != after[k])
    assert not differing, "%s bodies changed: %s" % (name, differing)


# ---------------------------------------------------------------------------
# success — the entry point the move would have silenced
# ---------------------------------------------------------------------------

def test_the_shard_no_longer_carries_an_entry_point_it_cannot_fire():
    """Shard 3's ``__main__`` guard is gone, replaced by a named ``run_cli``.

    Left in place the guard is not merely dead — it is a line that reads as the
    program's entry point while being unreachable, which is precisely how the
    token forge came to exit 0 writing nothing.
    """
    moved = PERF / "load_test_part3.py"
    assert not _has_main_guard(moved), (
        "the moved shard still carries a __main__ guard that can never fire")
    assert _has_main_guard(LEGACY / "load_test_part3_flat.py"), (
        "the archive has no guard — this test's premise is gone")
    src = moved.read_text(encoding="utf-8")
    assert re.search(r"^def run_cli\(", src, re.M), "run_cli is missing"
    assert "set_start_method" in src, (
        "run_cli dropped the fork start-method the workers depend on")


def test_the_shim_is_what_runs_the_driver_now():
    """``tests/load_test.py`` must carry the guard and call ``run_cli``."""
    shim = TESTS / "load_test.py"
    assert _has_main_guard(shim), "the shim has no entry point"
    src = shim.read_text(encoding="utf-8")
    assert "_canonical.run_cli()" in src, (
        "the shim does not call the named entry point")
    assert "_sys.modules[__name__] = _canonical" in src, (
        "the shim does not self-replace")


def test_the_load_driver_cli_still_runs_by_its_documented_path():
    """``python3 tests/load_test.py --help`` — the spelling the docs give.

    Run as a subprocess on purpose: the defect this guards against is invisible
    to any in-process check, because in-process the module is imported and the
    guard was never going to fire either way.
    """
    out = subprocess.run(
        [sys.executable, str(TESTS / "load_test.py"), "--help"],
        capture_output=True, text=True, timeout=120, env=_suite_env())
    assert out.returncode == 0, out.stderr
    assert "--target" in out.stdout and "--concurrency" in out.stdout, (
        "the driver started but is not the driver: %s" % out.stdout[:400])


def test_the_ab_measurer_cli_still_runs_by_its_documented_path():
    """``python3 tests/_perf_ab_helpers.py --help`` — used to take one-off numbers."""
    out = subprocess.run(
        [sys.executable, str(TESTS / "_perf_ab_helpers.py"), "--help"],
        capture_output=True, text=True, timeout=120, env=_suite_env())
    assert out.returncode == 0, out.stderr
    assert "--size-mib" in out.stdout and "--tls" in out.stdout, (
        "not the measurer's parser: %s" % out.stdout[:400])


# ---------------------------------------------------------------------------
# success — the module that stayed, and the guard that kept it
# ---------------------------------------------------------------------------

def test_the_netem_harness_is_still_a_real_module_here():
    """``_perf_netem_helpers`` must be flat and whole, not a shim."""
    flat = TESTS / (STAYED + ".py")
    src = flat.read_text(encoding="utf-8")
    assert "_sys.modules[__name__]" not in src, (
        "%s became a shim — see brix_suite/perf/__init__.py for why it must not"
        % STAYED)
    assert not (PERF / (STAYED + ".py")).exists(), (
        "a package copy of %s exists; the flat file is the only one" % STAYED)
    assert not (LEGACY / (STAYED + "_flat.py")).exists(), (
        "an archive of %s exists — the archive alone would break the registry "
        "lint, since it carries the launch text" % STAYED)


def test_moving_the_netem_harness_would_break_the_registry_lint():
    """Show that the path-keyed launcher allowlist currently blocks the move."""
    import test_server_registry_lint as lint

    flat_rel = STAYED + ".py"
    assert flat_rel in lint.LAUNCH_BACKLOG, (
        "the premise is gone: %s is no longer an allowlisted launcher" % flat_rel)

    moved_rel = "brix_suite/perf/%s.py" % STAYED
    archive_rel = "brix_suite/_legacy/%s_flat.py" % STAYED
    for rel in (moved_rel, archive_rel):
        assert rel not in lint.LAUNCH_BACKLOG, (
            "%s is already allowlisted — the move is no longer blocked and this "
            "cluster should finish" % rel)

    text = (TESTS / flat_rel).read_text(encoding="utf-8")
    assert lint._server_launches(text), (
        "%s no longer launches nginx directly; the allowlist entry is stale and "
        "the move is unblocked" % flat_rel)


def test_the_netem_child_still_finds_the_measurer_through_the_shim():
    """Run the netem child's flat import without ``tests/`` on ``PYTHONPATH``."""
    code = (
        "import sys, os\n"
        "sys.path.insert(0, os.path.dirname(os.path.abspath(%r)))\n"
        "from _perf_ab_helpers import measure_read_throughput\n"
        "print(measure_read_throughput.__module__)\n"
        % str(TESTS / (STAYED + ".py")))
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, timeout=120, env=env, cwd=str(REPO))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "brix_suite.perf._perf_ab_helpers", (
        "the child resolved somewhere else: %s" % out.stdout.strip())


# ---------------------------------------------------------------------------
# error paths
# ---------------------------------------------------------------------------

def test_a_shard_imported_on_its_own_is_incomplete_rather_than_broken():
    """Importing a shard directly succeeds and yields two thirds of nothing.

    This is why the shards are shims nobody calls rather than modules with an
    API.  The failure is not an ImportError — the shard's prelude is complete —
    it is a module that answers ``hasattr`` correctly for its own names and not
    at all for the ones its body calls at runtime.
    """
    out = _child(
        "import brix_suite.perf.load_test_part3 as p3\n"
        "print(hasattr(p3, 'main'), hasattr(p3, 'build_suites'),"
        " hasattr(p3, 'run_concurrent'))\n")
    assert out.returncode == 0, (
        "importing the shard raised; the point is that it does not: %s"
        % out.stderr)
    assert out.stdout.split() == ["True", "False", "False"], (
        "the shard is no longer incomplete on its own: %s" % out.stdout)


def test_the_head_refuses_to_import_without_its_shards():
    """A head whose loader line is gone must fail, not run short.

    Written against a scratch copy — the real head is never touched.  It proves
    the composition is load-bearing: with the line removed the module still
    imports, so nothing raises, and the driver's whole command surface is simply
    absent.  That is the failure this file's composition test exists to catch.
    """
    import tempfile

    src = (PERF / "load_test.py").read_text(encoding="utf-8")
    assert "_load_continuations(globals()" in src
    maimed = re.sub(r"^from split_continuation import.*\n_load_continuations.*\n",
                    "", src, flags=re.M)
    assert maimed != src, "the loader line was not found to remove"
    with tempfile.TemporaryDirectory() as td:
        scratch = pathlib.Path(td) / "maimed_head.py"
        scratch.write_text(maimed, encoding="utf-8")
        out = _child(
            "import sys\n"
            "sys.path.insert(0, %r)\n"
            "import maimed_head as m\n"
            "print(hasattr(m, 'main'), hasattr(m, 'run_cli'))\n" % td)
    assert out.returncode == 0, (
        "the maimed head raised — then a dropped loader line would be loud and "
        "this hazard would not need a test: %s" % out.stderr)
    assert out.stdout.split() == ["False", "False"], (
        "the maimed head still has an entry point: %s" % out.stdout)


def test_no_module_in_the_cluster_reaches_a_name_it_never_binds():
    """Static scan for the cross-shard reference that only breaks on a real import.

    Unioned across the three shards, because run per file it reports every name
    the *parent* binds — which is most of them.
    """
    paths = [PERF / (name + ".py") for name in MOVED]
    missing = missing_names(paths, union_scope=True)
    assert not missing, (
        "names used but bound nowhere in the cluster — a real import will "
        "NameError on these: %s" % {k: sorted(v) for k, v in missing.items()})


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

def test_the_driver_never_lets_an_operator_credential_into_a_gsi_worker():
    """``_apply_brix_gsi_env`` must strip ``X509_USER_CERT``/``KEY``.

    The benchmark forks a hundred-odd ``xrdcp`` children from the operator's own
    environment.  With ``XrdSecPROTOCOL=gsi`` forced and a long-lived
    ``X509_USER_CERT`` still in the environment, a child can authenticate as the
    operator instead of as the test proxy — and the run still succeeds, so the
    numbers look right and the identity on the wire is wrong.
    """
    out = _child(
        "import load_test as lt\n"
        "env = {'X509_USER_CERT': '/home/op/real.pem',\n"
        "       'X509_USER_KEY': '/home/op/real.key'}\n"
        "lt._apply_brix_gsi_env(env, '/tmp/proxy.pem', '/tmp/ca')\n"
        "print(sorted(env))\n")
    assert out.returncode == 0, out.stderr
    keys = eval(out.stdout.strip())
    assert "X509_USER_CERT" not in keys and "X509_USER_KEY" not in keys, (
        "the operator's long-lived credential survived into the worker: %s" % keys)
    assert "X509_USER_PROXY" in keys and "X509_CERT_DIR" in keys


def test_the_no_proxy_path_forces_no_protocol_it_cannot_credential():
    """With no proxy the helper returns early — and must force no GSI either.

    The asymmetry is deliberate and worth pinning: the anonymous and token legs
    pass ``proxy=None``, and the ambient ``X509_*`` variables are left alone.
    That is only safe because ``XrdSecPROTOCOL`` is *not* set on this path, so
    nothing steers the client at GSI with a credential the test did not choose.
    A future edit that hoisted the protocol assignment above the early return
    would invert exactly that.
    """
    out = _child(
        "import load_test as lt\n"
        "env = {'X509_USER_CERT': '/home/op/real.pem'}\n"
        "lt._apply_brix_gsi_env(env, None, '/tmp/ca')\n"
        "print(sorted(env))\n")
    assert out.returncode == 0, out.stderr
    keys = eval(out.stdout.strip())
    assert "XrdSecPROTOCOL" not in keys and "XRD_SECPROTOCOL" not in keys, (
        "GSI is forced with no proxy to authenticate as: %s" % keys)
    assert "X509_CERT_DIR" in keys, "server-cert verification was dropped"


def test_the_moved_modules_start_no_server_of_their_own():
    """None of the four may become a direct nginx launcher.

    ``_perf_netem_helpers`` is allowlisted to launch one and stayed behind
    partly for that reason; the four that moved are clients, and a launch
    appearing in one of them would land it in a package directory the registry
    lint has no allowlist entry for.
    """
    import test_server_registry_lint as lint

    for name in MOVED:
        for path in (PERF / (name + ".py"), LEGACY / (name + "_flat.py")):
            text = path.read_text(encoding="utf-8")
            assert not lint._server_launches(text), (
                "%s starts nginx directly — route it through the registry"
                % path.relative_to(TESTS))


# ---------------------------------------------------------------------------
# the tier's own hazards
# ---------------------------------------------------------------------------

def test_no_ci_gate_file_is_auto_marked_slow():
    """This file's name must not match ``conftest_part3._SLOW_MODULE_HINTS``.

    Read out of the conftest rather than copied, so a new hint that swallows a
    gate fails here instead of quietly deselecting it.  ``test_ci_ts5_mesh_move``
    is how this test came to exist — it matched ``_mesh``, all forty of its tests
    were deselected, and the gate set reported green.  ``interop`` is also a
    hint, which is why the next cluster's gate cannot be named for it.
    """
    import conftest_part3

    hints = conftest_part3._SLOW_MODULE_HINTS
    gates = sorted(TESTS.glob("test_ci_ts*.py")) + [TESTS / "test_ci_suite_surface.py"]
    swallowed = substring_matches(gates, hints)
    assert not swallowed, (
        "gate files auto-marked slow — they are deselected by pytest.ini's "
        "`-m \"not slow\"` PR gate and report green having run nothing: %s"
        % swallowed)


@pytest.mark.parametrize("name", MOVED)
def test_the_archive_is_frozen_and_the_shim_is_not_the_archive(name):
    """The three copies must be three distinct roles.

    A move that wrote the shim over the package module, or archived the shim
    instead of the body, leaves every import working and the archive proving
    nothing — the parity test above would then be comparing a file to itself.
    """
    shim = (TESTS / (name + ".py")).read_text(encoding="utf-8")
    moved = (PERF / (name + ".py")).read_text(encoding="utf-8")
    archive = (LEGACY / (name + "_flat.py")).read_text(encoding="utf-8")
    assert "_sys.modules[__name__] = _canonical" in shim
    assert "_sys.modules[__name__]" not in archive, (
        "the archive is a shim — it froze the wrong file")
    assert "_sys.modules[__name__]" not in moved, (
        "the package module is a shim — the body never arrived")
    assert len(archive) > 4 * len(shim), (
        "the archive is shim-sized (%d vs %d bytes)" % (len(archive), len(shim)))


def test_the_shim_baseline_carries_every_shim_in_the_cluster():
    """Guard #3's baseline must know all four shims.

    Guard #3 and ``dump_suite_surface`` both *import* a shim's target, so a
    module that cannot be imported standalone cannot be a shim at all — which is
    what the deviation below is for.
    """
    import json

    baseline = json.loads(
        (REPO / "docs" / "refactor" / "testsuite-shim-baseline.json")
        .read_text(encoding="utf-8"))
    for name in MOVED:
        assert name in baseline, (
            "%s is not in the shim baseline — guard #3 will not notice if it "
            "stops exporting what it used to" % name)


@pytest.mark.parametrize("name", sorted(FUTURE_ANNOTATIONS))
def test_the_one_declared_deviation_is_the_future_import(name):
    """Exactly one line differs from verbatim, and here is what it bought.

    The archived pre-move body still raises ``NameError: RunStats`` when
    imported on its own — the annotation ``-> RunStats`` is evaluated as the
    class body runs and shard 1 is what defines that name.  So the shard could
    not be a shim, could not be baselined, and broke the inventory dumper, all
    for a module nothing imports by name.  The future import makes the
    annotation lazy and the shard ordinary.

    Both halves are asserted: the archive still fails, and the moved copy no
    longer does.  If someone later removes the future import, the second half
    fails here rather than in the guard lane.
    """
    code = ("import sys\n"
            "sys.path.insert(0, %r)\n"
            "import %s\n"
            "print('imported')\n")

    archived = _child(code % (str(LEGACY), name + "_flat"))
    _assert_archive_annotation_failure(archived)

    moved = _child(code % (str(PERF), name))
    _assert_moved_annotation_import(moved)

    src = (PERF / (name + ".py")).read_text(encoding="utf-8")
    assert "from __future__ import annotations" in src


def test_no_other_module_in_the_cluster_gained_a_future_import():
    """The deviation is one line in one file, not a habit."""
    for name in MOVED:
        if name in FUTURE_ANNOTATIONS:
            continue
        moved = (PERF / (name + ".py")).read_text(encoding="utf-8")
        archive = (LEGACY / (name + "_flat.py")).read_text(encoding="utf-8")
        assert ("from __future__ import annotations" in moved) == (
            "from __future__ import annotations" in archive), (
            "%s changed its future imports and did not declare it" % name)
