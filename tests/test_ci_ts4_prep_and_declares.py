"""TS-4 item 6 — prep steps, declares, orphans.

Three flat modules move behind §10.2 shims.  `fleet_declares` and
`fleet_orphans` go verbatim.  `fleet_prep` does not: §9.2.4 asks for the
pipeline to become `PrepStep` objects so the core `brixtest.fleet.prep`
engine and the shim path drive the *same* code rather than two copies of
it, and `brix_suite/prep_steps.py` is where those steps now live.

What `prepare()` keeps is its snapshot cache.  The core engine snapshots
the lane's artifact tree under `snapshot_dir` and stamps it per step; the
grown cache snapshots `pki/` + `tokens/` into a path-hashed directory
outside the lane and stamps it on generator sources.  They disagree, and
`test_fleet_prep_cache.py` pins the grown layout by reading `meta.json`
and `_CACHE_TTL_SECONDS` directly.  The plan schedules that conversion for
TS-7 (§9.2.4: "the §11 unit tests convert from monkeypatch-heavy to
constructor-parameter tests"), when editing the pinning suite is allowed.

The interesting property here is why a shim was safe at all.  Item 4
measured that a *package* split makes `monkeypatch.setattr("mod.name", …)`
invisible to the module that reads `name`.  `fleet_prep` is patched that
way five times over, so the move had to stay flat-to-flat: one module
object, one dict, one place a rebind can land.  The error test below is
that property, asserted rather than assumed.
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
SRC = TESTS.parent / "brixtest" / "src"
LEGACY = TESTS / "brix_suite" / "_legacy"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

#: flat name -> canonical module, for the identity probes.
_SHIMS = {
    "fleet_prep": "brix_suite.prep_steps",
    "fleet_declares": "brix_suite.declares",
    "fleet_orphans": "brix_suite.orphans",
}

#: The two modules that crossed into the package with no edit at all, and the
#: one deviation each: `declares` gained a comment above `import fleet_ports`
#: recording that the ports consolidation is still outstanding.  What the
#: archive pins is that MOVE.  A module may grow or be fixed afterwards — see
#: the two ledgers below, which make each such change something a reader can
#: find rather than something the diff quietly absorbed.
_VERBATIM = {
    "fleet_declares_flat.py": "declares.py",
    "fleet_orphans_flat.py": "orphans.py",
}

#: Definitions a moved module grew AFTER its move.  The archive pins the MOVE
#: — that nothing was lost or quietly edited on the way across — not the
#: module's future, and a frozen module is a module nobody may fix.  Listed by
#: name rather than waved through with a superset rule, so growth is something
#: somebody wrote down: an undeclared new definition still fails here, and a
#: lost or edited archived one always does.
_ADDED_SINCE_MOVE = {
    "orphans.py": {
        # The lane-claim gate (ask viii).  Everything in the archive answers
        # "which processes belong to this root"; nothing answered "is this
        # root mine", and a root read off a `ps` listing was reaped and took
        # ~200 processes of a concurrent run with it.  Pinned in full by
        # test_ci_lane_ownership_gate.py.
        "ForeignLaneError", "__init__", "_ancestry", "_declared_root",
        "_is_harness_cmd", "lane_claimants", "lane_harnesses", "live_lanes",
    },
}

#: Archived definitions a moved module has since EDITED.  Held to a stricter
#: standard than an addition, because an edit is where a move can be
#: retroactively rewritten: the entry has to say what changed, and one entry
#: buys one function, not the module.
_CHANGED_SINCE_MOVE = {
    "orphans.py": {
        # Gained `force=False` and a `lane_harnesses` check that raises
        # `ForeignLaneError` instead of reaping a lane another live harness
        # claims.  The reaping behaviour below the gate is untouched, and a
        # harness reaping its own lane is exempt by ancestry, so the caller
        # that mattered — conftest teardown — needed no change.
        "kill_orphans",
    },
}


def _probe(script: str) -> str:
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r); sys.path.insert(0, %r)\n%s"
         % (str(TESTS), str(SRC), script)],
        capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def _defs(path: pathlib.Path) -> dict:
    source = path.read_text()
    tree = ast.parse(source)
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[node.name] = ast.get_source_segment(source, node)
    return out


def _move_complaints(before: dict, after: dict, module: str) -> list:
    """Everything the archive says is wrong about ``after``, as sentences.

    One function so the ledgers cannot be bypassed by a second caller
    reimplementing a looser comparison — the failure mode this whole file
    exists to catch, one level up.
    """
    assert before, "the archive is empty; the comparison would prove nothing"
    added_ok = _ADDED_SINCE_MOVE.get(module, set())
    changed_ok = _CHANGED_SINCE_MOVE.get(module, set())
    out = []
    lost = sorted(set(before) - set(after))
    if lost:
        out.append("%s dropped %r on the way across" % (module, lost))
    added = sorted(set(after) - set(before) - added_ok)
    if added:
        out.append("%s grew %r since the move — add it to _ADDED_SINCE_MOVE "
                   "with the reason, or take it back out" % (module, added))
    changed = sorted(name for name in before
                     if name in after and before[name] != after[name]
                     and name not in changed_ok)
    if changed:
        out.append("%s edited %r after the move — add it to "
                   "_CHANGED_SINCE_MOVE with what changed, or restore it"
                   % (module, changed))
    stale = sorted(name for name in changed_ok
                   if name in before and name in after
                   and before[name] == after[name])
    if stale:
        out.append("%s lists %r in _CHANGED_SINCE_MOVE but it still matches "
                   "the archive" % (module, stale))
    return out


@pytest.fixture
def prep(monkeypatch, tmp_path):
    """`brix_suite.prep_steps` with its generators faked and no real openssl."""
    import brix_suite.prep_steps as prep_steps

    calls: list[str] = []
    monkeypatch.setattr(prep_steps, "regenerate_pki",
                        lambda pki_dir, env: calls.append("pki"))
    monkeypatch.setattr(prep_steps, "_make_token",
                        lambda *a, **k: calls.append("token"))
    monkeypatch.setattr(prep_steps, "_run", lambda *a, **k: calls.append("run"))
    prep_steps.calls = calls  # type: ignore[attr-defined]
    yield prep_steps
    del prep_steps.calls


# ---------------------------------------------------------------------------
# success


@pytest.mark.parametrize("flat,canonical", sorted(_SHIMS.items()))
def test_each_flat_name_is_the_canonical_module_itself(flat, canonical):
    """Not a copy of it.  Registration, caches and monkeypatches are all
    side effects on a module dict, so two objects would mean two of each."""
    both = _probe("import %s as a\nimport %s as b\nprint(a is b)" % (flat, canonical))
    assert both == "True"
    # ... and in the other import order, which is the one that catches a shim
    # that only works when it happens to be imported first.
    both = _probe("import %s as b\nimport %s as a\nprint(a is b)" % (canonical, flat))
    assert both == "True"


def test_the_eight_pipeline_stages_are_steps_in_the_documented_order():
    import brix_suite.prep_steps as prep_steps

    paths = prep_steps.PrepPaths.resolve({"TEST_ROOT": "/tmp/unused-by-this-test"})
    assert [s.name for s in prep_steps.crypto_steps(paths)] == [
        "pki", "jwks-refresh-key", "signing-key", "fleet-artifacts",
        "issued-tokens"]
    assert [s.name for s in prep_steps.session_steps(paths)] == [
        "crl-drops", "authdb-placeholder", "stage-hook"]


def test_the_steps_satisfy_the_core_prep_protocol():
    """Structural, not nominal: the core engine calls `name`, `stamp()` and
    `build(artifacts)`, and the point of the lift is that it can drive these
    objects unchanged."""
    import brix_suite.prep_steps as prep_steps

    paths = prep_steps.PrepPaths.resolve({"TEST_ROOT": "/tmp/unused-by-this-test"})
    steps = prep_steps.crypto_steps(paths) + prep_steps.session_steps(paths)
    assert len(steps) == 8
    for step in steps:
        assert isinstance(step.name, str) and step.name
        assert isinstance(step.stamp(), str)
        # build() takes the core's artifacts argument even though this fleet
        # resolves its paths from the env — see the class docstring.
        assert "artifacts" in step.build.__code__.co_varnames


def test_the_generator_paths_survived_the_move():
    """The move hazard, asserted.

    `TESTS_DIR` was `Path(__file__).resolve().parent`, which after the move
    resolves into `tests/brix_suite` — making `UTILS_DIR` `tests/utils`, a
    directory that does not exist, and every `_GENERATOR_SOURCES` entry a
    path to nothing.  Nothing would have raised at import; the cache would
    simply have stamped five missing files.
    """
    import brix_suite.prep_steps as prep_steps

    assert prep_steps.TESTS_DIR == TESTS
    assert prep_steps.UTILS_DIR == TESTS.parent / "utils"
    assert prep_steps.UTILS_DIR.is_dir()
    missing = [p for p in prep_steps._GENERATOR_SOURCES if not p.exists()]
    assert missing == []
    # The module stamps its own source, which post-move is the canonical file.
    assert prep_steps._GENERATOR_SOURCES[0].name == "prep_steps.py"


@pytest.mark.parametrize("archive,module", sorted(_VERBATIM.items()))
def test_the_verbatim_moves_really_were_verbatim(archive, module):
    complaints = _move_complaints(
        _defs(LEGACY / archive), _defs(TESTS / "brix_suite" / module), module)
    assert complaints == []


# ---------------------------------------------------------------------------
# error


def test_a_step_reads_its_generator_at_build_time_not_at_construction(prep, tmp_path):
    """The whole justification for shimming this module rather than splitting
    it into a package.  A step built before the rebind must still call the
    rebind — which is only true while `build()` reads the module global.

    If someone later "optimises" `PkiStep.__init__` into
    `self._generate = regenerate_pki`, every test in
    `test_fleet_prep_cache.py` starts running the real openssl against a real
    PKI directory and passing anyway, because the fakes it installs are never
    consulted.
    """
    paths = prep.PrepPaths.resolve({"TEST_ROOT": str(tmp_path)})
    step = prep.PkiStep(paths)          # constructed BEFORE the rebind below

    seen = []
    prep.regenerate_pki = lambda pki_dir, env: seen.append(pki_dir)
    try:
        step.build()
    finally:
        del prep.regenerate_pki
    assert seen == [str(tmp_path / "pki")]


def test_the_shims_hold_no_logic_of_their_own():
    """A shim that grew a function would be a second definition site: the
    canonical module's version would be shadowed for flat importers only."""
    for flat in _SHIMS:
        tree = ast.parse((TESTS / ("%s.py" % flat)).read_text())
        defs = [n.name for n in tree.body
                if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
        assert defs == [], "%s.py defines %s" % (flat, defs)


def test_prep_paths_honours_an_out_of_tree_pki_dir(tmp_path):
    """`PKI_DIR` may point outside `TEST_ROOT`.  Resolving it once and handing
    it to the steps is what stops a step from recomputing the default and
    writing to the wrong tree."""
    import brix_suite.prep_steps as prep_steps

    elsewhere = tmp_path / "shared-pki"
    paths = prep_steps.PrepPaths.resolve(
        {"TEST_ROOT": str(tmp_path / "lane"), "PKI_DIR": str(elsewhere)})
    assert paths.pki_dir == elsewhere
    assert paths.tokens_dir == tmp_path / "lane" / "tokens"


# ---------------------------------------------------------------------------
# security-negative


def test_editing_one_generator_restamps_every_step(prep, tmp_path, monkeypatch):
    """One shared stamp, deliberately.

    Per-step stamps would look tidier and would be wrong: the steps share
    generators (both token steps run `make_token.py`), so an edit to one
    could leave another step's output restored from a snapshot built by the
    old code — stale credentials, silently.
    """
    gen_a = tmp_path / "gen_a.py"
    gen_b = tmp_path / "gen_b.py"
    gen_a.write_text("a = 1\n")
    gen_b.write_text("b = 1\n")
    monkeypatch.setattr(prep, "_GENERATOR_SOURCES", (gen_a, gen_b))

    paths = prep.PrepPaths.resolve({"TEST_ROOT": str(tmp_path)})
    steps = prep.crypto_steps(paths) + prep.session_steps(paths)
    before = [s.stamp() for s in steps]

    gen_a.write_text("a = 2  # changed\n")
    after = [s.stamp() for s in steps]

    assert all(b != a for b, a in zip(before, after))
    assert len(set(after)) == 1, "the stamp is shared, not per-step"
    #: One key per generator, and the key names the generator.  Keys carry the
    #: parent directory since TS-5: the sources stopped being siblings when
    #: `tokenforge` became a package, and two packages may each hold a
    #: `mint.py`.  Asserted as a property rather than as the literal spelling
    #: so the next move does not have to come back and edit this line.
    keys = json.loads(after[0]).keys()
    assert len(keys) == 2
    assert {k.rsplit("/", 1)[-1] for k in keys} == {"gen_a.py", "gen_b.py"}


def test_the_session_steps_are_never_snapshotted():
    """CRL drops, the authdb placeholder and the stage hook are per-session
    state.  Restoring them from a snapshot would carry over a tree that no
    longer exists — and in the CRL case would reinstate a revocation list the
    current PKI never issued."""
    import brix_suite.prep_steps as prep_steps

    source = (TESTS / "brix_suite" / "prep_steps.py").read_text()
    body = source[source.index("def prepare("):]
    restore_block = body[:body.index("# 6-8)")]
    for step in prep_steps.SESSION_STEPS:
        assert step.__name__ not in restore_block
    assert "session_steps(paths)" in body[body.index("# 6-8)"):]


def test_the_legacy_archives_are_inert():
    for stem in ("fleet_prep_flat", "fleet_declares_flat", "fleet_orphans_flat"):
        importers = [p.name for p in TESTS.rglob("*.py")
                     if "import %s" % stem in p.read_text()]
        assert importers == [], "%s is imported by %s" % (stem, importers)


def test_the_flat_script_spelling_still_generates_artifacts(monkeypatch):
    """`python3 tests/fleet_prep.py` must do the work, not just exit 0.

    It was a script before TS-4 — `prepare()` plus a line operators grep for —
    and the move to `brix_suite.prep_steps` took the `__main__` guard with it,
    leaving the flat path a no-op for a phase and a half.  Guard #11
    (`tools/ci/check_shim_entrypoints.py`) is what found it; this asserts the
    behaviour rather than the shape, with the expensive leg stubbed.
    """
    import runpy

    import brix_suite.prep_steps as prep_steps

    called = []
    monkeypatch.setattr(prep_steps, "prepare", lambda env=None: called.append(env))
    monkeypatch.setattr(sys, "argv", ["tests/fleet_prep.py"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(TESTS / "fleet_prep.py"), run_name="__main__")
    assert exc.value.code == 0
    assert called == [None], "the script exited without generating anything"


def test_the_move_ledgers_cannot_be_left_behind():
    """A ledger that only ever says yes is a comment.

    Four ways a moved module can drift, each checked against the SAME helper
    the real pin uses: a definition lost, one added without an entry, one
    edited without an entry, and — the one that rots silently — an entry that
    outlived the edit it was written for.
    """
    before = {"kept": "A", "gone": "B", "edited": "C"}
    after = {"kept": "A", "edited": "D", "fresh": "E"}

    complaints = _move_complaints(before, after, "unledgered.py")
    assert len(complaints) == 3, complaints
    assert "dropped ['gone']" in complaints[0]
    assert "grew ['fresh']" in complaints[1]
    assert "edited ['edited']" in complaints[2]

    assert _CHANGED_SINCE_MOVE["orphans.py"] == {"kill_orphans"}, (
        "the stale-entry check below is written against this ledger")
    stale = _move_complaints({"kill_orphans": "A"}, {"kill_orphans": "A"},
                             "orphans.py")
    assert len(stale) == 1 and "still matches the archive" in stale[0], stale
